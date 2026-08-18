package controller

import (
	"context"
	"fmt"
	"path"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	securityv1alpha1 "github.com/JUMP1ST/assay/api/v1alpha1"
	"github.com/JUMP1ST/assay/internal/registry"
)

// defaultPollInterval is how often the registry is polled when the connector
// does not specify an interval.
const defaultPollInterval = time.Minute

// ModelRegistryConnectorReconciler polls an OpenShift AI Model Registry,
// creates an ArtifactScan for every model version it has not scanned, and
// writes scan summaries back into the registry.
type ModelRegistryConnectorReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	// NewClient builds a registry client. Overridden in tests.
	NewClient func(registry.Options) RegistryClient
}

// RegistryClient is the subset of the Model Registry API the connector uses.
type RegistryClient interface {
	Ping(ctx context.Context) error
	ListRegisteredModels(ctx context.Context) ([]registry.RegisteredModel, error)
	ListModelVersions(ctx context.Context, modelID string) ([]registry.ModelVersion, error)
	ListArtifacts(ctx context.Context, versionID string) ([]registry.ModelArtifact, error)
	PatchModelVersionProperties(ctx context.Context, versionID string, props map[string]registry.MetadataValue) error
}

// Annotations Assay puts on ArtifactScans to correlate them with the registry.
const (
	AnnotationRegistryModelID   = "security.davano.io/registry-model-id"
	AnnotationRegistryVersionID = "security.davano.io/registry-version-id"
	AnnotationArtifactID        = "security.davano.io/registry-artifact-id"
	LabelConnector              = "security.davano.io/connector"
)

// +kubebuilder:rbac:groups=security.davano.io,resources=modelregistryconnectors,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.davano.io,resources=modelregistryconnectors/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch

// Reconcile polls the registry once and requeues after the poll interval.
func (r *ModelRegistryConnectorReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var connector securityv1alpha1.ModelRegistryConnector
	if err := r.Get(ctx, req.NamespacedName, &connector); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !connector.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}

	interval := defaultPollInterval
	if connector.Spec.PollInterval != nil && connector.Spec.PollInterval.Duration > 0 {
		interval = connector.Spec.PollInterval.Duration
	}

	token, err := r.resolveToken(ctx, &connector)
	if err != nil {
		return r.degrade(ctx, &connector, "AuthSecretUnavailable", err.Error(), interval)
	}

	newClient := r.NewClient
	if newClient == nil {
		newClient = func(opts registry.Options) RegistryClient { return registry.New(opts) }
	}
	rc := newClient(registry.Options{
		BaseURL:               connector.Spec.RegistryURL,
		Token:                 token,
		InsecureSkipTLSVerify: connector.Spec.InsecureSkipTLSVerify,
	})

	if err := rc.Ping(ctx); err != nil {
		return r.degrade(ctx, &connector, "RegistryUnreachable", err.Error(), interval)
	}

	models, err := rc.ListRegisteredModels(ctx)
	if err != nil {
		return r.degrade(ctx, &connector, "ListModelsFailed", err.Error(), interval)
	}

	var (
		versionCount int32
		scansCreated int32
	)

	for _, model := range models {
		if !matchesIncludeList(model.Name, connector.Spec.IncludeModels) {
			continue
		}

		versions, err := rc.ListModelVersions(ctx, model.ID)
		if err != nil {
			logger.Error(err, "list model versions", "model", model.Name)
			continue
		}
		versionCount += int32(len(versions))

		for _, version := range versions {
			created, err := r.syncVersion(ctx, &connector, rc, model, version)
			if err != nil {
				logger.Error(err, "sync model version", "model", model.Name, "version", version.Name)
				continue
			}
			scansCreated += created
		}
	}

	now := metav1.Now()
	connector.Status.Phase = "Connected"
	connector.Status.Message = ""
	connector.Status.LastSyncTime = &now
	connector.Status.RegisteredModels = int32(len(models))
	connector.Status.ModelVersions = versionCount
	connector.Status.ScansCreated += scansCreated
	setCondition(&connector.Status.Conditions, metav1.Condition{
		Type:    "Ready",
		Status:  metav1.ConditionTrue,
		Reason:  "SyncSucceeded",
		Message: fmt.Sprintf("synced %d models, %d versions", len(models), versionCount),
	})
	if err := r.Status().Update(ctx, &connector); err != nil {
		return ctrl.Result{}, err
	}

	if scansCreated > 0 {
		logger.Info("created scans from registry", "connector", connector.Name, "scans", scansCreated)
	}
	return ctrl.Result{RequeueAfter: interval}, nil
}

// syncVersion ensures an ArtifactScan exists for each artifact of a model
// version, and pushes any completed verdict back into the registry.
func (r *ModelRegistryConnectorReconciler) syncVersion(
	ctx context.Context,
	connector *securityv1alpha1.ModelRegistryConnector,
	rc RegistryClient,
	model registry.RegisteredModel,
	version registry.ModelVersion,
) (int32, error) {
	artifacts, err := rc.ListArtifacts(ctx, version.ID)
	if err != nil {
		return 0, fmt.Errorf("list artifacts for version %s: %w", version.Name, err)
	}

	var created int32
	for _, artifact := range artifacts {
		uri := normalizeArtifactURI(artifact)
		if uri == "" {
			// An artifact with no resolvable location cannot be scanned;
			// skip rather than creating a scan that will always fail.
			continue
		}

		scanName := scanNameFor(model.Name, version.Name, artifact.ID)
		var existing securityv1alpha1.ArtifactScan
		err := r.Get(ctx, client.ObjectKey{Name: scanName, Namespace: connector.Namespace}, &existing)
		if err == nil {
			continue
		}
		if !apierrors.IsNotFound(err) {
			return created, fmt.Errorf("check scan %s: %w", scanName, err)
		}

		scan := &securityv1alpha1.ArtifactScan{
			ObjectMeta: metav1.ObjectMeta{
				Name:      scanName,
				Namespace: connector.Namespace,
				Labels: map[string]string{
					LabelConnector:             connector.Name,
					LabelManagedBy:             ManagerName,
					"security.davano.io/model": sanitizeLabel(model.Name),
				},
				Annotations: map[string]string{
					AnnotationRegistryModelID:   model.ID,
					AnnotationRegistryVersionID: version.ID,
					AnnotationArtifactID:        artifact.ID,
				},
			},
			Spec: securityv1alpha1.ArtifactScanSpec{
				ModelName:         model.Name,
				ModelVersion:      version.Name,
				RegistryModelID:   model.ID,
				RegistryVersionID: version.ID,
				ConnectorRef:      connector.Name,
				PolicyRef:         connector.Spec.PolicyRef,
				Artifact: securityv1alpha1.ArtifactRef{
					URI:    uri,
					Format: artifact.ModelFormatName,
				},
			},
		}
		if err := controllerutil.SetControllerReference(connector, scan, r.Scheme); err != nil {
			return created, fmt.Errorf("set owner on scan: %w", err)
		}
		if err := r.Create(ctx, scan); err != nil {
			if apierrors.IsAlreadyExists(err) {
				continue
			}
			return created, fmt.Errorf("create scan %s: %w", scanName, err)
		}
		created++
	}

	if err := r.writeBack(ctx, connector, rc, model, version); err != nil {
		return created, err
	}
	return created, nil
}

// writeBack pushes the model version's security summary into the registry as
// custom properties, so users see the verdict without leaving the registry UI.
func (r *ModelRegistryConnectorReconciler) writeBack(
	ctx context.Context,
	connector *securityv1alpha1.ModelRegistryConnector,
	rc RegistryClient,
	model registry.RegisteredModel,
	version registry.ModelVersion,
) error {
	if connector.Spec.WriteBack != nil && !*connector.Spec.WriteBack {
		return nil
	}

	var report securityv1alpha1.ModelSecurityReport
	key := client.ObjectKey{Name: modelReportName(model.Name, version.Name), Namespace: connector.Namespace}
	if err := r.Get(ctx, key, &report); err != nil {
		if apierrors.IsNotFound(err) {
			return nil // not scanned yet
		}
		return fmt.Errorf("get model security report: %w", err)
	}
	if report.Status.LastScanTime == nil {
		return nil
	}

	// Skip the PATCH when the registry already carries this verdict, so a
	// steady-state poll does not write on every interval.
	if current, ok := version.CustomProperties[registry.PropLastScan]; ok {
		if current.StringValue == report.Status.LastScanTime.UTC().Format(time.RFC3339) {
			return nil
		}
	}

	props := registry.SummaryProperties(&report)
	if err := rc.PatchModelVersionProperties(ctx, version.ID, props); err != nil {
		return fmt.Errorf("write security metadata to registry: %w", err)
	}
	return nil
}

func (r *ModelRegistryConnectorReconciler) resolveToken(ctx context.Context, connector *securityv1alpha1.ModelRegistryConnector) (string, error) {
	ref := connector.Spec.AuthSecretRef
	if ref == nil || ref.Name == "" {
		return "", nil
	}
	var secret corev1.Secret
	if err := r.Get(ctx, client.ObjectKey{Name: ref.Name, Namespace: connector.Namespace}, &secret); err != nil {
		return "", fmt.Errorf("read auth secret %s: %w", ref.Name, err)
	}
	key := ref.Key
	if key == "" {
		key = "token"
	}
	value, ok := secret.Data[key]
	if !ok {
		return "", fmt.Errorf("auth secret %s has no key %q", ref.Name, key)
	}
	return strings.TrimSpace(string(value)), nil
}

func (r *ModelRegistryConnectorReconciler) degrade(ctx context.Context, connector *securityv1alpha1.ModelRegistryConnector, reason, message string, interval time.Duration) (ctrl.Result, error) {
	connector.Status.Phase = "Degraded"
	connector.Status.Message = message
	setCondition(&connector.Status.Conditions, metav1.Condition{
		Type:    "Ready",
		Status:  metav1.ConditionFalse,
		Reason:  reason,
		Message: message,
	})
	if err := r.Status().Update(ctx, connector); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: interval}, nil
}

// normalizeArtifactURI turns a registry artifact record into a URI the
// resolver understands. The registry stores locations inconsistently: some
// artifacts carry a full URI, others only a storage key plus path.
func normalizeArtifactURI(artifact registry.ModelArtifact) string {
	uri := strings.TrimSpace(artifact.URI)
	if uri != "" {
		if strings.Contains(uri, "://") {
			return uri
		}
		// A bare registry reference is an OCI image.
		return "oci://" + uri
	}

	if artifact.StorageKey != "" && artifact.StoragePath != "" {
		return "s3://" + path.Join(artifact.StorageKey, artifact.StoragePath)
	}
	return ""
}

// matchesIncludeList reports whether a model name matches any glob in the
// include list. An empty list matches everything.
func matchesIncludeList(name string, patterns []string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, pattern := range patterns {
		if ok, err := path.Match(pattern, name); err == nil && ok {
			return true
		}
	}
	return false
}

// SetupWithManager wires the reconciler into the manager.
func (r *ModelRegistryConnectorReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&securityv1alpha1.ModelRegistryConnector{}).
		Owns(&securityv1alpha1.ArtifactScan{}).
		Named("modelregistryconnector").
		Complete(r)
}
