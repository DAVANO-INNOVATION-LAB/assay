package controller

import (
	"context"
	"fmt"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/assay/api/v1alpha1"
	"github.com/DAVANO-INNOVATION-LAB/assay/internal/metrics"
	"github.com/DAVANO-INNOVATION-LAB/assay/internal/modelsource"
	"github.com/DAVANO-INNOVATION-LAB/assay/internal/registry"
)

// Trigger values recorded on a scan. They are what makes a verdict readable
// after the fact: "checked when it was registered" and "checked only because
// somebody tried to deploy it" are very different assurances, and without this
// they are indistinguishable.
const (
	TriggerRegistry = "Registry"
	TriggerRuntime  = "Runtime"
	TriggerPeriodic = "Periodic"
	TriggerManual   = "Manual"
	TriggerPipeline = "Pipeline"
)

// Connector types.
const (
	SourceKubeflow = "KubeflowModelRegistry"
	SourceMLflow   = "MLflow"
)

// sourceFor builds the ModelSource behind a connector.
//
// Both registries go through one interface, so adding a third is an
// implementation rather than a parallel controller — registry scanning stays
// one pipeline with several front doors.
func (r *ModelRegistryConnectorReconciler) sourceFor(
	connector *securityv1alpha1.ModelRegistryConnector, token string,
) (modelsource.Source, error) {
	switch connector.Spec.Type {
	case SourceMLflow:
		return modelsource.NewMLflow(modelsource.MLflowOptions{
			BaseURL: connector.Spec.RegistryURL,
			Token:   token,
		}), nil
	case "", SourceKubeflow:
		return modelsource.NewModelRegistry(registry.Options{
			BaseURL:               connector.Spec.RegistryURL,
			Token:                 token,
			InsecureSkipTLSVerify: connector.Spec.InsecureSkipTLSVerify,
		}, nil), nil
	default:
		return nil, fmt.Errorf("unknown connector type %q; want %s or %s",
			connector.Spec.Type, SourceKubeflow, SourceMLflow)
	}
}

// syncSource discovers everything a source holds and ensures a scan exists for
// each version, creating a fresh one when the last is older than the
// connector's rescan interval.
//
// Returns how many versions were seen, how many scans were created, and how
// many versions failed — the last so a connector cannot report Ready while
// every model silently failed to sync.
func (r *ModelRegistryConnectorReconciler) syncSource(
	ctx context.Context,
	connector *securityv1alpha1.ModelRegistryConnector,
	src modelsource.Source,
) (versions, created, failures int, err error) {
	list, err := src.List(ctx)
	if err != nil {
		return 0, 0, 0, err
	}
	logger := log.FromContext(ctx)

	for _, v := range list {
		if !matchesIncludeList(v.ModelName, connector.Spec.IncludeModels) {
			continue
		}
		versions++

		trigger := TriggerRegistry
		name := scanNameFor(v.ModelName, v.Version, "")

		var existing securityv1alpha1.ArtifactScan
		getErr := r.Get(ctx, client.ObjectKey{Name: name, Namespace: connector.Namespace}, &existing)
		switch {
		case getErr == nil:
			due, why := rescanDue(&existing, connector.Spec.RescanInterval)
			if !due {
				continue
			}
			// A verdict is a statement about what was known when it ran, and
			// CVE data moves. Recheck under a new name so the previous verdict
			// stays on record rather than being overwritten — an audit needs
			// the history, not just the latest answer.
			trigger = TriggerPeriodic
			name = scanNameFor(v.ModelName, v.Version, time.Now().UTC().Format("20060102-1504"))
			logger.Info("rescanning", "model", v.ModelName, "version", v.Version, "reason", why)

		case !apierrors.IsNotFound(getErr):
			failures++
			continue
		}

		scan := &securityv1alpha1.ArtifactScan{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: connector.Namespace,
				Labels: map[string]string{
					LabelConnector:             connector.Name,
					LabelManagedBy:             ManagerName,
					LabelTrigger:               trigger,
					"security.davano.io/model": sanitizeLabel(v.ModelName),
				},
			},
			Spec: securityv1alpha1.ArtifactScanSpec{
				ModelName:    v.ModelName,
				ModelVersion: v.Version,
				ConnectorRef: connector.Name,
				PolicyRef:    connector.Spec.PolicyRef,
				Artifact:     v.Artifact,
				Trigger:      trigger,
				TriggeredBy:  fmt.Sprintf("%s/%s", src.Name(), connector.Name),
			},
		}
		if err := controllerutil.SetControllerReference(connector, scan, r.Scheme); err != nil {
			failures++
			continue
		}
		if err := r.Create(ctx, scan); err != nil {
			if !apierrors.IsAlreadyExists(err) {
				failures++
				metrics.SourceSyncFailures.WithLabelValues(src.Name(), "create_scan").Inc()
			}
			continue
		}
		created++
	}

	// Push finished verdicts back to the source. This is what makes the
	// result visible to the people who registered the model, rather than only
	// to whoever reads Kubernetes — and dropping it when the sync was
	// rewritten would have silently turned Assay into a system that scans and
	// tells nobody.
	if connector.Spec.WriteBack == nil || *connector.Spec.WriteBack {
		for _, v := range list {
			if !matchesIncludeList(v.ModelName, connector.Spec.IncludeModels) {
				continue
			}
			if err := r.writeVerdictBack(ctx, connector, src, v); err != nil {
				failures++
				metrics.SourceSyncFailures.WithLabelValues(src.Name(), "write_back").Inc()
			}
		}
	}
	return versions, created, failures, nil
}

// writeVerdictBack records a completed verdict on the source's own version.
func (r *ModelRegistryConnectorReconciler) writeVerdictBack(
	ctx context.Context,
	connector *securityv1alpha1.ModelRegistryConnector,
	src modelsource.Source,
	v modelsource.Version,
) error {
	var report securityv1alpha1.ModelSecurityReport
	key := client.ObjectKey{
		Name:      modelReportName(v.ModelName, v.Version),
		Namespace: connector.Namespace,
	}
	if err := r.Get(ctx, key, &report); err != nil {
		// Not scanned yet is the normal case on the first pass, not an error.
		return client.IgnoreNotFound(err)
	}
	if report.Status.LastScanTime == nil {
		return nil
	}
	return src.WriteBack(ctx, v, modelsource.Verdict{
		Verdict:   report.Status.Verdict,
		RiskScore: report.Status.RiskScore,
		Malware:   report.Status.Malware,
		Secrets:   report.Status.Secrets,
		ScanTime:  report.Status.LastScanTime.Time,
		ReportRef: report.Namespace + "/" + report.Name,
	})
}

// rescanDue reports whether a completed scan is old enough to redo.
func rescanDue(scan *securityv1alpha1.ArtifactScan, interval *metav1.Duration) (bool, string) {
	if interval == nil || interval.Duration <= 0 {
		return false, ""
	}
	// Only recheck something that finished. Rescanning a scan still in flight
	// would just pile up duplicate work.
	if scan.Status.Phase != "Completed" && scan.Status.Phase != "Failed" {
		return false, ""
	}
	last := scan.Status.CompletionTime
	if last == nil {
		last = scan.Status.StartTime
	}
	if last == nil {
		return false, ""
	}
	age := time.Since(last.Time)
	if age < interval.Duration {
		return false, ""
	}
	return true, fmt.Sprintf("last verdict is %s old, interval is %s",
		age.Round(time.Minute), interval.Duration)
}
