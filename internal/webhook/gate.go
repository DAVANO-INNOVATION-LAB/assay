// Package webhook implements the admission gate that stops unapproved models
// from being deployed. It is the enforcement point for everything the scan
// pipeline concludes.
package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	securityv1alpha1 "github.com/JUMP1ST/assay/api/v1alpha1"
	"github.com/JUMP1ST/assay/internal/controller"
)

// Annotations a workload uses to declare which model it serves. KServe
// InferenceServices are read directly; anything else opts in with these.
const (
	AnnotationModel       = "security.davano.io/model"
	AnnotationVersion     = "security.davano.io/model-version"
	AnnotationEnvironment = "security.davano.io/environment"
	AnnotationPolicy      = "security.davano.io/policy"
	AnnotationSkip        = "security.davano.io/skip-validation"
)

// ModelGate validates that any workload serving a registered model is backed
// by an approved ModelSecurityReport.
type ModelGate struct {
	Client  client.Client
	decoder admission.Decoder

	// DefaultPolicy is consulted for enforcement mode when a workload does
	// not name a policy.
	DefaultPolicy string
	// RequireReport rejects workloads that reference a model with no report
	// at all. When false, unknown models are admitted with a warning.
	RequireReport bool
}

// Handle implements admission.Handler.
func (g *ModelGate) Handle(ctx context.Context, req admission.Request) admission.Response {
	if req.Operation == admissionv1.Delete {
		return admission.Allowed("")
	}

	obj := &unstructured.Unstructured{}
	if err := json.Unmarshal(req.Object.Raw, obj); err != nil {
		return admission.Errored(http.StatusBadRequest, fmt.Errorf("decode object: %w", err))
	}

	annotations := obj.GetAnnotations()
	if strings.EqualFold(annotations[AnnotationSkip], "true") {
		// Opting out is recorded in the response so it shows up in the audit
		// log rather than passing silently.
		return admission.Allowed("assay validation explicitly skipped by annotation")
	}

	ref := extractModelRef(obj)
	if ref.Model == "" {
		return admission.Allowed("no model reference; nothing for assay to validate")
	}

	report := &securityv1alpha1.ModelSecurityReport{}
	key := client.ObjectKey{
		Name:      modelReportName(ref.Model, ref.Version),
		Namespace: req.Namespace,
	}
	if err := g.Client.Get(ctx, key, report); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return admission.Errored(http.StatusInternalServerError, fmt.Errorf("look up security report: %w", err))
		}
		if g.RequireReport {
			return admission.Denied(fmt.Sprintf(
				"model %q version %q has not been scanned by Assay; register it and wait for the scan to complete",
				ref.Model, ref.Version))
		}
		return admission.Allowed(fmt.Sprintf("no Assay security report for model %q version %q", ref.Model, ref.Version))
	}

	enforcement := g.enforcementFor(ctx, req.Namespace, annotations)

	if decision := g.evaluate(report, ref); decision.deny {
		switch enforcement {
		case "Audit":
			return admission.Allowed("assay: " + decision.reason + " (audit mode)")
		case "Warn":
			resp := admission.Allowed("assay: admitted with warnings")
			resp.Warnings = append(resp.Warnings, "assay: "+decision.reason)
			return resp
		default:
			return admission.Denied("assay: " + decision.reason)
		}
	}

	return admission.Allowed(fmt.Sprintf(
		"assay: model %q version %q approved (risk score %d)", ref.Model, ref.Version, report.Status.RiskScore))
}

type decision struct {
	deny   bool
	reason string
}

func (g *ModelGate) evaluate(report *securityv1alpha1.ModelSecurityReport, ref ModelRef) decision {
	switch report.Status.Verdict {
	case securityv1alpha1.VerdictApproved:
		// keep going: an approved model may still be unpromoted for this env
	case securityv1alpha1.VerdictQuarantined:
		return decision{true, fmt.Sprintf(
			"model %q version %q is quarantined (risk score %d, malware: %s)",
			ref.Model, ref.Version, report.Status.RiskScore, orUnknown(report.Status.Malware))}
	case securityv1alpha1.VerdictReviewRequired:
		return decision{true, fmt.Sprintf(
			"model %q version %q requires security review before deployment (risk score %d)",
			ref.Model, ref.Version, report.Status.RiskScore)}
	default:
		return decision{true, fmt.Sprintf(
			"model %q version %q has no completed scan verdict", ref.Model, ref.Version)}
	}

	// The digest pinned in the workload must match what was actually scanned,
	// otherwise an approved verdict could be replayed onto different bytes.
	if ref.Digest != "" && report.Spec.Artifact.Digest != "" && ref.Digest != report.Spec.Artifact.Digest {
		return decision{true, fmt.Sprintf(
			"artifact digest %s does not match the scanned digest %s",
			ref.Digest, report.Spec.Artifact.Digest)}
	}

	if ref.Environment != "" && len(report.Status.ApprovedEnvironments) > 0 {
		if !contains(report.Status.ApprovedEnvironments, ref.Environment) {
			return decision{true, fmt.Sprintf(
				"model %q version %q is not promoted to %q (approved for: %s)",
				ref.Model, ref.Version, ref.Environment,
				strings.Join(report.Status.ApprovedEnvironments, ", "))}
		}
	}

	return decision{}
}

// enforcementFor resolves the enforcement mode from the named policy, the
// namespace default policy, or the operator default.
func (g *ModelGate) enforcementFor(ctx context.Context, namespace string, annotations map[string]string) string {
	name := annotations[AnnotationPolicy]
	if name == "" {
		name = g.DefaultPolicy
	}
	if name == "" {
		return "Enforce"
	}

	var pol securityv1alpha1.ArtifactScanPolicy
	if err := g.Client.Get(ctx, client.ObjectKey{Name: name, Namespace: namespace}, &pol); err != nil {
		// A missing policy must not weaken the gate.
		return "Enforce"
	}
	if pol.Spec.Enforcement == "" {
		return "Enforce"
	}
	return pol.Spec.Enforcement
}

// InjectDecoder satisfies controller-runtime's decoder injection.
func (g *ModelGate) InjectDecoder(d admission.Decoder) error {
	g.decoder = d
	return nil
}

// SetupWithManager registers the gate on the manager's webhook server.
func (g *ModelGate) SetupWithManager(mgr ctrl.Manager) error {
	if g.Client == nil {
		g.Client = mgr.GetClient()
	}
	g.decoder = admission.NewDecoder(mgr.GetScheme())
	mgr.GetWebhookServer().Register("/validate-model-deployment", &admission.Webhook{Handler: g})
	return nil
}

// modelReportName mirrors the controller's naming so the gate finds the same
// report the scan pipeline wrote.
func modelReportName(model, version string) string {
	return controller.ModelReportName(model, version)
}

func contains(list []string, value string) bool {
	for _, item := range list {
		if strings.EqualFold(item, value) {
			return true
		}
	}
	return false
}

func orUnknown(v string) string {
	if v == "" {
		return "unknown"
	}
	return v
}
