package webhook

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/prometheus/client_golang/prometheus/testutil"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/assay/api/v1alpha1"
	"github.com/DAVANO-INNOVATION-LAB/assay/internal/metrics"
	"github.com/DAVANO-INNOVATION-LAB/assay/internal/naming"
)

const testNamespace = "models"

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := securityv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return scheme
}

func report(model, version string, mutate func(*securityv1alpha1.ModelSecurityReport)) *securityv1alpha1.ModelSecurityReport {
	r := &securityv1alpha1.ModelSecurityReport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      naming.ModelReport(model, version),
			Namespace: testNamespace,
		},
		Spec: securityv1alpha1.ModelSecurityReportSpec{ModelName: model, ModelVersion: version},
		Status: securityv1alpha1.ModelSecurityReportStatus{
			Verdict: securityv1alpha1.VerdictApproved,
		},
	}
	if mutate != nil {
		mutate(r)
	}
	return r
}

// deployment builds an admission request for a workload annotated with a
// model reference.
func deployment(annotations map[string]string) admission.Request {
	obj := map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata": map[string]any{
			"name":        "serving",
			"namespace":   testNamespace,
			"annotations": toAnyMap(annotations),
		},
	}
	raw, _ := json.Marshal(obj)
	return admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
		Operation: admissionv1.Create,
		Namespace: testNamespace,
		Object:    runtime.RawExtension{Raw: raw},
	}}
}

func inferenceService(storageURI string, annotations map[string]string) admission.Request {
	obj := map[string]any{
		"apiVersion": "serving.kserve.io/v1beta1",
		"kind":       "InferenceService",
		"metadata": map[string]any{
			"name":        "predictor",
			"namespace":   testNamespace,
			"annotations": toAnyMap(annotations),
		},
		"spec": map[string]any{
			"predictor": map[string]any{
				"model": map[string]any{"storageUri": storageURI},
			},
		},
	}
	raw, _ := json.Marshal(obj)
	return admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
		Operation: admissionv1.Create,
		Namespace: testNamespace,
		Object:    runtime.RawExtension{Raw: raw},
	}}
}

func toAnyMap(in map[string]string) map[string]any {
	out := map[string]any{}
	for k, v := range in {
		out[k] = v
	}
	return out
}

func newGate(t *testing.T, objects ...runtime.Object) *ModelGate {
	t.Helper()
	scheme := testScheme(t)
	return &ModelGate{
		Client: fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(objects...).Build(),
	}
}

func TestApprovedModelIsAdmitted(t *testing.T) {
	gate := newGate(t, report("fraud", "v1", nil))

	resp := gate.Handle(context.Background(), deployment(map[string]string{
		AnnotationModel:   "fraud",
		AnnotationVersion: "v1",
	}))

	if !resp.Allowed {
		t.Fatalf("approved model was denied: %s", resp.Result.Message)
	}
}

func TestQuarantinedModelIsDenied(t *testing.T) {
	gate := newGate(t, report("fraud", "v1", func(r *securityv1alpha1.ModelSecurityReport) {
		r.Status.Verdict = securityv1alpha1.VerdictQuarantined
		r.Status.Malware = "Detected"
		r.Status.RiskScore = 100
	}))

	resp := gate.Handle(context.Background(), deployment(map[string]string{
		AnnotationModel:   "fraud",
		AnnotationVersion: "v1",
	}))

	if resp.Allowed {
		t.Fatal("quarantined model was admitted")
	}
	if !strings.Contains(resp.Result.Message, "quarantined") {
		t.Errorf("denial message does not explain why: %q", resp.Result.Message)
	}
}

func TestReviewRequiredModelIsDenied(t *testing.T) {
	gate := newGate(t, report("fraud", "v1", func(r *securityv1alpha1.ModelSecurityReport) {
		r.Status.Verdict = securityv1alpha1.VerdictReviewRequired
	}))

	resp := gate.Handle(context.Background(), deployment(map[string]string{
		AnnotationModel:   "fraud",
		AnnotationVersion: "v1",
	}))

	if resp.Allowed {
		t.Fatal("model awaiting review was admitted")
	}
}

// A report with no verdict means the scan never finished. Admitting it would
// let an unscanned model through the moment the report object exists.
func TestEmptyVerdictIsDenied(t *testing.T) {
	gate := newGate(t, report("fraud", "v1", func(r *securityv1alpha1.ModelSecurityReport) {
		r.Status.Verdict = ""
	}))

	resp := gate.Handle(context.Background(), deployment(map[string]string{
		AnnotationModel:   "fraud",
		AnnotationVersion: "v1",
	}))

	if resp.Allowed {
		t.Fatal("model with no verdict was admitted")
	}
}

func TestUnknownModelIsDeniedWhenReportRequired(t *testing.T) {
	gate := newGate(t)
	gate.RequireReport = true

	resp := gate.Handle(context.Background(), deployment(map[string]string{
		AnnotationModel:   "never-scanned",
		AnnotationVersion: "v1",
	}))

	if resp.Allowed {
		t.Fatal("unscanned model was admitted while --require-report was set")
	}
}

func TestUnknownModelIsAdmittedWhenReportOptional(t *testing.T) {
	gate := newGate(t)

	resp := gate.Handle(context.Background(), deployment(map[string]string{
		AnnotationModel:   "never-scanned",
		AnnotationVersion: "v1",
	}))

	if !resp.Allowed {
		t.Fatal("unscanned model was denied even though reports are optional")
	}
}

func TestWorkloadWithoutModelReferenceIsIgnored(t *testing.T) {
	gate := newGate(t)

	if resp := gate.Handle(context.Background(), deployment(nil)); !resp.Allowed {
		t.Fatal("a workload with no model reference was denied")
	}
}

// The digest a workload pins must be the digest that was scanned, otherwise
// an approved verdict could be replayed onto entirely different bytes.
func TestDigestMismatchIsDenied(t *testing.T) {
	gate := newGate(t, report("fraud", "v1", func(r *securityv1alpha1.ModelSecurityReport) {
		r.Spec.Artifact.Digest = "sha256:aaaa"
	}))

	resp := gate.Handle(context.Background(), inferenceService(
		"oci://registry.example/models/fraud/v1@sha256:bbbb", nil))

	if resp.Allowed {
		t.Fatal("workload pinning a different digest than was scanned was admitted")
	}
	if !strings.Contains(resp.Result.Message, "digest") {
		t.Errorf("denial message does not mention the digest: %q", resp.Result.Message)
	}
}

func TestMatchingDigestIsAdmitted(t *testing.T) {
	gate := newGate(t, report("fraud", "v1", func(r *securityv1alpha1.ModelSecurityReport) {
		r.Spec.Artifact.Digest = "sha256:aaaa"
	}))

	resp := gate.Handle(context.Background(), inferenceService(
		"oci://registry.example/models/fraud/v1@sha256:aaaa", nil))

	if !resp.Allowed {
		t.Fatalf("matching digest was denied: %s", resp.Result.Message)
	}
}

func TestUnpromotedEnvironmentIsDenied(t *testing.T) {
	gate := newGate(t, report("fraud", "v1", func(r *securityv1alpha1.ModelSecurityReport) {
		r.Status.ApprovedEnvironments = []string{"dev", "stage"}
	}))

	resp := gate.Handle(context.Background(), deployment(map[string]string{
		AnnotationModel:       "fraud",
		AnnotationVersion:     "v1",
		AnnotationEnvironment: "prod",
	}))

	if resp.Allowed {
		t.Fatal("model not promoted to prod was admitted into prod")
	}
}

func TestPromotedEnvironmentIsAdmitted(t *testing.T) {
	gate := newGate(t, report("fraud", "v1", func(r *securityv1alpha1.ModelSecurityReport) {
		r.Status.ApprovedEnvironments = []string{"dev", "prod"}
	}))

	resp := gate.Handle(context.Background(), deployment(map[string]string{
		AnnotationModel:       "fraud",
		AnnotationVersion:     "v1",
		AnnotationEnvironment: "prod",
	}))

	if !resp.Allowed {
		t.Fatalf("promoted model was denied: %s", resp.Result.Message)
	}
}

func TestAuditModeAdmitsWithReason(t *testing.T) {
	policy := &securityv1alpha1.ArtifactScanPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "audit-only", Namespace: testNamespace},
		Spec:       securityv1alpha1.ArtifactScanPolicySpec{Enforcement: "Audit"},
	}
	gate := newGate(t, policy, report("fraud", "v1", func(r *securityv1alpha1.ModelSecurityReport) {
		r.Status.Verdict = securityv1alpha1.VerdictQuarantined
	}))

	resp := gate.Handle(context.Background(), deployment(map[string]string{
		AnnotationModel:   "fraud",
		AnnotationVersion: "v1",
		AnnotationPolicy:  "audit-only",
	}))

	if !resp.Allowed {
		t.Fatal("audit mode denied a deployment")
	}
	if !strings.Contains(resp.Result.Message, "audit") {
		t.Errorf("audit-mode message does not record the violation: %q", resp.Result.Message)
	}
}

func TestWarnModeAdmitsWithWarning(t *testing.T) {
	policy := &securityv1alpha1.ArtifactScanPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "warn-only", Namespace: testNamespace},
		Spec:       securityv1alpha1.ArtifactScanPolicySpec{Enforcement: "Warn"},
	}
	gate := newGate(t, policy, report("fraud", "v1", func(r *securityv1alpha1.ModelSecurityReport) {
		r.Status.Verdict = securityv1alpha1.VerdictQuarantined
	}))

	resp := gate.Handle(context.Background(), deployment(map[string]string{
		AnnotationModel:   "fraud",
		AnnotationVersion: "v1",
		AnnotationPolicy:  "warn-only",
	}))

	if !resp.Allowed {
		t.Fatal("warn mode denied a deployment")
	}
	if len(resp.Warnings) == 0 {
		t.Error("warn mode produced no warning")
	}
}

// A policy that cannot be read must not silently weaken the gate.
func TestMissingPolicyFailsClosed(t *testing.T) {
	gate := newGate(t, report("fraud", "v1", func(r *securityv1alpha1.ModelSecurityReport) {
		r.Status.Verdict = securityv1alpha1.VerdictQuarantined
	}))

	resp := gate.Handle(context.Background(), deployment(map[string]string{
		AnnotationModel:   "fraud",
		AnnotationVersion: "v1",
		AnnotationPolicy:  "does-not-exist",
	}))

	if resp.Allowed {
		t.Fatal("a missing policy caused the gate to admit a quarantined model")
	}
}

func TestDeleteIsAlwaysAllowed(t *testing.T) {
	gate := newGate(t)
	req := deployment(map[string]string{AnnotationModel: "fraud"})
	req.Operation = admissionv1.Delete

	if resp := gate.Handle(context.Background(), req); !resp.Allowed {
		t.Fatal("a delete was denied")
	}
}

func TestMalformedObjectIsRejected(t *testing.T) {
	gate := newGate(t)
	req := admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
		Operation: admissionv1.Create,
		Namespace: testNamespace,
		Object:    runtime.RawExtension{Raw: []byte("{not json")},
	}}

	if resp := gate.Handle(context.Background(), req); resp.Allowed {
		t.Fatal("a malformed object was admitted")
	}
}

func TestInferenceServiceModelIsDerivedFromStorageURI(t *testing.T) {
	gate := newGate(t, report("fraud", "v1", func(r *securityv1alpha1.ModelSecurityReport) {
		r.Status.Verdict = securityv1alpha1.VerdictQuarantined
	}))

	resp := gate.Handle(context.Background(), inferenceService("s3://models/fraud/v1", nil))

	if resp.Allowed {
		t.Fatal("gate failed to derive the model from the KServe storageUri, so a quarantined model got through")
	}
}

// The deployed layout puts scans and their reports in the operator's namespace
// while the workloads being gated run in the teams' own namespaces. Looking
// only in the workload's namespace found nothing, and "nothing" is read as
// "unscanned" — so with the shipped --require-report=false the gate admitted
// every workload it was installed to stop. These pin the split-namespace case.
func TestGateFindsReportInThePipelineNamespace(t *testing.T) {
	const pipelineNS = "assay-system"

	quarantined := report("fraud", "v1", func(r *securityv1alpha1.ModelSecurityReport) {
		r.Namespace = pipelineNS
		r.Status.Verdict = securityv1alpha1.VerdictQuarantined
		r.Status.RiskScore = 100
	})

	gate := newGate(t, quarantined)
	gate.ReportNamespace = pipelineNS

	// The workload lives in testNamespace; its report lives in pipelineNS.
	resp := gate.Handle(context.Background(), deployment(map[string]string{
		AnnotationModel:   "fraud",
		AnnotationVersion: "v1",
	}))

	if resp.Allowed {
		t.Fatalf("quarantined model was admitted because its report is in another namespace: %s",
			resp.Result.Message)
	}
}

// Without a configured report namespace the gate must not start guessing:
// behaviour stays exactly as before for anyone whose reports are co-located.
func TestGateWithoutReportNamespaceOnlyChecksTheWorkloadNamespace(t *testing.T) {
	elsewhere := report("fraud", "v1", func(r *securityv1alpha1.ModelSecurityReport) {
		r.Namespace = "somewhere-else"
		r.Status.Verdict = securityv1alpha1.VerdictQuarantined
	})

	gate := newGate(t, elsewhere) // ReportNamespace deliberately unset

	resp := gate.Handle(context.Background(), deployment(map[string]string{
		AnnotationModel:   "fraud",
		AnnotationVersion: "v1",
	}))
	if !resp.Allowed {
		t.Error("gate reached into an unrelated namespace for a report")
	}
}

// A report beside the workload still wins, so co-located installs keep working
// and a team can override the pipeline's verdict location deliberately.
func TestWorkloadNamespaceReportTakesPrecedence(t *testing.T) {
	local := report("fraud", "v1", nil) // testNamespace, Approved
	remote := report("fraud", "v1", func(r *securityv1alpha1.ModelSecurityReport) {
		r.Namespace = "assay-system"
		r.Status.Verdict = securityv1alpha1.VerdictQuarantined
	})

	gate := newGate(t, local, remote)
	gate.ReportNamespace = "assay-system"

	resp := gate.Handle(context.Background(), deployment(map[string]string{
		AnnotationModel:   "fraud",
		AnnotationVersion: "v1",
	}))
	if !resp.Allowed {
		t.Errorf("local approved report was not preferred: %s", resp.Result.Message)
	}
}

// A gate that fails open is indistinguishable from a working gate unless what
// it waved through is counted. "Allowed because there was no report" and
// "allowed because the model passed" are opposite facts that produce the same
// admission response, so they must not share a counter.
func TestUnscannedAdmissionsAreCountedSeparately(t *testing.T) {
	const ns = "counted-ns"

	read := func(outcome string) float64 {
		return testutil.ToFloat64(metrics.AdmissionDecisions.WithLabelValues(outcome, ns))
	}
	beforeUnscanned := read(metrics.OutcomeAllowedNoScan)
	beforeApproved := read(metrics.OutcomeAllowed)

	gate := newGate(t) // no reports at all
	req := deployment(map[string]string{
		AnnotationModel:   "never-scanned",
		AnnotationVersion: "v1",
	})
	req.Namespace = ns

	resp := gate.Handle(context.Background(), req)
	if !resp.Allowed {
		t.Fatalf("expected the permissive default to admit: %v", resp.Result)
	}

	if got := read(metrics.OutcomeAllowedNoScan); got != beforeUnscanned+1 {
		t.Errorf("allowed_unscanned counter = %v, want %v", got, beforeUnscanned+1)
	}
	if got := read(metrics.OutcomeAllowed); got != beforeApproved {
		t.Errorf("an unscanned admission was counted as an approval (%v)", got)
	}
}
