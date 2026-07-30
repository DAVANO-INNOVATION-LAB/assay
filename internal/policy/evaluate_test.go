package policy

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	securityv1alpha1 "github.com/zeus-security/zeus-operator/api/v1alpha1"
)

func result(scanner, status string, counts securityv1alpha1.SeverityCounts) securityv1alpha1.ScannerResult {
	return securityv1alpha1.ScannerResult{
		Scanner:    scanner,
		Status:     status,
		Findings:   counts.Total(),
		Severities: counts,
	}
}

func TestCleanScanIsApproved(t *testing.T) {
	results := []securityv1alpha1.ScannerResult{
		result("clamav", "Passed", securityv1alpha1.SeverityCounts{}),
		result("trivy", "Passed", securityv1alpha1.SeverityCounts{}),
		result("trufflehog", "Passed", securityv1alpha1.SeverityCounts{}),
		result("syft", "Passed", securityv1alpha1.SeverityCounts{}),
	}

	eval := Evaluate(results, securityv1alpha1.ArtifactRef{}, nil, nil, time.Now())

	if eval.Verdict != securityv1alpha1.VerdictApproved {
		t.Fatalf("verdict = %q, want Approved (violations: %v)", eval.Verdict, eval.Violations)
	}
	if eval.RiskScore != 0 {
		t.Errorf("risk score = %d, want 0", eval.RiskScore)
	}
	if eval.MalwareStatus != StatusClean {
		t.Errorf("malware = %q, want Clean", eval.MalwareStatus)
	}
}

func TestMalwareQuarantinesAndSaturatesRisk(t *testing.T) {
	results := []securityv1alpha1.ScannerResult{
		result("clamav", "Failed", securityv1alpha1.SeverityCounts{Critical: 1}),
		result("trivy", "Passed", securityv1alpha1.SeverityCounts{}),
	}

	eval := Evaluate(results, securityv1alpha1.ArtifactRef{}, nil, nil, time.Now())

	if eval.Verdict != securityv1alpha1.VerdictQuarantined {
		t.Errorf("verdict = %q, want Quarantined", eval.Verdict)
	}
	if eval.RiskScore != 100 {
		t.Errorf("risk score = %d, want 100 for confirmed malware", eval.RiskScore)
	}
}

// An incomplete scan must never read as a pass: absence of findings from a
// scanner that never ran is not evidence of safety.
func TestPendingScannerBlocksApproval(t *testing.T) {
	results := []securityv1alpha1.ScannerResult{
		result("clamav", "Passed", securityv1alpha1.SeverityCounts{}),
		result("trivy", "Running", securityv1alpha1.SeverityCounts{}),
	}

	eval := Evaluate(results, securityv1alpha1.ArtifactRef{}, nil, nil, time.Now())

	if eval.Verdict == securityv1alpha1.VerdictApproved {
		t.Fatal("approved an artifact with an incomplete scan")
	}
	if !hasRule(eval.Violations, RuleScanIncomplete) {
		t.Errorf("violations = %v, want a %s violation", eval.Violations, RuleScanIncomplete)
	}
}

func TestCVEThresholds(t *testing.T) {
	limit := int32(0)
	pol := &securityv1alpha1.ArtifactScanPolicy{
		Spec: securityv1alpha1.ArtifactScanPolicySpec{
			Rules: securityv1alpha1.PolicyRules{MaxCriticalCVEs: &limit},
		},
	}
	results := []securityv1alpha1.ScannerResult{
		result("trivy", "Failed", securityv1alpha1.SeverityCounts{Critical: 3, High: 5}),
	}

	eval := Evaluate(results, securityv1alpha1.ArtifactRef{}, pol, nil, time.Now())

	if !hasRule(eval.Violations, RuleMaxCriticalCVEs) {
		t.Errorf("violations = %v, want %s", eval.Violations, RuleMaxCriticalCVEs)
	}
	if eval.Verdict != securityv1alpha1.VerdictQuarantined {
		t.Errorf("verdict = %q, want Quarantined for a critical violation", eval.Verdict)
	}
}

// Trivy and Grype find overlapping CVE sets. Summing them would double-count
// the same vulnerability and inflate the risk score, so the evaluator takes
// the per-severity maximum instead.
func TestOverlappingCVEScannersAreNotDoubleCounted(t *testing.T) {
	results := []securityv1alpha1.ScannerResult{
		result("trivy", "Failed", securityv1alpha1.SeverityCounts{Critical: 2, High: 4}),
		result("grype", "Failed", securityv1alpha1.SeverityCounts{Critical: 2, High: 6}),
	}

	eval := Evaluate(results, securityv1alpha1.ArtifactRef{}, nil, nil, time.Now())

	if eval.CVEs.Critical != 2 {
		t.Errorf("critical CVEs = %d, want 2 (max, not sum)", eval.CVEs.Critical)
	}
	if eval.CVEs.High != 6 {
		t.Errorf("high CVEs = %d, want 6 (max, not sum)", eval.CVEs.High)
	}
}

func TestBlockedFormatQuarantines(t *testing.T) {
	pol := &securityv1alpha1.ArtifactScanPolicy{
		Spec: securityv1alpha1.ArtifactScanPolicySpec{
			Rules: securityv1alpha1.PolicyRules{BlockedFormats: []string{"pickle"}},
		},
	}
	results := []securityv1alpha1.ScannerResult{
		result("clamav", "Passed", securityv1alpha1.SeverityCounts{}),
	}

	eval := Evaluate(results, securityv1alpha1.ArtifactRef{Format: "Pickle"}, pol, nil, time.Now())

	if !hasRule(eval.Violations, RuleBlockedFormats) {
		t.Errorf("violations = %v, want %s (format match must be case-insensitive)",
			eval.Violations, RuleBlockedFormats)
	}
}

func TestAllowedFormatsRejectsUnlisted(t *testing.T) {
	pol := &securityv1alpha1.ArtifactScanPolicy{
		Spec: securityv1alpha1.ArtifactScanPolicySpec{
			Rules: securityv1alpha1.PolicyRules{AllowedFormats: []string{"safetensors", "onnx"}},
		},
	}
	results := []securityv1alpha1.ScannerResult{
		result("clamav", "Passed", securityv1alpha1.SeverityCounts{}),
	}

	eval := Evaluate(results, securityv1alpha1.ArtifactRef{Format: "pytorch"}, pol, nil, time.Now())

	if !hasRule(eval.Violations, RuleAllowedFormats) {
		t.Errorf("violations = %v, want %s", eval.Violations, RuleAllowedFormats)
	}
}

func TestUnexpiredExceptionWaivesViolation(t *testing.T) {
	limit := int32(0)
	pol := &securityv1alpha1.ArtifactScanPolicy{
		Spec: securityv1alpha1.ArtifactScanPolicySpec{
			Rules: securityv1alpha1.PolicyRules{MaxCriticalCVEs: &limit},
		},
	}
	results := []securityv1alpha1.ScannerResult{
		result("trivy", "Failed", securityv1alpha1.SeverityCounts{Critical: 1}),
	}
	future := metav1.NewTime(time.Now().Add(24 * time.Hour))
	exceptions := []securityv1alpha1.ArtifactException{{
		Spec: securityv1alpha1.ArtifactExceptionSpec{
			Rules:     []string{RuleMaxCriticalCVEs},
			Reason:    "accepted risk pending upstream fix",
			ExpiresAt: &future,
		},
	}}

	eval := Evaluate(results, securityv1alpha1.ArtifactRef{}, pol, exceptions, time.Now())

	if hasRule(eval.Violations, RuleMaxCriticalCVEs) {
		t.Errorf("violation was not waived: %v", eval.Violations)
	}
	if !hasRule(eval.Waived, RuleMaxCriticalCVEs) {
		t.Errorf("waived = %v, want the CVE violation recorded as waived", eval.Waived)
	}
	if eval.Verdict != securityv1alpha1.VerdictApproved {
		t.Errorf("verdict = %q, want Approved once the only violation is waived", eval.Verdict)
	}
}

// An expired exception must stop waiving, or exceptions become permanent.
func TestExpiredExceptionDoesNotWaive(t *testing.T) {
	limit := int32(0)
	pol := &securityv1alpha1.ArtifactScanPolicy{
		Spec: securityv1alpha1.ArtifactScanPolicySpec{
			Rules: securityv1alpha1.PolicyRules{MaxCriticalCVEs: &limit},
		},
	}
	results := []securityv1alpha1.ScannerResult{
		result("trivy", "Failed", securityv1alpha1.SeverityCounts{Critical: 1}),
	}
	past := metav1.NewTime(time.Now().Add(-24 * time.Hour))
	exceptions := []securityv1alpha1.ArtifactException{{
		Spec: securityv1alpha1.ArtifactExceptionSpec{
			Rules:     []string{RuleMaxCriticalCVEs},
			Reason:    "expired waiver",
			ExpiresAt: &past,
		},
	}}

	eval := Evaluate(results, securityv1alpha1.ArtifactRef{}, pol, exceptions, time.Now())

	if !hasRule(eval.Violations, RuleMaxCriticalCVEs) {
		t.Errorf("expired exception still waived the violation: %v", eval.Violations)
	}
}

func TestRequireSignatureFailsWithoutProvenance(t *testing.T) {
	pol := &securityv1alpha1.ArtifactScanPolicy{
		Spec: securityv1alpha1.ArtifactScanPolicySpec{
			Rules: securityv1alpha1.PolicyRules{RequireSignature: true},
		},
	}
	results := []securityv1alpha1.ScannerResult{
		result("clamav", "Passed", securityv1alpha1.SeverityCounts{}),
	}

	eval := Evaluate(results, securityv1alpha1.ArtifactRef{}, pol, nil, time.Now())

	if !hasRule(eval.Violations, RuleRequireSignature) {
		t.Errorf("violations = %v, want %s", eval.Violations, RuleRequireSignature)
	}
	if eval.SignatureVerified {
		t.Error("signature reported verified with no provenance scanner result")
	}
}

func TestVerifiedSecretsBlock(t *testing.T) {
	results := []securityv1alpha1.ScannerResult{
		result("trufflehog", "Failed", securityv1alpha1.SeverityCounts{Critical: 1}),
		result("clamav", "Passed", securityv1alpha1.SeverityCounts{}),
	}

	eval := Evaluate(results, securityv1alpha1.ArtifactRef{}, nil, nil, time.Now())

	if eval.SecretsStatus != StatusDetected {
		t.Errorf("secrets = %q, want Detected", eval.SecretsStatus)
	}
	if !hasRule(eval.Violations, RuleBlockSecrets) {
		t.Errorf("violations = %v, want %s blocked by default", eval.Violations, RuleBlockSecrets)
	}
}

func TestRiskScoreIsBounded(t *testing.T) {
	results := []securityv1alpha1.ScannerResult{
		result("trivy", "Failed", securityv1alpha1.SeverityCounts{Critical: 50, High: 200}),
		result("trufflehog", "Failed", securityv1alpha1.SeverityCounts{Critical: 10}),
	}

	eval := Evaluate(results, securityv1alpha1.ArtifactRef{}, nil, nil, time.Now())

	if eval.RiskScore > 100 {
		t.Errorf("risk score = %d, want it clamped to 100", eval.RiskScore)
	}
}

func hasRule(violations []Violation, rule string) bool {
	for _, v := range violations {
		if v.Rule == rule {
			return true
		}
	}
	return false
}

func TestCriticalModelFindingQuarantinesByDefault(t *testing.T) {
	results := []securityv1alpha1.ScannerResult{
		result("model-inspector", "Failed", securityv1alpha1.SeverityCounts{Critical: 1}),
		result("clamav", "Passed", securityv1alpha1.SeverityCounts{}),
	}

	eval := Evaluate(results, securityv1alpha1.ArtifactRef{}, nil, nil, time.Now())

	if !hasRule(eval.Violations, RuleBlockUnsafeModel) {
		t.Errorf("violations = %v, want %s enforced by default", eval.Violations, RuleBlockUnsafeModel)
	}
	if eval.Verdict != securityv1alpha1.VerdictQuarantined {
		t.Errorf("verdict = %q, want Quarantined", eval.Verdict)
	}
}

// Model findings outweigh a CVE of the same severity: unsafe deserialization
// is already-working code execution, not a bug something else has to reach.
func TestModelFindingsOutweighEquivalentCVEs(t *testing.T) {
	modelRisk := Evaluate(
		[]securityv1alpha1.ScannerResult{
			result("model-inspector", "Failed", securityv1alpha1.SeverityCounts{Critical: 1}),
		},
		securityv1alpha1.ArtifactRef{}, nil, nil, time.Now()).RiskScore

	cveRisk := Evaluate(
		[]securityv1alpha1.ScannerResult{
			result("trivy", "Failed", securityv1alpha1.SeverityCounts{Critical: 1}),
		},
		securityv1alpha1.ArtifactRef{}, nil, nil, time.Now()).RiskScore

	if modelRisk <= cveRisk {
		t.Errorf("model risk %d does not exceed CVE risk %d for the same severity", modelRisk, cveRisk)
	}
}

func TestBlockUnsafeModelCanBeDisabled(t *testing.T) {
	disabled := false
	pol := &securityv1alpha1.ArtifactScanPolicy{
		Spec: securityv1alpha1.ArtifactScanPolicySpec{
			Rules: securityv1alpha1.PolicyRules{BlockUnsafeModel: &disabled},
		},
	}
	results := []securityv1alpha1.ScannerResult{
		result("model-inspector", "Failed", securityv1alpha1.SeverityCounts{Critical: 1}),
	}

	eval := Evaluate(results, securityv1alpha1.ArtifactRef{}, pol, nil, time.Now())

	if hasRule(eval.Violations, RuleBlockUnsafeModel) {
		t.Errorf("rule still enforced after being disabled: %v", eval.Violations)
	}
}
