// Package policy evaluates scan results against an ArtifactScanPolicy to
// produce a verdict and a risk score. It is pure: no cluster access, no I/O,
// so both the scan controller and the admission webhook can call it.
package policy

import (
	"fmt"
	"sort"
	"strings"
	"time"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/assay/api/v1alpha1"
	"github.com/DAVANO-INNOVATION-LAB/assay/internal/scanners"
)

// Evaluation is the outcome of applying a policy to a set of scan results.
type Evaluation struct {
	// Verdict is Approved, Quarantined, or ReviewRequired.
	Verdict string
	// RiskScore is 0 (clean) to 100 (critical risk).
	RiskScore int32
	// Violations are the policy rules the artifact failed.
	Violations []Violation
	// Waived are violations suppressed by an ArtifactException.
	Waived []Violation
	// CVEs aggregated across all vulnerability scanners.
	CVEs securityv1alpha1.SeverityCounts
	// ModelFindings are the model-inspection results: unsafe serialization,
	// archive escapes, code-executing configs. These are what distinguish a
	// model scan from a container scan, so they carry their own weight.
	ModelFindings securityv1alpha1.SeverityCounts
	// MalwareStatus is Clean, Detected, or Unknown.
	MalwareStatus string
	// SecretsStatus is Clean, Detected, or Unknown.
	SecretsStatus string
	// SignatureVerified reports whether provenance verification passed.
	SignatureVerified bool
	// ProvenanceChecked reports whether a provenance scanner actually ran.
	// Unverified and unmeasured are different states: only the former is
	// evidence of risk.
	ProvenanceChecked bool
}

// Violation is a single failed policy rule.
type Violation struct {
	// Rule is the policy field that failed (e.g. maxCriticalCVEs).
	Rule string
	// Message explains the failure in user-facing terms.
	Message string
	// Severity of the violation.
	Severity string
}

func (v Violation) String() string { return fmt.Sprintf("%s: %s", v.Rule, v.Message) }

// Rule names, also used as ArtifactException.spec.rules values.
const (
	RuleMaxCriticalCVEs   = "maxCriticalCVEs"
	RuleMaxHighCVEs       = "maxHighCVEs"
	RuleBlockMalware      = "blockMalware"
	RuleBlockSecrets      = "blockSecrets"
	RuleBlockUnsafeModel  = "blockUnsafeModel"
	RuleRequireSignature  = "requireSignature"
	RuleRequireSBOM       = "requireSBOM"
	RuleRequireProvenance = "requireProvenance"
	RuleAllowedFormats    = "allowedFormats"
	RuleBlockedFormats    = "blockedFormats"
	RuleScanIncomplete    = "scanIncomplete"
)

// Status values for the malware and secrets summaries.
const (
	StatusClean    = "Clean"
	StatusDetected = "Detected"
	StatusUnknown  = "Unknown"
)

// Evaluate applies the policy to scan results for an artifact. A nil policy
// uses conservative built-in defaults: block malware and secrets, allow CVEs.
func Evaluate(
	results []securityv1alpha1.ScannerResult,
	artifact securityv1alpha1.ArtifactRef,
	pol *securityv1alpha1.ArtifactScanPolicy,
	exceptions []securityv1alpha1.ArtifactException,
	now time.Time,
) Evaluation {
	rules := effectiveRules(pol)
	byCategory := groupByCategory(results)

	eval := Evaluation{
		MalwareStatus: statusFor(byCategory[scanners.CategoryMalware]),
		SecretsStatus: statusFor(byCategory[scanners.CategorySecret]),
		CVEs:          sumSeverities(byCategory[scanners.CategoryCVE]),
		ModelFindings: sumSeverities(byCategory[scanners.CategoryModel]),
	}
	eval.ProvenanceChecked = hasCategory(byCategory, scanners.CategoryProvenance)
	eval.SignatureVerified = allPassed(byCategory[scanners.CategoryProvenance])

	var violations []Violation

	// An incomplete scan is itself a policy failure: absence of findings is
	// not evidence of safety.
	if incomplete := incompleteScanners(results); len(incomplete) > 0 {
		violations = append(violations, Violation{
			Rule:     RuleScanIncomplete,
			Severity: "High",
			Message:  fmt.Sprintf("scanners did not complete: %s", strings.Join(incomplete, ", ")),
		})
	}

	if boolValue(rules.BlockMalware, true) && eval.MalwareStatus == StatusDetected {
		violations = append(violations, Violation{
			Rule:     RuleBlockMalware,
			Severity: "Critical",
			Message:  fmt.Sprintf("malware detected (%d findings)", countFindings(byCategory[scanners.CategoryMalware])),
		})
	}

	if boolValue(rules.BlockSecrets, true) && eval.SecretsStatus == StatusDetected {
		violations = append(violations, Violation{
			Rule:     RuleBlockSecrets,
			Severity: "High",
			Message:  fmt.Sprintf("embedded secrets detected (%d findings)", countFindings(byCategory[scanners.CategorySecret])),
		})
	}

	// A critical model-inspection finding means the artifact executes code
	// when it is loaded. That is disqualifying on its own, independent of any
	// format allow-list a policy happens to configure.
	if boolValue(rules.BlockUnsafeModel, true) && eval.ModelFindings.Critical > 0 {
		violations = append(violations, Violation{
			Rule:     RuleBlockUnsafeModel,
			Severity: "Critical",
			Message: fmt.Sprintf("%d critical model-inspection finding(s): the artifact executes code on load",
				eval.ModelFindings.Critical),
		})
	}

	if rules.MaxCriticalCVEs != nil && eval.CVEs.Critical > *rules.MaxCriticalCVEs {
		violations = append(violations, Violation{
			Rule:     RuleMaxCriticalCVEs,
			Severity: "Critical",
			Message:  fmt.Sprintf("%d critical CVEs exceeds limit of %d", eval.CVEs.Critical, *rules.MaxCriticalCVEs),
		})
	}

	if rules.MaxHighCVEs != nil && eval.CVEs.High > *rules.MaxHighCVEs {
		violations = append(violations, Violation{
			Rule:     RuleMaxHighCVEs,
			Severity: "High",
			Message:  fmt.Sprintf("%d high CVEs exceeds limit of %d", eval.CVEs.High, *rules.MaxHighCVEs),
		})
	}

	if rules.RequireSignature && !eval.SignatureVerified {
		violations = append(violations, Violation{
			Rule:     RuleRequireSignature,
			Severity: "High",
			Message:  "no verified signature from a trusted publisher",
		})
	}

	if rules.RequireProvenance && !hasCategory(byCategory, scanners.CategoryProvenance) {
		violations = append(violations, Violation{
			Rule:     RuleRequireProvenance,
			Severity: "Medium",
			Message:  "provenance attestation is required but was not verified",
		})
	}

	if rules.RequireSBOM && !hasCategory(byCategory, scanners.CategorySBOM) {
		violations = append(violations, Violation{
			Rule:     RuleRequireSBOM,
			Severity: "Medium",
			Message:  "SBOM is required but was not generated",
		})
	}

	if format := strings.ToLower(artifact.Format); format != "" {
		if len(rules.AllowedFormats) > 0 && !containsFold(rules.AllowedFormats, format) {
			violations = append(violations, Violation{
				Rule:     RuleAllowedFormats,
				Severity: "High",
				Message:  fmt.Sprintf("model format %q is not in the allowed list %v", artifact.Format, rules.AllowedFormats),
			})
		}
		if containsFold(rules.BlockedFormats, format) {
			violations = append(violations, Violation{
				Rule:     RuleBlockedFormats,
				Severity: "Critical",
				Message:  fmt.Sprintf("model format %q is blocked by policy", artifact.Format),
			})
		}
	}

	eval.Violations, eval.Waived = applyExceptions(violations, exceptions, now)
	eval.RiskScore = riskScore(eval)
	eval.Verdict = verdict(eval)
	return eval
}

// applyExceptions splits violations into enforced and waived.
func applyExceptions(violations []Violation, exceptions []securityv1alpha1.ArtifactException, now time.Time) (enforced, waived []Violation) {
	waivedRules := map[string]bool{}
	for _, ex := range exceptions {
		if ex.Spec.ExpiresAt != nil && now.After(ex.Spec.ExpiresAt.Time) {
			continue
		}
		for _, rule := range ex.Spec.Rules {
			waivedRules[rule] = true
		}
	}
	for _, v := range violations {
		if waivedRules[v.Rule] {
			waived = append(waived, v)
			continue
		}
		enforced = append(enforced, v)
	}
	return enforced, waived
}

// riskScore maps findings onto 0-100. Malware saturates the score because a
// single confirmed detection is disqualifying regardless of anything else.
func riskScore(eval Evaluation) int32 {
	if eval.MalwareStatus == StatusDetected {
		return 100
	}

	score := 0
	score += int(eval.CVEs.Critical) * 20
	score += int(eval.CVEs.High) * 8
	score += int(eval.CVEs.Medium) * 2
	score += int(eval.CVEs.Low)

	// Model-level findings are weighted above CVEs of the same severity: a
	// pickle that imports os.system is already-working code execution, not a
	// vulnerability that something else still has to reach.
	score += int(eval.ModelFindings.Critical) * 35
	score += int(eval.ModelFindings.High) * 12
	score += int(eval.ModelFindings.Medium) * 3

	if eval.SecretsStatus == StatusDetected {
		score += 40
	}
	// Only penalize provenance when it was actually checked and did not
	// verify. If no provenance scanner ran, that dimension is unmeasured, and
	// the requireSignature/requireProvenance rules are what force the issue.
	if eval.ProvenanceChecked && !eval.SignatureVerified {
		score += 10
	}
	for _, v := range eval.Violations {
		switch v.Severity {
		case "Critical":
			score += 25
		case "High":
			score += 10
		default:
			score += 3
		}
	}

	if score > 100 {
		score = 100
	}
	return int32(score)
}

func verdict(eval Evaluation) string {
	if len(eval.Violations) == 0 {
		return securityv1alpha1.VerdictApproved
	}
	for _, v := range eval.Violations {
		if v.Severity == "Critical" {
			return securityv1alpha1.VerdictQuarantined
		}
	}
	return securityv1alpha1.VerdictReviewRequired
}

func effectiveRules(pol *securityv1alpha1.ArtifactScanPolicy) securityv1alpha1.PolicyRules {
	if pol == nil {
		return securityv1alpha1.PolicyRules{}
	}
	return pol.Spec.Rules
}

func groupByCategory(results []securityv1alpha1.ScannerResult) map[scanners.Category][]securityv1alpha1.ScannerResult {
	grouped := map[scanners.Category][]securityv1alpha1.ScannerResult{}
	for _, r := range results {
		def, err := scanners.Get(r.Scanner)
		if err != nil {
			continue
		}
		grouped[def.Category] = append(grouped[def.Category], r)
	}
	return grouped
}

func statusFor(results []securityv1alpha1.ScannerResult) string {
	if len(results) == 0 {
		return StatusUnknown
	}
	sawCompleted := false
	for _, r := range results {
		if r.Findings > 0 {
			return StatusDetected
		}
		if r.Status == "Passed" || r.Status == "Failed" {
			sawCompleted = true
		}
	}
	if !sawCompleted {
		return StatusUnknown
	}
	return StatusClean
}

func sumSeverities(results []securityv1alpha1.ScannerResult) securityv1alpha1.SeverityCounts {
	// Multiple CVE scanners overlap heavily, so take the per-severity maximum
	// rather than the sum. Summing would double-count the same CVE found by
	// both Trivy and Grype and inflate the risk score.
	var total securityv1alpha1.SeverityCounts
	for _, r := range results {
		total.Critical = max32(total.Critical, r.Severities.Critical)
		total.High = max32(total.High, r.Severities.High)
		total.Medium = max32(total.Medium, r.Severities.Medium)
		total.Low = max32(total.Low, r.Severities.Low)
		total.Unknown = max32(total.Unknown, r.Severities.Unknown)
	}
	return total
}

func incompleteScanners(results []securityv1alpha1.ScannerResult) []string {
	var incomplete []string
	for _, r := range results {
		switch r.Status {
		case "Passed", "Failed", "Skipped":
			continue
		default:
			incomplete = append(incomplete, r.Scanner)
		}
	}
	sort.Strings(incomplete)
	return incomplete
}

func allPassed(results []securityv1alpha1.ScannerResult) bool {
	if len(results) == 0 {
		return false
	}
	for _, r := range results {
		if r.Status != "Passed" || r.Findings > 0 {
			return false
		}
	}
	return true
}

func hasCategory(grouped map[scanners.Category][]securityv1alpha1.ScannerResult, cat scanners.Category) bool {
	for _, r := range grouped[cat] {
		if r.Status == "Passed" || r.Status == "Failed" {
			return true
		}
	}
	return false
}

func countFindings(results []securityv1alpha1.ScannerResult) int32 {
	var total int32
	for _, r := range results {
		total += r.Findings
	}
	return total
}

func containsFold(list []string, value string) bool {
	for _, item := range list {
		if strings.EqualFold(item, value) {
			return true
		}
	}
	return false
}

func boolValue(p *bool, fallback bool) bool {
	if p == nil {
		return fallback
	}
	return *p
}

func max32(a, b int32) int32 {
	if a > b {
		return a
	}
	return b
}
