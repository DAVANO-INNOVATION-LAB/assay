package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/assay/api/v1alpha1"
	"github.com/DAVANO-INNOVATION-LAB/assay/internal/inspector"
	"github.com/DAVANO-INNOVATION-LAB/assay/internal/policy"
	"time"
)

// evaluate mirrors runInspect's core: inspect a path, then feed the findings
// through the policy engine. Tests assert on the verdict the CLI would map to
// an exit code, without spawning a subprocess.
func evaluate(t *testing.T, path string) policy.Evaluation {
	t.Helper()
	report, err := inspector.Inspect(path, inspector.DefaultLimits())
	if err != nil {
		t.Fatalf("inspect %s: %v", path, err)
	}
	result := securityv1alpha1.ScannerResult{
		Scanner:    "model-inspector",
		Status:     "Passed",
		Findings:   int32(len(report.Findings)),
		Severities: countSeverities(report.Findings),
	}
	if len(report.Findings) > 0 {
		result.Status = "Failed"
	}
	return policy.Evaluate(
		[]securityv1alpha1.ScannerResult{result},
		securityv1alpha1.ArtifactRef{URI: path, Format: primaryFormat(report.Formats)},
		nil, nil, time.Now(),
	)
}

func TestInspectVerdicts(t *testing.T) {
	dir := t.TempDir()

	// A malicious pickle: GLOBAL-form reference to os.system. Using the
	// inline "module\nattr\n" encoding keeps the fixture Python-free.
	evil := filepath.Join(dir, "evil.pkl")
	writeFile(t, evil, []byte("\x80\x04cos\nsystem\nq\x00."))

	// A clean safetensors header: 8-byte little-endian length + minimal JSON.
	good := filepath.Join(dir, "model.safetensors")
	header := []byte(`{"__metadata__":{}}`)
	buf := make([]byte, 8+len(header))
	buf[0] = byte(len(header))
	copy(buf[8:], header)
	writeFile(t, good, buf)

	if v := evaluate(t, evil).Verdict; v != securityv1alpha1.VerdictQuarantined {
		t.Errorf("evil pickle: verdict = %q, want Quarantined", v)
	}
	if v := evaluate(t, good).Verdict; v != securityv1alpha1.VerdictApproved {
		t.Errorf("clean safetensors: verdict = %q, want Approved", v)
	}
}

func TestCountSeverities(t *testing.T) {
	findings := []securityv1alpha1.Finding{
		{Severity: "Critical"}, {Severity: "High"}, {Severity: "High"},
		{Severity: "Medium"}, {Severity: "Low"}, {Severity: "weird"},
	}
	got := countSeverities(findings)
	if got.Critical != 1 || got.High != 2 || got.Medium != 1 || got.Low != 1 || got.Unknown != 1 {
		t.Errorf("countSeverities = %+v", got)
	}
}

func TestJSONOutputShape(t *testing.T) {
	// The JSON contract is what CI gates parse; guard the field names.
	out := jsonOutput{Verdict: "Quarantined", RiskScore: 60}
	data, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	var round map[string]any
	if err := json.Unmarshal(data, &round); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"verdict", "riskScore", "severities", "findings", "assayVersion"} {
		if _, ok := round[key]; !ok {
			t.Errorf("JSON output missing %q field", key)
		}
	}
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}
