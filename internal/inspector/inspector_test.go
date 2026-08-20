package inspector

import (
	"os"
	"path/filepath"
	"testing"
)

// The analysis is tested in the library. What has to be tested here is the
// boundary: that a walk's findings arrive in the operator's vocabulary with
// nothing dropped, and that the flags a verdict depends on survive the crossing.
func TestAdapterCarriesFindingsIntoTheResourceShape(t *testing.T) {
	dir := t.TempDir()
	payload, err := os.ReadFile(filepath.Join("testdata", "evil_proto4.pkl"))
	if err != nil {
		t.Skipf("fixture unavailable: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "weights.pkl"), payload, 0o644); err != nil {
		t.Fatal(err)
	}

	report, err := Inspect(dir, DefaultLimits())
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if len(report.Findings) == 0 {
		t.Fatal("no findings crossed the boundary; a malicious pickle produced an empty report")
	}

	var critical bool
	for _, f := range report.Findings {
		if f.ID == "" || f.Title == "" || f.Severity == "" {
			t.Errorf("finding lost a required field in conversion: %+v", f)
		}
		if f.Severity == "Critical" {
			critical = true
		}
	}
	if !critical {
		t.Error("the pickle's Critical finding did not survive; the gate reads severity to quarantine")
	}
	if report.FilesScanned == 0 {
		t.Error("FilesScanned did not cross; a scan that examined nothing looks identical to a clean one")
	}
}

// Truncation is the flag that stops a partial walk reading as a clean result.
// It has to survive the adapter or the operator loses the distinction.
func TestTruncationSurvivesTheBoundary(t *testing.T) {
	dir := t.TempDir()
	for i := range 12 {
		name := filepath.Join(dir, string(rune('a'+i))+".bin")
		if err := os.WriteFile(name, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	limits := DefaultLimits()
	limits.MaxFiles = 3

	report, err := Inspect(dir, limits)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if report.FilesScanned > 3 {
		t.Errorf("scanned %d files under a cap of 3; the adapter dropped the caller's limits",
			report.FilesScanned)
	}
	if !report.Truncated {
		t.Error("a walk stopped by its file cap must report Truncated across the boundary; " +
			"without it the operator reads a partial scan as a clean one")
	}
}
