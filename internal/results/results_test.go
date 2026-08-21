package results

import (
	"os"
	"path/filepath"
	"testing"
)

// The parsers are tested in the library. What matters here is the boundary:
// that findings arrive in the resource shape with nothing dropped, and that a
// failure to read output is reported as an error rather than as an empty result
// — a scanner that found nothing and a scanner whose output could not be parsed
// are opposite facts that look identical once the list is empty.
func TestParseCarriesFindingsIntoTheResourceShape(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "clamav.txt")
	body := "/scan/weights.pkl: Unix.Trojan.Test FOUND\n" +
		"----------- SCAN SUMMARY -----------\nInfected files: 1\n"
	if err := os.WriteFile(out, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	parsed, err := Parse(FormatClamAV, out)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(parsed.Findings) == 0 {
		t.Fatal("a detected trojan produced no findings across the boundary")
	}
	for _, f := range parsed.Findings {
		if f.ID == "" || f.Severity == "" {
			t.Errorf("finding lost a required field in conversion: %+v", f)
		}
	}
	if parsed.Severities.Total() == 0 {
		t.Error("severity counts did not cross; the gate weighs these into the verdict")
	}
}

func TestMissingOutputIsFlaggedAbsentRatherThanClean(t *testing.T) {
	dir := t.TempDir()
	p, err := Parse(FormatTrivyJSON, filepath.Join(dir, "absent.json"))
	if err != nil {
		t.Fatalf("a missing file must not be an error: a clean scanner may write none (%v)", err)
	}
	if !p.Absent {
		t.Error("Absent did not cross the boundary; the runner cannot tell a clean scan " +
			"from a scanner that crashed before writing")
	}
}

func TestUnreadableOutputIsAnError(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(FormatTrivyJSON, bad); err == nil {
		t.Error("malformed scanner output parsed successfully; it would look like a clean scan")
	}
}

func TestUnknownFormatIsRejected(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "x.json")
	if err := os.WriteFile(f, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Parse("not-a-scanner", f); err == nil {
		t.Error("an unknown format was accepted; reading one scanner's output as another's " +
			"produces a confidently wrong finding list rather than an error")
	}
}
