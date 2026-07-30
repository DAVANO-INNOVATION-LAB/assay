package results

import (
	"testing"

	"github.com/zeus-security/zeus-operator/internal/scanners"
)

// The fixtures in testdata/ are verbatim output from the real scanner images
// (scanners/*/Dockerfile) run against a known-bad model artifact. The
// hand-written tests in parse_test.go check the shapes the parsers expect;
// these check the shapes the tools actually emit, which is the only way to
// catch a format assumption that was wrong from the start.
//
// Regenerate with: make scanner-fixtures

func TestParsesRealClamAVOutput(t *testing.T) {
	parsed, err := Parse(scanners.FormatClamAV, "testdata/real_clamav.txt")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if parsed.Severities.Critical != 1 {
		t.Fatalf("critical = %d, want the EICAR detection (findings: %+v)",
			parsed.Severities.Critical, parsed.Findings)
	}
	f := parsed.Findings[0]
	if f.ID != "Eicar-Test-Signature" {
		t.Errorf("ID = %q, want the ClamAV signature name", f.ID)
	}
	if f.Location != "/workspace/suspicious.dat" {
		t.Errorf("location = %q, want the infected file path", f.Location)
	}
}

func TestParsesRealTrivyOutput(t *testing.T) {
	parsed, err := Parse(scanners.FormatTrivyJSON, "testdata/real_trivy.json")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	// The fixture pins vulnerable versions of pillow, torch, transformers,
	// requests, and pyyaml, plus three planted credentials.
	if parsed.Severities.Critical == 0 {
		t.Error("no critical findings parsed from real Trivy output")
	}
	if parsed.Severities.Total() < 50 {
		t.Errorf("parsed %d findings, want the full vulnerability set (>=50)",
			parsed.Severities.Total())
	}

	var sawCVE, sawSecret bool
	for _, f := range parsed.Findings {
		switch f.Category {
		case string(scanners.CategoryCVE):
			sawCVE = true
			if f.ID == "" {
				t.Error("a CVE finding parsed with no vulnerability ID")
			}
			if f.Location == "" {
				t.Errorf("CVE %s parsed with no location", f.ID)
			}
		case string(scanners.CategorySecret):
			sawSecret = true
		}
	}
	if !sawCVE {
		t.Error("no CVE-category findings parsed from real Trivy output")
	}
	// Trivy reports secrets in the same document as vulnerabilities; if the
	// parser only walked Vulnerabilities, planted credentials would vanish.
	if !sawSecret {
		t.Error("no secret-category findings parsed; Trivy's Secrets array was missed")
	}
}

func TestParsesRealTrufflehogOutput(t *testing.T) {
	parsed, err := Parse(scanners.FormatTrufflehog, "testdata/real_trufflehog.json")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if parsed.Severities.Total() < 2 {
		t.Fatalf("parsed %d findings, want the planted AWS and GitHub credentials",
			parsed.Severities.Total())
	}

	detectors := map[string]bool{}
	for _, f := range parsed.Findings {
		detectors[f.ID] = true
		if f.Location == "" {
			t.Errorf("finding %q parsed with no location", f.ID)
		}
		if f.Category != string(scanners.CategorySecret) {
			t.Errorf("finding %q has category %q, want secret", f.ID, f.Category)
		}
	}
	for _, want := range []string{"AWS", "Github"} {
		if !detectors[want] {
			t.Errorf("detector %q missing; parsed detectors: %v", want, detectors)
		}
	}
}

// Syft output is evidence that the SBOM requirement was met, not a finding.
// Parsing it must succeed and must not manufacture findings.
func TestParsesRealSyftOutput(t *testing.T) {
	parsed, err := Parse(scanners.FormatSyftSPDX, "testdata/real_syft_spdx.json")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if parsed.Severities.Total() != 0 {
		t.Errorf("SBOM parsing produced %d findings, want 0", parsed.Severities.Total())
	}
}
