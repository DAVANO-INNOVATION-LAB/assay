package results

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/JUMP1ST/assay/internal/scanners"
)

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// A scanner that found nothing may not write a file at all. That must read as
// a clean result, not an error.
func TestMissingOutputFileIsClean(t *testing.T) {
	parsed, err := Parse(scanners.FormatTrivyJSON, filepath.Join(t.TempDir(), "absent.json"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if parsed.Severities.Total() != 0 {
		t.Errorf("findings = %d, want 0", parsed.Severities.Total())
	}
}

func TestEmptyOutputIsClean(t *testing.T) {
	for _, format := range []string{
		scanners.FormatAssay, scanners.FormatClamAV, scanners.FormatTrivyJSON,
		scanners.FormatGrypeJSON, scanners.FormatSyftSPDX, scanners.FormatTrufflehog,
	} {
		t.Run(format, func(t *testing.T) {
			parsed, err := Parse(format, writeFile(t, "out", ""))
			if err != nil {
				t.Fatalf("Parse(%s): %v", format, err)
			}
			if parsed.Severities.Total() != 0 {
				t.Errorf("findings = %d, want 0", parsed.Severities.Total())
			}
		})
	}
}

func TestParseClamAV(t *testing.T) {
	output := `/workspace/model.pkl: Unix.Trojan.Generic-1234 FOUND
/workspace/config.json: OK

----------- SCAN SUMMARY -----------
Infected files: 1
`
	parsed, err := Parse(scanners.FormatClamAV, writeFile(t, "clamav.txt", output))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if got := parsed.Severities.Total(); got != 1 {
		t.Fatalf("findings = %d, want 1", got)
	}
	if parsed.Severities.Critical != 1 {
		t.Errorf("critical = %d, want 1 (malware is always critical)", parsed.Severities.Critical)
	}
	if parsed.Findings[0].ID != "Unix.Trojan.Generic-1234" {
		t.Errorf("ID = %q, want the signature name", parsed.Findings[0].ID)
	}
	if parsed.Findings[0].Location != "/workspace/model.pkl" {
		t.Errorf("location = %q, want the infected path", parsed.Findings[0].Location)
	}
}

// The scan summary block also contains the word FOUND in some locales; only
// lines with the "path: signature FOUND" shape are findings.
func TestParseClamAVIgnoresSummaryLines(t *testing.T) {
	output := "----------- SCAN SUMMARY -----------\nInfected files: 0\nData scanned: 1.20 MB\n"

	parsed, err := Parse(scanners.FormatClamAV, writeFile(t, "clamav.txt", output))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if parsed.Severities.Total() != 0 {
		t.Errorf("findings = %d, want 0 for a clean scan", parsed.Severities.Total())
	}
}

func TestParseTrivy(t *testing.T) {
	output := `{
  "Results": [
    {
      "Target": "requirements.txt",
      "Vulnerabilities": [
        {"VulnerabilityID":"CVE-2024-1111","PkgName":"torch","InstalledVersion":"2.0.0","FixedVersion":"2.2.0","Severity":"CRITICAL","Title":"RCE in torch"},
        {"VulnerabilityID":"CVE-2024-2222","PkgName":"numpy","InstalledVersion":"1.20.0","Severity":"HIGH","Title":"Overflow"},
        {"VulnerabilityID":"CVE-2024-3333","PkgName":"idna","InstalledVersion":"3.0","Severity":"LOW","Title":"DoS"}
      ]
    }
  ]
}`
	parsed, err := Parse(scanners.FormatTrivyJSON, writeFile(t, "trivy.json", output))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if parsed.Severities.Critical != 1 || parsed.Severities.High != 1 || parsed.Severities.Low != 1 {
		t.Errorf("severities = %+v, want 1 critical, 1 high, 1 low", parsed.Severities)
	}
	if len(parsed.Findings) != 3 {
		t.Fatalf("findings = %d, want 3", len(parsed.Findings))
	}
	if parsed.Findings[0].Severity != "Critical" {
		t.Errorf("severity = %q, want it normalized to Critical", parsed.Findings[0].Severity)
	}
}

func TestParseGrype(t *testing.T) {
	output := `{
  "matches": [
    {
      "vulnerability": {"id":"CVE-2024-9999","severity":"Critical","description":"bad"},
      "artifact": {"name":"transformers","version":"4.0.0","locations":[{"path":"/workspace/lib/transformers"}]}
    }
  ]
}`
	parsed, err := Parse(scanners.FormatGrypeJSON, writeFile(t, "grype.json", output))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if parsed.Severities.Critical != 1 {
		t.Errorf("critical = %d, want 1", parsed.Severities.Critical)
	}
	if parsed.Findings[0].Location != "/workspace/lib/transformers" {
		t.Errorf("location = %q, want the artifact path", parsed.Findings[0].Location)
	}
}

// A verified secret has been confirmed live against the issuing service, so it
// outranks an unverified pattern match.
func TestParseTrufflehogEscalatesVerifiedSecrets(t *testing.T) {
	output := `{"DetectorName":"AWS","Verified":true,"SourceMetadata":{"Data":{"Filesystem":{"file":"/workspace/train.py","line":12}}}}
{"DetectorName":"Slack","Verified":false,"SourceMetadata":{"Data":{"Filesystem":{"file":"/workspace/notes.md","line":3}}}}
`
	parsed, err := Parse(scanners.FormatTrufflehog, writeFile(t, "th.json", output))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if parsed.Severities.Critical != 1 {
		t.Errorf("critical = %d, want 1 for the verified secret", parsed.Severities.Critical)
	}
	if parsed.Severities.High != 1 {
		t.Errorf("high = %d, want 1 for the unverified secret", parsed.Severities.High)
	}
	if parsed.Findings[0].Location != "/workspace/train.py:12" {
		t.Errorf("location = %q, want file:line", parsed.Findings[0].Location)
	}
}

// TruffleHog interleaves progress lines with JSON. A malformed line must not
// abort parsing and lose the real findings.
func TestParseTrufflehogSkipsNonJSONLines(t *testing.T) {
	output := `🐷 scanning...
{"DetectorName":"AWS","Verified":true,"SourceMetadata":{"Data":{"Filesystem":{"file":"a.py","line":1}}}}
{broken json
{"DetectorName":"GitHub","Verified":false,"SourceMetadata":{"Data":{"Filesystem":{"file":"b.py","line":2}}}}
`
	parsed, err := Parse(scanners.FormatTrufflehog, writeFile(t, "th.json", output))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if parsed.Severities.Total() != 2 {
		t.Errorf("findings = %d, want both valid records", parsed.Severities.Total())
	}
}

func TestParseAssayNativeFormat(t *testing.T) {
	output := `{"findings":[
    {"id":"ASSAY-PICKLE-001","title":"Pickle RCE","severity":"Critical","category":"model","location":"model.pkl"},
    {"id":"ASSAY-EXEC-001","title":"Executable","severity":"Medium","category":"model","location":"run.sh"}
]}`
	parsed, err := Parse(scanners.FormatAssay, writeFile(t, "assay.json", output))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if parsed.Severities.Critical != 1 || parsed.Severities.Medium != 1 {
		t.Errorf("severities = %+v, want 1 critical and 1 medium", parsed.Severities)
	}
}

// Malformed output must surface as an error, never as a clean scan.
func TestMalformedJSONIsAnError(t *testing.T) {
	if _, err := Parse(scanners.FormatTrivyJSON, writeFile(t, "trivy.json", "{not json")); err == nil {
		t.Fatal("malformed trivy output parsed without error")
	}
}

func TestUnknownFormatIsAnError(t *testing.T) {
	if _, err := Parse("no-such-format", writeFile(t, "out", "{}")); err == nil {
		t.Fatal("unknown format parsed without error")
	}
}

// Reports are stored in etcd, which has a hard object-size limit. Detailed
// findings are capped, but the counts must stay true.
func TestFindingsAreCappedButCountsStayAccurate(t *testing.T) {
	var output string
	for i := 0; i < maxFindings+250; i++ {
		if i > 0 {
			output += "\n"
		}
		output += `{"DetectorName":"AWS","Verified":false,"SourceMetadata":{"Data":{"Filesystem":{"file":"f.py","line":1}}}}`
	}

	parsed, err := Parse(scanners.FormatTrufflehog, writeFile(t, "th.json", output))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if len(parsed.Findings) != maxFindings {
		t.Errorf("stored findings = %d, want them capped at %d", len(parsed.Findings), maxFindings)
	}
	if got := parsed.Severities.Total(); got != int32(maxFindings+250) {
		t.Errorf("counted findings = %d, want the true total %d", got, maxFindings+250)
	}
}

// When findings are capped, the most severe must be the ones kept.
func TestCappingKeepsTheMostSevereFindings(t *testing.T) {
	output := `{"findings":[`
	for i := 0; i < maxFindings; i++ {
		if i > 0 {
			output += ","
		}
		output += `{"id":"LOW","severity":"Low","category":"model"}`
	}
	output += `,{"id":"CRIT","severity":"Critical","category":"model"}]}`

	parsed, err := Parse(scanners.FormatAssay, writeFile(t, "assay.json", output))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if len(parsed.Findings) != maxFindings {
		t.Fatalf("stored findings = %d, want %d", len(parsed.Findings), maxFindings)
	}
	if parsed.Findings[0].ID != "CRIT" {
		t.Errorf("first stored finding = %q, want the critical one retained", parsed.Findings[0].ID)
	}
}

func TestSeverityNormalization(t *testing.T) {
	cases := map[string]string{
		"CRITICAL": "Critical", "critical": "Critical",
		"HIGH": "High", "MODERATE": "Medium", "MEDIUM": "Medium",
		"NEGLIGIBLE": "Low", "LOW": "Low",
		"": "Unknown", "bogus": "Unknown",
	}
	for input, want := range cases {
		if got := normalizeSeverity(input); got != want {
			t.Errorf("normalizeSeverity(%q) = %q, want %q", input, got, want)
		}
	}
}
