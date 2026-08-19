package aibom

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeSafetensors writes a minimal but genuinely valid safetensors file, so
// the tests exercise the real parser rather than a stub of it.
func writeSafetensors(t *testing.T, path string, meta map[string]string) {
	t.Helper()
	header := map[string]any{
		"weight": map[string]any{
			"dtype":        "F32",
			"shape":        []int{2, 2},
			"data_offsets": []int{0, 16},
		},
	}
	if meta != nil {
		header["__metadata__"] = meta
	}
	body, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, uint64(len(body)))
	buf = append(buf, body...)
	buf = append(buf, make([]byte, 16)...)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestGeneratesBothDocuments(t *testing.T) {
	dir := t.TempDir()
	writeSafetensors(t, filepath.Join(dir, "model.safetensors"), nil)

	report, docs, err := Generate(context.Background(), dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Generated {
		t.Fatal("a readable safetensors file must produce a bill of materials")
	}
	if docs == nil || len(docs.CycloneDX) == 0 || len(docs.SPDX) == 0 {
		t.Fatal("both documents must be rendered")
	}
	if report.Format != "safetensors" {
		t.Fatalf("format %q", report.Format)
	}
	if report.MeasuredParameters != 4 {
		t.Errorf("a 2x2 tensor is 4 parameters, got %d", report.MeasuredParameters)
	}

	// The documents must be parseable JSON, or nothing downstream can consume
	// them and the scanner is producing decoration.
	var cdx, spdx map[string]any
	if err := json.Unmarshal(docs.CycloneDX, &cdx); err != nil {
		t.Fatalf("CycloneDX is not valid JSON: %v", err)
	}
	if err := json.Unmarshal(docs.SPDX, &spdx); err != nil {
		t.Fatalf("SPDX is not valid JSON: %v", err)
	}
	if cdx["specVersion"] != "1.6" {
		t.Errorf("expected CycloneDX 1.6, got %v", cdx["specVersion"])
	}
}

// The failure this scanner must not have: exiting cleanly with no output. A
// report with no findings and no document is indistinguishable from a model
// that was examined and found sound, which is the fail-open shape.
func TestNoModelIsReportedRatherThanPassed(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}

	report, docs, err := Generate(context.Background(), dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if docs != nil {
		t.Fatal("there is no model, so there is nothing to render")
	}
	if report.Generated {
		t.Fatal("Generated must be false when no bill of materials was produced")
	}
	var found bool
	for _, f := range report.Findings {
		if f.ID == FindingNoModel {
			found = true
			if f.Severity == "Low" || f.Severity == "" {
				t.Errorf("severity %q lets a policy approve a scan that described "+
					"nothing", f.Severity)
			}
		}
	}
	if !found {
		t.Fatal("an artifact with no describable model must say so, or the absence " +
			"of a bill of materials reads as a clean one")
	}
}

// Drift is the finding class nothing else in the scanner set produces, so the
// integration is only worth having if drift actually arrives in the report.
func TestDriftFindingsReachTheReport(t *testing.T) {
	dir := t.TempDir()
	writeSafetensors(t, filepath.Join(dir, "model.safetensors"), nil)
	// A config that declares a precision the tensors do not carry. The weights
	// above are F32; this claims the model is bfloat16.
	cfg := `{"architectures":["LlamaForCausalLM"],"model_type":"llama","dtype":"bfloat16"}`
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}

	report, _, err := Generate(context.Background(), dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	var drift bool
	for _, f := range report.Findings {
		if strings.HasPrefix(f.ID, "TESS-DRIFT-") {
			drift = true
			// The drift gate counts findings by this category, so losing it
			// here would silently disable the rule rather than fail it.
			if f.Category != CategoryDrift {
				t.Errorf("finding %s carries category %q, so the drift gate would "+
					"never count it", f.ID, f.Category)
			}
		}
	}
	if !drift {
		t.Fatalf("a config declaring bfloat16 over F32 weights is drift and must be "+
			"reported; got %v", ids(report))
	}
}

// A model nested under the workspace root still has to be found: artifacts are
// staged as repositories, and the analyser's own directory resolution does not
// recurse.
func TestNestedModelIsFound(t *testing.T) {
	dir := t.TempDir()
	writeSafetensors(t, filepath.Join(dir, "snapshots", "abc123", "model.safetensors"), nil)

	report, _, err := Generate(context.Background(), dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Generated {
		t.Fatalf("a model one directory down must still be described; got %v", ids(report))
	}
	if report.ModelPath != filepath.Join("snapshots", "abc123") {
		t.Errorf("the report should locate the model, got %q", report.ModelPath)
	}
}

// Describing one model out of several and saying nothing about the rest is the
// same failure as a truncated walk: partial coverage that reads as complete.
func TestAdditionalModelsAreDeclared(t *testing.T) {
	dir := t.TempDir()
	writeSafetensors(t, filepath.Join(dir, "model.safetensors"), nil)
	writeSafetensors(t, filepath.Join(dir, "adapter", "model.safetensors"), nil)

	report, _, err := Generate(context.Background(), dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.AdditionalModels) != 1 || report.AdditionalModels[0] != "adapter" {
		t.Fatalf("the undescribed model must be named, got %v", report.AdditionalModels)
	}
	var found bool
	for _, f := range report.Findings {
		if f.ID == FindingPartial {
			found = true
		}
	}
	if !found {
		t.Fatal("a document covering part of an artifact must declare that it does")
	}
}

// Locations have to survive back to whoever reads the report, which is not
// inside the scan pod.
func TestFindingLocationsAreWorkspaceRelative(t *testing.T) {
	dir := t.TempDir()
	writeSafetensors(t, filepath.Join(dir, "nested", "model.safetensors"), nil)

	report, _, err := Generate(context.Background(), dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range report.Findings {
		if filepath.IsAbs(f.Location) {
			t.Errorf("finding %s has absolute location %q, which names a path inside a "+
				"pod that no longer exists", f.ID, f.Location)
		}
	}
}

// The same artifact and the same timestamp must render identically, or a bill
// of materials cannot be diffed between scans — and diffing is what turns it
// into a change-detection signal.
func TestRenderingIsDeterministic(t *testing.T) {
	dir := t.TempDir()
	writeSafetensors(t, filepath.Join(dir, "model.safetensors"), nil)

	opts := Options{GeneratedAt: time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)}
	_, a, err := Generate(context.Background(), dir, opts)
	if err != nil {
		t.Fatal(err)
	}
	_, b, err := Generate(context.Background(), dir, opts)
	if err != nil {
		t.Fatal(err)
	}
	if string(a.CycloneDX) != string(b.CycloneDX) {
		t.Error("the same artifact at the same timestamp must render byte-identically")
	}
	if string(a.SPDX) != string(b.SPDX) {
		t.Error("SPDX rendering is not deterministic")
	}
}

func ids(r *Report) []string {
	out := make([]string, 0, len(r.Findings))
	for _, f := range r.Findings {
		out = append(out, f.ID)
	}
	return out
}
