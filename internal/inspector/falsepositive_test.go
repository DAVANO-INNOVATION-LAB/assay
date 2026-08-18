package inspector

import (
	"encoding/binary"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
)

// A security scanner that cries wolf gets turned off. These tests pin the
// inert cases that must stay silent, so tightening detection later cannot
// quietly reintroduce noise.

func npyHeader(descr string) []byte {
	header := []byte("{'descr': '" + descr + "', 'fortran_order': False, 'shape': (256,), }")
	for len(header)%16 != 15 {
		header = append(header, ' ')
	}
	header = append(header, '\n')

	out := []byte("\x93NUMPY\x01\x00")
	length := make([]byte, 2)
	binary.LittleEndian.PutUint16(length, uint16(len(header)))
	out = append(out, length...)
	return append(out, header...)
}

func randomBytes(n int, seed int64) []byte {
	buf := make([]byte, n)
	rand.New(rand.NewSource(seed)).Read(buf)
	return buf
}

// Random float data contains every pickle opcode byte by chance. Flagging it
// would make every numeric weight file a High finding.
func TestNumericNumpyArrayIsClean(t *testing.T) {
	dir := t.TempDir()
	data := append(npyHeader("<f4"), randomBytes(4096, 1)...)
	write(t, dir, "embeddings.npy", data)

	if report := inspect(t, dir); len(report.Findings) != 0 {
		t.Fatalf("false positive on a numeric numpy array: %+v", report.Findings)
	}
}

// An object-dtype array really is a pickle in disguise, so it must be caught.
func TestObjectDtypeNumpyArrayIsFlagged(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "objects.npy", append(npyHeader("|O"), randomBytes(256, 2)...))

	if report := inspect(t, dir); !hasID(report, "ASSAY-NPY-001") {
		t.Fatalf("did not flag an object-dtype array; findings: %v", findingIDs(report))
	}
}

// A raw tensor dump under a .bin extension is not a pickle. Without the
// protocol magic there is no evidence, and guessing produces noise.
func TestRawBinaryWeightsAreClean(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "weights.bin", randomBytes(8192, 3))

	if report := inspect(t, dir); len(report.Findings) != 0 {
		t.Fatalf("false positive on raw binary weights: %+v", report.Findings)
	}
}

func TestTokenizerAndConfigFilesAreClean(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "tokenizer_config.json", []byte(`{"model_max_length":4096,"tokenizer_class":"LlamaTokenizer"}`))
	write(t, dir, "special_tokens_map.json", []byte(`{"bos_token":"<s>","eos_token":"</s>"}`))
	write(t, dir, "generation_config.json", []byte(`{"temperature":0.6,"top_p":0.9}`))
	write(t, dir, "vocab.txt", []byte("the\nquick\nbrown\nfox\n"))

	if report := inspect(t, dir); len(report.Findings) != 0 {
		t.Fatalf("false positives on ordinary model metadata: %+v", report.Findings)
	}
}

// Documentation that merely mentions dangerous APIs is not executable.
func TestMarkdownMentioningDangerousAPIsIsClean(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "README.md", []byte(`# Model card

Do not call os.system or eval() on untrusted input. This model was
converted from a pickle checkpoint using torch.load.
`))

	if report := inspect(t, dir); len(report.Findings) != 0 {
		t.Fatalf("false positives on a model card: %+v", report.Findings)
	}
}

func TestEmptyDirectoryIsClean(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "nested", "deeper"), 0o755); err != nil {
		t.Fatal(err)
	}

	report := inspect(t, dir)

	if len(report.Findings) != 0 {
		t.Fatalf("empty directory produced findings: %+v", report.Findings)
	}
	if report.FilesScanned != 0 {
		t.Errorf("scanned %d files in an empty tree, want 0", report.FilesScanned)
	}
}

func TestZeroLengthFileIsClean(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "placeholder.bin", nil)
	write(t, dir, "empty.pkl", nil)

	if report := inspect(t, dir); len(report.Findings) != 0 {
		t.Fatalf("zero-length files produced findings: %+v", report.Findings)
	}
}
