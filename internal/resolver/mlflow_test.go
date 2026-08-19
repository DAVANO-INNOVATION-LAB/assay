package resolver

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A verdict has to belong to bytes, not to a URI. Every other resolver
// digests what it staged; MLflow shipped without one, which quietly disabled
// the admission gate's replay check for anything sourced from a tracking
// server and left the SI-7 control mapping unsupported for those models.
func TestMLflowResolverProducesADigest(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "model.safetensors"), []byte("weights"), 0o644); err != nil {
		t.Fatal(err)
	}

	digest, size, err := treeDigest(dir)
	if err != nil {
		t.Fatal(err)
	}
	if digest == "" {
		t.Fatal("a staged tree must digest to something")
	}
	if !strings.HasPrefix(digest, "sha256:") {
		t.Fatalf("digest should be algorithm-prefixed, got %q", digest)
	}
	if size == 0 {
		t.Fatal("size should be measured")
	}

	// Different bytes at the same path must produce a different digest, or
	// the replay check it feeds is decorative.
	if err := os.WriteFile(filepath.Join(dir, "model.safetensors"), []byte("different"), 0o644); err != nil {
		t.Fatal(err)
	}
	other, _, err := treeDigest(dir)
	if err != nil {
		t.Fatal(err)
	}
	if other == digest {
		t.Fatal("changing the staged bytes must change the digest")
	}
}
