package resolver

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// Every resolver has to materialise the artifact into destDir, because that is
// the only directory the scan container mounts.
//
// This test exists because the PVC resolver originally returned a path inside
// the mounted claim and copied nothing. The scan pod then ran every scanner
// against an empty workspace, which does not error — it reports zero findings
// and the model is approved. A planted model containing EICAR, a malicious
// pickle, vulnerable dependency pins and credentials came back clean.
func TestPVCResolverStagesFilesIntoDestDir(t *testing.T) {
	claimRoot := t.TempDir()
	model := filepath.Join(claimRoot, "model-store", "fraud", "v1")
	if err := os.MkdirAll(filepath.Join(model, "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"pytorch_model.bin":  "\x80\x05pickle-ish",
		"requirements.txt":   "pillow==9.0.0\n",
		"nested/weights.bin": "data",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(model, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	dest := t.TempDir()
	res := &PVCResolver{MountRoot: claimRoot}
	art, err := res.Resolve(context.Background(), "pvc://model-store/fraud/v1", dest)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if art.LocalPath != dest {
		t.Errorf("LocalPath = %q, want the staging dir %q — the scan container mounts only that", art.LocalPath, dest)
	}
	for name := range files {
		if _, err := os.Stat(filepath.Join(dest, name)); err != nil {
			t.Errorf("%s was not staged into the workspace: %v", name, err)
		}
	}
}

// A single-file artifact must land in the workspace too, not just directories.
func TestPVCResolverStagesASingleFile(t *testing.T) {
	claimRoot := t.TempDir()
	dir := filepath.Join(claimRoot, "store", "m")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "model.bin"), []byte("weights"), 0o644); err != nil {
		t.Fatal(err)
	}

	dest := t.TempDir()
	res := &PVCResolver{MountRoot: claimRoot}
	if _, err := res.Resolve(context.Background(), "pvc://store/m/model.bin", dest); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "model.bin")); err != nil {
		t.Errorf("single file not staged: %v", err)
	}
}

// A model artifact is untrusted. A symlink escaping the claim must not pull
// host files into the workspace, where they would be scanned and could surface
// in a report.
func TestPVCResolverDoesNotFollowSymlinksOutOfTheClaim(t *testing.T) {
	claimRoot := t.TempDir()
	model := filepath.Join(claimRoot, "store", "m")
	if err := os.MkdirAll(model, 0o755); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(t.TempDir(), "host-secret")
	if err := os.WriteFile(secret, []byte("do-not-exfiltrate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(model, "innocent.bin")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.WriteFile(filepath.Join(model, "real.bin"), []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}

	dest := t.TempDir()
	res := &PVCResolver{MountRoot: claimRoot}
	if _, err := res.Resolve(context.Background(), "pvc://store/m", dest); err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dest, "innocent.bin")); err == nil {
		t.Error("symlink was followed; host file staged into the scan workspace")
	}
	if _, err := os.Stat(filepath.Join(dest, "real.bin")); err != nil {
		t.Errorf("regular file should still be staged: %v", err)
	}
}
