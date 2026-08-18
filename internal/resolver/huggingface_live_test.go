//go:build hf_live

// Exercises the Hugging Face resolver against the real Hub, which is the only
// way to know the API shapes and the Range behaviour still hold. Needs network
// access, no credentials — every repository used here is public.
//
//	go test -tags hf_live -run TestHuggingFaceLive ./internal/resolver/ -v
package resolver

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHuggingFaceLive(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	t.Run("stages a small public model and pins the commit", func(t *testing.T) {
		dest := t.TempDir()
		r := &HuggingFaceResolver{}

		artifact, err := r.Resolve(ctx, "hf://openai-community/gpt2", dest)
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}

		// The digest has to be the commit, not the branch: a verdict against
		// "main" stops meaning anything the moment main moves.
		if !strings.HasPrefix(artifact.Digest, "hf-commit:") || len(artifact.Digest) < 20 {
			t.Errorf("digest = %q, want a pinned commit", artifact.Digest)
		}
		if strings.Contains(artifact.URI, "@main") || !strings.Contains(artifact.URI, "@") {
			t.Errorf("URI = %q, want the resolved commit rather than a branch", artifact.URI)
		}

		// config.json is the file that can declare trust_remote_code, so it is
		// the one that must always arrive whole.
		cfg := filepath.Join(dest, "config.json")
		if data, err := os.ReadFile(cfg); err != nil {
			t.Errorf("config.json was not staged: %v", err)
		} else if len(data) == 0 {
			t.Error("config.json is empty")
		}
		t.Logf("staged %d bytes; coverage: %s", artifact.SizeBytes, artifact.Coverage.Summary())
	})

	t.Run("samples a huge model without downloading it", func(t *testing.T) {
		// Most of a terabyte. If the resolver were naive this would never
		// finish, which is the point of the test.
		const repo = "hf://deepseek-ai/DeepSeek-V4-Pro-0813"

		dest := t.TempDir()
		r := &HuggingFaceResolver{}
		start := time.Now()

		artifact, err := r.Resolve(ctx, repo, dest)
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		elapsed := time.Since(start)

		if artifact.Coverage == nil {
			t.Fatal("no coverage recorded for a partial fetch")
		}
		cov := artifact.Coverage
		if cov.Complete() {
			t.Error("a 900GB repository was reported as fully read")
		}
		if len(cov.HeaderOnly) == 0 {
			t.Error("no file was header-sampled; the weights were either skipped or downloaded whole")
		}

		// The whole design claim: the interesting files arrive in full while
		// the bulk does not.
		var gotConfig bool
		for _, f := range cov.FetchedWhole {
			if f == "config.json" {
				gotConfig = true
			}
		}
		if !gotConfig {
			t.Error("config.json was not read in full; that is where trust_remote_code lives")
		}

		const ceiling = 4 << 30
		if artifact.SizeBytes > ceiling {
			t.Errorf("staged %d bytes, which is past the limit", artifact.SizeBytes)
		}
		t.Logf("staged %.1f MB of a ~893GB repository in %s; %s",
			float64(artifact.SizeBytes)/(1<<20), elapsed.Round(time.Second), cov.Summary())

		// A sampled safetensors must still be parseable as one, or the
		// inspector would report a malformed header for every large model.
		for _, f := range cov.HeaderOnly {
			if !strings.HasSuffix(f, ".safetensors") {
				continue
			}
			info, err := os.Stat(filepath.Join(dest, f))
			if err != nil {
				t.Errorf("header-only file %s was not staged: %v", f, err)
				continue
			}
			if info.Size() < 8 {
				t.Errorf("%s is too short to hold a safetensors header", f)
			}
			break
		}
	})

	t.Run("refuses a repository that does not exist", func(t *testing.T) {
		r := &HuggingFaceResolver{}
		if _, err := r.Resolve(ctx, "hf://assay-test/definitely-not-a-real-model-9x8", t.TempDir()); err == nil {
			t.Fatal("resolving a missing repository succeeded")
		}
	})
}
