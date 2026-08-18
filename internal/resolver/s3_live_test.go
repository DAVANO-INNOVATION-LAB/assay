//go:build s3_live

// This test runs the S3 resolver against real S3-compatible object storage
// (MinIO in Docker), closing the long-standing "compiles but untested against
// real storage" gap for the s3:// path that ODF and MinIO both serve.
//
// It asserts the things only real storage can prove: multi-object prefix
// staging, nested key layout preserved on disk, the aggregate digest, byte
// totals, and that a prefix with no objects is an error rather than an empty
// success.
//
//	go test -tags s3_live -run TestS3Live ./internal/resolver/ -v
//
// Requires Docker and the minio/minio image.
package resolver

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	minioImage     = "minio/minio:latest"
	minioContainer = "assay-minio-live-test"
	minioPort      = "9111"
	minioUser      = "assaytest"
	minioPassword  = "assaytest123"
	testBucket     = "models"
)

func TestS3Live(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}
	startMinIO(t)

	endpoint := "http://localhost:" + minioPort
	t.Setenv("AWS_ACCESS_KEY_ID", minioUser)
	t.Setenv("AWS_SECRET_ACCESS_KEY", minioPassword)
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("AWS_S3_ENDPOINT", endpoint)

	// A model laid out the way a real one is: weights at the top, a config,
	// and a nested subdirectory the staging code has to recreate.
	seed(t, map[string]string{
		"llm/v1/model.safetensors":    "safetensors-bytes",
		"llm/v1/config.json":          `{"model_type":"llama"}`,
		"llm/v1/tokenizer/vocab.json": `{"a":1}`,
		"llm/v2/model.safetensors":    "other-version",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	res := &S3Resolver{}

	t.Run("stages a multi-object prefix", func(t *testing.T) {
		dest := t.TempDir()
		artifact, err := res.Resolve(ctx, "s3://"+testBucket+"/llm/v1", dest)
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}

		// The nested key must land as a nested path, not a flattened name.
		for rel, want := range map[string]string{
			"model.safetensors":    "safetensors-bytes",
			"config.json":          `{"model_type":"llama"}`,
			"tokenizer/vocab.json": `{"a":1}`,
		} {
			got, err := os.ReadFile(filepath.Join(dest, rel))
			if err != nil {
				t.Errorf("staged file %s missing: %v", rel, err)
				continue
			}
			if string(got) != want {
				t.Errorf("%s = %q, want %q", rel, got, want)
			}
		}

		// The other version's object must not be dragged in by prefix overlap.
		if _, err := os.Stat(filepath.Join(dest, "..", "v2")); err == nil {
			t.Error("resolver staged objects outside the requested prefix")
		}

		wantSize := int64(len("safetensors-bytes") + len(`{"model_type":"llama"}`) + len(`{"a":1}`))
		if artifact.SizeBytes != wantSize {
			t.Errorf("SizeBytes = %d, want %d", artifact.SizeBytes, wantSize)
		}
		if !strings.HasPrefix(artifact.Digest, "sha256:") {
			t.Errorf("Digest = %q, want a sha256: prefix", artifact.Digest)
		}
		t.Logf("staged %d bytes, digest %s", artifact.SizeBytes, artifact.Digest)
	})

	t.Run("digest is stable across resolves", func(t *testing.T) {
		// The digest is the artifact's identity; if it moved between two
		// resolves of identical bytes, every scan would look like a new model.
		a, err := res.Resolve(ctx, "s3://"+testBucket+"/llm/v1", t.TempDir())
		if err != nil {
			t.Fatalf("first resolve: %v", err)
		}
		b, err := res.Resolve(ctx, "s3://"+testBucket+"/llm/v1", t.TempDir())
		if err != nil {
			t.Fatalf("second resolve: %v", err)
		}
		if a.Digest != b.Digest {
			t.Errorf("digest not stable: %s != %s", a.Digest, b.Digest)
		}
	})

	t.Run("empty prefix is an error, not an empty success", func(t *testing.T) {
		// A scan that stages nothing and reports success would be scored as a
		// clean model. This must fail loudly.
		if _, err := res.Resolve(ctx, "s3://"+testBucket+"/does-not-exist", t.TempDir()); err == nil {
			t.Fatal("resolving an empty prefix succeeded; want an error")
		}
	})

	t.Run("missing bucket is an error", func(t *testing.T) {
		if _, err := res.Resolve(ctx, "s3://no-such-bucket/x", t.TempDir()); err == nil {
			t.Fatal("resolving a missing bucket succeeded; want an error")
		}
	})
}

func startMinIO(t *testing.T) {
	t.Helper()
	_ = exec.Command("docker", "rm", "-f", minioContainer).Run()

	run := exec.Command("docker", "run", "-d", "--name", minioContainer,
		"-p", minioPort+":9000",
		"-e", "MINIO_ROOT_USER="+minioUser,
		"-e", "MINIO_ROOT_PASSWORD="+minioPassword,
		minioImage, "server", "/data",
	)
	if out, err := run.CombinedOutput(); err != nil {
		t.Fatalf("docker run minio: %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", minioContainer).Run() })

	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", "localhost:"+minioPort, time.Second)
		if err == nil {
			conn.Close()
			// The port opens slightly before the API is ready to serve.
			time.Sleep(2 * time.Second)
			return
		}
		time.Sleep(time.Second)
	}
	t.Fatal("minio did not become ready within 60s")
}

// seed writes objects into the test bucket using the MinIO client inside the
// server container, so the test needs no extra host tooling.
func seed(t *testing.T, objects map[string]string) {
	t.Helper()

	script := fmt.Sprintf(
		"mc alias set local http://localhost:9000 %s %s >/dev/null && mc mb -p local/%s >/dev/null",
		minioUser, minioPassword, testBucket,
	)
	for key, content := range objects {
		script += fmt.Sprintf(" && printf '%%s' '%s' | mc pipe local/%s/%s >/dev/null", content, testBucket, key)
	}

	cmd := exec.Command("docker", "exec", minioContainer, "sh", "-c", script)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("seed minio: %v: %s", err, out)
	}
}
