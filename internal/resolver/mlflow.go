package resolver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// MLflowResolver stages artifacts through an MLflow tracking server's artifact
// proxy. URI form:
//
//	mlflow://host:port/<artifact-path>
//
// MLflow's own registry reports a version's location as
// "mlflow-artifacts:/0/<run>/artifacts/model", which names a path inside a
// server it does not identify. That is fine for a client that already knows
// which tracking server it is talking to, and useless to the scan pod, which
// receives only the URI. The connector therefore rewrites the scheme to carry
// the host, so the fetch step can resolve it without extra configuration.
type MLflowResolver struct {
	HTTPClient *http.Client
	Token      string
}

// Scheme implements Resolver.
func (m *MLflowResolver) Scheme() string { return "mlflow" }

func (m *MLflowResolver) client() *http.Client {
	if m.HTTPClient != nil {
		return m.HTTPClient
	}
	return &http.Client{Timeout: 5 * time.Minute}
}

// RewriteMLflowURI converts an mlflow-artifacts: location into a self-
// describing mlflow:// URI against the given tracking server.
func RewriteMLflowURI(artifactURI, trackingURL string) (string, bool) {
	const scheme = "mlflow-artifacts:"
	if !strings.HasPrefix(artifactURI, scheme) {
		return "", false
	}
	base, err := url.Parse(trackingURL)
	if err != nil || base.Host == "" {
		return "", false
	}
	rest := strings.TrimPrefix(artifactURI, scheme)
	rest = strings.TrimPrefix(rest, "//")
	// Drop an authority the server may have included; the tracking URL is the
	// authority that matters, since that is who we can actually reach.
	if i := strings.Index(rest, "/"); strings.Contains(rest, ":") && i > 0 && !strings.HasPrefix(rest, "/") {
		rest = rest[i:]
	}
	return fmt.Sprintf("mlflow://%s/%s", base.Host, strings.TrimPrefix(rest, "/")), true
}

type mlflowFile struct {
	Path  string `json:"path"`
	IsDir bool   `json:"is_dir"`
}

type mlflowListing struct {
	Files []mlflowFile `json:"files"`
}

// Resolve implements Resolver.
func (m *MLflowResolver) Resolve(ctx context.Context, uri, destDir string) (*Artifact, error) {
	u, err := parseURL(uri)
	if err != nil {
		return nil, err
	}
	if u.Host == "" {
		return nil, fmt.Errorf("mlflow URI %q names no tracking server", uri)
	}
	base := "http://" + u.Host
	root := strings.TrimPrefix(u.Path, "/")

	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return nil, fmt.Errorf("create staging dir: %w", err)
	}

	var total int64
	queue := []string{root}
	for len(queue) > 0 {
		dir := queue[0]
		queue = queue[1:]

		q := url.Values{}
		if dir != "" {
			q.Set("path", dir)
		}
		var listing mlflowListing
		if err := m.getJSON(ctx, base+"/api/2.0/mlflow-artifacts/artifacts?"+q.Encode(), &listing); err != nil {
			return nil, fmt.Errorf("list %s: %w", dir, err)
		}
		for _, f := range listing.Files {
			// The listing returns paths relative to the queried directory
			// while downloads want the full path, so rejoin before use.
			full := path.Join(dir, f.Path)
			if f.IsDir {
				queue = append(queue, full)
				continue
			}
			rel, err := filepath.Rel(root, full)
			if err != nil || strings.HasPrefix(rel, "..") {
				return nil, fmt.Errorf("artifact path %q escapes the model root", full)
			}
			target, err := safeJoin(destDir, rel)
			if err != nil {
				return nil, err
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return nil, err
			}
			n, err := m.download(ctx, base, full, target)
			if err != nil {
				return nil, err
			}
			total += n
		}
	}
	if total == 0 {
		// An empty staging directory would be scanned as a clean model.
		return nil, fmt.Errorf("no artifact bytes found at %s", uri)
	}

	// Digest the staged tree, as every other resolver does. Without it the
	// verdict is bound to a URI rather than to bytes, so the admission gate's
	// replay check has nothing to compare and an approval for one version of
	// an MLflow artifact would admit whatever is published at that path next.
	digest, _, err := treeDigest(destDir)
	if err != nil {
		return nil, fmt.Errorf("digest staged artifact: %w", err)
	}

	return &Artifact{
		URI:       uri,
		Digest:    digest,
		MediaType: "application/vnd.mlflow.model",
		LocalPath: destDir,
		SizeBytes: total,
	}, nil
}

func (m *MLflowResolver) download(ctx context.Context, base, file, target string) (int64, error) {
	endpoint := base + "/api/2.0/mlflow-artifacts/artifacts/" + pathEscapeSegments(file)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return 0, err
	}
	m.authorize(req)
	resp, err := m.client().Do(req)
	if err != nil {
		return 0, fmt.Errorf("download %s: %w", file, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<10))
		return 0, fmt.Errorf("download %s: HTTP %d: %s", file, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	out, err := os.Create(target)
	if err != nil {
		return 0, err
	}
	defer out.Close()
	return io.Copy(out, io.LimitReader(resp.Body, 8<<30))
}

func (m *MLflowResolver) getJSON(ctx context.Context, endpoint string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	m.authorize(req)
	resp, err := m.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(payload)))
	}
	return json.Unmarshal(payload, out)
}

func (m *MLflowResolver) authorize(req *http.Request) {
	if m.Token != "" {
		req.Header.Set("Authorization", "Bearer "+m.Token)
	}
}
