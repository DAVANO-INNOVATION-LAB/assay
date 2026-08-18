package resolver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// PVCResolver reads artifacts from a PersistentVolumeClaim mounted into the
// scan pod. URI form: pvc://claim-name/path/within/claim
//
// The orchestrator mounts the claim read-only at MountRoot/<claim-name>, so
// this resolver only has to locate and verify the path.
type PVCResolver struct {
	// MountRoot is where the orchestrator mounts claims. Defaults to /mnt/pvc.
	MountRoot string
}

// Scheme implements Resolver.
func (p *PVCResolver) Scheme() string { return "pvc" }

// Resolve implements Resolver.
func (p *PVCResolver) Resolve(_ context.Context, uri, destDir string) (*Artifact, error) {
	u, err := parseURL(uri)
	if err != nil {
		return nil, err
	}
	claim := u.Host
	if claim == "" {
		return nil, fmt.Errorf("pvc URI %q is missing a claim name", uri)
	}

	root := p.MountRoot
	if root == "" {
		root = "/mnt/pvc"
	}
	claimRoot := filepath.Join(root, claim)

	local, err := safeJoin(claimRoot, strings.TrimPrefix(u.Path, "/"))
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(local)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", local, err)
	}

	digest, size, err := treeDigest(local)
	if err != nil {
		return nil, err
	}

	// Copy into the staging directory rather than pointing at the claim.
	//
	// Every resolver's contract is to materialise the artifact into destDir,
	// because that is the only path the scan container mounts. Returning a
	// path inside the claim instead left the workspace empty, and an empty
	// workspace does not fail — every scanner simply reports zero findings and
	// the model is approved. A silent false negative is the worst outcome this
	// component can produce, so the copy is not optional.
	//
	// It also preserves the isolation model: the scanner reads a copy in an
	// emptyDir, never the source claim.
	if err := copyTree(local, destDir, info); err != nil {
		return nil, err
	}

	return &Artifact{
		URI:       uri,
		Digest:    digest,
		MediaType: "application/vnd.assay.model-directory",
		LocalPath: destDir,
		SizeBytes: size,
	}, nil
}

// copyTree materialises src (a file or directory) into destDir.
//
// Symlinks are skipped rather than followed. A model artifact is untrusted
// input, and a link pointing outside the claim would otherwise pull host or
// cluster files into the workspace and into the scan report.
func copyTree(src, destDir string, info os.FileInfo) error {
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return fmt.Errorf("create staging dir: %w", err)
	}

	if !info.IsDir() {
		return copyFile(src, filepath.Join(destDir, filepath.Base(src)))
	}

	return filepath.Walk(src, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		target, err := safeJoin(destDir, rel)
		if err != nil {
			return err
		}
		switch {
		case fi.IsDir():
			return os.MkdirAll(target, 0o755)
		case fi.Mode()&os.ModeSymlink != 0:
			// Skipped deliberately; see the note above.
			return nil
		case fi.Mode().IsRegular():
			return copyFile(path, target)
		default:
			// Devices, sockets, and pipes are not model data.
			return nil
		}
	})
}

func copyFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open %s: %w", src, err)
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("create %s: %w", dst, err)
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return fmt.Errorf("copy %s: %w", src, err)
	}
	return nil
}

// HTTPResolver downloads a single artifact over HTTP(S). It is the fallback
// for registries that record a plain download URL.
type HTTPResolver struct {
	scheme string
}

// Scheme implements Resolver.
func (h *HTTPResolver) Scheme() string {
	if h.scheme == "" {
		return "https"
	}
	return h.scheme
}

// Resolve implements Resolver.
func (h *HTTPResolver) Resolve(ctx context.Context, uri, destDir string) (*Artifact, error) {
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return nil, fmt.Errorf("create staging dir: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, fmt.Errorf("build request for %s: %w", uri, err)
	}
	client := &http.Client{Timeout: 30 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", uri, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("fetch %s: status %d", uri, resp.StatusCode)
	}

	name := filepath.Base(strings.SplitN(strings.TrimSuffix(uri, "/"), "?", 2)[0])
	if name == "" || name == "." || name == "/" {
		name = "artifact.bin"
	}
	target, err := safeJoin(destDir, name)
	if err != nil {
		return nil, err
	}

	f, err := os.Create(target)
	if err != nil {
		return nil, fmt.Errorf("create %s: %w", target, err)
	}
	defer f.Close()

	hasher := sha256.New()
	size, err := io.Copy(io.MultiWriter(f, hasher), resp.Body)
	if err != nil {
		return nil, fmt.Errorf("write %s: %w", target, err)
	}

	return &Artifact{
		URI:       uri,
		Digest:    "sha256:" + hex.EncodeToString(hasher.Sum(nil)),
		MediaType: resp.Header.Get("Content-Type"),
		LocalPath: destDir,
		SizeBytes: size,
	}, nil
}

// treeDigest hashes a file or directory tree into a stable content digest.
func treeDigest(root string) (string, int64, error) {
	info, err := os.Stat(root)
	if err != nil {
		return "", 0, fmt.Errorf("stat %s: %w", root, err)
	}

	if !info.IsDir() {
		f, err := os.Open(root)
		if err != nil {
			return "", 0, fmt.Errorf("open %s: %w", root, err)
		}
		defer f.Close()
		hasher := sha256.New()
		size, err := io.Copy(hasher, f)
		if err != nil {
			return "", 0, fmt.Errorf("hash %s: %w", root, err)
		}
		return "sha256:" + hex.EncodeToString(hasher.Sum(nil)), size, nil
	}

	type entry struct {
		rel  string
		hash string
	}
	var (
		entries []entry
		total   int64
	)
	err = filepath.Walk(root, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if fi.IsDir() {
			return nil
		}
		// Symlinks are not followed: a model artifact must not be able to
		// pull the scanner's view outside the mounted tree.
		if fi.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		h := sha256.New()
		n, err := io.Copy(h, f)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		entries = append(entries, entry{rel: rel, hash: hex.EncodeToString(h.Sum(nil))})
		total += n
		return nil
	})
	if err != nil {
		return "", 0, fmt.Errorf("hash tree %s: %w", root, err)
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].rel < entries[j].rel })
	top := sha256.New()
	for _, e := range entries {
		fmt.Fprintf(top, "%s %s\n", e.hash, e.rel)
	}
	return "sha256:" + hex.EncodeToString(top.Sum(nil)), total, nil
}
