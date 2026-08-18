package resolver

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// HuggingFaceResolver stages a model from the Hugging Face Hub, or any
// deployment of it. URI forms:
//
//	hf://owner/name                     the default branch, pinned at fetch time
//	hf://owner/name@revision            a branch, tag or commit SHA
//	https://huggingface.co/owner/name   normalised to the above
//
// Public models are the case security engineers most want to check and the one
// nothing else here covered: the artifact is not in anyone's registry yet, and
// the question is whether it is safe to bring in at all.
//
// The size problem is the whole design. A current frontier model is most of a
// terabyte, and downloading that to run a scanner over it is not viable. It is
// also unnecessary: the files that can execute code are tiny — configs
// declaring trust_remote_code, custom .py, pickles — while the bulk is
// safetensors, which cannot execute anything and whose only inspectable part
// is a header at byte zero. The Hub honours HTTP Range, so that header costs a
// few kilobytes out of hundreds of gigabytes.
//
// What that buys in speed it owes in honesty: the resolver records exactly
// which files were read whole, which were read only far enough to validate a
// header, and which were not read at all, so a report can never be mistaken
// for a complete one.
type HuggingFaceResolver struct {
	// BaseURL is the Hub endpoint. Empty means the public Hub.
	BaseURL string
	// Token authenticates to gated or private repositories. Empty is
	// anonymous, which is the normal case for public models.
	Token string
	// HTTPClient overrides the default. Optional.
	HTTPClient *http.Client
	// Limits bounds what is fetched. Zero uses HuggingFaceDefaults.
	Limits HuggingFaceLimits
}

// HuggingFaceLimits bounds a fetch.
type HuggingFaceLimits struct {
	// MaxFiles caps how many repository files are considered.
	MaxFiles int
	// MaxFileBytes is the largest file fetched in full. Anything larger is
	// header-sampled if its format supports it, and otherwise skipped.
	MaxFileBytes int64
	// MaxTotalBytes caps the whole staged artifact.
	MaxTotalBytes int64
	// HeaderBytes is how much of a large file is read to validate its header.
	HeaderBytes int64
}

// HuggingFaceDefaults are deliberately small. The interesting files are all
// kilobytes; a repository whose configs are hundreds of megabytes is itself
// worth a second look.
func HuggingFaceDefaults() HuggingFaceLimits {
	return HuggingFaceLimits{
		MaxFiles: 5000,
		// Generous on purpose. A pytorch_model.bin is a pickle, and a pickle is
		// the payload — it is the single file most worth reading, and real ones
		// run to several gigabytes. Skipping it to save bandwidth would be
		// optimising away the scan.
		MaxFileBytes:  8 << 30,  // 8 GiB read in full
		MaxTotalBytes: 32 << 30, // 32 GiB staged in total
		HeaderBytes:   16 << 20, // far past any real tensor header
	}
}

// Scheme implements Resolver.
func (h *HuggingFaceResolver) Scheme() string { return "hf" }

const defaultHubURL = "https://huggingface.co"

func (h *HuggingFaceResolver) hub() string {
	if h.BaseURL != "" {
		return strings.TrimRight(h.BaseURL, "/")
	}
	return defaultHubURL
}

func (h *HuggingFaceResolver) client() *http.Client {
	if h.HTTPClient != nil {
		return h.HTTPClient
	}
	return &http.Client{Timeout: 5 * time.Minute}
}

func (h *HuggingFaceResolver) limits() HuggingFaceLimits {
	if h.Limits.MaxFiles == 0 {
		return HuggingFaceDefaults()
	}
	return h.Limits
}

// ParseHuggingFaceURI splits a Hub URI into repository and revision.
// A https://huggingface.co/... URL is accepted so a URL pasted from a browser
// works without editing.
func ParseHuggingFaceURI(uri string) (repo, revision string, err error) {
	trimmed := uri
	for _, prefix := range []string{"hf://", "huggingface://"} {
		if strings.HasPrefix(strings.ToLower(trimmed), prefix) {
			trimmed = trimmed[len(prefix):]
		}
	}
	if i := strings.Index(strings.ToLower(trimmed), "huggingface.co/"); i >= 0 {
		trimmed = trimmed[i+len("huggingface.co/"):]
	}
	trimmed = strings.Trim(trimmed, "/")

	// A browser URL may carry /tree/<rev> or /blob/<rev>; treat that as the
	// revision rather than as part of the repository name.
	for _, sep := range []string{"/tree/", "/blob/"} {
		if i := strings.Index(trimmed, sep); i >= 0 {
			revision = strings.Trim(trimmed[i+len(sep):], "/")
			trimmed = trimmed[:i]
			break
		}
	}
	if i := strings.LastIndex(trimmed, "@"); i >= 0 {
		revision = trimmed[i+1:]
		trimmed = trimmed[:i]
	}

	parts := strings.Split(trimmed, "/")
	if len(parts) < 1 || parts[0] == "" {
		return "", "", fmt.Errorf("hugging face URI %q names no repository", uri)
	}
	if len(parts) > 2 {
		return "", "", fmt.Errorf("hugging face URI %q has too many path segments; want owner/name", uri)
	}
	return strings.Join(parts, "/"), revision, nil
}

type hfModelInfo struct {
	ID  string `json:"id"`
	SHA string `json:"sha"`
}

type hfTreeEntry struct {
	Type string `json:"type"` // "file" or "directory"
	Path string `json:"path"`
	Size int64  `json:"size"`
	LFS  *struct {
		Size int64 `json:"size"`
	} `json:"lfs,omitempty"`
}

func (e hfTreeEntry) size() int64 {
	if e.LFS != nil && e.LFS.Size > 0 {
		return e.LFS.Size
	}
	return e.Size
}

// Coverage records what a partial fetch actually read, so a scan over it can
// state its own limits.
type Coverage struct {
	// FetchedWhole are files staged in full.
	FetchedWhole []string `json:"fetchedWhole,omitempty"`
	// HeaderOnly are files staged only far enough to validate their header.
	HeaderOnly []string `json:"headerOnly,omitempty"`
	// Skipped are files not read at all, with the reason.
	Skipped map[string]string `json:"skipped,omitempty"`
}

// Complete reports whether every file was read in full.
func (c Coverage) Complete() bool { return len(c.HeaderOnly) == 0 && len(c.Skipped) == 0 }

// UnreadExecutable lists skipped files whose format can carry executable
// content, sorted.
//
// This is the set that must never be silently absent from a verdict. A
// safetensors that was header-sampled is genuinely covered — the format cannot
// execute anything — but a pickle that was not read is an unknown, and an
// unknown is not a clean result.
func (c Coverage) UnreadExecutable() []string {
	var out []string
	for f := range c.Skipped {
		if CanExecuteCode(f) {
			out = append(out, f)
		}
	}
	sort.Strings(out)
	return out
}

// CanExecuteCode reports whether a filename's format is one that can run code
// when a model is loaded. Deliberately broad: the cost of treating an inert
// file as risky is a redundant download, and the cost of the reverse is a
// clean verdict over an unread payload.
func CanExecuteCode(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".pkl", ".pickle", ".joblib", ".dill",
		".bin", ".pt", ".pth", ".ckpt", // torch pickles
		".py", ".sh", ".bash",
		".h5", ".keras", // Keras lambda layers carry pickled code
		".zip", ".tar", ".whl", ".egg",
		".so", ".dylib", ".dll",
		".onnx", ".pb", ".msgpack", ".ot":
		return true
	}
	return false
}

// Summary is a one-line description for a report or a log.
func (c Coverage) Summary() string {
	if c.Complete() {
		return fmt.Sprintf("%d file(s) read in full", len(c.FetchedWhole))
	}
	return fmt.Sprintf("%d read in full, %d header-only, %d not read",
		len(c.FetchedWhole), len(c.HeaderOnly), len(c.Skipped))
}

// Resolve implements Resolver.
func (h *HuggingFaceResolver) Resolve(ctx context.Context, uri, destDir string) (*Artifact, error) {
	repo, revision, err := ParseHuggingFaceURI(uri)
	if err != nil {
		return nil, err
	}

	// Pin the revision before fetching anything. A verdict against "main" is
	// meaningless the moment main moves, so the commit SHA becomes the
	// artifact's digest and the thing every later file read is fetched at.
	sha, err := h.resolveRevision(ctx, repo, revision)
	if err != nil {
		return nil, err
	}

	entries, err := h.listTree(ctx, repo, sha)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("hugging face repository %s@%s contains no files", repo, sha)
	}

	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return nil, fmt.Errorf("create staging dir: %w", err)
	}

	lim := h.limits()
	cov := Coverage{Skipped: map[string]string{}}
	var total int64

	for _, e := range entries {
		if len(cov.FetchedWhole)+len(cov.HeaderOnly) >= lim.MaxFiles {
			cov.Skipped[e.Path] = "file limit reached"
			continue
		}
		target, err := safeJoin(destDir, e.Path)
		if err != nil {
			// A repository path that escapes the staging directory is itself
			// a finding, but the resolver's job is to refuse it.
			return nil, fmt.Errorf("repository %s: %w", repo, err)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return nil, err
		}

		size := e.size()
		switch {
		case headerInspectable(e.Path):
			// Sampled whatever the size: the risk in these formats is entirely
			// in the header, so the remaining bytes are inert weight data.
			n, err := h.sampleHeader(ctx, repo, sha, e.Path, target, lim.HeaderBytes)
			if err != nil {
				return nil, err
			}
			total += n
			cov.HeaderOnly = append(cov.HeaderOnly, e.Path)

		case size <= lim.MaxFileBytes && total+size <= lim.MaxTotalBytes:
			n, err := h.download(ctx, repo, sha, e.Path, target, 0)
			if err != nil {
				return nil, err
			}
			total += n
			cov.FetchedWhole = append(cov.FetchedWhole, e.Path)

		default:
			cov.Skipped[e.Path] = fmt.Sprintf("%d bytes exceeds the fetch limit and the format has no inspectable header", size)
		}
	}

	sort.Strings(cov.FetchedWhole)
	sort.Strings(cov.HeaderOnly)

	return &Artifact{
		URI: fmt.Sprintf("hf://%s@%s", repo, sha),
		// The commit SHA is the artifact's identity on the Hub, which is
		// exactly what a verdict needs to be pinned to.
		Digest:    "hf-commit:" + sha,
		MediaType: "application/vnd.huggingface.repo",
		LocalPath: destDir,
		SizeBytes: total,
		Coverage:  &cov,
	}, nil
}

// headerInspectable reports whether a file too large to fetch is still worth
// sampling, because its risk lives in a header at the start of the file.
func headerInspectable(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".safetensors", ".gguf", ".ggml", ".npy":
		return true
	}
	// .onnx is deliberately absent: a suspicious operator can appear anywhere
	// in the protobuf, so the inspector reads the whole file. Sampling one
	// would return "no findings" for a graph it never looked at.
	return false
}

func (h *HuggingFaceResolver) resolveRevision(ctx context.Context, repo, revision string) (string, error) {
	endpoint := fmt.Sprintf("%s/api/models/%s", h.hub(), repo)
	if revision != "" {
		endpoint += "/revision/" + url.PathEscape(revision)
	}
	var info hfModelInfo
	if err := h.getJSON(ctx, endpoint, &info); err != nil {
		return "", fmt.Errorf("look up %s on the hub: %w", repo, err)
	}
	if info.SHA == "" {
		// Without a commit the fetch is unpinned, which makes the verdict
		// unattributable. Better to fail than to record a claim about
		// "whatever main was at the time".
		return "", fmt.Errorf("hub returned no commit for %s; refusing to scan an unpinned revision", repo)
	}
	return info.SHA, nil
}

// listTree walks the repository, following directories.
func (h *HuggingFaceResolver) listTree(ctx context.Context, repo, sha string) ([]hfTreeEntry, error) {
	var out []hfTreeEntry
	queue := []string{""}
	seen := map[string]bool{}

	for len(queue) > 0 {
		dir := queue[0]
		queue = queue[1:]
		if seen[dir] {
			continue
		}
		seen[dir] = true

		endpoint := fmt.Sprintf("%s/api/models/%s/tree/%s", h.hub(), repo, url.PathEscape(sha))
		if dir != "" {
			endpoint += "/" + dir
		}
		var entries []hfTreeEntry
		if err := h.getJSON(ctx, endpoint, &entries); err != nil {
			return nil, fmt.Errorf("list %s@%s: %w", repo, sha, err)
		}
		for _, e := range entries {
			if e.Type == "directory" {
				queue = append(queue, strings.TrimPrefix(e.Path, "/"))
				continue
			}
			out = append(out, e)
		}
	}
	return out, nil
}

// download fetches a repository file. limit > 0 requests only the first limit
// bytes, via a Range request; the Hub serves 206 for these, which is what
// makes sampling a multi-gigabyte tensor file affordable.
func (h *HuggingFaceResolver) download(ctx context.Context, repo, sha, file, target string, limit int64) (int64, error) {
	endpoint := fmt.Sprintf("%s/%s/resolve/%s/%s", h.hub(), repo, url.PathEscape(sha), pathEscapeSegments(file))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return 0, err
	}
	h.authorize(req)
	if limit > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=0-%d", limit-1))
	}

	resp, err := h.client().Do(req)
	if err != nil {
		return 0, fmt.Errorf("fetch %s: %w", file, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<10))
		return 0, fmt.Errorf("fetch %s: HTTP %d: %s", file, resp.StatusCode, strings.TrimSpace(string(body)))
	}

	out, err := os.Create(target)
	if err != nil {
		return 0, err
	}
	defer out.Close()

	// Cap regardless of what the server sends: a Range request the server
	// chose to ignore would otherwise stream the whole file to disk.
	cap := limit
	if cap == 0 {
		cap = h.limits().MaxFileBytes
	}
	n, err := io.Copy(out, io.LimitReader(resp.Body, cap))
	if err != nil {
		return n, fmt.Errorf("write %s: %w", target, err)
	}
	return n, nil
}

// sampleHeader stages only as much of a file as its header needs.
//
// Safetensors declares its header length in the first eight bytes, so two
// small Range requests fetch exactly the header and nothing else — on the
// order of kilobytes against a file of hundreds of gigabytes. Formats that do
// not self-describe fall back to a fixed sample.
//
// The staged bytes stay a valid prefix of the original: the length prefix is
// written back along with the header, so the inspector parses it as the
// safetensors it is rather than reporting a truncated file.
func (h *HuggingFaceResolver) sampleHeader(ctx context.Context, repo, sha, file, target string, fallback int64) (int64, error) {
	if strings.EqualFold(filepath.Ext(file), ".safetensors") {
		prefix, err := h.readRange(ctx, repo, sha, file, 0, 8)
		if err == nil && len(prefix) == 8 {
			declared := binary.LittleEndian.Uint64(prefix)
			// Guard the length the file claims: it is attacker-controlled, and
			// an absurd value would otherwise turn into an absurd request.
			if declared > 0 && declared <= uint64(fallback) {
				want := int64(8 + declared)
				body, err := h.readRange(ctx, repo, sha, file, 0, want)
				if err == nil && int64(len(body)) >= 8 {
					if err := os.WriteFile(target, body, 0o644); err != nil { //nolint:gosec // G306: staged artifact, read by the scanner in the same pod
						return 0, err
					}
					return int64(len(body)), nil
				}
			}
		}
		// Fall through: a malformed or unreadable header is itself worth
		// staging so the inspector can report it.
	}
	return h.download(ctx, repo, sha, file, target, fallback)
}

// readRange fetches [start, start+length) and returns the bytes.
func (h *HuggingFaceResolver) readRange(ctx context.Context, repo, sha, file string, start, length int64) ([]byte, error) {
	endpoint := fmt.Sprintf("%s/%s/resolve/%s/%s", h.hub(), repo, url.PathEscape(sha), pathEscapeSegments(file))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	h.authorize(req)
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, start+length-1))

	resp, err := h.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusPartialContent && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("range read %s: HTTP %d", file, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, length))
}

func (h *HuggingFaceResolver) getJSON(ctx context.Context, endpoint string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	h.authorize(req)

	resp, err := h.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	payload, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("HTTP %d: the repository is gated or private; set a hub token", resp.StatusCode)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(payload)))
	}
	return json.Unmarshal(payload, out)
}

func (h *HuggingFaceResolver) authorize(req *http.Request) {
	if h.Token != "" {
		req.Header.Set("Authorization", "Bearer "+h.Token)
	}
}

// pathEscapeSegments escapes each path segment while keeping the separators.
func pathEscapeSegments(p string) string {
	parts := strings.Split(p, "/")
	for i, s := range parts {
		parts[i] = url.PathEscape(s)
	}
	return path.Join(parts...)
}
