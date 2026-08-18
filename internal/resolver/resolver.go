// Package resolver abstracts the storage backends a model artifact can live
// in (OCI, S3/ODF, PVC, ModelCar, HTTP) behind one interface, so the scan
// orchestrator never needs to know where the bytes came from.
package resolver

import (
	"context"
	"fmt"
	"net/url"
	"path"
	"strings"
)

// Artifact is a resolved, staged artifact on local disk.
type Artifact struct {
	// URI is the original artifact URI.
	URI string
	// Digest is the content digest (sha256:...) when the backend provides one.
	Digest string
	// MediaType when the backend provides one.
	MediaType string
	// LocalPath is the staging directory the artifact was fetched into.
	LocalPath string
	// SizeBytes is the total staged size.
	SizeBytes int64
	// Coverage records what a partial fetch actually read. Nil means the
	// whole artifact was staged. A scan over a partial fetch must say so:
	// "no findings" over files that were never read is not a clean result.
	Coverage *Coverage
}

// Resolver fetches an artifact from one class of storage backend.
type Resolver interface {
	// Scheme returns the URI scheme this resolver handles.
	Scheme() string
	// Resolve fetches the artifact at uri into destDir.
	Resolve(ctx context.Context, uri string, destDir string) (*Artifact, error)
}

// Registry dispatches URIs to the resolver registered for their scheme.
type Registry struct {
	resolvers map[string]Resolver
}

// NewRegistry returns a Registry with the built-in resolvers installed.
func NewRegistry() *Registry {
	r := &Registry{resolvers: map[string]Resolver{}}
	r.Register(&OCIResolver{})
	r.Register(&ModelCarResolver{})
	r.Register(&S3Resolver{})
	r.Register(&PVCResolver{})
	r.Register(&HuggingFaceResolver{})
	r.Register(&MLflowResolver{})
	r.Register(&HTTPResolver{scheme: "https"})
	r.Register(&HTTPResolver{scheme: "http"})
	return r
}

// Register installs a resolver, replacing any resolver for the same scheme.
func (r *Registry) Register(res Resolver) {
	r.resolvers[res.Scheme()] = res
}

// Resolve fetches uri into destDir using the resolver for its scheme.
func (r *Registry) Resolve(ctx context.Context, uri, destDir string) (*Artifact, error) {
	scheme, err := SchemeOf(uri)
	if err != nil {
		return nil, err
	}
	res, ok := r.resolvers[scheme]
	if !ok {
		return nil, fmt.Errorf("no resolver registered for scheme %q (uri %q)", scheme, uri)
	}
	return res.Resolve(ctx, uri, destDir)
}

// Supports reports whether a resolver is registered for the URI's scheme.
func (r *Registry) Supports(uri string) bool {
	scheme, err := SchemeOf(uri)
	if err != nil {
		return false
	}
	_, ok := r.resolvers[scheme]
	return ok
}

// SchemeOf extracts the scheme from an artifact URI.
func SchemeOf(uri string) (string, error) {
	idx := strings.Index(uri, "://")
	if idx <= 0 {
		return "", fmt.Errorf("artifact URI %q has no scheme", uri)
	}
	return strings.ToLower(uri[:idx]), nil
}

// parseURL parses an artifact URI, keeping the opaque remainder accessible.
func parseURL(uri string) (*url.URL, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("parse artifact URI %q: %w", uri, err)
	}
	if u.Host == "" && u.Path == "" {
		return nil, fmt.Errorf("artifact URI %q is missing a location", uri)
	}
	return u, nil
}

// safeJoin joins base and rel, refusing paths that escape base. Artifact
// contents are untrusted, so archive members and object keys must never be
// able to write outside the staging directory.
func safeJoin(base, rel string) (string, error) {
	cleaned := path.Clean("/" + strings.ReplaceAll(rel, "\\", "/"))
	joined := path.Join(base, cleaned)
	if joined != base && !strings.HasPrefix(joined, base+"/") {
		return "", fmt.Errorf("path %q escapes staging directory", rel)
	}
	return joined, nil
}
