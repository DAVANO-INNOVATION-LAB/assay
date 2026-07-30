package resolver

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/file"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/retry"
)

// OCIResolver pulls artifacts from an OCI registry, including the OpenShift
// integrated registry. URI form: oci://registry/repo:tag or
// oci://registry/repo@sha256:...
type OCIResolver struct {
	// PlainHTTP forces http for registries without TLS (test clusters).
	PlainHTTP bool
	// Insecure skips registry TLS verification.
	Insecure bool
}

// Scheme implements Resolver.
func (o *OCIResolver) Scheme() string { return "oci" }

// Resolve implements Resolver.
func (o *OCIResolver) Resolve(ctx context.Context, uri, destDir string) (*Artifact, error) {
	ref := strings.TrimPrefix(uri, "oci://")
	return pullOCI(ctx, ref, destDir, uri, o.PlainHTTP, o.Insecure)
}

// ModelCarResolver pulls a ModelCar (a model packaged as an OCI image whose
// layers carry the model files). The transport is identical to OCI; the
// distinction is preserved so policies can treat ModelCar images differently.
type ModelCarResolver struct {
	PlainHTTP bool
	Insecure  bool
}

// Scheme implements Resolver.
func (m *ModelCarResolver) Scheme() string { return "modelcar" }

// Resolve implements Resolver.
func (m *ModelCarResolver) Resolve(ctx context.Context, uri, destDir string) (*Artifact, error) {
	ref := strings.TrimPrefix(uri, "modelcar://")
	return pullOCI(ctx, ref, destDir, uri, m.PlainHTTP, m.Insecure)
}

func pullOCI(ctx context.Context, ref, destDir, originalURI string, plainHTTP, insecure bool) (*Artifact, error) {
	repoRef, tagOrDigest, err := splitReference(ref)
	if err != nil {
		return nil, err
	}

	repo, err := remote.NewRepository(repoRef)
	if err != nil {
		return nil, fmt.Errorf("open repository %q: %w", repoRef, err)
	}
	repo.PlainHTTP = plainHTTP

	client := &auth.Client{
		Client:     retry.DefaultClient,
		Cache:      auth.NewCache(),
		Credential: credentialFunc(insecure),
	}
	repo.Client = client

	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return nil, fmt.Errorf("create staging dir: %w", err)
	}
	store, err := file.New(destDir)
	if err != nil {
		return nil, fmt.Errorf("create file store: %w", err)
	}
	defer store.Close()

	desc, err := oras.Copy(ctx, repo, tagOrDigest, store, tagOrDigest, oras.DefaultCopyOptions)
	if err != nil {
		return nil, fmt.Errorf("pull %s: %w", ref, err)
	}

	size, err := dirSize(destDir)
	if err != nil {
		return nil, err
	}

	return &Artifact{
		URI:       originalURI,
		Digest:    desc.Digest.String(),
		MediaType: desc.MediaType,
		LocalPath: destDir,
		SizeBytes: size,
	}, nil
}

// credentialFunc resolves registry credentials from the standard Docker
// config mounted into the scan pod, falling back to anonymous access.
func credentialFunc(insecure bool) auth.CredentialFunc {
	store, err := dockerConfigStore()
	if err != nil || store == nil {
		return auth.StaticCredential("", auth.EmptyCredential)
	}
	return store.Get
}

func splitReference(ref string) (repo string, tagOrDigest string, err error) {
	if at := strings.LastIndex(ref, "@"); at > 0 {
		return ref[:at], ref[at+1:], nil
	}
	// A colon after the last slash is a tag; a colon before it is a port.
	lastSlash := strings.LastIndex(ref, "/")
	if colon := strings.LastIndex(ref, ":"); colon > lastSlash {
		return ref[:colon], ref[colon+1:], nil
	}
	if ref == "" {
		return "", "", fmt.Errorf("empty OCI reference")
	}
	return ref, "latest", nil
}

func dirSize(dir string) (int64, error) {
	var total int64
	err := filepath.Walk(dir, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			total += info.Size()
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("measure staged artifact: %w", err)
	}
	return total, nil
}
