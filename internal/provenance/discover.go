package provenance

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// SignatureKind distinguishes the shapes a signature can arrive in. They differ
// in what they cover, which is the part that matters: a per-file bundle proves
// one file, a manifest signature proves a set of files, and conflating them
// makes an unsigned weights file look signed.
type SignatureKind string

const (
	// KindBundle is a Sigstore bundle covering exactly one file.
	KindBundle SignatureKind = "bundle"
	// KindManifest is a sigstore/model-transparency manifest signature: a DSSE
	// envelope over an in-toto statement whose subjects are the model's files.
	KindManifest SignatureKind = "manifest"
	// KindDetached is a raw signature file beside a certificate or verified
	// against a configured public key.
	KindDetached SignatureKind = "detached"
)

// Signature is a candidate signature found in the workspace.
type Signature struct {
	Kind SignatureKind
	// Path is the signature file, relative to the workspace.
	Path string
	// Target is the file a per-file signature covers, relative to the
	// workspace. Empty for manifest signatures, whose subjects are read from
	// the envelope during verification.
	Target string
	// CertPath is a detached certificate accompanying a raw signature.
	CertPath string
}

// signature file suffixes, longest first so ".sigstore.json" wins over ".json".
var bundleSuffixes = []string{
	".sigstore.json",
	".sigstore",
	".bundle.json",
	".bundle",
	".cosign.bundle",
}

// manifestNames are the conventional names for a signature covering a whole
// model directory. model.sig is what sigstore/model-transparency writes.
var manifestNames = map[string]bool{
	"model.sig":            true,
	"model.sig.json":       true,
	"model_signature.json": true,
	"signature.json":       true,
}

// Inventory is what the workspace holds: the files that were staged and the
// signatures found alongside them.
type Inventory struct {
	// Files are the artifact files, relative to the workspace, excluding
	// anything identified as a signature.
	Files []string
	// Signatures found in the workspace.
	Signatures []Signature
	// Sizes maps each file to its size in bytes.
	Sizes map[string]int64
}

// Discover walks a staged workspace and separates artifact files from the
// signatures that claim to cover them.
func Discover(workspace string) (*Inventory, error) {
	inv := &Inventory{Sizes: map[string]int64{}}
	sigPaths := map[string]bool{}
	var all []string

	err := filepath.WalkDir(workspace, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, relErr := filepath.Rel(workspace, p)
		if relErr != nil {
			return relErr
		}
		info, infoErr := d.Info()
		if infoErr != nil {
			return infoErr
		}
		all = append(all, rel)
		inv.Sizes[rel] = info.Size()
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk workspace: %w", err)
	}
	sort.Strings(all)

	present := map[string]bool{}
	for _, f := range all {
		present[f] = true
	}

	for _, rel := range all {
		base := filepath.Base(rel)

		if manifestNames[strings.ToLower(base)] {
			inv.Signatures = append(inv.Signatures, Signature{
				Kind: KindManifest, Path: rel,
			})
			sigPaths[rel] = true
			continue
		}

		if suffix, ok := matchSuffix(base, bundleSuffixes); ok {
			target := strings.TrimSuffix(rel, suffix)
			// A bundle whose target is missing covers nothing present. Record
			// it anyway so verification can say "signed a file that is not
			// here" rather than silently ignoring it.
			inv.Signatures = append(inv.Signatures, Signature{
				Kind: KindBundle, Path: rel, Target: target,
			})
			sigPaths[rel] = true
			continue
		}

		if strings.HasSuffix(base, ".sig") {
			target := strings.TrimSuffix(rel, ".sig")
			sig := Signature{Kind: KindDetached, Path: rel, Target: target}
			for _, ext := range []string{".crt", ".pem", ".cert"} {
				if candidate := target + ext; present[candidate] {
					sig.CertPath = candidate
					sigPaths[candidate] = true
					break
				}
			}
			inv.Signatures = append(inv.Signatures, sig)
			sigPaths[rel] = true
		}
	}

	for _, rel := range all {
		if !sigPaths[rel] {
			inv.Files = append(inv.Files, rel)
		}
	}
	return inv, nil
}

func matchSuffix(name string, suffixes []string) (string, bool) {
	lower := strings.ToLower(name)
	for _, s := range suffixes {
		if strings.HasSuffix(lower, s) && len(lower) > len(s) {
			return s, true
		}
	}
	return "", false
}

// UnsignedExecutables returns the staged files that can execute code on load
// and are not covered by the given set of verified paths.
//
// This is the check that keeps a partial signature honest. Signing one file of
// forty and calling the model signed is the provenance equivalent of scanning
// one file of forty and calling it clean.
func (inv *Inventory) UnsignedExecutables(covered map[string]bool) []string {
	var out []string
	for _, f := range inv.Files {
		if covered[f] {
			continue
		}
		if ExecutableFormat(f) != "" {
			out = append(out, f)
		}
	}
	sort.Strings(out)
	return out
}

// inTotoStatement is the subset of an in-toto statement we need: the subjects a
// manifest signature claims to cover, with their digests.
type inTotoStatement struct {
	Type    string `json:"_type"`
	Subject []struct {
		Name   string            `json:"name"`
		Digest map[string]string `json:"digest"`
	} `json:"subject"`
	PredicateType string `json:"predicateType"`
}

// parseStatement reads an in-toto statement from raw JSON.
func parseStatement(raw []byte) (*inTotoStatement, error) {
	var st inTotoStatement
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, fmt.Errorf("parse in-toto statement: %w", err)
	}
	if len(st.Subject) == 0 {
		return nil, fmt.Errorf("statement lists no subjects")
	}
	return &st, nil
}

// readLimit caps how much of a signature file we will read. Signature files are
// kilobytes; anything larger is either not a signature or is trying to make us
// allocate.
const readLimit = 4 << 20

func readSignatureFile(p string) ([]byte, error) {
	info, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	if info.Size() > readLimit {
		return nil, fmt.Errorf("signature file is %d bytes, over the %d limit", info.Size(), readLimit)
	}
	return os.ReadFile(p)
}
