// Package provenance verifies that a staged model artifact was signed by
// somebody the cluster is willing to trust.
//
// The load-bearing idea is that "signed" is not a boolean. A signature covers
// specific bytes, was made by a specific identity, and may or may not have been
// recorded somewhere a third party can audit. A verifier that collapses those
// into one yes/no will happily report success for a signature over the README
// of a directory whose weights are unsigned. So the result here reports what
// was covered as well as what verified, and an executable file left outside the
// signature is a finding in its own right.
package provenance

import (
	"fmt"
	"path"
	"strings"
)

// Publisher is a signer the cluster trusts, flattened from a TrustedPublisher
// object so this package does not depend on the Kubernetes API.
type Publisher struct {
	// Name is the TrustedPublisher object name, used in findings so a reader
	// can tell which rule admitted or rejected an artifact.
	Name string
	// DisplayName is the human label.
	DisplayName string
	// PublicKeyPEM verifies key-based signatures. Mutually exclusive with the
	// keyless fields in practice, though both may be set.
	PublicKeyPEM string
	// Issuer is the OIDC issuer for Sigstore keyless signing.
	Issuer string
	// Subject is the certificate SAN. A trailing "*" matches a prefix.
	Subject string
	// URIPrefixes limits which artifact URIs this publisher may sign. Empty
	// means any URI.
	URIPrefixes []string
}

// Keyless reports whether this publisher signs with Sigstore certificates.
func (p Publisher) Keyless() bool { return p.Issuer != "" && p.Subject != "" }

// MatchesURI reports whether this publisher is permitted to sign the artifact.
//
// Scoping a publisher to a URI prefix is what stops a signature that is
// perfectly valid for one repository from being replayed to admit an artifact
// from somewhere else entirely.
func (p Publisher) MatchesURI(uri string) bool {
	if len(p.URIPrefixes) == 0 {
		return true
	}
	for _, prefix := range p.URIPrefixes {
		if strings.HasPrefix(uri, prefix) {
			return true
		}
	}
	return false
}

// MatchesSubject reports whether a certificate SAN satisfies this publisher.
//
// Only a trailing "*" is honoured. Full globbing would let a policy author
// write something like "*@example.com" that reads restrictive and matches far
// more than intended; a prefix is the shape people actually mean.
func (p Publisher) MatchesSubject(san string) bool {
	if strings.HasSuffix(p.Subject, "*") {
		return strings.HasPrefix(san, strings.TrimSuffix(p.Subject, "*"))
	}
	return san == p.Subject
}

// Policy is the trust configuration handed to a scan.
type Policy struct {
	// Publishers the cluster trusts. An empty list means nothing can verify,
	// which is reported as a configuration problem rather than as a failure of
	// the artifact — those are different situations and blaming the model for
	// an unconfigured cluster sends people to the wrong place.
	Publishers []Publisher

	// TrustRootPath is a Sigstore trusted-root JSON file (TUF output) used to
	// validate Fulcio certificates and Rekor entries.
	//
	// Deliberately not defaulted to the public-good instance: fetching a trust
	// root means the scan pod reaches out to the internet, which is exactly
	// what an air-gapped or classified environment forbids. Verification
	// without a configured root reports why it could not run instead of
	// quietly phoning home.
	TrustRootPath string

	// RequireTransparencyLog demands a verifiable transparency-log entry, not
	// just a valid signature. Without one, a signature proves who signed but
	// leaves no public record that the signature ever existed, so a signer who
	// later loses their key cannot tell which artifacts were signed with it.
	RequireTransparencyLog bool
}

// Trusted reports whether the policy names any publisher at all.
func (p Policy) Trusted() bool { return len(p.Publishers) > 0 }

// PublishersForURI narrows the policy to publishers permitted to sign this URI.
func (p Policy) PublishersForURI(uri string) []Publisher {
	var out []Publisher
	for _, pub := range p.Publishers {
		if pub.MatchesURI(uri) {
			out = append(out, pub)
		}
	}
	return out
}

// executableFormats are the file extensions that can run code when a model is
// loaded. An unsigned file in this set is materially worse than an unsigned
// README, and the coverage findings say so.
var executableFormats = map[string]string{
	".pkl":         "pickle",
	".pickle":      "pickle",
	".bin":         "pytorch",
	".pt":          "pytorch",
	".pth":         "pytorch",
	".ckpt":        "pytorch checkpoint",
	".joblib":      "joblib",
	".dill":        "dill",
	".h5":          "keras/HDF5",
	".keras":       "keras",
	".pb":          "tensorflow graph",
	".npy":         "numpy",
	".npz":         "numpy",
	".msgpack":     "flax",
	".model":       "sentencepiece",
	".safetensors": "", // safetensors cannot execute on load; listed to be explicit
}

// ExecutableFormat returns the format name if loading this file can execute
// code, and "" if it cannot.
func ExecutableFormat(name string) string {
	ext := strings.ToLower(path.Ext(name))
	format, ok := executableFormats[ext]
	if !ok || format == "" {
		return ""
	}
	return format
}

// String renders a publisher for a finding message.
func (p Publisher) String() string {
	label := p.DisplayName
	if label == "" {
		label = p.Name
	}
	switch {
	case p.Keyless():
		return fmt.Sprintf("%s (%s via %s)", label, p.Subject, p.Issuer)
	case p.PublicKeyPEM != "":
		return fmt.Sprintf("%s (public key)", label)
	default:
		return label
	}
}
