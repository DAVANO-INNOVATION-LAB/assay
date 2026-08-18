package provenance

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// Finding identifiers. They are stable because policies and waivers reference
// them; renaming one silently changes which exceptions apply.
const (
	// FindingUnsigned means no signature was found at all.
	FindingUnsigned = "ASSAY-PROV-001"
	// FindingInvalid means a signature was present and did not verify. This is
	// categorically worse than unsigned: something claimed provenance falsely.
	FindingInvalid = "ASSAY-PROV-002"
	// FindingUntrustedSigner means the signature verified but the identity is
	// not one this cluster trusts.
	FindingUntrustedSigner = "ASSAY-PROV-003"
	// FindingNoTransparencyLog means the signature verified but left no
	// auditable public record.
	FindingNoTransparencyLog = "ASSAY-PROV-004"
	// FindingPartialCoverage means executable files were left outside the
	// signature.
	FindingPartialCoverage = "ASSAY-PROV-005"
	// FindingNotConfigured means verification could not run because the
	// cluster has no trust configuration. A property of the cluster, not the
	// artifact.
	FindingNotConfigured = "ASSAY-PROV-006"
	// FindingVerified records a successful verification, so the report shows
	// what was proven rather than only what failed.
	FindingVerified = "ASSAY-PROV-000"
)

// Finding is a provenance result. It mirrors the shape of the API Finding type
// without importing it, so this package stays usable from the CLI.
type Finding struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	Category    string `json:"category"`
	Location    string `json:"location,omitempty"`
	Description string `json:"description"`
}

// Result is the outcome of verifying a workspace.
type Result struct {
	Findings []Finding `json:"findings"`
	// Verified is true only when a trusted publisher's signature covered every
	// executable file in the workspace.
	Verified bool `json:"verified"`
	// Signer identifies who signed, when verification succeeded.
	Signer string `json:"signer,omitempty"`
	// CoveredFiles are the paths a verified signature attested to.
	CoveredFiles []string `json:"coveredFiles,omitempty"`
}

// Verifier checks staged artifacts against a trust policy.
type Verifier struct {
	policy  Policy
	trusted root.TrustedMaterial
}

// NewVerifier builds a verifier for a policy.
//
// A missing or unreadable trust root is not fatal here. It degrades to
// reporting FindingNotConfigured, because a cluster that has not been given a
// trust root should get a clear message about its own configuration rather
// than a crashed scan Job.
func NewVerifier(policy Policy) (*Verifier, error) {
	v := &Verifier{policy: policy}
	if policy.TrustRootPath == "" {
		return v, nil
	}
	tr, err := root.NewTrustedRootFromPath(policy.TrustRootPath)
	if err != nil {
		return v, fmt.Errorf("load trust root %s: %w", policy.TrustRootPath, err)
	}
	v.trusted = tr
	return v, nil
}

// Verify checks every signature in the workspace against the policy.
//
// artifactURI scopes which publishers may sign; pass the URI the artifact was
// fetched from.
func (v *Verifier) Verify(workspace, artifactURI string) (*Result, error) {
	inv, err := Discover(workspace)
	if err != nil {
		return nil, err
	}

	res := &Result{}
	publishers := v.policy.PublishersForURI(artifactURI)

	if len(inv.Signatures) == 0 {
		res.Findings = append(res.Findings, Finding{
			ID:       FindingUnsigned,
			Title:    "Artifact is not signed",
			Severity: "Medium",
			Category: "provenance",
			Description: "No signature accompanied this artifact, so its origin cannot be " +
				"established. The bytes may be exactly what the publisher intended, or may " +
				"not be; nothing here can tell the difference.",
		})
		return res, nil
	}

	// A signature is present but the cluster cannot check it. Say that plainly
	// rather than reporting the artifact as unsigned, which would blame the
	// model for the cluster's missing configuration.
	if !v.policy.Trusted() || v.trusted == nil {
		res.Findings = append(res.Findings, Finding{
			ID:          FindingNotConfigured,
			Title:       "Signature present but cannot be verified",
			Severity:    "Medium",
			Category:    "provenance",
			Description: v.notConfiguredReason(len(inv.Signatures)),
		})
		return res, nil
	}

	covered := map[string]bool{}
	var (
		signers    []string
		anyValid   bool
		hadFailure bool
	)

	for _, sig := range inv.Signatures {
		outcome := v.verifyOne(workspace, sig, publishers, inv)
		res.Findings = append(res.Findings, outcome.findings...)
		if outcome.valid {
			anyValid = true
			for _, f := range outcome.covered {
				covered[f] = true
			}
			if outcome.signer != "" {
				signers = append(signers, outcome.signer)
			}
		}
		if outcome.failed {
			hadFailure = true
		}
	}

	// Executable files outside the signature. Reported whenever something
	// verified, because "this model is signed" is the claim that becomes false
	// when weights sit outside the attestation.
	if anyValid {
		if unsigned := inv.UnsignedExecutables(covered); len(unsigned) > 0 {
			res.Findings = append(res.Findings, Finding{
				ID:       FindingPartialCoverage,
				Title:    fmt.Sprintf("%d executable file(s) outside the signature", len(unsigned)),
				Severity: "High",
				Category: "provenance",
				Location: strings.Join(truncate(unsigned, 8), ", "),
				Description: fmt.Sprintf(
					"A valid signature covers part of this artifact, but %s not attested to. "+
						"These formats execute code when the model is loaded, so the signature "+
						"does not vouch for the code that will actually run.",
					plural(len(unsigned), "file is", "files are")),
			})
		}
	}

	res.Verified = anyValid && !hadFailure && len(inv.UnsignedExecutables(covered)) == 0
	if len(signers) > 0 {
		sort.Strings(signers)
		res.Signer = signers[0]
	}
	for f := range covered {
		res.CoveredFiles = append(res.CoveredFiles, f)
	}
	sort.Strings(res.CoveredFiles)

	if res.Verified {
		res.Findings = append(res.Findings, Finding{
			ID:       FindingVerified,
			Title:    "Signature verified",
			Severity: "Low",
			Category: "provenance",
			Description: fmt.Sprintf(
				"Signed by %s. The signature covers %d file(s), including every format that "+
					"can execute code on load.", res.Signer, len(res.CoveredFiles)),
		})
	}
	return res, nil
}

func (v *Verifier) notConfiguredReason(sigCount int) string {
	switch {
	case !v.policy.Trusted() && v.trusted == nil:
		return fmt.Sprintf(
			"Found %d signature(s), but this cluster declares no TrustedPublisher and no "+
				"Sigstore trust root. Verification was not attempted. Nothing is being "+
				"checked against anything.", sigCount)
	case !v.policy.Trusted():
		return fmt.Sprintf(
			"Found %d signature(s) and a Sigstore trust root, but no TrustedPublisher "+
				"declares whose signatures this cluster accepts. A signature that verifies "+
				"cryptographically still has to be somebody you trust.", sigCount)
	default:
		return fmt.Sprintf(
			"Found %d signature(s) and a TrustedPublisher, but no Sigstore trust root is "+
				"configured, so certificates cannot be chained to a certificate authority. "+
				"Set trustRootPath; leaving it unset avoids fetching one over the network, "+
				"which an air-gapped cluster cannot do.", sigCount)
	}
}

// outcome is the per-signature verification result.
type outcome struct {
	findings []Finding
	covered  []string
	signer   string
	valid    bool
	failed   bool
}

func (v *Verifier) verifyOne(workspace string, sig Signature, publishers []Publisher, inv *Inventory) outcome {
	raw, err := readSignatureFile(filepath.Join(workspace, sig.Path))
	if err != nil {
		return outcome{failed: true, findings: []Finding{{
			ID:          FindingInvalid,
			Title:       "Signature file could not be read",
			Severity:    "High",
			Category:    "provenance",
			Location:    sig.Path,
			Description: err.Error(),
		}}}
	}

	if sig.Kind == KindDetached && sig.CertPath == "" {
		return v.verifyDetachedKey(workspace, sig, raw, publishers)
	}
	return v.verifyBundle(workspace, sig, raw, publishers, inv)
}

// verifyBundle handles Sigstore bundles and DSSE manifest signatures.
func (v *Verifier) verifyBundle(workspace string, sig Signature, raw []byte, publishers []Publisher, inv *Inventory) outcome {
	b := &bundle.Bundle{}
	if err := b.UnmarshalJSON(raw); err != nil {
		return outcome{failed: true, findings: []Finding{{
			ID:       FindingInvalid,
			Title:    "Signature is not a valid Sigstore bundle",
			Severity: "High",
			Category: "provenance",
			Location: sig.Path,
			Description: fmt.Sprintf("The file sits where a signature belongs but does not parse "+
				"as one: %v", err),
		}}}
	}

	// Build the identity policy from the trusted publishers. Verification runs
	// once per candidate publisher; the first that satisfies both the
	// cryptography and the identity wins.
	keyless := filterKeyless(publishers)
	if len(keyless) == 0 {
		return outcome{failed: true, findings: []Finding{{
			ID:       FindingUntrustedSigner,
			Title:    "No trusted publisher accepts this artifact URI",
			Severity: "High",
			Category: "provenance",
			Location: sig.Path,
			Description: "A Sigstore signature is present, but no TrustedPublisher with a " +
				"keyless identity is scoped to this artifact's URI, so there is nobody to " +
				"check the certificate against.",
		}}}
	}

	artifactOpt, coveredPaths, err := v.artifactPolicy(workspace, sig, inv)
	if err != nil {
		return outcome{failed: true, findings: []Finding{{
			ID:          FindingInvalid,
			Title:       "Signature does not correspond to staged files",
			Severity:    "High",
			Category:    "provenance",
			Location:    sig.Path,
			Description: err.Error(),
		}}}
	}

	// Requiring a transparency log also requires an observer timestamp: the
	// log entry is what dates the signature, and without one an expired
	// certificate cannot be told apart from one that was valid when used.
	verifierOpts := []verify.VerifierOption{}
	if v.policy.RequireTransparencyLog {
		verifierOpts = append(verifierOpts, verify.WithTransparencyLog(1), verify.WithObserverTimestamps(1))
	} else {
		verifierOpts = append(verifierOpts, verify.WithNoObserverTimestamps())
	}

	sev, err := verify.NewVerifier(v.trusted, verifierOpts...)
	if err != nil {
		return outcome{failed: true, findings: []Finding{{
			ID:          FindingInvalid,
			Title:       "Verifier could not be constructed",
			Severity:    "High",
			Category:    "provenance",
			Location:    sig.Path,
			Description: err.Error(),
		}}}
	}

	var lastErr error
	for _, pub := range keyless {
		ident, idErr := certIdentity(pub)
		if idErr != nil {
			lastErr = idErr
			continue
		}
		result, vErr := sev.Verify(b, verify.NewPolicy(artifactOpt, verify.WithCertificateIdentity(ident)))
		if vErr != nil {
			lastErr = vErr
			continue
		}
		out := outcome{valid: true, covered: coveredPaths, signer: pub.String()}
		if v.policy.RequireTransparencyLog && len(result.VerifiedTimestamps) == 0 {
			out.findings = append(out.findings, Finding{
				ID:       FindingNoTransparencyLog,
				Title:    "Signature has no transparency-log entry",
				Severity: "Medium",
				Category: "provenance",
				Location: sig.Path,
				Description: "The signature verified but is not recorded in a transparency log, " +
					"so there is no public evidence it was ever made. If the signing key is " +
					"later found compromised, nothing here says what it signed.",
			})
		}
		return out
	}

	// Everything failed. Distinguish "the maths did not work" from "the maths
	// worked but we do not trust that person" — they call for different
	// responses and merging them wastes a responder's time.
	title, sevText, desc := classifyFailure(lastErr, keyless)
	return outcome{failed: true, findings: []Finding{{
		ID:          title,
		Title:       sevText,
		Severity:    severityForFailure(title),
		Category:    "provenance",
		Location:    sig.Path,
		Description: desc,
	}}}
}

// artifactPolicy binds the signature to the bytes it must cover.
func (v *Verifier) artifactPolicy(workspace string, sig Signature, inv *Inventory) (verify.ArtifactPolicyOption, []string, error) {
	if sig.Kind == KindManifest {
		// A manifest signature's subjects are inside the envelope; the
		// envelope itself is what gets verified, and the digests are then
		// checked against the staged files.
		covered, err := v.manifestCoverage(workspace, sig, inv)
		if err != nil {
			return nil, nil, err
		}
		return verify.WithoutArtifactUnsafe(), covered, nil
	}

	target := filepath.Join(workspace, sig.Target)
	f, err := os.Open(target)
	if err != nil {
		return nil, nil, fmt.Errorf("signature %s covers %q, which was not staged", sig.Path, sig.Target)
	}
	defer f.Close()

	digest := sha256.New()
	if _, err := io_Copy(digest, f); err != nil {
		return nil, nil, fmt.Errorf("hash %s: %w", sig.Target, err)
	}
	return verify.WithArtifactDigest("sha256", digest.Sum(nil)), []string{sig.Target}, nil
}

// manifestCoverage reads the in-toto subjects from a manifest signature and
// confirms each named file is staged with the digest the statement claims.
//
// Verifying the envelope alone would prove only that somebody signed a list.
// The list has to match the bytes on disk, or a valid signature over a stale
// manifest would vouch for files that have since changed.
func (v *Verifier) manifestCoverage(workspace string, sig Signature, inv *Inventory) ([]string, error) {
	raw, err := readSignatureFile(filepath.Join(workspace, sig.Path))
	if err != nil {
		return nil, err
	}
	b := &bundle.Bundle{}
	if err := b.UnmarshalJSON(raw); err != nil {
		return nil, fmt.Errorf("parse manifest bundle: %w", err)
	}
	env := b.GetDsseEnvelope()
	if env == nil {
		return nil, fmt.Errorf("manifest signature carries no DSSE envelope")
	}
	st, err := parseStatement(env.GetPayload())
	if err != nil {
		return nil, err
	}

	var covered []string
	var mismatched []string
	for _, subj := range st.Subject {
		name := filepath.Clean(subj.Name)
		want, ok := subj.Digest["sha256"]
		if !ok {
			continue
		}
		got, err := fileSHA256(filepath.Join(workspace, name))
		if err != nil {
			mismatched = append(mismatched, name+" (not staged)")
			continue
		}
		if !strings.EqualFold(got, want) {
			mismatched = append(mismatched, name+" (digest differs)")
			continue
		}
		covered = append(covered, name)
	}
	if len(mismatched) > 0 {
		return nil, fmt.Errorf("manifest lists %s that do not match the staged bytes: %s",
			plural(len(mismatched), "a file", "files"), strings.Join(truncate(mismatched, 5), ", "))
	}
	sort.Strings(covered)
	return covered, nil
}

// verifyDetachedKey verifies a raw signature against a configured public key.
//
// This path exists because plenty of internal signing still happens with a key
// pair and no certificate authority. It cannot offer a transparency log, and
// the finding says so rather than implying equivalence with keyless signing.
func (v *Verifier) verifyDetachedKey(workspace string, sig Signature, rawSig []byte, publishers []Publisher) outcome {
	target := filepath.Join(workspace, sig.Target)
	payload, err := os.ReadFile(target)
	if err != nil {
		return outcome{failed: true, findings: []Finding{{
			ID:          FindingInvalid,
			Title:       "Signature covers a file that was not staged",
			Severity:    "High",
			Category:    "provenance",
			Location:    sig.Path,
			Description: fmt.Sprintf("%s signs %q, which is not present.", sig.Path, sig.Target),
		}}}
	}

	for _, pub := range publishers {
		if pub.PublicKeyPEM == "" {
			continue
		}
		ok, err := verifyRawSignature([]byte(pub.PublicKeyPEM), payload, rawSig)
		if err != nil || !ok {
			continue
		}
		out := outcome{valid: true, covered: []string{sig.Target}, signer: pub.String()}
		if v.policy.RequireTransparencyLog {
			out.findings = append(out.findings, Finding{
				ID:       FindingNoTransparencyLog,
				Title:    "Key-based signature has no transparency log",
				Severity: "Medium",
				Category: "provenance",
				Location: sig.Path,
				Description: "This signature was made with a bare key pair, which leaves no " +
					"public record. Policy requires a transparency-log entry; keyless " +
					"Sigstore signing provides one.",
			})
		}
		return out
	}

	return outcome{failed: true, findings: []Finding{{
		ID:       FindingUntrustedSigner,
		Title:    "No trusted public key verifies this signature",
		Severity: "High",
		Category: "provenance",
		Location: sig.Path,
		Description: fmt.Sprintf("A detached signature is present for %q, but none of the %s "+
			"scoped to this URI verifies it.", sig.Target,
			plural(len(publishers), "trusted publisher", "trusted publishers")),
	}}}
}

// certIdentity converts a publisher into a Sigstore certificate identity.
func certIdentity(pub Publisher) (verify.CertificateIdentity, error) {
	san, sanRegex := pub.Subject, ""
	if strings.HasSuffix(pub.Subject, "*") {
		// Sigstore matches SANs by exact value or regex; a prefix glob becomes
		// an anchored regex with the literal part quoted so a dot in a domain
		// cannot match an arbitrary character.
		san = ""
		sanRegex = "^" + regexpQuoteMeta(strings.TrimSuffix(pub.Subject, "*")) + ".*$"
	}
	return verify.NewShortCertificateIdentity(pub.Issuer, "", san, sanRegex)
}

func filterKeyless(pubs []Publisher) []Publisher {
	var out []Publisher
	for _, p := range pubs {
		if p.Keyless() {
			out = append(out, p)
		}
	}
	return out
}

// classifyFailure decides whether a failure was cryptographic or a matter of
// identity, so the finding points at the right problem.
func classifyFailure(err error, publishers []Publisher) (id, title, desc string) {
	names := make([]string, 0, len(publishers))
	for _, p := range publishers {
		names = append(names, p.String())
	}
	joined := strings.Join(truncate(names, 4), "; ")

	if err == nil {
		return FindingInvalid, "Signature did not verify",
			"Verification failed without a specific reason."
	}
	msg := err.Error()
	lower := strings.ToLower(msg)

	switch {
	case strings.Contains(lower, "certificate identity") ||
		strings.Contains(lower, "no matching certificate") ||
		strings.Contains(lower, "subject") && strings.Contains(lower, "mismatch"):
		return FindingUntrustedSigner, "Signature is valid but the signer is not trusted",
			fmt.Sprintf("The signature is cryptographically sound, so somebody really did sign "+
				"this artifact — just not anybody this cluster accepts. Trusted publishers "+
				"for this URI: %s. Underlying result: %s", joined, msg)
	case strings.Contains(lower, "expired") || strings.Contains(lower, "validity"):
		return FindingInvalid, "Signing certificate was not valid when used",
			fmt.Sprintf("The certificate was outside its validity window at signing time, so "+
				"the signature cannot be tied to a live identity. %s", msg)
	default:
		return FindingInvalid, "Signature failed verification",
			fmt.Sprintf("A signature is present and does not verify against the trusted "+
				"material. Something claimed provenance for this artifact that it cannot "+
				"support, which is worse than an unsigned artifact. %s", msg)
	}
}

func severityForFailure(id string) string {
	if id == FindingInvalid {
		return "Critical"
	}
	return "High"
}

func fileSHA256(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io_Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// verifyRawSignature checks a detached signature against a PEM public key.
func verifyRawSignature(pemKey, payload, sig []byte) (bool, error) {
	block, _ := pem.Decode(pemKey)
	if block == nil {
		return false, fmt.Errorf("public key is not PEM encoded")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return false, fmt.Errorf("parse public key: %w", err)
	}
	// Signatures are conventionally base64 in .sig files written by cosign.
	decoded, err := decodeMaybeBase64(sig)
	if err != nil {
		return false, err
	}
	return checkSignature(pub, payload, decoded)
}

func truncate(items []string, n int) []string {
	if len(items) <= n {
		return items
	}
	out := append([]string{}, items[:n]...)
	return append(out, fmt.Sprintf("and %d more", len(items)-n))
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

var _ = bytes.Equal
