package provenance

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, dir, name, content string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func findingIDs(res *Result) []string {
	var out []string
	for _, f := range res.Findings {
		out = append(out, f.ID)
	}
	return out
}

func hasFinding(res *Result, id string) bool {
	for _, f := range res.Findings {
		if f.ID == id {
			return true
		}
	}
	return false
}

func TestUnsignedArtifactIsReported(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "model.safetensors", "weights")
	write(t, dir, "config.json", "{}")

	v, err := NewVerifier(Policy{})
	if err != nil {
		t.Fatal(err)
	}
	res, err := v.Verify(dir, "s3://models/x")
	if err != nil {
		t.Fatal(err)
	}
	if !hasFinding(res, FindingUnsigned) {
		t.Fatalf("want %s, got %v", FindingUnsigned, findingIDs(res))
	}
	if res.Verified {
		t.Fatal("an unsigned artifact must never report Verified")
	}
}

// The distinction this test protects is the whole point of FindingNotConfigured:
// a cluster with no trust root has a configuration problem, and reporting that
// as "unsigned" sends the reader to inspect the model instead of the cluster.
func TestSignaturePresentButClusterNotConfigured(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "model.safetensors", "weights")
	write(t, dir, "model.safetensors.sigstore.json", `{"mediaType":"x"}`)

	v, err := NewVerifier(Policy{})
	if err != nil {
		t.Fatal(err)
	}
	res, err := v.Verify(dir, "s3://models/x")
	if err != nil {
		t.Fatal(err)
	}
	if !hasFinding(res, FindingNotConfigured) {
		t.Fatalf("want %s, got %v", FindingNotConfigured, findingIDs(res))
	}
	if hasFinding(res, FindingUnsigned) {
		t.Fatal("an artifact that carries a signature must not be reported as unsigned")
	}
}

func TestNotConfiguredReasonNamesTheMissingPiece(t *testing.T) {
	cases := []struct {
		name   string
		policy Policy
		want   string
	}{
		{"nothing", Policy{}, "no TrustedPublisher and no"},
		{"publishers only", Policy{Publishers: []Publisher{{Name: "a", Issuer: "i", Subject: "s"}}}, "no Sigstore trust root"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := &Verifier{policy: tc.policy}
			got := v.notConfiguredReason(1)
			if !strings.Contains(got, tc.want) {
				t.Fatalf("reason %q does not mention %q", got, tc.want)
			}
		})
	}
}

// Partial coverage is the fail-open shape for provenance: a valid signature
// over one file must not make the whole directory read as signed.
func TestUnsignedExecutablesAreFound(t *testing.T) {
	inv := &Inventory{Files: []string{
		"model.safetensors",
		"weights.pkl",
		"pytorch_model.bin",
		"README.md",
		"tokenizer.json",
	}}
	covered := map[string]bool{"model.safetensors": true, "README.md": true}

	got := inv.UnsignedExecutables(covered)
	want := []string{"pytorch_model.bin", "weights.pkl"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestSafetensorsIsNotExecutable(t *testing.T) {
	if ExecutableFormat("model.safetensors") != "" {
		t.Fatal("safetensors cannot execute code on load and must not be flagged")
	}
	if ExecutableFormat("weights.pkl") == "" {
		t.Fatal("pickle executes on load and must be flagged")
	}
	if ExecutableFormat("model.PKL") == "" {
		t.Fatal("extension matching must be case-insensitive")
	}
}

func TestDiscoverSeparatesSignaturesFromArtifacts(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "model.safetensors", "w")
	write(t, dir, "model.safetensors.sigstore.json", "{}")
	write(t, dir, "weights.pkl", "p")
	write(t, dir, "weights.pkl.sig", "sig")
	write(t, dir, "weights.pkl.crt", "cert")
	write(t, dir, "config.json", "{}")

	inv, err := Discover(dir)
	if err != nil {
		t.Fatal(err)
	}
	// The .crt is signature material, not an artifact file.
	for _, f := range inv.Files {
		if strings.HasSuffix(f, ".sig") || strings.HasSuffix(f, ".crt") || strings.Contains(f, "sigstore") {
			t.Fatalf("signature material %q was counted as an artifact file", f)
		}
	}
	if len(inv.Signatures) != 2 {
		t.Fatalf("want 2 signatures, got %d: %+v", len(inv.Signatures), inv.Signatures)
	}
	for _, s := range inv.Signatures {
		if s.Kind == KindDetached && s.CertPath == "" {
			t.Fatal("the detached signature should have found its certificate")
		}
	}
}

func TestManifestSignatureIsRecognised(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "model.safetensors", "w")
	write(t, dir, "model.sig", "{}")

	inv, err := Discover(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Signatures) != 1 || inv.Signatures[0].Kind != KindManifest {
		t.Fatalf("want one manifest signature, got %+v", inv.Signatures)
	}
}

func TestURIScopingLimitsPublishers(t *testing.T) {
	policy := Policy{Publishers: []Publisher{
		{Name: "internal", URIPrefixes: []string{"oci://registry.internal/"}},
		{Name: "anywhere"},
		{Name: "hub", URIPrefixes: []string{"hf://"}},
	}}

	got := policy.PublishersForURI("oci://registry.internal/models/x")
	if len(got) != 2 {
		t.Fatalf("want internal+anywhere, got %d", len(got))
	}
	got = policy.PublishersForURI("s3://elsewhere/x")
	if len(got) != 1 || got[0].Name != "anywhere" {
		t.Fatalf("a scoped publisher must not sign outside its prefix, got %+v", got)
	}
}

func TestSubjectGlobIsPrefixOnly(t *testing.T) {
	p := Publisher{Subject: "https://github.com/davano/*"}
	if !p.MatchesSubject("https://github.com/davano/assay/.github/workflows/release.yml@refs/tags/v1") {
		t.Fatal("prefix glob should match")
	}
	if p.MatchesSubject("https://github.com/evil/repo") {
		t.Fatal("prefix glob must not match a different org")
	}

	exact := Publisher{Subject: "release@davano.net"}
	if exact.MatchesSubject("attacker-release@davano.net") {
		t.Fatal("a non-glob subject must match exactly, not as a substring")
	}
}

// A raw signature that verifies against a configured key is the on-prem path;
// this proves the crypto actually checks rather than always returning true.
func TestDetachedKeySignatureRoundTrip(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})

	payload := []byte("model weights")
	digest := sha256.Sum256(payload)
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	encoded := []byte(base64.StdEncoding.EncodeToString(sig))

	ok, err := verifyRawSignature(pubPEM, payload, encoded)
	if err != nil || !ok {
		t.Fatalf("valid signature failed to verify: ok=%v err=%v", ok, err)
	}

	// Tampering with the payload must break it.
	ok, err = verifyRawSignature(pubPEM, []byte("model weights!"), encoded)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("a signature must not verify against modified bytes")
	}
}

func TestDetachedKeyVerificationEndToEnd(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	dir := t.TempDir()
	payload := "the real weights"
	write(t, dir, "model.pkl", payload)
	digest := sha256.Sum256([]byte(payload))
	raw, _ := ecdsa.SignASN1(rand.Reader, key, digest[:])
	write(t, dir, "model.pkl.sig", base64.StdEncoding.EncodeToString(raw))

	v := &Verifier{policy: Policy{
		Publishers: []Publisher{{Name: "onprem", PublicKeyPEM: pubPEM}},
	}}
	inv, _ := Discover(dir)
	sigBytes, _ := os.ReadFile(filepath.Join(dir, "model.pkl.sig"))
	out := v.verifyDetachedKey(dir, inv.Signatures[0], sigBytes, v.policy.Publishers)

	if !out.valid {
		t.Fatalf("expected the signature to verify, findings: %+v", out.findings)
	}
	if len(out.covered) != 1 || out.covered[0] != "model.pkl" {
		t.Fatalf("coverage should name the signed file, got %v", out.covered)
	}
}

func TestDetachedKeyRejectsWrongKey(t *testing.T) {
	signing, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&other.PublicKey)
	otherPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	dir := t.TempDir()
	write(t, dir, "model.pkl", "weights")
	digest := sha256.Sum256([]byte("weights"))
	raw, _ := ecdsa.SignASN1(rand.Reader, signing, digest[:])
	write(t, dir, "model.pkl.sig", base64.StdEncoding.EncodeToString(raw))

	v := &Verifier{policy: Policy{
		Publishers: []Publisher{{Name: "wrong", PublicKeyPEM: otherPEM}},
	}}
	inv, _ := Discover(dir)
	sigBytes, _ := os.ReadFile(filepath.Join(dir, "model.pkl.sig"))
	out := v.verifyDetachedKey(dir, inv.Signatures[0], sigBytes, v.policy.Publishers)

	if out.valid {
		t.Fatal("a signature from a different key must not verify")
	}
	if out.findings[0].ID != FindingUntrustedSigner {
		t.Fatalf("want %s, got %s", FindingUntrustedSigner, out.findings[0].ID)
	}
}

func TestFailureClassificationSeparatesIdentityFromCrypto(t *testing.T) {
	pubs := []Publisher{{Name: "p", Issuer: "https://accounts.google.com", Subject: "a@b.c"}}

	id, _, _ := classifyFailure(errString("no matching certificate identity found"), pubs)
	if id != FindingUntrustedSigner {
		t.Fatalf("an identity mismatch should be %s, got %s", FindingUntrustedSigner, id)
	}

	id, _, _ = classifyFailure(errString("signature does not match"), pubs)
	if id != FindingInvalid {
		t.Fatalf("a cryptographic failure should be %s, got %s", FindingInvalid, id)
	}
	if severityForFailure(FindingInvalid) != "Critical" {
		t.Fatal("a forged signature is worse than an unsigned artifact and must be Critical")
	}
}

type errString string

func (e errString) Error() string { return string(e) }
