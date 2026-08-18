package provenance

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"regexp"
)

// io_Copy is io.Copy, aliased so the hashing helpers read the same in both
// files without each importing io separately.
func io_Copy(dst io.Writer, src io.Reader) (int64, error) { return io.Copy(dst, src) }

// regexpQuoteMeta escapes a literal for use inside a certificate-identity
// regex.
func regexpQuoteMeta(s string) string { return regexp.QuoteMeta(s) }

// decodeMaybeBase64 accepts a signature written either as raw bytes or as the
// base64 that cosign writes into .sig files.
func decodeMaybeBase64(sig []byte) ([]byte, error) {
	trimmed := trimSpace(sig)
	if decoded, err := base64.StdEncoding.DecodeString(string(trimmed)); err == nil {
		return decoded, nil
	}
	return sig, nil
}

func trimSpace(b []byte) []byte {
	start, end := 0, len(b)
	for start < end && isSpace(b[start]) {
		start++
	}
	for end > start && isSpace(b[end-1]) {
		end--
	}
	return b[start:end]
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}

// checkSignature verifies a signature over a payload with a parsed public key.
//
// The digest is always SHA-256: it is what cosign produces and what every
// signer in this path uses. Accepting a caller-chosen algorithm would let a
// weak one be negotiated by whoever wrote the signature file, which is the
// wrong party to be deciding that.
func checkSignature(pub any, payload, sig []byte) (bool, error) {
	digest := sha256.Sum256(payload)

	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		return ecdsa.VerifyASN1(key, digest[:], sig), nil
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig); err == nil {
			return true, nil
		}
		// Some signers emit PSS; try it before declaring failure.
		if err := rsa.VerifyPSS(key, crypto.SHA256, digest[:], sig, nil); err == nil {
			return true, nil
		}
		return false, nil
	case ed25519.PublicKey:
		// Ed25519 signs the message itself, not a pre-computed digest.
		return ed25519.Verify(key, payload, sig), nil
	default:
		return false, fmt.Errorf("unsupported public key type %T", pub)
	}
}
