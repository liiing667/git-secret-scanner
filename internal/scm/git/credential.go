package git

import (
	"crypto/sha256"
	"encoding/hex"
)

// FingerprintCredential returns a stable, non-reversible fingerprint of a
// credential (e.g. an SCM token). It allows clones and findings to be bound
// to the credential they were fetched with, without ever storing the
// credential itself.
func FingerprintCredential(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
