package scm

import (
	"sync"

	"github.com/padok-team/git-secret-scanner/internal/scm/git"
)

// CredentialRegistry assigns a stable generation number to every distinct
// credential used during a scan. Findings and clones are bound to the
// generation of the credential they were fetched with, so that content
// retrieved with one credential can never be attributed to another one.
//
// Credentials are only compared through non-reversible fingerprints and are
// never stored by the registry.
type CredentialRegistry struct {
	mu          sync.Mutex
	generations map[string]int
}

func NewCredentialRegistry() *CredentialRegistry {
	return &CredentialRegistry{generations: make(map[string]int)}
}

// Generation returns the generation assigned to the given credential. The
// same credential always yields the same generation, while every new
// distinct credential is assigned the next generation. It is safe for
// concurrent use.
func (r *CredentialRegistry) Generation(token string) int {
	fingerprint := git.FingerprintCredential(token)

	r.mu.Lock()
	defer r.mu.Unlock()

	if generation, ok := r.generations[fingerprint]; ok {
		return generation
	}
	generation := len(r.generations) + 1
	r.generations[fingerprint] = generation
	return generation
}
