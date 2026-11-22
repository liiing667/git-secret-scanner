package git

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// ProvenanceFileName is the name of the file written into every clone made by
// the scanner, recording what the clone contains and how it was fetched.
const ProvenanceFileName string = ".git-secret-scanner-provenance.json"

// Provenance binds a local clone to the normalized identity of the repository
// it was fetched from, the SCM source (provider) and the credential
// generation used to fetch it. It never contains the credential itself, only
// a non-reversible fingerprint, and the recorded URL is sanitized.
type Provenance struct {
	Provider              string       `json:"provider"`
	Identity              RepoIdentity `json:"identity"`
	Protocol              Protocol     `json:"protocol"`
	CredentialGeneration  int          `json:"credential_generation"`
	CredentialFingerprint string       `json:"credential_fingerprint"`
	URL                   string       `json:"url"`
	UpdatedAt             time.Time    `json:"updated_at"`
}

// NewProvenance builds the provenance record of a clone of the repository
// identified by identity, fetched from rawURL with the given credential
// generation and token.
func NewProvenance(provider string, identity RepoIdentity, generation int, token string, rawURL string) (Provenance, error) {
	_, protocol, err := ParseRepoURL(rawURL)
	if err != nil {
		return Provenance{}, fmt.Errorf("cannot build provenance for invalid repository URL: %w", err)
	}

	return Provenance{
		Provider:              provider,
		Identity:              identity,
		Protocol:              protocol,
		CredentialGeneration:  generation,
		CredentialFingerprint: FingerprintCredential(token),
		URL:                   SanitizeURL(rawURL),
		UpdatedAt:             time.Now().UTC(),
	}, nil
}

// SameRepository reports whether both provenance records describe the same
// repository coming from the same SCM source.
func (p Provenance) SameRepository(other Provenance) bool {
	return p.Provider == other.Provider && p.Identity == other.Identity
}

// SameCredential reports whether both provenance records were fetched with
// the same credential.
func (p Provenance) SameCredential(other Provenance) bool {
	return p.CredentialFingerprint == other.CredentialFingerprint
}

// WriteProvenance stores the provenance record of a clone on disk.
func WriteProvenance(destination string, p Provenance) error {
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return os.WriteFile(provenancePath(destination), b, 0o600)
}

// ReadProvenance reads the provenance record of a clone. It returns an error
// if no provenance was recorded or if it cannot be decoded.
func ReadProvenance(destination string) (Provenance, error) {
	var p Provenance

	b, err := os.ReadFile(provenancePath(destination))
	if err != nil {
		return p, err
	}

	if err := json.Unmarshal(b, &p); err != nil {
		return Provenance{}, fmt.Errorf("invalid provenance file in %q: %w", destination, err)
	}

	return p, nil
}

func provenancePath(destination string) string {
	return filepath.Join(destination, ProvenanceFileName)
}
