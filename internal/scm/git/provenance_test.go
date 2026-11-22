package git

import (
	"strings"
	"testing"
)

func TestNewProvenance(t *testing.T) {
	identity := NewRepoIdentity("github.com", "Test_User/Test_Repo")

	p, err := NewProvenance("github", identity, 2, "faketoken", "https://x-access-token:faketoken@github.com/Test_User/Test_Repo")
	if err != nil {
		t.Fatalf(`NewProvenance(...) = _, %v, want _, nil`, err)
	}

	if p.Provider != "github" {
		t.Fatalf(`provenance.Provider = %q, want "github"`, p.Provider)
	}
	if p.Identity != identity {
		t.Fatalf(`provenance.Identity = %v, want %v`, p.Identity, identity)
	}
	if p.Protocol != ProtocolHTTPS {
		t.Fatalf(`provenance.Protocol = %v, want %v`, p.Protocol, ProtocolHTTPS)
	}
	if p.CredentialGeneration != 2 {
		t.Fatalf(`provenance.CredentialGeneration = %d, want 2`, p.CredentialGeneration)
	}
	if p.CredentialFingerprint != FingerprintCredential("faketoken") {
		t.Fatalf(`provenance.CredentialFingerprint = %q, want %q`, p.CredentialFingerprint, FingerprintCredential("faketoken"))
	}
	// the recorded URL must not contain the credential
	if strings.Contains(p.URL, "faketoken") {
		t.Fatalf(`provenance.URL = %q, must not contain the credential`, p.URL)
	}
	if p.URL != "https://github.com/Test_User/Test_Repo" {
		t.Fatalf(`provenance.URL = %q, want %q`, p.URL, "https://github.com/Test_User/Test_Repo")
	}
}

func TestNewProvenanceInvalidURL(t *testing.T) {
	_, err := NewProvenance("github", NewRepoIdentity("github.com", "test_user/test_repo"), 1, "faketoken", "not-a-url")
	if err == nil {
		t.Fatalf(`NewProvenance(..., "not-a-url") = _, nil, want error`)
	}
}

func TestWriteReadProvenance(t *testing.T) {
	dir := t.TempDir()

	identity := NewRepoIdentity("github.com", "test_user/test_repo")
	p, err := NewProvenance("github", identity, 1, "faketoken", "git@github.com:test_user/test_repo.git")
	if err != nil {
		t.Fatalf(`NewProvenance(...) = _, %v, want _, nil`, err)
	}

	if err := WriteProvenance(dir, p); err != nil {
		t.Fatalf(`WriteProvenance(...) = %v, want nil`, err)
	}

	got, err := ReadProvenance(dir)
	if err != nil {
		t.Fatalf(`ReadProvenance(...) = _, %v, want _, nil`, err)
	}

	if got.Provider != p.Provider || got.Identity != p.Identity || got.Protocol != p.Protocol ||
		got.CredentialGeneration != p.CredentialGeneration || got.CredentialFingerprint != p.CredentialFingerprint ||
		got.URL != p.URL {
		t.Fatalf(`ReadProvenance(...) = %v, want %v`, got, p)
	}

	if !got.SameRepository(p) || !got.SameCredential(p) {
		t.Fatalf(`ReadProvenance(...) = %v, want a provenance identical to %v`, got, p)
	}
}

func TestReadProvenanceMissing(t *testing.T) {
	if _, err := ReadProvenance(t.TempDir()); err == nil {
		t.Fatalf(`ReadProvenance(empty dir) = _, nil, want error`)
	}
}

func TestProvenanceSameRepository(t *testing.T) {
	a := Provenance{Provider: "github", Identity: NewRepoIdentity("github.com", "test_user/test_repo")}
	b := Provenance{Provider: "github", Identity: NewRepoIdentity("GitHub.com", "Test_User/Test_Repo.git")}
	c := Provenance{Provider: "gitlab", Identity: NewRepoIdentity("github.com", "test_user/test_repo")}
	d := Provenance{Provider: "github", Identity: NewRepoIdentity("github.com", "test_user/other_repo")}
	e := Provenance{Provider: "github", Identity: NewRepoIdentity("github.example.com", "test_user/test_repo")}

	if !a.SameRepository(b) {
		t.Fatalf(`%v.SameRepository(%v) = false, want true (case and ".git" suffix must be normalized)`, a, b)
	}
	if a.SameRepository(c) {
		t.Fatalf(`%v.SameRepository(%v) = true, want false (different SCM sources)`, a, c)
	}
	if a.SameRepository(d) {
		t.Fatalf(`%v.SameRepository(%v) = true, want false (different repositories)`, a, d)
	}
	if a.SameRepository(e) {
		t.Fatalf(`%v.SameRepository(%v) = true, want false (different servers)`, a, e)
	}
}

func TestProvenanceSameCredential(t *testing.T) {
	a := Provenance{CredentialFingerprint: FingerprintCredential("faketoken-a")}
	b := Provenance{CredentialFingerprint: FingerprintCredential("faketoken-a")}
	c := Provenance{CredentialFingerprint: FingerprintCredential("faketoken-b")}

	if !a.SameCredential(b) {
		t.Fatalf(`%v.SameCredential(%v) = false, want true`, a, b)
	}
	if a.SameCredential(c) {
		t.Fatalf(`%v.SameCredential(%v) = true, want false`, a, c)
	}
}
