package git

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// initTestRepo creates a git repository with a single commit and returns its
// path.
func initTestRepo(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()

	r, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatalf(`git.PlainInit(%q) = _, %v, want _, nil`, dir, err)
	}

	if err := os.WriteFile(filepath.Join(dir, "file.txt"), []byte("content"), 0o644); err != nil {
		t.Fatalf(`os.WriteFile(...) = %v, want nil`, err)
	}

	w, err := r.Worktree()
	if err != nil {
		t.Fatalf(`r.Worktree() = _, %v, want _, nil`, err)
	}
	if _, err := w.Add("file.txt"); err != nil {
		t.Fatalf(`w.Add("file.txt") = _, %v, want _, nil`, err)
	}
	_, err = w.Commit("initial commit", &git.CommitOptions{
		Author: &object.Signature{Name: "test", Email: "test@example.com", When: time.Now()},
	})
	if err != nil {
		t.Fatalf(`w.Commit(...) = _, %v, want _, nil`, err)
	}

	return dir
}

func testProvenance(provider string, identity RepoIdentity, generation int, token string, url string) *Provenance {
	return &Provenance{
		Provider:              provider,
		Identity:              identity,
		Protocol:              ProtocolHTTPS,
		CredentialGeneration:  generation,
		CredentialFingerprint: FingerprintCredential(token),
		URL:                   url,
		UpdatedAt:             time.Now().UTC(),
	}
}

func TestClone(t *testing.T) {
	src := initTestRepo(t)
	dst := filepath.Join(t.TempDir(), "clone")

	// fresh full clone
	if err := Clone(context.Background(), "file://"+src, dst, false, true); err != nil {
		t.Fatalf(`Clone(...) = %v, want nil`, err)
	}
	// cloning again with fetchIfExists must not fail
	if err := Clone(context.Background(), "file://"+src, dst, false, true); err != nil {
		t.Fatalf(`Clone(...) on existing clone = %v, want nil`, err)
	}
	// cloning again without fetchIfExists must not fail either
	if err := Clone(context.Background(), "file://"+src, dst, false, false); err != nil {
		t.Fatalf(`Clone(...) on existing clone = %v, want nil`, err)
	}

	// shallow clone
	dstShallow := filepath.Join(t.TempDir(), "clone-shallow")
	if err := Clone(context.Background(), "file://"+src, dstShallow, true, true); err != nil {
		t.Fatalf(`Clone(..., shallow) = %v, want nil`, err)
	}
}

func TestCloneRepositoryWritesProvenance(t *testing.T) {
	src := initTestRepo(t)
	dst := filepath.Join(t.TempDir(), "clone")

	identity := NewRepoIdentity("github.com", "test_user/test_repo")
	provenance := testProvenance("github", identity, 1, "faketoken", "file://"+src)

	err := CloneRepository(context.Background(), CloneRequest{
		URL:           "file://" + src,
		Destination:   dst,
		Shallow:       false,
		FetchIfExists: true,
		Identity:      identity,
		Provenance:    provenance,
	})
	if err != nil {
		t.Fatalf(`CloneRepository(...) = %v, want nil`, err)
	}

	stored, err := ReadProvenance(dst)
	if err != nil {
		t.Fatalf(`ReadProvenance(...) = _, %v, want _, nil`, err)
	}
	if !stored.SameRepository(*provenance) || !stored.SameCredential(*provenance) {
		t.Fatalf(`ReadProvenance(...) = %v, want %v`, stored, *provenance)
	}
	if stored.CredentialGeneration != 1 {
		t.Fatalf(`stored.CredentialGeneration = %d, want 1`, stored.CredentialGeneration)
	}
}

func TestCloneRepositoryBindsNewCredentialGeneration(t *testing.T) {
	src := initTestRepo(t)
	dst := filepath.Join(t.TempDir(), "clone")

	identity := NewRepoIdentity("github.com", "test_user/test_repo")

	// first clone, fetched with the first credential generation
	err := CloneRepository(context.Background(), CloneRequest{
		URL:           "file://" + src,
		Destination:   dst,
		Shallow:       false,
		FetchIfExists: true,
		Identity:      identity,
		Provenance:    testProvenance("github", identity, 1, "faketoken-a", "file://"+src),
	})
	if err != nil {
		t.Fatalf(`CloneRepository(...) = %v, want nil`, err)
	}

	// retry of the same repository with another credential: the clone is
	// refreshed and bound to the new credential generation
	err = CloneRepository(context.Background(), CloneRequest{
		URL:           "file://" + src,
		Destination:   dst,
		Shallow:       false,
		FetchIfExists: true,
		Identity:      identity,
		Provenance:    testProvenance("github", identity, 2, "faketoken-b", "file://"+src),
	})
	if err != nil {
		t.Fatalf(`CloneRepository(...) = %v, want nil`, err)
	}

	stored, err := ReadProvenance(dst)
	if err != nil {
		t.Fatalf(`ReadProvenance(...) = _, %v, want _, nil`, err)
	}
	if stored.CredentialGeneration != 2 || stored.CredentialFingerprint != FingerprintCredential("faketoken-b") {
		t.Fatalf(`stored provenance = %v, want generation 2 with the fingerprint of "faketoken-b"`, stored)
	}
}

func TestCloneRepositoryRebindsStaleRemoteURL(t *testing.T) {
	src := initTestRepo(t)
	dst := filepath.Join(t.TempDir(), "clone")

	identity := NewRepoIdentity("github.com", "test_user/test_repo")
	provenance := testProvenance("github", identity, 1, "faketoken", "file://"+src)

	req := CloneRequest{
		URL:           "file://" + src,
		Destination:   dst,
		Shallow:       false,
		FetchIfExists: true,
		Identity:      identity,
		Provenance:    provenance,
	}
	if err := CloneRepository(context.Background(), req); err != nil {
		t.Fatalf(`CloneRepository(...) = %v, want nil`, err)
	}

	// simulate an existing clone whose origin still points to the old SCM
	// URL (e.g. left over by a failed HTTPS attempt before an SSH retry)
	if err := SetRemoteURL(dst, "https://x-access-token:faketoken@github.com/test_user/test_repo"); err != nil {
		t.Fatalf(`SetRemoteURL(...) = %v, want nil`, err)
	}

	// the retry must bind the clone back to the current URL before fetching
	if err := CloneRepository(context.Background(), req); err != nil {
		t.Fatalf(`CloneRepository(...) after remote change = %v, want nil`, err)
	}

	remote, err := RemoteURL(dst)
	if err != nil {
		t.Fatalf(`RemoteURL(...) = _, %v, want _, nil`, err)
	}
	if remote != "file://"+src {
		t.Fatalf(`RemoteURL(...) = %q, want %q`, remote, "file://"+src)
	}
}

func TestCloneRepositoryRecloneOnIdentityMismatch(t *testing.T) {
	srcA := initTestRepo(t)
	srcB := initTestRepo(t)
	dst := filepath.Join(t.TempDir(), "clone")

	identityA := NewRepoIdentity("github.com", "test_user/test_repo_a")
	identityB := NewRepoIdentity("github.com", "test_user/test_repo_b")

	// clone a first repository
	err := CloneRepository(context.Background(), CloneRequest{
		URL:           "file://" + srcA,
		Destination:   dst,
		Shallow:       false,
		FetchIfExists: true,
		Identity:      identityA,
		Provenance:    testProvenance("github", identityA, 1, "faketoken", "file://"+srcA),
	})
	if err != nil {
		t.Fatalf(`CloneRepository(...) = %v, want nil`, err)
	}

	// another repository reusing the same destination (e.g. a different SCM
	// entry point with a colliding name) must trigger a fresh clone: the
	// content of the first repository must never be attributed to the second
	err = CloneRepository(context.Background(), CloneRequest{
		URL:           "file://" + srcB,
		Destination:   dst,
		Shallow:       false,
		FetchIfExists: true,
		Identity:      identityB,
		Provenance:    testProvenance("github", identityB, 1, "faketoken", "file://"+srcB),
	})
	if err != nil {
		t.Fatalf(`CloneRepository(...) with another identity = %v, want nil`, err)
	}

	stored, err := ReadProvenance(dst)
	if err != nil {
		t.Fatalf(`ReadProvenance(...) = _, %v, want _, nil`, err)
	}
	if stored.Identity != identityB {
		t.Fatalf(`stored.Identity = %v, want %v`, stored.Identity, identityB)
	}

	remote, err := RemoteURL(dst)
	if err != nil {
		t.Fatalf(`RemoteURL(...) = _, %v, want _, nil`, err)
	}
	if remote != "file://"+srcB {
		t.Fatalf(`RemoteURL(...) = %q, want %q`, remote, "file://"+srcB)
	}
}

func TestCloneRepositoryRecloneOnProviderMismatch(t *testing.T) {
	src := initTestRepo(t)
	dst := filepath.Join(t.TempDir(), "clone")

	identity := NewRepoIdentity("github.com", "test_user/test_repo")

	// clone from a first SCM source
	err := CloneRepository(context.Background(), CloneRequest{
		URL:           "file://" + src,
		Destination:   dst,
		Shallow:       false,
		FetchIfExists: true,
		Identity:      identity,
		Provenance:    testProvenance("github", identity, 1, "faketoken", "file://"+src),
	})
	if err != nil {
		t.Fatalf(`CloneRepository(...) = %v, want nil`, err)
	}

	// the same repository identity coming from another SCM source must not
	// reuse the existing clone
	err = CloneRepository(context.Background(), CloneRequest{
		URL:           "file://" + src,
		Destination:   dst,
		Shallow:       false,
		FetchIfExists: true,
		Identity:      identity,
		Provenance:    testProvenance("gitlab", identity, 1, "faketoken", "file://"+src),
	})
	if err != nil {
		t.Fatalf(`CloneRepository(...) with another provider = %v, want nil`, err)
	}

	stored, err := ReadProvenance(dst)
	if err != nil {
		t.Fatalf(`ReadProvenance(...) = _, %v, want _, nil`, err)
	}
	if stored.Provider != "gitlab" {
		t.Fatalf(`stored.Provider = %q, want "gitlab"`, stored.Provider)
	}
}

func TestCloneRepositoryNoFetchWithOtherCredential(t *testing.T) {
	src := initTestRepo(t)
	dst := filepath.Join(t.TempDir(), "clone")

	identity := NewRepoIdentity("github.com", "test_user/test_repo")

	// first clone, fetched with the first credential generation
	err := CloneRepository(context.Background(), CloneRequest{
		URL:           "file://" + src,
		Destination:   dst,
		Shallow:       false,
		FetchIfExists: true,
		Identity:      identity,
		Provenance:    testProvenance("github", identity, 1, "faketoken-a", "file://"+src),
	})
	if err != nil {
		t.Fatalf(`CloneRepository(...) = %v, want nil`, err)
	}

	// without fetch, content fetched under another credential generation
	// must not be reused: the clone is dropped and fetched again with the
	// current credential
	err = CloneRepository(context.Background(), CloneRequest{
		URL:           "file://" + src,
		Destination:   dst,
		Shallow:       false,
		FetchIfExists: false,
		Identity:      identity,
		Provenance:    testProvenance("github", identity, 2, "faketoken-b", "file://"+src),
	})
	if err != nil {
		t.Fatalf(`CloneRepository(...) = %v, want nil`, err)
	}

	stored, err := ReadProvenance(dst)
	if err != nil {
		t.Fatalf(`ReadProvenance(...) = _, %v, want _, nil`, err)
	}
	if stored.CredentialGeneration != 2 || stored.CredentialFingerprint != FingerprintCredential("faketoken-b") {
		t.Fatalf(`stored provenance = %v, want generation 2 with the fingerprint of "faketoken-b"`, stored)
	}
}
