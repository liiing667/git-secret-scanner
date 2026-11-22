package scan

import (
	"os"
	"path"
	"strings"
	"testing"

	"github.com/padok-team/git-secret-scanner/internal/utils"
)

func TestNewBatch(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())

	repos := []string{"org/repo1", "org/repo2"}

	b, err := NewBatch(repos)
	if err != nil {
		t.Fatalf("NewBatch() = _, %v, want _, nil", err)
	}

	if b.ID == "" {
		t.Fatalf(`NewBatch().ID = "", want a non-empty generation ID`)
	}

	wantDir := path.Join(utils.TempDirPath(), batchesDirName, b.ID)
	if b.Dir() != wantDir {
		t.Fatalf("NewBatch().Dir() = %q, want %q", b.Dir(), wantDir)
	}

	info, err := os.Stat(b.Dir())
	if err != nil || !info.IsDir() {
		t.Fatalf("batch directory %q does not exist: %v", b.Dir(), err)
	}

	if len(b.Repos) != len(repos) {
		t.Fatalf("NewBatch().Repos = %v, want %v", b.Repos, repos)
	}
	for i, repo := range repos {
		if b.Repos[i] != repo {
			t.Fatalf("NewBatch().Repos[%d] = %q, want %q", i, b.Repos[i], repo)
		}
	}
}

func TestNewBatchGenerationsAreUnique(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())

	repos := []string{"org/repo"}

	b1, err := NewBatch(repos)
	if err != nil {
		t.Fatalf("NewBatch() = _, %v, want _, nil", err)
	}
	b2, err := NewBatch(repos)
	if err != nil {
		t.Fatalf("NewBatch() = _, %v, want _, nil", err)
	}

	if b1.ID == b2.ID {
		t.Fatalf("NewBatch() generations are not unique: both have ID %q", b1.ID)
	}
	if b1.Dir() == b2.Dir() {
		t.Fatalf("NewBatch() generations share the same directory %q", b1.Dir())
	}

	// a leftover artifact of a previous generation must not be reused nor
	// removed by a new batch
	halfClone := path.Join(b1.RepoDir("org/repo"), ".git")
	if err := os.MkdirAll(halfClone, 0o755); err != nil {
		t.Fatalf("os.MkdirAll(%q) = %v, want nil", halfClone, err)
	}

	b3, err := NewBatch(repos)
	if err != nil {
		t.Fatalf("NewBatch() = _, %v, want _, nil", err)
	}

	if b3.Dir() == b1.Dir() {
		t.Fatalf("NewBatch() reused directory %q of a previous generation", b3.Dir())
	}
	if _, err := os.Stat(halfClone); err != nil {
		t.Fatalf("artifact of a previous generation was altered: %v", err)
	}
}

func TestNewBatchSnapshotsManifest(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())

	repos := []string{"org/repo1", "org/repo2"}

	b, err := NewBatch(repos)
	if err != nil {
		t.Fatalf("NewBatch() = _, %v, want _, nil", err)
	}

	// mutating the input slice after the batch creation must not affect the
	// manifest of the batch
	repos[0] = "org/other"

	if b.Repos[0] != "org/repo1" {
		t.Fatalf("NewBatch().Repos[0] = %q, want %q", b.Repos[0], "org/repo1")
	}
}

func TestBatchRepoDir(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())

	b, err := NewBatch([]string{"org/repo"})
	if err != nil {
		t.Fatalf("NewBatch() = _, %v, want _, nil", err)
	}

	got := b.RepoDir("org/repo")
	want := path.Join(b.Dir(), "org/repo")

	if got != want {
		t.Fatalf("Batch.RepoDir() = %q, want %q", got, want)
	}
	if !strings.HasPrefix(got, b.Dir()+string(os.PathSeparator)) {
		t.Fatalf("Batch.RepoDir() = %q, want a path inside the batch directory %q", got, b.Dir())
	}
}

func TestBatchCleanup(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())

	b, err := NewBatch([]string{"org/repo"})
	if err != nil {
		t.Fatalf("NewBatch() = _, %v, want _, nil", err)
	}

	if err := os.MkdirAll(b.RepoDir("org/repo"), 0o755); err != nil {
		t.Fatalf("os.MkdirAll() = %v, want nil", err)
	}

	if err := b.Cleanup(); err != nil {
		t.Fatalf("Batch.Cleanup() = %v, want nil", err)
	}

	if _, err := os.Stat(b.Dir()); !os.IsNotExist(err) {
		t.Fatalf("batch directory %q still exists after cleanup", b.Dir())
	}
}
