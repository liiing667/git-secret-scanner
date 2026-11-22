package scan

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path"
	"time"

	"github.com/padok-team/git-secret-scanner/internal/utils"
)

const (
	// batchesDirName is the subdirectory of the tool temporary directory in
	// which every scan batch allocates its own generation-scoped directory.
	batchesDirName = "batches"

	// maxBatchDirAllocAttempts bounds the number of tries to allocate a
	// unique batch directory before giving up.
	maxBatchDirAllocAttempts = 3
)

// Batch ties the artifacts of a single scan run to one generation: the
// repository manifest, the clone directories, the findings and the staged
// report all belong to exactly one batch. Artifacts of a batch are never
// shared with or reused by another batch, in particular after a repository
// retry or a process restart.
type Batch struct {
	// ID uniquely identifies the batch generation.
	ID string
	// Repos is the snapshot of the repository manifest scanned by this batch.
	Repos []string

	dir string
}

// NewBatch creates a new batch generation for the given repositories and
// allocates its dedicated temporary directory. The directory is guaranteed to
// be freshly created so that no artifact of a previous generation (such as a
// half-cloned repository) can be reused by this batch.
func NewBatch(repos []string) (*Batch, error) {
	// snapshot the manifest so that the batch is immune to later mutations
	// of the input slice
	manifest := make([]string, len(repos))
	copy(manifest, repos)

	parent := path.Join(utils.TempDirPath(), batchesDirName)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return nil, fmt.Errorf("failed to create batches directory %q: %w", parent, err)
	}

	for i := 0; i < maxBatchDirAllocAttempts; i++ {
		b := &Batch{
			ID:    newBatchID(),
			Repos: manifest,
		}
		b.dir = path.Join(parent, b.ID)

		// os.Mkdir fails if the directory already exists, which guarantees
		// that a batch never reuses the directory of another generation
		if err := os.Mkdir(b.dir, 0o755); err != nil {
			if os.IsExist(err) {
				continue
			}
			return nil, fmt.Errorf("failed to create batch directory %q: %w", b.dir, err)
		}

		return b, nil
	}

	return nil, fmt.Errorf("failed to allocate a unique batch directory after %d attempts", maxBatchDirAllocAttempts)
}

// newBatchID returns a unique identifier for a batch generation, made of a
// timestamp and a random suffix.
func newBatchID() string {
	var randBytes [4]byte
	if _, err := rand.Read(randBytes[:]); err != nil {
		// crypto/rand should never fail; fall back to a timestamp-only ID
		return time.Now().Format("20060102-150405.000000000")
	}
	return fmt.Sprintf("%s-%s", time.Now().Format("20060102-150405"), hex.EncodeToString(randBytes[:]))
}

// Dir returns the root temporary directory of the batch.
func (b *Batch) Dir() string {
	return b.dir
}

// RepoDir returns the clone destination of a repository for this batch. The
// directory lives inside the batch directory so that it can never be confused
// with the clone of the same repository in another batch generation.
func (b *Batch) RepoDir(repository string) string {
	return path.Join(b.dir, repository)
}

// Cleanup removes all the temporary artifacts of the batch.
func (b *Batch) Cleanup() error {
	return os.RemoveAll(b.dir)
}
