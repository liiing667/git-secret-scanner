package scan

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/padok-team/git-secret-scanner/internal/report/secret"
	"github.com/padok-team/git-secret-scanner/internal/utils"
)

var (
	lastScanGeneration   string
	lastScanGenerationMu sync.RWMutex
)

// ScanGeneration binds a repository manifest, an engine set, the effective
// baseline/ignore snapshots and the staged report to one scan run. Every
// finding produced by the generation carries its identifier, and temporary
// artifacts are isolated in a generation-specific directory so that retries
// and later scans can never observe a half-written previous run.
type ScanGeneration struct {
	ID           string
	Repositories []string
	Engines      EngineSet

	dir      string
	baseline map[string]secret.SecretSet
	ignored  map[string][]string
}

// Generation is an alias for callers that refer to a scan generation directly.
type Generation = ScanGeneration

// RepositoryGeneration scopes one repository inside a scan generation.
type RepositoryGeneration struct {
	Generation *ScanGeneration
	ID         string
	Repository string
	Engines    EngineSet
	Directory  string
}

// NewScanGeneration captures the current repository manifest, engine set and
// baseline/ignore snapshots and allocates a unique temporary directory.
func NewScanGeneration(repositories []string, engines EngineSet) (*ScanGeneration, error) {
	normalized, err := engines.Normalize()
	if err != nil {
		return nil, err
	}

	id := newGenerationID()
	root := utils.TempDirPath()
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, fmt.Errorf("failed to create temporary directory %q: %w", root, err)
	}

	dir, err := os.MkdirTemp(root, "generation-"+id+"-")
	if err != nil {
		return nil, fmt.Errorf("failed to create generation directory: %w", err)
	}

	generation := &ScanGeneration{
		ID:           id,
		Repositories: uniqueRepositories(repositories),
		Engines:      normalized,
		dir:          dir,
		baseline:     snapshotBaseline(),
		ignored:      snapshotIgnoredFingerprints(),
	}

	setLastScanGeneration(id)
	return generation, nil
}

// Directory returns the root directory that contains every repository clone of
// this generation.
func (g *ScanGeneration) Directory() string {
	if g == nil {
		return ""
	}
	return g.dir
}

// Repos returns a copy of the repository manifest bound to the generation.
func (g *ScanGeneration) Repos() []string {
	if g == nil {
		return nil
	}
	return append([]string(nil), g.Repositories...)
}

// RepoDir returns the clone destination of a repository inside the generation.
func (g *ScanGeneration) RepoDir(repository string) string {
	if g == nil {
		return ""
	}
	return g.RepositoryGeneration(repository).Directory
}

// RepositoryGeneration returns the generation-scoped view of a repository.
func (g *ScanGeneration) RepositoryGeneration(repository string) *RepositoryGeneration {
	return &RepositoryGeneration{
		Generation: g,
		ID:         g.ID,
		Repository: repository,
		Engines:    append(EngineSet(nil), g.Engines...),
		Directory:  path.Join(g.dir, safeRepositoryName(repository)),
	}
}

// BaselineFor returns the baseline snapshot captured for the generation.
func (g *ScanGeneration) BaselineFor(repository string) secret.SecretSet {
	if g == nil || g.baseline == nil {
		return secret.NewSet()
	}
	if set, ok := g.baseline[repository]; ok {
		return set.Clone()
	}
	return secret.NewSet()
}

// IgnoredFor returns the ignored-fingerprint snapshot captured for the
// generation.
func (g *ScanGeneration) IgnoredFor(repository string) []string {
	if g == nil {
		return nil
	}
	return append([]string(nil), g.ignored[repository]...)
}

// Cleanup removes all temporary artifacts of the generation.
func (g *ScanGeneration) Cleanup() error {
	if g == nil || g.dir == "" || g.dir == "." || g.dir == "/" {
		return nil
	}
	return os.RemoveAll(g.dir)
}

// Cleanup removes the clone directory of the repository.
func (r *RepositoryGeneration) Cleanup() error {
	if r == nil || r.Directory == "" || r.Directory == "." || r.Directory == "/" {
		return nil
	}
	return os.RemoveAll(r.Directory)
}

// GetLastScanGeneration returns the identifier of the latest scan generation
// started in this process.
func GetLastScanGeneration() string {
	lastScanGenerationMu.RLock()
	defer lastScanGenerationMu.RUnlock()
	return lastScanGeneration
}

func setLastScanGeneration(generation string) {
	lastScanGenerationMu.Lock()
	defer lastScanGenerationMu.Unlock()
	lastScanGeneration = generation
}

func newGenerationID() string {
	var randomBytes [8]byte
	if _, err := rand.Read(randomBytes[:]); err == nil {
		return fmt.Sprintf("%s-%s", time.Now().UTC().Format("20060102T150405.000000000"), hex.EncodeToString(randomBytes[:]))
	}
	return time.Now().UTC().Format("20060102T150405.000000000")
}

func safeRepositoryName(repository string) string {
	sum := sha256.Sum256([]byte(repository))
	name := strings.NewReplacer(
		"/", "_",
		"\\", "_",
		":", "_",
		" ", "_",
	).Replace(repository)
	name = strings.Trim(name, "._-")
	if name == "" {
		name = "repository"
	}
	if len(name) > 80 {
		name = name[:80]
	}
	return fmt.Sprintf("%s-%s", name, hex.EncodeToString(sum[:4]))
}

func uniqueRepositories(repositories []string) []string {
	seen := make(map[string]struct{}, len(repositories))
	unique := make([]string, 0, len(repositories))
	for _, repository := range repositories {
		if repository == "" {
			continue
		}
		if _, ok := seen[repository]; ok {
			continue
		}
		seen[repository] = struct{}{}
		unique = append(unique, repository)
	}
	return unique
}
