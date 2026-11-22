package scan

import (
	"crypto/sha256"
	"fmt"
	"os"
	"sync"

	"github.com/padok-team/git-secret-scanner/internal/report"
	"github.com/padok-team/git-secret-scanner/internal/report/secret"
	"github.com/rs/zerolog/log"
)

var (
	baselineMu         sync.RWMutex
	baseline           map[string]secret.SecretSet
	baselineGeneration = "empty"
)

func SetBaseline(b map[string]secret.SecretSet) {
	baselineMu.Lock()
	baseline = b
	baselineMu.Unlock()
	rebindLoadedIgnoreEntriesToBaseline()
}

// ResetBaseline clears the loaded baseline before a new scan generation.
func ResetBaseline() {
	baselineMu.Lock()
	baseline = nil
	baselineGeneration = "empty"
	baselineMu.Unlock()
}

func GetRepoBaseline(repository string) secret.SecretSet {
	baselineMu.RLock()
	defer baselineMu.RUnlock()
	return baseline[repository]
}

// CaptureBaseline returns a snapshot of the complete baseline. The inner sets
// are cloned so a concurrent reload cannot change the current scan's view.
func CaptureBaseline() map[string]secret.SecretSet {
	baselineMu.RLock()
	defer baselineMu.RUnlock()

	snapshot := make(map[string]secret.SecretSet, len(baseline))
	for repository, set := range baseline {
		snapshot[repository] = set.Clone()
	}
	return snapshot
}

func GetBaselineGeneration() string {
	baselineMu.RLock()
	defer baselineMu.RUnlock()
	return baselineGeneration
}

func LoadBaseline(path string) error {
	if path != "" {
		r, err := report.ReadJSONReport(path)
		if err != nil {
			// if we got an error, try to read the baseline as CSV instead
			r, err = report.ReadCSVReport(path)
			if err != nil {
				return fmt.Errorf("failed to parse file %s", path)
			}
		}

		b := make(map[string]secret.SecretSet)
		num := 0

		for _, s := range r {
			_, ok := b[s.Repository]
			if !ok {
				b[s.Repository] = secret.NewSet()
			}
			b[s.Repository].Add(s)
			num += 1
		}

		SetBaseline(b)
		baselineMu.Lock()
		baselineGeneration = baselineDigest(path)
		baselineMu.Unlock()
		rebindLoadedIgnoreEntriesToBaseline()

		log.Debug().
			Int("num", num).
			Msg("baseline loaded")
	}
	return nil
}

func baselineDigest(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return "unreadable"
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("sha256:%x", sum)
}
