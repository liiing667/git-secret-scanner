package scan

import (
	"fmt"
	"sync"

	"github.com/padok-team/git-secret-scanner/internal/report"
	"github.com/padok-team/git-secret-scanner/internal/report/secret"
	"github.com/rs/zerolog/log"
)

var (
	baseline   map[string]secret.SecretSet
	baselineMu sync.RWMutex
)

func SetBaseline(b map[string]secret.SecretSet) {
	baselineMu.Lock()
	defer baselineMu.Unlock()
	baseline = b
}

func GetRepoBaseline(repository string) secret.SecretSet {
	baselineMu.RLock()
	defer baselineMu.RUnlock()

	if set, ok := baseline[repository]; ok {
		return set.Clone()
	}
	return nil
}

func ResetBaseline() {
	baselineMu.Lock()
	defer baselineMu.Unlock()
	baseline = nil
}

func snapshotBaseline() map[string]secret.SecretSet {
	baselineMu.RLock()
	defer baselineMu.RUnlock()

	snapshot := make(map[string]secret.SecretSet, len(baseline))
	for repository, set := range baseline {
		snapshot[repository] = set.Clone()
	}
	return snapshot
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

		log.Debug().
			Int("num", num).
			Msg("baseline loaded")
	}
	return nil
}
