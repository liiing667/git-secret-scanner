package scan

import (
	"bufio"
	"errors"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
)

var (
	ignoredFingerprints   map[string][]string
	ignoredFingerprintsMu sync.RWMutex
)

func SetIgnoredFingerprints(fps map[string][]string) {
	ignoredFingerprintsMu.Lock()
	defer ignoredFingerprintsMu.Unlock()
	ignoredFingerprints = fps
}

func GetRepoIgnoredFingerprints(repository string) []string {
	ignoredFingerprintsMu.RLock()
	defer ignoredFingerprintsMu.RUnlock()

	fps, ok := ignoredFingerprints[repository]
	if !ok {
		return make([]string, 0)
	}
	return append([]string(nil), fps...)
}

func ResetIgnoredFingerprints() {
	ignoredFingerprintsMu.Lock()
	defer ignoredFingerprintsMu.Unlock()
	ignoredFingerprints = nil
}

func snapshotIgnoredFingerprints() map[string][]string {
	ignoredFingerprintsMu.RLock()
	defer ignoredFingerprintsMu.RUnlock()

	snapshot := make(map[string][]string, len(ignoredFingerprints))
	for repository, fps := range ignoredFingerprints {
		snapshot[repository] = append([]string(nil), fps...)
	}
	return snapshot
}

func LoadIgnoredFingerprints(path string) error {
	if path != "" {
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()

		r, err := regexp.Compile(`^(.+:){3}[0-9]+$`)
		if err != nil {
			return err
		}

		fps := make(map[string][]string, 0)
		num := 0

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			t := scanner.Text()
			if !r.MatchString(t) {
				return errors.New("wrongly formatted fingerprint in file")
			}
			repository := strings.SplitN(t, ":", 4)[0]
			_, ok := fps[repository]
			if !ok {
				fps[repository] = make([]string, 0)
			}
			fps[repository] = append(fps[repository], t)
			num += 1
		}

		if err := scanner.Err(); err != nil {
			return err
		}

		SetIgnoredFingerprints(fps)

		log.Debug().
			Int("num", num).
			Msg("ignored fingerprints loaded")
	}

	return nil
}
