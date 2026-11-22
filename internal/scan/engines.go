package scan

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/padok-team/git-secret-scanner/internal/report/secret"
	"github.com/padok-team/git-secret-scanner/internal/scan/scanners/gitleaks"
	"github.com/padok-team/git-secret-scanner/internal/scan/scanners/trufflehog"
	"github.com/rs/zerolog/log"
)

const (
	defaultMaxEngineScanAttempts = 3
	defaultEngineRetryBackoff    = 50 * time.Millisecond
	maxEngineRetryBackoff        = time.Second
)

// Engine identifies a secret detection engine.
type Engine string

const (
	EngineAll        Engine = "all"
	EngineGitleaks   Engine = "gitleaks"
	EngineTrufflehog Engine = "trufflehog"
)

// Scanner returns the report scanner identity of the engine.
func (engine Engine) Scanner() secret.SecretScanners {
	switch Engine(strings.ToLower(string(engine))) {
	case EngineGitleaks:
		return secret.SecretScannersGitleaks
	case EngineTrufflehog:
		return secret.SecretScannersTrufflehog
	default:
		return secret.SecretScannersAll
	}
}

// EngineSet is the set of engines that participated in one scan generation.
// An empty set is normalized to all supported engines.
type EngineSet []Engine

// AllEngines returns the complete supported engine set.
func AllEngines() EngineSet {
	return EngineSet{EngineGitleaks, EngineTrufflehog}
}

// Normalize validates the engine set, removes duplicates and returns a
// deterministic canonical order. An empty set means all engines.
func (set EngineSet) Normalize() (EngineSet, error) {
	if len(set) == 0 {
		return AllEngines(), nil
	}

	hasGitleaks := false
	hasTrufflehog := false
	for _, engine := range set {
		switch Engine(strings.ToLower(string(engine))) {
		case EngineGitleaks:
			hasGitleaks = true
		case EngineTrufflehog:
			hasTrufflehog = true
		case EngineAll:
			hasGitleaks = true
			hasTrufflehog = true
		default:
			return nil, fmt.Errorf(
				"unknown engine %q, must be one of %q, %q or %q",
				engine,
				"all",
				EngineGitleaks,
				EngineTrufflehog,
			)
		}
	}

	normalized := make(EngineSet, 0, 2)
	if hasGitleaks {
		normalized = append(normalized, EngineGitleaks)
	}
	if hasTrufflehog {
		normalized = append(normalized, EngineTrufflehog)
	}
	return normalized, nil
}

// Set implements the pflag.Value interface.
func (set *EngineSet) Set(value string) error {
	fields := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n'
	})

	engines := make(EngineSet, 0, len(fields))
	for _, field := range fields {
		engines = append(engines, Engine(strings.ToLower(field)))
	}

	normalized, err := engines.Normalize()
	if err != nil {
		return err
	}
	*set = normalized
	return nil
}

// Type implements the pflag.Value interface.
func (set *EngineSet) Type() string {
	return "{all,gitleaks,trufflehog}"
}

func (set EngineSet) String() string {
	hasGitleaks := set.Contains(EngineGitleaks)
	hasTrufflehog := set.Contains(EngineTrufflehog)

	switch {
	case hasGitleaks && hasTrufflehog:
		return "all"
	case hasGitleaks:
		return string(EngineGitleaks)
	case hasTrufflehog:
		return string(EngineTrufflehog)
	default:
		return "all"
	}
}

// Contains reports whether the engine is part of the set.
func (set EngineSet) Contains(engine Engine) bool {
	engine = Engine(strings.ToLower(string(engine)))
	if engine == EngineAll {
		return set.Contains(EngineGitleaks) && set.Contains(EngineTrufflehog)
	}
	for _, candidate := range set {
		candidate = Engine(strings.ToLower(string(candidate)))
		if candidate == EngineAll {
			if engine == EngineGitleaks || engine == EngineTrufflehog {
				return true
			}
			continue
		}
		if candidate == engine {
			return true
		}
	}
	return false
}

// Scanners maps an engine set to the report scanner field.
func (set EngineSet) Scanners() secret.SecretScanners {
	hasGitleaks := set.Contains(EngineGitleaks)
	hasTrufflehog := set.Contains(EngineTrufflehog)

	switch {
	case hasGitleaks && hasTrufflehog:
		return secret.SecretScannersAll
	case hasGitleaks:
		return secret.SecretScannersGitleaks
	case hasTrufflehog:
		return secret.SecretScannersTrufflehog
	default:
		return secret.SecretScannersAll
	}
}

// EngineScanFunc scans one repository with one engine.
type EngineScanFunc func(ctx context.Context, repository string, directory string, full bool) (secret.SecretSet, error)

// RepositoryScanner runs a set of engines concurrently against one immutable
// repository snapshot. Engine retries are isolated to the failing engine and
// only a complete, successful engine set is returned.
type RepositoryScanner struct {
	Repository   string
	Directory    string
	Engines      EngineSet
	Generation   string
	MaxAttempts  int
	RetryBackoff time.Duration

	// Scans overrides the default engine implementations. It is useful for
	// tests and for embedding the scanner in another orchestrator.
	Scans map[Engine]EngineScanFunc

	// Filter is applied to the complete engine result before duplicate
	// identities are collapsed. It lets the caller apply fingerprint-based
	// baseline and ignore rules without losing non-ignored duplicate lines.
	Filter func(secret.SecretSet) secret.SecretSet
}

// NewRepositoryScanner creates a scanner for one repository snapshot. When no
// engine set is supplied, both default engines are used.
func NewRepositoryScanner(repository string, directory string, engines ...EngineSet) *RepositoryScanner {
	var engineSet EngineSet
	if len(engines) > 0 {
		engineSet = engines[0]
	}

	return &RepositoryScanner{
		Repository: repository,
		Directory:  directory,
		Engines:    engineSet,
	}
}

type engineOutcome struct {
	engine   Engine
	secrets  secret.SecretSet
	attempts int
	err      error
}

// Scan runs every selected engine concurrently. If an engine fails, it is
// retried with a clean result slot. The findings of a failed attempt are never
// merged: the returned set is either the complete result of every engine or an
// error.
func (s *RepositoryScanner) Scan(ctx context.Context, full bool) (secret.SecretSet, error) {
	engines := s.Engines
	if engines == nil && len(s.Scans) > 0 {
		// A caller-provided scan map is also an implicit engine selection.
		for engine := range s.Scans {
			engines = append(engines, engine)
		}
	}

	engines, err := engines.Normalize()
	if err != nil {
		return nil, err
	}

	scans := s.engineScans()
	for _, engine := range engines {
		if scans[engine] == nil {
			return nil, fmt.Errorf("no scanner configured for engine %q", engine)
		}
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	outcomes := make(chan engineOutcome, len(engines))
	var workers sync.WaitGroup

	for _, engine := range engines {
		engine := engine
		scan := scans[engine]

		workers.Add(1)
		go func() {
			defer workers.Done()

			findings, attempts, err := s.scanEngineWithRetry(ctx, engine, scan, full)
			if err != nil {
				// Stop the other engines as soon as the generation is known
				// to be incomplete.
				cancel()
			}
			outcomes <- engineOutcome{
				engine:   engine,
				secrets:  findings,
				attempts: attempts,
				err:      err,
			}
		}()
	}

	workers.Wait()
	close(outcomes)

	byEngine := make(map[Engine]engineOutcome, len(engines))
	for outcome := range outcomes {
		byEngine[outcome.engine] = outcome
	}

	failures := make([]engineOutcome, 0, len(engines))
	results := make(map[Engine]secret.SecretSet, len(engines))
	for _, engine := range engines {
		outcome, ok := byEngine[engine]
		if !ok {
			failures = append(failures, engineOutcome{
				engine: engine,
				err:    errors.New("no result"),
			})
			continue
		}
		if outcome.err != nil {
			log.Warn().
				Err(outcome.err).
				Str("repository", s.Repository).
				Str("engine", string(engine)).
				Int("attempts", outcome.attempts).
				Msg("engine scan failed for generation")
			failures = append(failures, outcome)
			continue
		}
		if outcome.secrets == nil {
			outcome.secrets = secret.NewSet()
		}
		// Bind every finding to the engine that actually produced it. A
		// failed or retried engine can therefore never leak a stale scanner
		// identity into the final report.
		for _, finding := range outcome.secrets {
			finding.Scanners = engine.Scanner()
		}
		results[engine] = outcome.secrets
	}

	if len(failures) > 0 {
		// A failure cancels the sibling engines. Do not drown the genuine
		// failure in the context cancellation it caused.
		selected := make([]error, 0, len(failures))
		for _, failure := range failures {
			if errors.Is(failure.err, context.Canceled) || errors.Is(failure.err, context.DeadlineExceeded) {
				continue
			}
			selected = append(selected, fmt.Errorf("%s scan failed for repository %q: %w", failure.engine, s.Repository, failure.err))
		}
		if len(selected) == 0 {
			for _, failure := range failures {
				selected = append(selected, fmt.Errorf("%s scan failed for repository %q: %w", failure.engine, s.Repository, failure.err))
			}
		}
		return nil, errors.Join(selected...)
	}

	// Keep the historical merge order (trufflehog first, then gitleaks) so
	// that SecretKind and validity choices remain stable.
	merged := secret.NewSet()
	for _, engine := range []Engine{EngineTrufflehog, EngineGitleaks} {
		if !engines.Contains(engine) {
			continue
		}
		merged = merged.Union(results[engine])
	}

	if s.Generation != "" {
		for _, finding := range merged {
			// Always rebind to the current generation. A retried or reused
			// engine result must never leak an older scan's identity.
			finding.Generation = s.Generation
		}
	}

	if s.Filter != nil {
		merged = s.Filter(merged)
	}

	if len(engines) > 1 {
		// Cross-engine duplicate hits can be reported at slightly different
		// lines. Only collapse value identities when more than one engine took
		// part; a single-engine scan keeps its historical per-line findings.
		merged = merged.DedupeIdentities()
	}

	return merged, nil
}

func (s *RepositoryScanner) engineScans() map[Engine]EngineScanFunc {
	scans := defaultEngineScans()
	for engine, scan := range s.Scans {
		if scan == nil {
			continue
		}

		normalized, err := EngineSet{engine}.Normalize()
		if err != nil {
			continue
		}
		if Engine(strings.ToLower(string(engine))) == EngineAll {
			scans[EngineGitleaks] = scan
			scans[EngineTrufflehog] = scan
			continue
		}
		if len(normalized) == 1 {
			scans[normalized[0]] = scan
		}
	}
	return scans
}

func defaultEngineScans() map[Engine]EngineScanFunc {
	return map[Engine]EngineScanFunc{
		EngineGitleaks: func(ctx context.Context, repository string, directory string, full bool) (secret.SecretSet, error) {
			// Remove a report left behind by an interrupted attempt before
			// starting the next one.
			_ = os.Remove(path.Join(directory, "gitleaks.json"))
			return gitleaks.Scan(ctx, repository, directory, full)
		},
		EngineTrufflehog: func(ctx context.Context, repository string, directory string, full bool) (secret.SecretSet, error) {
			return trufflehog.Scan(ctx, repository, directory, full)
		},
	}
}

func (s *RepositoryScanner) scanEngineWithRetry(ctx context.Context, engine Engine, scan EngineScanFunc, full bool) (secret.SecretSet, int, error) {
	attempts := s.MaxAttempts
	if attempts <= 0 {
		attempts = defaultMaxEngineScanAttempts
	}

	backoff := s.RetryBackoff
	if backoff <= 0 {
		backoff = defaultEngineRetryBackoff
	}

	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, attempt, err
		}

		findings, err := scan(ctx, s.Repository, s.Directory, full)
		if err == nil {
			if findings == nil {
				findings = secret.NewSet()
			}
			return findings, attempt, nil
		}
		lastErr = err

		if attempt >= attempts || ctx.Err() != nil {
			break
		}

		log.Warn().
			Err(err).
			Str("repository", s.Repository).
			Str("engine", string(engine)).
			Int("attempt", attempt).
			Int("max_attempts", attempts).
			Msg("engine scan failed, retrying")

		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, attempt, ctx.Err()
		case <-timer.C:
		}

		if backoff < maxEngineRetryBackoff {
			backoff *= 2
			if backoff > maxEngineRetryBackoff {
				backoff = maxEngineRetryBackoff
			}
		}
	}

	return nil, attempts, lastErr
}
