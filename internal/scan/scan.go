package scan

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/padok-team/git-secret-scanner/internal/progress"
	"github.com/padok-team/git-secret-scanner/internal/report"
	"github.com/padok-team/git-secret-scanner/internal/report/secret"
	"github.com/padok-team/git-secret-scanner/internal/scm"
	"github.com/padok-team/git-secret-scanner/internal/scm/git"
	"github.com/rs/zerolog/log"
)

type ScanType int

const (
	ScanTypeFull ScanType = iota
	ScanTypeFilesOnly
)

func (t ScanType) String() string {
	switch t {
	case ScanTypeFull:
		return "full"
	case ScanTypeFilesOnly:
		return "files-only"
	default:
		// should never be reached
		return ""
	}
}

type ReportFormat int

const (
	ReportFormatJSON ReportFormat = iota
	ReportFormatCSV
)

func (f ReportFormat) String() string {
	switch f {
	case ReportFormatJSON:
		return "json"
	case ReportFormatCSV:
		return "csv"
	default:
		// should never be reached
		return ""
	}
}

// ReportFormat must implement cobra pflag.Value interface
func (f *ReportFormat) Set(s string) error {
	switch s {
	case ReportFormatJSON.String():
		*f = ReportFormatJSON
		return nil
	case ReportFormatCSV.String():
		*f = ReportFormatCSV
		return nil
	default:
		return fmt.Errorf(
			"format must be one of \"%s\" or \"%s\"",
			ReportFormatJSON.String(),
			ReportFormatCSV.String(),
		)
	}
}

// ReportFormat must implement cobra pflag.Value interface
func (v *ReportFormat) Type() string {
	return "{json,csv}"
}

type ScanArgs struct {
	ScanType               ScanType
	ReportPath             string
	ReportFormat           ReportFormat
	FingerprintsIgnorePath string
	BaselinePath           string
	MaxConcurrency         int
	ShowProgress           bool
	// Engines selects the scanners to run. An empty set means all engines.
	Engines EngineSet
	// Scanners is kept as a compatibility alias for callers that already use
	// the report scanner enum. It is only considered when Engines is empty.
	Scanners secret.SecretScanners
}

func (args ScanArgs) resolvedEngines() (EngineSet, error) {
	return ResolveEngines(args.Engines, args.Scanners)
}

// ResolveEngines resolves the engine selection, keeping the zero value
// compatible with the historical behaviour of running both engines.
func ResolveEngines(engines EngineSet, scanners secret.SecretScanners) (EngineSet, error) {
	if len(engines) > 0 {
		return engines.Normalize()
	}

	switch scanners {
	case secret.SecretScannersAll:
		return AllEngines(), nil
	case secret.SecretScannersGitleaks:
		return EngineSet{EngineGitleaks}, nil
	case secret.SecretScannersTrufflehog:
		return EngineSet{EngineTrufflehog}, nil
	default:
		return nil, fmt.Errorf("unknown scanners value %d", scanners)
	}
}

func repoScanTask(ctx context.Context, repository string, s scm.Scm, full bool, w report.ReportWriter) error {
	generation, err := NewScanGeneration([]string{repository}, nil)
	if err != nil {
		return fmt.Errorf("failed to initialize scan generation: %w", err)
	}
	defer generation.Cleanup() //nolint:errcheck

	return repoScanTaskWithGeneration(ctx, generation, repository, s, full, w)
}

func repoScanTaskWithGeneration(
	ctx context.Context,
	generation *ScanGeneration,
	repository string,
	s scm.Scm,
	full bool,
	w report.ReportWriter,
) error {
	repoGeneration := generation.RepositoryGeneration(repository)
	defer repoGeneration.Cleanup() //nolint:errcheck

	err := git.Clone(ctx, s.GitRepoUrl(repository), repoGeneration.Directory, !full, true)
	if err != nil {
		// if remote is empty, scan next repository
		if errors.Is(err, transport.ErrEmptyRemoteRepository) {
			return nil
		}
		return fmt.Errorf("failed to clone repository %q: %w", repository, err)
	}

	repositoryScanner := NewRepositoryScanner(repository, repoGeneration.Directory, repoGeneration.Engines)
	repositoryScanner.Generation = repoGeneration.ID
	repositoryScanner.Filter = func(found secret.SecretSet) secret.SecretSet {
		// Apply fingerprint rules before identity deduplication. Otherwise an
		// ignored representative line could hide a non-ignored duplicate.
		found = found.Diff(generation.BaselineFor(repository))
		found = found.DropFingerprints(generation.IgnoredFor(repository))
		return found
	}

	secrets, err := repositoryScanner.Scan(ctx, full)
	if err != nil {
		return err
	}

	if err := w.WriteAll(secrets.ToSlice()); err != nil {
		return fmt.Errorf("failed to add secrets in report for repository %q: %w", repository, err)
	}

	if secrets.Length() > 0 {
		log.Warn().
			Int("num", secrets.Length()).
			Str("repository", repository).
			Msgf("scanned %s, got findings", repository)
	} else {
		log.Debug().
			Str("repository", repository).
			Msgf("scanned %s", repository)
	}

	return nil
}

func Scan(ctx context.Context, s scm.Scm, args ScanArgs) error {
	log.Info().Msg("scan initiated")

	engines, err := args.resolvedEngines()
	if err != nil {
		return fmt.Errorf("invalid scanner selection: %w", err)
	}

	reportFormat := args.ReportFormat.String()
	if reportFormat == "" {
		return errors.New("failed to initialize report writer: unsupported report format")
	}

	finalReportPath := report.ResolvePath(args.ReportPath, reportFormat)
	if info, statErr := os.Stat(finalReportPath); statErr == nil {
		switch {
		case info.IsDir():
			return fmt.Errorf("failed to initialize report writer: file %q is a directory", finalReportPath)
		case info.Size() > 0:
			return fmt.Errorf("failed to initialize report writer: file %q already exists", finalReportPath)
		default:
			if err := os.Remove(finalReportPath); err != nil {
				return fmt.Errorf("failed to initialize report writer: failed to remove empty report file %q: %w", finalReportPath, err)
			}
		}
	} else if !os.IsNotExist(statErr) {
		return fmt.Errorf("failed to initialize report writer: failed to inspect report file %q: %w", finalReportPath, statErr)
	}

	// A scan always starts from a clean baseline/ignore state. A missing
	// option must not silently reuse the state of a previous scan.
	ResetBaseline()
	ResetIgnoredFingerprints()

	if err := LoadBaseline(args.BaselinePath); err != nil {
		return fmt.Errorf("failed to load baseline: %w", err)
	}
	if err := LoadIgnoredFingerprints(args.FingerprintsIgnorePath); err != nil {
		return fmt.Errorf("failed to load ignored fingerprints: %w", err)
	}

	repos, err := s.ListRepos(ctx)
	if err != nil {
		return fmt.Errorf("failed to retrieve repositories list: %w", err)
	}

	generation, err := NewScanGeneration(repos, engines)
	if err != nil {
		return fmt.Errorf("failed to initialize scan generation: %w", err)
	}
	defer generation.Cleanup() //nolint:errcheck

	stagedReportPath := report.StagedPath(finalReportPath, generation.ID)
	writer, err := report.NewWriter(reportFormat, stagedReportPath)
	if err != nil {
		return fmt.Errorf("failed to initialize report writer: %w", err)
	}

	closeAndDiscard := func() {
		if err := writer.Close(); err != nil {
			log.Debug().Err(err).Msg("failed to close staged report writer")
		}
		if err := os.Remove(stagedReportPath); err != nil && !os.IsNotExist(err) {
			log.Debug().Err(err).Str("path", stagedReportPath).Msg("failed to remove staged report")
		}
	}

	maxConcurrency := args.MaxConcurrency
	if maxConcurrency <= 0 {
		maxConcurrency = 1
	}

	tasks := make([]*progress.Task, 0, len(generation.Repositories))
	for _, repo := range generation.Repositories {
		repo := repo // closure
		tasks = append(tasks, progress.NewTask(func(ctx context.Context) error {
			return repoScanTaskWithGeneration(ctx, generation, repo, s, args.ScanType == ScanTypeFull, writer)
		}))
	}

	if args.ShowProgress {
		err = progress.RunTasksWithProgressBar(ctx, "Scanning repositories...", tasks, maxConcurrency)
	} else {
		err = progress.RunTasks(ctx, tasks, maxConcurrency)
	}
	if err != nil {
		// The generation is incomplete: never publish a partial or mixed
		// report. An existing report is left untouched.
		closeAndDiscard()
		return fmt.Errorf("repositories scan failed: %w", err)
	}

	if err := writer.Close(); err != nil {
		_ = os.Remove(stagedReportPath)
		return fmt.Errorf("failed to finalize report: %w", err)
	}

	if err := report.Publish(stagedReportPath, finalReportPath); err != nil {
		_ = os.Remove(stagedReportPath)
		return fmt.Errorf("failed to publish report: %w", err)
	}

	log.Info().
		Str("generation", generation.ID).
		Str("engines", generation.Engines.String()).
		Str("report", finalReportPath).
		Msg("scan completed")

	return nil
}
