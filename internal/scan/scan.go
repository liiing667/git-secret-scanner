package scan

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/padok-team/git-secret-scanner/internal/progress"
	"github.com/padok-team/git-secret-scanner/internal/report"
	"github.com/padok-team/git-secret-scanner/internal/report/secret"
	"github.com/padok-team/git-secret-scanner/internal/scan/scanners/gitleaks"
	"github.com/padok-team/git-secret-scanner/internal/scan/scanners/trufflehog"
	"github.com/padok-team/git-secret-scanner/internal/scm"
	"github.com/padok-team/git-secret-scanner/internal/scm/git"
	"github.com/padok-team/git-secret-scanner/internal/utils"
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
}

const (
	// maxRepoScanAttempts bounds how many times the scan of a single
	// repository is attempted within the same batch generation before
	// failing the whole batch.
	maxRepoScanAttempts = 3

	// repoScanRetryBackoff is the delay between two scan attempts of a
	// repository.
	repoScanRetryBackoff = time.Second
)

// cloneAndScanRepo clones a repository into destination and scans it for
// secrets. The returned findings are filtered against the baseline and the
// ignored fingerprints of the repository.
func cloneAndScanRepo(ctx context.Context, url string, repository string, destination string, full bool) (secret.SecretSet, error) {
	err := git.Clone(ctx, url, destination, !full, true)
	if err != nil {
		// if remote is empty, scan next repository
		if errors.Is(err, transport.ErrEmptyRemoteRepository) {
			return nil, err
		}
		return nil, fmt.Errorf("failed to clone repository %q: %w", repository, err)
	}

	thSecrets, err := trufflehog.Scan(ctx, repository, destination, full)
	if err != nil {
		return nil, fmt.Errorf("trufflehog scan failed for repository %q: %w", repository, err)
	}
	glSecrets, err := gitleaks.Scan(ctx, repository, destination, full)
	if err != nil {
		return nil, fmt.Errorf("gitleaks scan failed for repository %q: %w", repository, err)
	}

	secrets := thSecrets.
		Union(glSecrets).
		Diff(GetRepoBaseline(repository)).
		DropFingerprints(GetRepoIgnoredFingerprints(repository))

	return secrets, nil
}

func repoScanTask(ctx context.Context, batch *Batch, repository string, s scm.Scm, full bool, w report.ReportWriter) error {
	// the clone directory is scoped to the batch generation so that a clone
	// of the same repository from a previous run is never reused
	destination := batch.RepoDir(repository)

	url := s.GitRepoUrl(repository)

	var secrets secret.SecretSet

	for attempt := 1; ; attempt++ {
		// every attempt starts from a clean slate so that a half-cloned or
		// half-updated directory left behind by a failed attempt is never
		// reused
		if err := os.RemoveAll(destination); err != nil {
			return fmt.Errorf("failed to reset clone directory %q for repository %q: %w", destination, repository, err)
		}

		var err error
		secrets, err = cloneAndScanRepo(ctx, url, repository, destination, full)
		if err == nil {
			break
		}
		if errors.Is(err, transport.ErrEmptyRemoteRepository) {
			// empty repositories have nothing to scan and retrying would
			// not help: skip the repository without failing the batch
			return nil
		}
		if attempt >= maxRepoScanAttempts {
			return err
		}

		log.Warn().
			Err(err).
			Str("repository", repository).
			Int("attempt", attempt).
			Int("max_attempts", maxRepoScanAttempts).
			Msg("repository scan failed, retrying with a clean clone")

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(repoScanRetryBackoff):
		}
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

// stagedReportPath returns the path of the staged report file of a batch
// generation. The staged file sits next to the final report path so that
// publishing the report is an atomic rename on the same filesystem.
func stagedReportPath(finalPath string, batchID string) string {
	return fmt.Sprintf("%s.%s.tmp", finalPath, batchID)
}

// publishReport atomically moves the staged report of a completed batch to
// its final path. It refuses to overwrite a non-empty report so that the
// report of a previous batch is never clobbered; in that case the staged
// report is kept on disk for manual recovery.
func publishReport(stagedPath string, finalPath string) error {
	if utils.FileExistsAndNotEmpty(finalPath) {
		return fmt.Errorf("report file %q already exists, staged report of this batch kept at %q", finalPath, stagedPath)
	}

	// an empty leftover file may occupy the final path; remove it so that
	// the rename also works on platforms that do not replace existing files
	if err := os.Remove(finalPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove empty report file %q: %w", finalPath, err)
	}

	if err := os.Rename(stagedPath, finalPath); err != nil {
		return fmt.Errorf("failed to move staged report %q to %q: %w", stagedPath, finalPath, err)
	}

	return nil
}

func Scan(ctx context.Context, s scm.Scm, args ScanArgs) error {
	var err error

	log.Info().Msg("scan initiated")

	// resolve the final report path and make sure upfront that no report
	// already occupies it, so that a scan is not started when its report
	// could not be published without overwriting a previous batch
	finalReportPath := report.ResolvePath(args.ReportPath, args.ReportFormat.String())
	if utils.FileExistsAndNotEmpty(finalReportPath) {
		return fmt.Errorf("failed to initialize report writer: file %q already exists", finalReportPath)
	}

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

	// bind the repository manifest, the clone directories, the findings and
	// the report of this run to a single batch generation
	batch, err := NewBatch(repos)
	if err != nil {
		return fmt.Errorf("failed to initialize scan batch: %w", err)
	}
	// whatever the outcome of the batch is, its temporary artifacts must not
	// be left behind where a later batch could reuse them
	defer func() {
		if err := batch.Cleanup(); err != nil {
			log.Warn().Err(err).Str("batch", batch.ID).Msg("failed to clean up batch directory")
		}
	}()

	log.Info().
		Str("batch", batch.ID).
		Int("num_repositories", len(batch.Repos)).
		Msg("scan batch initialized")

	// the report is written to a staged file bound to the batch generation
	// and is only published, atomically, once every repository of the batch
	// has been scanned successfully, so that a failed batch never leaves a
	// partial or mixed report behind
	stagedPath := stagedReportPath(finalReportPath, batch.ID)

	var writer report.ReportWriter

	switch args.ReportFormat {
	case ReportFormatJSON:
		writer, err = report.NewJSONReportWriter(stagedPath)
	case ReportFormatCSV:
		writer, err = report.NewCSVReportWriter(stagedPath)
	}

	if err != nil {
		return fmt.Errorf("failed to initialize report writer: %w", err)
	}

	tasks := make([]*progress.Task, 0, len(batch.Repos))
	for _, repo := range batch.Repos {
		repo := repo // closure
		tasks = append(tasks, progress.NewTask(func(ctx context.Context) error {
			return repoScanTask(ctx, batch, repo, s, args.ScanType == ScanTypeFull, writer)
		}))
	}

	if args.ShowProgress {
		err = progress.RunTasksWithProgressBar(ctx, "Scanning repositories...", tasks, args.MaxConcurrency)
	} else {
		err = progress.RunTasks(ctx, tasks, args.MaxConcurrency)
	}
	if err != nil {
		// the batch failed: discard its staged report instead of publishing
		// partial findings mixed with a previous generation
		if cerr := writer.Close(); cerr != nil {
			log.Debug().Err(cerr).Msg("failed to close report writer")
		}
		if rerr := os.Remove(stagedPath); rerr != nil {
			log.Debug().Err(rerr).Str("path", stagedPath).Msg("failed to remove staged report")
		}
		return fmt.Errorf("repositories scan failed: %w", err)
	}

	if err := writer.Close(); err != nil {
		if rerr := os.Remove(stagedPath); rerr != nil {
			log.Debug().Err(rerr).Str("path", stagedPath).Msg("failed to remove staged report")
		}
		return fmt.Errorf("failed to finalize report: %w", err)
	}

	if err := publishReport(stagedPath, finalReportPath); err != nil {
		return fmt.Errorf("failed to publish report: %w", err)
	}

	log.Info().
		Str("batch", batch.ID).
		Str("report", finalReportPath).
		Msg("scan completed")

	return nil
}
