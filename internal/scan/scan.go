package scan

import (
	"context"
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"

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

// ReportFormats is the list of report formats selected for a scan. When
// empty, the scan falls back to a single JSON report.
type ReportFormats []ReportFormat

func (f ReportFormats) String() string {
	formats := make([]string, 0, len(f))
	for _, format := range f {
		formats = append(formats, format.String())
	}
	return strings.Join(formats, ",")
}

// ReportFormats must implement cobra pflag.Value interface. It accepts a
// single format or a comma-separated list of formats (e.g. "csv,json") and
// can be repeated. Duplicated formats are only kept once.
func (f *ReportFormats) Set(s string) error {
	for _, v := range strings.Split(s, ",") {
		var format ReportFormat
		if err := format.Set(strings.TrimSpace(v)); err != nil {
			return err
		}
		if !slices.Contains(*f, format) {
			*f = append(*f, format)
		}
	}
	return nil
}

// ReportFormats must implement cobra pflag.Value interface
func (f *ReportFormats) Type() string {
	return "{json,csv}"
}

type ScanArgs struct {
	ScanType      ScanType
	ReportPath    string
	ReportFormats ReportFormats
	// ReportFormat is kept for backward compatibility and is only used when
	// ReportFormats is empty. Prefer ReportFormats.
	ReportFormat           ReportFormat
	FingerprintsIgnorePath string
	BaselinePath           string
	MaxConcurrency         int
	ShowProgress           bool
}

// secretCollector gathers the secrets found by the concurrent repository
// scan tasks into a single set that can be committed to the report files
// once every repository has been scanned.
type secretCollector struct {
	lock    sync.Mutex
	secrets secret.SecretSet
}

func newSecretCollector() *secretCollector {
	return &secretCollector{secrets: secret.NewSet()}
}

func (c *secretCollector) AddAll(s secret.SecretSet) {
	c.lock.Lock()
	defer c.lock.Unlock()
	for _, sec := range s {
		c.secrets.Add(sec)
	}
}

func (c *secretCollector) ToSlice() []*secret.Secret {
	c.lock.Lock()
	defer c.lock.Unlock()
	return c.secrets.ToSlice()
}

func repoScanTask(ctx context.Context, repository string, s scm.Scm, full bool, c *secretCollector) error {
	destination := path.Join(utils.TempDirPath(), repository)

	url := s.GitRepoUrl(repository)

	err := git.Clone(ctx, url, destination, !full, true)
	if err != nil {
		// if remote is empty, scan next repository
		if errors.Is(err, transport.ErrEmptyRemoteRepository) {
			return nil
		}
		return fmt.Errorf("failed to clone repository %q: %w", repository, err)
	}

	thSecrets, err := trufflehog.Scan(ctx, repository, destination, full)
	if err != nil {
		return fmt.Errorf("trufflehog scan failed for repository %q: %w", repository, err)
	}
	glSecrets, err := gitleaks.Scan(ctx, repository, destination, full)
	if err != nil {
		return fmt.Errorf("gitleaks scan failed for repository %q: %w", repository, err)
	}

	secrets := thSecrets.
		Union(glSecrets).
		Diff(GetRepoBaseline(repository)).
		DropFingerprints(GetRepoIgnoredFingerprints(repository))

	c.AddAll(secrets)

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

// reportTargets resolves the output file of each selected report format.
// With a single format, the report path is used as is (or defaults to
// "report.<format>"). With several formats, one file per format is
// generated by deriving the extension of the report path.
func reportTargets(path string, formats ReportFormats) []report.ReportTarget {
	targets := make([]report.ReportTarget, 0, len(formats))
	for _, format := range formats {
		targets = append(targets, report.ReportTarget{
			Path: reportOutputPath(path, format.String(), len(formats) > 1),
			Ext:  format.String(),
		})
	}
	return targets
}

func reportOutputPath(path string, ext string, multi bool) string {
	if path == "" {
		return fmt.Sprintf("%s.%s", report.DefaultReportName, ext)
	}
	if !multi {
		return path
	}
	if e := filepath.Ext(path); e == "."+ReportFormatJSON.String() || e == "."+ReportFormatCSV.String() {
		return strings.TrimSuffix(path, e) + "." + ext
	}
	return path + "." + ext
}

func Scan(ctx context.Context, s scm.Scm, args ScanArgs) error {
	var err error

	log.Info().Msg("scan initiated")

	formats := args.ReportFormats
	if len(formats) == 0 {
		// ReportFormat defaults to JSON, so this also covers an empty ScanArgs
		formats = ReportFormats{args.ReportFormat}
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

	collector := newSecretCollector()

	tasks := make([]*progress.Task, 0, len(repos))
	for _, repo := range repos {
		repo := repo // closure
		tasks = append(tasks, progress.NewTask(func(ctx context.Context) error {
			return repoScanTask(ctx, repo, s, args.ScanType == ScanTypeFull, collector)
		}))
	}

	if args.ShowProgress {
		err = progress.RunTasksWithProgressBar(ctx, "Scanning repositories...", tasks, args.MaxConcurrency)
	} else {
		err = progress.RunTasks(ctx, tasks, args.MaxConcurrency)
	}
	if err != nil {
		return fmt.Errorf("repositories scan failed: %w", err)
	}

	// commit the secrets, all selected reports and the exit status of the
	// scan as a single recoverable transaction: either every report is
	// written or no report is updated at all
	if err := report.WriteReports(collector.ToSlice(), reportTargets(args.ReportPath, formats)...); err != nil {
		return fmt.Errorf("failed to write report: %w", err)
	}

	log.Info().Msg("scan completed")

	return nil
}
