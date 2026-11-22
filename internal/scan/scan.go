package scan

import (
	"context"
	"errors"
	"fmt"
	"path"
	"sync"

	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/padok-team/git-secret-scanner/internal/progress"
	"github.com/padok-team/git-secret-scanner/internal/report"
	"github.com/padok-team/git-secret-scanner/internal/report/secret"
	"github.com/padok-team/git-secret-scanner/internal/scan/scanners"
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

type scanScope struct {
	Ignore     IgnoreSnapshot
	Baseline   map[string]secret.SecretSet
	Generation string
}

func (scope scanScope) baselineFor(repository string) secret.SecretSet {
	if set, ok := scope.Baseline[repository]; ok {
		return set
	}
	return secret.NewSet()
}

func captureScanScope() scanScope {
	ignoreSnapshot := CaptureIgnoredFingerprints()
	return scanScope{
		Ignore:     ignoreSnapshot,
		Baseline:   CaptureBaseline(),
		Generation: fmt.Sprintf("ignore:%s;baseline:%s", ignoreSnapshot.Generation, GetBaselineGeneration()),
	}
}

var (
	ignoredEvidenceMu   sync.Mutex
	ignoredEvidence     = make(map[string][]secret.IgnoredFinding)
	lastScanGeneration  = "empty"
)

func resetIgnoredEvidence(generation string) {
	ignoredEvidenceMu.Lock()
	ignoredEvidence = make(map[string][]secret.IgnoredFinding)
	lastScanGeneration = generation
	ignoredEvidenceMu.Unlock()
}

func recordIgnoredEvidence(repository string, findings []secret.IgnoredFinding) {
	if len(findings) == 0 {
		return
	}
	ignoredEvidenceMu.Lock()
	ignoredEvidence[repository] = append(ignoredEvidence[repository], findings...)
	ignoredEvidenceMu.Unlock()
}

// GetIgnoredFindings returns the recovery evidence collected for a repository
// during the latest scan. It exposes the real fingerprint, identity, rule
// source and generation without changing the CSV/JSON report schema.
func GetIgnoredFindings(repository string) []secret.IgnoredFinding {
	ignoredEvidenceMu.Lock()
	defer ignoredEvidenceMu.Unlock()
	return append([]secret.IgnoredFinding(nil), ignoredEvidence[repository]...)
}

// GetAllIgnoredFindings returns the full evidence map for the latest scan.
func GetAllIgnoredFindings() map[string][]secret.IgnoredFinding {
	ignoredEvidenceMu.Lock()
	defer ignoredEvidenceMu.Unlock()

	copied := make(map[string][]secret.IgnoredFinding, len(ignoredEvidence))
	for repository, findings := range ignoredEvidence {
		copied[repository] = append([]secret.IgnoredFinding(nil), findings...)
	}
	return copied
}

func GetLastScanGeneration() string {
	ignoredEvidenceMu.Lock()
	defer ignoredEvidenceMu.Unlock()
	return lastScanGeneration
}

func repoScanTask(ctx context.Context, repository string, s scm.Scm, full bool, w report.ReportWriter) error {
	return repoScanTaskWithScope(ctx, repository, s, full, w, captureScanScope())
}

func filterLineIgnored(repository string, directory string, secrets secret.SecretSet, generation string) (secret.SecretSet, []secret.IgnoredFinding, error) {
	entries := make([]secret.IgnoreEntry, 0)
	for _, s := range secrets {
		tag, err := scanners.IgnoredLineSource(directory, s.Commit, s.Path, s.Line)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to check line ignore for %q: %w", s.Fingerprint, err)
		}
		if tag == "" {
			continue
		}
		entries = append(entries, secret.IgnoreEntry{
			Fingerprint: s.Fingerprint,
			Identity:    s.Identity(),
			Repository:  repository,
			Commit:      s.Commit,
			Path:        s.Path,
			Line:        s.Line,
			Generation:  generation,
			Version:     1,
			Source:      secret.IgnoreSourceLineAnnotation,
			Reason:      tag,
		})
	}

	if len(entries) == 0 {
		return secrets, nil, nil
	}
	remaining, evidence := secrets.DropIgnoreEntries(entries)
	return remaining, evidence, nil
}

func repoScanTaskWithScope(ctx context.Context, repository string, s scm.Scm, full bool, w report.ReportWriter, scope scanScope) error {
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

	secrets := thSecrets.Union(glSecrets)
	evidence := make([]secret.IgnoredFinding, 0)

	// Apply line annotations once more on the merged set. Both scanners and
	// the final consumer therefore reach the same conclusion even when one
	// engine reported a duplicate that the other one had already suppressed.
	secrets, lineEvidence, err := filterLineIgnored(repository, destination, secrets, scope.Generation)
	if err != nil {
		return fmt.Errorf("failed to apply line ignores for repository %q: %w", repository, err)
	}
	evidence = append(evidence, lineEvidence...)

	secrets, baselineEvidence := secrets.DiffWithEvidence(
		scope.baselineFor(repository),
		secret.IgnoreSourceBaseline,
		scope.Generation,
	)
	evidence = append(evidence, baselineEvidence...)

	secrets, fingerprintEvidence := secrets.DropIgnoreEntries(scope.Ignore.Entries[repository])
	evidence = append(evidence, fingerprintEvidence...)

	recordIgnoredEvidence(repository, evidence)
	for _, finding := range evidence {
		log.Info().
			Str("repository", finding.Repository).
			Str("fingerprint", finding.Fingerprint).
			Str("secret_identity", finding.Identity).
			Str("source", string(finding.Source)).
			Str("stage", finding.Stage).
			Str("generation", finding.Generation).
			Str("reason", finding.Reason).
			Msg("finding ignored")
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
	var err error

	log.Info().Msg("scan initiated")

	var writer report.ReportWriter

	switch args.ReportFormat {
	case ReportFormatJSON:
		writer, err = report.NewJSONReportWriter(args.ReportPath)
	case ReportFormatCSV:
		writer, err = report.NewCSVReportWriter(args.ReportPath)
	}

	if err != nil {
		return fmt.Errorf("failed to initialize report writer: %w", err)
	}

	defer writer.Close()

	// A new Scan is a new generation. When an option is absent, clear the
	// previous state so it cannot be reused silently. When a file is given,
	// Load* publishes only after a successful full parse; a malformed reload
	// therefore leaves the previous complete generation intact.
	if args.BaselinePath == "" {
		ResetBaseline()
	}
	if args.FingerprintsIgnorePath == "" {
		ResetIgnoredFingerprints()
	}
	resetIgnoredEvidence("empty")

	if err := LoadBaseline(args.BaselinePath); err != nil {
		return fmt.Errorf("failed to load baseline: %w", err)
	}
	if err := LoadIgnoredFingerprints(args.FingerprintsIgnorePath); err != nil {
		return fmt.Errorf("failed to load ignored fingerprints: %w", err)
	}

	scope := captureScanScope()
	resetIgnoredEvidence(scope.Generation)
	log.Info().
		Str("generation", scope.Generation).
		Int("ignore_version", scope.Ignore.Version).
		Msg("scan generation captured")

	repos, err := s.ListRepos(ctx)
	if err != nil {
		return fmt.Errorf("failed to retrieve repositories list: %w", err)
	}

	tasks := make([]*progress.Task, 0, len(repos))
	for _, repo := range repos {
		repo := repo // closure
		tasks = append(tasks, progress.NewTask(func(ctx context.Context) error {
			return repoScanTaskWithScope(ctx, repo, s, args.ScanType == ScanTypeFull, writer, scope)
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

	log.Info().Msg("scan completed")

	return nil
}
