package report

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/padok-team/git-secret-scanner/internal/report/secret"
)

// ReportTarget describes one report file to produce: the final path of the
// report and its format extension ("json" or "csv").
type ReportTarget struct {
	Path string
	Ext  string
}

// stagedReport is a report that has been fully written to a temporary file
// and is waiting to be moved to its final path.
type stagedReport struct {
	tmp       string
	target    string
	backup    string
	committed bool
}

// WriteReports writes the given secrets to one report file per target and
// commits all of them as a single recoverable transaction: every report is
// first fully written to a temporary file in the target directory, previous
// reports are moved aside, and only then is every report atomically moved to
// its final path. If any report cannot be staged or committed, every change
// is rolled back so that consumers keep seeing the previous reports (or no
// report at all) instead of clean-looking partial data or mixed generations,
// and an error is returned.
func WriteReports(s []*secret.Secret, targets ...ReportTarget) error {
	staged := make([]*stagedReport, 0, len(targets))

	// rollback restores the state consumers saw before the transaction:
	// previous reports are moved back in place, newly committed reports are
	// removed and temporary files are cleaned up
	rollback := func() {
		for _, r := range staged {
			if r.backup != "" {
				_ = os.Rename(r.backup, r.target)
			} else if r.committed {
				_ = os.Remove(r.target)
			}
			_ = os.Remove(r.tmp)
		}
	}

	// stage every report to a temporary file: a report that cannot be fully
	// written never reaches its final path
	for _, target := range targets {
		tmp, err := stageReport(target, s)
		if err != nil {
			rollback()
			return err
		}
		staged = append(staged, &stagedReport{tmp: tmp, target: target.Path})
	}

	// move previous reports aside so that they can be restored on failure
	for _, r := range staged {
		if info, err := os.Stat(r.target); err == nil {
			if info.IsDir() {
				rollback()
				return fmt.Errorf("failed to backup previous report %q: is a directory", r.target)
			}
			backup, err := backupPath(r.target)
			if err != nil {
				rollback()
				return err
			}
			if err := os.Rename(r.target, backup); err != nil {
				_ = os.Remove(backup)
				rollback()
				return fmt.Errorf("failed to backup previous report %q: %w", r.target, err)
			}
			r.backup = backup
		} else if !os.IsNotExist(err) {
			rollback()
			return fmt.Errorf("failed to read report %q: %w", r.target, err)
		}
	}

	// commit every staged report to its final path
	for _, r := range staged {
		if err := os.Rename(r.tmp, r.target); err != nil {
			rollback()
			return fmt.Errorf("failed to commit report %q: %w", r.target, err)
		}
		r.committed = true
	}

	// the commit succeeded, previous generations can be dropped
	for _, r := range staged {
		if r.backup != "" {
			_ = os.Remove(r.backup)
		}
	}

	return nil
}

// stageReport fully writes the report of the given target to a temporary
// file in the target directory and returns the temporary file path. The
// temporary file is removed if the report cannot be written completely.
func stageReport(target ReportTarget, s []*secret.Secret) (string, error) {
	dir := filepath.Dir(target.Path)
	base := filepath.Base(target.Path)

	f, err := os.CreateTemp(dir, "."+base+".tmp-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temporary report file for %q: %w", target.Path, err)
	}
	tmp := f.Name()
	_ = f.Close()

	failed := true
	defer func() {
		if failed {
			_ = os.Remove(tmp)
		}
	}()

	var w ReportWriter
	switch target.Ext {
	case "json":
		w, err = NewJSONReportWriter(tmp)
	case "csv":
		w, err = NewCSVReportWriter(tmp)
	default:
		err = fmt.Errorf("unsupported report format %q", target.Ext)
	}
	if err != nil {
		return "", fmt.Errorf("failed to initialize report writer for %q: %w", target.Path, err)
	}

	if err := w.WriteAll(s); err != nil {
		_ = w.Close()
		return "", fmt.Errorf("failed to write report %q: %w", target.Path, err)
	}
	if err := w.Close(); err != nil {
		return "", fmt.Errorf("failed to close report %q: %w", target.Path, err)
	}

	// temporary files are created with 0600 permissions, align with the
	// 0644 permissions reports created with os.Create usually get
	if err := os.Chmod(tmp, 0o644); err != nil {
		return "", fmt.Errorf("failed to set permissions on report %q: %w", target.Path, err)
	}

	// flush the report to stable storage before committing it
	f, err = os.OpenFile(tmp, os.O_WRONLY, 0)
	if err != nil {
		return "", fmt.Errorf("failed to open report %q: %w", target.Path, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return "", fmt.Errorf("failed to sync report %q: %w", target.Path, err)
	}
	_ = f.Close()

	failed = false
	return tmp, nil
}

// backupPath returns a unique path in the same directory as path, suitable
// to hold its previous content while a new report is being committed.
func backupPath(path string) (string, error) {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".bak-*")
	if err != nil {
		return "", fmt.Errorf("failed to create backup file for %q: %w", path, err)
	}
	_ = f.Close()
	return f.Name(), nil
}
