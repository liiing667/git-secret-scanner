package report

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/padok-team/git-secret-scanner/internal/report/secret"
	"github.com/padok-team/git-secret-scanner/internal/utils"
)

const DefaultReportName string = "report"

type ReportWriter interface {
	WriteAll(s []*secret.Secret) error
	Close() error
}

func reportPath(path string, ext string) string {
	if path == "" {
		return fmt.Sprintf("%s.%s", DefaultReportName, ext)
	}
	return path
}

// ResolvePath returns the effective report file path for a user-provided path,
// falling back to the default report file name with the given extension when
// the path is empty.
func ResolvePath(path string, ext string) string {
	return reportPath(path, ext)
}

// NewWriter creates a report writer for the given format ("json" or "csv").
func NewWriter(format string, path string) (ReportWriter, error) {
	switch format {
	case "json":
		writer, err := NewJSONReportWriter(path)
		if err != nil {
			return nil, err
		}
		return writer, nil
	case "csv":
		writer, err := NewCSVReportWriter(path)
		if err != nil {
			return nil, err
		}
		return writer, nil
	default:
		return nil, fmt.Errorf("unsupported report format %q", format)
	}
}

// StagedPath returns the path of a staged report that belongs to the given
// scan generation. It is placed next to the final report so that publishing it
// is an atomic rename on the same filesystem.
func StagedPath(finalPath string, generation string) string {
	dir := filepath.Dir(finalPath)
	base := filepath.Base(finalPath)
	return filepath.Join(dir, fmt.Sprintf(".%s.%s.tmp", base, generation))
}

// Publish atomically replaces the final report with the staged report. An
// existing non-empty report is never overwritten, preserving the historical
// "report already exists" behaviour.
func Publish(stagedPath string, finalPath string) error {
	if utils.FileExistsAndNotEmpty(finalPath) {
		return fmt.Errorf("file %q already exists", finalPath)
	}

	// An empty leftover file can occupy the final path. Remove it so that the
	// rename also works on platforms that do not replace existing files.
	if err := os.Remove(finalPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove empty report file %q: %w", finalPath, err)
	}

	if err := os.Rename(stagedPath, finalPath); err != nil {
		return fmt.Errorf("failed to move staged report %q to %q: %w", stagedPath, finalPath, err)
	}

	return nil
}
