package report

import (
	"fmt"

	"github.com/padok-team/git-secret-scanner/internal/report/secret"
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

// ResolvePath returns the effective report file path for a user-provided
// path, falling back to the default report file name with the given
// extension when the path is empty.
func ResolvePath(path string, ext string) string {
	return reportPath(path, ext)
}
