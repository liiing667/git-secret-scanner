package scanners

import (
	"strings"

	"github.com/padok-team/git-secret-scanner/internal/scm/git"
)

const (
	GitleaksIgnoreTag   string = "gitleaks:allow"
	TrufflehogIgnoreTag string = "trufflehog:ignore"
)

func lineIgnoreTag(line string) string {
	switch {
	case strings.Contains(line, GitleaksIgnoreTag):
		return GitleaksIgnoreTag
	case strings.Contains(line, TrufflehogIgnoreTag):
		return TrufflehogIgnoreTag
	default:
		return ""
	}
}

// IgnoredLineSource returns the annotation that ignores the line, or an empty
// string when the line is not ignored. Returning the source lets the scan
// record why a finding was removed without changing the report schema.
func IgnoredLineSource(repo string, hash string, file string, lineNum int) (string, error) {
	diff, err := git.CommitDiff(repo, hash, file)
	if err != nil {
		return "", err
	}

	lines := strings.Split(diff, "\n")

	if lineNum > 0 && lineNum <= len(lines) {
		line := lines[lineNum-1]
		if tag := lineIgnoreTag(line); tag != "" {
			return tag, nil
		}
	}

	return "", nil
}

func IsLineIgnored(repo string, hash string, file string, lineNum int) (bool, error) {
	tag, err := IgnoredLineSource(repo, hash, file, lineNum)
	if err != nil {
		return false, err
	}
	return tag != "", nil
}
