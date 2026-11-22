package report

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAtomicReportPublishGeneration(t *testing.T) {
	directory := t.TempDir()
	finalPath := filepath.Join(directory, "report.json")
	stagedPath := StagedPath(finalPath, "generation-1")

	if err := os.WriteFile(stagedPath, []byte("staged"), 0o600); err != nil {
		t.Fatalf("WriteFile(staged) error = %v", err)
	}

	if err := Publish(stagedPath, finalPath); err != nil {
		t.Fatalf("Publish() error = %v, want nil", err)
	}

	content, err := os.ReadFile(finalPath)
	if err != nil {
		t.Fatalf("ReadFile(final) error = %v", err)
	}
	if string(content) != "staged" {
		t.Fatalf("final report = %q, want %q", content, "staged")
	}
}

func TestAtomicReportPublishRefusesExistingReport(t *testing.T) {
	directory := t.TempDir()
	finalPath := filepath.Join(directory, "report.json")
	stagedPath := StagedPath(finalPath, "generation-2")

	if err := os.WriteFile(finalPath, []byte("previous"), 0o600); err != nil {
		t.Fatalf("WriteFile(final) error = %v", err)
	}
	if err := os.WriteFile(stagedPath, []byte("staged"), 0o600); err != nil {
		t.Fatalf("WriteFile(staged) error = %v", err)
	}

	if err := Publish(stagedPath, finalPath); err == nil {
		t.Fatalf("Publish() error = nil, want existing report error")
	}

	content, err := os.ReadFile(finalPath)
	if err != nil {
		t.Fatalf("ReadFile(final) error = %v", err)
	}
	if string(content) != "previous" {
		t.Fatalf("final report = %q, want %q", content, "previous")
	}
}
