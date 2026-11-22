package scan

import (
	"os"
	"path"
	"testing"
)

func TestStagedReportPath(t *testing.T) {
	test := stagedReportPath("report.json", "20261122-153045-a1b2c3d4")
	want := "report.json.20261122-153045-a1b2c3d4.tmp"

	if test != want {
		t.Fatalf("stagedReportPath() = %q, want %q", test, want)
	}
}

func TestPublishReport(t *testing.T) {
	tmp := t.TempDir()

	staged := path.Join(tmp, "report.json.batch-1.tmp")
	final := path.Join(tmp, "report.json")

	if err := os.WriteFile(staged, []byte("[\n]\n"), 0o644); err != nil {
		t.Fatalf("os.WriteFile() = %v, want nil", err)
	}

	if err := publishReport(staged, final); err != nil {
		t.Fatalf("publishReport() = %v, want nil", err)
	}

	content, err := os.ReadFile(final)
	if err != nil {
		t.Fatalf("os.ReadFile(%q) = _, %v, want _, nil", final, err)
	}
	if string(content) != "[\n]\n" {
		t.Fatalf("published report content = %q, want %q", string(content), "[\n]\n")
	}

	if _, err := os.Stat(staged); !os.IsNotExist(err) {
		t.Fatalf("staged report %q still exists after publish", staged)
	}
}

func TestPublishReportRefusesToOverwrite(t *testing.T) {
	tmp := t.TempDir()

	staged := path.Join(tmp, "report.json.batch-2.tmp")
	final := path.Join(tmp, "report.json")

	if err := os.WriteFile(final, []byte("previous batch"), 0o644); err != nil {
		t.Fatalf("os.WriteFile() = %v, want nil", err)
	}
	if err := os.WriteFile(staged, []byte("current batch"), 0o644); err != nil {
		t.Fatalf("os.WriteFile() = %v, want nil", err)
	}

	if err := publishReport(staged, final); err == nil {
		t.Fatalf("publishReport() = nil, want an error")
	}

	// the report of the previous batch must be left untouched and the staged
	// report must be kept for manual recovery
	content, err := os.ReadFile(final)
	if err != nil {
		t.Fatalf("os.ReadFile(%q) = _, %v, want _, nil", final, err)
	}
	if string(content) != "previous batch" {
		t.Fatalf("final report content = %q, want %q", string(content), "previous batch")
	}
	if _, err := os.Stat(staged); err != nil {
		t.Fatalf("staged report %q should be kept on publish failure: %v", staged, err)
	}
}

func TestPublishReportReplacesEmptyFile(t *testing.T) {
	tmp := t.TempDir()

	staged := path.Join(tmp, "report.csv.batch-3.tmp")
	final := path.Join(tmp, "report.csv")

	// an empty leftover file must not prevent publishing
	if err := os.WriteFile(final, []byte{}, 0o644); err != nil {
		t.Fatalf("os.WriteFile() = %v, want nil", err)
	}
	if err := os.WriteFile(staged, []byte("header\n"), 0o644); err != nil {
		t.Fatalf("os.WriteFile() = %v, want nil", err)
	}

	if err := publishReport(staged, final); err != nil {
		t.Fatalf("publishReport() = %v, want nil", err)
	}

	content, err := os.ReadFile(final)
	if err != nil {
		t.Fatalf("os.ReadFile(%q) = _, %v, want _, nil", final, err)
	}
	if string(content) != "header\n" {
		t.Fatalf("published report content = %q, want %q", string(content), "header\n")
	}
}
