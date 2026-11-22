package report

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/padok-team/git-secret-scanner/internal/report/secret"
)

func TestWriteReportsCSV(t *testing.T) {
	target := filepath.Join(t.TempDir(), "report.csv")

	secrets := []*secret.Secret{&test1, &test2}

	if err := WriteReports(secrets, ReportTarget{Path: target, Ext: "csv"}); err != nil {
		t.Fatalf(`WriteReports({test1, test2}, csv) = %v, want nil`, err)
	}

	got, err := ReadCSVReport(target)
	if err != nil {
		t.Fatalf(`ReadCSVReport(%q) = _, %v, want _, nil`, target, err)
	}

	if !reflect.DeepEqual(got, secrets) {
		t.Fatalf(`ReadCSVReport(%q) = %v, want %v`, target, got, secrets)
	}
}

func TestWriteReportsJSON(t *testing.T) {
	target := filepath.Join(t.TempDir(), "report.json")

	secrets := []*secret.Secret{&test1, &test2}

	if err := WriteReports(secrets, ReportTarget{Path: target, Ext: "json"}); err != nil {
		t.Fatalf(`WriteReports({test1, test2}, json) = %v, want nil`, err)
	}

	got, err := ReadJSONReport(target)
	if err != nil {
		t.Fatalf(`ReadJSONReport(%q) = _, %v, want _, nil`, target, err)
	}

	if !reflect.DeepEqual(got, secrets) {
		t.Fatalf(`ReadJSONReport(%q) = %v, want %v`, target, got, secrets)
	}
}

func TestWriteReportsMultipleFormats(t *testing.T) {
	dir := t.TempDir()
	csvTarget := filepath.Join(dir, "report.csv")
	jsonTarget := filepath.Join(dir, "report.json")

	secrets := []*secret.Secret{&test1, &test2}

	err := WriteReports(
		secrets,
		ReportTarget{Path: csvTarget, Ext: "csv"},
		ReportTarget{Path: jsonTarget, Ext: "json"},
	)
	if err != nil {
		t.Fatalf(`WriteReports({test1, test2}, csv, json) = %v, want nil`, err)
	}

	gotCSV, err := ReadCSVReport(csvTarget)
	if err != nil {
		t.Fatalf(`ReadCSVReport(%q) = _, %v, want _, nil`, csvTarget, err)
	}
	if !reflect.DeepEqual(gotCSV, secrets) {
		t.Fatalf(`ReadCSVReport(%q) = %v, want %v`, csvTarget, gotCSV, secrets)
	}

	gotJSON, err := ReadJSONReport(jsonTarget)
	if err != nil {
		t.Fatalf(`ReadJSONReport(%q) = _, %v, want _, nil`, jsonTarget, err)
	}
	if !reflect.DeepEqual(gotJSON, secrets) {
		t.Fatalf(`ReadJSONReport(%q) = %v, want %v`, jsonTarget, gotJSON, secrets)
	}
}

func TestWriteReportsEmpty(t *testing.T) {
	dir := t.TempDir()
	csvTarget := filepath.Join(dir, "report.csv")
	jsonTarget := filepath.Join(dir, "report.json")

	err := WriteReports(
		[]*secret.Secret{},
		ReportTarget{Path: csvTarget, Ext: "csv"},
		ReportTarget{Path: jsonTarget, Ext: "json"},
	)
	if err != nil {
		t.Fatalf(`WriteReports({}, csv, json) = %v, want nil`, err)
	}

	for _, target := range []string{csvTarget, jsonTarget} {
		info, err := os.Stat(target)
		if err != nil {
			t.Fatalf(`os.Stat(%q) = _, %v, want _, nil`, target, err)
		}
		if info.Size() != 0 {
			t.Fatalf(`report %q size = %d, want 0`, target, info.Size())
		}
	}
}

func TestWriteReportsReplacesExistingReport(t *testing.T) {
	target := filepath.Join(t.TempDir(), "report.json")

	if err := WriteReports([]*secret.Secret{&test1}, ReportTarget{Path: target, Ext: "json"}); err != nil {
		t.Fatalf(`WriteReports({test1}, json) = %v, want nil`, err)
	}

	// committing a new generation of the report atomically replaces the
	// previous one
	if err := WriteReports([]*secret.Secret{&test2}, ReportTarget{Path: target, Ext: "json"}); err != nil {
		t.Fatalf(`WriteReports({test2}, json) = %v, want nil`, err)
	}

	got, err := ReadJSONReport(target)
	if err != nil {
		t.Fatalf(`ReadJSONReport(%q) = _, %v, want _, nil`, target, err)
	}

	want := []*secret.Secret{&test2}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf(`ReadJSONReport(%q) = %v, want %v`, target, got, want)
	}
}

func TestWriteReportsFailureLeavesNoReport(t *testing.T) {
	dir := t.TempDir()
	csvTarget := filepath.Join(dir, "report.csv")
	// the directory of this target does not exist, staging it must fail
	jsonTarget := filepath.Join(dir, "missing", "report.json")

	secrets := []*secret.Secret{&test1, &test2}

	err := WriteReports(
		secrets,
		ReportTarget{Path: csvTarget, Ext: "csv"},
		ReportTarget{Path: jsonTarget, Ext: "json"},
	)
	if err == nil {
		t.Fatal(`WriteReports({test1, test2}, csv, json) = nil, want error`)
	}

	// consumers must not see a clean-looking csv report: the commit is
	// rolled back and no report is created at all
	if _, err := os.Stat(csvTarget); !os.IsNotExist(err) {
		t.Fatalf(`os.Stat(%q) = _, %v, want _, not-exist error`, csvTarget, err)
	}

	// no temporary or backup file may be left behind
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf(`os.ReadDir(%q) = _, %v, want _, nil`, dir, err)
	}
	if len(entries) != 0 {
		t.Fatalf(`directory %q contains %d entries, want 0`, dir, len(entries))
	}
}

func TestWriteReportsFailurePreservesPreviousReports(t *testing.T) {
	dir := t.TempDir()
	csvTarget := filepath.Join(dir, "report.csv")
	jsonTarget := filepath.Join(dir, "missing", "report.json")

	// commit a first generation of the csv report
	if err := WriteReports([]*secret.Secret{&test1}, ReportTarget{Path: csvTarget, Ext: "csv"}); err != nil {
		t.Fatalf(`WriteReports({test1}, csv) = %v, want nil`, err)
	}
	previous, err := os.ReadFile(csvTarget)
	if err != nil {
		t.Fatalf(`os.ReadFile(%q) = _, %v, want _, nil`, csvTarget, err)
	}

	// the new commit fails: the previous generation must be preserved
	err = WriteReports(
		[]*secret.Secret{&test1, &test2},
		ReportTarget{Path: csvTarget, Ext: "csv"},
		ReportTarget{Path: jsonTarget, Ext: "json"},
	)
	if err == nil {
		t.Fatal(`WriteReports({test1, test2}, csv, json) = nil, want error`)
	}

	current, err := os.ReadFile(csvTarget)
	if err != nil {
		t.Fatalf(`os.ReadFile(%q) = _, %v, want _, nil`, csvTarget, err)
	}
	if string(current) != string(previous) {
		t.Fatalf(`report %q = %q, want previous generation %q`, csvTarget, current, previous)
	}

	// no temporary or backup file may be left behind
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf(`os.ReadDir(%q) = _, %v, want _, nil`, dir, err)
	}
	if len(entries) != 1 {
		t.Fatalf(`directory %q contains %d entries, want 1`, dir, len(entries))
	}
}

func TestWriteReportsUnsupportedFormat(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "report.yaml")

	err := WriteReports([]*secret.Secret{&test1}, ReportTarget{Path: target, Ext: "yaml"})
	if err == nil {
		t.Fatal(`WriteReports({test1}, yaml) = nil, want error`)
	}

	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf(`os.Stat(%q) = _, %v, want _, not-exist error`, target, err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf(`os.ReadDir(%q) = _, %v, want _, nil`, dir, err)
	}
	if len(entries) != 0 {
		t.Fatalf(`directory %q contains %d entries, want 0`, dir, len(entries))
	}
}
