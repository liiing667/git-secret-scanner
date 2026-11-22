package scan

import (
	"reflect"
	"testing"

	"github.com/padok-team/git-secret-scanner/internal/report"
)

func TestReportFormatsSet(t *testing.T) {
	var formats ReportFormats

	if err := formats.Set("csv"); err != nil {
		t.Fatalf(`formats.Set("csv") = %v, want nil`, err)
	}
	if want := (ReportFormats{ReportFormatCSV}); !reflect.DeepEqual(formats, want) {
		t.Fatalf(`formats = %v, want %v`, formats, want)
	}

	// comma-separated formats are all selected, without duplicates
	if err := formats.Set("json,csv,json"); err != nil {
		t.Fatalf(`formats.Set("json,csv,json") = %v, want nil`, err)
	}
	if want := (ReportFormats{ReportFormatCSV, ReportFormatJSON}); !reflect.DeepEqual(formats, want) {
		t.Fatalf(`formats = %v, want %v`, formats, want)
	}

	// unknown formats are rejected
	if err := formats.Set("yaml"); err == nil {
		t.Fatal(`formats.Set("yaml") = nil, want error`)
	}
}

func TestReportFormatsString(t *testing.T) {
	test := ReportFormats{ReportFormatCSV, ReportFormatJSON}.String()
	want := "csv,json"

	if test != want {
		t.Fatalf(`ReportFormats{csv, json}.String() = %q, want %q`, test, want)
	}
}

func TestReportTargets(t *testing.T) {
	// default report path, single format
	test := reportTargets("", ReportFormats{ReportFormatJSON})
	want := []report.ReportTarget{{Path: "report.json", Ext: "json"}}
	if !reflect.DeepEqual(test, want) {
		t.Fatalf(`reportTargets("", {json}) = %v, want %v`, test, want)
	}

	// explicit report path, single format: the path is used as is
	test = reportTargets("custom/report.out", ReportFormats{ReportFormatCSV})
	want = []report.ReportTarget{{Path: "custom/report.out", Ext: "csv"}}
	if !reflect.DeepEqual(test, want) {
		t.Fatalf(`reportTargets("custom/report.out", {csv}) = %v, want %v`, test, want)
	}

	// default report path, multiple formats: one file per format
	test = reportTargets("", ReportFormats{ReportFormatCSV, ReportFormatJSON})
	want = []report.ReportTarget{
		{Path: "report.csv", Ext: "csv"},
		{Path: "report.json", Ext: "json"},
	}
	if !reflect.DeepEqual(test, want) {
		t.Fatalf(`reportTargets("", {csv, json}) = %v, want %v`, test, want)
	}

	// explicit report path, multiple formats: the extension is derived per format
	test = reportTargets("custom/report.json", ReportFormats{ReportFormatCSV, ReportFormatJSON})
	want = []report.ReportTarget{
		{Path: "custom/report.csv", Ext: "csv"},
		{Path: "custom/report.json", Ext: "json"},
	}
	if !reflect.DeepEqual(test, want) {
		t.Fatalf(`reportTargets("custom/report.json", {csv, json}) = %v, want %v`, test, want)
	}

	// explicit report path without report extension, multiple formats
	test = reportTargets("custom/report", ReportFormats{ReportFormatCSV, ReportFormatJSON})
	want = []report.ReportTarget{
		{Path: "custom/report.csv", Ext: "csv"},
		{Path: "custom/report.json", Ext: "json"},
	}
	if !reflect.DeepEqual(test, want) {
		t.Fatalf(`reportTargets("custom/report", {csv, json}) = %v, want %v`, test, want)
	}
}
