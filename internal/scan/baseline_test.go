package scan

import (
	"reflect"
	"testing"

	"github.com/padok-team/git-secret-scanner/internal/report/secret"
)

func TestLoadBaseline(t *testing.T) {
	err := LoadBaseline("../../test/testdata/baseline.csv")
	if err != nil {
		t.Fatalf(`LoadBaseline("test/testdata/baseline.csv") = %v, want nil`, err)
	}

	want := map[string]secret.SecretSet{
		"test1_repo": {
			"test1_repo:e2acefa38de1bb02673cd2496a4663a3c6c42508:test1_path:10": &secret.Secret{
				Repository:  "test1_repo",
				Path:        "test1_path",
				Kind:        secret.SecretKindGeneric,
				Commit:      "e2acefa38de1bb02673cd2496a4663a3c6c42508",
				Line:        10,
				Valid:       secret.SecretValidityInvalid,
				Scanners:    secret.SecretScannersGitleaks,
				Cleartext:   "test1_cleartext",
				Fingerprint: "test1_repo:e2acefa38de1bb02673cd2496a4663a3c6c42508:test1_path:10",
			},
			"test1_repo:e2acefa38de1bb02673cd2496a4663a3c6c42508:test1_path:5": &secret.Secret{
				Repository:  "test1_repo",
				Path:        "test1_path",
				Kind:        secret.SecretKindAMQP,
				Commit:      "e2acefa38de1bb02673cd2496a4663a3c6c42508",
				Line:        5,
				Valid:       secret.SecretValidityUnknown,
				Scanners:    secret.SecretScannersTrufflehog,
				Cleartext:   "test1_cleartext",
				Fingerprint: "test1_repo:e2acefa38de1bb02673cd2496a4663a3c6c42508:test1_path:5",
			},
		},
		"test2_repo": {
			"hardcoded_fingerprint": &secret.Secret{
				Repository:  "test2_repo",
				Path:        "test2_path",
				Kind:        secret.SecretKindGeneric,
				Commit:      "e2acefa38de1bb02673cd2496a4663a3c6c42599",
				Line:        42,
				Valid:       secret.SecretValidityUnknown,
				Scanners:    secret.SecretScannersAll,
				Cleartext:   "",
				Fingerprint: "hardcoded_fingerprint",
			},
		},
	}

	if !reflect.DeepEqual(baseline, want) {
		t.Fatalf(`baseline = %v, want %v`, baseline, want)
	}
}

func TestBaselineLineDrift(t *testing.T) {
	err := LoadBaseline("../../test/testdata/baseline_drift.csv")
	if err != nil {
		t.Fatalf(`LoadBaseline("test/testdata/baseline_drift.csv") = %v, want nil`, err)
	}

	commit := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	// same value as the baseline, but the code moved it to another line in a
	// newer commit: it must not be reported again
	drifted, err := secret.NewSecret("drift_repo", "config/app.yaml", secret.SecretKindGeneric, commit, 42, secret.SecretValidityInvalid, secret.SecretScannersGitleaks, "drifted_cleartext", "")
	if err != nil {
		t.Fatalf(`NewSecret(drifted) = %v, want nil`, err)
	}

	// the same value repeated on the next line must be merged with the
	// previous one instead of producing a second finding
	duplicate, err := secret.NewSecret("drift_repo", "config/app.yaml", secret.SecretKindGeneric, commit, 43, secret.SecretValidityUnknown, secret.SecretScannersTrufflehog, "drifted_cleartext", "")
	if err != nil {
		t.Fatalf(`NewSecret(duplicate) = %v, want nil`, err)
	}

	// the value at this location changed since the baseline: it must be reported
	changed, err := secret.NewSecret("drift_repo", "config/app.yaml", secret.SecretKindAWS, commit, 30, secret.SecretValidityUnknown, secret.SecretScannersTrufflehog, "changed_cleartext", "")
	if err != nil {
		t.Fatalf(`NewSecret(changed) = %v, want nil`, err)
	}

	// a brand new secret must be reported
	brandNew, err := secret.NewSecret("drift_repo", "src/main.go", secret.SecretKindGeneric, commit, 7, secret.SecretValidityUnknown, secret.SecretScannersGitleaks, "brand_new_cleartext", "")
	if err != nil {
		t.Fatalf(`NewSecret(brandNew) = %v, want nil`, err)
	}

	// matches a baseline entry without cleartext through its fingerprint
	manual, err := secret.NewSecret("drift_repo", "README.md", secret.SecretKindGeneric, commit, 3, secret.SecretValidityUnknown, secret.SecretScannersAll, "", "manual_fingerprint_entry")
	if err != nil {
		t.Fatalf(`NewSecret(manual) = %v, want nil`, err)
	}

	scanned := secret.NewSetFromSlice([]*secret.Secret{drifted, duplicate, changed, brandNew, manual})

	got := scanned.
		DedupeIdentities().
		DiffIdentities(GetRepoBaseline("drift_repo"))

	want := secret.NewSetFromSlice([]*secret.Secret{changed, brandNew})

	if !reflect.DeepEqual(got, want) {
		t.Fatalf(`scanned.DedupeIdentities().DiffIdentities(baseline) = %v, want %v`, got, want)
	}
}
