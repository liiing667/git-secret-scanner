package secret

import (
	"errors"
	"reflect"
	"testing"
)

var test1 Secret = Secret{
	Repository:  "test1_repo",
	Path:        "test1_path",
	Kind:        SecretKindGeneric,
	Commit:      "e2acefa38de1bb02673cd2496a4663a3c6c42508",
	Line:        10,
	Valid:       SecretValidityInvalid,
	Scanners:    SecretScannersGitleaks,
	Cleartext:   "test1_cleartext",
	Fingerprint: "test1_repo:e2acefa38de1bb02673cd2496a4663a3c6c42508:test1_path:10",
}

var test2 Secret = Secret{
	Repository:  "test2_repo",
	Path:        "test2_path",
	Kind:        SecretKindGeneric,
	Commit:      "e2acefa38de1bb02673cd2496a4663a3c6c42599",
	Line:        42,
	Valid:       SecretValidityUnknown,
	Scanners:    SecretScannersAll,
	Cleartext:   "",
	Fingerprint: "hardcoded_fingerprint",
}

var test3 Secret = Secret{
	Repository:  "test1_repo",
	Path:        "test1_path",
	Kind:        SecretKindAMQP,
	Commit:      "e2acefa38de1bb02673cd2496a4663a3c6c42508",
	Line:        10,
	Valid:       SecretValidityUnknown,
	Scanners:    SecretScannersTrufflehog,
	Cleartext:   "test1_cleartext",
	Fingerprint: "test1_repo:e2acefa38de1bb02673cd2496a4663a3c6c42508:test1_path:10",
}

// same secret value as test1, but the code around it moved (new commit and line)
var test1Drifted Secret = Secret{
	Repository:  "test1_repo",
	Path:        "test1_path",
	Kind:        SecretKindGeneric,
	Commit:      "ff0eefa38de1bb02673cd2496a4663a3c6c4ffff",
	Line:        57,
	Valid:       SecretValidityUnknown,
	Scanners:    SecretScannersGitleaks,
	Cleartext:   "test1_cleartext",
	Fingerprint: "test1_repo:ff0eefa38de1bb02673cd2496a4663a3c6c4ffff:test1_path:57",
}

// same location as test1Drifted, but the secret value changed
var test1Changed Secret = Secret{
	Repository:  "test1_repo",
	Path:        "test1_path",
	Kind:        SecretKindGeneric,
	Commit:      "ff0eefa38de1bb02673cd2496a4663a3c6c4ffff",
	Line:        57,
	Valid:       SecretValidityUnknown,
	Scanners:    SecretScannersGitleaks,
	Cleartext:   "changed_cleartext",
	Fingerprint: "test1_repo:ff0eefa38de1bb02673cd2496a4663a3c6c4ffff:test1_path:57",
}

func TestSecretIdentity(t *testing.T) {
	test := test1.Identity()
	want := "test1_repo:test1_path:e272f5f2466d724d16b053356da74bfa90a7b1cd3dbb579314e47da4ee43afa3"

	if test != want {
		t.Fatalf(`test1.Identity() = %q, want %q`, test, want)
	}

	// identity is stable across commit and line drift
	if test1.Identity() != test1Drifted.Identity() {
		t.Fatalf(`test1.Identity() = %q, want %q (drifted)`, test1.Identity(), test1Drifted.Identity())
	}

	// identity changes when the secret value changes
	if test1.Identity() == test1Changed.Identity() {
		t.Fatalf(`test1.Identity() = %q, want different from changed value %q`, test1.Identity(), test1Changed.Identity())
	}

	// identity changes when the same value appears in another file
	if test1.Identity() == test6.Identity() {
		t.Fatalf(`test1.Identity() = %q, want different from test6 %q`, test1.Identity(), test6.Identity())
	}

	// secrets without cleartext fall back to their fingerprint
	test = test2.Identity()
	want = "hardcoded_fingerprint"

	if test != want {
		t.Fatalf(`test2.Identity() = %q, want %q`, test, want)
	}
}

func TestSecretMergeIdentity(t *testing.T) {
	test := test1Drifted.MergeIdentity(&test3)
	want := &Secret{
		Repository:  "test1_repo",
		Path:        "test1_path",
		Kind:        SecretKindAMQP,
		Commit:      "e2acefa38de1bb02673cd2496a4663a3c6c42508",
		Line:        10,
		Valid:       SecretValidityUnknown,
		Scanners:    SecretScannersAll,
		Cleartext:   "test1_cleartext",
		Fingerprint: "test1_repo:e2acefa38de1bb02673cd2496a4663a3c6c42508:test1_path:10",
	}

	if !reflect.DeepEqual(test, want) {
		t.Fatalf(`test1Drifted.MergeIdentity(test3) = %v, want %v`, test, want)
	}

	// the representative keeps the lowest line, whichever side it is on
	test = test3.MergeIdentity(&test1Drifted)
	if !reflect.DeepEqual(test, want) {
		t.Fatalf(`test3.MergeIdentity(test1Drifted) = %v, want %v`, test, want)
	}
}

func TestNewSecret(t *testing.T) {
	test, err := NewSecret(
		"test1_repo",
		"test1_path",
		SecretKindGeneric,
		"e2acefa38de1bb02673cd2496a4663a3c6c42508",
		10,
		SecretValidityInvalid,
		SecretScannersGitleaks,
		"test1_cleartext",
		"",
	)
	want := &test1

	if !reflect.DeepEqual(test, want) || err != nil {
		t.Fatalf(`NewSecret(...test1) = %v, %v, want %v, nil`, test, err, want)
	}

	test, err = NewSecret(
		"test2_repo",
		"test2_path",
		SecretKindGeneric,
		"e2acefa38de1bb02673cd2496a4663a3c6c42599",
		42,
		SecretValidityUnknown,
		SecretScannersAll,
		"",
		"hardcoded_fingerprint",
	)
	want = &test2

	if !reflect.DeepEqual(test, want) || err != nil {
		t.Fatalf(`NewSecret(...test2) = %v, %v, want %v, nil`, test, err, want)
	}

	test, err = NewSecret("test1_repo",
		"test1_path",
		SecretKindAMQP,
		"e2acefa38de1bb02673cd2496a4663a3c6c42508",
		10,
		SecretValidityUnknown,
		SecretScannersTrufflehog,
		"test1_cleartext",
		"",
	)
	want = &test3

	if !reflect.DeepEqual(test, want) || err != nil {
		t.Fatalf(`NewSecret(...test3) = %v, %v, want %v, nil`, test, err, want)
	}
}

func TestSecretIsEqual(t *testing.T) {
	test := test1.IsEqual(&test2)
	want := false

	if test != want {
		t.Fatalf(`test1.IsEqual(test2) = %t, want %t`, test, want)
	}

	test = test1.IsEqual(&test3)
	want = true

	if test != want {
		t.Fatalf(`test1.IsEqual(test3) = %t, want %t`, test, want)
	}

	test = test2.IsEqual(&test3)
	want = false

	if test != want {
		t.Fatalf(`test2.IsEqual(test3) = %t, want %t`, test, want)
	}
}

func TestSecretMerge(t *testing.T) {
	test, err := test1.Merge(&test2)
	var want *Secret = nil

	if test != nil || !errors.Is(err, ErrMergeSecretsNotEqual) {
		t.Fatalf(`test1.Merge(test2) = %v, %v, want %v, %v`, test, err, want, ErrMergeSecretsNotEqual)
	}

	test, err = test1.Merge(&test3)
	want = &Secret{
		Repository:  "test1_repo",
		Path:        "test1_path",
		Kind:        SecretKindAMQP,
		Commit:      "e2acefa38de1bb02673cd2496a4663a3c6c42508",
		Line:        10,
		Valid:       SecretValidityInvalid,
		Scanners:    SecretScannersAll,
		Cleartext:   "test1_cleartext",
		Fingerprint: "test1_repo:e2acefa38de1bb02673cd2496a4663a3c6c42508:test1_path:10",
	}

	if !reflect.DeepEqual(test, want) || err != nil {
		t.Fatalf(`test1.Merge(test3) = %v, %v, want %v, nil`, test, err, want)
	}

	test, err = test1.Merge(&test2)
	want = nil

	if test != nil || !errors.Is(err, ErrMergeSecretsNotEqual) {
		t.Fatalf(`test2.Merge(test3) = %v, %v, want %v, %v`, test, err, want, ErrMergeSecretsNotEqual)
	}
}
