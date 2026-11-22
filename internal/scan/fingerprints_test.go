package scan

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/padok-team/git-secret-scanner/internal/report/secret"
)

func TestLoadIgnoredFingerprints(t *testing.T) {
	err := LoadIgnoredFingerprints("../../test/testdata/.fingerprintsignore")
	if err != nil {
		t.Fatalf(`LoadIgnoredFingerprints("test/testdata/.fingerprintsignore") = %v, want nil`, err)
	}

	want := map[string][]string{
		"test1_repo": {
			"test1_repo:e2acefa38de1bb02673cd2496a4663a3c6c42508:test1_path:10",
		},
		"test2_repo": {
			"test2_repo:e2acefa38de1aaaaa73cd2496a4663a3c6c42509:test2_path:5",
		},
	}

	if !reflect.DeepEqual(ignoredFingerprints, want) {
		t.Fatalf(`ignoredFingerprints = %v, want %v`, ignoredFingerprints, want)
	}
}

func writeIgnoreTestFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ignore")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("os.WriteFile() = %v, want nil", err)
	}
	return path
}

func mustScanTestSecret(t *testing.T, repository string, path string, commit string, line int, cleartext string, fingerprint string) *secret.Secret {
	t.Helper()
	s, err := secret.NewSecret(
		repository,
		path,
		secret.SecretKindGeneric,
		commit,
		line,
		secret.SecretValidityUnknown,
		secret.SecretScannersGitleaks,
		cleartext,
		fingerprint,
	)
	if err != nil {
		t.Fatalf("NewSecret() = %v, want nil", err)
	}
	return s
}

func TestVersionedIgnoreOnlyDropsTargetSecret(t *testing.T) {
	ResetBaseline()
	ResetIgnoredFingerprints()

	const (
		repository = "test_repo"
		commit     = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		file       = "config/app.yaml"
		fingerprint = "test_repo:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:config/app.yaml:10"
	)

	old := mustScanTestSecret(t, repository, file, commit, 10, "old_cleartext", fingerprint)
	current := mustScanTestSecret(t, repository, file, commit, 10, "new_cleartext", fingerprint)

	path := writeIgnoreTestFile(t, "# gss-ignore-version: 2\n"+
		"# gss-ignore-generation: generation-2\n"+
		fingerprint+"\tsha256:"+old.ValueDigest()+"\tgeneration-2\n")

	if err := LoadIgnoredFingerprints(path); err != nil {
		t.Fatalf("LoadIgnoredFingerprints() = %v, want nil", err)
	}

	snapshot := CaptureIgnoredFingerprints()
	if snapshot.Version != 2 || snapshot.Generation != "generation-2" {
		t.Fatalf("snapshot = %+v, want version 2 generation-2", snapshot)
	}

	remaining, evidence := secret.NewSetFromSlice([]*secret.Secret{old, current}).
		DropIgnoreEntries(GetRepoIgnoredEntries(repository))
	if remaining.Length() != 1 || !remaining.Has(current) {
		t.Fatalf("remaining = %v, want only the new value", remaining)
	}
	if len(evidence) != 1 || evidence[0].Generation != "generation-2" {
		t.Fatalf("evidence = %v, want one generation-2 removal", evidence)
	}

	remaining = secret.NewSetFromSlice([]*secret.Secret{old, current}).
		DropFingerprints(GetRepoIgnoredFingerprints(repository))
	if remaining.Length() != 1 || !remaining.Has(current) {
		t.Fatalf("DropFingerprints() = %v, want only the new value", remaining)
	}
}

func TestVersionedIgnoreSurvivesLineDrift(t *testing.T) {
	ResetBaseline()
	ResetIgnoredFingerprints()

	const (
		repository = "test_repo"
		oldCommit  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		newCommit  = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		file       = "config/app.yaml"
		fingerprint = "test_repo:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:config/app.yaml:10"
	)

	old := mustScanTestSecret(t, repository, file, oldCommit, 10, "closed_cleartext", fingerprint)
	drifted := mustScanTestSecret(t, repository, file, newCommit, 57, "closed_cleartext", "")

	path := writeIgnoreTestFile(t, "# gss-ignore-version: 2\n"+
		fingerprint+"\t"+old.Identity()+"\n")

	if err := LoadIgnoredFingerprints(path); err != nil {
		t.Fatalf("LoadIgnoredFingerprints() = %v, want nil", err)
	}

	remaining, evidence := secret.NewSetFromSlice([]*secret.Secret{drifted}).
		DropIgnoreEntries(GetRepoIgnoredEntries(repository))
	if remaining.Length() != 0 {
		t.Fatalf("remaining = %v, want the moved closed secret to stay ignored", remaining)
	}
	if len(evidence) != 1 || evidence[0].Line != 57 {
		t.Fatalf("evidence = %v, want the drifted line", evidence)
	}
}

func TestLegacyIgnoreBindsToBaselineGeneration(t *testing.T) {
	const (
		repository = "test_repo"
		oldCommit  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		newCommit  = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		file       = "config/app.yaml"
		fingerprint = "test_repo:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:config/app.yaml:10"
	)

	old := mustScanTestSecret(t, repository, file, oldCommit, 10, "legacy_cleartext", fingerprint)
	drifted := mustScanTestSecret(t, repository, file, newCommit, 57, "legacy_cleartext", "")
	current := mustScanTestSecret(t, repository, file, newCommit, 10, "replacement_cleartext", "")

	ResetBaseline()
	ResetIgnoredFingerprints()
	SetBaseline(map[string]secret.SecretSet{
		repository: secret.NewSetFromSlice([]*secret.Secret{old}),
	})

	path := writeIgnoreTestFile(t, fingerprint+"\n")
	if err := LoadIgnoredFingerprints(path); err != nil {
		t.Fatalf("LoadIgnoredFingerprints() = %v, want nil", err)
	}

	entries := GetRepoIgnoredEntries(repository)
	if len(entries) != 1 || entries[0].Identity != old.Identity() {
		t.Fatalf("entries = %v, want legacy entry bound to the baseline value", entries)
	}

	remaining, _ := secret.NewSetFromSlice([]*secret.Secret{drifted, current}).
		DropIgnoreEntries(entries)
	if remaining.Length() != 1 || !remaining.Has(current) {
		t.Fatalf("remaining = %v, want the replacement value to remain", remaining)
	}
}

func TestIgnoreReloadIsAtomic(t *testing.T) {
	ResetBaseline()
	ResetIgnoredFingerprints()

	const fingerprint = "test_repo:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:config/app.yaml:10"
	validPath := writeIgnoreTestFile(t, fingerprint+"\n")
	if err := LoadIgnoredFingerprints(validPath); err != nil {
		t.Fatalf("LoadIgnoredFingerprints(valid) = %v, want nil", err)
	}
	validGeneration := CaptureIgnoredFingerprints().Generation

	invalidPath := writeIgnoreTestFile(t, "this is not a fingerprint\n")
	if err := LoadIgnoredFingerprints(invalidPath); err == nil {
		t.Fatal("LoadIgnoredFingerprints(invalid) = nil, want an error")
	}

	snapshot := CaptureIgnoredFingerprints()
	if snapshot.Generation != validGeneration {
		t.Fatalf("generation = %q, want the previous complete generation %q", snapshot.Generation, validGeneration)
	}
	if got := GetRepoIgnoredFingerprints("test_repo"); !reflect.DeepEqual(got, []string{fingerprint}) {
		t.Fatalf("fingerprints = %v, want %v", got, []string{fingerprint})
	}
}

func TestDuplicateIgnoreLinesDoNotDropDuplicateFindings(t *testing.T) {
	ResetBaseline()
	ResetIgnoredFingerprints()
	secret.ResetLearnedIgnoreIdentities()

	const (
		repository = "test_repo"
		commit     = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		file       = "config/app.yaml"
	)

	first := mustScanTestSecret(t, repository, file, commit, 10, "duplicate_cleartext", "")
	second := mustScanTestSecret(t, repository, file, commit, 11, "duplicate_cleartext", "")

	path := writeIgnoreTestFile(t, first.Fingerprint+"\t"+first.Identity()+"\n")
	if err := LoadIgnoredFingerprints(path); err != nil {
		t.Fatalf("LoadIgnoredFingerprints() = %v, want nil", err)
	}

	remaining, _ := secret.NewSetFromSlice([]*secret.Secret{first, second}).
		DropIgnoreEntries(GetRepoIgnoredEntries(repository))
	if remaining.Length() != 1 || !remaining.Has(second) {
		t.Fatalf("remaining = %v, want the second duplicate line", remaining)
	}
}

func TestCapturedIgnoreSnapshotIsStableAcrossReload(t *testing.T) {
	ResetBaseline()
	ResetIgnoredFingerprints()

	firstFingerprint := "test_repo:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:config/app.yaml:10"
	secondFingerprint := "test_repo:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:config/app.yaml:20"

	firstPath := writeIgnoreTestFile(t, firstFingerprint+"\n")
	if err := LoadIgnoredFingerprints(firstPath); err != nil {
		t.Fatalf("LoadIgnoredFingerprints(first) = %v, want nil", err)
	}
	firstSnapshot := CaptureIgnoredFingerprints()

	secondPath := writeIgnoreTestFile(t, secondFingerprint+"\n")
	if err := LoadIgnoredFingerprints(secondPath); err != nil {
		t.Fatalf("LoadIgnoredFingerprints(second) = %v, want nil", err)
	}
	secondSnapshot := CaptureIgnoredFingerprints()

	if got := firstSnapshot.Entries["test_repo"]; len(got) != 1 || got[0].Fingerprint != firstFingerprint {
		t.Fatalf("first snapshot entries = %v, want %v", got, firstFingerprint)
	}
	if got := secondSnapshot.Entries["test_repo"]; len(got) != 1 || got[0].Fingerprint != secondFingerprint {
		t.Fatalf("second snapshot entries = %v, want %v", got, secondFingerprint)
	}
}

func TestUnsupportedIgnoreVersionFailsClosed(t *testing.T) {
	ResetBaseline()
	ResetIgnoredFingerprints()

	const fingerprint = "test_repo:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:config/app.yaml:10"
	validPath := writeIgnoreTestFile(t, fingerprint+"\n")
	if err := LoadIgnoredFingerprints(validPath); err != nil {
		t.Fatalf("LoadIgnoredFingerprints(valid) = %v, want nil", err)
	}
	previous := CaptureIgnoredFingerprints()

	futurePath := writeIgnoreTestFile(t, "# gss-ignore-version: 3\n"+fingerprint+"\n")
	if err := LoadIgnoredFingerprints(futurePath); err == nil {
		t.Fatal("LoadIgnoredFingerprints(version 3) = nil, want an error")
	}

	current := CaptureIgnoredFingerprints()
	if current.Generation != previous.Generation || !reflect.DeepEqual(current.Entries, previous.Entries) {
		t.Fatalf("snapshot = %+v, want the previous complete generation %+v", current, previous)
	}
}

func TestLegacyIgnoreLearnsValueAcrossRetry(t *testing.T) {
	const (
		repository  = "learn_repo"
		commit      = "cccccccccccccccccccccccccccccccccccccccc"
		file        = "config/legacy.yaml"
		fingerprint = "learn_repo:cccccccccccccccccccccccccccccccccccccccc:config/legacy.yaml:10"
	)

	ResetBaseline()
	ResetIgnoredFingerprints()
	secret.ResetLearnedIgnoreIdentities()

	old := mustScanTestSecret(t, repository, file, commit, 10, "closed_legacy_value", fingerprint)
	current := mustScanTestSecret(t, repository, file, commit, 10, "new_legacy_value", fingerprint)

	path := writeIgnoreTestFile(t, fingerprint+"\n")
	if err := LoadIgnoredFingerprints(path); err != nil {
		t.Fatalf("LoadIgnoredFingerprints() = %v, want nil", err)
	}

	firstScan := secret.NewSetFromSlice([]*secret.Secret{old}).
		DropFingerprints(GetRepoIgnoredFingerprints(repository))
	if firstScan.Length() != 0 {
		t.Fatalf("first scan = %v, want the reviewed secret ignored", firstScan)
	}

	// Retry with the same legacy file. The learned generation binding must
	// keep the old alert closed without swallowing the replacement value.
	if err := LoadIgnoredFingerprints(path); err != nil {
		t.Fatalf("LoadIgnoredFingerprints(retry) = %v, want nil", err)
	}
	retry := secret.NewSetFromSlice([]*secret.Secret{old, current}).
		DropFingerprints(GetRepoIgnoredFingerprints(repository))
	if retry.Length() != 1 || !retry.Has(current) {
		t.Fatalf("retry = %v, want only the replacement value", retry)
	}
}
