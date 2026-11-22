package secret

import (
	"reflect"
	"testing"
)

func mustIgnoreTestSecret(t *testing.T, repository string, path string, commit string, line int, cleartext string, fingerprint string) *Secret {
	t.Helper()
	s, err := NewSecret(
		repository,
		path,
		SecretKindGeneric,
		commit,
		line,
		SecretValidityUnknown,
		SecretScannersGitleaks,
		cleartext,
		fingerprint,
	)
	if err != nil {
		t.Fatalf("NewSecret() = %v, want nil", err)
	}
	return s
}

func TestSecretIdentityIgnoresLocationButNotValue(t *testing.T) {
	original := mustIgnoreTestSecret(t, "repo", "config/app.yaml", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 10, "same_cleartext", "")
	drifted := mustIgnoreTestSecret(t, "repo", "config/app.yaml", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 57, "same_cleartext", "")
	changed := mustIgnoreTestSecret(t, "repo", "config/app.yaml", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 10, "changed_cleartext", "")
	otherFile := mustIgnoreTestSecret(t, "repo", "src/main.go", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 10, "same_cleartext", "")
	quoted := mustIgnoreTestSecret(t, "repo", "config/app.yaml", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 10, `"same_cleartext"`, "")

	if original.Identity() != drifted.Identity() {
		t.Fatalf("Identity() drift = %q, want %q", drifted.Identity(), original.Identity())
	}
	if original.Identity() == changed.Identity() {
		t.Fatalf("Identity() = %q for changed value, want a new identity", changed.Identity())
	}
	if original.Identity() == otherFile.Identity() {
		t.Fatalf("Identity() = %q across files, want a new identity", otherFile.Identity())
	}
	if original.Identity() != quoted.Identity() {
		t.Fatalf("Identity() = %q for equivalent quotes, want %q", quoted.Identity(), original.Identity())
	}

	if original.Identity() != "repo:config/app.yaml:"+original.ValueDigest() {
		t.Fatalf("Identity() = %q, want repository/path/digest", original.Identity())
	}
}

func TestSecretSetKeepsSameFingerprintDifferentValues(t *testing.T) {
	const fingerprint = "repo:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:config/app.yaml:10"
	old := mustIgnoreTestSecret(t, "repo", "config/app.yaml", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 10, "old_cleartext", fingerprint)
	current := mustIgnoreTestSecret(t, "repo", "config/app.yaml", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 10, "new_cleartext", fingerprint)

	set := NewSetFromSlice([]*Secret{old, current})
	if set.Length() != 2 {
		t.Fatalf("set.Length() = %d, want 2", set.Length())
	}
	if !set.Has(old) || !set.Has(current) {
		t.Fatalf("set = %v, want both values at the same fingerprint", set)
	}

	remaining, evidence := set.DropIgnoreEntries([]IgnoreEntry{{
		Fingerprint: fingerprint,
		Identity:    old.Identity(),
		Repository:  "repo",
		Commit:      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Path:        "config/app.yaml",
		Line:        10,
		Generation:  "generation-1",
		Version:     2,
		Source:      IgnoreSourceFingerprintFile,
	}})

	if remaining.Length() != 1 || !remaining.Has(current) {
		t.Fatalf("remaining = %v, want only the new value", remaining)
	}
	if len(evidence) != 1 || evidence[0].Identity != old.Identity() {
		t.Fatalf("evidence = %v, want the old value identity", evidence)
	}
}

func TestSecretDiffKeepsChangedValueAtSameFingerprint(t *testing.T) {
	const fingerprint = "repo:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:config/app.yaml:10"
	old := mustIgnoreTestSecret(t, "repo", "config/app.yaml", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 10, "old_cleartext", fingerprint)
	current := mustIgnoreTestSecret(t, "repo", "config/app.yaml", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 10, "new_cleartext", fingerprint)

	baseline := NewSetFromSlice([]*Secret{old})
	remaining := NewSetFromSlice([]*Secret{old, current}).Diff(baseline)
	if remaining.Length() != 1 || !remaining.Has(current) {
		t.Fatalf("Diff() = %v, want only the changed value", remaining)
	}

	remaining, evidence := NewSetFromSlice([]*Secret{old, current}).DiffWithEvidence(baseline, IgnoreSourceBaseline, "generation-2")
	if remaining.Length() != 1 || !remaining.Has(current) {
		t.Fatalf("DiffWithEvidence() = %v, want only the changed value", remaining)
	}
	if len(evidence) != 1 || evidence[0].Fingerprint != fingerprint {
		t.Fatalf("evidence = %v, want the old fingerprint", evidence)
	}
}

func TestDuplicateLinesRemainSeparateFindings(t *testing.T) {
	first := mustIgnoreTestSecret(t, "repo", "config/app.yaml", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 10, "duplicate_secret", "")
	second := mustIgnoreTestSecret(t, "repo", "config/app.yaml", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 11, "duplicate_secret", "")

	set := NewSetFromSlice([]*Secret{first, second})
	if set.Length() != 2 {
		t.Fatalf("set.Length() = %d, want 2 duplicate lines", set.Length())
	}

	remaining := set.DropFingerprints([]string{first.Fingerprint})
	if remaining.Length() != 1 {
		t.Fatalf("remaining.Length() = %d, want 1", remaining.Length())
	}
	if !remaining.Has(second) {
		t.Fatalf("remaining = %v, want the second duplicate line", remaining)
	}
}

func TestDropIgnoreEntriesReportsSource(t *testing.T) {
	entry := IgnoreEntry{
		Fingerprint: test1.Fingerprint,
		Identity:    test1.Identity(),
		Repository:  test1.Repository,
		Commit:      test1.Commit,
		Path:        test1.Path,
		Line:        test1.Line,
		Generation:  "generation-3",
		Version:     2,
		Source:      IgnoreSourceFingerprintFile,
		Stage:       "fingerprint-filter",
		Reason:      "reviewed",
	}

	remaining, evidence := NewSetFromSlice(testSlice).DropIgnoreEntries([]IgnoreEntry{entry})
	if remaining.Has(&test1) {
		t.Fatalf("remaining = %v, want test1 ignored", remaining)
	}
	if len(evidence) != 1 {
		t.Fatalf("len(evidence) = %d, want 1", len(evidence))
	}

	want := IgnoredFinding{
		Fingerprint: test1.Fingerprint,
		Identity:    test1.Identity(),
		Repository:  test1.Repository,
		Commit:      test1.Commit,
		Path:        test1.Path,
		Line:        test1.Line,
		Generation:  "generation-3",
		Version:     2,
		Source:      IgnoreSourceFingerprintFile,
		Reason:      "reviewed",
	}
	if !reflect.DeepEqual(evidence[0], want) {
		t.Fatalf("evidence[0] = %v, want %v", evidence[0], want)
	}
}
