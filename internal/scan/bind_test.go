package scan

import (
	"testing"

	"github.com/padok-team/git-secret-scanner/internal/report/secret"
	"github.com/padok-team/git-secret-scanner/internal/scm/git"
)

func testSecret(t *testing.T, repository string, line int) *secret.Secret {
	t.Helper()

	s, err := secret.NewSecret(
		repository,
		"test_path",
		secret.SecretKindGeneric,
		"e2acefa38de1bb02673cd2496a4663a3c6c42508",
		line,
		secret.SecretValidityUnknown,
		secret.SecretScannersGitleaks,
		"test_cleartext",
		"",
	)
	if err != nil {
		t.Fatalf(`secret.NewSecret(...) = _, %v, want _, nil`, err)
	}
	return s
}

func TestBindSecretsToIdentity(t *testing.T) {
	identity := git.NewRepoIdentity("github.com", "test_user/test_repo")

	matching := testSecret(t, "test_user/test_repo", 1)
	caseVariant := testSecret(t, "Test_User/Test_Repo", 2)
	gitSuffixVariant := testSecret(t, "test_user/test_repo.git", 3)
	otherRepo := testSecret(t, "test_user/other_repo", 4)
	otherOrg := testSecret(t, "other_user/test_repo", 5)

	secrets := secret.NewSet()
	secrets.Add(matching)
	secrets.Add(caseVariant)
	secrets.Add(gitSuffixVariant)
	secrets.Add(otherRepo)
	secrets.Add(otherOrg)

	bound := BindSecretsToIdentity(secrets, identity)

	if bound.Length() != 3 {
		t.Fatalf(`BindSecretsToIdentity(...) kept %d secrets, want 3`, bound.Length())
	}
	if !bound.Has(matching) || !bound.Has(caseVariant) || !bound.Has(gitSuffixVariant) {
		t.Fatalf(`BindSecretsToIdentity(...) dropped secrets that belong to %v`, identity)
	}
	if bound.Has(otherRepo) || bound.Has(otherOrg) {
		t.Fatalf(`BindSecretsToIdentity(...) kept secrets of another repository`)
	}
}

func TestBindSecretsToIdentityEmpty(t *testing.T) {
	identity := git.NewRepoIdentity("github.com", "test_user/test_repo")

	bound := BindSecretsToIdentity(secret.NewSet(), identity)
	if bound.Length() != 0 {
		t.Fatalf(`BindSecretsToIdentity(empty) kept %d secrets, want 0`, bound.Length())
	}
}
