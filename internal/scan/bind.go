package scan

import (
	"github.com/padok-team/git-secret-scanner/internal/report/secret"
	"github.com/padok-team/git-secret-scanner/internal/scm/git"
	"github.com/rs/zerolog/log"
)

// BindSecretsToIdentity filters the secrets found during the scan of a
// repository to keep only the ones that belong to its normalized identity.
//
// This is the last step of the binding between the normalized repository
// identity, the SCM source, the credential generation and the findings: a
// retry with another protocol or a different SCM entry point must never
// cause findings of another repository or another credential to be reported
// under the name of the repository being scanned.
func BindSecretsToIdentity(secrets secret.SecretSet, identity git.RepoIdentity) secret.SecretSet {
	bound := secret.NewSet()

	for _, s := range secrets {
		if git.NewRepoIdentity(identity.Server, s.Repository) == identity {
			bound.Add(s)
		} else {
			log.Warn().
				Str("repository", s.Repository).
				Str("expected_identity", identity.String()).
				Str("fingerprint", s.Fingerprint).
				Msg("dropping finding that does not belong to the scanned repository")
		}
	}

	return bound
}
