package scm

import (
	"context"
	"fmt"

	"github.com/padok-team/git-secret-scanner/internal/scm/git"
	gitlab "gitlab.com/gitlab-org/api/client-go/v2"
)

type Visibility int

// repository visiblity
const (
	VisibilityAll Visibility = iota
	VisibilityPrivate
	VisibilityPublic
)

func (v Visibility) String() string {
	switch v {
	case VisibilityAll:
		return "all"
	case VisibilityPrivate:
		return "private"
	case VisibilityPublic:
		return "public"
	default:
		// should never be reached
		return ""
	}
}

// Visiblity must implement cobra pflag.Value interface
func (v *Visibility) Set(s string) error {
	switch s {
	case VisibilityAll.String():
		*v = VisibilityAll
		return nil
	case VisibilityPrivate.String():
		*v = VisibilityPrivate
		return nil
	case VisibilityPublic.String():
		*v = VisibilityPublic
		return nil
	default:
		return fmt.Errorf(
			"visiblity must be one of \"%s\", \"%s\" or \"%s\"",
			VisibilityAll.String(),
			VisibilityPrivate.String(),
			VisibilityPublic.String(),
		)
	}
}

// Visiblity must implement cobra pflag.Value interface
func (v *Visibility) Type() string {
	return "{all,private,public}"
}

func (v Visibility) Gitlab() *gitlab.VisibilityValue {
	var visiblity gitlab.VisibilityValue

	switch v {
	case VisibilityAll:
		return nil
	case VisibilityPublic:
		visiblity = gitlab.PublicVisibility
		return &visiblity
	case VisibilityPrivate:
		visiblity = gitlab.PrivateVisibility
		return &visiblity
	default:
		// should not be reached
		return nil
	}
}

type Scm interface {
	GitRepoUrl(repository string) string
	ListRepos(ctx context.Context) ([]string, error)

	// Provider returns the identifier of the SCM source (e.g. "github" or
	// "gitlab") the repositories are listed from.
	Provider() string
	// Token returns the credential used to authenticate to the SCM.
	Token() string
	// RepoIdentity returns the normalized identity of a repository, which
	// stays stable across protocols, credentials and case variations.
	RepoIdentity(repository string) git.RepoIdentity
	// GitRepoUrlForProtocol builds the clone URL of a repository for the
	// given protocol, with the same server and credential as GitRepoUrl.
	GitRepoUrlForProtocol(repository string, protocol git.Protocol) string
}

// SCM source identifiers
const (
	ProviderGithub string = "github"
	ProviderGitlab string = "gitlab"
)

type ScmConfig struct {
	Org             string
	Server          string
	GitProtocol     git.Protocol
	Visiblity       Visibility
	IncludeArchived bool
}
