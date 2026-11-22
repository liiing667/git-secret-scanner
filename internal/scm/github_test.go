package scm

import (
	"reflect"
	"testing"

	"github.com/padok-team/git-secret-scanner/internal/scm/git"
)

func TestNewGithubScm(t *testing.T) {
	config := &ScmConfig{
		Org:             "test_org",
		Server:          "",
		GitProtocol:     git.ProtocolHTTPS,
		Visiblity:       VisibilityAll,
		IncludeArchived: true,
	}

	test, err := NewGithubScm(config, "faketoken")

	if !reflect.DeepEqual(test.ScmConfig, config) || test.token != "faketoken" || test.client.BaseURL() != "https://api.github.com/" || err != nil {
		t.Fatalf(`NewGithubScm(...) = %v, %v, want {%v faketoken client}, nil`, test, err, config)
	}
	if config.Server != "github.com" {
		t.Fatalf(`NewGithubScm(...) -> config.Server = %q, want "github.com"`, config.Server)
	}

	config.Server = "test.server"
	test, err = NewGithubScm(config, "faketoken")

	if !reflect.DeepEqual(test.ScmConfig, config) || test.token != "faketoken" || test.client.BaseURL() != "https://test.server/api/v3/" || err != nil {
		t.Fatalf(`NewGithubScm(...) = %v, %v, want {%v faketoken client}, nil`, test, err, config)
	}
	if config.Server != "test.server" {
		t.Fatalf(`NewGithubScm(...) -> config.Server = %q, want "test.server"`, config.Server)
	}
}

func TestGithubScmGitRepoUrl(t *testing.T) {
	config := &ScmConfig{
		Org:             "test_org",
		Server:          "test.server",
		GitProtocol:     git.ProtocolHTTPS,
		Visiblity:       VisibilityAll,
		IncludeArchived: true,
	}

	scm, err := NewGithubScm(config, "faketoken")
	if err != nil {
		t.Fatalf(`NewGithubScm(...) = _, %v, want _, nil`, err)
	}

	test := scm.GitRepoUrl("test_user/test_repo")
	want := "https://x-access-token:faketoken@test.server/test_user/test_repo"

	if test != want {
		t.Fatalf(`scm.GitRepoUrl("test_user/test_repo") = %q, want %q`, test, want)
	}

	config.Server = "github.com"
	config.GitProtocol = git.ProtocolSSH

	scm, err = NewGithubScm(config, "faketoken")
	if err != nil {
		t.Fatalf(`NewGithubScm(...) = _, %v, want _, nil`, err)
	}

	test = scm.GitRepoUrl("test_user/test_repo")
	want = "git@github.com:test_user/test_repo.git"

	if test != want {
		t.Fatalf(`scm.GitRepoUrl("test_user/test_repo") = %q, want %q`, test, want)
	}
}

func TestGithubScmBinding(t *testing.T) {
	config := &ScmConfig{
		Org:             "test_org",
		Server:          "TEST.server",
		GitProtocol:     git.ProtocolHTTPS,
		Visiblity:       VisibilityAll,
		IncludeArchived: true,
	}

	scm, err := NewGithubScm(config, "faketoken")
	if err != nil {
		t.Fatalf(`NewGithubScm(...) = _, %v, want _, nil`, err)
	}

	if scm.Provider() != ProviderGithub {
		t.Fatalf(`scm.Provider() = %q, want %q`, scm.Provider(), ProviderGithub)
	}
	if scm.Token() != "faketoken" {
		t.Fatalf(`scm.Token() = %q, want "faketoken"`, scm.Token())
	}

	// the server is normalized (case-insensitive) at construction
	if scm.Server != "test.server" {
		t.Fatalf(`scm.Server = %q, want "test.server"`, scm.Server)
	}

	// the identity is normalized: case and ".git" suffix variations of the
	// same repository share the same identity
	test := scm.RepoIdentity("Test_User/Test_Repo")
	want := git.NewRepoIdentity("test.server", "test_user/test_repo")
	if test != want {
		t.Fatalf(`scm.RepoIdentity("Test_User/Test_Repo") = %v, want %v`, test, want)
	}

	// URLs built for any protocol map back to the same identity
	for _, protocol := range []git.Protocol{git.ProtocolHTTPS, git.ProtocolSSH} {
		url := scm.GitRepoUrlForProtocol("test_user/test_repo", protocol)
		identity, parsedProtocol, err := git.ParseRepoURL(url)
		if err != nil {
			t.Fatalf(`git.ParseRepoURL(%q) = _, _, %v, want _, _, nil`, url, err)
		}
		if identity != want {
			t.Fatalf(`git.ParseRepoURL(%q) = %v, want %v`, url, identity, want)
		}
		if parsedProtocol != protocol {
			t.Fatalf(`git.ParseRepoURL(%q) protocol = %v, want %v`, url, parsedProtocol, protocol)
		}
	}

	// GitRepoUrl keeps using the configured protocol
	if scm.GitRepoUrl("test_user/test_repo") != scm.GitRepoUrlForProtocol("test_user/test_repo", git.ProtocolHTTPS) {
		t.Fatalf(`scm.GitRepoUrl(...) != scm.GitRepoUrlForProtocol(..., ProtocolHTTPS)`)
	}
}
