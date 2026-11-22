package git

import "testing"

func TestProtocolString(t *testing.T) {
	test := ProtocolHTTPS.String()
	want := "https"

	if test != want {
		t.Fatalf(`ProtocolHTTPS.String() = %q, want %q`, test, want)
	}

	test = ProtocolSSH.String()
	want = "ssh"

	if test != want {
		t.Fatalf(`ProtocolSSH.String() = %q, want %q`, test, want)
	}
}

func TestRepoUrl(t *testing.T) {
	test := RepoUrl("test_user/test_repo", ProtocolHTTPS, "test.server", "faketoken")
	want := "https://x-access-token:faketoken@test.server/test_user/test_repo"

	if test != want {
		t.Fatalf(`RepoUrl("test_user/test_repo", ProtocolHTTPS, "test.server", "faketoken") = %q, want %q`, test, want)
	}

	test = RepoUrl("test_user/test_repo", ProtocolSSH, "test.server", "faketoken")
	want = "git@test.server:test_user/test_repo.git"

	if test != want {
		t.Fatalf(`RepoUrl("test_user/test_repo", ProtocolSSH, "test.server", "faketoken") = %q, want %q`, test, want)
	}
}

func TestRepoUrlWithPort(t *testing.T) {
	// HTTPS URLs keep the port as-is
	test := RepoUrl("test_user/test_repo", ProtocolHTTPS, "test.server:8443", "faketoken")
	want := "https://x-access-token:faketoken@test.server:8443/test_user/test_repo"

	if test != want {
		t.Fatalf(`RepoUrl("test_user/test_repo", ProtocolHTTPS, "test.server:8443", "faketoken") = %q, want %q`, test, want)
	}

	// the SCP-like SSH syntax does not support ports, the ssh:// form must
	// be used instead
	test = RepoUrl("test_user/test_repo", ProtocolSSH, "test.server:2222", "faketoken")
	want = "ssh://git@test.server:2222/test_user/test_repo.git"

	if test != want {
		t.Fatalf(`RepoUrl("test_user/test_repo", ProtocolSSH, "test.server:2222", "faketoken") = %q, want %q`, test, want)
	}
}

func TestNormalizeServer(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"github.com", "github.com"},
		{"GitHub.COM", "github.com"},
		{" github.com ", "github.com"},
		{"github.com/", "github.com"},
		{"github.com:443", "github.com"},
		{"github.com:22", "github.com"},
		{"gitlab.example.com:8443", "gitlab.example.com:8443"},
		{"GITLAB.EXAMPLE.COM:8443", "gitlab.example.com:8443"},
		{"", ""},
	}

	for _, c := range cases {
		if test := NormalizeServer(c.in); test != c.want {
			t.Errorf(`NormalizeServer(%q) = %q, want %q`, c.in, test, c.want)
		}
	}
}

func TestNormalizeRepository(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"test_user/test_repo", "test_user/test_repo"},
		{"Test_User/Test_Repo", "test_user/test_repo"},
		{"test_user/test_repo.git", "test_user/test_repo"},
		{"test_user/test_repo.GIT", "test_user/test_repo"},
		{"/test_user/test_repo/", "test_user/test_repo"},
		{" test_user/test_repo ", "test_user/test_repo"},
		{"test_group/test_subgroup/test_repo", "test_group/test_subgroup/test_repo"},
	}

	for _, c := range cases {
		if test := NormalizeRepository(c.in); test != c.want {
			t.Errorf(`NormalizeRepository(%q) = %q, want %q`, c.in, test, c.want)
		}
	}
}

func TestParseRepoURL(t *testing.T) {
	cases := []struct {
		in         string
		identity   RepoIdentity
		protocol   Protocol
		shouldFail bool
	}{
		{
			in:       "https://x-access-token:faketoken@GitHub.com/Test_User/Test_Repo",
			identity: RepoIdentity{Server: "github.com", Repository: "test_user/test_repo"},
			protocol: ProtocolHTTPS,
		},
		{
			in:       "https://gitlab.example.com:8443/test_user/test_repo.git",
			identity: RepoIdentity{Server: "gitlab.example.com:8443", Repository: "test_user/test_repo"},
			protocol: ProtocolHTTPS,
		},
		{
			in:       "https://github.com:443/test_user/test_repo",
			identity: RepoIdentity{Server: "github.com", Repository: "test_user/test_repo"},
			protocol: ProtocolHTTPS,
		},
		{
			in:       "git@github.com:Test_User/Test_Repo.git",
			identity: RepoIdentity{Server: "github.com", Repository: "test_user/test_repo"},
			protocol: ProtocolSSH,
		},
		{
			in:       "ssh://git@gitlab.example.com:2222/test_user/test_repo.git",
			identity: RepoIdentity{Server: "gitlab.example.com:2222", Repository: "test_user/test_repo"},
			protocol: ProtocolSSH,
		},
		{
			in:       "ssh://git@github.com:22/test_user/test_repo.git",
			identity: RepoIdentity{Server: "github.com", Repository: "test_user/test_repo"},
			protocol: ProtocolSSH,
		},
		{in: "", shouldFail: true},
		{in: "https://github.com", shouldFail: true},
		{in: "ftp://github.com/test_user/test_repo", shouldFail: true},
	}

	for _, c := range cases {
		identity, protocol, err := ParseRepoURL(c.in)
		if c.shouldFail {
			if err == nil {
				t.Errorf(`ParseRepoURL(%q) = %v, %v, nil, want error`, c.in, identity, protocol)
			}
			continue
		}
		if err != nil {
			t.Errorf(`ParseRepoURL(%q) = _, _, %v, want nil`, c.in, err)
			continue
		}
		if identity != c.identity || protocol != c.protocol {
			t.Errorf(`ParseRepoURL(%q) = %v, %v, nil, want %v, %v, nil`, c.in, identity, protocol, c.identity, c.protocol)
		}
	}
}

func TestParseRepoURLRoundTrip(t *testing.T) {
	// URLs built by RepoUrl must parse back to the identity they were built
	// from, whatever the protocol
	for _, protocol := range []Protocol{ProtocolHTTPS, ProtocolSSH} {
		url := RepoUrl("Test_User/Test_Repo", protocol, "GitHub.com", "faketoken")

		identity, parsedProtocol, err := ParseRepoURL(url)
		if err != nil {
			t.Fatalf(`ParseRepoURL(%q) = _, _, %v, want nil`, url, err)
		}

		want := NewRepoIdentity("github.com", "test_user/test_repo")
		if identity != want {
			t.Fatalf(`ParseRepoURL(%q) = %v, want %v`, url, identity, want)
		}
		if parsedProtocol != protocol {
			t.Fatalf(`ParseRepoURL(%q) protocol = %v, want %v`, url, parsedProtocol, protocol)
		}
	}
}

func TestSanitizeURL(t *testing.T) {
	test := SanitizeURL("https://x-access-token:faketoken@test.server/test_user/test_repo")
	want := "https://test.server/test_user/test_repo"

	if test != want {
		t.Fatalf(`SanitizeURL("https://x-access-token:faketoken@test.server/test_user/test_repo") = %q, want %q`, test, want)
	}

	// SCP-like SSH URLs carry no credential and are left untouched
	test = SanitizeURL("git@test.server:test_user/test_repo.git")
	want = "git@test.server:test_user/test_repo.git"

	if test != want {
		t.Fatalf(`SanitizeURL("git@test.server:test_user/test_repo.git") = %q, want %q`, test, want)
	}
}
