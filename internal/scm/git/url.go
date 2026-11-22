package git

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

type Protocol int

// git protocol
const (
	ProtocolHTTPS Protocol = iota
	ProtocolSSH
)

func (p Protocol) String() string {
	switch p {
	case ProtocolHTTPS:
		return "https"
	case ProtocolSSH:
		return "ssh"
	default:
		// should never be reached
		return ""
	}
}

// NormalizeServer returns the canonical form of a git server: the host is
// lowercased, trailing slashes are removed and default ports (22 for SSH and
// 443 for HTTPS) are stripped. Non-default ports are preserved, so servers
// reachable on different ports keep distinct identities.
func NormalizeServer(server string) string {
	s := strings.TrimSpace(server)
	s = strings.TrimSuffix(s, "/")
	if s == "" {
		return ""
	}

	host, port, err := net.SplitHostPort(s)
	if err != nil {
		// no port specified
		return strings.ToLower(s)
	}
	if port == "" || port == "22" || port == "443" {
		return strings.ToLower(host)
	}
	return net.JoinHostPort(strings.ToLower(host), port)
}

// NormalizeRepository returns the canonical form of a repository path.
// GitHub and GitLab repository paths are case-insensitive, so the path is
// lowercased; surrounding slashes and a trailing ".git" suffix are removed.
func NormalizeRepository(repository string) string {
	r := strings.TrimSpace(repository)
	r = strings.Trim(r, "/")
	if len(r) >= len(".git") && strings.EqualFold(r[len(r)-len(".git"):], ".git") {
		r = r[:len(r)-len(".git")]
	}
	return strings.ToLower(r)
}

// RepoIdentity is the normalized, protocol-independent identity of a
// repository on a given server. Two URLs that only differ by protocol,
// credentials, case or a ".git" suffix share the same identity.
type RepoIdentity struct {
	Server     string `json:"server"`
	Repository string `json:"repository"`
}

// NewRepoIdentity builds the normalized identity of a repository on a server.
func NewRepoIdentity(server string, repository string) RepoIdentity {
	return RepoIdentity{
		Server:     NormalizeServer(server),
		Repository: NormalizeRepository(repository),
	}
}

func (id RepoIdentity) String() string {
	if id.Server == "" {
		return id.Repository
	}
	return id.Server + "/" + id.Repository
}

func (id RepoIdentity) IsZero() bool {
	return id.Server == "" && id.Repository == ""
}

func RepoUrl(repository string, protocol Protocol, server string, token string) string {
	url := ""
	switch protocol {
	case ProtocolHTTPS:
		if token == "" {
			url = fmt.Sprintf("https://%s/%s", server, repository)
		} else {
			url = fmt.Sprintf("https://x-access-token:%s@%s/%s", token, server, repository)
		}
	case ProtocolSSH:
		if host, port, err := net.SplitHostPort(server); err == nil && port != "" {
			// the SCP-like syntax does not support ports, use the ssh:// form
			url = fmt.Sprintf("ssh://git@%s/%s.git", net.JoinHostPort(host, port), repository)
		} else {
			url = fmt.Sprintf("git@%s:%s.git", server, repository)
		}
	default:
	}

	return url
}

// ParseRepoURL parses an HTTPS or SSH git URL and returns the normalized
// identity of the repository it points to, together with the protocol of the
// URL. Credentials embedded in the URL are ignored.
func ParseRepoURL(rawURL string) (RepoIdentity, Protocol, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return RepoIdentity{}, ProtocolHTTPS, fmt.Errorf("empty repository URL")
	}

	if !strings.Contains(rawURL, "://") {
		// SCP-like SSH syntax: [user@]host:repository
		i := strings.Index(rawURL, ":")
		if i < 0 {
			return RepoIdentity{}, ProtocolHTTPS, fmt.Errorf("unsupported repository URL %q", rawURL)
		}
		host := rawURL[:i]
		repository := rawURL[i+1:]
		if at := strings.LastIndex(host, "@"); at >= 0 {
			host = host[at+1:]
		}
		if host == "" || repository == "" {
			return RepoIdentity{}, ProtocolHTTPS, fmt.Errorf("malformed SSH repository URL %q", rawURL)
		}
		return NewRepoIdentity(host, repository), ProtocolSSH, nil
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return RepoIdentity{}, ProtocolHTTPS, fmt.Errorf("failed to parse repository URL: %w", err)
	}

	var protocol Protocol
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		protocol = ProtocolHTTPS
	case "ssh", "git", "git+ssh":
		protocol = ProtocolSSH
	default:
		return RepoIdentity{}, ProtocolHTTPS, fmt.Errorf("unsupported scheme %q in repository URL", u.Scheme)
	}

	if u.Host == "" {
		return RepoIdentity{}, ProtocolHTTPS, fmt.Errorf("missing host in repository URL")
	}

	repository := strings.TrimPrefix(u.Path, "/")
	if repository == "" {
		return RepoIdentity{}, ProtocolHTTPS, fmt.Errorf("missing repository in repository URL")
	}

	return NewRepoIdentity(u.Host, repository), protocol, nil
}

// SanitizeURL removes any credential embedded in the given URL so that it can
// be safely logged or stored.
func SanitizeURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.User == nil {
		return rawURL
	}
	u.User = nil
	return u.String()
}
