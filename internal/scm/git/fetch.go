package git

import (
	"errors"
	"fmt"
	"math"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
)

const FullFetchRefSpec string = "+refs/*:refs/remotes/%s/*"

func Fetch(repo string, shallow bool) error {
	r, err := git.PlainOpen(repo)
	if err != nil {
		return err
	}

	opts := &git.FetchOptions{}
	if shallow {
		opts.RefSpecs = []config.RefSpec{"+HEAD:refs/remotes/origin/HEAD"}
		opts.Tags = git.NoTags
		opts.Depth = 1
	} else {
		opts.RefSpecs = []config.RefSpec{
			config.RefSpec(fmt.Sprintf(FullFetchRefSpec, "origin")),
		}
		opts.Tags = git.AllTags
		opts.Depth = math.MaxInt32 // means infinite depth, cf. https://git-scm.com/docs/shallow
	}

	err = r.Fetch(opts)
	if err != nil {
		if errors.Is(err, git.NoErrAlreadyUpToDate) {
			return nil
		}
		return err
	}

	return nil
}

// RemoteURL returns the URL of the "origin" remote of the repository at the
// given path.
func RemoteURL(repo string) (string, error) {
	r, err := git.PlainOpen(repo)
	if err != nil {
		return "", err
	}

	remote, err := r.Remote("origin")
	if err != nil {
		return "", err
	}

	urls := remote.Config().URLs
	if len(urls) == 0 {
		return "", errors.New("remote \"origin\" has no URL configured")
	}

	return urls[0], nil
}

// SetRemoteURL sets the URL of the "origin" remote of the repository at the
// given path.
func SetRemoteURL(repo string, url string) error {
	r, err := git.PlainOpen(repo)
	if err != nil {
		return err
	}

	if err := r.DeleteRemote("origin"); err != nil {
		return err
	}

	_, err = r.CreateRemote(&config.RemoteConfig{Name: "origin", URLs: []string{url}})
	return err
}
