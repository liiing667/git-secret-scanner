package git

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/go-git/go-git/v5"
)

// CloneRequest describes how a repository must be cloned and how the
// resulting clone is bound to a normalized repository identity, an SCM source
// and a credential generation.
type CloneRequest struct {
	// URL is the SCM URL to clone from.
	URL string
	// Destination is the local path of the clone.
	Destination string
	// Shallow clones and fetches with a depth of 1.
	Shallow bool
	// FetchIfExists fetches new refs instead of failing when the destination
	// already contains a clone of the same repository.
	FetchIfExists bool
	// Identity is the normalized identity the clone must belong to. When
	// empty, it is derived from URL.
	Identity RepoIdentity
	// Provenance, when set, is enforced when reusing an existing clone and
	// written into the clone after a successful clone or fetch.
	Provenance *Provenance
}

// Clone clones a repository to the given destination, optionally fetching new
// refs when the destination already contains a clone of the same repository.
func Clone(ctx context.Context, url string, destination string, shallow bool, fetchIfExists bool) error {
	return CloneRepository(ctx, CloneRequest{
		URL:           url,
		Destination:   destination,
		Shallow:       shallow,
		FetchIfExists: fetchIfExists,
	})
}

// CloneRepository clones a repository while binding the resulting clone to
// the requested repository identity and credential generation:
//   - an existing clone that belongs to another repository or SCM source is
//     removed and cloned again, so its content can never be attributed to the
//     requested repository;
//   - an existing clone of the same repository is bound to the current URL
//     before fetching, so a retry with another protocol or credential never
//     keeps fetching from the old SCM URL;
//   - content fetched under another credential generation is never reused
//     without being refreshed.
func CloneRepository(ctx context.Context, req CloneRequest) error {
	identity := req.Identity
	if identity.IsZero() {
		if id, _, err := ParseRepoURL(req.URL); err == nil {
			identity = id
		}
	}

	err := plainClone(ctx, req.URL, req.Destination, req.Shallow)
	if err != nil {
		// if the path already exists, it means the repository has already
		// been cloned and it is not an error
		if errors.Is(err, git.ErrRepositoryAlreadyExists) {
			return cloneExisting(ctx, req, identity)
		}
		return err
	}

	return finishClone(req)
}

// plainClone performs a fresh clone of url into destination.
func plainClone(ctx context.Context, url string, destination string, shallow bool) error {
	opts := &git.CloneOptions{URL: url}
	if shallow {
		opts.SingleBranch = true
		opts.Tags = git.NoTags
		opts.Depth = 1
	}

	_, err := git.PlainCloneContext(ctx, destination, true, opts)
	return err
}

// finishClone completes a fresh clone: for full clones, fetch all other
// remote refs that are not retrieved by default, then record the provenance
// of the clone.
func finishClone(req CloneRequest) error {
	if !req.Shallow {
		if err := Fetch(req.Destination, false); err != nil {
			return fmt.Errorf("fetch error: %w", err)
		}
	}
	return writeProvenance(req)
}

// reclone removes the destination and performs a fresh clone.
func reclone(ctx context.Context, req CloneRequest) error {
	if err := os.RemoveAll(req.Destination); err != nil {
		return fmt.Errorf("failed to remove existing clone at %q: %w", req.Destination, err)
	}
	if err := plainClone(ctx, req.URL, req.Destination, req.Shallow); err != nil {
		return err
	}
	return finishClone(req)
}

// cloneExisting handles a clone destination that already exists.
func cloneExisting(ctx context.Context, req CloneRequest, identity RepoIdentity) error {
	stored, storedErr := ReadProvenance(req.Destination)

	// determine the identity of the existing clone, from its provenance when
	// available or from its remote URL otherwise
	existingIdentity := RepoIdentity{}
	if storedErr == nil {
		existingIdentity = stored.Identity
	} else if remote, err := RemoteURL(req.Destination); err == nil {
		if id, _, err := ParseRepoURL(remote); err == nil {
			existingIdentity = id
		}
	}

	provider := ""
	if req.Provenance != nil {
		provider = req.Provenance.Provider
	}

	// a clone that belongs to another repository or SCM source must never be
	// reused: its findings would be attributed to the wrong repository
	mismatch := !identity.IsZero() && existingIdentity != identity
	if storedErr == nil && provider != "" && stored.Provider != provider {
		mismatch = true
	}
	if mismatch {
		return reclone(ctx, req)
	}

	// bind the clone to the current URL before fetching: a retry with
	// another protocol or a new credential generation must not keep fetching
	// from the old SCM URL
	if remote, err := RemoteURL(req.Destination); err == nil && remote != req.URL {
		if err := SetRemoteURL(req.Destination, req.URL); err != nil {
			return fmt.Errorf("failed to update remote of clone at %q: %w", req.Destination, err)
		}
	}

	credentialChanged := storedErr == nil && req.Provenance != nil &&
		!stored.SameCredential(*req.Provenance)

	if req.FetchIfExists {
		if err := Fetch(req.Destination, req.Shallow); err != nil {
			return fmt.Errorf("fetch error: %w", err)
		}
		return writeProvenance(req)
	}

	if credentialChanged {
		// the clone content was fetched under another credential generation
		// and refreshing it is not allowed: drop it instead of attributing
		// findings fetched with another credential to this repository
		return reclone(ctx, req)
	}

	return nil
}

// writeProvenance records the provenance of a clone when requested.
func writeProvenance(req CloneRequest) error {
	if req.Provenance == nil {
		return nil
	}
	provenance := *req.Provenance
	provenance.UpdatedAt = time.Now().UTC()
	if err := WriteProvenance(req.Destination, provenance); err != nil {
		return fmt.Errorf("failed to write provenance for clone at %q: %w", req.Destination, err)
	}
	return nil
}
