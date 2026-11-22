package secret

import (
	"sort"
	"strings"
)

type SecretSet map[string]*Secret

func NewSet() SecretSet {
	return make(SecretSet)
}

func NewSetFromSlice(ss []*Secret) SecretSet {
	set := NewSet()
	for _, s := range ss {
		set.Add(s)
	}
	return set
}

func (set SecretSet) Add(s *Secret) {
	set.AddWithKey(s)
}

// AddWithKey adds a secret and returns the internal map key that stores it.
// The key is normally the public fingerprint; a generation-qualified key is
// used when the same fingerprint belongs to another scan generation.
func (set SecretSet) AddWithKey(s *Secret) string {
	elem, ok := set[s.Fingerprint]
	if ok && (s.Generation == "" || elem.Generation == "" || s.Generation == elem.Generation) {
		// errors are not handled here as secrets are known to be equal at this stage
		set[s.Fingerprint], _ = elem.Merge(s)
		return s.Fingerprint
	}

	key := s.Fingerprint
	if ok {
		// The same location is used by another generation. Keep both
		// occurrences separately instead of silently mixing generations.
		key = s.Fingerprint + "\x00" + s.Generation
	}
	if existing, exists := set[key]; exists {
		set[key], _ = existing.Merge(s)
		return key
	}
	set[key] = s
	return key
}

func (set SecretSet) Has(s *Secret) bool {
	if elem, ok := set[s.Fingerprint]; ok {
		if s.Generation == "" || elem.Generation == "" || elem.Generation == s.Generation {
			return true
		}
	}

	if s.Generation == "" {
		return false
	}
	_, ok := set[s.Fingerprint+"\x00"+s.Generation]
	return ok
}

func (set SecretSet) Remove(s *Secret) {
	set.removeFingerprint(s.Fingerprint)
}

func (set SecretSet) Length() int {
	return len(set)
}

func (set SecretSet) Clone() SecretSet {
	newSet := NewSet()
	for k, s := range set {
		newSet[k] = s
	}
	return newSet
}

func (set SecretSet) Union(other SecretSet) SecretSet {
	newSet := set.Clone()
	for _, s := range other {
		newSet.Add(s)
	}
	return newSet
}

func (set SecretSet) Diff(other SecretSet) SecretSet {
	newSet := set.Clone()
	for _, s := range other {
		newSet.Remove(s)
	}
	return newSet
}

// DiffIdentities returns the secrets of the set whose stable identity does not
// appear in the other set. Unlike Diff, it does not depend on the commit or
// line where a secret was reported.
func (set SecretSet) DiffIdentities(other SecretSet) SecretSet {
	identities := make(map[string]struct{}, other.Length())
	for _, s := range other {
		identities[s.Identity()] = struct{}{}
	}

	newSet := NewSet()
	for _, s := range set {
		if _, ok := identities[s.Identity()]; !ok {
			newSet.Add(s)
		}
	}
	return newSet
}

// DedupeIdentities merges findings that share the same stable identity (the
// same value in the same file, possibly reported at different lines). The
// representative finding keeps the lowest line number while kind, validity,
// scanner and generation information are combined.
func (set SecretSet) DedupeIdentities() SecretSet {
	ordered := set.ToSlice()
	sort.Slice(ordered, func(i int, j int) bool {
		left := ordered[i]
		right := ordered[j]

		leftGeneration := left.Generation
		rightGeneration := right.Generation
		if leftGeneration != rightGeneration {
			return leftGeneration < rightGeneration
		}

		leftIdentity := left.Identity()
		rightIdentity := right.Identity()
		if leftIdentity != rightIdentity {
			return leftIdentity < rightIdentity
		}

		if left.Line != right.Line {
			return left.Line < right.Line
		}

		return left.Fingerprint < right.Fingerprint
	})

	newSet := NewSet()
	representatives := make(map[string]string, set.Length())
	for _, s := range ordered {
		// Findings from different scan generations must never be mixed, even
		// if they describe the same secret value.
		identity := s.Identity()
		if s.Generation != "" {
			identity = s.Generation + "\x00" + identity
		}

		key, ok := representatives[identity]
		if !ok {
			representatives[identity] = newSet.AddWithKey(s)
			continue
		}

		existing, ok := newSet[key]
		if !ok {
			representatives[identity] = newSet.AddWithKey(s)
			continue
		}

		merged := existing.MergeIdentity(s)
		delete(newSet, key)
		representatives[identity] = newSet.AddWithKey(merged)
	}

	return newSet
}

func (set SecretSet) DropFingerprints(fps []string) SecretSet {
	newSet := set.Clone()
	for _, fp := range fps {
		newSet.removeFingerprint(fp)
	}
	return newSet
}

func (set SecretSet) removeFingerprint(fingerprint string) {
	delete(set, fingerprint)

	prefix := fingerprint + "\x00"
	for key := range set {
		if strings.HasPrefix(key, prefix) {
			delete(set, key)
		}
	}
}

func (set SecretSet) ToSlice() []*Secret {
	slice := make([]*Secret, 0, set.Length())
	for _, s := range set {
		slice = append(slice, s)
	}
	return slice
}
