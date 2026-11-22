package secret

import "sort"

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
	elem, ok := set[s.Fingerprint]
	if ok {
		// errors are not handled here as secrets are known to be equal at this stage
		set[s.Fingerprint], _ = elem.Merge(s)
	} else {
		set[s.Fingerprint] = s
	}
}

func (set SecretSet) Has(s *Secret) bool {
	_, ok := set[s.Fingerprint]
	return ok
}

func (set SecretSet) Remove(s *Secret) {
	delete(set, s.Fingerprint)
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

func (set SecretSet) DropFingerprints(fps []string) SecretSet {
	newSet := set.Clone()
	for _, fp := range fps {
		delete(newSet, fp)
	}
	return newSet
}

// ToSlice returns the secrets of the set as a slice. The secrets are sorted
// in a stable, deterministic order (by repository, path, line, commit and
// fingerprint) so that reports generated from a set do not depend on map
// iteration order.
func (set SecretSet) ToSlice() []*Secret {
	slice := make([]*Secret, 0, set.Length())
	for _, s := range set {
		slice = append(slice, s)
	}
	sort.SliceStable(slice, func(i, j int) bool {
		if slice[i].Repository != slice[j].Repository {
			return slice[i].Repository < slice[j].Repository
		}
		if slice[i].Path != slice[j].Path {
			return slice[i].Path < slice[j].Path
		}
		if slice[i].Line != slice[j].Line {
			return slice[i].Line < slice[j].Line
		}
		if slice[i].Commit != slice[j].Commit {
			return slice[i].Commit < slice[j].Commit
		}
		return slice[i].Fingerprint < slice[j].Fingerprint
	})
	return slice
}
