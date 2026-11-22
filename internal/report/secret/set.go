package secret

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

func sameOccurrence(a *Secret, b *Secret) bool {
	if a == nil || b == nil {
		return false
	}
	return a.Fingerprint == b.Fingerprint && a.Identity() == b.Identity()
}

func (set SecretSet) find(s *Secret) (string, *Secret) {
	if s == nil {
		return "", nil
	}
	if existing, ok := set[s.Fingerprint]; ok && sameOccurrence(existing, s) {
		return s.Fingerprint, existing
	}
	for key, existing := range set {
		if sameOccurrence(existing, s) {
			return key, existing
		}
	}
	return "", nil
}

func (set SecretSet) Add(s *Secret) {
	if s == nil {
		return
	}

	if key, elem := set.find(s); elem != nil {
		// errors are not handled here as secrets are known to be equal at this stage
		set[key], _ = elem.Merge(s)
		return
	}

	// Keep the historical fingerprint key for the first occurrence. If a
	// different value already uses that fingerprint, keep both findings by
	// giving the new occurrence a collision-free internal key. The public
	// Fingerprint field remains unchanged for CSV/JSON compatibility.
	key := s.Fingerprint
	if _, exists := set[key]; exists {
		key = s.Fingerprint + "\x00" + s.Identity()
	}
	set[key] = s
}

func (set SecretSet) Has(s *Secret) bool {
	_, found := set.find(s)
	return found != nil
}

func (set SecretSet) Remove(s *Secret) {
	key, found := set.find(s)
	if found != nil {
		delete(set, key)
	}
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

func (set SecretSet) ToSlice() []*Secret {
	slice := make([]*Secret, 0, set.Length())
	for _, s := range set {
		slice = append(slice, s)
	}
	return slice
}
