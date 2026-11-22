package secret

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// IgnoreSource identifies which part of the scan decided to ignore a finding.
// It is kept in the in-memory evidence so callers can distinguish a manual
// fingerprint entry from a line annotation or a baseline entry.
type IgnoreSource string

const (
	IgnoreSourceFingerprintFile IgnoreSource = "fingerprint-file"
	IgnoreSourceLineAnnotation  IgnoreSource = "line-annotation"
	IgnoreSourceBaseline        IgnoreSource = "baseline"
	IgnoreSourceManual          IgnoreSource = "manual"
)

var ignoreFingerprintPattern = regexp.MustCompile(`^([^:]+):([^:]+):(.+):([0-9]+)$`)
var sha256HexPattern = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

var (
	defaultIgnoreMu      sync.RWMutex
	defaultIgnoreEntries []IgnoreEntry

	learnedIgnoreMu         sync.RWMutex
	learnedIgnoreIdentities = make(map[string]string)
)

// SetDefaultIgnoreEntries installs the current snapshot for callers of the
// historical DropFingerprints([]string) API. Those callers only pass
// fingerprints, so this is how a versioned entry keeps its value identity.
func SetDefaultIgnoreEntries(entries []IgnoreEntry) {
	defaultIgnoreMu.Lock()
	defaultIgnoreEntries = append([]IgnoreEntry(nil), entries...)
	defaultIgnoreMu.Unlock()
}

func ClearDefaultIgnoreEntries() {
	SetDefaultIgnoreEntries(nil)
}

func DefaultIgnoreEntries() []IgnoreEntry {
	defaultIgnoreMu.RLock()
	defer defaultIgnoreMu.RUnlock()
	return append([]IgnoreEntry(nil), defaultIgnoreEntries...)
}

// LearnIgnoreIdentity binds a fingerprint to the value that was actually
// ignored in a scan generation. The first learned value wins: if a later
// secret reuses the same fingerprint, it must not overwrite the closed
// alert's identity and become silently ignored.
func LearnIgnoreIdentity(fingerprint string, identity string) {
	fingerprint = strings.TrimSpace(fingerprint)
	identity = strings.TrimSpace(identity)
	if fingerprint == "" || identity == "" {
		return
	}

	learnedIgnoreMu.Lock()
	if _, exists := learnedIgnoreIdentities[fingerprint]; !exists {
		learnedIgnoreIdentities[fingerprint] = identity
	}
	learnedIgnoreMu.Unlock()
}

func LearnedIgnoreIdentity(fingerprint string) (string, bool) {
	learnedIgnoreMu.RLock()
	defer learnedIgnoreMu.RUnlock()
	identity, ok := learnedIgnoreIdentities[fingerprint]
	return identity, ok
}

// ResetLearnedIgnoreIdentities is intended for tests and for callers that
// explicitly want to discard the recovered generation bindings.
func ResetLearnedIgnoreIdentities() {
	learnedIgnoreMu.Lock()
	learnedIgnoreIdentities = make(map[string]string)
	learnedIgnoreMu.Unlock()
}

// ParseFingerprint splits the historical
// "<repository>:<commit>:<path>:<line>" fingerprint. The path is greedy so
// paths containing ':' keep working.
func ParseFingerprint(fingerprint string) (repository string, commit string, path string, line int, ok bool) {
	match := ignoreFingerprintPattern.FindStringSubmatch(strings.TrimSpace(fingerprint))
	if match == nil {
		return "", "", "", 0, false
	}

	line, err := strconv.Atoi(match[4])
	if err != nil || line < 0 {
		return "", "", "", 0, false
	}

	return match[1], match[2], match[3], line, true
}

// IgnoreEntry is a versioned ignore decision. An entry with an empty Identity
// keeps the historical fingerprint-only behaviour. An entry with an Identity
// only matches the secret value it was created for, so a different secret at
// the same old line is not swallowed.
type IgnoreEntry struct {
	Fingerprint string
	Identity    string
	Repository  string
	Commit      string
	Path        string
	Line        int
	Generation  string
	Version     int
	Source      IgnoreSource
	Stage       string
	Reason      string

	// Budget is the maximum number of findings this entry may remove. The
	// default is one, which preserves duplicate lines as separate findings.
	Budget int
}

// IgnoredFinding is the recovery evidence for a finding removed by an ignore
// rule. It intentionally contains no cleartext.
type IgnoredFinding struct {
	Fingerprint string
	Identity    string
	Repository  string
	Commit      string
	Path        string
	Line        int
	Generation  string
	Version     int
	Source      IgnoreSource
	Stage       string
	Reason      string
}

func (e IgnoreEntry) budget() int {
	if e.Budget <= 0 {
		return 1
	}
	return e.Budget
}

func (e IgnoreEntry) stage() string {
	if e.Stage != "" {
		return e.Stage
	}
	switch e.Source {
	case IgnoreSourceLineAnnotation:
		return "line-filter"
	case IgnoreSourceBaseline:
		return "baseline-filter"
	case IgnoreSourceFingerprintFile, IgnoreSourceManual:
		return "fingerprint-filter"
	default:
		return "ignore-filter"
	}
}

func (e IgnoreEntry) withLearnedIdentity() IgnoreEntry {
	if e.Identity != "" {
		return e
	}
	if identity, learned := LearnedIgnoreIdentity(e.Fingerprint); learned {
		e.Identity = identity
		e.Version = 2
		e.Reason = "learned-from-scan-generation"
	}
	return e
}

func normalizeIdentity(identity string) string {
	value := strings.TrimSpace(strings.Trim(identity, `"'`))
	lower := strings.ToLower(value)

	for _, prefix := range []string{
		"sha256:",
		"sha256=",
		"value-sha256:",
		"value-sha256=",
		"cleartext-sha256:",
		"cleartext-sha256=",
		"identity=",
		"id=",
		"digest=",
	} {
		if strings.HasPrefix(lower, prefix) {
			value = value[len(prefix):]
			lower = strings.ToLower(value)
			break
		}
	}

	if sha256HexPattern.MatchString(value) {
		return lower
	}
	return value
}

func (e IgnoreEntry) identityMatches(s *Secret) bool {
	identity := normalizeIdentity(e.Identity)
	if identity == "" {
		// Historical fingerprint-only entry.
		return true
	}

	if identity == normalizeIdentity(s.Identity()) {
		return true
	}

	digest := s.ValueDigest()
	if digest == "" {
		return false
	}

	if identity == digest {
		return true
	}

	// A full stable identity is "<repository>:<path>:<digest>". Accept the
	// digest suffix as well, but only after the repository/path checks below
	// have confirmed that this entry belongs to the same file.
	prefix := s.Repository + ":" + s.Path + ":"
	return strings.HasPrefix(identity, prefix) && strings.HasSuffix(identity, ":"+digest)
}

func (e IgnoreEntry) matchScore(s *Secret) (int, bool) {
	if s == nil {
		return 0, false
	}
	if e.Repository != "" && !strings.EqualFold(e.Repository, s.Repository) {
		return 0, false
	}
	if e.Path != "" && e.Path != s.Path {
		return 0, false
	}

	if e.Fingerprint != "" && e.Fingerprint == s.Fingerprint {
		if !e.identityMatches(s) {
			// The line is the same but the secret value changed. This is a
			// new finding, not the one the ignore entry closed.
			return 0, false
		}
		return 0, true
	}

	if e.Identity == "" {
		// Legacy entries only match their exact fingerprint.
		return 0, false
	}

	if !e.identityMatches(s) {
		return 0, false
	}

	// The same value moved to another commit/line. Prefer the closest line
	// when a value occurs more than once, but consume only this entry's
	// budget so duplicate occurrences remain reportable.
	distance := e.Line - s.Line
	if distance < 0 {
		distance = -distance
	}
	return 1000 + distance, true
}

// DropIgnoreEntries removes only the findings targeted by the supplied
// entries. Each entry removes at most one finding (unless Budget is raised),
// which keeps duplicate occurrences of the same value as separate findings.
func (set SecretSet) DropIgnoreEntries(entries []IgnoreEntry) (SecretSet, []IgnoredFinding) {
	remaining := set.Clone()
	evidence := make([]IgnoredFinding, 0)

	for _, entry := range entries {
		entry = entry.withLearnedIdentity()
		for removed := 0; removed < entry.budget(); removed++ {
			key, target := bestIgnoreMatch(remaining, entry)
			if target == nil {
				break
			}

			delete(remaining, key)
			if entry.Identity == "" && entry.Fingerprint == target.Fingerprint &&
				entry.Source != IgnoreSourceBaseline && entry.Reason != "legacy-fingerprint" {
				LearnIgnoreIdentity(entry.Fingerprint, target.Identity())
			}
			evidence = append(evidence, IgnoredFinding{
				Fingerprint: target.Fingerprint,
				Identity:    target.Identity(),
				Repository:  target.Repository,
				Commit:      target.Commit,
				Path:        target.Path,
				Line:        target.Line,
				Generation:  entry.Generation,
				Version:     entry.Version,
				Source:      entry.Source,
				Stage:       entry.stage(),
				Reason:      entry.Reason,
			})
		}
	}

	return remaining, evidence
}

func bestIgnoreMatch(set SecretSet, entry IgnoreEntry) (string, *Secret) {
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	bestKey := ""
	bestScore := int(^uint(0) >> 1)
	var best *Secret
	for _, key := range keys {
		candidate := set[key]
		score, ok := entry.matchScore(candidate)
		if !ok || score >= bestScore {
			continue
		}
		bestKey = key
		bestScore = score
		best = candidate
	}
	return bestKey, best
}

// DropFingerprints keeps the historical API. When the entry carries no value
// identity it removes one exact fingerprint match, so duplicate lines are not
// all deleted by a single entry.
func (set SecretSet) DropFingerprints(fps []string) SecretSet {
	entries := make([]IgnoreEntry, 0, len(fps))
	defaults := make(map[string][]IgnoreEntry)
	for _, entry := range DefaultIgnoreEntries() {
		defaults[entry.Fingerprint] = append(defaults[entry.Fingerprint], entry)
	}

	for _, fingerprint := range fps {
		fingerprint = strings.TrimSpace(fingerprint)
		if matches, ok := defaults[fingerprint]; ok && len(matches) > 0 {
			for _, entry := range matches {
				if entry.Identity == "" {
					if identity, learned := LearnedIgnoreIdentity(entry.Fingerprint); learned {
						entry.Identity = identity
						entry.Version = 2
						entry.Reason = "learned-from-scan-generation"
					}
				}
				entries = append(entries, entry)
			}
			continue
		}

		entry := IgnoreEntry{
			Fingerprint: fingerprint,
			Source:      IgnoreSourceManual,
			Reason:      "legacy-fingerprint",
			Version:     1,
		}
		entry.Repository, entry.Commit, entry.Path, entry.Line, _ = ParseFingerprint(entry.Fingerprint)
		if identity, learned := LearnedIgnoreIdentity(entry.Fingerprint); learned {
			entry.Identity = identity
			entry.Version = 2
			entry.Reason = "learned-from-scan-generation"
		}
		entries = append(entries, entry)
	}

	remaining, _ := set.DropIgnoreEntries(entries)
	return remaining
}

// DiffWithEvidence behaves like Diff for historical callers, but records the
// source of each removed finding. Baseline secrets that contain a cleartext
// value are matched by their stable identity as well, so a new value at the
// old location is not hidden by the baseline.
func (set SecretSet) DiffWithEvidence(other SecretSet, source IgnoreSource, generation string) (SecretSet, []IgnoredFinding) {
	entries := make([]IgnoreEntry, 0, len(other))
	for _, s := range other {
		entry := IgnoreEntry{
			Fingerprint: s.Fingerprint,
			Repository:  s.Repository,
			Commit:      s.Commit,
			Path:        s.Path,
			Line:        s.Line,
			Generation:  generation,
			Source:      source,
			Reason:      "matched-entry",
			Version:     1,
		}
		if s.Cleartext != "" {
			entry.Identity = s.Identity()
			entry.Version = 2
			entry.Reason = "matched-identity"
		}
		entries = append(entries, entry)
	}
	return set.DropIgnoreEntries(entries)
}

// DiffIdentities returns the secrets whose stable identity does not appear in
// the other set. Unlike Diff, it does not rely on commit or line number.
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

// DedupeIdentities merges secrets that share the same stable identity (same
// value found at multiple lines of the same file) into a single entry. The
// representative entry keeps the lowest line while validity and scanner
// information are merged across all duplicates.
func (set SecretSet) DedupeIdentities() SecretSet {
	representatives := make(map[string]string, set.Length())
	newSet := NewSet()
	for _, s := range set {
		identity := s.Identity()
		key, ok := representatives[identity]
		if ok {
			merged := newSet[key].MergeIdentity(s)
			delete(newSet, key)
			newSet.Add(merged)
			mergedKey, _ := newSet.find(merged)
			representatives[identity] = mergedKey
		} else {
			newSet.Add(s)
			key, _ := newSet.find(s)
			representatives[identity] = key
		}
	}
	return newSet
}
