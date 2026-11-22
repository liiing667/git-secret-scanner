package scan

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/padok-team/git-secret-scanner/internal/report/secret"
	"github.com/rs/zerolog/log"
)

// IgnoreSnapshot is the immutable view of an ignore file that a scan uses.
// The loader validates the whole file before publishing a snapshot, and Scan
// captures one snapshot before starting repository workers. A hot update of
// the file therefore applies to the next scan, never half-way through the
// current one.
type IgnoreSnapshot struct {
	Version      int
	Generation   string
	Digest       string
	Entries      map[string][]secret.IgnoreEntry
	Fingerprints map[string][]string
}

var (
	ignoredMu           sync.RWMutex
	ignoredFingerprints map[string][]string
	ignoredSnapshot     = emptyIgnoreSnapshot()
)

var hexDigestPattern = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

func emptyIgnoreSnapshot() IgnoreSnapshot {
	return IgnoreSnapshot{
		Version:      1,
		Generation:   "empty",
		Entries:      make(map[string][]secret.IgnoreEntry),
		Fingerprints: make(map[string][]string),
	}
}

func cloneIgnoreSnapshot(snapshot IgnoreSnapshot) IgnoreSnapshot {
	cloned := IgnoreSnapshot{
		Version:      snapshot.Version,
		Generation:   snapshot.Generation,
		Digest:       snapshot.Digest,
		Entries:      make(map[string][]secret.IgnoreEntry, len(snapshot.Entries)),
		Fingerprints: make(map[string][]string, len(snapshot.Fingerprints)),
	}
	for repository, entries := range snapshot.Entries {
		cloned.Entries[repository] = append([]secret.IgnoreEntry(nil), entries...)
	}
	for repository, fingerprints := range snapshot.Fingerprints {
		cloned.Fingerprints[repository] = append([]string(nil), fingerprints...)
	}
	return cloned
}

func publishIgnoreSnapshot(snapshot IgnoreSnapshot) {
	ignoredMu.Lock()
	ignoredSnapshot = snapshot
	ignoredFingerprints = snapshot.Fingerprints
	ignoredMu.Unlock()

	entries := make([]secret.IgnoreEntry, 0, countIgnoreEntries(snapshot))
	for _, repositoryEntries := range snapshot.Entries {
		entries = append(entries, repositoryEntries...)
	}
	secret.SetDefaultIgnoreEntries(entries)
}

// SetIgnoredFingerprints keeps the historical programmatic entry point. Such
// entries have no value identity and therefore keep fingerprint-only
// semantics.
func SetIgnoredFingerprints(fps map[string][]string) {
	snapshot := emptyIgnoreSnapshot()
	snapshot.Version = 1
	snapshot.Generation = "programmatic"

	for repository, fingerprints := range fps {
		for _, fingerprint := range fingerprints {
			entry := newIgnoreEntry(fingerprint, "", "", "", secret.IgnoreSourceManual)
			entry.Repository = repository
			if identity, learned := secret.LearnedIgnoreIdentity(entry.Fingerprint); learned {
				entry.Identity = identity
				entry.Version = 2
				entry.Reason = "learned-from-scan-generation"
			}
			snapshot.Fingerprints[repository] = append(snapshot.Fingerprints[repository], entry.Fingerprint)
			snapshot.Entries[repository] = append(snapshot.Entries[repository], entry)
		}
	}

	publishIgnoreSnapshot(snapshot)
}

// ResetIgnoredFingerprints clears the loaded state. Scan calls it before
// loading so a scan without an ignore file cannot reuse a previous scan's
// generation.
func ResetIgnoredFingerprints() {
	publishIgnoreSnapshot(emptyIgnoreSnapshot())
}

// GetRepoIgnoredFingerprints returns the historical fingerprint strings for a
// repository.
func GetRepoIgnoredFingerprints(repository string) []string {
	ignoredMu.RLock()
	defer ignoredMu.RUnlock()

	fps, ok := ignoredSnapshot.Fingerprints[repository]
	if !ok {
		return make([]string, 0)
	}
	return append([]string(nil), fps...)
}

// GetRepoIgnoredEntries returns the value-aware entries for a repository.
func GetRepoIgnoredEntries(repository string) []secret.IgnoreEntry {
	ignoredMu.RLock()
	defer ignoredMu.RUnlock()

	entries, ok := ignoredSnapshot.Entries[repository]
	if !ok {
		return make([]secret.IgnoreEntry, 0)
	}
	return append([]secret.IgnoreEntry(nil), entries...)
}

// CaptureIgnoredFingerprints returns the snapshot to use for one scan
// generation. The returned value is a deep enough copy to keep being valid
// after a concurrent reload.
func CaptureIgnoredFingerprints() IgnoreSnapshot {
	ignoredMu.RLock()
	defer ignoredMu.RUnlock()
	return cloneIgnoreSnapshot(ignoredSnapshot)
}

// CurrentIgnoredFingerprints is an alias for CaptureIgnoredFingerprints.
func CurrentIgnoredFingerprints() IgnoreSnapshot {
	return CaptureIgnoredFingerprints()
}

// LoadIgnoredFingerprints parses the complete file first and only then
// publishes it. If parsing fails, the previous complete generation stays
// active, which prevents a half-applied ignore set from closing or reopening
// alerts.
func LoadIgnoredFingerprints(path string) error {
	if path == "" {
		return nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	snapshot, err := parseIgnoreFile(data)
	if err != nil {
		return err
	}

	bindIgnoreEntriesToBaseline(&snapshot)
	bindLearnedIgnoreIdentities(&snapshot)
	publishIgnoreSnapshot(snapshot)

	log.Debug().
		Int("version", snapshot.Version).
		Str("generation", snapshot.Generation).
		Int("num", countIgnoreEntries(snapshot)).
		Msg("ignored fingerprints loaded")

	return nil
}

func countIgnoreEntries(snapshot IgnoreSnapshot) int {
	count := 0
	for _, entries := range snapshot.Entries {
		count += len(entries)
	}
	return count
}

func parseIgnoreFile(data []byte) (IgnoreSnapshot, error) {
	snapshot := emptyIgnoreSnapshot()
	snapshot.Version = 1

	sum := sha256.Sum256(data)
	snapshot.Digest = fmt.Sprintf("%x", sum)

	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	headerVersion := 0
	headerGeneration := ""

	for index, raw := range lines {
		line := strings.TrimSpace(strings.TrimPrefix(raw, "\ufeff"))
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "#") {
			version, generation := parseIgnoreHeader(line)
			if version > headerVersion {
				headerVersion = version
			}
			if generation != "" {
				headerGeneration = generation
			}
			continue
		}

		if _, _, _, _, ok := secret.ParseFingerprint(line); !ok && looksLikeIgnoreHeaderLine(line) {
			version, generation := parseIgnoreHeader(line)
			if version != 0 || generation != "" {
				if version > headerVersion {
					headerVersion = version
				}
				if generation != "" {
					headerGeneration = generation
				}
				continue
			}
		}

		entry, err := parseIgnoreLine(line, headerVersion)
		if err != nil {
			log.Debug().
				Err(err).
				Int("line", index+1).
				Msg("invalid ignored fingerprint entry")
			return IgnoreSnapshot{}, errors.New("wrongly formatted fingerprint in file")
		}
		if entry.Repository == "" {
			entry.Repository = strings.SplitN(entry.Fingerprint, ":", 2)[0]
		}

		snapshot.Entries[entry.Repository] = append(snapshot.Entries[entry.Repository], entry)
		snapshot.Fingerprints[entry.Repository] = append(snapshot.Fingerprints[entry.Repository], entry.Fingerprint)
		if entry.Version > headerVersion {
			headerVersion = entry.Version
		}
		if entry.Version > snapshot.Version {
			snapshot.Version = entry.Version
		}
	}

	if headerVersion > snapshot.Version {
		snapshot.Version = headerVersion
	}
	if snapshot.Version > 2 {
		return IgnoreSnapshot{}, fmt.Errorf("unsupported ignore file version %d", snapshot.Version)
	}
	if headerGeneration != "" {
		snapshot.Generation = headerGeneration
	} else {
		snapshot.Generation = "sha256:" + snapshot.Digest
	}

	for repository, entries := range snapshot.Entries {
		for index := range entries {
			if entries[index].Generation == "" {
				entries[index].Generation = snapshot.Generation
			}
			if entries[index].Version < snapshot.Version {
				entries[index].Version = snapshot.Version
			}
			if entries[index].Source == "" {
				entries[index].Source = secret.IgnoreSourceFingerprintFile
			}
		}
		snapshot.Entries[repository] = entries
	}

	return snapshot, nil
}

func looksLikeIgnoreHeaderLine(line string) bool {
	lower := strings.ToLower(strings.TrimSpace(line))
	if lower == "v1" || lower == "v2" {
		return true
	}
	for _, prefix := range []string{
		"version",
		"gss-ignore-version",
		"fingerprint-version",
		"generation",
		"gss-ignore-generation",
		"scan-generation",
	} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

func parseIgnoreHeader(line string) (version int, generation string) {
	value := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "#"))
	if value == "" {
		return 0, ""
	}

	lower := strings.ToLower(value)
	if lower == "v2" || lower == "gss-ignore v2" || lower == "gss-ignore-version: 2" {
		return 2, ""
	}
	if lower == "v1" || lower == "gss-ignore v1" {
		return 1, ""
	}

	if separator := strings.IndexAny(value, ":="); separator > 0 {
		key := strings.ToLower(strings.TrimSpace(value[:separator]))
		fieldValue := strings.TrimSpace(value[separator+1:])
		switch key {
		case "version", "gss-ignore-version", "fingerprint-version":
			if parsed, err := strconv.Atoi(fieldValue); err == nil {
				version = parsed
			}
		case "generation", "gss-ignore-generation", "scan-generation":
			generation = fieldValue
		}
		if version != 0 || generation != "" {
			return version, generation
		}
	}

	fields := strings.Fields(value)
	if len(fields) == 2 {
		key := strings.ToLower(fields[0])
		switch key {
		case "version", "gss-ignore-version", "fingerprint-version":
			if parsed, err := strconv.Atoi(fields[1]); err == nil {
				version = parsed
			}
		case "generation", "gss-ignore-generation", "scan-generation":
			generation = fields[1]
		}
		if version != 0 || generation != "" {
			return version, generation
		}
	}

	for _, field := range fields {
		parts := strings.FieldsFunc(field, func(r rune) bool {
			return r == ':' || r == '='
		})
		if len(parts) < 2 {
			continue
		}

		key := strings.ToLower(parts[0])
		fieldValue := strings.Join(parts[1:], ":")
		switch key {
		case "version", "gss-ignore-version", "fingerprint-version":
			parsed, err := strconv.Atoi(fieldValue)
			if err == nil {
				version = parsed
			}
		case "generation", "gss-ignore-generation", "scan-generation":
			generation = fieldValue
		}
	}

	return version, generation
}

type jsonIgnoreEntry struct {
	Fingerprint string `json:"fingerprint"`
	Identity    string `json:"identity"`
	Repository  string `json:"repository"`
	Commit      string `json:"commit"`
	Path        string `json:"path"`
	Line        int    `json:"line"`
	Generation  string `json:"generation"`
	Version     int    `json:"version"`
	Source      string `json:"source"`
	Reason      string `json:"reason"`
}

func parseIgnoreLine(line string, headerVersion int) (secret.IgnoreEntry, error) {
	value := strings.TrimSpace(line)
	if strings.HasPrefix(strings.ToLower(value), "v2 ") {
		value = strings.TrimSpace(value[3:])
	} else if strings.HasPrefix(strings.ToLower(value), "v1 ") {
		value = strings.TrimSpace(value[3:])
	}

	if value == "" {
		return secret.IgnoreEntry{}, errors.New("empty fingerprint")
	}

	if strings.HasPrefix(value, "{") {
		var raw jsonIgnoreEntry
		if err := json.Unmarshal([]byte(value), &raw); err != nil {
			return secret.IgnoreEntry{}, err
		}
		entry := newIgnoreEntry(
			raw.Fingerprint,
			raw.Identity,
			raw.Generation,
			raw.Source,
			secret.IgnoreSourceFingerprintFile,
		)
		if raw.Repository != "" {
			entry.Repository = raw.Repository
		}
		if raw.Commit != "" {
			entry.Commit = raw.Commit
		}
		if raw.Path != "" {
			entry.Path = raw.Path
		}
		if raw.Line != 0 {
			entry.Line = raw.Line
		}
		if raw.Version > entry.Version {
			entry.Version = raw.Version
		}
		if raw.Reason != "" {
			entry.Reason = raw.Reason
		}
		return entry, validateIgnoreEntry(entry)
	}

	fields := splitIgnoreFields(value)
	if len(fields) == 0 {
		return secret.IgnoreEntry{}, errors.New("empty fingerprint")
	}

	fingerprintIndex := -1
	for index, field := range fields {
		if _, _, _, _, ok := secret.ParseFingerprint(field); ok {
			fingerprintIndex = index
			break
		}
	}
	if fingerprintIndex < 0 {
		return secret.IgnoreEntry{}, errors.New("fingerprint must have the form <repository>:<commit>:<path>:<line>")
	}

	entry := newIgnoreEntry(fields[fingerprintIndex], "", "", "", secret.IgnoreSourceFingerprintFile)
	positionalFields := make([]string, 0, len(fields)-1)
	for index, field := range fields {
		if index == fingerprintIndex {
			continue
		}
		if index < fingerprintIndex {
			positionalFields = append(positionalFields, field)
			continue
		}

		lower := strings.ToLower(field)
		switch {
		case strings.HasPrefix(lower, "identity:") || strings.HasPrefix(lower, "identity=") ||
			strings.HasPrefix(lower, "id:") || strings.HasPrefix(lower, "id=") ||
			strings.HasPrefix(lower, "digest:") || strings.HasPrefix(lower, "digest="):
			for _, key := range []string{"identity", "digest", "id"} {
				entry.Identity = normalizeOption(field, key)
				if entry.Identity != field {
					break
				}
			}
			if entry.Identity != "" {
				entry.Version = 2
			}
		case strings.HasPrefix(lower, "generation:") || strings.HasPrefix(lower, "generation="):
			entry.Generation = normalizeOption(field, "generation")
		case strings.HasPrefix(lower, "version:") || strings.HasPrefix(lower, "version="):
			if parsed, err := strconv.Atoi(normalizeOption(field, "version")); err == nil {
				entry.Version = parsed
			}
		case strings.HasPrefix(lower, "source:") || strings.HasPrefix(lower, "source="):
			entry.Source = secret.IgnoreSource(normalizeOption(field, "source"))
		case strings.HasPrefix(lower, "reason:") || strings.HasPrefix(lower, "reason="):
			entry.Reason = normalizeOption(field, "reason")
		default:
			positionalFields = append(positionalFields, field)
		}
	}
	for _, field := range positionalFields {
		if entry.Identity == "" && looksLikeIdentity(field) {
			entry.Identity = field
			entry.Version = 2
			continue
		}
		if entry.Source == "" && looksLikeIgnoreSource(field) {
			entry.Source = secret.IgnoreSource(field)
			continue
		}
		if entry.Generation == "" {
			entry.Generation = normalizeOption(field, "generation")
			continue
		}
		if entry.Source == "" {
			entry.Source = secret.IgnoreSource(normalizeOption(field, "source"))
			continue
		}
		if entry.Reason == "" {
			entry.Reason = field
		}
	}
	if len(positionalFields) > 0 && entry.Identity == "" && headerVersion < 2 && entry.Version < 2 {
		return secret.IgnoreEntry{}, fmt.Errorf("unexpected field %q after fingerprint", positionalFields[0])
	}
	if entry.Identity == "-" || strings.EqualFold(entry.Identity, "none") || strings.EqualFold(entry.Identity, "legacy") {
		entry.Identity = ""
	}
	return entry, validateIgnoreEntry(entry)
}

func looksLikeIgnoreSource(value string) bool {
	switch secret.IgnoreSource(strings.TrimSpace(value)) {
	case secret.IgnoreSourceFingerprintFile, secret.IgnoreSourceLineAnnotation, secret.IgnoreSourceBaseline, secret.IgnoreSourceManual:
		return true
	default:
		return false
	}
}

func looksLikeIdentity(value string) bool {
	value = strings.TrimSpace(strings.Trim(value, `"'`))
	if value == "-" || strings.EqualFold(value, "none") || strings.EqualFold(value, "legacy") {
		return true
	}

	lower := strings.ToLower(value)
	for _, prefix := range []string{
		"sha256:",
		"sha256=",
		"value-sha256:",
		"value-sha256=",
		"cleartext-sha256:",
		"cleartext-sha256=",
	} {
		if strings.HasPrefix(lower, prefix) {
			value = value[len(prefix):]
			break
		}
	}

	if hexDigestPattern.MatchString(value) {
		return true
	}

	parts := strings.Split(value, ":")
	if len(parts) >= 2 && hexDigestPattern.MatchString(parts[len(parts)-1]) {
		return true
	}
	return false
}

func splitIgnoreFields(value string) []string {
	if _, _, _, _, ok := secret.ParseFingerprint(value); ok {
		return []string{value}
	}
	if strings.Contains(value, "\t") {
		return splitNonEmpty(value, "\t")
	}
	if strings.Contains(value, "|") {
		return splitNonEmpty(value, "|")
	}
	if strings.Contains(value, ",") {
		return splitNonEmpty(value, ",")
	}
	if strings.Contains(value, ";") {
		return splitNonEmpty(value, ";")
	}
	return strings.Fields(value)
}

func splitNonEmpty(value string, separator string) []string {
	parts := strings.Split(value, separator)
	fields := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			fields = append(fields, part)
		}
	}
	return fields
}

func normalizeOption(value string, key string) string {
	value = strings.TrimSpace(value)
	lower := strings.ToLower(value)
	for _, prefix := range []string{key + ":", key + "="} {
		if strings.HasPrefix(lower, prefix) {
			return value[len(prefix):]
		}
	}
	return value
}

func newIgnoreEntry(fingerprint string, identity string, generation string, source string, defaultSource secret.IgnoreSource) secret.IgnoreEntry {
	entry := secret.IgnoreEntry{
		Fingerprint: strings.TrimSpace(fingerprint),
		Identity:    normalizeOption(identity, "identity"),
		Generation:  normalizeOption(generation, "generation"),
		Version:     1,
		Source:      defaultSource,
		Reason:      "fingerprint-entry",
	}

	if entry.Identity == "-" || strings.EqualFold(entry.Identity, "none") || strings.EqualFold(entry.Identity, "legacy") {
		entry.Identity = ""
	}
	if entry.Identity != "" {
		entry.Version = 2
	}

	if source = strings.TrimSpace(source); source != "" {
		entry.Source = secret.IgnoreSource(normalizeOption(source, "source"))
	}

	if repository, commit, path, line, ok := secret.ParseFingerprint(entry.Fingerprint); ok {
		entry.Repository = repository
		entry.Commit = commit
		entry.Path = path
		entry.Line = line
	}

	return entry
}

func validateIgnoreEntry(entry secret.IgnoreEntry) error {
	if entry.Fingerprint == "" {
		return errors.New("missing fingerprint")
	}
	if _, _, _, _, ok := secret.ParseFingerprint(entry.Fingerprint); !ok {
		return errors.New("fingerprint must have the form <repository>:<commit>:<path>:<line>")
	}
	if entry.Identity != "" && !looksLikeIdentity(entry.Identity) {
		return errors.New("identity must be a SHA-256 digest or <repository>:<path>:<SHA-256 digest>")
	}
	return nil
}

// bindIgnoreEntriesToBaseline recovers the value identity of historical
// fingerprint-only entries from a baseline/report from the previous scan
// generation. When the same fingerprint maps to more than one value, the
// binding is ambiguous and the entry keeps the conservative legacy behaviour.
func bindIgnoreEntriesToBaseline(snapshot *IgnoreSnapshot) {
	baselineSnapshot := CaptureBaseline()

	for repository, entries := range snapshot.Entries {
		baselineSecrets := baselineSnapshot[repository]
		if len(baselineSecrets) == 0 {
			continue
		}

		for index := range entries {
			entry := &entries[index]
			if entry.Fingerprint == "" {
				continue
			}
			if entry.Identity != "" && entry.Reason != "learned-from-scan-generation" {
				continue
			}

			identities := make(map[string]struct{})
			for _, s := range baselineSecrets {
				if s == nil || s.Fingerprint != entry.Fingerprint || s.Cleartext == "" {
					continue
				}
				identities[s.Identity()] = struct{}{}
			}

			if len(identities) != 1 {
				continue
			}
			for identity := range identities {
				entry.Identity = identity
			}
			entry.Reason = "bound-to-baseline"
		}
		snapshot.Entries[repository] = entries
	}
}

func bindLearnedIgnoreIdentities(snapshot *IgnoreSnapshot) {
	for repository, entries := range snapshot.Entries {
		for index := range entries {
			if entries[index].Identity != "" {
				continue
			}
			if identity, learned := secret.LearnedIgnoreIdentity(entries[index].Fingerprint); learned {
				entries[index].Identity = identity
				entries[index].Version = 2
				entries[index].Reason = "learned-from-scan-generation"
			}
		}
		snapshot.Entries[repository] = entries
	}
}

// rebindLoadedIgnoreEntriesToBaseline lets ignore-file loading and baseline
// loading happen in either order. It never removes an entry and never changes
// the fingerprint list, so an already published generation stays usable.
func rebindLoadedIgnoreEntriesToBaseline() {
	snapshot := CaptureIgnoredFingerprints()
	bindIgnoreEntriesToBaseline(&snapshot)
	publishIgnoreSnapshot(snapshot)
}
