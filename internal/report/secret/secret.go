package secret

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

type SecretValidity int

const (
	SecretValidityUnknown SecretValidity = iota
	SecretValidityValid
	SecretValidityInvalid
)

func (sv SecretValidity) String() string {
	switch sv {
	case SecretValidityValid:
		return "true"
	case SecretValidityInvalid:
		return "false"
	case SecretValidityUnknown:
		return ""
	default:
		// should never be reached
		return ""
	}
}

// implements json.Marshaler
func (sv SecretValidity) MarshalJSON() ([]byte, error) {
	return json.Marshal(sv.String())
}

// implements json.Unmarshaler
func (sv *SecretValidity) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}

	switch s {
	case SecretValidityValid.String():
		*sv = SecretValidityValid
		return nil
	case SecretValidityInvalid.String():
		*sv = SecretValidityInvalid
		return nil
	case SecretValidityUnknown.String():
		*sv = SecretValidityUnknown
		return nil
	default:
		return fmt.Errorf(
			"validity must be one of \"%s\", \"%s\" or \"%s\"",
			SecretValidityValid.String(),
			SecretValidityInvalid.String(),
			SecretValidityUnknown.String(),
		)
	}
}

// implements gocsv.TypeUnmarshaller
func (sv *SecretValidity) UnmarshalCSV(s string) error {
	switch s {
	case SecretValidityValid.String():
		*sv = SecretValidityValid
		return nil
	case SecretValidityInvalid.String():
		*sv = SecretValidityInvalid
		return nil
	case SecretValidityUnknown.String():
		*sv = SecretValidityUnknown
		return nil
	default:
		return fmt.Errorf(
			"validity must be one of \"%s\", \"%s\" or \"%s\"",
			SecretValidityValid.String(),
			SecretValidityInvalid.String(),
			SecretValidityUnknown.String(),
		)
	}
}

type SecretScanners int

const (
	SecretScannersAll SecretScanners = iota
	SecretScannersGitleaks
	SecretScannersTrufflehog
)

func (ss SecretScanners) String() string {
	switch ss {
	case SecretScannersAll:
		return "all"
	case SecretScannersGitleaks:
		return "gitleaks"
	case SecretScannersTrufflehog:
		return "trufflehog"
	default:
		// should never be reached
		return ""
	}
}

// implements json.Marshaler
func (ss SecretScanners) MarshalJSON() ([]byte, error) {
	return json.Marshal(ss.String())
}

// implements json.Unmarshaler
func (ss *SecretScanners) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}

	switch s {
	case SecretScannersAll.String():
		*ss = SecretScannersAll
		return nil
	case SecretScannersGitleaks.String():
		*ss = SecretScannersGitleaks
		return nil
	case SecretScannersTrufflehog.String():
		*ss = SecretScannersTrufflehog
		return nil
	default:
		return fmt.Errorf(
			"scanners must be one of \"%s\", \"%s\" or \"%s\"",
			SecretScannersAll.String(),
			SecretScannersGitleaks.String(),
			SecretScannersTrufflehog.String(),
		)
	}
}

// implements gocsv.TypeUnmarshaller
func (ss *SecretScanners) UnmarshalCSV(s string) error {
	switch s {
	case SecretScannersAll.String():
		*ss = SecretScannersAll
		return nil
	case SecretScannersGitleaks.String():
		*ss = SecretScannersGitleaks
		return nil
	case SecretScannersTrufflehog.String():
		*ss = SecretScannersTrufflehog
		return nil
	default:
		return fmt.Errorf(
			"scanners must be one of \"%s\", \"%s\" or \"%s\"",
			SecretScannersAll.String(),
			SecretScannersGitleaks.String(),
			SecretScannersTrufflehog.String(),
		)
	}
}

var ErrMergeSecretsNotEqual error = errors.New("not equal secrets cannot be merge")

type Secret struct {
	Repository  string         `csv:"repository" json:"repository"`
	Path        string         `csv:"path" json:"path"`
	Kind        SecretKind     `csv:"kind" json:"kind"`
	Commit      string         `csv:"commit" json:"commit"`
	Line        int            `csv:"line" json:"line"`
	Valid       SecretValidity `csv:"valid" json:"valid"`
	Scanners    SecretScanners `csv:"scanners" json:"scanners"`
	Cleartext   string         `csv:"cleartext" json:"cleartext"`
	Fingerprint string         `csv:"fingerprint" json:"fingerprint"`
}

func NewSecret(repository string, path string, kind SecretKind, commit string, line int, valid SecretValidity, scanners SecretScanners, cleartext string, fingerprint string) (*Secret, error) {
	if fingerprint == "" {
		fingerprint = fmt.Sprintf("%s:%s:%s:%d", repository, commit, path, line)
	}

	return &Secret{
		Repository:  repository,
		Path:        path,
		Kind:        kind,
		Commit:      commit,
		Line:        line,
		Valid:       valid,
		Scanners:    scanners,
		Cleartext:   cleartext,
		Fingerprint: fingerprint,
	}, nil
}

func (s Secret) IsEqual(other *Secret) bool {
	if other == nil {
		return false
	}
	return s.Fingerprint == other.Fingerprint && s.Identity() == other.Identity()
}

// CanonicalCleartext normalizes only representation differences that do not
// change the secret value (surrounding whitespace and a matching pair of
// quotes). The raw cleartext is kept in reports; the canonical form is only
// used to compute a stable identity.
func CanonicalCleartext(cleartext string) string {
	value := strings.TrimSpace(cleartext)
	if len(value) >= 2 {
		first := value[0]
		last := value[len(value)-1]
		if first == last && (first == '"' || first == '\'' || first == '`') {
			value = value[1 : len(value)-1]
		}
	}
	return value
}

// ValueDigest returns the SHA-256 digest of the canonical secret value. An
// empty cleartext has no digest: entries without a value stay compatible with
// the historical fingerprint-only behaviour.
func (s Secret) ValueDigest() string {
	if s.Cleartext == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(CanonicalCleartext(s.Cleartext)))
	return fmt.Sprintf("%x", sum)
}

// Identity returns a stable identifier for the secret, independent from its
// location (commit and line) in the repository. Two secrets with the same
// value in the same file share the same identity, even if the code around
// them moved. Secrets without a cleartext value fall back to their
// fingerprint to remain compatible with manually crafted entries.
func (s Secret) Identity() string {
	if s.Cleartext == "" {
		return s.Fingerprint
	}
	return fmt.Sprintf("%s:%s:%s", s.Repository, s.Path, s.ValueDigest())
}

func (s Secret) Merge(other *Secret) (*Secret, error) {
	if s.IsEqual(other) {
		kind := s.Kind
		if kind == SecretKindGeneric {
			kind = other.Kind
		}

		valid := s.Valid
		if valid == SecretValidityUnknown {
			valid = other.Valid
		}

		scanners := s.Scanners
		if scanners != SecretScannersAll && scanners != other.Scanners {
			scanners = SecretScannersAll
		}

		return &Secret{
			Repository:  s.Repository,
			Path:        s.Path,
			Kind:        kind,
			Commit:      s.Commit,
			Line:        s.Line,
			Valid:       valid,
			Scanners:    scanners,
			Cleartext:   s.Cleartext,
			Fingerprint: s.Fingerprint,
		}, nil
	} else {
		return nil, ErrMergeSecretsNotEqual
	}
}

// MergeIdentity merges two secrets that share the same stable identity (same
// value in the same file, e.g. reported at different lines). The location of
// the merged secret is the lowest line of the two, while kind, validity and
// scanner information are combined.
func (s Secret) MergeIdentity(other *Secret) *Secret {
	base := &s
	extra := other
	if other.Line < s.Line || (other.Line == s.Line && other.Fingerprint < s.Fingerprint) {
		base = other
		extra = &s
	}

	kind := base.Kind
	if kind == SecretKindGeneric {
		kind = extra.Kind
	}

	valid := base.Valid
	if valid == SecretValidityUnknown {
		valid = extra.Valid
	}

	scanners := base.Scanners
	if scanners != SecretScannersAll && scanners != extra.Scanners {
		scanners = SecretScannersAll
	}

	return &Secret{
		Repository:  base.Repository,
		Path:        base.Path,
		Kind:        kind,
		Commit:      base.Commit,
		Line:        base.Line,
		Valid:       valid,
		Scanners:    scanners,
		Cleartext:   base.Cleartext,
		Fingerprint: base.Fingerprint,
	}
}
