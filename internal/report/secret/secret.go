package secret

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
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
	// Generation binds the finding to the scan run that produced it. It is
	// internal bookkeeping and is deliberately not part of the CSV or JSON
	// report schema.
	Generation string `csv:"-" json:"-"`
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
	if s.Fingerprint != other.Fingerprint {
		return false
	}
	// Findings from different scan generations never describe the same
	// occurrence, even when they share a fingerprint.
	if s.Generation != "" && other.Generation != "" && s.Generation != other.Generation {
		return false
	}
	return true
}

// Identity returns a stable identifier for the secret, independent from the
// location (commit and line) of a finding. Two findings that carry the same
// value in the same file share the same identity even when an engine reports
// them at different lines. Findings without a cleartext value fall back to
// their fingerprint so manually crafted entries keep working.
func (s Secret) Identity() string {
	if s.Cleartext == "" {
		return s.Fingerprint
	}
	sum := sha256.Sum256([]byte(s.Cleartext))
	return fmt.Sprintf("%s:%s:%x", s.Repository, s.Path, sum)
}

// WithGeneration returns a copy of the secret bound to the given scan
// generation.
func (s Secret) WithGeneration(generation string) *Secret {
	s.Generation = generation
	return &s
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

		generation := s.Generation
		if generation == "" {
			generation = other.Generation
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
			Generation:  generation,
		}, nil
	} else {
		return nil, ErrMergeSecretsNotEqual
	}
}

// MergeIdentity merges two findings that share the same stable identity (the
// same value in the same file, potentially reported at different lines). The
// representative finding is the one with the lowest line number, while kind,
// validity, scanner and generation information are combined.
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

	generation := base.Generation
	if generation == "" {
		generation = extra.Generation
	}

	cleartext := base.Cleartext
	if cleartext == "" {
		cleartext = extra.Cleartext
	}

	return &Secret{
		Repository:  base.Repository,
		Path:        base.Path,
		Kind:        kind,
		Commit:      base.Commit,
		Line:        base.Line,
		Valid:       valid,
		Scanners:    scanners,
		Cleartext:   cleartext,
		Fingerprint: base.Fingerprint,
		Generation:  generation,
	}
}
