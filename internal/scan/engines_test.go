package scan

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/padok-team/git-secret-scanner/internal/report/secret"
)

func TestConcurrentEngineSetNormalize(t *testing.T) {
	tests := []struct {
		name    string
		input   EngineSet
		want    EngineSet
		wantErr bool
	}{
		{
			name:  "empty means all",
			input: nil,
			want:  AllEngines(),
		},
		{
			name:  "single engine",
			input: EngineSet{EngineGitleaks},
			want:  EngineSet{EngineGitleaks},
		},
		{
			name:  "duplicates are removed",
			input: EngineSet{EngineTrufflehog, EngineTrufflehog, EngineGitleaks},
			want:  AllEngines(),
		},
		{
			name:  "all expands",
			input: EngineSet{EngineAll},
			want:  AllEngines(),
		},
		{
			name:    "unknown engine",
			input:   EngineSet{Engine("unknown")},
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := test.input.Normalize()
			if (err != nil) != test.wantErr {
				t.Fatalf("Normalize() error = %v, wantErr %t", err, test.wantErr)
			}
			if test.wantErr {
				return
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("Normalize() = %v, want %v", got, test.want)
			}
		})
	}
}

func newConcurrentEngineTestFinding(repository string, path string, line int, scanners secret.SecretScanners, cleartext string) *secret.Secret {
	finding, _ := secret.NewSecret(
		repository,
		path,
		secret.SecretKindGeneric,
		"commit",
		line,
		secret.SecretValidityUnknown,
		scanners,
		cleartext,
		"",
	)
	return finding
}

func TestConcurrentEngineRetriesAndDeduplicates(t *testing.T) {
	const generation = "generation-1"
	repository := "owner/repo"
	directory := t.TempDir()

	trufflehogCalls := 0
	var lock sync.Mutex

	scanner := NewRepositoryScanner(repository, directory, EngineSet{EngineGitleaks, EngineTrufflehog})
	scanner.Generation = generation
	scanner.MaxAttempts = 3
	scanner.RetryBackoff = time.Millisecond
	scanner.Scans = map[Engine]EngineScanFunc{
		EngineGitleaks: func(ctx context.Context, repository string, directory string, full bool) (secret.SecretSet, error) {
			set := secret.NewSet()
			set.Add(newConcurrentEngineTestFinding(repository, "config.yml", 10, secret.SecretScannersGitleaks, "shared-secret"))
			set.Add(newConcurrentEngineTestFinding(repository, "config.yml", 11, secret.SecretScannersGitleaks, "gitleaks-only"))
			return set, nil
		},
		EngineTrufflehog: func(ctx context.Context, repository string, directory string, full bool) (secret.SecretSet, error) {
			lock.Lock()
			trufflehogCalls++
			attempt := trufflehogCalls
			lock.Unlock()

			if attempt == 1 {
				// The first attempt produces a partial result and then fails.
				set := secret.NewSet()
				set.Add(newConcurrentEngineTestFinding(repository, "config.yml", 99, secret.SecretScannersTrufflehog, "partial-secret"))
				return set, errors.New("transient failure")
			}

			set := secret.NewSet()
			set.Add(newConcurrentEngineTestFinding(repository, "config.yml", 10, secret.SecretScannersTrufflehog, "shared-secret"))
			set.Add(newConcurrentEngineTestFinding(repository, "config.yml", 20, secret.SecretScannersTrufflehog, "trufflehog-only"))
			return set, nil
		},
	}

	findings, err := scanner.Scan(context.Background(), true)
	if err != nil {
		t.Fatalf("Scan() error = %v, want nil", err)
	}

	lock.Lock()
	calls := trufflehogCalls
	lock.Unlock()
	if calls != 2 {
		t.Fatalf("trufflehog calls = %d, want 2", calls)
	}

	if findings.Length() != 3 {
		t.Fatalf("findings.Length() = %d, want 3: %v", findings.Length(), findings)
	}

	shared := findings["owner/repo:commit:config.yml:10"]
	if shared == nil {
		t.Fatalf("shared finding is missing: %v", findings)
	}
	if shared.Scanners != secret.SecretScannersAll {
		t.Fatalf("shared finding scanners = %v, want all", shared.Scanners)
	}
	if shared.Generation != generation {
		t.Fatalf("shared finding generation = %q, want %q", shared.Generation, generation)
	}

	for _, finding := range findings {
		if finding.Cleartext == "partial-secret" {
			t.Fatalf("partial result of the failed attempt leaked into findings: %v", findings)
		}
	}
}

func TestConcurrentEnginePermanentFailureDiscardsGeneration(t *testing.T) {
	repository := "owner/repo"
	directory := t.TempDir()

	scanner := NewRepositoryScanner(repository, directory, AllEngines())
	scanner.MaxAttempts = 2
	scanner.RetryBackoff = time.Millisecond
	scanner.Scans = map[Engine]EngineScanFunc{
		EngineGitleaks: func(ctx context.Context, repository string, directory string, full bool) (secret.SecretSet, error) {
			set := secret.NewSet()
			set.Add(newConcurrentEngineTestFinding(repository, "config.yml", 10, secret.SecretScannersGitleaks, "gitleaks-secret"))
			return set, nil
		},
		EngineTrufflehog: func(ctx context.Context, repository string, directory string, full bool) (secret.SecretSet, error) {
			return nil, errors.New("permanent failure")
		},
	}

	findings, err := scanner.Scan(context.Background(), true)
	if err == nil {
		t.Fatalf("Scan() error = nil, want an engine failure")
	}
	if !strings.Contains(err.Error(), "trufflehog scan failed for repository") {
		t.Fatalf("Scan() error = %q, want trufflehog failure", err)
	}
	if findings != nil {
		t.Fatalf("Scan() findings = %v, want nil on incomplete generation", findings)
	}
}

func TestConcurrentEngineSingleEngineCompatibility(t *testing.T) {
	repository := "owner/repo"
	directory := t.TempDir()

	scanner := NewRepositoryScanner(repository, directory, EngineSet{EngineGitleaks})
	scanner.Scans = map[Engine]EngineScanFunc{
		EngineGitleaks: func(ctx context.Context, repository string, directory string, full bool) (secret.SecretSet, error) {
			set := secret.NewSet()
			set.Add(newConcurrentEngineTestFinding(repository, "config.yml", 10, secret.SecretScannersGitleaks, "gitleaks-secret"))
			return set, nil
		},
	}

	findings, err := scanner.Scan(context.Background(), true)
	if err != nil {
		t.Fatalf("Scan() error = %v, want nil", err)
	}
	if findings.Length() != 1 {
		t.Fatalf("findings.Length() = %d, want 1", findings.Length())
	}
	for _, finding := range findings {
		if finding.Scanners != secret.SecretScannersGitleaks {
			t.Fatalf("finding scanners = %v, want gitleaks", finding.Scanners)
		}
	}
}
