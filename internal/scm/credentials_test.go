package scm

import (
	"sync"
	"testing"
)

func TestCredentialRegistry(t *testing.T) {
	r := NewCredentialRegistry()

	g1 := r.Generation("faketoken-a")
	g2 := r.Generation("faketoken-b")
	g1again := r.Generation("faketoken-a")

	if g1 != g1again {
		t.Fatalf(`Generation("faketoken-a") = %d then %d, want a stable generation`, g1, g1again)
	}
	if g1 == g2 {
		t.Fatalf(`Generation("faketoken-a") = Generation("faketoken-b") = %d, want different generations`, g1)
	}
	if g1 != 1 || g2 != 2 {
		t.Fatalf(`generations = %d, %d, want 1, 2 (1-based and monotonic)`, g1, g2)
	}
}

func TestCredentialRegistryEmptyToken(t *testing.T) {
	r := NewCredentialRegistry()

	// anonymous access (empty token) is a valid credential and gets its own
	// generation
	if g := r.Generation(""); g != 1 {
		t.Fatalf(`Generation("") = %d, want 1`, g)
	}
	if g := r.Generation("faketoken"); g != 2 {
		t.Fatalf(`Generation("faketoken") = %d, want 2`, g)
	}
}

func TestCredentialRegistryConcurrent(t *testing.T) {
	r := NewCredentialRegistry()

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if g := r.Generation("faketoken"); g != 1 {
				t.Errorf(`Generation("faketoken") = %d, want 1`, g)
			}
		}()
	}
	wg.Wait()
}
