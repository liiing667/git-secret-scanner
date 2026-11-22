package git

import "testing"

func TestFingerprintCredential(t *testing.T) {
	fp1 := FingerprintCredential("faketoken-a")
	fp2 := FingerprintCredential("faketoken-a")
	fp3 := FingerprintCredential("faketoken-b")

	if fp1 != fp2 {
		t.Fatalf(`FingerprintCredential("faketoken-a") is not stable: %q != %q`, fp1, fp2)
	}
	if fp1 == fp3 {
		t.Fatalf(`FingerprintCredential("faketoken-a") = FingerprintCredential("faketoken-b") = %q, want different fingerprints`, fp1)
	}
	if fp1 == "faketoken-a" {
		t.Fatalf(`FingerprintCredential("faketoken-a") = %q, credential must not be stored in clear`, fp1)
	}
	if len(fp1) != 64 {
		t.Fatalf(`FingerprintCredential("faketoken-a") = %q, want a 64 characters SHA-256 hex digest`, fp1)
	}
}
