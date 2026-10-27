package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEraseKeaLeasesForResetParity17171: regular lease erased, absent
// clean (symlink and hardlink are already pinned by the 10769 cells);
// the symlinked-lease error must still name the lease after routing
// through the shared primitive.
func TestEraseKeaLeasesForResetParity17171(t *testing.T) {
	t.Run("regular removed", func(t *testing.T) {
		isolateFactoryResetOwnershipPaths(t)
		isolateFactoryResetIdentityPaths(t)
		lease := resetKeaLeaseCurrents[0]
		if err := os.MkdirAll(filepath.Dir(lease), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(lease, []byte("address,hwaddr\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := eraseKeaLeasesForReset(); err != nil {
			t.Fatalf("regular lease erase: %v", err)
		}
		if _, err := os.Lstat(lease); !os.IsNotExist(err) {
			t.Fatalf("lease survived: %v", err)
		}
	})
	t.Run("absent is clean", func(t *testing.T) {
		isolateFactoryResetOwnershipPaths(t)
		isolateFactoryResetIdentityPaths(t)
		if err := eraseKeaLeasesForReset(); err != nil {
			t.Fatalf("absent erase must be nil, got %v", err)
		}
	})
	t.Run("symlink error types survive", func(t *testing.T) {
		isolateFactoryResetOwnershipPaths(t)
		isolateFactoryResetIdentityPaths(t)
		lease := resetKeaLeaseCurrents[0]
		if err := os.MkdirAll(filepath.Dir(lease), 0o700); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(filepath.Dir(lease), "real-leases.csv")
		if err := os.WriteFile(target, []byte("address,hwaddr\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, lease); err != nil {
			t.Fatal(err)
		}
		if err := eraseKeaLeasesForReset(); err == nil || !strings.Contains(err.Error(), "symlinked Kea lease") {
			t.Fatalf("expected symlinked Kea lease refusal, got %v", err)
		}
		for _, p := range []string{lease, target} {
			if _, serr := os.Lstat(p); serr != nil {
				t.Fatalf("refusal must remove nothing, %s: %v", p, serr)
			}
		}
	})
}
