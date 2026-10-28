package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// TestEraseKeaLeasesForResetParity17171: regular lease erased, absent
// clean; the symlinked-lease refusal is asserted as the verbatim
// historic PLAIN message (no typed error survives, by design) and the
// hardlinked-lease refusal as the verbatim historic wording WITH the
// typed error, after routing through the shared primitive.
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
	t.Run("symlink refusal is a plain historic message, no typed error", func(t *testing.T) {
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
		// Explicit plain-message contract (#17171 fold F3): the Kea
		// symlink mapping is deliberately a bare fmt.Errorf with no
		// %w (exactly the historic pre-primitive spelling), so NO
		// FactoryResetSymlinkError type survives — assert that, plus
		// the verbatim historic sentence naming the lease.
		err := eraseKeaLeasesForReset()
		if err == nil {
			t.Fatal("symlinked Kea lease must fail the re-erase, got nil")
		}
		want := "factory reset: refusing to re-erase symlinked Kea lease file " + lease + ": link target is out of erase scope"
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("symlink refusal = %q, want verbatim historic %q", err, want)
		}
		var symErr *configstore.FactoryResetSymlinkError
		if errors.As(err, &symErr) {
			t.Fatalf("Kea symlink refusal must NOT wrap FactoryResetSymlinkError (plain historic message), got %v", err)
		}
		for _, p := range []string{lease, target} {
			if _, serr := os.Lstat(p); serr != nil {
				t.Fatalf("refusal must remove nothing, %s: %v", p, serr)
			}
		}
	})
	t.Run("hardlink refusal keeps historic Kea wording and typed error", func(t *testing.T) {
		isolateFactoryResetOwnershipPaths(t)
		isolateFactoryResetIdentityPaths(t)
		lease := resetKeaLeaseCurrents[0]
		if err := os.MkdirAll(filepath.Dir(lease), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(lease, []byte("address,hwaddr\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		sibling := filepath.Join(filepath.Dir(lease), "sibling.csv")
		if err := os.Link(lease, sibling); err != nil {
			t.Fatalf("hardlink plant: %v", err)
		}
		err := eraseKeaLeasesForReset()
		var linkErr *configstore.FactoryResetHardlinkError
		if !errors.As(err, &linkErr) {
			t.Fatalf("expected FactoryResetHardlinkError, got %v", err)
		}
		want := "factory reset: refusing to erase hard-linked Kea lease file " + lease + ": "
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("hardlink refusal = %q, want verbatim historic prefix %q", err, want)
		}
		for _, p := range []string{lease, sibling} {
			if _, serr := os.Lstat(p); serr != nil {
				t.Fatalf("refusal must remove nothing, %s: %v", p, serr)
			}
		}
	})
}
