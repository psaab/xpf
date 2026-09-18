package cli

// #5890: the interactive-console `request system zeroize` must run the FULL
// factory-reset wipe (config state + tls/ + rendered service configs + login
// accounts + archive), not the partial config-state-only wipe it used before.
// It does so by DELEGATING to grpcapi.PerformZeroizeWipe — the exact primitive
// the gRPC path runs — so the two paths cannot diverge and leave secret residue.
// The full secret-set erasure is proven in pkg/grpcapi (TestPerformZeroizeWipe
// ErasesFullSecretSet_5890, which the console's delegate calls); these tests pin
// the CONSOLE-side contract: it delegates, propagates a wipe failure fail-closed,
// and only stops the daemon once the wipe succeeded.

import (
	"errors"
	"path/filepath"
	"testing"
)

// consoleZeroizeStore builds a CLI whose store resolves a valid, non-shared
// configured root so zeroizeConfigRoot succeeds.
func consoleZeroizeStore(t *testing.T) *CLI {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "site.conf"))
	return &CLI{store: store}
}

// TestConsoleZeroizeDelegatesToFullWipe_5890 pins that the console runs the full
// shared wipe (not the retired partial config-state-only path) and stops the
// daemon only after it succeeds.
//
// FAIL-ON-REVERT: reverting the console to the old zeroizeConfigState-only wipe
// makes zeroizeFullWipe never fire — `wiped` stays false.
func TestConsoleZeroizeDelegatesToFullWipe_5890(t *testing.T) {
	c := consoleZeroizeStore(t)

	var wiped, stopped bool
	origWipe, origStop := zeroizeFullWipe, zeroizeStopDaemon
	t.Cleanup(func() { zeroizeFullWipe, zeroizeStopDaemon = origWipe, origStop })
	zeroizeFullWipe = func(string, string, string) error { wiped = true; return nil }
	zeroizeStopDaemon = func() error { stopped = true; return nil }

	if err := c.performConsoleZeroize(); err != nil {
		t.Fatalf("performConsoleZeroize: %v", err)
	}
	if !wiped {
		t.Fatal("console zeroize did NOT run the shared full-wipe primitive (regressed to a partial wipe?)")
	}
	if !stopped {
		t.Fatal("console zeroize did not stop the daemon after a successful wipe")
	}
}

// TestConsoleZeroizeFailClosedOnWipeError_5890 pins fail-closed behavior: a wipe
// error is surfaced to the operator, and the daemon is NOT stopped (a partial
// reset must not be silently completed by a reboot).
func TestConsoleZeroizeFailClosedOnWipeError_5890(t *testing.T) {
	c := consoleZeroizeStore(t)

	wipeErr := errors.New("tls wipe failed")
	var stopped bool
	origWipe, origStop := zeroizeFullWipe, zeroizeStopDaemon
	t.Cleanup(func() { zeroizeFullWipe, zeroizeStopDaemon = origWipe, origStop })
	zeroizeFullWipe = func(string, string, string) error { return wipeErr }
	zeroizeStopDaemon = func() error { stopped = true; return nil }

	err := c.performConsoleZeroize()
	if err == nil || !errors.Is(err, wipeErr) {
		t.Fatalf("console zeroize must surface the wipe failure (fail-closed), got %v", err)
	}
	if stopped {
		t.Fatal("console zeroize stopped the daemon despite an incomplete wipe (would reboot into a partial reset)")
	}
}

// TestConsoleZeroizeFailClosedWithoutConfigRoot_5890 pins that an undeterminable
// config root aborts the wipe BEFORE it runs (no store => zeroizeConfigRoot
// errors), so the console never wipes the wrong directory or reports success.
func TestConsoleZeroizeFailClosedWithoutConfigRoot_5890(t *testing.T) {
	c := &CLI{store: nil}
	var wiped bool
	origWipe, origStop := zeroizeFullWipe, zeroizeStopDaemon
	t.Cleanup(func() { zeroizeFullWipe, zeroizeStopDaemon = origWipe, origStop })
	zeroizeFullWipe = func(string, string, string) error { wiped = true; return nil }
	zeroizeStopDaemon = func() error { return nil }

	if err := c.performConsoleZeroize(); err == nil {
		t.Fatal("performConsoleZeroize with no store must fail closed; got nil error")
	}
	if wiped {
		t.Fatal("performConsoleZeroize ran the wipe despite an undeterminable config root")
	}
}
