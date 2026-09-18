package cli

// #5871: the interactive-console `request system zeroize` must run its wipe
// THROUGH the daemon's coordinated factory-reset transaction (factoryResetFn ->
// daemon.factoryReset, the SAME gate the gRPC ZeroizeFn path uses), not as an
// independent out-of-band wipe. The transaction acquires the daemon apply
// semaphore and enters the terminal reset generation BEFORE erasing, so no
// concurrent/subsequent commit / HA-sync / reconcile can re-create the
// just-erased .configdb SSOT or re-render the wiped secrets while the console
// reports a clean reset. #5890 already unified the WIPE primitive; these tests
// pin that the console runs it under the daemon's FENCING transaction and
// surfaces a transaction/removal failure fail-CLOSED.

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

// TestConsoleZeroizeRoutesThroughDaemonTransaction_5871 is the fail-on-revert
// pin for #5871: when the daemon has wired factoryResetFn, the console MUST run
// the wipe inside that coordinated transaction (the apply-gate + terminal reset
// generation), not call the wipe directly/ungated.
//
// FAIL-ON-REVERT: reverting performConsoleZeroize to call zeroizeFullWipe
// directly (the pre-#5871 ungated path) makes factoryResetFn never fire, so
// `enteredTransaction` stays false and the assertion goes RED.
func TestConsoleZeroizeRoutesThroughDaemonTransaction_5871(t *testing.T) {
	c := &CLI{store: newConfigStore(t, filepath.Join(t.TempDir(), "site.conf"))}

	var enteredTransaction, wipedAtAll, wipedInsideTransaction, stopped bool
	origWipe, origStop := zeroizeFullWipe, zeroizeStopDaemon
	t.Cleanup(func() { zeroizeFullWipe, zeroizeStopDaemon = origWipe, origStop })
	zeroizeFullWipe = func(string, string, string) error {
		wipedAtAll = true
		// Records that the wipe ran only AFTER the transaction was entered —
		// proving fencing (apply-gate + reset generation) precedes erasure.
		if enteredTransaction {
			wipedInsideTransaction = true
		}
		return nil
	}
	zeroizeStopDaemon = func() error { stopped = true; return nil }

	// Spy coordinated transaction: mirrors daemon.factoryReset's contract —
	// enters the gate, then runs the wipe closure while "held".
	c.factoryResetFn = func(_ context.Context, wipe func() error) error {
		enteredTransaction = true
		return wipe()
	}

	if err := c.performConsoleZeroize(); err != nil {
		t.Fatalf("performConsoleZeroize: %v", err)
	}
	if !enteredTransaction {
		t.Fatal("console zeroize did NOT route through the daemon's coordinated " +
			"factory-reset transaction (#5871): it ran the wipe ungated, bypassing " +
			"the apply-gate + terminal reset generation")
	}
	if !wipedAtAll {
		t.Fatal("console zeroize never ran the shared wipe primitive")
	}
	if !wipedInsideTransaction {
		t.Fatal("console zeroize ran the wipe OUTSIDE the coordinated transaction " +
			"(fencing not applied before erasure)")
	}
	if !stopped {
		t.Fatal("console zeroize did not stop the daemon after a successful reset")
	}
}

// TestConsoleZeroizeSurfacesTransactionFailure_5871 pins fail-CLOSED behavior
// through the transaction path: a factory-reset transaction FAILURE (e.g. the
// apply semaphore could not be acquired, or a rendered-config removal inside the
// wipe failed) must be SURFACED to the operator, never discarded, and the daemon
// must NOT be stopped (a half-reset box must stay recoverable rather than reboot
// into a partial, secret-retaining reset).
func TestConsoleZeroizeSurfacesTransactionFailure_5871(t *testing.T) {
	c := &CLI{store: newConfigStore(t, filepath.Join(t.TempDir(), "site.conf"))}

	// A removal failure inside the wipe, propagated by the transaction — the
	// exact "reconciler/removal FAILURE surfaced (not discarded)" contract.
	removalErr := errors.New("remove rendered frr.conf failed")
	var enteredTransaction, stopped bool
	origWipe, origStop := zeroizeFullWipe, zeroizeStopDaemon
	t.Cleanup(func() { zeroizeFullWipe, zeroizeStopDaemon = origWipe, origStop })
	zeroizeFullWipe = func(string, string, string) error { return removalErr }
	zeroizeStopDaemon = func() error { stopped = true; return nil }

	c.factoryResetFn = func(_ context.Context, wipe func() error) error {
		enteredTransaction = true
		// daemon.factoryReset propagates the wipe error (and exits the reset
		// generation) — the console must not swallow it.
		return wipe()
	}

	err := c.performConsoleZeroize()
	if !enteredTransaction {
		t.Fatal("console zeroize did not route through the coordinated transaction (#5871)")
	}
	if err == nil || !errors.Is(err, removalErr) {
		t.Fatalf("console zeroize must surface a removal/transaction failure "+
			"fail-closed (not discard it), got %v", err)
	}
	if stopped {
		t.Fatal("console zeroize stopped the daemon despite an incomplete reset " +
			"(would reboot into a partial, secret-retaining state)")
	}
}

// TestConsoleZeroizeSurfacesGateAcquireFailure_5871 pins that a transaction that
// fails BEFORE the wipe (e.g. the apply-gate acquire is cancelled, or a factory
// reset is already in progress) is surfaced fail-CLOSED and never runs the wipe
// or stops the daemon.
func TestConsoleZeroizeSurfacesGateAcquireFailure_5871(t *testing.T) {
	c := &CLI{store: newConfigStore(t, filepath.Join(t.TempDir(), "site.conf"))}

	gateErr := errors.New("apply gate: context canceled")
	var wiped, stopped bool
	origWipe, origStop := zeroizeFullWipe, zeroizeStopDaemon
	t.Cleanup(func() { zeroizeFullWipe, zeroizeStopDaemon = origWipe, origStop })
	zeroizeFullWipe = func(string, string, string) error { wiped = true; return nil }
	zeroizeStopDaemon = func() error { stopped = true; return nil }

	// The transaction fails to enter the gate and never invokes the wipe closure.
	c.factoryResetFn = func(context.Context, func() error) error { return gateErr }

	err := c.performConsoleZeroize()
	if err == nil || !errors.Is(err, gateErr) {
		t.Fatalf("console zeroize must surface an apply-gate acquire failure "+
			"fail-closed, got %v", err)
	}
	if wiped {
		t.Fatal("console zeroize ran the wipe even though the transaction never entered the gate")
	}
	if stopped {
		t.Fatal("console zeroize stopped the daemon despite a failed transaction")
	}
}

// TestConsoleZeroizeOfflineFallbackUngatedWipe_5871 pins the explicit
// offline-recovery fallback: a CLI spawned OUTSIDE the daemon has no
// factoryResetFn wired, so performConsoleZeroize runs the shared wipe directly
// (no reconcile loop is running to race) and still surfaces failures / stops the
// daemon on success. This documents the reduced-guarantee path is deliberate,
// not a silent partial best-effort.
func TestConsoleZeroizeOfflineFallbackUngatedWipe_5871(t *testing.T) {
	c := &CLI{store: newConfigStore(t, filepath.Join(t.TempDir(), "site.conf"))}
	// factoryResetFn deliberately left nil (no daemon).

	var wiped, stopped bool
	origWipe, origStop := zeroizeFullWipe, zeroizeStopDaemon
	t.Cleanup(func() { zeroizeFullWipe, zeroizeStopDaemon = origWipe, origStop })
	zeroizeFullWipe = func(string, string, string) error { wiped = true; return nil }
	zeroizeStopDaemon = func() error { stopped = true; return nil }

	if err := c.performConsoleZeroize(); err != nil {
		t.Fatalf("performConsoleZeroize (offline fallback): %v", err)
	}
	if !wiped {
		t.Fatal("offline-fallback console zeroize did not run the shared wipe primitive")
	}
	if !stopped {
		t.Fatal("offline-fallback console zeroize did not stop the daemon after success")
	}
}
