package cli

import (
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// TestCLIZeroizeResolvesConfiguredRoot pins #5554: the interactive-CLI
// `request system zeroize` path must resolve the wipe target from the daemon's
// ACTUAL configured config root — the directory + base name of the store's
// `-config` path (configstore.Store.ConfigPath) — NOT a hardcoded /etc/xpf.
// This is the local-CLI twin of the gRPC fix (#5280): when xpfd runs with a
// non-default `-config` (e.g. /srv/xpf/site.conf), the .configdb SSOT +
// master.key, rollback slots and journal live under THAT root; resolving to a
// hardcoded /etc/xpf would leave the prior tenant's secrets on disk.
//
// RED on revert: restoring `configDir := "/etc/xpf"` (and the "xpf.conf" base)
// makes zeroizeConfigRoot return /etc/xpf + xpf.conf instead of the store's
// temp root — so the gotDir/gotBase assertions (and the explicit /etc/xpf
// guard) fail.
func TestCLIZeroizeResolvesConfiguredRoot(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "site.conf")
	store := newConfigStore(t, configPath)
	c := &CLI{store: store}

	gotDir, gotBase, err := c.zeroizeConfigRoot()
	if err != nil {
		t.Fatalf("zeroizeConfigRoot: unexpected error %v", err)
	}
	if gotDir != dir {
		t.Fatalf("zeroize resolved configDir %q, want the CONFIGURED root %q (not hardcoded /etc/xpf)", gotDir, dir)
	}
	if gotBase != "site.conf" {
		t.Fatalf("zeroize resolved configBase %q, want the CONFIGURED base %q", gotBase, "site.conf")
	}
	// Explicit revert-shape guard: a hardcoded wipe would resolve /etc/xpf.
	if gotDir == "/etc/xpf" {
		t.Fatalf("zeroize resolved the hardcoded default /etc/xpf instead of the configured root %q", dir)
	}
}

// TestCLIZeroizeFailsClosedWithoutConfigRoot pins the fail-CLOSED half of
// #5554: if the configured config root cannot be determined (no store, or a
// store with an empty config path), the CLI zeroize must NOT silently wipe the
// wrong path or nothing — it must surface an error so the operator knows the
// device is not safe to re-tenant.
func TestCLIZeroizeFailsClosedWithoutConfigRoot(t *testing.T) {
	// No store => config root undeterminable.
	c := &CLI{store: nil}
	if _, _, err := c.zeroizeConfigRoot(); err == nil {
		t.Fatal("zeroizeConfigRoot with no store must fail closed; got nil error")
	}

	// A store with an empty config path is equally undeterminable.
	c = &CLI{store: &configstore.Store{}}
	if _, _, err := c.zeroizeConfigRoot(); err == nil {
		t.Fatal("zeroizeConfigRoot with an empty config path must fail closed; got nil error")
	}
}

// TestCLIZeroizeWipesConfiguredRootNotHardcoded drives the full CLI console
// factory-reset path (performConsoleZeroize) against a NON-default configured
// root and asserts the CONFIGURED root — not a hardcoded /etc/xpf — is handed to
// the shared full-wipe primitive. It is the console-path revert guard for #5554:
// with the hardcoded `configDir := "/etc/xpf"` restored, the wipe would receive
// /etc/xpf and the temp root's secrets would survive. The wipe primitive itself
// is seamed to a spy so the test stays hermetic (no real /etc); the full
// secret-set erasure is proven in pkg/grpcapi (#5890).
func TestCLIZeroizeWipesConfiguredRootNotHardcoded(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "site.conf")
	store := newConfigStore(t, configPath)

	var gotDir, gotBase string
	var called bool
	origWipe, origStop := zeroizeFullWipe, zeroizeStopDaemon
	t.Cleanup(func() { zeroizeFullWipe, zeroizeStopDaemon = origWipe, origStop })
	zeroizeFullWipe = func(configDir, configBase, _ string) error {
		called = true
		gotDir, gotBase = configDir, configBase
		return nil
	}
	zeroizeStopDaemon = func() error { return nil }

	c := &CLI{store: store}
	if err := c.performConsoleZeroize(); err != nil {
		t.Fatalf("performConsoleZeroize: %v", err)
	}

	if !called {
		t.Fatal("console zeroize did not invoke the shared full-wipe primitive")
	}
	if gotDir != dir {
		t.Fatalf("console zeroize wiped configDir %q, want the CONFIGURED root %q (not hardcoded /etc/xpf)", gotDir, dir)
	}
	if gotBase != "site.conf" {
		t.Fatalf("console zeroize wiped configBase %q, want %q", gotBase, "site.conf")
	}
	if gotDir == "/etc/xpf" {
		t.Fatalf("console zeroize resolved the hardcoded default /etc/xpf instead of %q", dir)
	}
}
