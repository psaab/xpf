package grpcapi

import (
	"context"
	"path/filepath"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestZeroizeTargetsConfiguredRootNotHardcoded pins #5280: a gRPC `zeroize`
// SystemAction must erase the daemon's ACTUAL configured config root — the
// directory + base name of the store's `-config` path
// (configstore.Store.ConfigPath) — NOT a hardcoded /etc/xpf. When xpfd is
// started with a non-default `-config` (e.g. /srv/xpf/site.conf), the .configdb
// SSOT + master.key, rollback slots and journal live under THAT root; wiping
// /etc/xpf instead would report a clean factory reset while the prior tenant's
// secrets survive under the real root.
//
// The store here is pointed at a NON-default root (a temp dir with base
// "site.conf"), and the destructive wipe primitive is stubbed so the test
// observes exactly which (configDir, configBase) the handler threads into it.
//
// RED on revert: restoring performZeroizeWipe to call
// zeroizeConfigDir(defaultConfigDir, defaultConfigBase) (or making runZeroize
// pass the hardcoded default) makes the handler wipe /etc/xpf — gotDir becomes
// defaultConfigDir instead of the store's temp root — so the gotDir/gotBase
// assertions (and the explicit defaultConfigDir guard) fail.
func TestZeroizeTargetsConfiguredRootNotHardcoded(t *testing.T) {
	origWipe := performZeroizeWipe
	origStop := scheduleStopDaemon
	t.Cleanup(func() {
		performZeroizeWipe = origWipe
		scheduleStopDaemon = origStop
	})

	var gotDir, gotBase string
	var called bool
	performZeroizeWipe = func(configDir, configBase, _ string) error {
		called = true
		gotDir, gotBase = configDir, configBase
		return nil
	}
	scheduleStopDaemon = func() {}

	// A configured root deliberately different from the hardcoded /etc/xpf
	// default: a temp dir (never /etc/xpf) with a non-default config base name.
	dir := t.TempDir()
	configPath := filepath.Join(dir, "site.conf")
	store := newConfigStore(t, configPath)
	s := &Server{store: store}

	if _, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "zeroize"}); err != nil {
		t.Fatalf("SystemAction(zeroize): %v", err)
	}
	if !called {
		t.Fatal("zeroize never invoked performZeroizeWipe")
	}
	if gotDir != dir {
		t.Fatalf("zeroize wiped configDir %q, want the CONFIGURED root %q (not hardcoded /etc/xpf)", gotDir, dir)
	}
	if gotBase != "site.conf" {
		t.Fatalf("zeroize wiped configBase %q, want the CONFIGURED base %q", gotBase, "site.conf")
	}
	// Explicit revert-shape guard: a hardcoded wipe would pass defaultConfigDir.
	if gotDir == defaultConfigDir {
		t.Fatalf("zeroize wiped the hardcoded default %q instead of the configured root %q", defaultConfigDir, dir)
	}
}

// TestZeroizeFailsClosedWithoutConfigRoot pins the fail-CLOSED half of #5280: if
// the configured config root cannot be determined (no store / empty config
// path), the handler must NOT silently wipe the wrong path or nothing — it must
// surface an error so the operator knows the device is not safe to re-tenant.
//
// A bare Server with a nil store cannot resolve ConfigPath, so runZeroize must
// return an error BEFORE ever invoking performZeroizeWipe or scheduling a stop.
func TestZeroizeFailsClosedWithoutConfigRoot(t *testing.T) {
	origWipe := performZeroizeWipe
	origStop := scheduleStopDaemon
	t.Cleanup(func() {
		performZeroizeWipe = origWipe
		scheduleStopDaemon = origStop
	})

	var wiped, stopped bool
	performZeroizeWipe = func(_, _, _ string) error { wiped = true; return nil }
	scheduleStopDaemon = func() { stopped = true }

	s := &Server{} // no store => config root undeterminable

	resp, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "zeroize"})
	if err == nil {
		t.Fatalf("SystemAction(zeroize) with no config root must fail closed; got resp=%+v", resp)
	}
	if status.Code(err) != codes.Internal {
		t.Errorf("SystemAction(zeroize) fail-closed error code = %v, want Internal", status.Code(err))
	}
	if wiped {
		t.Error("zeroize must NOT wipe when the configured root is undeterminable (fail-closed)")
	}
	if stopped {
		t.Error("zeroize must NOT stop the daemon when it fails closed")
	}
}
