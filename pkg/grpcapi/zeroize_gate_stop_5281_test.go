package grpcapi

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// TestZeroizeGoesThroughGateAndStopsDaemon pins the #5281 contract at the RPC
// boundary: a gRPC `zeroize` SystemAction must (a) run the wipe THROUGH the
// daemon apply gate (Config.ZeroizeFn / s.zeroizeFn), not call performZeroizeWipe
// directly, and (b) STOP xpfd after a fully-successful wipe (scheduleStopDaemon)
// so the daemon does not keep running with the pre-wipe in-memory config and
// re-render the erased secrets.
//
// The destructive side effects are stubbed via the package seams, so the test
// drives the real SystemAction dispatch without touching disk or a real daemon.
//
// RED on revert: restoring the pre-#5281 handler (which called
// performZeroizeWipe directly and never stopped xpfd) makes gateUsed stay false
// (the gate is bypassed) AND stopped stay false (no stop scheduled), so this
// test fails.
func TestZeroizeGoesThroughGateAndStopsDaemon(t *testing.T) {
	origWipe := performZeroizeWipeWithLogInventory
	origStop := scheduleStopDaemon
	t.Cleanup(func() {
		performZeroizeWipeWithLogInventory = origWipe
		scheduleStopDaemon = origStop
	})

	// seq records the ORDER of the observable steps so the test proves the
	// sequence is gate → wipe → stop (never stop-before-wipe, never a bypassed
	// gate).
	var seq []string
	performZeroizeWipeWithLogInventory = func(_, _, _ string, _ ZeroizeLogInventory, _ zeroizeCompletion) error {
		seq = append(seq, "wipe")
		return nil
	}
	scheduleStopDaemon = func() { seq = append(seq, "stop") }

	var gateWipeArg func() error
	dir := t.TempDir()
	store := newConfigStore(t, filepath.Join(dir, "xpf.conf"))
	s := &Server{
		store: store,
		// The gate fake records that the handler routed through it, captures the
		// wipe closure the handler passed (which must, when run, invoke
		// performZeroizeWipe), and runs it — exactly as the real daemon
		// factoryReset does under applySem.
		zeroizeFn: func(_ context.Context, wipe func() error) error {
			seq = append(seq, "gate")
			gateWipeArg = wipe
			return wipe()
		},
	}

	resp, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "zeroize"})
	if err != nil {
		t.Fatalf("SystemAction(zeroize): %v", err)
	}
	if resp == nil || resp.Message == "" {
		t.Fatalf("SystemAction(zeroize) returned empty response: %+v", resp)
	}

	// The wipe ran through the gate (not directly): the handler passed a wipe
	// closure into ZeroizeFn. Since #5280 the handler wraps performZeroizeWipe in
	// a closure that binds the CONFIGURED config root, so we no longer assert
	// pointer identity — the "wipe" entry in seq below proves the gate's closure
	// invoked performZeroizeWipe.
	if gateWipeArg == nil {
		t.Fatal("zeroize did not route the wipe through the apply gate (ZeroizeFn)")
	}

	// Exact sequence: gate first, wipe under it, daemon stop last.
	if want := []string{"gate", "wipe", "stop"}; !reflect.DeepEqual(seq, want) {
		t.Fatalf("zeroize step sequence = %v, want %v", seq, want)
	}
}

// TestZeroizeFailClosedDoesNotStopDaemon pins the fail-closed half of #5281: if
// the wipe does not fully complete, the handler must surface the error AND must
// NOT stop xpfd (stopping a half-wiped box would strand prior-tenant secrets on
// disk while the daemon is down).
func TestZeroizeFailClosedDoesNotStopDaemon(t *testing.T) {
	origWipe := performZeroizeWipeWithLogInventory
	origStop := scheduleStopDaemon
	t.Cleanup(func() {
		performZeroizeWipeWithLogInventory = origWipe
		scheduleStopDaemon = origStop
	})

	wantErr := errors.New("configdb not fully erased")
	performZeroizeWipeWithLogInventory = func(_, _, _ string, _ ZeroizeLogInventory, _ zeroizeCompletion) error {
		return wantErr
	}
	var stopped bool
	scheduleStopDaemon = func() { stopped = true }

	var gateUsed bool
	dir := t.TempDir()
	store := newConfigStore(t, filepath.Join(dir, "xpf.conf"))
	s := &Server{
		store: store,
		zeroizeFn: func(_ context.Context, wipe func() error) error {
			gateUsed = true
			return wipe()
		},
	}

	resp, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "zeroize"})
	if err == nil {
		t.Fatalf("SystemAction(zeroize) with a failed wipe must return an error; got resp=%+v", resp)
	}
	if !gateUsed {
		t.Fatal("zeroize must still route through the apply gate on the failure path")
	}
	if stopped {
		t.Fatal("zeroize must NOT stop the daemon when the wipe did not complete (fail-closed)")
	}
}

// TestZeroizeFallsBackToDirectWipeWithoutGate pins the NoDataplane / no-daemon
// fallback: with ZeroizeFn unset, the handler still wipes (via performZeroizeWipe
// directly) and still stops the daemon — the pre-#5281 behavior, preserved for a
// build with no running reconcile loop to race.
func TestZeroizeFallsBackToDirectWipeWithoutGate(t *testing.T) {
	origWipe := performZeroizeWipeWithLogInventory
	origStop := scheduleStopDaemon
	t.Cleanup(func() {
		performZeroizeWipeWithLogInventory = origWipe
		scheduleStopDaemon = origStop
	})

	var wiped, stopped bool
	performZeroizeWipeWithLogInventory = func(_, _, _ string, _ ZeroizeLogInventory, _ zeroizeCompletion) error {
		wiped = true
		return nil
	}
	scheduleStopDaemon = func() { stopped = true }

	dir := t.TempDir()
	store := newConfigStore(t, filepath.Join(dir, "xpf.conf"))
	s := &Server{store: store} // zeroizeFn nil

	if _, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "zeroize"}); err != nil {
		t.Fatalf("SystemAction(zeroize) fallback: %v", err)
	}
	if !wiped {
		t.Fatal("zeroize fallback must still run performZeroizeWipe")
	}
	if !stopped {
		t.Fatal("zeroize fallback must still stop the daemon")
	}
}

// RED on revert: a gated wipe that records clean instead of pending lets a
// crash before daemon post-verification open N+1 provisioning over
// unverified residue. The gated path must record PENDING (with the helper
// path) and leave the clean flip to the daemon.
func TestGatedZeroizeWipeRecordsPending10769(t *testing.T) {
	root := t.TempDir()
	hermeticWipe10100(t, root)
	configDir := filepath.Join(root, "etc-xpf")
	mustWriteFile(t, filepath.Join(configDir, ".configdb", "master.key"), []byte("key"))
	mustWriteFile(t, filepath.Join(configDir, ".configdb", "active.json"), []byte("{}"))
	mustWriteFile(t, filepath.Join(configDir, "xpf.conf"), []byte("system { host-name fw; }\n"))
	store := newConfigStore(t, filepath.Join(configDir, "xpf.conf"))
	origStop := scheduleStopDaemon
	t.Cleanup(func() { scheduleStopDaemon = origStop })
	scheduleStopDaemon = func() {}
	s := &Server{
		store: store,
		zeroizeFn: func(_ context.Context, wipe func() error) error {
			return wipe()
		},
	}
	if _, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "zeroize"}); err != nil {
		t.Fatalf("SystemAction(zeroize): %v", err)
	}
	_, dirty, helperPath, present, err := configstore.ReadResetHandoff()
	if err != nil || !present || dirty != configstore.ResetHandoffPending {
		t.Fatalf("gated wipe must record pending: dirty=%q present=%v err=%v", dirty, present, err)
	}
	if helperPath == "" {
		t.Fatal("gated wipe must record the pre-wipe helper path")
	}
}

// RED on revert: snapshotting the helper path before the apply gate lets a
// commit delayed at the gate move the state file first, recording a stale
// path the boot repair then sweeps instead of the residue.
func TestGatedZeroizeSnapshotsHelperPathInsideGate10769(t *testing.T) {
	origWipe := performZeroizeWipeWithLogInventory
	origStop := scheduleStopDaemon
	t.Cleanup(func() {
		performZeroizeWipeWithLogInventory = origWipe
		scheduleStopDaemon = origStop
	})
	var got zeroizeCompletion
	performZeroizeWipeWithLogInventory = func(_, _, _ string, _ ZeroizeLogInventory, c zeroizeCompletion) error {
		got = c
		return nil
	}
	scheduleStopDaemon = func() {}
	dir := t.TempDir()
	store := newConfigStore(t, filepath.Join(dir, "xpf.conf"))
	commitStateFile := func(path string) {
		t.Helper()
		if err := store.EnterConfigure(); err != nil {
			t.Fatal(err)
		}
		set := "set system dataplane-type userspace\n" +
			"set system dataplane state-file " + path + "\n"
		if _, err := store.LoadSet(set); err != nil {
			t.Fatalf("LoadSet: %v", err)
		}
		if _, err := store.Commit(); err != nil {
			t.Fatalf("Commit: %v", err)
		}
		store.ExitConfigure()
	}
	pathA := filepath.Join(dir, "a", "userspace-dp.json")
	pathB := filepath.Join(dir, "b", "userspace-dp.json")
	commitStateFile(pathA)
	s := &Server{
		store: store,
		zeroizeFn: func(_ context.Context, wipe func() error) error {
			// Model the commit delayed at the gate: it lands after
			// runZeroize's entry but before the wipe runs inside it.
			commitStateFile(pathB)
			return wipe()
		},
	}
	if _, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "zeroize"}); err != nil {
		t.Fatalf("SystemAction(zeroize): %v", err)
	}
	if !got.pending || got.helperPath != pathB {
		t.Fatalf("pending completion = %+v, want pending with helper path %q", got, pathB)
	}
}

func commitHelperPaths(t *testing.T, store *configstore.Store, sets ...string) {
	t.Helper()
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	for _, set := range sets {
		if _, err := store.LoadSet(set); err != nil {
			t.Fatalf("LoadSet: %v", err)
		}
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	store.ExitConfigure()
}

// The ungated (no-daemon) fallback resolves the effective helper path —
// including the derived sibling dragged out of /run/xpf by a custom
// control-socket — erases it in-wipe, and records it on the clean flag.
// Without this, a custom path survives while boot repair re-derives the
// default and clears post-reboot.
func TestUngatedFallbackErasesDerivedHelperState10769(t *testing.T) {
	root := t.TempDir()
	hermeticWipe10100(t, root)
	configDir := filepath.Join(root, "etc-xpf")
	mustWriteFile(t, filepath.Join(configDir, ".configdb", "master.key"), []byte("key"))
	mustWriteFile(t, filepath.Join(configDir, ".configdb", "active.json"), []byte("{}"))
	mustWriteFile(t, filepath.Join(configDir, "xpf.conf"), []byte("system { host-name fw; }\n"))
	store := newConfigStore(t, filepath.Join(configDir, "xpf.conf"))
	commitHelperPaths(t, store,
		"set system dataplane-type userspace",
		"set system dataplane control-socket "+filepath.Join(root, "custom-xpf", "control.sock"))
	derived := dpuserspace.StateFilePathForConfig(store.ActiveConfig())
	if derived == dpuserspace.StateFilePathForConfig(nil) {
		t.Fatal("fixture must derive a non-default state path from the custom socket")
	}
	mustWriteFile(t, derived, []byte(`{"flows":["prior"]}`))
	mustWriteFile(t, derived+".4250000000.1.tmp", []byte(`{"flows":["prior-temp"]}`))
	origStop := scheduleStopDaemon
	t.Cleanup(func() { scheduleStopDaemon = origStop })
	scheduleStopDaemon = func() {}
	s := &Server{store: store}
	if _, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "zeroize"}); err != nil {
		t.Fatalf("SystemAction(zeroize): %v", err)
	}
	for _, path := range []string{derived, derived + ".4250000000.1.tmp"} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Errorf("derived helper residue %s survived the ungated wipe: %v", path, err)
		}
	}
	_, dirty, gotPath, present, err := configstore.ReadResetHandoff()
	if err != nil || !present || dirty != "" || gotPath != derived {
		t.Fatalf("ungated handoff = dirty %q path %q present %v err %v, want clean with the derived path", dirty, gotPath, present, err)
	}
}
