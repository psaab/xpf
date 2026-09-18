package grpcapi

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"

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
	origWipe := performZeroizeWipe
	origStop := scheduleStopDaemon
	t.Cleanup(func() {
		performZeroizeWipe = origWipe
		scheduleStopDaemon = origStop
	})

	// seq records the ORDER of the observable steps so the test proves the
	// sequence is gate → wipe → stop (never stop-before-wipe, never a bypassed
	// gate).
	var seq []string
	performZeroizeWipe = func(_, _, _ string) error { seq = append(seq, "wipe"); return nil }
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
	origWipe := performZeroizeWipe
	origStop := scheduleStopDaemon
	t.Cleanup(func() {
		performZeroizeWipe = origWipe
		scheduleStopDaemon = origStop
	})

	wantErr := errors.New("configdb not fully erased")
	performZeroizeWipe = func(_, _, _ string) error { return wantErr }
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
	origWipe := performZeroizeWipe
	origStop := scheduleStopDaemon
	t.Cleanup(func() {
		performZeroizeWipe = origWipe
		scheduleStopDaemon = origStop
	})

	var wiped, stopped bool
	performZeroizeWipe = func(_, _, _ string) error { wiped = true; return nil }
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
