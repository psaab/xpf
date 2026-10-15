package main

import (
	"context"
	"reflect"
	"testing"
	"time"
)

// TestNewKernelConfig_WiresGate4DataplaneProbe_6607 proves the PRODUCTION
// kernel-channel construction site actually wires Gate 4's dataplane-liveness
// probe.
//
// This is the wiring half of #6607 and it is not redundant with the pkg/upgrade
// tests: those drive realKernelSystem.ForwardBeacon with a HelperStatus set by
// hand, so reverting this site to upgrade.NewKernelSystem() leaves every one of
// them green while production silently returns to asking about a systemd unit
// that does not exist.
//
// It overrides the control-socket status seam with a recorder reporting the
// helper up-but-not-forwarding — the #5286 state a `systemctl is-active` probe
// is structurally incapable of seeing. The wired system must (a) CONSULT that
// query, proving the probe is installed, and (b) refuse forward progress.
func TestNewKernelConfig_WiresGate4DataplaneProbe_6607(t *testing.T) {
	statusCalled := false
	restoreStatus := swapHelperStatus(func(string, time.Duration) (bool, bool, int, error) {
		statusCalled = true
		return true, false, 777, nil // process up, helper NOT forwarding
	})
	defer restoreStatus()

	restoreSock := swapControlSock(func(string) string { return "/unused-in-test.sock" })
	defer restoreSock()

	// Precondition A held healthy: the point of this test is that A alone is not
	// enough, so A must never be why it fails. Without forcing it the assertion
	// below depends on whether the host running the suite happens to have xpfd
	// active — on a dev box it does not, A short-circuits, and the status query
	// is never reached.
	restoreActive := swapUnitActive(func(context.Context, string) (bool, error) { return true, nil })
	defer restoreActive()

	cfg := newKernelConfig("/unused-journal", false, time.Second, "xpfd")

	ok, err := cfg.Sys.ForwardBeacon(50 * time.Millisecond)
	if !statusCalled {
		t.Fatal("the production kernel KernelSystem did NOT consult the control-socket helper " +
			"status query — Gate 4's second condition is not wired, so the guard asserts only " +
			"that xpfd is active")
	}
	if ok {
		t.Fatalf("ForwardBeacon reported forward progress with the helper up but NOT forwarding "+
			"(err=%v) — a kernel that breaks the dataplane would be promoted", err)
	}
}

// TestNewKernelConfig_WiresBeaconTargetClassifier_7157 binds the #7157 beacon
// target classifier at the PRIMARY production construction site.
//
// Same reasoning as the #6607 wiring test above: pkg/upgrade's tests set
// IsManagementIface by hand, so reverting this site to nil leaves all of them
// green while production loses the ability to refuse a beacon target that
// egresses the out-of-band management interface.
//
// Asserts BEHAVIOUR: a locally-written copy of the three prefixes would satisfy
// a nil-check while being free to drift from config.IsManagementIfName, which
// #7515 records as always a bug.
func TestNewKernelConfig_WiresBeaconTargetClassifier_7157(t *testing.T) {
	cfg := newKernelConfig("/unused-journal", false, time.Second, "xpfd")
	v := reflect.Indirect(reflect.ValueOf(cfg.Sys))
	if v.Kind() != reflect.Struct {
		t.Fatalf("kernel system is %s, not a struct", v.Kind())
	}
	f := v.FieldByName("IsManagementIface")
	if !f.IsValid() || f.IsNil() {
		t.Fatal("newKernelConfig did not wire IsManagementIface — ForwardBeacon cannot refuse " +
			"a beacon target that egresses the management interface, so a candidate kernel " +
			"that keeps management up while breaking transit forwarding is promoted (#7157)")
	}
	fn, ok := f.Interface().(func(string) bool)
	if !ok {
		t.Fatalf("IsManagementIface has type %s, want func(string) bool", f.Type())
	}
	for _, tc := range []struct {
		iface string
		want  bool
	}{
		{"fxp0", true}, {"em0", true}, {"fab0", true},
		{"ge-0-0-1", false}, {"reth0.50", false}, {"lo", false},
	} {
		if got := fn(tc.iface); got != tc.want {
			t.Errorf("wired classifier(%q) = %v, want %v — it must be config.IsManagementIfName, "+
				"the #7515 SSOT, not a local copy free to drift from it", tc.iface, got, tc.want)
		}
	}
}
