package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #5275 regression tests for the transit-forwarding fail-closed gate.
//
// The defect: a dataplane ARM failure (rt.Start / LoadUserspaceShim) cleared
// the dataplane cell, logged "config-only mode", and fell through to
// applyConfig while `ip_forward` / `ipv6.conf.all.forwarding` stayed at 1 —
// bring-up had already raised them and applyKernelTuning re-raised them at
// every apply tail. With no XDP shim attached and no nftables `hook forward`
// chain anywhere in the repo, the kernel routed transit under zero policy.
//
// Each test drives ONE production writer against a temp-dir stand-in for the
// two procfs knobs, so a revert of one production line reds one test:
//
//	armBootDataplane failure branch  -> TestBootArmFailureClosesTransit5275
//	applyKernelTuning gate           -> TestApplyKernelTuningHonoursArmGate5275
//	armBootDataplane success branch  -> TestBootArmSuccessKeepsTransit5275
//	armBootstrapExitDataplane re-arm -> TestRearmAfterArmFailureRestoresTransit5275
//
// These tests swap the package-level sysctl path vars, so none of them may
// run t.Parallel() (same constraint as the sshKnownHostsPath / linkDir
// seams elsewhere in this package).

// withTempTransitForwardSysctls points the two gated sysctl paths at temp
// files seeded with `initial`, restoring the real /proc paths afterwards.
func withTempTransitForwardSysctls(t *testing.T, initial string) (v4, v6 string) {
	t.Helper()
	dir := t.TempDir()
	v4 = filepath.Join(dir, "ip_forward")
	v6 = filepath.Join(dir, "all_forwarding")
	for _, p := range []string{v4, v6} {
		if err := os.WriteFile(p, []byte(initial+"\n"), 0o644); err != nil {
			t.Fatalf("seed %s: %v", p, err)
		}
	}
	origV4, origV6 := ipv4ForwardSysctlPath, ipv6ForwardSysctlPath
	ipv4ForwardSysctlPath, ipv6ForwardSysctlPath = v4, v6
	t.Cleanup(func() {
		ipv4ForwardSysctlPath, ipv6ForwardSysctlPath = origV4, origV6
	})
	return v4, v6
}

// assertTransitForwarding fails when either knob does not hold `want`.
func assertTransitForwarding(t *testing.T, v4, v6, want, when string) {
	t.Helper()
	for _, tc := range []struct {
		path, family string
	}{{v4, "IPv4 ip_forward"}, {v6, "IPv6 conf.all.forwarding"}} {
		b, err := os.ReadFile(tc.path)
		if err != nil {
			t.Fatalf("read %s: %v", tc.path, err)
		}
		if got := strings.TrimSpace(string(b)); got != want {
			t.Errorf("%s = %q %s, want %q: an unarmed dataplane must not leave the "+
				"kernel routing transit with no policy (#5275)", tc.family, got, when, want)
		}
	}
}

// TestBootArmFailureClosesTransit5275 binds the BRING-UP write: the boot arm
// fails, so kernel transit forwarding must be 0 before applyConfig runs.
func TestBootArmFailureClosesTransit5275(t *testing.T) {
	v4, v6 := withTempTransitForwardSysctls(t, "1")

	d := &Daemon{}
	d.setDataplane(&failingStartUserspaceDP{})
	d.armBootDataplane(d.dataplane())

	if d.dataplane() != nil {
		t.Fatal("the dataplane cell must be cleared after a boot arm failure")
	}
	if d.DataplaneArmed() {
		t.Error("DataplaneArmed() = true after a failed boot arm, want false")
	}
	assertTransitForwarding(t, v4, v6, "0", "after a boot arm FAILURE")
}

// TestApplyKernelTuningHonoursArmGate5275 binds the APPLY-TAIL gate, the
// load-bearing half: the tail runs on every commit, so an unconditional "1"
// there silently re-opens the hole a failed bring-up just closed.
//
// Deliberately INDEPENDENT of the bring-up writer — it never calls
// armBootDataplane — so reverting the bring-up close cannot red it and a red
// here localises to applyKernelTuning alone. Both directions are asserted in
// one test because they are one expression: the gate must FOLLOW the arm
// state, not be pinned either way.
func TestApplyKernelTuningHonoursArmGate5275(t *testing.T) {
	v4, v6 := withTempTransitForwardSysctls(t, "1")

	d := &Daemon{} // zero value: never armed

	// The apply tail, exactly as applyTailReconciles step 9.5 calls it.
	d.applyKernelTuning(&config.Config{})
	assertTransitForwarding(t, v4, v6, "0",
		"after applyKernelTuning ran on an UNARMED daemon")

	// Same call on an ARMED daemon must raise them again — proving the gate
	// reads the arm state and is not simply pinned off.
	d.markDataplaneArmed("test")
	d.applyKernelTuning(&config.Config{})
	assertTransitForwarding(t, v4, v6, "1",
		"after applyKernelTuning ran on an ARMED daemon")
}

// TestArmFailureSurvivesApplyTail5275 is the END-TO-END sequence the defect
// report describes: bring-up fails to arm, then the boot applyConfig runs its
// tail. The pre-#5275 code closed nothing at bring-up and re-raised both
// knobs at the tail; a fix that only did the bring-up half would pass
// TestBootArmFailureClosesTransit5275 and still ship the hole, because the
// tail runs again on every later commit.
func TestArmFailureSurvivesApplyTail5275(t *testing.T) {
	v4, v6 := withTempTransitForwardSysctls(t, "1")

	d := &Daemon{}
	d.setDataplane(&failingStartUserspaceDP{})
	d.armBootDataplane(d.dataplane())

	// Two apply tails: the boot applyConfig this arm falls through to, and a
	// later operator commit.
	d.applyKernelTuning(&config.Config{})
	d.applyKernelTuning(&config.Config{})
	assertTransitForwarding(t, v4, v6, "0",
		"after a failed arm followed by two apply tails")
}

// TestBootTransitPolicyClosesWhenNeverArming5275 binds the BOOT-POLICY
// decision for the two states that never arm. #1922 already suppressed
// enableForwarding in bootstrap, but suppression is not closure: the sysctls
// outlive the process, so a daemon restart into bootstrap (or into the #1960
// compile-failed boot, which forces bootstrap) inherited ip_forward=1 from
// the previous armed run.
//
// Only the two CLOSING cases are driven. The default (arming) branch calls
// enableForwarding, which writes five further host-posture sysctls
// (accept_ra, l3mdev_accept, accept_local) to the real /proc — deliberately
// not exercised from a unit test. That branch's outcome is covered instead by
// TestBootArmSuccessKeepsTransit5275 and the armed leg of
// TestApplyKernelTuningHonoursArmGate5275.
func TestBootTransitPolicyClosesWhenNeverArming5275(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(*Daemon)
	}{
		{"no-dataplane", func(d *Daemon) { d.opts.NoDataplane = true }},
		{"bootstrap", func(d *Daemon) { d.bootstrapMode.Store(true) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v4, v6 := withTempTransitForwardSysctls(t, "1")
			d := &Daemon{}
			tc.setup(d)

			d.applyBootTransitPolicy()

			if d.DataplaneArmed() {
				t.Error("DataplaneArmed() = true in a mode that never arms, want false")
			}
			assertTransitForwarding(t, v4, v6, "0",
				"after bring-up in a mode that never arms the dataplane")
		})
	}
}

// TestBootArmSuccessKeepsTransit5275 is the negative control: a SUCCESSFUL
// arm must leave kernel transit forwarding enabled. Without it, "always
// closed" would pass every other test in this file while breaking every
// XDP_PASS-to-kernel path (route-based-VPN plaintext, SNAT'd frames).
func TestBootArmSuccessKeepsTransit5275(t *testing.T) {
	// Seed "0" so the enable is an observable WRITE, not a pre-existing value.
	v4, v6 := withTempTransitForwardSysctls(t, "0")

	d := &Daemon{}
	backend := &armedRecorderDP{}
	d.setDataplane(backend)
	d.armBootDataplane(d.dataplane())

	if d.dataplane() == nil {
		t.Fatal("the dataplane cell must retain the backend after a successful arm")
	}
	if !d.DataplaneArmed() {
		t.Error("DataplaneArmed() = false after a successful boot arm, want true")
	}
	assertTransitForwarding(t, v4, v6, "1", "after a SUCCESSFUL boot arm")
}

// TestBootstrapExitArmFailureClosesTransit5275 binds the SECOND arm-failure
// writer. runBootstrapExitStartup calls enableForwarding in ANTICIPATION of
// the arm that follows it, so a bootstrap-exit arm failure leaves the knobs
// freshly raised — this is the one site where the pre-#5275 code raised
// forwarding and then failed to arm within the same function.
func TestBootstrapExitArmFailureClosesTransit5275(t *testing.T) {
	// "1" is what runBootstrapExitStartup's enableForwarding just wrote.
	v4, v6 := withTempTransitForwardSysctls(t, "1")

	d := &Daemon{}
	d.bootstrapMode.Store(false) // exitBootstrapMode already flipped it in production
	d.setDataplane(&failingStartUserspaceDP{})

	d.armBootstrapExitDataplane(0)

	if d.dataplane() != nil {
		t.Fatal("the dataplane cell must be cleared after a bootstrap-exit arm failure")
	}
	if d.DataplaneArmed() {
		t.Error("DataplaneArmed() = true after a failed bootstrap-exit arm, want false")
	}
	assertTransitForwarding(t, v4, v6, "0", "after a bootstrap-exit arm FAILURE")
}

// TestBootstrapRollbackClosesTransit5275 binds the third un-arm site: the
// #1922 first-commit-confirmed timeout detaches the dataplane
// (enterBootstrapMode -> runBootstrapTeardownSteps step 4) without going
// through either arm writer, so an armed node becomes unarmed while the
// knobs are still open. Without the close, the very next apply tail would
// read a stale armed=true and keep the kernel routing transit for a
// dataplane that is no longer attached.
func TestBootstrapRollbackClosesTransit5275(t *testing.T) {
	v4, v6 := withTempTransitForwardSysctls(t, "1")

	// Drive the PRODUCTION teardown branch (not the applyBodyForTest seam,
	// which skips it): linkDir points at an empty temp dir so the networkd
	// step removes nothing and never calls networkctl, and d.frr is nil so
	// the FRR step is skipped.
	prevLinkDir := linkDir
	linkDir = t.TempDir()
	t.Cleanup(func() { linkDir = prevLinkDir })

	d := &Daemon{}
	d.natPoolAlarmTestTick = time.Millisecond
	d.bootstrapMode.Store(false)
	t.Cleanup(d.stopAndDiscardNATPoolAlarm)

	// Arm first, so the rollback has something to un-arm.
	d.setDataplane(&armedRecorderDP{})
	d.armBootDataplane(d.dataplane())
	assertTransitForwarding(t, v4, v6, "1", "after a successful arm")

	if err := d.enterBootstrapMode(); err != nil {
		t.Fatalf("enterBootstrapMode: %v", err)
	}

	if d.DataplaneArmed() {
		t.Error("DataplaneArmed() = true after the dataplane was detached, want false")
	}
	assertTransitForwarding(t, v4, v6, "0", "after a bootstrap rollback detached the dataplane")

	// And the apply tail must not undo it.
	d.applyKernelTuning(&config.Config{})
	assertTransitForwarding(t, v4, v6, "0",
		"after an apply tail followed the bootstrap rollback")
}

// TestRearmAfterArmFailureRestoresTransit5275 binds recovery: the
// bootstrap-exit arm is the one production re-arm path, and a node that came
// up unarmed must regain transit on it without a daemon restart.
func TestRearmAfterArmFailureRestoresTransit5275(t *testing.T) {
	v4, v6 := withTempTransitForwardSysctls(t, "1")

	d := &Daemon{}
	d.natPoolAlarmTestTick = time.Millisecond
	d.bootstrapMode.Store(false) // exitBootstrapMode already flipped it in production
	t.Cleanup(d.stopAndDiscardNATPoolAlarm)

	// Boot arm fails: closed.
	d.setDataplane(&failingStartUserspaceDP{})
	d.armBootDataplane(d.dataplane())
	assertTransitForwarding(t, v4, v6, "0", "after the first arm FAILED")

	// A corrected commit re-arms through the real bootstrap-exit writer.
	d.setDataplane(&armedRecorderDP{})
	d.armBootstrapExitDataplane(0)

	if !d.DataplaneArmed() {
		t.Error("DataplaneArmed() = false after a successful re-arm, want true")
	}
	assertTransitForwarding(t, v4, v6, "1", "after a successful RE-ARM")
}
