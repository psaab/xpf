package daemon

import (
	"errors"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// #7191. Two halves: the nftables barrier depth, and the arm-coverage gate.
//
// The OVER-REJECTION controls are the load-bearing cells here, not the defect
// cells. A forward-hook DROP is a reject-direction change whose worst case is a
// silent black hole rather than a loud error, so "the armed case still
// forwards" matters more than "the unarmed case drops".

func withBarrierRecorder(t *testing.T) *fakeNftInstaller {
	t.Helper()
	f := &fakeNftInstaller{}
	prev := nftInstaller
	nftInstaller = f
	t.Cleanup(func() { nftInstaller = prev })
	return f
}

func lastBarrierCall(f *fakeNftInstaller) string {
	if len(f.barrierCalls) == 0 {
		return ""
	}
	return f.barrierCalls[len(f.barrierCalls)-1]
}

// OVER-REJECTION CONTROL. An armed daemon must end with the barrier REMOVED.
// If this ever fails, armed transit is being dropped — route-based IPsec
// plaintext off an xfrm interface, SNAT'd frames passed up for kernel routing,
// and the #7409 slow-path reinject all rely on an OPEN kernel forward hook, and
// daemon_transit_gate.go names them as the reason the gate never lowers the
// knob while armed.
func TestArmedStateRemovesTheBarrier7191(t *testing.T) {
	withTempTransitForwardSysctls(t, "0")
	f := withBarrierRecorder(t)
	d := &Daemon{}
	d.setDataplane(&armedRecorderDP{})
	d.markDataplaneArmed("test")

	if got := lastBarrierCall(f); got != "remove" {
		t.Fatalf("arming must REMOVE the barrier, last call = %q (calls: %v). "+
			"A barrier that survives arming black-holes IPsec plaintext and SNAT'd "+
			"frames, which is worse than the hole this change closes", got, f.barrierCalls)
	}
}

// The same control on the repeating path. The apply tail runs on EVERY commit,
// so a barrier re-asserted there against an armed daemon would black-hole the
// box on the next unrelated config change rather than at arm time.
func TestApplyTailKeepsTheBarrierOffWhileArmed7191(t *testing.T) {
	withTempTransitForwardSysctls(t, "0")
	f := withBarrierRecorder(t)
	d := &Daemon{}
	d.setDataplane(&armedRecorderDP{})
	d.markDataplaneArmed("test")
	f.barrierCalls = nil // isolate the tail's own decision

	d.applyKernelTuning(&config.Config{})

	if got := lastBarrierCall(f); got != "remove" {
		t.Errorf("the apply tail on an ARMED daemon must keep the barrier off, last call = %q (calls: %v)",
			got, f.barrierCalls)
	}
	for _, c := range f.barrierCalls {
		if c == "install" {
			t.Errorf("the apply tail installed the barrier on an ARMED daemon: %v", f.barrierCalls)
		}
	}
}

// The defect cell: unarmed must install it.
func TestUnarmedStateInstallsTheBarrier7191(t *testing.T) {
	withTempTransitForwardSysctls(t, "1")
	f := withBarrierRecorder(t)

	d := &Daemon{} // zero value: never armed
	d.applyKernelTuning(&config.Config{})

	if got := lastBarrierCall(f); got != "install" {
		t.Errorf("an UNARMED daemon must install the forward-hook barrier, last call = %q (calls: %v)",
			got, f.barrierCalls)
	}
}

func TestArmFailureInstallsTheBarrier7191(t *testing.T) {
	withTempTransitForwardSysctls(t, "1")
	f := withBarrierRecorder(t)

	d := &Daemon{}
	d.markDataplaneArmFailed("test", "remediation", errors.New("boom"))

	if got := lastBarrierCall(f); got != "install" {
		t.Errorf("an arm FAILURE must install the barrier, last call = %q (calls: %v)", got, f.barrierCalls)
	}
}

// A barrier that cannot be REMOVED must not take the arm state down with it:
// the daemon stays armed and the failure is loud. Disarming here would convert
// an nftables fault into a forwarding outage.
func TestBarrierRemoveFailureDoesNotDisarm7191(t *testing.T) {
	withTempTransitForwardSysctls(t, "0")
	f := withBarrierRecorder(t)
	f.barrierRemove = func() error { return errors.New("kernel says no") }

	d := &Daemon{}
	d.setDataplane(&armedRecorderDP{})
	d.markDataplaneArmed("test")

	if !d.DataplaneArmed() {
		t.Error("a barrier REMOVE failure must not disarm the dataplane")
	}
}

// --- arm-coverage gate -------------------------------------------------

type fakeCoverageDP struct {
	dataplane.RuntimeDataPlane
	uncovered int
	total     int
	ran       bool
	seen      bool
}

func (f *fakeCoverageDP) ArmCoverageSummary() (int, int, bool, bool) {
	return f.uncovered, f.total, f.ran, f.seen
}

func (f *fakeCoverageDP) AttachedXDPLinkCount() int { return 1 }

func (f *fakeCoverageDP) SetAttachedLinksObserver(func()) {}

func TestArmCoverageVerdictIsThreeState7191(t *testing.T) {
	for _, tc := range []struct {
		name      string
		uncovered int
		ran, seen bool
		want      armCoverageVerdict
	}{
		// The control that keeps this a fence and not a brick: before the first
		// apply nothing has been proven, and that must NOT read as a hole.
		{"never published", 0, false, false, armCoverageUnknown},
		{"published but did not run", 3, false, true, armCoverageUnknown},
		{"ran, all covered", 0, true, true, armCoverageComplete},
		{"ran, one uncovered", 1, true, true, armCoverageIncomplete},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyArmCoverageVerdict(tc.uncovered, tc.ran, tc.seen); got != tc.want {
				t.Errorf("verdict = %v, want %v", got, tc.want)
			}
		})
	}
}

// OVER-REJECTION CONTROL for the coverage gate. A fully covered dataplane must
// stay armed. This is the cell that fails if the gate is inverted or if
// "uncovered" is miscounted — and an inverted gate here disarms every healthy
// box on its next commit.
func TestCompleteCoverageKeepsTheBoxArmed7191(t *testing.T) {
	v4, v6 := withTempTransitForwardSysctls(t, "0")
	withBarrierRecorder(t)

	d := &Daemon{}
	d.setDataplane(&fakeCoverageDP{
		uncovered: 0, total: 3, ran: true, seen: true,
	})
	d.markDataplaneArmed("test")

	d.evaluateArmCoverage("apply")

	if !d.DataplaneArmed() {
		t.Fatal("a fully covered dataplane must stay ARMED — disarming here black-holes a healthy box")
	}
	assertTransitForwarding(t, v4, v6, "1", "with complete arm coverage")
}

// Never-observed must also keep the box armed. Same brick-vs-fence property.
func TestUnknownCoverageKeepsTheBoxArmed7191(t *testing.T) {
	withTempTransitForwardSysctls(t, "0")
	withBarrierRecorder(t)

	d := &Daemon{}
	d.setDataplane(&fakeCoverageDP{seen: false})
	d.markDataplaneArmed("test")

	d.evaluateArmCoverage("apply")

	if !d.DataplaneArmed() {
		t.Error("an unpublished coverage report must not disarm — that is a brick, not a fence")
	}
}

// The defect cell: an uncovered surface disarms and closes transit, exactly as
// a Start failure does. FAIL-ON-REVERT — delete the evaluateArmCoverage call in
// applyKernelTuning and this reds.
func TestUncoveredInterfaceDisarmsAndClosesTransit7191(t *testing.T) {
	v4, v6 := withTempTransitForwardSysctls(t, "1")
	f := withBarrierRecorder(t)

	d := &Daemon{}
	d.setDataplane(&fakeCoverageDP{
		uncovered: 1, total: 3, ran: true, seen: true,
	})
	d.markDataplaneArmed("test")
	f.barrierCalls = nil

	d.applyKernelTuning(&config.Config{})

	if d.DataplaneArmed() {
		t.Fatal("an interface with no shim attached must DISARM the box: nothing adjudicates its transit")
	}
	assertTransitForwarding(t, v4, v6, "0", "after an uncovered interface was proven")
	if got := lastBarrierCall(f); got != "install" {
		t.Errorf("disarming on incomplete coverage must also install the barrier, last call = %q (calls: %v)",
			got, f.barrierCalls)
	}
}
