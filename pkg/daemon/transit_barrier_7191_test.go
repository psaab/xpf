package daemon

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

// #7191 plus #10302. Two halves: the nftables barrier depth, and the
// arm-coverage gate.
//
// The OVER-REJECTION controls remain load-bearing. The armed path now keeps a
// default-drop forward fence with only explicit provenance pinholes; an
// install failure must not open kernel forwarding.
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
func lastFenceCall10302(f *fakeNftInstaller) string {
	if len(f.fenceCalls10302) == 0 {
		return ""
	}
	return f.fenceCalls10302[len(f.fenceCalls10302)-1]
}

// OVER-REJECTION CONTROL. An armed daemon must install the explicit armed
// forward fence rather than remove the forward hook entirely. Unlisted ingress
// remains policy-DROP; the XDP_PASS pinholes are tested in
// transit_fence_10302_test.go.
func TestArmedStateInstallsTheForwardFence7191(t *testing.T) {
	withTempTransitForwardSysctls(t, "0")
	f := withBarrierRecorder(t)
	d := &Daemon{}
	d.setDataplane(&armedRecorderDP{})
	d.markDataplaneArmed("test")

	if got := lastFenceCall10302(f); got != "install" {
		t.Fatalf("arming must INSTALL the armed forward fence, last call = %q (fence calls: %v barrier calls: %v)",
			got, f.fenceCalls10302, f.barrierCalls)
	}
	if len(f.barrierCalls) != 0 {
		t.Fatalf("arming must not remove or install the unconditional barrier directly: %v", f.barrierCalls)
	}
}

// The same control on the repeating path. The apply tail runs on EVERY commit,
// so an armed daemon must re-assert the explicit fence rather than remove the
// forward hook and reopen unlisted kernel transit.
func TestApplyTailKeepsTheArmedForwardFence7191(t *testing.T) {
	withTempTransitForwardSysctls(t, "0")
	f := withBarrierRecorder(t)
	d := &Daemon{}
	d.setDataplane(&armedRecorderDP{})
	d.markDataplaneArmed("test")
	f.barrierCalls = nil
	f.fenceCalls10302 = nil

	d.applyKernelTuning(&config.Config{})

	if got := lastFenceCall10302(f); got != "install" {
		t.Errorf("the apply tail on an ARMED daemon must keep the armed fence installed, last call = %q (calls: %v)",
			got, f.fenceCalls10302)
	}
	if len(f.barrierCalls) != 0 {
		t.Errorf("the apply tail installed/removed the unconditional barrier on an ARMED daemon: %v", f.barrierCalls)
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

// An armed-fence install failure must keep the dataplane arm bit intact for
// observability, but the ordered gate writer must leave both transit sysctls
// closed rather than exposing an unfiltered forward path.
func TestArmedFenceInstallFailureKeepsTransitClosed7191(t *testing.T) {
	withTempTransitForwardSysctls(t, "0")
	f := withBarrierRecorder(t)
	f.fenceInstall10302 = func(xnft.ForwardFenceSpec) error { return errors.New("kernel says no") }

	d := &Daemon{}
	d.setDataplane(&armedRecorderDP{})
	d.markDataplaneArmed("test")

	if !d.DataplaneArmed() {
		t.Error("an armed-fence install failure must not disarm the dataplane")
	}
	for _, path := range transitForwardSysctlPaths() {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read transit knob %s: %v", path, err)
		}
		if strings.TrimSpace(string(b)) != "0" {
			t.Errorf("armed-fence install failure opened %s to %q", path, strings.TrimSpace(string(b)))
		}
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
