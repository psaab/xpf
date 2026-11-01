package daemon

import (
	"errors"
	"sync/atomic"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

// The transit gate asserts the readiness surface on the RUNTIME dataplane,
// which in production is the adapter, so the adapter must carry it (the first
// tcp SIGSTOP cell ran with only the Manager carrying it, and the RGs never
// moved).
var _ helperElectionReadinessSource = (*dpuserspace.LegacyDataPlaneAdapter)(nil)
var _ helperElectionReadinessSource = (*dpuserspace.Manager)(nil)

// readinessRuntime18697 adds the #18697/#18685 verdict to the #12159 fake.
type readinessRuntime18697 struct {
	*supervisorRuntime12159
	notReady atomic.Bool
}

func (r *readinessRuntime18697) HelperElectionNotReady() bool { return r.notReady.Load() }

func newReadinessDaemon18697(t *testing.T) (*Daemon, func() int, *readinessRuntime18697) {
	t.Helper()
	d, cm, base := newDebtProbeDaemon12159(t, 1)
	rt := &readinessRuntime18697{supervisorRuntime12159: base}
	d.setDataplane(dataplane.RuntimeDataPlane(rt))
	return d, func() int { return rgWeight12159(cm, 1) }, rt
}

// TestUnexpectedHelperExitRaisesArmDebt18697: a helper that died unexpectedly
// on the RG primary installs arm debt (weight 1, which yields the data RG to a
// healthy peer, #12164). The debt stays while the respawned helper runs but is
// not yet armed and healthy, and clears only when it is.
func TestUnexpectedHelperExitRaisesArmDebt18697(t *testing.T) {
	withBarrierRecorder(t)
	d, weight, rt := newReadinessDaemon18697(t)
	d.reassertTransitGate("healthy")
	if got := weight(); got != 255 {
		t.Fatalf("healthy weight = %d, want 255", got)
	}
	rt.running.Store(false)
	rt.notReady.Store(true)
	d.reassertTransitGate("helper-died")
	if got := weight(); got != 1 {
		t.Fatalf("weight after an unexpected helper exit = %d, want 1 (arm debt)", got)
	}
	rt.running.Store(true) // respawned, not yet armed and healthy
	d.reassertTransitGate("respawned")
	if got := weight(); got != 1 {
		t.Fatalf("weight after respawn but before re-arm = %d, want 1", got)
	}
	rt.notReady.Store(false)
	d.reassertTransitGate("re-armed")
	if got := weight(); got != 255 {
		t.Fatalf("weight after re-arm = %d, want 255", got)
	}
}

// TestIntentionalHelperStopKeepsWeight18697: F2's pass-through survives for an
// intentional stop or respawn (a plan-key change, an operator stop), so a
// config commit does not move the RGs.
func TestIntentionalHelperStopKeepsWeight18697(t *testing.T) {
	withBarrierRecorder(t)
	d, weight, rt := newReadinessDaemon18697(t)
	d.reassertTransitGate("healthy")
	rt.running.Store(false)
	d.reassertTransitGate("intentional-stop")
	d.markDataplaneArmed("intentional-stop-arm")
	if got := weight(); got != 255 {
		t.Fatalf("weight after an intentional helper stop = %d, want 255 (F2 pass-through)", got)
	}
}

// TestWedgedHelperRaisesArmDebt18685: a helper that is running but wedged (a
// frozen worker, or unanswered control requests) installs arm debt, and it
// clears when the verdict clears.
func TestWedgedHelperRaisesArmDebt18685(t *testing.T) {
	withBarrierRecorder(t)
	d, weight, rt := newReadinessDaemon18697(t)
	d.reassertTransitGate("healthy")
	rt.notReady.Store(true)
	d.reassertTransitGate("wedged")
	if got := weight(); got != 1 {
		t.Fatalf("weight with a wedged running helper = %d, want 1", got)
	}
	d.markDataplaneArmed("wedged-arm-reassert")
	if got := weight(); got != 1 {
		t.Fatalf("markDataplaneArmed wiped the wedge debt: weight %d, want 1", got)
	}
	rt.notReady.Store(false)
	d.reassertTransitGate("recovered")
	if got := weight(); got != 255 {
		t.Fatalf("weight after the wedge cleared = %d, want 255", got)
	}
}

// TestUnrelatedArmDebtSurvivesUnexpectedExit18697: F2's other half is kept. A
// fence failure that predates an unexpected helper death keeps its debt through
// the death and the respawn, and the readiness verdict clearing does not wipe
// it while the fence still fails.
func TestUnrelatedArmDebtSurvivesUnexpectedExit18697(t *testing.T) {
	f := withBarrierRecorder(t)
	d, weight, rt := newReadinessDaemon18697(t)
	d.reassertTransitGate("healthy")
	f.fenceInstall10302 = func(xnft.ForwardFenceSpec) error { return errors.New("kernel says no") }
	d.reassertTransitGate("fence-fails")
	rt.running.Store(false)
	rt.notReady.Store(true)
	d.reassertTransitGate("helper-died")
	rt.running.Store(true)
	rt.notReady.Store(false)
	d.reassertTransitGate("respawned-ready")
	if got := weight(); got != 1 {
		t.Fatalf("fence debt lost across an unexpected exit: weight %d, want 1", got)
	}
}
