package daemon

import (
	"slices"
	"sync/atomic"
	"testing"
	"time"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #18791: during the unexpected-exit restart grace, the exit has not raised
// election debt (HelperElectionNotReady is false), but no helper is running to
// answer control.

// The adapter must carry the surface: the daemon asserts it on the RUNTIME
// dataplane (the #18704 lesson).
var _ helperExitSource = (*dpuserspace.LegacyDataPlaneAdapter)(nil)
var _ helperExitSource = (*dpuserspace.Manager)(nil)

// exitedDP18791 is the #18701 demotion fake with the #18791 exit surface.
type exitedDP18791 struct {
	*readinessDP18701
	exited atomic.Bool
}

func (d *exitedDP18791) HelperExitedUnexpectedly() bool { return d.exited.Load() }

// TestPeerRequestDuringTheGraceTakesTheVIPFirstPath18791 (coordinator 1): a
// peer-requested transfer of an RG whose owner's helper has just exited, still
// inside the grace, takes the helper-down (VIP-first) demotion path. The
// verdict is not raised, but nothing answers control. So the VIPs go first,
// the bounded rg_active write fails, the fence is acked (the socket is silent
// and every VIP is confirmed gone), and the transfer converges instead of
// blocking on the restarting helper.
func TestPeerRequestDuringTheGraceTakesTheVIPFirstPath18791(t *testing.T) {
	old := helperDownDemotionBound
	helperDownDemotionBound = 200 * time.Millisecond
	t.Cleanup(func() { helperDownDemotionBound = old })
	d, log := newDemotion18701(t, false, 5*time.Second)
	if !d.isNoRethVRRP() {
		t.Skip("fixture config is not direct (no-RETH-VRRP) mode")
	}
	base := d.dataplane().(*readinessDP18701)
	dp := &exitedDP18791{readinessDP18701: base}
	dp.exited.Store(true) // no helper running; HelperElectionNotReady stays false (grace)
	d.setDataplane(dp)
	if d.helperElectionNotReady() {
		t.Fatal("setup: inside the grace the election verdict must not be raised")
	}
	d.tryPrepareDemotionFn = func(int) { log.add("prep") }
	primeRG1Primary(t, d)
	d.armFailoverActuation(1, actuationReqID)
	start := time.Now()
	demoteRG1(t, d)
	took := time.Since(start)
	ev := log.snapshot()
	vips, write := slices.Index(ev, "vips-removed"), slices.Index(ev, "rg_active=false sent")
	if vips < 0 || write < 0 || vips > write {
		t.Fatalf("events %v: inside the grace the VIPs must be released before the rg_active write", ev)
	}
	if slices.Contains(ev, "prep") {
		t.Fatalf("events %v: the prep ran against a helper that is not running", ev)
	}
	if took > 2*time.Second {
		t.Fatalf("the demotion waited %s on a helper that is not running", took)
	}
	if err := d.waitFailoverActuated(1, actuationReqID); err != nil {
		t.Fatalf("the peer-requested transfer did not converge inside the grace: %v (events %v)", err, ev)
	}
}

// TestGraceKeepsTheElectionWeight18791: inside the grace the transit gate sees
// a stopped helper with no verdict raised. That is the F2 pass-through, so the
// weight stays 255 and the RGs do not move. Once the grace ends without an
// arm, the verdict raises arm debt (weight 1).
func TestGraceKeepsTheElectionWeight18791(t *testing.T) {
	withBarrierRecorder(t)
	d, weight, rt := newReadinessDaemon18697(t)
	d.reassertTransitGate("healthy")
	rt.running.Store(false) // helper exited; grace open: verdict not raised
	d.reassertTransitGate("exited-in-grace")
	if got := weight(); got != 255 {
		t.Fatalf("weight inside the restart grace = %d, want 255 (no RG move)", got)
	}
	rt.notReady.Store(true) // grace ended without an arm
	d.reassertTransitGate("grace-expired")
	if got := weight(); got != 1 {
		t.Fatalf("weight after the grace ended without an arm = %d, want 1 (arm debt)", got)
	}
}

// TestSpawnedUnarmedResponsiveHelperUsesVIPFirstButNormalControlPathFold18794
// pins the spawned-but-unarmed state at helperDownForDemotion, which is shared
// by daemon_ha.go's event demotion (line 857) and reconcile (line 1653) paths.
// The source must choose VIP-first even though election debt is still inside
// grace, while a control answer remains responsive for prep and the real
// rg_active result (not the silent-socket bounded/ack path).
func TestSpawnedUnarmedResponsiveHelperUsesVIPFirstButNormalControlPathFold18794(t *testing.T) {
	d, _ := newDemotion18701(t, false, 0)
	if !d.isNoRethVRRP() {
		t.Skip("fixture config is not direct (no-RETH-VRRP) mode")
	}
	base := d.dataplane().(*readinessDP18701)
	base.controlAnswers.Store(true)
	dp := &exitedDP18791{readinessDP18701: base}
	dp.exited.Store(true) // spawned replacement, not yet armed
	d.setDataplane(dp)
	if d.helperElectionNotReady() {
		t.Fatal("setup: election debt must stay suppressed inside the restart grace")
	}
	if !d.helperDownForDemotion() {
		t.Fatal("spawned-but-unarmed replacement did not select VIP-first demotion")
	}
	if d.helperControlSilentForPrep() {
		t.Fatal("a responsive spawned replacement was misclassified as control-silent")
	}
	if d.helperControlConfirmedSilent() {
		t.Fatal("a responsive spawned replacement was accepted as silent fence evidence")
	}
	if err := d.helperDownFenceSilentAck(1, true); err == nil {
		t.Fatal("a failed rg_active write could be acknowledged while the spawned replacement answers control")
	}
}
