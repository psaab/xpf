package daemon

import (
	"errors"
	"testing"
)

// #6915: a cycled-MAC-write failure must still arm the post-cycle recovery.
//
// programRethMAC's fallback is DOWN -> set MAC -> UP. When the CYCLED
// setHardwareAddr fails, the link has already been taken down — and a DOWN
// flushes every kernel address on the interface, including the VRRP VIPs and
// the stable RETH link-local. The member then comes back UP holding the VRRP
// role while answering for none of the addresses that role exists to serve.
//
// It used to return linkCycled=false on that path, which is the gate feeding
// needLinkCycleRecovery, so step 2.6b's ReconcileVIPs / addStableRethLinkLocal
// was SKIPPED for a cycle that had genuinely happened. Nothing else re-added
// them: ReconcileVIPs has exactly ONE production caller (that gated one), the
// 2s reconcileRGState tick re-adds only the stable link-local in VRRP mode, and
// sendAdvert swallows its send error at Debug so VRRP never observes the flap
// and stays MASTER. The node stayed VIP-less until some later apply cycled it.
//
// Direct (no-VRRP) mode was never exposed: the same 2s tick calls
// reconcileDirectVIPOwnership -> addDirectVIPs unconditionally, which is
// idempotent and re-adds what the DOWN removed, announcing on `added > 0`.
// That asymmetry is why this is bound at the gate rather than at ReconcileVIPs.

// TestCycledMACWriteFailureArmsTheRecoveryGate6915 binds the HANDOFF, which is
// the part a unit test of programRethMACWithWorkerJoin alone cannot see.
//
// Making the cycle honest moves the rebind's owner: with linkCycled=true this
// member no longer fires the local rollback NotifyLinkCycle (that would be the
// double rebind the abort path's own comment warns gets EBUSY on mlx5
// zero-copy queues) and instead arms needLinkCycleRecovery, which is the gate
// on BOTH step 2.6b (the VIP reconcile this issue is about) and step 2.6b2 (the
// rebind that used to happen locally).
//
// So the sibling test's `wantNotify: 0` is only safe if the gate is genuinely
// armed. Without this cell, flipping the return would look like it had DELETED
// the rebind guard rather than relocated it — the local call count drops to
// zero and nothing observes that anything took it over.
//
// RED-on-revert: restore `return false` on programRethMAC's cycled-set-mac
// failure path and this reds at "recovery gate = false".
func TestCycledMACWriteFailureArmsTheRecoveryGate6915(t *testing.T) {
	var events []string
	withRethOps(t, newFailAfterJoinOps(t, &events, failSetMACCycled))
	d, lc := newAbortRecoveryDaemon(nil /* the join SUCCEEDS */)

	// needLinkCycleRecovery starts false, exactly as step 2.6 initialises it.
	commitErr, gate, _ := d.programRethMemberMAC("ge-0-0-1", virtMAC5103, nil, false, false)

	if lc.prepareCalls != 1 {
		t.Fatalf("PrepareLinkCycle calls = %d, want 1 — the fixture must reach the "+
			"hook and have it SUCCEED, or this is a different failure class",
			lc.prepareCalls)
	}
	if !gate {
		t.Errorf("recovery gate = false, want true. The link went DOWN and back UP, " +
			"so the kernel flushed the VRRP VIPs and the stable RETH link-local off " +
			"this member. needLinkCycleRecovery is the ONLY gate on step 2.6b's " +
			"ReconcileVIPs / addStableRethLinkLocal, and ReconcileVIPs has exactly one " +
			"production caller — so with the gate down nothing re-adds them and the " +
			"member holds the VRRP role carrying none of its addresses (#6915)")
	}
	// The commit must STILL fail — arming the recovery is not the same as
	// pretending the MAC write landed. Without this, a change that armed the
	// gate by swallowing the error would pass the assertion above.
	if commitErr == nil {
		t.Error("the commit must FAIL: the MAC write was refused after the dataplane " +
			"was deliberately torn down. Arming the recovery gate must not launder " +
			"that into a green commit")
	}
	if !errors.Is(commitErr, errRethPrepareLinkCycle) {
		t.Errorf("commit error must carry errRethPrepareLinkCycle; got %v", commitErr)
	}
}

// TestSetDownFailureDoesNotArmTheRecoveryGate6915 is the PAIRED control, and it
// is what makes the cell above about the DOWN having happened rather than about
// "any failure arms the gate".
//
// setDown FAILING means the link never went down: no addresses were flushed, so
// there is nothing for step 2.6b to reconcile, and step 2.6b2 must not rebind
// sockets that were never torn down by a cycle. That row keeps linkCycled=false
// and keeps its LOCAL rollback rebind, since the join did run.
//
// Without this control, `return true` unconditionally from the fallback would
// satisfy the measurement cell while arming recovery for a cycle that never
// happened.
func TestSetDownFailureDoesNotArmTheRecoveryGate6915(t *testing.T) {
	var events []string
	withRethOps(t, newFailAfterJoinOps(t, &events, failSetDown))
	d, lc := newAbortRecoveryDaemon(nil /* the join SUCCEEDS */)

	commitErr, gate, _ := d.programRethMemberMAC("ge-0-0-1", virtMAC5103, nil, false, false)

	if lc.prepareCalls != 1 {
		t.Fatalf("PrepareLinkCycle calls = %d, want 1", lc.prepareCalls)
	}
	if gate {
		t.Errorf("recovery gate = true, want false — setDown FAILED, so the link never " +
			"went down and no address was flushed. Arming step 2.6b here would reconcile " +
			"VIPs that were never removed, and arming step 2.6b2 would rebind AF_XDP " +
			"sockets no cycle tore down")
	}
	if lc.notifyCalls != 1 {
		t.Errorf("NotifyLinkCycle calls = %d, want 1 — with the gate correctly down, "+
			"step 2.6b2 will not rebind, so this path must still own its local rollback "+
			"or the join leaves every worker stopped with nothing to re-arm them",
			lc.notifyCalls)
	}
	if commitErr == nil {
		t.Error("the commit must FAIL on an aborted cycle after a successful join")
	}
}
