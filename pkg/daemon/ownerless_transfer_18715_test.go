package daemon

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
)

// #18715 (1'): the owner-side half of the aborted-transfer retry. A transfer
// request for an RG this node does not own is accepted only when the RG is
// ownerless from this node's fresh view, and its applied-ack waits for a FRESH
// rg_active=false write to succeed and every direct VIP to be confirmed gone.

// newOwnerless18715 builds a node whose RG1 is ownerless: cluster-secondary,
// desired inactive, with a fresh peer view that also reports secondary.
func newOwnerless18715(t *testing.T, hold time.Duration, writeErr error) (*Daemon, *order18701, *int) {
	t.Helper()
	d, log := newDemotion18701(t, false, hold)
	d.dataplane().(*readinessDP18701).ha.err = writeErr
	confirms := new(int)
	d.directVIPsConfirmAbsentFn = func(int) error { *confirms++; log.add("vips-confirmed"); return nil }
	for drained := true; drained; {
		select {
		case <-d.cluster.Events():
		default:
			drained = false
		}
	}
	d.cluster.SetGroupStateForTesting(1, cluster.StateSecondary)
	d.cluster.SetPeerGroupStateForTesting(1, cluster.StateSecondary)
	return d, log, confirms
}

func manualHold18715(d *Daemon) bool {
	for _, rg := range d.cluster.GroupStates() {
		if rg.GroupID == 1 {
			return rg.ManualFailover
		}
	}
	return false
}

// TestOwnerlessAcceptAcksOnlyAfterTheConfirm18715: the accepted request is
// acked only after the fresh write and the VIP confirm, and this node ends
// with the same Manual hold a completed evacuation leaves (coordinator 4).
func TestOwnerlessAcceptAcksOnlyAfterTheConfirm18715(t *testing.T) {
	d, log, confirms := newOwnerless18715(t, 0, nil)
	if err := d.acceptOwnerlessTransferOut(1, actuationReqID); err != nil {
		t.Fatalf("an ownerless request was not accepted: %v", err)
	}
	if err := d.waitFailoverActuated(1, actuationReqID); err != nil {
		t.Fatalf("the confirmed ownerless fence was not acked: %v", err)
	}
	ev := log.snapshot()
	w, v := slices.Index(ev, "rg_active=false sent"), slices.Index(ev, "vips-confirmed")
	if w < 0 || v < 0 || *confirms != 1 {
		t.Fatalf("events %v confirms=%d: the ack needs a fresh rg_active=false write and the VIP confirm", ev, *confirms)
	}
	if !manualHold18715(d) {
		t.Fatal("an accepted ownerless transfer must leave the Manual hold a completed evacuation leaves")
	}
}

// TestOwnerlessAcceptRejectsWhenThePeerOwns18715: the guard the exception
// sits beside still holds. With the peer primary (or a view too stale to say),
// the request is rejected with no hold, no write, and no barrier left armed.
func TestOwnerlessAcceptRejectsWhenThePeerOwns18715(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(d *Daemon)
	}{
		{"peer-primary", func(d *Daemon) { d.cluster.SetPeerGroupStateForTesting(1, cluster.StatePrimary) }},
		{"stale-view", func(d *Daemon) { d.cluster.SetPeerHeartbeatAgeForTesting(time.Second) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, log, _ := newOwnerless18715(t, 0, nil)
			tc.setup(d)
			err := d.acceptOwnerlessTransferOut(1, actuationReqID)
			if !errors.Is(err, cluster.ErrRemoteFailoverRejected) {
				t.Fatalf("err=%v: want a rejection, which the sync layer acks as rejected", err)
			}
			if manualHold18715(d) || slices.Contains(log.snapshot(), "rg_active=false sent") {
				t.Fatalf("a rejected request installed a hold or wrote rg_active: %v", log.snapshot())
			}
			if n := d.failoverActuations.armedCount(); n != 0 {
				t.Fatalf("%d barrier(s) left armed by a rejected request", n)
			}
		})
	}
}

// TestOwnerlessConfirmFailuresFailTheAck18715 (coordinator 3): anything short
// of a successful fresh write plus confirmed VIP release fails the ack, so the
// requester keeps its fence and retries.
func TestOwnerlessConfirmFailuresFailTheAck18715(t *testing.T) {
	oldBound := ownerlessConfirmBound
	ownerlessConfirmBound = 150 * time.Millisecond
	t.Cleanup(func() { ownerlessConfirmBound = oldBound })
	for _, tc := range []struct {
		name  string
		hold  time.Duration
		err   error
		setup func(d *Daemon)
	}{
		{"write-refused", 0, errors.New("rg_active refused"), nil},
		{"write-times-out", time.Second, nil, nil},
		{"vip-still-present", 0, nil, func(d *Daemon) {
			d.directVIPsConfirmAbsentFn = func(int) error { return errors.New("VIP still on ge-0-0-1") }
		}},
		{"desired-active", 0, nil, func(d *Daemon) { d.getOrCreateRGState(1).SetCluster(true) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, _, _ := newOwnerless18715(t, tc.hold, tc.err)
			if tc.setup != nil {
				tc.setup(d)
			}
			if err := d.acceptOwnerlessTransferOut(1, actuationReqID); err != nil {
				t.Fatalf("accept: %v", err)
			}
			if err := d.waitFailoverActuated(1, actuationReqID); err == nil {
				t.Fatal("the ownerless fence was acked without a confirmed inactive dataplane")
			}
		})
	}
}

// TestOwnerlessBarrierIgnoresTheHoldEvent18715: the accept's ManualFailover
// emits a Secondary -> SecondaryHold event, and handleClusterEvent resolves
// every barrier of the RG on a non-primary edge. That edge writes nothing to
// the helper, so it must not resolve the confirm-only barrier: with the confirm
// still pending (and about to fail), the wait must see the confirm's verdict.
func TestOwnerlessBarrierIgnoresTheHoldEvent18715(t *testing.T) {
	d, _, _ := newOwnerless18715(t, 400*time.Millisecond, errors.New("refused"))
	if err := d.acceptOwnerlessTransferOut(1, actuationReqID); err != nil {
		t.Fatalf("accept: %v", err)
	}
	select {
	case ev := <-d.cluster.Events():
		if timer := d.handleClusterEvent(context.Background(), ev, nil); timer != nil {
			timer.Stop()
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the accept emitted no hold event")
	}
	if err := d.waitFailoverActuated(1, actuationReqID); err == nil {
		t.Fatal("the hold event resolved the ownerless barrier as actuated before the confirm finished")
	}
}

// TestOwnerlessConfirmConvergesAfterAHelperRestart18715 (coordinator 3): while
// the wedged helper is gone (watchdog kill) the fresh write fails and the ack
// fails; the sync layer restores the hold. After the respawn the next retry's
// fresh write succeeds and the transfer is acked.
func TestOwnerlessConfirmConvergesAfterAHelperRestart18715(t *testing.T) {
	d, _, _ := newOwnerless18715(t, 0, errors.New("no helper running"))
	if err := d.acceptOwnerlessTransferOut(1, actuationReqID); err != nil {
		t.Fatalf("accept: %v", err)
	}
	if err := d.waitFailoverActuated(1, actuationReqID); err == nil {
		t.Fatal("acked while no helper was running")
	}
	// handleRemoteFailover restores the owner after a failed fence.
	if err := d.cluster.AbortRemoteTransferOut(1, actuationReqID); err != nil {
		t.Fatalf("abort: %v", err)
	}
	d.dataplane().(*readinessDP18701).ha.err = nil // the respawned helper answers
	// The fixture's peer view carries no weight, so the restore's election
	// promotes this node; in the trap it is the arm-debt floor that keeps it
	// secondary. Put the trap shape back.
	d.cluster.SetGroupStateForTesting(1, cluster.StateSecondary)
	d.cluster.SetPeerGroupStateForTesting(1, cluster.StateSecondary)
	next := actuationReqID + 1
	if err := d.acceptOwnerlessTransferOut(1, next); err != nil {
		t.Fatalf("retry accept: %v", err)
	}
	if err := d.waitFailoverActuated(1, next); err != nil {
		t.Fatalf("the retry after the respawn was not acked: %v", err)
	}
}

// TestOnRemoteFailoverRoutesNonOwnedRGsToTheOwnerlessAccept18715 binds the
// WIRING, not the function (the #9036 lesson): the installed OnRemoteFailover
// closure sends a request for a non-owned RG to the ownerless accept, and
// still rejects one for an RG the peer owns.
func TestOnRemoteFailoverRoutesNonOwnedRGsToTheOwnerlessAccept18715(t *testing.T) {
	t.Run("ownerless", func(t *testing.T) {
		d, _, _ := newOwnerless18715(t, 0, nil)
		ss := cluster.NewSessionSync("127.0.0.1:4785", "127.0.0.1:4785", nil)
		d.wireSessionSyncFailoverCallbacks(ss)
		if err := ss.OnRemoteFailover(1, actuationReqID); err != nil {
			t.Fatalf("OnRemoteFailover for an ownerless RG: %v", err)
		}
		if err := d.waitFailoverActuated(1, actuationReqID); err != nil {
			t.Fatalf("the wired ownerless accept was not acked: %v", err)
		}
	})
	t.Run("peer-owned", func(t *testing.T) {
		d, _, _ := newOwnerless18715(t, 0, nil)
		d.cluster.SetPeerGroupStateForTesting(1, cluster.StatePrimary)
		ss := cluster.NewSessionSync("127.0.0.1:4785", "127.0.0.1:4785", nil)
		d.wireSessionSyncFailoverCallbacks(ss)
		if err := ss.OnRemoteFailover(1, actuationReqID); !errors.Is(err, cluster.ErrRemoteFailoverRejected) {
			t.Fatalf("OnRemoteFailover for a peer-owned RG: %v, want ErrRemoteFailoverRejected", err)
		}
	})
}
