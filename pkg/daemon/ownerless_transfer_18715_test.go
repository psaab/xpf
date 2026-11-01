package daemon

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/ra"
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
// acked only after the fresh write and the VIP confirm, and the group is parked
// in Manual from the ack until the transfer ends (a commit then clears it).
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
		t.Fatal("an accepted ownerless transfer must park the group in Manual until the transfer ends")
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

// stableLLDaemon18715 is a daemon with a real RETH config (cluster 1, RG1 on
// reth0 unit 50) behind the fake kernel, and the REAL confirm check.
func stableLLDaemon18715(t *testing.T, d *Daemon) (*fakeKernel18573, string, string) {
	t.Helper()
	d.store = rethStore18573(t, "172.16.50.42/24", "2001:db8:50::42/64")
	k := newFakeKernel18573(t)
	k.install(t, d)
	d.directVIPsConfirmAbsentFn = nil
	cfg := d.store.ActiveConfig()
	ll := config.StableRethLinkLocal(cfg.Chassis.Cluster.ClusterID, 1).String()
	for _, netdev := range cfg.RemoveNetdevs(1) {
		if _, ok := k.links[netdev]; ok {
			return k, netdev, ll
		}
	}
	t.Fatalf("setup: none of RG1's netdevs %v is in the fake kernel", cfg.RemoveNetdevs(1))
	return nil, "", ""
}

// TestConfirmCoversTheStableRouterLinkLocal18715 (review U, fold 6 B): the
// stable router link-local is the RA source, i.e. the hosts' IPv6 default
// router, and its removal is best-effort. A node that kept it, or still runs
// an RA sender with that source, still claims the router identity, so the
// confirm must refuse.
func TestConfirmCoversTheStableRouterLinkLocal18715(t *testing.T) {
	d, _ := newDemotion18701(t, false, 0)
	k, netdev, ll := stableLLDaemon18715(t, d)
	if err := d.directVIPsConfirmedAbsent(1); err != nil {
		t.Fatalf("control: nothing is installed, yet the confirm refused: %v", err)
	}
	k.put(netdev, ll+"/128", 0)
	if err := d.directVIPsConfirmedAbsent(1); err == nil || !strings.Contains(err.Error(), "link-local") {
		t.Fatalf("the stable router link-local is still on %s and the confirm passed: %v", netdev, err)
	}
	k.rows = nil
	ifaces := rethInterfacesForRG(d.store.ActiveConfig(), 1)
	if len(ifaces) == 0 {
		t.Fatal("setup: RG1 has no RETH interfaces")
	}
	d.raSendersFn = func() []ra.SenderInfo {
		return []ra.SenderInfo{{Interface: ifaces[0], SrcAddr: ll, State: "active"}}
	}
	if err := d.directVIPsConfirmedAbsent(1); err == nil || !strings.Contains(err.Error(), "RA sender") {
		t.Fatalf("an RA sender is still active with the stable router source and the confirm passed: %v", err)
	}
	d.raSendersFn = func() []ra.SenderInfo {
		return []ra.SenderInfo{{Interface: ifaces[0], SrcAddr: "fe80::1234", State: "active"}}
	}
	if err := d.directVIPsConfirmedAbsent(1); err != nil {
		t.Fatalf("control: a per-node RA source is not the router identity, yet the confirm refused: %v", err)
	}
}

// TestStableLLDeleteFailureFailsTheAckAndTheConfirm18715 (review U, fold 6 B):
// with the stable router link-local delete failing (left on the interface),
// both the helper-down silent ack and the ownerless confirm refuse.
func TestStableLLDeleteFailureFailsTheAckAndTheConfirm18715(t *testing.T) {
	t.Run("silent-ack", func(t *testing.T) {
		d, _ := newDemotion18701(t, true, 0)
		k, netdev, ll := stableLLDaemon18715(t, d)
		k.put(netdev, ll+"/128", 0) // the best-effort delete failed
		if err := d.helperDownFenceSilentAck(1, true); err == nil {
			t.Fatal("the silent ack passed with the stable router link-local still installed")
		}
	})
	t.Run("ownerless-confirm", func(t *testing.T) {
		d, _, _ := newOwnerless18715(t, 0, nil)
		k, netdev, ll := stableLLDaemon18715(t, d)
		d.directRemoveStableLLFn = func(int) {} // the delete fails: the address stays
		k.put(netdev, ll+"/128", 0)
		if err := d.acceptOwnerlessTransferOut(1, actuationReqID); err != nil {
			t.Fatalf("accept: %v", err)
		}
		if err := d.waitFailoverActuated(1, actuationReqID); err == nil {
			t.Fatal("the ownerless confirm acked with the stable router link-local still installed")
		}
	})
}

// TestLateWriteOvertakingANewerStateIsReasserted18715 (review U NIT): writes
// given up on can land after a newer write of the other value (the
// controller's m.mu hands off in no order). A landed write whose value the
// RG no longer wants re-arms the reconcile retry.
func TestLateWriteOvertakingANewerStateIsReasserted18715(t *testing.T) {
	d, _ := newDemotion18701(t, false, 0)
	s := d.getOrCreateRGState(1)
	s.SetCluster(true) // promoted since the write started
	s.MarkApplied(true)
	if s.NeedsApply() {
		t.Fatal("setup: the promotion's write is recorded")
	}
	ha := &countingHA18715{release: make(chan struct{})}
	close(ha.release)
	w := d.startRGActiveWrite(context.Background(), ha, 1, false)
	<-w.done
	deadline := time.Now().Add(2 * time.Second)
	for !s.NeedsApply() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !s.NeedsApply() {
		t.Fatal("a stale rg_active=false landed after the promotion and nothing re-armed the reconcile retry")
	}
}
