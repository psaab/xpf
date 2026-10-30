package daemon

import (
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
)

// Review of #18525 round 4 (finding 1, HA seat): peer connect/disconnect
// callbacks are ordered per SessionSync (dispatchPeerEvent), but the state
// they write — syncPeerConnected, the prime-retry generation, the sync-ready
// timer, SetSyncReady — is daemon-wide and outlives the instance. On a comms
// restart, the old instance's OnPeerDisconnected can queue behind its own
// slow OnPeerConnected (config-key wait plus a config write) and run AFTER the
// successor's OnPeerConnected. Unguarded, it marked a live successor's peer
// disconnected until the next reconnect: manual failover refused, config
// reconcile stopped, the successor's prime retry and sync-ready timer killed.
//
// The closures are driven in exactly that order. A callback from an instance
// that is no longer the published one is ignored when a DIFFERENT instance is
// published; with nothing published (a teardown with no successor yet) it
// still records the disconnect. RED (disconnected) without the guard.
func TestStalePeerCallbackCannotOverwriteSuccessor18525(t *testing.T) {
	newDaemon := func() *Daemon {
		// Not the RG0 authority: the connect edge's config push skips, so the
		// cell observes only the peer-connection state.
		return &Daemon{cluster: newClusterManager(false), localFailoverCommitTimeout: 2 * time.Second}
	}
	publish := func(d *Daemon, ss *cluster.SessionSync) {
		d.clusterCommsMu.Lock()
		d.sessionSync = ss
		d.clusterCommsMu.Unlock()
	}

	t.Run("late disconnect from a replaced instance", func(t *testing.T) {
		d := newDaemon()
		t.Cleanup(d.stopSyncReadyTimer)
		old, successor := newWiringTestSessionSync(), newWiringTestSessionSync()
		d.wireSessionSyncPeerCallbacks(old)
		d.wireSessionSyncPeerCallbacks(successor)

		publish(d, old)
		old.OnPeerConnected() // its config push is what keeps it running long
		publish(d, nil)       // comms teardown
		publish(d, successor) // comms restart
		successor.OnPeerConnected()
		gen := d.syncPrimeRetryGen.Load()

		old.OnPeerDisconnected() // queued behind the old connect; lands last
		if !d.syncPeerConnected.Load() {
			t.Fatal("a replaced SessionSync's late OnPeerDisconnected marked the live successor's " +
				"peer disconnected: manual failover is refused and config reconcile stops until the " +
				"next reconnect (review of #18525 round 4)")
		}
		if got := d.syncPrimeRetryGen.Load(); got != gen {
			t.Fatalf("the stale disconnect advanced the prime-retry generation %d -> %d, killing the "+
				"successor's bulk-prime retry", gen, got)
		}
	})

	t.Run("late connect from a replaced instance", func(t *testing.T) {
		d := newDaemon()
		t.Cleanup(d.stopSyncReadyTimer)
		old, successor := newWiringTestSessionSync(), newWiringTestSessionSync()
		d.wireSessionSyncPeerCallbacks(old)
		d.wireSessionSyncPeerCallbacks(successor)
		publish(d, successor) // not connected yet
		epoch := d.syncPeerConnEpoch.Load()
		old.OnPeerConnected()
		if d.syncPeerConnected.Load() || d.syncPeerConnEpoch.Load() != epoch {
			t.Fatal("a replaced SessionSync's late OnPeerConnected wrote the successor's peer state")
		}
	})

	t.Run("disconnect with no successor published is recorded", func(t *testing.T) {
		d := newDaemon()
		t.Cleanup(d.stopSyncReadyTimer)
		old := newWiringTestSessionSync()
		d.wireSessionSyncPeerCallbacks(old)
		publish(d, old)
		old.OnPeerConnected()
		publish(d, nil) // stopClusterComms unpublished it; no successor
		old.OnPeerDisconnected()
		if d.syncPeerConnected.Load() {
			t.Fatal("a teardown with no successor must still record the disconnect")
		}
	})
}

// Review of #18525 at 5af11e4593 (ha-B seat, LOW): dropping a stale
// OnPeerDisconnected left nobody to record the disconnect. onSessionSync
// PeerDisconnected is the only writer of syncPeerConnected=false, so when the
// old instance's disconnect lost the race to a successor's publication the
// daemon kept believing the peer was connected for as long as the successor
// made no callback of its own — and an old connect callback that ran during
// the teardown (nothing published) armed a sync-ready timer the teardown had
// already stopped, which could release the hold 30s later. Now the retirement
// itself records the disconnect, and a connect from an instance that is not
// the published one is dropped even while nothing is published: the new
// instance always starts from "disconnected" and re-derives the state from
// its own callbacks. RED: connected, with a live timer.
func TestRetiredSessionSyncLeavesThePeerDisconnected18525(t *testing.T) {
	newDaemon := func() *Daemon {
		d := &Daemon{cluster: newClusterManager(false), localFailoverCommitTimeout: 2 * time.Second}
		d.syncReadyTimeout = time.Hour // the cold-start timer is armed, and must not survive
		return d
	}
	publish := func(d *Daemon, ss *cluster.SessionSync) {
		d.clusterCommsMu.Lock()
		d.sessionSync = ss
		d.clusterCommsMu.Unlock()
	}
	timerArmed := func(d *Daemon) bool {
		d.syncReadyTimerMu.Lock()
		defer d.syncReadyTimerMu.Unlock()
		return d.syncReadyTimer != nil
	}
	retire := map[string]func(d *Daemon, ss *cluster.SessionSync){
		"retirePredecessorSessionSync": func(d *Daemon, ss *cluster.SessionSync) { d.retirePredecessorSessionSync(ss) },
		"stopClusterComms":             func(d *Daemon, _ *cluster.SessionSync) { d.stopClusterComms() },
	}
	for name, retireFn := range retire {
		t.Run(name+"/old disconnect lands after the successor is published", func(t *testing.T) {
			d := newDaemon()
			t.Cleanup(d.stopSyncReadyTimer)
			old, successor := newWiringTestSessionSync(), newWiringTestSessionSync()
			d.wireSessionSyncPeerCallbacks(old)
			d.wireSessionSyncPeerCallbacks(successor)
			publish(d, old)
			old.OnPeerConnected()
			if !d.syncPeerConnected.Load() || !timerArmed(d) {
				t.Fatal("fixture: the old connect must mark the peer connected and arm the timer")
			}
			retireFn(d, old)
			publish(d, successor) // the successor never connects: the peer is down
			old.OnPeerDisconnected()
			if d.syncPeerConnected.Load() {
				t.Fatal("the retired instance's disconnect was dropped and nothing else recorded it: " +
					"the daemon believes a peer is connected that no live SessionSync has " +
					"(review of #18525, ha-B LOW)")
			}
			if timerArmed(d) {
				t.Fatal("the retired connection's sync-ready timer is still armed")
			}
		})
	}
	t.Run("connect from an instance being retired, nothing published", func(t *testing.T) {
		d := newDaemon()
		t.Cleanup(d.stopSyncReadyTimer)
		old := newWiringTestSessionSync()
		d.wireSessionSyncPeerCallbacks(old)
		publish(d, nil) // mid-teardown: unpublished, no successor yet
		old.OnPeerConnected()
		if d.syncPeerConnected.Load() || timerArmed(d) {
			t.Fatal("a connect callback from an unpublished instance wrote the peer state and armed " +
				"the sync-ready timer after the teardown stopped it")
		}
	})
}
