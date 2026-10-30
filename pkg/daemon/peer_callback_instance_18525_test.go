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
