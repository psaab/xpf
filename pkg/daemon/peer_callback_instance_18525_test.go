package daemon

import (
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/vrrp"
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

// A retired sync's late bulk-complete must not prime the successor or release
// startup holds. The currently published sync retains the valid release edge.
func TestOnBulkSyncReceivedFromRetiredSyncDoesNotReleaseHolds18554(t *testing.T) {
	d := &Daemon{
		cluster:   newClusterManager(false),
		vrrpMgr:   vrrp.NewManager(),
	}
	t.Cleanup(d.vrrpMgr.ReleaseSyncHold)
	d.cluster.SetSyncReady(false)
	d.cluster.SetSyncBulkPrimed(false)
	d.vrrpMgr.SetSyncHold(time.Hour)
	d.armNoRethSyncHold(time.Hour)

	old, successor := newWiringTestSessionSync(), newWiringTestSessionSync()
	d.wireSessionSyncPeerCallbacks(old)
	d.wireSessionSyncPeerCallbacks(successor)
	d.clusterCommsMu.Lock()
	d.sessionSync = successor
	d.clusterCommsMu.Unlock()

	old.OnBulkSyncReceived()

	if !d.vrrpMgr.InSyncHold() || !d.inNoRethSyncHold() {
		t.Fatal("a retired SessionSync's bulk-received callback released the current instance's startup holds")
	}
	if d.syncBulkPrimed.Load() || d.cluster.IsSyncBulkPrimed() {
		t.Fatal("a retired SessionSync's bulk-received callback marked the successor bulk-primed")
	}
	if d.cluster.IsSyncReady() {
		t.Fatal("a retired SessionSync's bulk-received callback marked the successor sync-ready")
	}
	if mode, active, _ := d.cluster.StartupSyncHoldStatus(); mode != "no-reth" || !active {
		t.Fatalf("retired callback changed startup hold status to (%q, %v)", mode, active)
	}

	successor.OnBulkSyncReceived()
	if d.vrrpMgr.InSyncHold() || d.inNoRethSyncHold() {
		t.Fatal("the current SessionSync's bulk-received callback did not release startup holds")
	}
	if !d.syncBulkPrimed.Load() || !d.cluster.IsSyncBulkPrimed() || !d.cluster.IsSyncReady() {
		t.Fatal("the current SessionSync's bulk-received callback did not publish bulk priming and readiness")
	}
}

// A bulk completion can pass the optimistic identity check, then be overtaken
// by a successor publication before it mutates daemon-wide readiness. The
// final check and mutation must therefore be serialized with publication.
func TestBulkReceivedCallbackRechecksSessionAfterReplacement18554(t *testing.T) {
	d := &Daemon{
		cluster:          newClusterManager(false),
		vrrpMgr:          vrrp.NewManager(),
		syncReadyTimeout: time.Hour,
	}
	t.Cleanup(d.stopSyncReadyTimer)
	t.Cleanup(d.vrrpMgr.ReleaseSyncHold)
	d.cluster.SetSyncReady(true)
	d.vrrpMgr.SetSyncHold(time.Hour)
	d.armNoRethSyncHold(time.Hour)

	old, successor := newWiringTestSessionSync(), newWiringTestSessionSync()
	d.wireSessionSyncPeerCallbacks(old)
	d.wireSessionSyncPeerCallbacks(successor)
	d.clusterCommsMu.Lock()
	d.sessionSync = old
	d.clusterCommsMu.Unlock()

	checked, resume := make(chan struct{}), make(chan struct{})
	var resumeOnce sync.Once
	releaseCallback := func() { resumeOnce.Do(func() { close(resume) }) }
	d.peerCallbackAfterSupersededForTest = func(which string) {
		if which == "OnBulkSyncReceived" {
			close(checked)
			<-resume
		}
	}
	callbackDone := make(chan struct{})
	go func() {
		defer close(callbackDone)
		old.OnBulkSyncReceived()
	}()
	t.Cleanup(func() {
		releaseCallback()
		<-callbackDone
	})
	select {
	case <-checked:
	case <-time.After(time.Second):
		t.Fatal("old bulk callback did not reach the post-check race seam")
	}

	d.clusterCommsMu.Lock()
	d.sessionSync = successor
	d.clusterCommsMu.Unlock()
	successor.OnPeerConnected()
	if d.cluster.IsSyncReady() {
		t.Fatal("fixture: successor cold connect must clear sync readiness before the stale callback resumes")
	}

	releaseCallback()
	<-callbackDone
	if !d.vrrpMgr.InSyncHold() || !d.inNoRethSyncHold() {
		t.Fatal("the superseded bulk callback released startup holds after successor publication")
	}
	if d.syncBulkPrimed.Load() || d.cluster.IsSyncBulkPrimed() {
		t.Fatal("the superseded bulk callback marked the successor bulk-primed")
	}
	if d.cluster.IsSyncReady() {
		t.Fatal("the superseded bulk callback restored readiness cleared by the successor cold connect")
	}
}

// A stale bulk ACK must not set syncPeerBulkPrimed after the successor's cold
// connect resets it; that flag is the stop condition for the prime-retry loop.
func TestRetiredBulkAckDoesNotStopSuccessorPrimeRetry18554(t *testing.T) {
	oldIntervals := syncPrimeRetryIntervalsForTest
	syncPrimeRetryIntervalsForTest = []time.Duration{10 * time.Millisecond, 10 * time.Millisecond}
	t.Cleanup(func() { syncPrimeRetryIntervalsForTest = oldIntervals })

	d := &Daemon{
		cluster:          newClusterManager(false),
		store:            testStoreWithSetConfig(t, []string{"set system host-name bulk-ack-18554"}),
		syncReadyTimeout: time.Hour,
	}
	d.setDataplane(&runtimeOnlyApplyTestDP{})
	t.Cleanup(d.stopSyncReadyTimer)
	t.Cleanup(func() { d.syncPrimeRetryGen.Add(1) })

	old, successor := newWiringTestSessionSync(), newWiringTestSessionSync()
	old.SetConnectedForTesting(true)
	successor.SetConnectedForTesting(true)
	d.wireSessionSyncPeerCallbacks(old)
	d.wireSessionSyncPeerCallbacks(successor)
	d.clusterCommsMu.Lock()
	d.sessionSync = old
	d.clusterCommsMu.Unlock()

	checked, resume := make(chan struct{}), make(chan struct{})
	var resumeOnce sync.Once
	releaseCallback := func() { resumeOnce.Do(func() { close(resume) }) }
	d.peerCallbackAfterSupersededForTest = func(which string) {
		if which == "OnBulkSyncAckReceived" {
			close(checked)
			<-resume
		}
	}
	callbackDone := make(chan struct{})
	go func() {
		defer close(callbackDone)
		old.OnBulkSyncAckReceived()
	}()
	t.Cleanup(func() {
		releaseCallback()
		<-callbackDone
	})
	select {
	case <-checked:
	case <-time.After(time.Second):
		t.Fatal("old bulk-ack callback did not reach the post-check race seam")
	}

	d.clusterCommsMu.Lock()
	d.sessionSync = successor
	d.clusterCommsMu.Unlock()
	retryFirst, retrySecond, retryRelease := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var retryReleaseOnce sync.Once
	releaseRetry := func() { retryReleaseOnce.Do(func() { close(retryRelease) }) }
	t.Cleanup(releaseRetry)
	retryCount := 0
	d.syncPrimeRetryBeforeSleepForTest = func() {
		retryCount++
		switch retryCount {
		case 1:
			close(retryFirst)
			<-retryRelease
		case 2:
			close(retrySecond)
		}
	}
	successor.OnPeerConnected()
	select {
	case <-retryFirst:
	case <-time.After(time.Second):
		t.Fatal("successor cold-connect did not start the bulk-prime retry loop")
	}

	releaseCallback()
	<-callbackDone
	if d.syncPeerBulkPrimed.Load() {
		t.Fatal("a retired bulk ACK set syncPeerBulkPrimed after the successor cold-connect reset")
	}
	releaseRetry()
	select {
	case <-retrySecond:
	case <-time.After(time.Second):
		t.Fatal("the successor bulk-prime retry loop stopped after the retired ACK")
	}
	if d.syncPeerBulkPrimed.Load() {
		t.Fatal("the retired ACK primed the successor during its retry loop")
	}
}
