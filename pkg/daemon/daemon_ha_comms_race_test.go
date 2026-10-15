package daemon

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
)

// TestStartClusterCommsPublishDropsStaleEpoch is the #4958 fail-on-revert guard.
//
// It reproduces the constructor-vs-restart race deterministically: a comms
// restart opens a NEW epoch and publishes its session-sync object, and only
// THEN does the prior epoch's still-running constructor finish its ≤60s address
// resolution and attempt to publish. The generation guard in
// publishSessionSyncIfCurrent must DROP that stale publish so the live epoch's
// session/endpoints are not clobbered (the stale-overwrite failure) and a
// stopping epoch's session is not resurrected (the nil-deref failure).
//
// This asserts the drop by object identity, so neutralizing the generation
// check (deleting the `gen != d.clusterCommsGen` guard in
// publishSessionSyncIfCurrent) makes the stale publish win and turns this test
// RED — independent of the race detector.
func TestStartClusterCommsPublishDropsStaleEpoch(t *testing.T) {
	d := &Daemon{}

	// Epoch 1: a constructor goroutine starts resolving its sync address.
	_, gen1, _ := d.beginClusterCommsEpoch(context.Background())
	ss1 := &cluster.SessionSync{} // what the slow epoch-1 constructor would publish

	// A transport-change commit restarts comms: a new epoch supersedes epoch 1
	// while its constructor is still resolving.
	_, gen2, _ := d.beginClusterCommsEpoch(context.Background())
	if gen2 == gen1 {
		t.Fatalf("beginClusterCommsEpoch did not advance the generation: gen1=%d gen2=%d", gen1, gen2)
	}
	ss2 := &cluster.SessionSync{}

	// Epoch 2's constructor publishes first — it owns the current epoch.
	if !d.publishSessionSyncIfCurrent(gen2, ss2) {
		t.Fatal("current-epoch publish was dropped; expected it to win")
	}
	if got := d.getSessionSync(); got != ss2 {
		t.Fatalf("current-epoch publish did not take effect: getSessionSync()=%p want ss2=%p", got, ss2)
	}

	// Now the slow epoch-1 constructor finally finishes and tries to publish.
	// The guard must drop it.
	if d.publishSessionSyncIfCurrent(gen1, ss1) {
		t.Fatal("stale-epoch publish succeeded; the generation guard is not dropping superseded publishes (#4958 regression)")
	}
	if got := d.getSessionSync(); got != ss2 {
		t.Fatalf("stale-epoch publish overwrote the live epoch: getSessionSync()=%p want ss2=%p (stale ss1=%p)", got, ss2, ss1)
	}
}

// TestStopClusterCommsSupersedesInflightConstructor asserts that
// stopClusterComms itself bumps the epoch generation (under clusterCommsMu) so a
// constructor that was still resolving when comms were torn down cannot
// resurrect d.sessionSync after the stop. This is the nil-deref half of #4958:
// before the fix, stop set d.sessionSync = nil and a late constructor wrote a
// fresh object back, so a subsequent reader saw a session for a torn-down epoch.
func TestStopClusterCommsSupersedesInflightConstructor(t *testing.T) {
	d := &Daemon{}

	_, gen1, _ := d.beginClusterCommsEpoch(context.Background())
	ss1 := &cluster.SessionSync{}

	// Tear comms down (no cluster/sessionSync wired yet — the constructor is
	// still resolving). stopClusterComms must advance the generation.
	d.stopClusterComms()

	if d.publishSessionSyncIfCurrent(gen1, ss1) {
		t.Fatal("a constructor published after stopClusterComms; stop did not supersede the epoch (#4958 regression)")
	}
	if got := d.getSessionSync(); got != nil {
		t.Fatalf("late publish resurrected sessionSync after stop: getSessionSync()=%p want nil", got)
	}
}

// TestPublishFabricRefreshChansDropsStaleEpoch is the fabric-channel companion
// to the session-sync guard: a superseded constructor must not replace a newer
// epoch's fabric refresh channels either (#4958).
func TestPublishFabricRefreshChansDropsStaleEpoch(t *testing.T) {
	d := &Daemon{}

	_, gen1, _ := d.beginClusterCommsEpoch(context.Background())
	stale0 := make(chan struct{}, 1)
	stale1 := make(chan struct{}, 1)

	_, gen2, _ := d.beginClusterCommsEpoch(context.Background())
	live0 := make(chan struct{}, 1)
	live1 := make(chan struct{}, 1)

	if !d.publishFabricRefreshChansIfCurrent(gen2, live0, live1) {
		t.Fatal("current-epoch fabric channel publish was dropped; expected it to win")
	}
	if d.publishFabricRefreshChansIfCurrent(gen1, stale0, stale1) {
		t.Fatal("stale-epoch fabric channel publish succeeded; generation guard missing (#4958 regression)")
	}
	got0, got1 := d.snapshotFabricRefreshChans()
	if got0 != live0 || got1 != live1 {
		t.Fatalf("stale-epoch publish overwrote the live fabric channels: got (%p,%p) want (%p,%p)", got0, got1, live0, live1)
	}
}

// TestClusterCommsPublishConcurrentIsRaceFree exercises the publish/read paths
// concurrently so `go test -race` proves clusterCommsMu synchronizes them
// (#4958). Before the fix the constructor wrote d.sessionSync and stop nilled it
// with no lock, so concurrent access here would be a data race. With the guard,
// every stale publish is dropped and the live object is never overwritten.
func TestClusterCommsPublishConcurrentIsRaceFree(t *testing.T) {
	d := &Daemon{}

	_, liveGen, _ := d.beginClusterCommsEpoch(context.Background())
	live := &cluster.SessionSync{}
	if !d.publishSessionSyncIfCurrent(liveGen, live) {
		t.Fatal("failed to publish the live epoch")
	}
	staleGen := liveGen - 1 // a generation that was never current → always dropped

	var wg sync.WaitGroup
	// Re-publisher for the live epoch (idempotent — must stay `live`).
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				d.publishSessionSyncIfCurrent(liveGen, live)
			}
		}()
	}
	// Stale-epoch publishers racing the live epoch — every one must be dropped.
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			stale := &cluster.SessionSync{}
			for j := 0; j < 500; j++ {
				if d.publishSessionSyncIfCurrent(staleGen, stale) {
					t.Errorf("stale-epoch publish (gen %d) was accepted", staleGen)
					return
				}
			}
		}()
	}
	// Concurrent readers.
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				_ = d.getSessionSync()
			}
		}()
	}
	wg.Wait()

	if got := d.getSessionSync(); got != live {
		t.Fatalf("live epoch object changed under concurrency: getSessionSync()=%p want live=%p", got, live)
	}
}

// TestSessionSyncStartExhaustionUnpublishesFailedObject13545 fault-injects
// every bounded Start attempt failing and verifies the constructor's
// exhaustion action leaves no published-but-unstarted sync object.
func TestSessionSyncStartExhaustionUnpublishesFailedObject13545(t *testing.T) {
	oldAttempts, oldDelay := sessionSyncStartAttempts, sessionSyncStartRetryDelay
	sessionSyncStartAttempts, sessionSyncStartRetryDelay = 30, 0
	t.Cleanup(func() {
		sessionSyncStartAttempts, sessionSyncStartRetryDelay = oldAttempts, oldDelay
	})

	d := &Daemon{}
	_, gen, _ := d.beginClusterCommsEpoch(context.Background())
	ss := &cluster.SessionSync{}
	if !d.publishSessionSyncIfCurrent(gen, ss) {
		t.Fatal("failed to publish test session-sync")
	}

	startCalls := 0
	started := false
	start := func() error {
		startCalls++
		return errors.New("injected bind failure")
	}
	for i := 0; i < sessionSyncStartAttempts; i++ {
		if err := start(); err == nil {
			started = true
			break
		}
	}
	if startCalls != 30 || started {
		t.Fatalf("fault injection made %d attempts, started=%t; want 30 failures", startCalls, started)
	}

	// This is the exhaustion path in startClusterComms.
	if !started {
		d.retireUnstartedSessionSync(gen, ss)
	}
	if got := d.getSessionSync(); got != nil {
		t.Fatalf("exhausted, unstarted session-sync remains published: %p", got)
	}
}
