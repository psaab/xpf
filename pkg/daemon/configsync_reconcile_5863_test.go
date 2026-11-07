package daemon

import (
	"context"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/configstore"
)

// newConfigSyncStore builds a committed store whose active config enables
// chassis-cluster configuration-synchronize, so ActiveConfig().Chassis.Cluster
// .ConfigSync is true and the reconciler reaches its push decision. hostName
// lets a caller mutate the active generation (a later commit changes the
// config text → a new configGenerationHash).
func newConfigSyncStore(t *testing.T, hostName string) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "config"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	for _, cmd := range []string{
		"chassis cluster cluster-id 1",
		"chassis cluster authentication-key test-cluster-psk-6611",
		"chassis cluster control-interface em0",
		"chassis cluster peer-address 10.99.0.2",
		"interfaces em0 unit 0 family inet address 10.99.0.1/24",
		"chassis cluster node 0",
		"chassis cluster redundancy-group 0 node 0 priority 200",
		"chassis cluster redundancy-group 0 node 1 priority 100",
		"chassis cluster configuration-synchronize",
		"system host-name " + hostName,
	} {
		if err := store.SetFromInput(cmd); err != nil {
			t.Fatalf("SetFromInput(%q): %v", cmd, err)
		}
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	cfg := store.ActiveConfig()
	if cfg == nil || cfg.Chassis.Cluster == nil || !cfg.Chassis.Cluster.ConfigSync {
		t.Fatalf("config-sync not enabled in active config: %#v", cfg)
	}
	return store
}

// commitHostName mutates the active config (new host-name) so the reconciler's
// config-generation token changes, modeling an operator commit while the peer
// connection stays up.
func commitHostName(t *testing.T, store *configstore.Store, hostName string) {
	t.Helper()
	// The store stays in configure mode after the initial Commit, so no
	// EnterConfigure here (a second EnterConfigure would self-conflict on the
	// held config lock).
	if err := store.SetFromInput("system host-name " + hostName); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
}

// newReconcileDaemon wires a Daemon for the reconciler tests: a real store with
// config-sync enabled, a primary/secondary cluster manager, and a counting push
// seam so pushes can be observed without a live TCP sync transport. The node is
// marked connected with a live epoch.
func newReconcileClusterManager(primary bool) *cluster.Manager {
	m := newClusterManager(primary)
	state := cluster.StateSecondary
	if primary {
		state = cluster.StatePrimary
	}
	m.SetGroupStateForTesting(0, state)
	return m
}

func newReconcileDaemon(t *testing.T, primary bool, uptime time.Duration) (*Daemon, *atomic.Int64) {
	t.Helper()
	var pushes atomic.Int64
	d := &Daemon{
		cluster:   newReconcileClusterManager(primary),
		store:     newConfigSyncStore(t, "recon-host"),
		startTime: time.Now().Add(-uptime),
	}
	d.configSyncPushForTest = func() { pushes.Add(1) }
	d.syncPeerConnected.Store(true)
	d.syncPeerConnEpoch.Add(1) // simulate a live peer connection
	return d, &pushes
}

// TestConfigSyncReconcile_PushesAfterPromotion is the primary #5863 fail-on-
// revert case: a peer connects while this node is SECONDARY (the connect edge
// skips the push), then this node is promoted to RG0 primary with the
// connection still up. The old edge-triggered code never re-pushed; the
// reconciler must push exactly once on the promotion re-evaluation and stay a
// no-op thereafter.
func TestConfigSyncReconcile_PushesAfterPromotion(t *testing.T) {
	d, pushes := newReconcileDaemon(t, false /*secondary*/, 60*time.Second)

	// Peer connected while secondary → the connect-edge reconcile must skip.
	d.reconcileConfigSyncToPeer("peer-connect")
	if got := pushes.Load(); got != 0 {
		t.Fatalf("secondary must not push config; got %d pushes", got)
	}

	// Later promotion to RG0 primary with the SAME connection up → the
	// reconciler must now push the authoritative config exactly once.
	d.cluster = newReconcileClusterManager(true /*primary*/)
	d.reconcileConfigSyncToPeer("rg0-promotion")
	if got := pushes.Load(); got != 1 {
		t.Fatalf("promotion must push exactly once; got %d pushes", got)
	}

	// Invariant still satisfied → further ticks are no-ops (no push storm).
	for i := 0; i < 5; i++ {
		d.reconcileConfigSyncToPeer("reconcile-loop")
	}
	if got := pushes.Load(); got != 1 {
		t.Fatalf("held invariant must not re-push; got %d pushes", got)
	}
}

// TestConfigSyncReconcile_PushesAfterStabilityCrossing covers the second
// ordering: a peer connects while this node is primary but too young (<30s
// uptime) → the connect edge skips; when uptime crosses the stability
// threshold, the reconciler (fired by the reconcile loop) must push once.
func TestConfigSyncReconcile_PushesAfterStabilityCrossing(t *testing.T) {
	d, pushes := newReconcileDaemon(t, true /*primary*/, 0 /*just started*/)

	// Primary but uptime 0 → connect-edge reconcile skips on stability gate.
	d.reconcileConfigSyncToPeer("peer-connect")
	if got := pushes.Load(); got != 0 {
		t.Fatalf("young node must not push config; got %d pushes", got)
	}

	// Cross the stability threshold with the connection still up.
	d.startTime = time.Now().Add(-60 * time.Second)
	d.reconcileConfigSyncToPeer("reconcile-loop")
	if got := pushes.Load(); got != 1 {
		t.Fatalf("stability crossing must push exactly once; got %d pushes", got)
	}
}

// TestConfigSyncReconcile_HappyPathPushesOnce verifies the normal case: a
// primary + stable node with a connected peer pushes exactly once at connect
// time and does not storm on repeated ticks.
func TestConfigSyncReconcile_HappyPathPushesOnce(t *testing.T) {
	d, pushes := newReconcileDaemon(t, true /*primary*/, 60*time.Second)

	for i := 0; i < 10; i++ {
		d.reconcileConfigSyncToPeer("peer-connect")
	}
	if got := pushes.Load(); got != 1 {
		t.Fatalf("primary+stable must push exactly once across many ticks; got %d", got)
	}
}

// TestConfigSyncReconcileAlreadyPushedDoesNotReserveGeneration18644 exercises
// the production reservation path with a satisfied (epoch x hash) marker.
// Repeated safety-net ticks must leave SessionSync's wire-generation counter
// unchanged, rather than reserving before recognizing the no-op.
func TestConfigSyncReconcileAlreadyPushedDoesNotReserveGeneration18644(t *testing.T) {
	d, _ := newReconcileDaemon(t, true /*primary*/, 60*time.Second)
	d.configSyncPushForTest = nil
	ss := cluster.NewSessionSync(":0", "10.99.0.2:4785", nil)
	d.clusterCommsMu.Lock()
	d.sessionSync = ss
	d.clusterCommsMu.Unlock()
	_, configText, _ := d.activeConfigSnapshotForPeer()
	epoch := d.syncPeerConnEpoch.Load()

	d.configSyncMu.Lock()
	d.configSyncHasPushed = true
	d.configSyncPushedEpoch = epoch
	d.configSyncPushedGen = configGenerationHash(configText)
	d.configSyncMu.Unlock()

	before := ss.ConfigGenCounterForTesting()
	const ticks = 10
	for range ticks {
		d.reconcileConfigSyncToPeer("reconcile-loop")
	}
	if after := ss.ConfigGenCounterForTesting(); after != before {
		t.Fatalf("already-pushed no-op ticks reserved config generations: before=%d after=%d across %d ticks",
			before, after, ticks)
	}
}

// FAIL-ON-REVERT: a same-text operator push at a newer wire generation
// supersedes a reconcile reservation paused before its final marker check.
// The old hash-only guard let that stale reconcile write G1 after G2 and
// replace the generation the overdue-ACK path must resend.
func TestConfigSyncReconcilePreservesNewerSameTextPush18644(t *testing.T) {
	d, _ := newReconcileDaemon(t, true /*primary*/, 60*time.Second)
	d.configSyncPushForTest = nil
	ss := cluster.NewSessionSync(":0", "10.99.0.2:4785", nil)
	ss.SetConnectedForTesting(true)
	d.clusterCommsMu.Lock()
	d.sessionSync = ss
	d.clusterCommsMu.Unlock()
	d.configPeerStateForTest = func() (bool, bool) { return true, true }

	type queuedConfig struct {
		text string
		gen  uint64
	}
	var queueMu sync.Mutex
	var queued []queuedConfig
	d.configSyncQueueForTest = func(text string, gen uint64) bool {
		queueMu.Lock()
		queued = append(queued, queuedConfig{text: text, gen: gen})
		queueMu.Unlock()
		return true
	}

	reserved := make(chan uint64, 1)
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseReconcile := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseReconcile()
	var paused atomic.Bool
	d.configSyncAfterReserveForTest = func(gen uint64) {
		if paused.CompareAndSwap(false, true) {
			reserved <- gen
			<-release
		}
	}

	reconcileDone := make(chan struct{})
	go func() {
		d.reconcileConfigSyncToPeer("same-text-commit-race")
		close(reconcileDone)
	}()
	var g1 uint64
	select {
	case g1 = <-reserved:
	case <-time.After(5 * time.Second):
		t.Fatal("reconcile did not pause after reserving G1")
	}

	if err := d.syncConfigToPeerWithAuthorization(nil); err != nil {
		t.Fatalf("same-text operator push: %v", err)
	}
	queueMu.Lock()
	if len(queued) != 1 {
		got := len(queued)
		queueMu.Unlock()
		t.Fatalf("operator push wrote %d generations before G1 resumed, want exactly G2", got)
	}
	g2 := queued[0].gen
	text := queued[0].text
	queueMu.Unlock()
	if g2 <= g1 {
		t.Fatalf("operator generation G2=%d is not newer than paused reconcile G1=%d", g2, g1)
	}
	_, activeText, _ := d.activeConfigSnapshotForPeer()
	if text != activeText {
		t.Fatalf("operator push text differs from active config: pushed=%q active=%q", text, activeText)
	}

	ss.SetOverdueConfigApplyDebtForTesting(g2, 2*time.Minute)
	type resend struct {
		text string
		gen  uint64
	}
	var resends []resend
	d.configResendForTest = func(text string, gen uint64) {
		resends = append(resends, resend{text: text, gen: gen})
	}
	releaseReconcile()
	select {
	case <-reconcileDone:
	case <-time.After(5 * time.Second):
		t.Fatal("reconcile did not finish after the newer push completed")
	}

	queueMu.Lock()
	finalQueued := append([]queuedConfig(nil), queued...)
	queueMu.Unlock()
	if len(finalQueued) != 1 || finalQueued[0].gen != g2 {
		t.Fatalf("stale reconcile wrote after G2: queued=%+v, want only G2=%d", finalQueued, g2)
	}
	d.configSyncMu.Lock()
	pushedGen, pushedWireGen, pushedText := d.configSyncPushedMarkerGen, d.configSyncPushedWireGen, d.configSyncPushedDigest
	d.configSyncMu.Unlock()
	if pushedGen != g2 || pushedWireGen != g2 || pushedText != text {
		t.Fatalf("G1 replaced the G2 pushed marker: marker=%d wire=%d textMatches=%v, want marker/wire=%d",
			pushedGen, pushedWireGen, pushedText == text, g2)
	}

	if !d.repushIfConfigAckOverdue("same-text-push-race") {
		t.Fatal("newest G2 overdue ACK debt was not re-sent")
	}
	if len(resends) != 1 || resends[0].gen != g2 || resends[0].text != text {
		t.Fatalf("overdue resend = %+v, want the same G2 text at generation %d", resends, g2)
	}
}

// TestConfigSyncReconcile_SecondaryNeverPushes guards #2239/#4385: a
// reconnecting SECONDARY must never push its (potentially stale) config over
// the authoritative primary's, regardless of uptime or how many ticks fire.
func TestConfigSyncReconcile_SecondaryNeverPushes(t *testing.T) {
	d, pushes := newReconcileDaemon(t, false /*secondary*/, 120*time.Second)

	for i := 0; i < 10; i++ {
		d.reconcileConfigSyncToPeer("reconcile-loop")
	}
	if got := pushes.Load(); got != 0 {
		t.Fatalf("secondary must never push config; got %d pushes", got)
	}
}

// TestConfigSyncReconcile_DisconnectedSkips verifies no push is attempted while
// no peer connection is up, even on a primary + stable node.
func TestConfigSyncReconcile_DisconnectedSkips(t *testing.T) {
	d, pushes := newReconcileDaemon(t, true /*primary*/, 60*time.Second)
	d.syncPeerConnected.Store(false)

	d.reconcileConfigSyncToPeer("reconcile-loop")
	if got := pushes.Load(); got != 0 {
		t.Fatalf("disconnected node must not push config; got %d pushes", got)
	}
}

// TestConfigSyncReconcile_ReconnectRepushes proves a new connection epoch
// re-pushes: after a satisfied push, a peer reconnect (epoch bump) must make the
// reconciler push again so the fresh connection receives the config.
func TestConfigSyncReconcile_ReconnectRepushes(t *testing.T) {
	d, pushes := newReconcileDaemon(t, true /*primary*/, 60*time.Second)

	d.reconcileConfigSyncToPeer("peer-connect")
	if got := pushes.Load(); got != 1 {
		t.Fatalf("initial push expected; got %d", got)
	}

	// Peer drops and reconnects: onSessionSyncPeerConnected bumps the epoch.
	d.onSessionSyncPeerConnected()
	d.reconcileConfigSyncToPeer("peer-connect")
	if got := pushes.Load(); got != 2 {
		t.Fatalf("reconnect (new epoch) must re-push; got %d pushes", got)
	}
}

// TestConfigSyncReconcile_ConfigChangeRepushes proves a config-generation
// change (a commit while the peer stays connected) re-pushes exactly once.
func TestConfigSyncReconcile_ConfigChangeRepushes(t *testing.T) {
	d, pushes := newReconcileDaemon(t, true /*primary*/, 60*time.Second)

	d.reconcileConfigSyncToPeer("peer-connect")
	if got := pushes.Load(); got != 1 {
		t.Fatalf("initial push expected; got %d", got)
	}

	// New commit → new active generation → the reconciler must push once more.
	commitHostName(t, d.store, "recon-host-2")
	d.reconcileConfigSyncToPeer("reconcile-loop")
	if got := pushes.Load(); got != 2 {
		t.Fatalf("config-generation change must re-push; got %d pushes", got)
	}
	// Generation now satisfied again → no further push.
	d.reconcileConfigSyncToPeer("reconcile-loop")
	if got := pushes.Load(); got != 2 {
		t.Fatalf("stable generation must not re-push; got %d pushes", got)
	}
}

// TestConfigSyncReconcileLoop_FiresOnStabilityCrossing exercises the real
// reconcile loop end-to-end: a primary + connected node that starts too young
// must push once the loop wakes at the stability threshold, and must not storm
// afterwards.
func TestConfigSyncReconcileLoop_FiresOnStabilityCrossing(t *testing.T) {
	d, pushes := newReconcileDaemon(t, true /*primary*/, 0 /*just started*/)
	d.configSyncStable = 30 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.configSyncReconcileLoop(ctx)

	deadline := time.Now().Add(2 * time.Second)
	for pushes.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("reconcile loop did not push after crossing stability threshold")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := pushes.Load(); got != 1 {
		t.Fatalf("reconcile loop must push exactly once; got %d", got)
	}
	// Give the loop several more periodic evaluations; it must stay a no-op.
	time.Sleep(150 * time.Millisecond)
	if got := pushes.Load(); got != 1 {
		t.Fatalf("reconcile loop stormed the control socket; got %d pushes", got)
	}
}
