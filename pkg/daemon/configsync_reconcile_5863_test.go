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
	d.configSyncPushedClaimToken = d.nextConfigSyncClaimTokenLocked()
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

// FAIL-ON-REVERT: a same-text operator push alone must fence a reconcile paused
// after reservation. This keeps the direct G1/G2 race independent of the NACK
// ABA case below.
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
	releaseG1 := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(releaseG1) })
	d.configSyncAfterReserveForTest = func(gen uint64) {
		reserved <- gen
		<-releaseG1
	}

	g1Done := make(chan struct{})
	go func() {
		defer close(g1Done)
		d.reconcileConfigSyncToPeer("same-text-before-operator-push")
	}()
	var g1 uint64
	select {
	case g1 = <-reserved:
	case <-time.After(5 * time.Second):
		t.Fatal("G1 reconcile did not pause after reserving")
	}
	d.configSyncMu.Lock()
	g1Token := d.configSyncPushedClaimToken
	d.configSyncMu.Unlock()
	if g1Token == 0 {
		t.Fatal("G1 reconcile has no claim token")
	}

	if err := d.syncConfigToPeerWithAuthorization(nil); err != nil {
		t.Fatalf("same-text operator push G2: %v", err)
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
	d.configSyncMu.Lock()
	g2Token := d.configSyncPushedClaimToken
	g2MarkerGen := d.configSyncPushedMarkerGen
	g2PushedWireGen := d.configSyncPushedWireGen
	g2PushedText := d.configSyncPushedDigest
	d.configSyncMu.Unlock()
	if g2 <= g1 || g2Token == 0 || g2Token <= g1Token ||
		g2MarkerGen != g2 || g2PushedWireGen != g2 || g2PushedText != text {
		t.Fatalf("G2 generation/token/published state = %d/%d marker=%d wire=%d textMatches=%v; want newer G2 over G1=%d/%d",
			g2, g2Token, g2MarkerGen, g2PushedWireGen, g2PushedText == text, g1, g1Token)
	}
	_, activeText, _ := d.activeConfigSnapshotForPeer()
	if text != activeText {
		t.Fatalf("operator push text differs from active config: pushed=%q active=%q", text, activeText)
	}

	releaseOnce.Do(func() { close(releaseG1) })
	select {
	case <-g1Done:
	case <-time.After(5 * time.Second):
		t.Fatal("G1 reconcile did not finish")
	}
	queueMu.Lock()
	finalQueued := append([]queuedConfig(nil), queued...)
	queueMu.Unlock()
	if len(finalQueued) != 1 || finalQueued[0].gen != g2 || finalQueued[0].text != text {
		t.Fatalf("stale G1 wrote after G2: queued=%+v, want only G2=%d", finalQueued, g2)
	}
	d.configSyncMu.Lock()
	hasG2 := d.configSyncHasPushed &&
		d.configSyncPushedEpoch == d.syncPeerConnEpoch.Load() &&
		d.configSyncPushedGen == configGenerationHash(text) &&
		d.configSyncPushedClaimToken == g2Token &&
		d.configSyncPushedMarkerGen == g2 &&
		d.configSyncPushedWireGen == g2 &&
		d.configSyncPushedDigest == text
	d.configSyncMu.Unlock()
	if !hasG2 {
		t.Fatal("stale G1 replaced or cleared the G2 marker/debt")
	}
}

// FAIL-ON-REVERT: invalidating G2 between a paused G1 and its G3 retry must
// not let the reused pre-reservation tuple alias either claim. The old G1 must
// neither steal G3's marker nor clear it on its failed late check.
func TestConfigSyncReconcileClaimTokenPreventsNACKABA18644(t *testing.T) {
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

	reserved := make(chan uint64, 2)
	releaseG1 := make(chan struct{})
	releaseG3 := make(chan struct{})
	var releaseG1Once, releaseG3Once sync.Once
	unblock := func() {
		releaseG1Once.Do(func() { close(releaseG1) })
		releaseG3Once.Do(func() { close(releaseG3) })
	}
	defer unblock()
	var reserveAttempt atomic.Int32
	d.configSyncAfterReserveForTest = func(gen uint64) {
		switch reserveAttempt.Add(1) {
		case 1:
			reserved <- gen
			<-releaseG1
		case 2:
			reserved <- gen
			<-releaseG3
		default:
			t.Errorf("unexpected reconcile reservation #%d", reserveAttempt.Load())
		}
	}

	startReconcile := func(reason string) <-chan struct{} {
		done := make(chan struct{})
		go func() {
			defer close(done)
			d.reconcileConfigSyncToPeer(reason)
		}()
		return done
	}
	waitReserved := func(name string) uint64 {
		t.Helper()
		select {
		case gen := <-reserved:
			return gen
		case <-time.After(5 * time.Second):
			t.Fatalf("%s did not pause after reserving", name)
			return 0
		}
	}
	waitDone := func(name string, done <-chan struct{}) {
		t.Helper()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("%s did not finish", name)
		}
	}

	g1Done := startReconcile("same-text-before-nack")
	g1 := waitReserved("G1 reconcile")
	d.configSyncMu.Lock()
	g1Token := d.configSyncPushedClaimToken
	d.configSyncMu.Unlock()
	if g1Token == 0 {
		t.Fatal("G1 reconcile has no claim token")
	}

	if err := d.syncConfigToPeerWithAuthorization(nil); err != nil {
		t.Fatalf("same-text operator push G2: %v", err)
	}
	queueMu.Lock()
	if len(queued) != 1 {
		got := len(queued)
		queueMu.Unlock()
		t.Fatalf("operator push wrote %d generations before invalidation, want exactly G2", got)
	}
	g2 := queued[0].gen
	text := queued[0].text
	queueMu.Unlock()
	d.configSyncMu.Lock()
	g2Token := d.configSyncPushedClaimToken
	d.configSyncMu.Unlock()
	if g2 <= g1 || g2Token == 0 || g2Token <= g1Token {
		t.Fatalf("G2 generation/token = %d/%d, want newer than G1 generation/token %d/%d",
			g2, g2Token, g1, g1Token)
	}
	_, activeText, _ := d.activeConfigSnapshotForPeer()
	if text != activeText {
		t.Fatalf("operator push text differs from active config: pushed=%q active=%q", text, activeText)
	}

	// Model the production NACK invalidation, then let a retry claim the same
	// (epoch, hash, zero-wire-generation) tuple while G1 remains paused.
	d.invalidateConfigSyncPushed()
	g3Done := startReconcile("same-text-after-nack")
	g3 := waitReserved("G3 reconcile")
	d.configSyncMu.Lock()
	g3Token := d.configSyncPushedClaimToken
	g3ClaimStillOwned := d.configSyncHasPushed &&
		d.configSyncPushedEpoch == d.syncPeerConnEpoch.Load() &&
		d.configSyncPushedGen == configGenerationHash(text) &&
		d.configSyncPushedMarkerGen == 0
	d.configSyncMu.Unlock()
	if g3 <= g2 || g3Token == 0 || g3Token <= g2Token || g3Token == g1Token || !g3ClaimStillOwned {
		t.Fatalf("G3 claim generation/token = %d/%d, want unique newer claim; marker still owned=%v",
			g3, g3Token, g3ClaimStillOwned)
	}

	// G1's failed post-reservation check must also fail its exact-token clear:
	// otherwise it erases G3's identical pre-reservation tuple.
	releaseG1Once.Do(func() { close(releaseG1) })
	waitDone("G1 reconcile", g1Done)
	queueMu.Lock()
	afterG1 := append([]queuedConfig(nil), queued...)
	queueMu.Unlock()
	if len(afterG1) != 1 || afterG1[0].gen != g2 {
		t.Fatalf("stale G1 wrote after G2/NACK while G3 owned the claim: queued=%+v", afterG1)
	}
	d.configSyncMu.Lock()
	hasG3Claim := d.configSyncHasPushed &&
		d.configSyncPushedEpoch == d.syncPeerConnEpoch.Load() &&
		d.configSyncPushedGen == configGenerationHash(text) &&
		d.configSyncPushedMarkerGen == 0 &&
		d.configSyncPushedClaimToken == g3Token
	d.configSyncMu.Unlock()
	if !hasG3Claim {
		t.Fatal("stale G1's late clear erased or replaced the G3 claim")
	}

	releaseG3Once.Do(func() { close(releaseG3) })
	waitDone("G3 reconcile", g3Done)
	queueMu.Lock()
	finalQueued := append([]queuedConfig(nil), queued...)
	queueMu.Unlock()
	if len(finalQueued) != 2 || finalQueued[0].gen != g2 ||
		finalQueued[1].gen != g3 || finalQueued[1].text != text {
		t.Fatalf("queued generations after G3 = %+v, want only G2=%d then G3=%d", finalQueued, g2, g3)
	}

	d.configSyncMu.Lock()
	markerHash := d.configSyncPushedGen
	markerEpoch := d.configSyncPushedEpoch
	markerWireGen := d.configSyncPushedMarkerGen
	markerToken := d.configSyncPushedClaimToken
	pushedWireGen := d.configSyncPushedWireGen
	pushedText := d.configSyncPushedDigest
	hasPushed := d.configSyncHasPushed
	d.configSyncMu.Unlock()
	if !hasPushed || markerEpoch != d.syncPeerConnEpoch.Load() ||
		markerHash != configGenerationHash(text) || markerToken != g3Token ||
		markerWireGen != g3 || pushedWireGen != g3 || pushedText != text {
		t.Fatalf("final G3 marker/debt mismatch: has=%v epoch=%d hash=%d token=%d marker-wire=%d pushed-wire=%d textMatches=%v; want G3=%d token=%d",
			hasPushed, markerEpoch, markerHash, markerToken, markerWireGen, pushedWireGen, pushedText == text,
			g3, g3Token)
	}

	ss.SetOverdueConfigApplyDebtForTesting(g3, 2*time.Minute)
	type resend struct {
		text string
		gen  uint64
	}
	var resends []resend
	d.configResendForTest = func(text string, gen uint64) {
		resends = append(resends, resend{text: text, gen: gen})
	}
	if !d.repushIfConfigAckOverdue("same-text-nack-aba") {
		t.Fatal("newest G3 overdue ACK debt was not re-sent")
	}
	if len(resends) != 1 || resends[0].gen != g3 || resends[0].text != text {
		t.Fatalf("overdue resend = %+v, want same G3 text at generation %d", resends, g3)
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
