package daemon

import (
	"context"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #2114 (Codex PR #6743 r7-F5): behavioural binders for the event-stream
// fallback loop's per-tick resolution.
//
// r6-F4 made the EventStream provider and the stream instance per-tick but
// bound neither: deleting the `es != wired` re-install block, or reverting
// the provider resolution to a capture-once local, left the whole
// pkg/daemon suite green. The only r6-F4 test called
// wireUserspaceEventStreamCallbacks directly, so reverting THAT hunk was a
// build break rather than an assertion — which does not count as a binder.
// r7-F1 then found the third resolution (the session-delta drainer) was
// still captured at loop entry.
//
// These two tests drive eventStreamFallbackLoop itself, which is what the
// production goroutine at daemon_ha_sync.go runs.

// countingDeltaDrainerDP is a publishable backend that counts
// DrainSessionDeltas calls. It deliberately does NOT implement
// userspaceEventStreamProvider, so the loop sees no stream, reports
// disconnected, and takes the FAST 100 ms fallback branch — the branch on
// which a captured drainer kept polling a disowned backend at 10 Hz.
type countingDeltaDrainerDP struct {
	runtimeOnlyApplyTestDP
	drains atomic.Int64
}

func (c *countingDeltaDrainerDP) DrainSessionDeltas(uint32) ([]dpuserspace.SessionDeltaInfo, dpuserspace.ProcessStatus, error) {
	c.drains.Add(1)
	return nil, dpuserspace.ProcessStatus{}, nil
}

// connectedSyncPairForDrainTest returns a SessionSync whose IsConnected()
// is true, built from a real loopback peer. The fallback loop's drain is
// gated on IsConnected(), so a disconnected stub would make the whole test
// vacuous (it would never reach the drain in EITHER direction).
func connectedSyncPairForDrainTest(t *testing.T, ctx context.Context) *cluster.SessionSync {
	t.Helper()

	// Two free loopback ports; the pair dials each other.
	lnA, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port A: %v", err)
	}
	addrA := lnA.Addr().String()
	lnB, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port B: %v", err)
	}
	addrB := lnB.Addr().String()
	if err := lnA.Close(); err != nil {
		t.Fatalf("release port A: %v", err)
	}
	if err := lnB.Close(); err != nil {
		t.Fatalf("release port B: %v", err)
	}

	local := cluster.NewSessionSync(addrA, addrB, nil)
	peer := cluster.NewSessionSync(addrB, addrA, nil)
	if err := local.Start(ctx); err != nil {
		t.Fatalf("start local session sync: %v", err)
	}
	t.Cleanup(local.Stop)
	if err := peer.Start(ctx); err != nil {
		t.Fatalf("start peer session sync: %v", err)
	}
	t.Cleanup(peer.Stop)

	deadline := time.Now().Add(20 * time.Second)
	for !local.IsConnected() {
		if time.Now().After(deadline) {
			t.Fatal("session sync pair never connected: the drain gate this test " +
				"depends on would never open, so a green run would say nothing")
		}
		time.Sleep(10 * time.Millisecond)
	}
	return local
}

// storeWithActiveConfigForDrainTest returns a store whose ActiveConfig() is
// non-nil (the loop's last gate before the drain).
func storeWithActiveConfigForDrainTest(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.SetFromInput("system host-name drain-binder"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if store.ActiveConfig() == nil {
		t.Fatal("test setup: ActiveConfig() is nil, the drain is unreachable")
	}
	return store
}

func waitForDrainsForDrainTest(t *testing.T, dp *countingDeltaDrainerDP, what string) int64 {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		if n := dp.drains.Load(); n > 0 {
			return n
		}
		if time.Now().After(deadline) {
			t.Fatalf("no DrainSessionDeltas call %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestEventStreamFallbackLoop_DrainerReresolvedPerTick is the F1 binder for
// the DISCONNECTED (fast, 100 ms) branch's resolution, in BOTH directions.
//
// SCOPE — corrected in #6743 r2 (B3). An earlier revision of this comment
// claimed the test failed on hoisting "the resolutions" in
// eventStreamFallbackLoop, plural. It binds exactly ONE of the two:
// countingDeltaDrainerDP deliberately does not implement the event-stream
// provider, so `connected` is false on every tick here and the entire
// `if connected` block — including its own
// `drainer, hasDrainer := d.currentSessionDeltaDrainer()` — is DEAD in this
// fixture. Hoisting only that site to a loop-entry capture left pkg/daemon
// FULL_RC=0 (measured at 710a87569). The connected branch's resolution is
// bound by TestEventStreamFallbackLoop_DrainerReresolvedOnTheConnectedBranch.
//
// Fail-on-revert: hoist the `drainer, hasDrainer := d.currentSessionDeltaDrainer()`
// resolution in the DISCONNECTED branch (the one after the `continue` that
// ends the connected block) back to a single capture at loop entry and this
// test fails on the FIRST assertion — the disowned backend keeps being
// drained at 10 Hz for the goroutine's life, because the loop's commsCtx is
// cancelled only by stopClusterComms, never by a dataplane disown. The
// second assertion covers the reverse arm the same revert also breaks: a
// backend published AFTER loop entry is never picked up, because the
// capture-once shape latched hasDrainer=false.
func TestEventStreamFallbackLoop_DrainerReresolvedPerTick(t *testing.T) {
	runDrainerReresolutionBinder(t, func(d *Daemon, ctx context.Context) {
		d.eventStreamFallbackLoop(ctx, nil)
	})
}

// TestRunUserspaceEventStream_DrainerReresolvedPerTick drives the SAME
// property through the production ENTRY POINT (the function
// daemon_ha_sync.go and daemon_run.go actually launch) rather than through
// eventStreamFallbackLoop directly, so a future entry point that stops
// routing into the shared loop cannot silently lose the per-tick
// resolution.
func TestRunUserspaceEventStream_DrainerReresolvedPerTick(t *testing.T) {
	runDrainerReresolutionBinder(t, func(d *Daemon, ctx context.Context) {
		d.runUserspaceEventStream(ctx)
	})
}

// runDrainerReresolutionBinder drives loop across a disown and a
// republication, asserting the drain follows the #2114 cell in BOTH
// directions.
func runDrainerReresolutionBinder(t *testing.T, loop func(*Daemon, context.Context)) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	d := &Daemon{
		cluster: clusterManagerPrimaryForRGs(0),
		store:   storeWithActiveConfigForDrainTest(t),
	}
	if !d.cluster.IsLocalPrimaryAny() {
		t.Fatal("test setup: node must be primary for some RG or the drain is unreachable")
	}
	d.sessionSync = connectedSyncPairForDrainTest(t, ctx)

	first := &countingDeltaDrainerDP{}
	d.setDataplane(first)

	loopDone := make(chan struct{})
	go func() {
		defer close(loopDone)
		loop(d, ctx)
	}()

	waitForDrainsForDrainTest(t, first, "against the published backend: the loop never reached its drain")

	// Arm 1: the daemon disowns the backend (the bootstrap-exit re-arm
	// failure at daemon_run_naming.go). The drain must stop.
	d.setDataplane(nil)
	settle := first.drains.Load()
	// 1.5 s is 15 ticks of the 100 ms fast cadence — the cadence both loops
	// run at here, since no backend means no stream and connected==false.
	time.Sleep(1500 * time.Millisecond)
	if got := first.drains.Load(); got != settle {
		t.Fatalf("DrainSessionDeltas ran %d more times on the DISOWNED backend after "+
			"setDataplane(nil) (%d -> %d): the loop captured the drainer instead of "+
			"re-resolving it from the #2114 cell", got-settle, settle, got)
	}

	// Arm 2: a healthy backend is republished (the corrected commit's
	// re-arm). The drain must resume against the NEW object.
	second := &countingDeltaDrainerDP{}
	d.setDataplane(second)
	waitForDrainsForDrainTest(t, second, "against the REPUBLISHED backend: the loop latched "+
		"\"no drainer\" at entry and stayed dead for the goroutine's life")

	// The disowned backend must still be untouched.
	if got := first.drains.Load(); got != settle {
		t.Fatalf("the disowned backend was drained again (%d -> %d) after a new one was published",
			settle, got)
	}

	cancel()
	<-loopDone
}

// replaceableStreamDP publishes a swappable EventStream, standing in for the
// commit-confirmed rollback that CLOSES the armed backend's stream and
// constructs a new one on the corrected re-arm.
type replaceableStreamDP struct {
	runtimeOnlyApplyTestDP
	es atomic.Pointer[dpuserspace.EventStream]
}

func (r *replaceableStreamDP) EventStream() *dpuserspace.EventStream { return r.es.Load() }

// startEventStreamForRewireTest starts an EventStream on a private socket
// and returns it with that socket path (EventStream exposes no getter).
func startEventStreamForRewireTest(t *testing.T, ctx context.Context, name string) (*dpuserspace.EventStream, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	es := dpuserspace.NewEventStream(path)
	// Start binds the listener synchronously, so a nil error means the
	// socket is connectable (#6038).
	if err := es.Start(ctx); err != nil {
		t.Fatalf("start event stream %s: %v", name, err)
	}
	t.Cleanup(es.Close)
	return es, path
}

// TestEventStreamFallbackLoop_RewiresReplacementStream binds the r6-F4
// re-install hunk, and ONLY that hunk.
//
// Fail-on-revert: delete the `if es != nil && es != wired { ... }` block in
// eventStreamFallbackLoop and no ACK ever comes back — the replacement
// stream's events sit in the callback-not-ready queue, which is exactly the
// post-rollback symptom r6-F4 describes.
//
// It deliberately does NOT bind the per-tick PROVIDER resolution: the
// backend is published BEFORE the loop starts, so a capture-once provider
// would resolve to the same object and reach the same stream. That arm is
// TestEventStreamFallbackLoop_ProviderResolvedPerTick, which is
// correspondingly built so this hunk's removal does not disturb it — one
// fixture, one arm, in each direction.
func TestEventStreamFallbackLoop_RewiresReplacementStream(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	wired, _ := startEventStreamForRewireTest(t, ctx, "w")
	replacement, replacementPath := startEventStreamForRewireTest(t, ctx, "r")

	// A cluster that is primary for NOTHING: handleEventStreamDelta then
	// takes its "ignored (not primary for any RG)" arm and ACKs, so the ACK
	// proves only that the CALLBACK ran — which is the property under test.
	d := &Daemon{
		cluster:     cluster.NewManager(0, 1),
		sessionSync: cluster.NewSessionSync(":0", "127.0.0.1:1", nil),
		store:       storeWithActiveConfigForDrainTest(t),
	}
	if d.cluster.IsLocalPrimaryAny() {
		t.Fatal("test setup: the cluster must not be primary for any RG")
	}

	backend := &replaceableStreamDP{}
	backend.es.Store(replacement)
	d.setDataplane(backend)

	loopDone := make(chan struct{})
	go func() {
		defer close(loopDone)
		// wired is the stream the callbacks were installed on at startup;
		// the published backend now exposes a DIFFERENT instance.
		d.eventStreamFallbackLoop(ctx, wired)
	}()

	conn, err := dialEventStreamForRewireTest(t, replacementPath)
	if err != nil {
		t.Fatalf("dial replacement event stream: %v", err)
	}
	defer conn.Close()

	writeEventFrameForWiringTest(t, conn, dpuserspace.EventTypeSessionOpen, 1,
		buildSessionOpenFrameV4PayloadForWiringTest())
	// SetOnEvent flushes the callback-not-ready queue, so this does not race
	// the loop's first tick: the ACK arrives whenever the re-install lands.
	waitForAckSeqForWiringTest(t, conn, 1)

	cancel()
	<-loopDone
}

// TestEventStreamFallbackLoop_ProviderResolvedPerTick binds the r6-F4
// per-tick PROVIDER resolution in isolation.
//
// The loop is handed the SAME stream instance it will later observe
// (wired == the published backend's stream), so the `es != wired`
// re-install block is a no-op throughout and deleting it changes nothing
// here. The only thing under test is whether a backend published AFTER
// loop entry is seen at all: the observable is d.eventStreamConnected,
// which the loop sets from `es != nil && es.IsConnected()`.
//
// Fail-on-revert: hoist `d.currentEventStreamProvider()` back out of the
// tick into a loop-entry capture and this fails — the cell is EMPTY when
// the loop starts (the production shape after a bootstrap-arm failure, or
// simply before the helper is armed), so the captured provider is nil for
// the goroutine's life and the stream is never observed.
func TestEventStreamFallbackLoop_ProviderResolvedPerTick(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	es, path := startEventStreamForRewireTest(t, ctx, "late.sock")

	// A live client, so es.IsConnected() is true once the loop looks at it.
	conn, err := dialEventStreamForRewireTest(t, path)
	if err != nil {
		t.Fatalf("dial event stream: %v", err)
	}
	defer conn.Close()

	d := &Daemon{
		cluster:     cluster.NewManager(0, 1),
		sessionSync: cluster.NewSessionSync(":0", "127.0.0.1:1", nil),
		store:       storeWithActiveConfigForDrainTest(t),
	}

	loopDone := make(chan struct{})
	go func() {
		defer close(loopDone)
		// Nothing is published yet. `wired` is the stream that will later
		// appear, so the re-install block never fires and this test is
		// blind to it.
		d.eventStreamFallbackLoop(ctx, es)
	}()

	// Let the loop take several ticks against the empty cell first.
	time.Sleep(300 * time.Millisecond)
	if d.eventStreamConnected.Load() {
		t.Fatal("eventStreamConnected is true with an EMPTY cell: the loop is not " +
			"reading the stream out of the #2114 cell at all")
	}

	backend := &replaceableStreamDP{}
	backend.es.Store(es)
	d.setDataplane(backend)

	deadline := time.Now().Add(20 * time.Second)
	for !d.eventStreamConnected.Load() {
		if time.Now().After(deadline) {
			t.Fatal("the loop never observed the stream of a backend published AFTER " +
				"loop entry: the event-stream provider was captured once instead of " +
				"being re-resolved from the #2114 cell every tick")
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	<-loopDone
}

// TestRunUserspaceEventStream_WiresAfterEmptyCellAtEntry binds INITIAL
// RECOVERY, the fourth independent regression in this chain (Codex r7-F1b).
//
// The entry point used to open with a one-shot
// `d.dataplane().(userspaceEventStreamProvider)` probe and, on a miss, hand
// off permanently to a wiring-free polling loop. An empty cell at that
// instant latched the daemon out of the event stream for the life of the
// process: a healthy provider published a moment later — the corrected
// commit after a bootstrap-arm failure — never had its callbacks installed,
// so every helper event accumulated in the callback-not-ready queue.
//
// Fail-on-revert: restore that pre-check (or route the HA branch anywhere
// that resolves the provider once) and no ACK ever comes back. Note this is
// NOT covered by the per-tick drainer or provider binders: with the
// pre-check in place the loop those tests exercise is never entered.
func TestRunUserspaceEventStream_WiresAfterEmptyCellAtEntry(t *testing.T) {
	runEmptyCellWiringBinder(t, true)
}

// TestRunUserspaceEventStream_StandaloneWiresAfterEmptyCellAtEntry is the
// same property on the STANDALONE path (d.cluster == nil, daemon_run.go).
// There is no session sync to poll there, but the helper's dataplane events
// still reach the event buffer through these callbacks — so collapsing the
// entry point into the HA fallback loop (which returns immediately without
// a cluster) would silently kill standalone event delivery. This is the
// guard against that.
func TestRunUserspaceEventStream_StandaloneWiresAfterEmptyCellAtEntry(t *testing.T) {
	runEmptyCellWiringBinder(t, false)
}

func runEmptyCellWiringBinder(t *testing.T, withCluster bool) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	es, path := startEventStreamForRewireTest(t, ctx, "l")

	d := &Daemon{store: storeWithActiveConfigForDrainTest(t)}
	if withCluster {
		// Primary for NOTHING, so handleEventStreamDelta takes its
		// "ignored (not primary for any RG)" arm and ACKs — the ACK then
		// proves only that the CALLBACK ran, which is the property here.
		d.cluster = cluster.NewManager(0, 1)
		d.sessionSync = cluster.NewSessionSync(":0", "127.0.0.1:1", nil)
	}

	// The cell is EMPTY when the entry point starts. This is the production
	// shape after a bootstrap-arm failure cleared it, and also simply
	// before the helper is armed.
	if d.dataplane() != nil {
		t.Fatal("test setup: the cell must be empty at entry")
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		d.runUserspaceEventStream(ctx)
	}()

	conn, err := dialEventStreamForRewireTest(t, path)
	if err != nil {
		t.Fatalf("dial event stream: %v", err)
	}
	defer conn.Close()

	// Only NOW does a healthy provider appear.
	time.Sleep(200 * time.Millisecond)
	backend := &replaceableStreamDP{}
	backend.es.Store(es)
	d.setDataplane(backend)

	writeEventFrameForWiringTest(t, conn, dpuserspace.EventTypeSessionOpen, 1,
		buildSessionOpenFrameV4PayloadForWiringTest())
	waitForAckSeqForWiringTest(t, conn, 1)

	cancel()
	<-done
}

// dialEventStreamForRewireTest dials the stream's socket, retrying until the
// listener is up.
func dialEventStreamForRewireTest(t *testing.T, socketPath string) (net.Conn, error) {
	t.Helper()
	deadline := wiringTestDeadline(t)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := net.Dial("unix", socketPath)
		if err == nil {
			return conn, nil
		}
		lastErr = err
		time.Sleep(10 * time.Millisecond)
	}
	return nil, lastErr
}

// Compile-time reminders that the fakes above really do carry the optional
// capabilities the loop probes for; a signature drift would otherwise turn
// both tests into vacuous no-ops (the loop would simply `continue`).
var (
	_ dataplane.RuntimeDataPlane   = (*countingDeltaDrainerDP)(nil)
	_ userspaceSessionDeltaDrainer = (*countingDeltaDrainerDP)(nil)
	_ dataplane.RuntimeDataPlane   = (*replaceableStreamDP)(nil)
	_ userspaceEventStreamProvider = (*replaceableStreamDP)(nil)
)

// --- #6743 r2 B3: the CONNECTED branch's drainer resolution -------------

// connectedStreamDrainerDP is a publishable backend that BOTH counts
// DrainSessionDeltas calls and exposes an event stream. It is the
// complement of countingDeltaDrainerDP: because the stream is connected,
// eventStreamFallbackLoop reports connected==true on every tick and takes
// the RECONCILE branch (5 s cadence) — the branch whose own drainer
// resolution countingDeltaDrainerDP can never reach.
type connectedStreamDrainerDP struct {
	runtimeOnlyApplyTestDP
	es     *dpuserspace.EventStream
	drains atomic.Int64
}

func (c *connectedStreamDrainerDP) EventStream() *dpuserspace.EventStream { return c.es }

func (c *connectedStreamDrainerDP) DrainSessionDeltas(uint32) ([]dpuserspace.SessionDeltaInfo, dpuserspace.ProcessStatus, error) {
	c.drains.Add(1)
	return nil, dpuserspace.ProcessStatus{}, nil
}

// connectedEventStreamForDrainTest starts an event stream and dials it, so
// IsConnected() is true. The client conn is kept open for the test's life:
// if it dropped, the loop would fall to the DISCONNECTED branch and the
// test would silently measure the already-bound site instead.
func connectedEventStreamForDrainTest(t *testing.T, ctx context.Context) *dpuserspace.EventStream {
	t.Helper()
	es, path := startEventStreamForRewireTest(t, ctx, "c")
	conn, err := dialEventStreamForRewireTest(t, path)
	if err != nil {
		t.Fatalf("dial event stream: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	deadline := time.Now().Add(20 * time.Second)
	for !es.IsConnected() {
		if time.Now().After(deadline) {
			t.Fatal("event stream never reported a connected client: the loop would take " +
				"the DISCONNECTED branch and this test would bind the wrong site")
		}
		time.Sleep(10 * time.Millisecond)
	}
	return es
}

func waitForDrainsOnConnectedBranch(t *testing.T, dp *connectedStreamDrainerDP, what string) int64 {
	t.Helper()
	// The connected branch runs at the 5 s reconcile cadence, so the
	// deadline has to clear several of those ticks.
	deadline := time.Now().Add(40 * time.Second)
	for {
		if n := dp.drains.Load(); n > 0 {
			return n
		}
		if time.Now().After(deadline) {
			t.Fatalf("no DrainSessionDeltas call %s", what)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// TestEventStreamFallbackLoop_DrainerReresolvedOnTheConnectedBranch binds
// the resolution at the reconcile-cadence site (#6743 r2 B3).
//
// WHY IT NEEDED ITS OWN FIXTURE. The sibling binder above is built on a
// backend with no event stream, so `connected` is false on every tick and
// the whole `if connected` block is unreachable there — the mutated
// behaviour is not merely unasserted, it is unexecuted. Measured at
// 710a87569: hoisting ONLY the connected branch's
// `drainer, hasDrainer := d.currentSessionDeltaDrainer()` to a loop-entry
// capture left pkg/daemon FULL_RC=0.
//
// WHY THE ARMS ARE A REPUBLICATION, NOT A DISOWN. A disown empties the
// cell, which also removes the provider, which flips `connected` to false
// and drops the loop into the already-bound fast branch — so a disown
// cannot observe this site at all. The commit-confirmed rollback's
// corrected re-arm CAN: it publishes a DIFFERENT backend while the stream
// stays up. The fixture therefore holds the stream constant across the
// swap, which is exactly what isolates the drainer resolution from the
// provider and stream resolutions the sibling tests already cover.
//
// Fail-on-revert: hoist that one resolution to loop entry. The captured
// drainer keeps draining the SUPERSEDED backend at the 0.2 Hz reconcile
// cadence — the r7-F1 escape, slower — and the newly published one is
// never drained at all, so its deltas never reach session sync.
func TestEventStreamFallbackLoop_DrainerReresolvedOnTheConnectedBranch(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	es := connectedEventStreamForDrainTest(t, ctx)

	d := &Daemon{
		cluster: clusterManagerPrimaryForRGs(0),
		store:   storeWithActiveConfigForDrainTest(t),
	}
	if !d.cluster.IsLocalPrimaryAny() {
		t.Fatal("test setup: node must be primary for some RG or the drain is unreachable")
	}
	d.sessionSync = connectedSyncPairForDrainTest(t, ctx)

	first := &connectedStreamDrainerDP{es: es}
	d.setDataplane(first)

	loopDone := make(chan struct{})
	go func() {
		defer close(loopDone)
		// wired == es, so the `es != wired` re-install block never fires
		// and this test is blind to it — one fixture, one arm.
		d.eventStreamFallbackLoop(ctx, es)
	}()

	waitForDrainsOnConnectedBranch(t, first, "against the published backend: the loop "+
		"never reached the reconcile drain")

	// CONTROL: the branch under test is the CONNECTED one. Without this a
	// dropped client conn would silently move the whole test onto the fast
	// branch, whose resolution is bound elsewhere.
	if !d.eventStreamConnected.Load() {
		t.Fatal("the loop is reporting DISCONNECTED: this test is measuring the fast " +
			"branch, not the reconcile branch it exists to bind")
	}

	// The corrected re-arm publishes a NEW backend behind the SAME stream.
	second := &connectedStreamDrainerDP{es: es}
	d.setDataplane(second)

	waitForDrainsOnConnectedBranch(t, second, "against the REPUBLISHED backend: the "+
		"reconcile branch captured its drainer at loop entry, so the superseded backend "+
		"kept being drained and the new one never was")

	if !d.eventStreamConnected.Load() {
		t.Fatal("the loop dropped to DISCONNECTED mid-test: the republication arm did " +
			"not measure the reconcile branch")
	}

	// The superseded backend must stop being drained. Sample AFTER the new
	// one has been seen, then let a full reconcile tick pass.
	settle := first.drains.Load()
	time.Sleep(6 * time.Second)
	if got := first.drains.Load(); got != settle {
		t.Fatalf("DrainSessionDeltas ran %d more times on the SUPERSEDED backend (%d -> %d) "+
			"after a new one was published: the reconcile branch captured the drainer "+
			"instead of re-resolving it from the #2114 cell", got-settle, settle, got)
	}

	cancel()
	<-loopDone
}

// --- #16627: the connected drain must not replay already-streamed deltas ---

// replayDrainer16627 is a publishable backend that is BOTH a connected
// event-stream provider and a session-delta drainer returning a fixed
// batch. It models a helper whose RPC-fallback buffer still holds deltas
// the stream already delivered (a pre-reconnect backlog, or an older
// helper that mirrors unconditionally).
type replayDrainer16627 struct {
	runtimeOnlyApplyTestDP
	es      *dpuserspace.EventStream
	drains  atomic.Int64
	mu      sync.Mutex
	batches [][]dpuserspace.SessionDeltaInfo
	// release gates when the replay batch is served: the test holds it
	// until the stream sequence has been applied, mirroring production
	// where the helpers fallback copy of a streamed delta can only be
	// drained after that delta was streamed (and applied) first.
	releaseOnce sync.Once
	releaseCh   chan struct{}
}

func (r *replayDrainer16627) release() {
	r.releaseOnce.Do(func() { close(r.releaseCh) })
}

func (r *replayDrainer16627) EventStream() *dpuserspace.EventStream { return r.es }

func (r *replayDrainer16627) DrainSessionDeltas(uint32) ([]dpuserspace.SessionDeltaInfo, dpuserspace.ProcessStatus, error) {
	if r.releaseCh != nil {
		<-r.releaseCh
	}
	r.drains.Add(1)
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.batches) == 0 {
		return nil, dpuserspace.ProcessStatus{}, nil
	}
	b := r.batches[0]
	r.batches = r.batches[1:]
	return b, dpuserspace.ProcessStatus{}, nil
}

// TestConnectedDrainDiscardsStreamedReplay16627 is the #16627 daemon-level
// acceptance cell. A stream sequence (open S1, close S1, open successor S2)
// is applied to a real sender SessionSync and its frames to a real receiver
// SessionSync, leaving the receiver in the stream-only state (S2 present,
// egress from S2). A replay of ANY prefix or suffix of that sequence
// through the connected fallback drain must leave the receiver in exactly
// that state — the drain discards already-streamed deltas instead of
// re-stamping them with fresh generations.
//
// Fail-on-revert: route the connected arm back through
// drainUserspaceSessionDeltasLocked (queueing) and the {open S1} replay
// resurrects the closed S1 (receiver reports S1's egress) while the
// {close S1} replay deletes the live same-key S2. Discarding WITHOUT
// the StreamSeq/watermark gate (blanket discard) fails the
// unsequenced-replay subtest below and the discard unit cells.
func TestConnectedDrainDiscardsStreamedReplay16627(t *testing.T) {
	open1 := transitOpen9767() // S1: egress ifindex 12
	open1.StreamSeq = 1
	// S2 is the SAME-KEY successor of S1: identical tuple (same SrcPort),
	// reincarnated after S1 closed, differing only in its egress. A
	// replayed close of S1 therefore names S2's exact key — with a
	// different SrcPort the close replay would miss S2 entirely and the
	// successor-deletion arm would be test-only-green.
	open2 := open1
	open2.StreamSeq = 3
	open2.EgressIfindex = 13
	open2.TXIfindex = 13
	close1 := open1
	close1.StreamSeq = 2
	close1.Event = "close"

	cases := []struct {
		name   string
		replay []dpuserspace.SessionDeltaInfo
	}{
		{"replay open S1 only", []dpuserspace.SessionDeltaInfo{open1}},
		{"replay close S1 only", []dpuserspace.SessionDeltaInfo{close1}},
		{"replay open+close S1", []dpuserspace.SessionDeltaInfo{open1, close1}},
		{"replay open S1 close S1 open S2", []dpuserspace.SessionDeltaInfo{open1, close1, open2}},
		{"replay open S2 only", []dpuserspace.SessionDeltaInfo{open2}},
		// Standalone suffix: the tail of the sequence on its own. A
		// replay need not be a prefix — any contiguous tail the drain
		// happens to pop must be equally inert.
		{"replay close S1 open S2 suffix", []dpuserspace.SessionDeltaInfo{close1, open2}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			es := connectedEventStreamForDrainTest(t, ctx)

			d, ss, _ := resyncFixture9767(t)
			d.sessionSync = ss
			zoneIDs := buildZoneIDs(d.store.ActiveConfig())
			key2, _, ok := userspaceSessionFromDeltaV4(open2, zoneIDs)
			if !ok {
				t.Fatal("setup: successor delta did not convert")
			}

			// Stream-only sequence: open S1, close S1, open S2.
			for i, step := range []struct {
				typ   uint8
				delta dpuserspace.SessionDeltaInfo
			}{
				{dpuserspace.EventTypeSessionOpen, open1},
				{dpuserspace.EventTypeSessionClose, close1},
				{dpuserspace.EventTypeSessionOpen, open2},
			} {
				if !d.handleEventStreamDelta(step.typ, step.delta) {
					t.Fatalf("stream step %d returned not-ready", i)
				}
			}

			receiverStore := newOrderingSessionStore9631()
			receiver := cluster.NewSessionSync("127.0.0.1:0", "127.0.0.1:1", nil)
			receiver.SetRuntimeDomains(receiverStore, nil)
			applyToReceiver := func(what string) {
				t.Helper()
				if _, err := ss.ApplyQueuedMessagesForTesting(receiver); err != nil {
					t.Fatalf("%s: apply queued messages: %v", what, err)
				}
			}
			applyToReceiver("stream sequence")
			// The three stream deltas were applied in order, so the
			// stream's applied watermark is 3 — what the read loop
			// would have recorded had these arrived as binary frames.
			es.SetLastAppliedSequenceForTesting(3)
			streamVal, streamOK := receiverStore.v4[key2]
			if !streamOK {
				t.Fatal("stream-only control: receiver must hold the successor S2")
			}
			streamCount := len(receiverStore.v4)

			// Replay through the production connected fallback loop.
			backend := &replayDrainer16627{es: es, batches: [][]dpuserspace.SessionDeltaInfo{tc.replay}, releaseCh: make(chan struct{})}
			d.setDataplane(backend)
			loopDone := make(chan struct{})
			go func() {
				defer close(loopDone)
				d.eventStreamFallbackLoop(ctx, es)
			}()
			backend.release()
			deadline := time.Now().Add(40 * time.Second)
			for backend.drains.Load() == 0 {
				if time.Now().After(deadline) {
					cancel()
					<-loopDone
					t.Fatal("connected fallback loop never drained the replay backend")
				}
				time.Sleep(25 * time.Millisecond)
			}
			// One drain is enough: the batch is discarded under the same
			// lock the stream callback queues with, so once the drain has
			// run the replay (if queued) is already in the send queue.
			cancel()
			<-loopDone
			if !d.eventStreamConnected.Load() && backend.drains.Load() == 0 {
				t.Fatal("loop never reported connected")
			}
			applyToReceiver("replay")
			gotVal, gotOK := receiverStore.v4[key2]
			if !gotOK {
				t.Fatalf("#16627: replay %q deleted the live successor S2 from the receiver", tc.name)
			}
			// Compare the egress identity, not the whole value: a queued
			// replay re-stamps timing fields, so value inequality alone
			// would be test-only noise. The resurrection signature is
			// S1's egress (12) replacing S2's (13) under the same key.
			if gotVal.FibIfindex != streamVal.FibIfindex {
				t.Fatalf("#16627: replay %q changed the receiver state: got fib=%d, stream-only fib=%d "+
					"(a replayed open resurrected the closed S1 over S2)", tc.name, gotVal.FibIfindex, streamVal.FibIfindex)
			}
			if len(receiverStore.v4) != streamCount {
				t.Fatalf("#16627: replay %q changed the receiver session count: got %d, stream-only %d",
					tc.name, len(receiverStore.v4), streamCount)
			}
		})
	}

	// Disconnected control: with no stream, the SAME drain path must still
	// queue fallback deltas (the fallback leg is authoritative while down).
	t.Run("disconnected drain still queues", func(t *testing.T) {
		d, ss, _ := resyncFixture9767(t)
		drainer := &fakeUserspaceDeltaDrainer{batches: [][]dpuserspace.SessionDeltaInfo{{open1}}}
		queued, err := d.drainUserspaceSessionDeltasWithConfig(drainer, d.store.ActiveConfig(), 1)
		if err != nil {
			t.Fatalf("disconnected drain: %v", err)
		}
		if queued != 1 {
			t.Fatalf("disconnected drain queued %d, want 1 (fallback must carry deltas while the stream is down)", queued)
		}
		if types := queuedTypes9767(ss); len(types) != 1 || types[0] != "session_v4" {
			t.Fatalf("disconnected drain send queue = %v, want [session_v4]", types)
		}
	})
}

// TestConnectedDrainQueuesUnsequencedReplay16627 pins the other half of
// the #16627 gate through the production connected loop: a fallback
// delta the stream never carried (StreamSeq 0) must still QUEUE while
// connected. A blanket discard-while-connected fails this — it would
// silently drop fallback-only deltas (produced while the stream was
// down, CommandExport copies, or deltas whose lossless enqueue failed).
func TestConnectedDrainQueuesUnsequencedReplay16627(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	es := connectedEventStreamForDrainTest(t, ctx)

	d, ss, _ := resyncFixture9767(t)
	d.sessionSync = ss

	open := transitOpen9767() // StreamSeq 0: never stream-carried
	backend := &replayDrainer16627{es: es, batches: [][]dpuserspace.SessionDeltaInfo{{open}}}
	d.setDataplane(backend)
	loopDone := make(chan struct{})
	go func() {
		defer close(loopDone)
		d.eventStreamFallbackLoop(ctx, es)
	}()
	deadline := time.Now().Add(40 * time.Second)
	for backend.drains.Load() == 0 {
		if time.Now().After(deadline) {
			cancel()
			<-loopDone
			t.Fatal("connected fallback loop never drained the replay backend")
		}
		time.Sleep(25 * time.Millisecond)
	}
	cancel()
	<-loopDone
	if types := queuedTypes9767(ss); len(types) != 1 || types[0] != "session_v4" {
		t.Fatalf("#16627: unsequenced (StreamSeq 0) fallback delta through the connected drain queued %v, "+
			"want [session_v4] — discard must be gated on the applied watermark, not on connectedness", types)
	}
}
