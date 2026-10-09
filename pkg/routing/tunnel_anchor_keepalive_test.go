package routing

import (
	"errors"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #4071 anchor-path keepalive tests. Before #4071 the production
// userspace-dp anchor path (applyAnchorLocked) unconditionally
// stopKeepaliveLocked'd and never started a runner, so a configured GRE
// `keepalive` was accepted-but-inert on the only runtime dataplane. These
// tests pin that applyAnchorLocked now starts/retains/stops the #1918
// engine by identity exactly like the legacy applyKernelTunnelLocked
// branch, and that the anchor-started runner's LinkSetDown down-action
// fires on threshold. RED-on-revert: reverting to the old unconditional
// stop leaves no runner (TestAnchorKeepaliveStartsRunnerLifecycle).

func anchorKATC(name string, keepalive, retry int) *config.TunnelConfig {
	return &config.TunnelConfig{
		Name:           name,
		AnchorOnly:     true,
		Source:         "198.51.100.1",
		Destination:    "203.0.113.1",
		Keepalive:      keepalive,
		KeepaliveRetry: retry,
	}
}

// runnerFor reads the keepalive runner for a tunnel under mu.
func runnerFor(tm *tunnelManager, name string) (*keepaliveRunner, bool) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	r, ok := tm.keepalives[name]
	return r, ok
}

// --- #4071 core (RED-on-revert): a keepalive anchor config STARTS a
// runner; an unchanged apply RETAINS the same runner (probe state
// survives commits); removing keepalive STOPS it. ---
func TestAnchorKeepaliveStartsRunnerLifecycle(t *testing.T) {
	ops := newFakeLinkOps()
	seedVRF(ops, "ka12083", 100)
	// A pre-existing reusable anchor TUN → reuse-in-place (no recreate),
	// so the runner is started purely by the keepalive reconcile.
	seedAnchor(ops, "gr-0-0-0", 10, 1500)
	tm, _ := newReconcileManager(ops)
	// Inject an alive fake prober so the runner goroutine performs no real
	// network I/O; interval 60s keeps its ticker from firing during the
	// test (identity/lifecycle only — no ticks driven here).
	tm.prober = &fakeProber{results: []probeOutcome{{result: ProbeAlive, kind: UnsupportedNone}}}

	tc := anchorKATC("gr-0-0-0", 60, 3)
	tc.RoutingInstance = "ka12083"

	// Apply 1: keepalive configured → a runner is started (RED on revert:
	// the old applyAnchorLocked stopped it → this map entry is absent).
	if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
		t.Fatalf("Apply 1: %v", err)
	}
	r1, ok := runnerFor(tm, "gr-0-0-0")
	if !ok {
		t.Fatal("anchor path must START a keepalive runner when keepalive is configured (accepted-but-inert regression, #4071)")
	}
	if r1.remote != "203.0.113.1" || r1.source != "198.51.100.1" ||
		r1.transportInstance != "ka12083" || r1.interval != 60 || r1.maxRetries != 3 {
		t.Fatalf("runner identity mismatch: remote=%q source=%q instance=%q interval=%d retries=%d",
			r1.remote, r1.source, r1.transportInstance, r1.interval, r1.maxRetries)
	}

	// Apply 2: identical config → the SAME runner object is retained (a
	// no-op reconcile, not a restart that would reset probe state).
	if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
		t.Fatalf("Apply 2: %v", err)
	}
	r2, ok := runnerFor(tm, "gr-0-0-0")
	if !ok || r2 != r1 {
		t.Fatalf("unchanged apply must retain the same runner (no restart); r1=%p r2=%p ok=%v", r1, r2, ok)
	}

	// Apply 3: keepalive removed → the runner is stopped and removed.
	if err := tm.Apply([]*config.TunnelConfig{anchorKATC("gr-0-0-0", 0, 0)}); err != nil {
		t.Fatalf("Apply 3: %v", err)
	}
	if _, ok := runnerFor(tm, "gr-0-0-0"); ok {
		t.Fatal("removing keepalive must STOP the anchor runner")
	}
}

// --- #4071: a config change (here the tunnel SOURCE, §5c bind) RESTARTS
// the runner — a new runner object with the new identity. ---
func TestAnchorKeepaliveIdentityChangeRestarts(t *testing.T) {
	ops := newFakeLinkOps()
	seedAnchor(ops, "gr-0-0-0", 10, 1500)
	tm, _ := newReconcileManager(ops)
	tm.prober = &fakeProber{results: []probeOutcome{{result: ProbeAlive, kind: UnsupportedNone}}}

	if err := tm.Apply([]*config.TunnelConfig{anchorKATC("gr-0-0-0", 60, 3)}); err != nil {
		t.Fatalf("Apply 1: %v", err)
	}
	r1, ok := runnerFor(tm, "gr-0-0-0")
	if !ok {
		t.Fatal("first apply must start a runner")
	}

	changed := anchorKATC("gr-0-0-0", 60, 3)
	changed.Source = "192.0.2.9" // source change → §5c restart
	if err := tm.Apply([]*config.TunnelConfig{changed}); err != nil {
		t.Fatalf("Apply 2: %v", err)
	}
	r2, ok := runnerFor(tm, "gr-0-0-0")
	if !ok {
		t.Fatal("changed apply must keep a runner")
	}
	if r2 == r1 {
		t.Fatal("a source change must RESTART the runner (new object), not retain the old bind")
	}
	if r2.source != "192.0.2.9" {
		t.Fatalf("restarted runner must bind the new source, got %q", r2.source)
	}

	// Drain the live goroutine.
	tm.mu.Lock()
	tm.stopKeepaliveLocked("gr-0-0-0")
	tm.mu.Unlock()
}

// --- #4071: the anchor-started runner's down-action (LinkSetDown on the
// anchor TUN) fires after MaxRetries dead probes. The recreate from the
// (non-TUN Dummy) seed also bumps the generation. ---
func TestAnchorKeepaliveDownActionOnThreshold(t *testing.T) {
	ops := newKaOps() // records LinkSetUp/Down; LinkByName returns a Dummy
	tm := &tunnelManager{
		ops:       ops,
		vrfBinder: noopVRFBinder{},
		prober:    &fakeProber{results: []probeOutcome{{result: ProbeAlive, kind: UnsupportedNone}}},
	}
	tc := anchorKATC("gr-0-0-0", 1, 3)

	tm.mu.Lock()
	tm.ensureReconcileStateLocked()
	tm.applyAnchorLocked(tc, true)
	runner, ok := tm.keepalives["gr-0-0-0"]
	if !ok {
		tm.mu.Unlock()
		t.Fatal("anchor path must start a runner for the down-action test")
	}
	state := runner.state
	gen := runner.linkGen
	startGen := runner.startGen
	// Stop the live goroutine so our manual ticks are the only driver.
	tm.stopKeepaliveLocked("gr-0-0-0")
	// The Dummy→TUN replacement is a recreate → the generation was bumped,
	// and the runner captured the post-bump value.
	if startGen == 0 {
		tm.mu.Unlock()
		t.Fatal("a recreate must bump the linkGen (startGen should be > 0)")
	}
	if gen.Load() != startGen {
		tm.mu.Unlock()
		t.Fatalf("runner startGen %d != current gen %d", startGen, gen.Load())
	}
	tm.mu.Unlock()

	dead := &fakeProber{results: []probeOutcome{{result: ProbeDead, kind: UnsupportedNone}}}
	// Below threshold (MaxRetries=3): failures climb, no LinkSetDown yet.
	tickN(tm, "gr-0-0-0", state, dead, gen, startGen, 2)
	if ops.downs() != 0 {
		t.Fatalf("no LinkSetDown before MaxRetries, got %d", ops.downs())
	}
	if !state.Up {
		t.Fatal("tunnel must stay up below threshold")
	}
	// Threshold tick → exactly one LinkSetDown, Up=false.
	tm.keepaliveTick("gr-0-0-0", state, dead, gen, startGen)
	if ops.downs() != 1 {
		t.Fatalf("expected exactly one LinkSetDown at threshold, got %d", ops.downs())
	}
	if state.Up {
		t.Fatal("expected Up=false after the anchor keepalive down-action")
	}
}

// --- #4071: a retained runner that currently holds the tunnel DOWN must
// SKIP the LinkSetUp in finishTunnelLocked, so the reconcile does not
// fight the keepalive-down state (ported skip-LinkSetUp-when-held-down
// guard). ---
func TestAnchorKeepaliveRetainedDownSkipsLinkUp(t *testing.T) {
	ops := newFakeLinkOps()
	seedAnchor(ops, "gr-0-0-0", 10, 1500)
	tm, _ := newReconcileManager(ops)

	tm.mu.Lock()
	tm.ensureReconcileStateLocked()
	// Seed a retained runner (matching the config identity) that holds the
	// tunnel DOWN, with a pre-closed done so any drain is instant.
	state := &KeepaliveState{
		Up: false, RemoteAddr: "203.0.113.1", SourceAddr: "198.51.100.1",
		Interval: 60, MaxRetries: 3,
	}
	gen := tm.linkGenForLocked("gr-0-0-0")
	seededDone := make(chan struct{})
	close(seededDone)
	tm.keepalives["gr-0-0-0"] = &keepaliveRunner{
		cancel: func() {}, state: state, done: seededDone,
		remote: "203.0.113.1", source: "198.51.100.1", interval: 60, maxRetries: 3,
		linkGen: gen, startGen: gen.Load(),
	}
	tm.mu.Unlock()

	if err := tm.Apply([]*config.TunnelConfig{anchorKATC("gr-0-0-0", 60, 3)}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(ops.setUpLinks) != 0 {
		t.Fatalf("retained keepalive-down runner must skip LinkSetUp, got %d", len(ops.setUpLinks))
	}
	r, ok := runnerFor(tm, "gr-0-0-0")
	if !ok {
		t.Fatal("matching runner must be retained across the apply")
	}
	if r.state.Up {
		t.Fatal("retained runner must still hold the tunnel down (no fight)")
	}
}

// --- #4071: a TRANSIENT (non-not-found) lookup error must NOT drain the
// live anchor keepalive runner nor bump the generation — the EEXIST-adopt
// fallback keeps the link, so the runner is preserved (mirrors the legacy
// TestApplyTransientLookupKeepsRunner). ---
func TestAnchorKeepaliveTransientLookupKeepsRunner(t *testing.T) {
	ops := newFakeLinkOps()
	ops.byNameHardErr["gr-0-0-0"] = errors.New("transient netlink transport error")
	ops.addExisting = true // LinkAdd reports EEXIST → no create path
	tm, _ := newReconcileManager(ops)

	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.ensureReconcileStateLocked()

	state := &KeepaliveState{
		Up: true, RemoteAddr: "203.0.113.1", SourceAddr: "198.51.100.1",
		Interval: 60, MaxRetries: 3,
	}
	gen := tm.linkGenForLocked("gr-0-0-0")
	startGen := gen.Load()
	seededDone := make(chan struct{})
	close(seededDone)
	tm.keepalives["gr-0-0-0"] = &keepaliveRunner{
		cancel: func() {}, state: state, done: seededDone,
		remote: "203.0.113.1", source: "198.51.100.1", interval: 60, maxRetries: 3,
		linkGen: gen, startGen: startGen,
	}

	tm.applyAnchorLocked(anchorKATC("gr-0-0-0", 60, 3), false)

	if _, ok := tm.keepalives["gr-0-0-0"]; !ok {
		t.Fatal("transient lookup error must NOT drain the anchor keepalive runner")
	}
	if gen.Load() != startGen {
		t.Fatalf("transient lookup error must NOT bump the generation: %d -> %d", startGen, gen.Load())
	}
}

// --- #4076: a TRANSIENT (non-not-found) lookup error whose device has
// SIMULTANEOUSLY VANISHED — so LinkAdd SUCCEEDS (created=true) — is a
// genuine (re)create. The up-front willRecreate classification cannot see
// the vanish THROUGH the transient error (the anchor switch has no
// `default: return`, unlike the legacy branch), so willRecreate stays
// false and the up-front bump is skipped. The created=true bump MUST then
// advance the generation so a stale keepalive runner still holding the
// previous generation drops any in-flight LinkSet* against the fresh
// device (the lock-free gen guard in keepaliveTick). RED-on-revert:
// dropping the created=true bump leaves the generation unbumped here. ---
func TestAnchorKeepaliveTransientLookupVanishedBumpsGen(t *testing.T) {
	ops := newFakeLinkOps()
	// Transient (non-not-found) lookup error → willRecreate stays false.
	ops.byNameHardErr["gr-0-0-0"] = errors.New("transient netlink transport error")
	// Device vanished: addExisting stays false → LinkAdd SUCCEEDS → created=true.
	tm, _ := newReconcileManager(ops)
	// Alive prober + 60s interval so the runner startKeepalive spawns does
	// no real I/O and never ticks during the test.
	tm.prober = &fakeProber{results: []probeOutcome{{result: ProbeAlive, kind: UnsupportedNone}}}

	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.ensureReconcileStateLocked()

	// Seed a STALE runner holding the PREVIOUS generation (pre-closed done
	// so any drain is instant). This is the runner the bump must invalidate.
	gen := tm.linkGenForLocked("gr-0-0-0")
	startGen := gen.Load()
	state := &KeepaliveState{
		Up: true, RemoteAddr: "203.0.113.1", SourceAddr: "198.51.100.1",
		Interval: 60, MaxRetries: 3,
	}
	seededDone := make(chan struct{})
	close(seededDone)
	tm.keepalives["gr-0-0-0"] = &keepaliveRunner{
		cancel: func() {}, state: state, done: seededDone,
		remote: "203.0.113.1", source: "198.51.100.1", interval: 60, maxRetries: 3,
		linkGen: gen, startGen: startGen,
	}

	tm.applyAnchorLocked(anchorKATC("gr-0-0-0", 60, 3), false)

	// The device genuinely vanished + was recreated (LinkAdd succeeded) →
	// the generation MUST have advanced so the stale runner's gen guard
	// drops any in-flight LinkSet* against the new device.
	if gen.Load() <= startGen {
		t.Fatalf("transient-lookup + device-vanished (LinkAdd created) must BUMP the generation: %d -> %d", startGen, gen.Load())
	}

	// Drain the fresh runner startKeepalive spawned (restartKA fired on created).
	tm.stopKeepaliveLocked("gr-0-0-0")
}

// --- #4076 (companion, no-needless-re-resolve): a REUSED (matching)
// anchor TUN across repeated applies must NOT bump the generation. The
// created=true bump fires only on a genuine (re)create, never on a plain
// reconcile, so a stable keepalive is never forced to re-resolve its
// anchor each commit. ---
func TestAnchorKeepaliveReuseDoesNotBumpGen(t *testing.T) {
	ops := newFakeLinkOps()
	seedAnchor(ops, "gr-0-0-0", 10, 1500) // reusable TUN → reuse-in-place (no recreate)
	tm, _ := newReconcileManager(ops)
	tm.prober = &fakeProber{results: []probeOutcome{{result: ProbeAlive, kind: UnsupportedNone}}}

	tc := anchorKATC("gr-0-0-0", 60, 3)
	if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
		t.Fatalf("Apply 1: %v", err)
	}
	tm.mu.Lock()
	gen := tm.linkGenForLocked("gr-0-0-0")
	afterFirst := gen.Load()
	tm.mu.Unlock()

	// Repeated identical applies (steady state, device reused each time)
	// must leave the generation untouched — no needless re-resolve.
	for i := 0; i < 3; i++ {
		if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
			t.Fatalf("Apply %d: %v", i+2, err)
		}
	}

	tm.mu.Lock()
	defer tm.mu.Unlock()
	if got := gen.Load(); got != afterFirst {
		t.Fatalf("steady-state reuse must NOT bump the generation: %d -> %d", afterFirst, got)
	}
	tm.stopKeepaliveLocked("gr-0-0-0")
}
