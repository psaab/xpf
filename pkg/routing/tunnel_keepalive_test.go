package routing

import (
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// fakeProber is a deterministic tunnelProber for keepalive tests. It
// returns a scripted sequence of results, recording the bind source it
// was asked to probe from (§5c assertions).
type fakeProber struct {
	mu      sync.Mutex
	results []probeOutcome
	idx     int
	// lastSource records the most recent source bind argument.
	lastSource string
	sources    []string
	calls      int
}

type probeOutcome struct {
	result ProbeResult
	kind   UnsupportedKind
	reason string
}

func (p *fakeProber) Probe(source, dst string, seq int, nonce []byte, deadline time.Duration) (ProbeResult, UnsupportedKind, string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	p.lastSource = source
	p.sources = append(p.sources, source)
	if len(p.results) == 0 {
		return ProbeAlive, UnsupportedNone, ""
	}
	o := p.results[p.idx%len(p.results)]
	p.idx++
	return o.result, o.kind, o.reason
}

// kaOps is a controllable linkOps for keepalive tick tests: it counts
// LinkSetUp/LinkSetDown, can inject errors on them, can block inside one
// of them (for lock-scope / drain tests), and can fail LinkByName.
type kaOps struct {
	mu sync.Mutex

	setUps   int
	setDowns int

	setUpErr   error
	setDownErr error

	byNameErr error
	delErr    error

	// blockDown, when non-nil, makes LinkSetDown block until released is
	// closed; entered is closed once LinkSetDown is inside the block.
	blockDown chan struct{}
	entered   chan struct{}
}

func newKaOps() *kaOps { return &kaOps{} }

func (o *kaOps) LinkByName(name string) (netlink.Link, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.byNameErr != nil {
		return nil, o.byNameErr
	}
	return &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name, Index: 1}}, nil
}

func (o *kaOps) LinkAdd(netlink.Link) error { return nil }
func (o *kaOps) LinkDel(netlink.Link) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.delErr
}
func (o *kaOps) LinkSetMaster(netlink.Link, netlink.Link) error { return nil }
func (o *kaOps) LinkSetNoMaster(netlink.Link) error             { return nil }
func (o *kaOps) LinkSetMTU(netlink.Link, int) error             { return nil }
func (o *kaOps) LinkList() ([]netlink.Link, error)              { return nil, nil }
func (o *kaOps) AddrAdd(netlink.Link, *netlink.Addr) error      { return nil }
func (o *kaOps) AddrDel(netlink.Link, *netlink.Addr) error      { return nil }
func (o *kaOps) AddrList(netlink.Link, int) ([]netlink.Addr, error) {
	return nil, nil
}

func (o *kaOps) LinkSetUp(netlink.Link) error {
	o.mu.Lock()
	o.setUps++
	err := o.setUpErr
	o.mu.Unlock()
	return err
}

func (o *kaOps) LinkSetDown(netlink.Link) error {
	o.mu.Lock()
	o.setDowns++
	block := o.blockDown
	entered := o.entered
	err := o.setDownErr
	o.mu.Unlock()
	if block != nil {
		if entered != nil {
			close(entered)
		}
		<-block
	}
	return err
}

func (o *kaOps) ups() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.setUps
}

func (o *kaOps) downs() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.setDowns
}

// newKAState builds a KeepaliveState and a fresh gen token for tick
// tests.
func newKAState(up bool, maxRetries, interval int) (*KeepaliveState, *atomic.Uint64) {
	return &KeepaliveState{
		Up:         up,
		RemoteAddr: "203.0.113.1",
		SourceAddr: "198.51.100.1",
		Interval:   interval,
		MaxRetries: maxRetries,
	}, &atomic.Uint64{}
}

func tickN(t *tunnelManager, name string, state *KeepaliveState, prober tunnelProber, gen *atomic.Uint64, startGen uint64, n int) {
	for i := 0; i < n; i++ {
		t.keepaliveTick(name, state, prober, gen, startGen)
	}
}

// --- §9 Alive: stays up, zero LinkSet* ---
func TestKeepaliveAliveStaysUp(t *testing.T) {
	ops := newKaOps()
	tm := &tunnelManager{ops: ops}
	state, gen := newKAState(true, 3, 1)
	prober := &fakeProber{results: []probeOutcome{{result: ProbeAlive, kind: UnsupportedNone}}}

	tickN(tm, "gr0", state, prober, gen, 0, 5)

	if ops.ups() != 0 || ops.downs() != 0 {
		t.Fatalf("alive ticks must issue no LinkSet*: ups=%d downs=%d", ops.ups(), ops.downs())
	}
	if !state.Up {
		t.Fatal("state should remain up")
	}
	if state.Failures != 0 {
		t.Fatalf("failures should be 0, got %d", state.Failures)
	}
}

// --- §9 Dead × MaxRetries: exactly one LinkSetDown, Up=false ---
func TestKeepaliveDeadGoesDownOnce(t *testing.T) {
	ops := newKaOps()
	tm := &tunnelManager{ops: ops}
	state, gen := newKAState(true, 3, 1)
	prober := &fakeProber{results: []probeOutcome{{result: ProbeDead, kind: UnsupportedNone}}}

	// First two dead ticks: increment failures, no transition.
	tickN(tm, "gr0", state, prober, gen, 0, 2)
	if ops.downs() != 0 {
		t.Fatalf("no down before MaxRetries: downs=%d", ops.downs())
	}
	if !state.Up {
		t.Fatal("still up before MaxRetries")
	}
	// Third dead tick crosses the threshold.
	tm.keepaliveTick("gr0", state, prober, gen, 0)
	if ops.downs() != 1 {
		t.Fatalf("expected exactly one LinkSetDown, got %d", ops.downs())
	}
	if state.Up {
		t.Fatal("expected Up=false after MaxRetries dead")
	}
	if state.Failures != 3 {
		t.Fatalf("expected Failures=3, got %d", state.Failures)
	}
	// Further dead ticks: no additional LinkSetDown (already down).
	tickN(tm, "gr0", state, prober, gen, 0, 3)
	if ops.downs() != 1 {
		t.Fatalf("expected still exactly one LinkSetDown, got %d", ops.downs())
	}
}

// --- §9 Dead then Alive: exactly one LinkSetUp on recovery ---
func TestKeepaliveRecoversUpOnce(t *testing.T) {
	ops := newKaOps()
	tm := &tunnelManager{ops: ops}
	state, gen := newKAState(true, 3, 1)
	dead := &fakeProber{results: []probeOutcome{{result: ProbeDead, kind: UnsupportedNone}}}
	tickN(tm, "gr0", state, dead, gen, 0, 3) // down
	if state.Up || ops.downs() != 1 {
		t.Fatalf("precondition: want down once; up=%v downs=%d", state.Up, ops.downs())
	}

	alive := &fakeProber{results: []probeOutcome{{result: ProbeAlive, kind: UnsupportedNone}}}
	tm.keepaliveTick("gr0", state, alive, gen, 0)
	if ops.ups() != 1 {
		t.Fatalf("expected exactly one LinkSetUp on recovery, got %d", ops.ups())
	}
	if !state.Up || state.Failures != 0 {
		t.Fatalf("expected up + failures reset; up=%v failures=%d", state.Up, state.Failures)
	}
	// Further alive ticks: no extra up.
	tickN(tm, "gr0", state, alive, gen, 0, 3)
	if ops.ups() != 1 {
		t.Fatalf("expected still one LinkSetUp, got %d", ops.ups())
	}
}

func TestKeepaliveLivenessCallbackTracksCommittedTransitions11423(t *testing.T) {
	ops := newKaOps()
	tm := &tunnelManager{ops: ops}
	state, gen := newKAState(true, 3, 1)
	var transitions []bool
	tm.setLivenessChangeCallback(func(_ string, up bool) {
		transitions = append(transitions, up)
	})

	dead := &fakeProber{results: []probeOutcome{{result: ProbeDead, kind: UnsupportedNone}}}
	tickN(tm, "gr0", state, dead, gen, 0, 3)
	if len(transitions) != 1 || transitions[0] {
		t.Fatalf("down transitions = %v, want [false]", transitions)
	}

	alive := &fakeProber{results: []probeOutcome{{result: ProbeAlive, kind: UnsupportedNone}}}
	tm.keepaliveTick("gr0", state, alive, gen, 0)
	tickN(tm, "gr0", state, alive, gen, 0, 2)
	if len(transitions) != 2 || transitions[0] || !transitions[1] {
		t.Fatalf("down/up transitions = %v, want [false true]", transitions)
	}
}

// --- §9 Unsupported(structural): never LinkSet*, KeepaliveUp nil, info "unknown" ---
func TestKeepaliveStructuralUnsupportedHolds(t *testing.T) {
	ops := newKaOps()
	tm := &tunnelManager{ops: ops}
	state, gen := newKAState(true, 3, 1)
	prober := &fakeProber{results: []probeOutcome{{result: ProbeUnsupported, kind: UnsupportedStructural}}}

	tickN(tm, "gr0", state, prober, gen, 0, 5)
	if ops.ups() != 0 || ops.downs() != 0 {
		t.Fatalf("structural unsupported must not LinkSet*: ups=%d downs=%d", ops.ups(), ops.downs())
	}
	if state.Failures != 0 {
		t.Fatalf("structural unsupported must not increment Failures, got %d", state.Failures)
	}
	if !state.Unknown {
		t.Fatal("expected Unknown=true")
	}
	if state.Up != true {
		t.Fatal("prior Up should be held (true)")
	}
}

// --- §9 Unsupported(transient) sustained: escalated status, still no down ---
func TestKeepaliveTransientUnsupportedEscalates(t *testing.T) {
	ops := newKaOps()
	tm := &tunnelManager{ops: ops}
	state, gen := newKAState(true, 3, 1)
	prober := &fakeProber{results: []probeOutcome{{result: ProbeUnsupported, kind: UnsupportedTransient}}}

	tickN(tm, "gr0", state, prober, gen, 0, 4)
	if ops.downs() != 0 {
		t.Fatalf("transient unsupported must never LinkSetDown, got %d", ops.downs())
	}
	if state.UnknownKind != UnsupportedTransient {
		t.Fatalf("expected transient kind, got %v", state.UnknownKind)
	}
	if state.unknownStreak < state.MaxRetries {
		t.Fatalf("expected streak >= MaxRetries, got %d", state.unknownStreak)
	}
}

// --- §9 LinkByName error on transition: Up not latched, retried ---
func TestKeepaliveLinkByNameErrorNoLatch(t *testing.T) {
	ops := newKaOps()
	ops.byNameErr = errors.New("transient netlink error")
	tm := &tunnelManager{ops: ops}
	state, gen := newKAState(true, 3, 1)
	prober := &fakeProber{results: []probeOutcome{{result: ProbeDead, kind: UnsupportedNone}}}

	tickN(tm, "gr0", state, prober, gen, 0, 5)
	// LinkByName keeps failing → no down committed, Up stays true.
	if state.Up != true {
		t.Fatal("Up must not latch false on LinkByName error")
	}
	if ops.downs() != 0 {
		t.Fatalf("no LinkSetDown should be issued, got %d", ops.downs())
	}
	// Failures still climb (committed in step 1).
	if state.Failures < state.MaxRetries {
		t.Fatalf("failures should climb, got %d", state.Failures)
	}
	// Now lookup recovers → exactly one down on the next tick.
	ops.mu.Lock()
	ops.byNameErr = nil
	ops.mu.Unlock()
	tm.keepaliveTick("gr0", state, prober, gen, 0)
	if ops.downs() != 1 {
		t.Fatalf("expected exactly one LinkSetDown after lookup recovers, got %d", ops.downs())
	}
	if state.Up {
		t.Fatal("expected Up=false after the transition lands")
	}
}

// --- §9 LinkSet* error retry (Codex r3 blocker) ---
func TestKeepaliveLinkSetDownErrorRetries(t *testing.T) {
	ops := newKaOps()
	ops.setDownErr = errors.New("netlink busy")
	tm := &tunnelManager{ops: ops}
	state, gen := newKAState(true, 3, 1)
	var transitions []bool
	tm.setLivenessChangeCallback(func(_ string, up bool) {
		transitions = append(transitions, up)
	})
	prober := &fakeProber{results: []probeOutcome{{result: ProbeDead, kind: UnsupportedNone}}}

	tickN(tm, "gr0", state, prober, gen, 0, 4)
	// Down keeps erroring → Up must NOT be committed false.
	if state.Up != true {
		t.Fatal("Up must stay true while LinkSetDown errors (commit-after-success)")
	}
	if ops.downs() < 2 {
		t.Fatalf("expected repeated LinkSetDown attempts, got %d", ops.downs())
	}
	if len(transitions) != 0 {
		t.Fatalf("failed LinkSetDown emitted liveness transitions %v", transitions)
	}
	// Now LinkSetDown succeeds → exactly one effective down.
	ops.mu.Lock()
	ops.setDownErr = nil
	beforeDowns := ops.setDowns
	ops.mu.Unlock()
	tm.keepaliveTick("gr0", state, prober, gen, 0)
	if state.Up {
		t.Fatal("expected Up=false after LinkSetDown succeeds")
	}
	if ops.downs() != beforeDowns+1 {
		t.Fatalf("expected one more LinkSetDown on the successful tick, got %d -> %d", beforeDowns, ops.downs())
	}
	if len(transitions) != 1 || transitions[0] {
		t.Fatalf("successful LinkSetDown transitions = %v, want [false]", transitions)
	}
}

// --- §9 NF3 generation guard: bump gen → action dropped ---
func TestKeepaliveGenerationGuardDropsAction(t *testing.T) {
	ops := newKaOps()
	tm := &tunnelManager{ops: ops}
	state, gen := newKAState(true, 1, 1) // MaxRetries=1 → dead immediately transitions
	prober := &fakeProber{results: []probeOutcome{{result: ProbeDead, kind: UnsupportedNone}}}

	startGen := gen.Load()
	// Bump the generation (simulating Apply recreate) before the tick.
	gen.Add(1)
	tm.keepaliveTick("gr0", state, prober, gen, startGen)
	if ops.downs() != 0 {
		t.Fatalf("stale-generation runner must drop LinkSetDown, got %d", ops.downs())
	}
	// Up not committed false (the action was dropped after intent).
	if state.Up != true {
		t.Fatal("Up must not be committed when the action is dropped")
	}
}

// --- §9 lock-scope regression: GetStatus must not block behind a parked LinkSetDown ---
func TestKeepaliveStatusNotBlockedByNetlink(t *testing.T) {
	ops := newKaOps()
	ops.blockDown = make(chan struct{})
	ops.entered = make(chan struct{})
	tm := &tunnelManager{ops: ops}
	state, gen := newKAState(true, 1, 1)
	// Register the runner in the manager so GetKeepaliveState finds it.
	// Setup mutates manager state guarded by mu in production, so hold mu
	// for the setup block (Copilot PR #1947 r4 — test/contract alignment).
	tm.mu.Lock()
	tm.ensureReconcileStateLocked()
	tm.keepalives["gr0"] = &keepaliveRunner{state: state, remote: state.RemoteAddr}
	tm.tunnels = []string{"gr0"}
	tm.mu.Unlock()

	prober := &fakeProber{results: []probeOutcome{{result: ProbeDead, kind: UnsupportedNone}}}

	// Run a tick in a goroutine; it will park inside LinkSetDown.
	go tm.keepaliveTick("gr0", state, prober, gen, 0)
	select {
	case <-ops.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("LinkSetDown never entered")
	}

	// While LinkSetDown is parked, GetStatus must return promptly — it
	// must NOT hold state.mu across the netlink op (Axis D).
	doneCh := make(chan struct{})
	go func() {
		_, _ = tm.GetStatus()
		close(doneCh)
	}()
	select {
	case <-doneCh:
	case <-time.After(2 * time.Second):
		close(ops.blockDown)
		t.Fatal("GetStatus blocked behind parked LinkSetDown — Axis D lock-scope violated")
	}
	close(ops.blockDown)
}

// --- §9 source bind (§5c): prober receives tc.Source; matches() on source change ---
func TestKeepaliveSourceBindAndMatches(t *testing.T) {
	ops := newKaOps()
	tm := &tunnelManager{ops: ops}
	state, gen := newKAState(true, 3, 1)
	prober := &fakeProber{results: []probeOutcome{{result: ProbeAlive, kind: UnsupportedNone}}}
	tm.keepaliveTick("gr0", state, prober, gen, 0)
	if prober.lastSource != state.SourceAddr {
		t.Fatalf("prober bind source = %q, want %q", prober.lastSource, state.SourceAddr)
	}

	// matches(): a source-only change must restart the runner.
	r := &keepaliveRunner{
		remote:     "203.0.113.1",
		source:     "198.51.100.1",
		interval:   5,
		maxRetries: 3,
	}
	same := &config.TunnelConfig{Destination: "203.0.113.1", Source: "198.51.100.1", Keepalive: 5, KeepaliveRetry: 3}
	if !r.matches(same) {
		t.Fatal("matches must be true when identity unchanged")
	}
	srcChanged := &config.TunnelConfig{Destination: "203.0.113.1", Source: "192.0.2.9", Keepalive: 5, KeepaliveRetry: 3}
	if r.matches(srcChanged) {
		t.Fatal("matches must be false when only the source changed (§5c)")
	}
}

// --- Finding 1 (Codex PR #1947 r1 HIGH): a TRANSIENT LinkByName error
// during apply must NOT drain the live keepalive runner nor bump the
// generation; only a genuine NOT-FOUND or a present-but-changed link is
// a recreate. ---
func TestApplyTransientLookupKeepsRunner(t *testing.T) {
	ops := newKaOps()
	ops.byNameErr = errors.New("transient netlink transport error") // NOT a LinkNotFound
	tm := &tunnelManager{ops: ops, vrfBinder: noopVRFBinder{}}
	// applyKernelTunnelLocked + the helpers below all require mu held in
	// production; hold it for the whole body (Copilot PR #1947 r4).
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.ensureReconcileStateLocked()

	// Seed a live keepalive runner + its generation token.
	state, gen := newKAState(true, 3, 5)
	tm.linkGen["gr0"] = gen
	startGen := gen.Load()
	tm.keepalives["gr0"] = &keepaliveRunner{
		cancel:   func() {},
		state:    state,
		done:     make(chan struct{}),
		remote:   "203.0.113.1",
		source:   "198.51.100.1",
		interval: 5, maxRetries: 3,
		linkGen: gen, startGen: startGen,
	}

	tc := &config.TunnelConfig{
		Name: "gr0", Mode: "gre",
		Source: "198.51.100.1", Destination: "203.0.113.1",
		Keepalive: 5, KeepaliveRetry: 3,
	}
	tm.applyKernelTunnelLocked(tc)

	if _, ok := tm.keepalives["gr0"]; !ok {
		t.Fatal("transient lookup error must NOT drain the keepalive runner")
	}
	if gen.Load() != startGen {
		t.Fatalf("transient lookup error must NOT bump the generation: %d -> %d", startGen, gen.Load())
	}
}

// --- Copilot PR #1947: the prober reason (real syscall/config detail)
// must propagate to KeepaliveInfo, not a generic label. ---
func TestKeepaliveUnknownReasonSurfacedInStatus(t *testing.T) {
	ops := newKaOps()
	tm := &tunnelManager{ops: ops}
	// Setup mutates mu-guarded state (Copilot PR #1947 r4); GetStatus later
	// takes mu, so lock only the setup block, not the read.
	tm.mu.Lock()
	tm.ensureReconcileStateLocked()
	state, gen := newKAState(true, 3, 1)
	tm.keepalives["gr0"] = &keepaliveRunner{state: state, remote: state.RemoteAddr}
	tm.tunnels = []string{"gr0"}
	tm.mu.Unlock()

	// A transient unsupported with a concrete reason.
	prober := &fakeProber{results: []probeOutcome{{
		result: ProbeUnsupported, kind: UnsupportedTransient,
		reason: "listen udp4 198.51.100.1: too many open files",
	}}}
	tickN(tm, "gr0", state, prober, gen, 0, 4)

	statuses, err := tm.GetStatus()
	if err != nil {
		t.Fatal(err)
	}
	var info string
	var kaUp *bool
	for _, s := range statuses {
		if s.Name == "gr0" {
			info = s.KeepaliveInfo
			kaUp = s.KeepaliveUp
		}
	}
	if kaUp != nil {
		t.Fatalf("KeepaliveUp must be nil on unknown, got %v", *kaUp)
	}
	if !strings.Contains(info, "too many open files") {
		t.Fatalf("status must carry the real probe reason, got %q", info)
	}

	// A structural unsupported with a reason → reason shown too.
	state2, gen2 := newKAState(true, 3, 1)
	tm.mu.Lock()
	tm.keepalives["gr1"] = &keepaliveRunner{state: state2, remote: state2.RemoteAddr}
	tm.tunnels = append(tm.tunnels, "gr1")
	tm.mu.Unlock()
	prober2 := &fakeProber{results: []probeOutcome{{
		result: ProbeUnsupported, kind: UnsupportedStructural,
		reason: "listen udp4 198.51.100.99: cannot assign requested address",
	}}}
	tm.keepaliveTick("gr1", state2, prober2, gen2, 0)
	statuses, _ = tm.GetStatus()
	for _, s := range statuses {
		if s.Name == "gr1" && !strings.Contains(s.KeepaliveInfo, "cannot assign requested address") {
			t.Fatalf("structural status must carry the reason, got %q", s.KeepaliveInfo)
		}
	}
}

// --- Copilot PR #1947 r3: a present-but-changed link whose LinkDel
// fails transiently must NOT silently leave the tunnel with no keepalive
// — the runner is restarted against the surviving link. ---
func TestApplyRecreateDelFailRestartsKeepalive(t *testing.T) {
	ops := newKaOps()
	ops.delErr = errors.New("transient LinkDel failure") // recreate aborts
	tm := &tunnelManager{ops: ops, vrfBinder: noopVRFBinder{}}
	// applyKernelTunnelLocked + stopKeepaliveLocked require mu in
	// production; hold it for the whole body (Copilot PR #1947 r4).
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.ensureReconcileStateLocked()

	// Seed a live keepalive runner. LinkByName returns a *netlink.Dummy,
	// which legacyTunnelMatches(Dummy, Gretun) treats as CHANGED → recreate
	// path → drain → LinkDel (fails).
	state, gen := newKAState(true, 3, 5)
	tm.linkGen["gr0"] = gen
	// Seed with a pre-closed done so stopKeepaliveLocked's drain returns
	// immediately (no real goroutine backs this fake runner).
	seededDone := make(chan struct{})
	close(seededDone)
	tm.keepalives["gr0"] = &keepaliveRunner{
		cancel: func() {}, state: state, done: seededDone,
		remote: "203.0.113.1", source: "198.51.100.1", interval: 5, maxRetries: 3,
		linkGen: gen,
	}

	tc := &config.TunnelConfig{
		Name: "gr0", Mode: "gre",
		Source: "198.51.100.1", Destination: "203.0.113.1",
		Keepalive: 5, KeepaliveRetry: 3,
	}
	tm.applyKernelTunnelLocked(tc)

	if _, ok := tm.keepalives["gr0"]; !ok {
		t.Fatal("LinkDel failure on recreate must restart the keepalive, not leave it absent")
	}
	// Drain the restarted runner so the goroutine does not leak into other
	// tests (it uses the real prober but a 5s interval, so it parks on the
	// ticker; cancel it).
	tm.stopKeepaliveLocked("gr0")
}

// --- prober errno classification ---
func TestClassifyListenErr(t *testing.T) {
	if got := classifyListenErr(errors.New("plain")); got != UnsupportedStructural {
		t.Fatalf("non-errno → structural, got %v", got)
	}
}
