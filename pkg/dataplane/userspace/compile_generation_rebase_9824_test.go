// #9824: a partial update that lands while Compile builds leaves Compile's
// snapshot at an older generation, and the XSK-startup deferral then never
// publishes the new config (publishedSnapshot >= lastSnapshot.Generation
// forever). The fix rebases the compiled snapshot unconditionally to
// m.generation += 2 under m.mu right after resampleForCompileLocked: H (max
// helper-installed) is at most m.generation+1, so the offer is strictly above H
// on every path and first attempts admit.
//
// These cells prove the END property at a helper MODEL that tracks installed
// (generation, fib, digest) separately from Go's counters and enforces the
// Rust's real admission gates (first-apply bypass, monotonic pair, equal-gen
// digest identity incl. partial digest invalidation) — gate arithmetic alone
// would pass the half-fixes this issue's review rounds killed. Cell R runs the
// r3-main drift trace (post-store drift + lost conflict retry, #10041) as a
// dual-numbering run proving pre-existing shape, not v4-created: pre-#9642 it
// demonstrated the conceded residual (below-installed stranding); #9642's
// deliberate retry adoption repairs that trace, so it now proves the repair
// converges identically at both numberings (#10064). Rollback-no-retry
// mechanics keep a direct pin (TestRollbackRefusalRetriesNothing9824).
package userspace

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// rollbackPrefix9824 is the helper's generation-rollback refusal prefix
// (userspace-dp/src/server/handlers/snapshot.rs). The model formats refusals
// with it and TestRollbackPrefixMatchesTheHelper9824 pins it against the Rust
// source, so a rewording voids these cells loudly instead of silently.
const rollbackPrefix9824 = "snapshot generation rollback rejected"

// markerZone9824 exists ONLY in the compiled snapshot under test. The
// end-to-end assertions look for it in the apply_snapshot the helper MODEL
// admits: its presence says the COMPILED generation reached the helper, as
// opposed to some earlier snapshot that happened to be published.
const markerZone9824 = "compiled-only-zone-9824"

// helperModel9824 is the #10041-grade admission model the plan's test section
// requires: installed (generation, fib, digest, fabrics) tracked separately
// from Go's counters, both real gates enforced with the real literals,
// drop-response-on-command, and the #6034 neighbor fence. It is an ADMISSION
// model, not a model of integrity/build/resource failures.
type helperModel9824 struct {
	mu              sync.Mutex
	installed       bool
	gen             uint64
	fib             uint32
	digest          string
	fabrics         []FabricSnapshot
	lastNeighborGen uint64
	// dropApplies answers that many upcoming apply_snapshot requests by
	// applying in the model and then dropping the response (transport error).
	dropApplies int
	// dropPartials answers that many upcoming update_* requests with a bare
	// transport error WITHOUT applying (loss-before-apply; the debt marking
	// is what the scripts need, and strictly-above offers admit regardless).
	dropPartials int
	// requests records every ControlRequest offered, refused or dropped ones
	// included — branch witnesses read the offers, not just the admissions.
	requests []ControlRequest
	// violations records fixture-implementation faults (an unstamped offer
	// would mean a new send site bypassing requestApplySnapshotLocked).
	violations []string
}

func (h *helperModel9824) hook(req ControlRequest, status *ProcessStatus) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	// Record a struct copy: the #9520 retry mutates the offered snapshot's
	// Generation in place, so retaining the pointer would rewrite history
	// (two offers of 10-then-11 would both read back as 11).
	rec := req
	if req.Snapshot != nil {
		snapCopy := *req.Snapshot
		rec.Snapshot = &snapCopy
	}
	h.requests = append(h.requests, rec)
	switch req.Type {
	case "apply_snapshot":
		return h.applyLocked(req.Snapshot, status)
	case "update_neighbors":
		if h.dropPartials > 0 {
			h.dropPartials--
			return errLostResponse9520
		}
		// #6034 fence, mirrored: a stale/reordered replace is fenced (ACK the
		// applied generation, change nothing, clear no digest).
		if req.NeighborGeneration <= h.lastNeighborGen {
			if status != nil {
				*status = ProcessStatus{ManagerNeighborGeneration: h.lastNeighborGen}
			}
			return nil
		}
		h.lastNeighborGen = req.NeighborGeneration
		// Applied: the helper enforces neighbors the installed full apply did
		// not carry, so that apply's digest must not vouch for a retry of it
		// (handlers/neighbors.rs).
		h.digest = ""
		if status != nil {
			*status = ProcessStatus{ManagerNeighborGeneration: req.NeighborGeneration}
		}
		return nil
	case "update_fabrics":
		if h.dropPartials > 0 {
			h.dropPartials--
			return errLostResponse9520
		}
		// Changed rows clear the installed digest (handlers/mod.rs); an
		// unchanged refresh leaves it alone.
		if !fabricSnapshotsEqual(h.fabrics, req.Fabrics) {
			h.fabrics = append([]FabricSnapshot(nil), req.Fabrics...)
			h.digest = ""
		}
		return nil
	case "ping":
		if status != nil {
			*status = ProcessStatus{
				PID:                           4321,
				ConfigSnapshotProtocolVersion: ProtocolVersion,
				LastSnapshotGeneration:        h.gen,
				LastFIBGeneration:             h.fib,
				ManagerNeighborGeneration:     h.lastNeighborGen,
			}
		}
		return nil
	default:
		return nil
	}
}

// applyLocked enforces the snapshot.rs admission gates. Caller holds h.mu.
func (h *helperModel9824) applyLocked(snap *ConfigSnapshot, status *ProcessStatus) error {
	if snap == nil {
		h.violations = append(h.violations, "apply_snapshot carried no snapshot")
		return errors.New("9824 model: apply_snapshot carried no snapshot")
	}
	if snap.ContentDigest == "" {
		// Production stamps every apply at the single send site; an unstamped
		// offer means a new bypassing send site exists and the H-bound census
		// in the plan is void.
		h.violations = append(h.violations, fmt.Sprintf("unstamped apply_snapshot at generation %d", snap.Generation))
	}
	// A refusal IS a response: only an admitted offer can lose its response.
	// Evaluate the gates first; consume a scripted drop only on admission.
	if h.installed {
		monotonic := snap.Generation > h.gen ||
			(snap.Generation == h.gen && snap.FIBGeneration >= h.fib)
		if !monotonic {
			return newHelperRejection(fmt.Sprintf("%s: (%d, %d) < current (%d, %d)",
				rollbackPrefix9824, snap.Generation, snap.FIBGeneration, h.gen, h.fib))
		}
		if snap.Generation == h.gen && (h.digest == "" || h.digest != snap.ContentDigest) {
			return newHelperRejection(fmt.Sprintf(
				"%s generation %d is installed with content digest %q; this apply carries %q",
				snapshotContentConflictPrefix, h.gen, h.digest, snap.ContentDigest))
		}
	}
	if h.dropApplies > 0 {
		h.dropApplies--
		h.admitLocked(snap)
		return errLostResponse9520
	}
	h.admitLocked(snap)
	if status != nil {
		ready := readyHelperStatus()
		ready.ConfigSnapshotProtocolVersion = ProtocolVersion
		ready.LastSnapshotGeneration = snap.Generation
		ready.LastFIBGeneration = snap.FIBGeneration
		ready.ManagerNeighborGeneration = h.lastNeighborGen
		*status = *ready
	}
	return nil
}

func (h *helperModel9824) admitLocked(snap *ConfigSnapshot) {
	h.installed = true
	h.gen = snap.Generation
	h.fib = snap.FIBGeneration
	h.digest = snap.ContentDigest
	h.fabrics = append([]FabricSnapshot(nil), snap.Fabrics...)
}

// seed installs (gen, fib, digest, fabrics) as the helper's starting state:
// the content of an earlier published snapshot Go's bookkeeping agrees on.
func (h *helperModel9824) seed(gen uint64, fib uint32, digest string, fabrics []FabricSnapshot) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.installed = true
	h.gen = gen
	h.fib = fib
	h.digest = digest
	h.fabrics = append([]FabricSnapshot(nil), fabrics...)
}

func (h *helperModel9824) installedState() (gen uint64, digest string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.gen, h.digest
}

// applyGenerations returns the generation of every apply_snapshot OFFERED, in
// order — admissions, refusals and drops alike.
func (h *helperModel9824) applyGenerations() []uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []uint64
	for _, r := range h.requests {
		if r.Type == "apply_snapshot" && r.Snapshot != nil {
			out = append(out, r.Snapshot.Generation)
		}
	}
	return out
}

func (h *helperModel9824) countVerb(verb string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, r := range h.requests {
		if r.Type == verb {
			n++
		}
	}
	return n
}

func (h *helperModel9824) violationsCopy() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.violations...)
}

// scriptDrops arms n apply_snapshot response drops (applied, then the
// response is lost). scriptPartialDrops arms n update_* transport failures
// without applying. Lock-held: the hook consults these under h.mu, so
// scripting them must too — direct field writes would race a tick.
func (h *helperModel9824) scriptDrops(n int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.dropApplies = n
}

func (h *helperModel9824) scriptPartialDrops(n int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.dropPartials = n
}

// fixture9824 wires a real Manager to the helper model with the 9337/6994
// seams. Non-cluster config throughout: the standalone HA clear has its own
// hook (recorded, nil), which keeps both the deferral branch and the normal
// tail deterministic without BPF maps.
type fixture9824 struct {
	t     *testing.T
	m     *Manager
	model *helperModel9824
	cfg   *config.Config
	ucfg  config.UserspaceConfig
	caps  UserspaceCapabilities
	ctrl  *fakeCtrlMap

	neighborCalls int
	neighborFunc  func(cfg *config.Config) []NeighborSnapshot
	fabricCalls   int
	fabricFunc    func(cfg *config.Config) []FabricSnapshot

	mu       sync.Mutex
	syncedTo []*ConfigSnapshot
	haClears int
}

// noopCancel9824 is the poller-startup sentinel: seeded as m.syncCancel, it
// makes every ensureStatusLoopLocked early-return, so no background statusLoop
// goroutine ever starts and no 1s tick can interleave with the scripted manual
// ticks (cancel-without-join would otherwise leave a racing ticker branch).
// The drivers below preserve it across operations.
func noopCancel9824() {}

func newFixture9824(t *testing.T) *fixture9824 {
	t.Helper()
	proc, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatalf("FindProcess: %v", err)
	}
	f := &fixture9824{t: t, cfg: &config.Config{}}
	f.ucfg = deriveUserspaceConfig(f.cfg)
	f.caps = deriveUserspaceCapabilities(f.cfg)
	f.model = &helperModel9824{}
	m := New()
	m.proc = &exec.Cmd{Process: proc}
	m.cfg = f.ucfg
	m.syncCancel = noopCancel9824
	m.controlRequestHook = f.model.hook
	m.syncClassifierMapsHook = func(s *ConfigSnapshot) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.syncedTo = append(f.syncedTo, s)
		return nil
	}
	// Single shared ctrl oracle (r4 minor): fail-closed writes and
	// status-driven writes land on the same row, so the transition
	// disabled-after-loss → re-enabled-at-convergence is observable.
	// Seeded Enabled=1 (a running firewall) so a disable is observable.
	f.ctrl = &fakeCtrlMap{
		stored:     userspaceCtrlValue{Enabled: 1, MetadataVersion: userspaceMetadataVersion, Workers: 4, QueueCount: 4},
		haveStored: true,
	}
	m.failClosedCtrlMapHook = f.ctrl
	m.helperStatusCtrlMapHook = f.ctrl
	m.helperStatusBindingsMapHook = &fakeBindingsMap{}
	m.clearHelperHAStateHook = func() error {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.haClears++
		return nil
	}
	// Protocol observed and current, so the required-protocol gates pass
	// without spending a control round trip (9337 pattern).
	m.lastStatus = ProcessStatus{ConfigSnapshotProtocolVersion: ProtocolVersion}
	m.helperStatusObserved = true
	m.neighborSnapshotBuilder = func(cfg *config.Config) []NeighborSnapshot {
		f.neighborCalls++
		if f.neighborFunc != nil {
			return f.neighborFunc(cfg)
		}
		return nil
	}
	m.fabricSnapshotBuilder = func(cfg *config.Config) []FabricSnapshot {
		f.fabricCalls++
		if f.fabricFunc != nil {
			return f.fabricFunc(cfg)
		}
		return nil
	}
	f.m = m
	return f
}

// snap9824 builds a hand-controlled snapshot shell. Userspace stays zero-value
// on every snapshot so the binding-plan contribution is identical; plan halves
// of fabric rows are the caller's responsibility (alpha/beta share them).
func (f *fixture9824) snap9824(gen uint64, zones []ZoneSnapshot, neighbors []NeighborSnapshot, fabrics []FabricSnapshot) *ConfigSnapshot {
	return &ConfigSnapshot{
		Version:    ProtocolVersion,
		Generation: gen,
		Config:     f.cfg,
		Zones:      append([]ZoneSnapshot(nil), zones...),
		Neighbors:  append([]NeighborSnapshot(nil), neighbors...),
		Fabrics:    append([]FabricSnapshot(nil), fabrics...),
	}
}

func digest9824(t *testing.T, snap *ConfigSnapshot) string {
	t.Helper()
	sum, ok := snapshotContentHash(snap)
	if !ok {
		t.Fatal("fixture: snapshot must hash")
	}
	return hex.EncodeToString(sum[:])
}

// seedPublished installs a coherent published state: Go's bookkeeping and the
// helper model agree the helper holds (gen, digest, fabrics).
func (f *fixture9824) seedPublished(t *testing.T, gen uint64, zones []ZoneSnapshot, neighbors []NeighborSnapshot, fabrics []FabricSnapshot) *ConfigSnapshot {
	t.Helper()
	snap := f.snap9824(gen, zones, neighbors, fabrics)
	f.m.mu.Lock()
	f.m.lastSnapshot = snap
	f.m.generation = gen
	f.m.publishedSnapshot = gen
	f.m.publishedPlanKey = snapshotBindingPlanKey(snap)
	if h, ok := snapshotContentHash(snap); ok {
		f.m.lastSnapshotHash = h
	} else {
		t.Fatal("fixture: published snapshot must hash")
	}
	f.m.lastStatus.LastSnapshotGeneration = gen
	f.m.mu.Unlock()
	f.model.seed(gen, 0, digest9824(t, snap), fabrics)
	return snap
}

// forcePendingXSK puts the manager in the deferral window: a live helper with
// an outstanding XSK liveness probe.
func (f *fixture9824) forcePendingXSK() {
	f.m.mu.Lock()
	defer f.m.mu.Unlock()
	f.m.xskLivenessProven = false
	f.m.xskLivenessFailed = false
}

// endXSKWindow closes the probe window: the state in which the status tick is
// supposed to service a deferred publish.
func (f *fixture9824) endXSKWindow() {
	f.m.mu.Lock()
	defer f.m.mu.Unlock()
	f.m.xskLivenessProven = true
}

// tick drives the real deferred-publish path. No background poller can be
// running (the constructor sentinel makes every ensureStatusLoopLocked
// early-return); the capture below only preserves the sentinel and would
// stop a loop if a path ever started one.
func (f *fixture9824) tick(t *testing.T) error {
	t.Helper()
	f.m.mu.Lock()
	err := f.m.syncSnapshotLocked()
	cancel := f.m.syncCancel
	f.m.syncCancel = noopCancel9824
	f.m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	return err
}

// apply drives the real applyCompiledSnapshot (5485 pattern), preserving the
// poller-startup sentinel the same way tick does.
func (f *fixture9824) apply(t *testing.T, snap *ConfigSnapshot) (*dataplane.CompileResult, error) {
	t.Helper()
	result := &dataplane.CompileResult{}
	out, err := f.m.applyCompiledSnapshot(f.cfg, result, snap, f.ucfg, f.caps)
	f.m.mu.Lock()
	cancel := f.m.syncCancel
	f.m.syncCancel = noopCancel9824
	f.m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	return out, err
}

func (f *fixture9824) gate() (published, last uint64, open bool) {
	f.m.mu.Lock()
	defer f.m.mu.Unlock()
	published, last = f.m.publishedSnapshot, f.m.lastSnapshot.Generation
	return published, last, published < last
}

func (f *fixture9824) assertNoViolations(t *testing.T) {
	t.Helper()
	if v := f.model.violationsCopy(); len(v) != 0 {
		t.Fatalf("helper-model violations: %v", v)
	}
}

// neighbor9824 builds a publishable neighbor row: valid ifindex/IP/MAC and a
// usable NUD state.
func neighbor9824(ifindex int, ip, mac string) NeighborSnapshot {
	return NeighborSnapshot{Ifindex: ifindex, IP: ip, MAC: mac, State: "REACHABLE"}
}

// fabric rows share one plan half (parent interface/netdev/ifindex, queues,
// verdict) and differ only in the peer MAC, the non-plan field a re-resolve
// moves. Plan halves identical is what makes resample cross them and persist
// compare them meaningfully.
func fabricAlpha9824() FabricSnapshot {
	return FabricSnapshot{
		Name: "fab0", ParentInterface: "ge-0/0/0", ParentLinuxName: "ge-0-0-0",
		ParentIfindex: 7, RXQueues: 4, PeerAddress: "10.99.1.2", PeerMAC: "02:00:00:00:00:aa", Up: true,
	}
}

func fabricBeta9824() FabricSnapshot {
	out := fabricAlpha9824()
	out.PeerMAC = "02:00:00:00:00:bb"
	return out
}

func baseZones9824() []ZoneSnapshot {
	return []ZoneSnapshot{{Name: "zone-a", ID: 1}}
}

func equalUint64s(a, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func snapshotHasZone(snap *ConfigSnapshot, name string) bool {
	for _, z := range snap.Zones {
		if z.Name == name {
			return true
		}
	}
	return false
}

// lastApplyOfType returns the most recent recorded request of a verb.
func (f *fixture9824) lastApplyOfType(t *testing.T, verb string) ControlRequest {
	t.Helper()
	f.model.mu.Lock()
	defer f.model.mu.Unlock()
	for i := len(f.model.requests) - 1; i >= 0; i-- {
		if f.model.requests[i].Type == verb {
			return f.model.requests[i]
		}
	}
	t.Fatalf("no %s request was ever recorded", verb)
	return ControlRequest{}
}

// TestRollbackPrefixMatchesTheHelper9824 pins the rollback refusal prefix
// against the Rust source. Unlike the content-conflict prefix (an exported
// const with its own pin test), the rollback message is an inline format!
// with embedded values, so this pins the PREFIX via a source read.
func TestRollbackPrefixMatchesTheHelper9824(t *testing.T) {
	body, err := os.ReadFile("../../../userspace-dp/src/server/handlers/snapshot.rs")
	if err != nil {
		t.Fatalf("read snapshot.rs: %v", err)
	}
	if !strings.Contains(string(body), "\""+rollbackPrefix9824+": (") {
		t.Fatalf("rollback prefix %q not found as a format literal in snapshot.rs; "+
			"the helper reworded the refusal and the 9824 cells' refusal classification is void", rollbackPrefix9824)
	}
}

// TestCompileRebasePublishesAfterInterleavedPartial9824 is Cell 1: the issue
// trace. Published A/7, reserve C/8, a REAL RegenerateNeighborSnapshot
// advances published to 9, the deferral stores C — and the status tick must
// publish the compiled config carrying both the marker and the partial's
// neighbor content.
func TestCompileRebasePublishesAfterInterleavedPartial9824(t *testing.T) {
	f := newFixture9824(t)
	nRetained := neighbor9824(7, "10.0.0.2", "02:00:00:00:00:01")
	nNew := neighbor9824(7, "10.0.0.2", "02:00:00:00:00:02")
	f.seedPublished(t, 7, baseZones9824(), []NeighborSnapshot{nRetained}, []FabricSnapshot{fabricAlpha9824()})
	f.forcePendingXSK()
	// The kernel now holds the new MAC; the partial and the later resample
	// both observe it.
	f.neighborFunc = func(*config.Config) []NeighborSnapshot { return []NeighborSnapshot{nNew} }
	f.fabricFunc = func(*config.Config) []FabricSnapshot { return []FabricSnapshot{fabricAlpha9824()} }

	// Compile's contract, in order: read the epoch, reserve, build, stamp.
	epoch0 := f.m.partialUpdateEpoch.Load()
	reserved := f.m.bumpGeneration()
	compiled := f.snap9824(reserved,
		[]ZoneSnapshot{{Name: "zone-a", ID: 1}, {Name: markerZone9824, ID: 77}},
		[]NeighborSnapshot{nRetained}, []FabricSnapshot{fabricAlpha9824()})
	compiled.partialUpdateEpoch = epoch0

	// The interleaved partial, through the real entry point.
	f.m.RegenerateNeighborSnapshot()
	if got := f.m.partialUpdateEpoch.Load(); got != epoch0+1 {
		t.Fatalf("premise broken: partialUpdateEpoch = %d, want %d — the partial did not advance it", got, epoch0+1)
	}
	f.m.mu.Lock()
	published, gen := f.m.publishedSnapshot, f.m.generation
	f.m.mu.Unlock()
	if published != 9 || gen != 9 {
		t.Fatalf("premise broken: published=%d m.generation=%d, want 9/9 — the partial did not advance the high-water", published, gen)
	}
	if got := f.model.countVerb("update_neighbors"); got != 1 {
		t.Fatalf("update_neighbors requests = %d, want 1 — the partial was not sent", got)
	}

	// The deferral stores the compiled snapshot; nothing may publish yet.
	// The partial already advanced the allocator past the reserve, so the
	// rebase offers m.generation-at-apply + 2, not reserved + 2.
	f.m.mu.Lock()
	mgenBeforeApply := f.m.generation
	f.m.mu.Unlock()
	appliesBefore := f.model.countVerb("apply_snapshot")
	if _, err := f.apply(t, compiled); err != nil {
		t.Fatalf("deferred apply returned %v, want nil", err)
	}
	if got := f.model.countVerb("apply_snapshot"); got != appliesBefore {
		t.Fatalf("apply_snapshot requests during deferral = %d, want 0 — the publish was not deferred", got-appliesBefore)
	}
	published, last, open := f.gate()
	if !open {
		t.Fatalf("gate CLOSED after the deferral (published=%d last=%d): the compiled generation was stored at-or-below water and the tick will never publish it (#9824)", published, last)
	}
	f.m.mu.Lock()
	stored := f.m.lastSnapshot
	f.m.mu.Unlock()
	if stored.Generation != mgenBeforeApply+2 {
		t.Fatalf("stored generation = %d, want m.generation-at-apply+2 = %d — the rebase did not fire", stored.Generation, mgenBeforeApply+2)
	}
	if !snapshotHasZone(stored, markerZone9824) {
		t.Fatal("stored snapshot lost the compiled marker zone")
	}
	if !neighborsEqualForwarding(stored.Neighbors, []NeighborSnapshot{nNew}) {
		t.Fatalf("stored neighbors = %+v, want the partial's content — the resample did not carry the interleaved update (#9684 composition)", stored.Neighbors)
	}
	if f.neighborCalls != 2 {
		t.Fatalf("neighbor samples = %d, want 2 (partial + resample)", f.neighborCalls)
	}

	// The service tick publishes the compiled config with both contents.
	f.endXSKWindow()
	if err := f.tick(t); err != nil {
		t.Fatalf("service tick returned %v, want nil", err)
	}
	sent := f.lastApplyOfType(t, "apply_snapshot")
	if sent.Snapshot == nil || !snapshotHasZone(sent.Snapshot, markerZone9824) {
		t.Fatal("the published apply_snapshot does not carry the COMPILED marker zone")
	}
	if !neighborsEqualForwarding(sent.Snapshot.Neighbors, []NeighborSnapshot{nNew}) {
		t.Fatalf("published neighbors = %+v, want the partial's content", sent.Snapshot.Neighbors)
	}
	if got := f.model.countVerb("apply_snapshot"); got != appliesBefore+1 {
		t.Fatalf("apply_snapshot requests at the service tick = %d, want exactly 1", got-appliesBefore)
	}
	published, last, open = f.gate()
	if open || published != last {
		t.Fatalf("gate still open after the service tick (published=%d last=%d)", published, last)
	}
	installed, _ := f.model.installedState()
	if installed != stored.Generation {
		t.Fatalf("helper holds generation %d, want the compiled %d", installed, stored.Generation)
	}
	f.assertNoViolations(t)
}

// TestCompileRebaseSurvivesLostDeferredPublish9824 is Cell 2: the round-1
// composition. An outstanding deferral B, a reserve, a partial that must NOT
// advance published (guard), a tick publish that lands but loses its response
// (helper ahead of publishedSnapshot), then the compiled apply — which must
// offer strictly above helper-installed and admit on the first attempt.
func TestCompileRebaseSurvivesLostDeferredPublish9824(t *testing.T) {
	f := newFixture9824(t)
	n0 := neighbor9824(7, "10.0.0.2", "02:00:00:00:00:01")
	alpha := []FabricSnapshot{fabricAlpha9824()}
	f.seedPublished(t, 7, baseZones9824(), []NeighborSnapshot{n0}, alpha)
	f.forcePendingXSK()
	// No resample is expected on any path here (no verb crosses the epoch, no
	// mark is set): echo retained content and count the calls that must not
	// happen.
	f.neighborFunc = func(*config.Config) []NeighborSnapshot { return []NeighborSnapshot{n0} }
	f.fabricFunc = func(*config.Config) []FabricSnapshot { return append([]FabricSnapshot(nil), alpha...) }

	// The outstanding deferral B, through the real apply. Baseline-neutral
	// by design: capture B's actual store (10 fixed, 8 pre-fix) and build
	// the composition relative to it, so a RED run reaches the below-helper
	// assertion instead of stopping here. Fixed numbering is Cell 4's job.
	epochB := f.m.partialUpdateEpoch.Load()
	reservedB := f.m.bumpGeneration()
	deferred := f.snap9824(reservedB,
		[]ZoneSnapshot{{Name: "zone-a", ID: 1}, {Name: "zone-b", ID: 2}},
		[]NeighborSnapshot{n0}, append([]FabricSnapshot(nil), alpha...))
	deferred.partialUpdateEpoch = epochB
	appliesBeforeB := f.model.countVerb("apply_snapshot")
	if _, err := f.apply(t, deferred); err != nil {
		t.Fatalf("deferral-B apply returned %v, want nil", err)
	}
	if got := f.model.countVerb("apply_snapshot"); got != appliesBeforeB {
		t.Fatalf("apply_snapshot requests during B's deferral = %d, want 0", got-appliesBeforeB)
	}
	publishedB, lastB, openB := f.gate()
	if !openB {
		t.Fatalf("gate CLOSED after B's deferral (published=%d last=%d) — no outstanding deferral, no composition", publishedB, lastB)
	}

	// Compile C reserves; a fabric writeback lands on top (guard holds
	// published: the full snapshot was NOT published).
	epochC := f.m.partialUpdateEpoch.Load()
	reservedC := f.m.bumpGeneration()
	compiled := f.snap9824(reservedC,
		[]ZoneSnapshot{{Name: "zone-a", ID: 1}, {Name: markerZone9824, ID: 77}},
		[]NeighborSnapshot{n0}, append([]FabricSnapshot(nil), alpha...))
	compiled.partialUpdateEpoch = epochC
	changed := fabricBeta9824()
	f.m.mu.Lock()
	f.m.persistResolvedFabricsLocked([]FabricSnapshot{changed})
	f.m.mu.Unlock()
	f.m.mu.Lock()
	published, gen, retained := f.m.publishedSnapshot, f.m.generation, f.m.lastSnapshot.Generation
	f.m.mu.Unlock()
	if published != 7 {
		t.Fatalf("premise broken: published=%d, want 7 — the #6986 guard advanced published over a deferral", published)
	}
	if gen != retained || gen != reservedC+1 {
		t.Fatalf("premise broken: m.generation=%d retained=%d, want both %d", gen, retained, reservedC+1)
	}

	// Tick during the pending window: same-plan B publishes, lands, loses
	// its response. Helper is now ahead of publishedSnapshot.
	f.model.scriptDrops(1)
	if err := f.tick(t); err == nil {
		t.Fatal("premise broken: the dropped tick returned nil, want the transport error")
	}
	installed, _ := f.model.installedState()
	if installed != retained {
		t.Fatalf("premise broken: helper holds %d, want the landed %d", installed, retained)
	}
	f.m.mu.Lock()
	published = f.m.publishedSnapshot
	unknown := f.m.applySnapshotOutcomeUnknown
	f.m.mu.Unlock()
	if published != 7 || !unknown {
		t.Fatalf("premise broken: published=%d unknown=%v, want 7/true — the lost publish booked itself", published, unknown)
	}

	// C applies while still pending: must defer strictly above installed.
	appliesBefore := f.model.countVerb("apply_snapshot")
	if _, err := f.apply(t, compiled); err != nil {
		t.Fatalf("deferred apply returned %v, want nil", err)
	}
	if got := f.model.countVerb("apply_snapshot"); got != appliesBefore {
		t.Fatalf("apply_snapshot requests during C's deferral = %d, want 0", got-appliesBefore)
	}
	f.m.mu.Lock()
	storedC := f.m.lastSnapshot.Generation
	f.m.mu.Unlock()
	installed, _ = f.model.installedState()
	if storedC <= installed {
		t.Fatalf("C stored at %d, helper holds %d: the offer is at-or-below installed and the tick will be rollback-refused (#9824 r1)", storedC, installed)
	}

	// Service tick: first attempt admits with the marker.
	f.endXSKWindow()
	if err := f.tick(t); err != nil {
		t.Fatalf("service tick returned %v, want nil", err)
	}
	if got := f.model.countVerb("apply_snapshot"); got != appliesBefore+1 {
		t.Fatalf("apply_snapshot requests at the service tick = %d, want exactly 1 (no conflict retry)", got-appliesBefore)
	}
	sent := f.lastApplyOfType(t, "apply_snapshot")
	if sent.Snapshot == nil || !snapshotHasZone(sent.Snapshot, markerZone9824) {
		t.Fatal("the published apply_snapshot does not carry the COMPILED marker zone")
	}
	if f.neighborCalls != 0 || f.fabricCalls != 0 {
		t.Fatalf("sampler calls = neighbors %d fabrics %d, want 0/0 — nothing here should resample", f.neighborCalls, f.fabricCalls)
	}
	f.assertNoViolations(t)
}

// TestCompileRebaseAdmitsAfterLostRepublishDeferred9824 is Cell 3 (deferred
// arm): sub-case 2a. Reserve C/8, then a worker-arm republish of unallocated
// m.generation+1 lands but loses its response — the helper holds 9 with NO
// counter evidence — then the deferral must offer strictly above it, and an
// identical re-offer after a second loss must converge idempotently with
// cessation.
func TestCompileRebaseAdmitsAfterLostRepublishDeferred9824(t *testing.T) {
	f := newFixture9824(t)
	n0 := neighbor9824(7, "10.0.0.2", "02:00:00:00:00:01")
	alpha := []FabricSnapshot{fabricAlpha9824()}
	seed := f.seedPublished(t, 7, baseZones9824(), []NeighborSnapshot{n0}, alpha)
	// #5134 debt shape: a published workerless snapshot with the arm
	// outstanding. DeferWorkers is not plan-relevant, so same-plan holds.
	// Recompute the hash/digest after flipping the bit: DeferWorkers enters
	// the content hash, and the seed must stay coherent.
	f.m.mu.Lock()
	seed.DeferWorkers = true
	if h, ok := snapshotContentHash(seed); ok {
		f.m.lastSnapshotHash = h
	}
	f.m.pendingWorkerArm = true
	f.m.mu.Unlock()
	f.model.seed(7, 0, digest9824(t, seed), []FabricSnapshot{fabricAlpha9824()})
	f.forcePendingXSK()
	// No resample anywhere here (no partial verb crosses the epoch, no mark):
	// echo retained content and prove it by zero calls.
	f.neighborFunc = func(*config.Config) []NeighborSnapshot { return []NeighborSnapshot{n0} }
	f.fabricFunc = func(*config.Config) []FabricSnapshot { return append([]FabricSnapshot(nil), alpha...) }

	epoch0 := f.m.partialUpdateEpoch.Load()
	reserved := f.m.bumpGeneration()
	compiled := f.snap9824(reserved,
		[]ZoneSnapshot{{Name: "zone-a", ID: 1}, {Name: markerZone9824, ID: 77}},
		[]NeighborSnapshot{n0}, append([]FabricSnapshot(nil), alpha...))
	compiled.partialUpdateEpoch = epoch0

	// The lost unallocated republish, through the real worker-arm retry.
	f.model.scriptDrops(1)
	f.m.mu.Lock()
	retryErr := f.m.retryDeferredWorkerArmLocked()
	f.m.mu.Unlock()
	if retryErr == nil {
		t.Fatal("premise broken: the dropped worker-arm retry returned nil")
	}
	f.m.mu.Lock()
	mgen, retainedGen, pub, debt := f.m.generation, f.m.lastSnapshot.Generation, f.m.publishedSnapshot, f.m.pendingWorkerArm
	f.m.mu.Unlock()
	if mgen != reserved || retainedGen != 7 || pub != 7 || !debt {
		t.Fatalf("premise broken: m.gen=%d retained=%d pub=%d debt=%v, want %d/7/7/true — "+
			"the lost republish must leave Go's counters untouched", mgen, retainedGen, pub, debt, reserved)
	}
	installed, _ := f.model.installedState()
	if installed != reserved+1 {
		t.Fatalf("premise broken: helper holds %d, want unallocated %d", installed, reserved+1)
	}
	if gens := f.model.applyGenerations(); !equalUint64s(gens, []uint64{reserved + 1}) {
		t.Fatalf("premise broken: republish offers = %v, want single unallocated [%d]", gens, reserved+1)
	}

	// The deferral offers strictly above the held-but-unbooked generation.
	appliesBefore := f.model.countVerb("apply_snapshot")
	if _, err := f.apply(t, compiled); err != nil {
		t.Fatalf("deferred apply returned %v, want nil", err)
	}
	if got := f.model.countVerb("apply_snapshot"); got != appliesBefore {
		t.Fatalf("apply_snapshot requests during deferral = %d, want 0", got-appliesBefore)
	}
	f.m.mu.Lock()
	stored := f.m.lastSnapshot.Generation
	f.m.mu.Unlock()
	if stored != installed+1 {
		t.Fatalf("stored %d, want held+1 = %d — the offer is not strictly above H", stored, installed+1)
	}

	// First service tick: single offer, lands, response lost. No conflict
	// retry may appear: strictly-above admits without consulting equality.
	f.endXSKWindow()
	f.model.scriptDrops(1)
	if err := f.tick(t); err == nil {
		t.Fatal("the dropped service tick returned nil, want the transport error")
	}
	if gens := f.model.applyGenerations()[appliesBefore:]; !equalUint64s(gens, []uint64{stored}) {
		t.Fatalf("apply_snapshot offers = %v, want single [%d] (first attempt — no conflict retry)", gens, stored)
	}
	if f.ctrl.stored.Enabled != 0 {
		t.Fatalf("ctrl.Enabled = %d after the lost response, want 0 (transient fail-close)", f.ctrl.stored.Enabled)
	}

	// Identical re-offer: idempotent admit, bookkeeping converges, ctrl
	// re-arms, then cessation.
	if err := f.tick(t); err != nil {
		t.Fatalf("re-offer tick returned %v, want nil (idempotent admit)", err)
	}
	published, last, open := f.gate()
	if open || published != last || published != stored {
		t.Fatalf("gate not converged after the re-offer (published=%d last=%d)", published, last)
	}
	if f.ctrl.stored.Enabled != 1 {
		t.Fatalf("ctrl.Enabled = %d after convergence, want re-enabled 1", f.ctrl.stored.Enabled)
	}
	sent := f.lastApplyOfType(t, "apply_snapshot")
	if sent.Snapshot == nil || !snapshotHasZone(sent.Snapshot, markerZone9824) {
		t.Fatal("the admitted apply_snapshot does not carry the COMPILED marker zone")
	}
	appliesAfterConverge := f.model.countVerb("apply_snapshot")
	if err := f.tick(t); err != nil {
		t.Fatalf("cessation tick returned %v, want nil", err)
	}
	if got := f.model.countVerb("apply_snapshot"); got != appliesAfterConverge {
		t.Fatalf("apply_snapshot requests after convergence = %d, want 0 (no cessation)", got-appliesAfterConverge)
	}
	if f.neighborCalls != 0 || f.fabricCalls != 0 {
		t.Fatalf("sampler calls = neighbors %d fabrics %d, want 0/0", f.neighborCalls, f.fabricCalls)
	}
	f.assertNoViolations(t)
}

// TestCompileRebaseAdmitsAfterLostRepublishNormal9824 is Cell 3
// (non-deferred arm): the same 2a state on the normal path must commit
// successfully. Pre-fix it publishes below H and the commit spuriously fails
// closed with a rollback refusal.
func TestCompileRebaseAdmitsAfterLostRepublishNormal9824(t *testing.T) {
	f := newFixture9824(t)
	n0 := neighbor9824(7, "10.0.0.2", "02:00:00:00:00:01")
	alpha := []FabricSnapshot{fabricAlpha9824()}
	seed := f.seedPublished(t, 7, baseZones9824(), []NeighborSnapshot{n0}, alpha)
	f.m.mu.Lock()
	seed.DeferWorkers = true
	if h, ok := snapshotContentHash(seed); ok {
		f.m.lastSnapshotHash = h
	}
	f.m.pendingWorkerArm = true
	f.m.mu.Unlock()
	f.model.seed(7, 0, digest9824(t, seed), []FabricSnapshot{fabricAlpha9824()})
	f.endXSKWindow() // proven from the start: no deferral on this arm.
	f.neighborFunc = func(*config.Config) []NeighborSnapshot { return []NeighborSnapshot{n0} }
	f.fabricFunc = func(*config.Config) []FabricSnapshot { return append([]FabricSnapshot(nil), alpha...) }

	epoch0 := f.m.partialUpdateEpoch.Load()
	reserved := f.m.bumpGeneration()
	compiled := f.snap9824(reserved,
		[]ZoneSnapshot{{Name: "zone-a", ID: 1}, {Name: markerZone9824, ID: 77}},
		[]NeighborSnapshot{n0}, append([]FabricSnapshot(nil), alpha...))
	compiled.partialUpdateEpoch = epoch0

	f.model.scriptDrops(1)
	f.m.mu.Lock()
	retryErr := f.m.retryDeferredWorkerArmLocked()
	f.m.mu.Unlock()
	if retryErr == nil {
		t.Fatal("premise broken: the dropped worker-arm retry returned nil")
	}
	installed, _ := f.model.installedState()
	if installed != reserved+1 {
		t.Fatalf("premise broken: helper holds %d, want unallocated %d", installed, reserved+1)
	}

	appliesBefore := f.model.countVerb("apply_snapshot")
	if _, err := f.apply(t, compiled); err != nil {
		t.Fatalf("commit returned %v — a spurious fail-closed on a below-H publish (#9824 2a)", err)
	}
	if gens := f.model.applyGenerations()[appliesBefore:]; !equalUint64s(gens, []uint64{reserved + 2}) {
		t.Fatalf("commit offers = %v, want single [%d]", gens, reserved+2)
	}
	sent := f.lastApplyOfType(t, "apply_snapshot")
	if sent.Snapshot == nil || !snapshotHasZone(sent.Snapshot, markerZone9824) {
		t.Fatal("the committed apply_snapshot does not carry the COMPILED marker zone")
	}
	f.m.mu.Lock()
	pub, last := f.m.publishedSnapshot, f.m.lastSnapshot.Generation
	f.m.mu.Unlock()
	if pub != last || pub != reserved+2 {
		t.Fatalf("published=%d last=%d, want both %d", pub, last, reserved+2)
	}
	if f.ctrl.stored.Enabled != 1 {
		t.Fatalf("ctrl.Enabled = %d after a successful commit, want 1", f.ctrl.stored.Enabled)
	}
	f.assertNoViolations(t)
}

// TestCompileRebaseNumbering9824 is Cell 4: with no interleaving the stored
// generation is exactly reserved+2 and m.generation advances exactly 3. A
// single-++ implementation REDs here — the round-2 regression as a number.
func TestCompileRebaseNumbering9824(t *testing.T) {
	f := newFixture9824(t)
	n0 := neighbor9824(7, "10.0.0.2", "02:00:00:00:00:01")
	alpha := []FabricSnapshot{fabricAlpha9824()}
	f.seedPublished(t, 7, baseZones9824(), []NeighborSnapshot{n0}, alpha)
	f.endXSKWindow()
	f.neighborFunc = func(*config.Config) []NeighborSnapshot { return []NeighborSnapshot{n0} }
	f.fabricFunc = func(*config.Config) []FabricSnapshot { return append([]FabricSnapshot(nil), alpha...) }

	f.m.mu.Lock()
	genBefore := f.m.generation
	f.m.mu.Unlock()
	epoch0 := f.m.partialUpdateEpoch.Load()
	reserved := f.m.bumpGeneration()
	compiled := f.snap9824(reserved,
		[]ZoneSnapshot{{Name: "zone-a", ID: 1}, {Name: markerZone9824, ID: 77}},
		[]NeighborSnapshot{n0}, append([]FabricSnapshot(nil), alpha...))
	compiled.partialUpdateEpoch = epoch0

	appliesBefore := f.model.countVerb("apply_snapshot")
	if _, err := f.apply(t, compiled); err != nil {
		t.Fatalf("commit returned %v, want nil", err)
	}
	f.m.mu.Lock()
	genAfter, stored, pub := f.m.generation, f.m.lastSnapshot.Generation, f.m.publishedSnapshot
	f.m.mu.Unlock()
	if stored != reserved+2 {
		t.Fatalf("stored = %d, want reserved+2 = %d", stored, reserved+2)
	}
	if genAfter-genBefore != 3 {
		t.Fatalf("m.generation advanced %d (from %d to %d), want exactly 3 (reserve + rebase)", genAfter-genBefore, genBefore, genAfter)
	}
	if pub != stored {
		t.Fatalf("published=%d stored=%d, want both %d", pub, stored, stored)
	}
	if gens := f.model.applyGenerations()[appliesBefore:]; !equalUint64s(gens, []uint64{stored}) {
		t.Fatalf("commit offers = %v, want single [%d]", gens, stored)
	}
	f.assertNoViolations(t)
}

// TestHelperModelAdmitsIdenticalRetry9824 is Cell 5: the #4036 arm the
// identical-re-offer closure relies on. Same generation + same digest admits
// with zero conflict; same generation + different digest conflicts. This pins
// the MODEL against future edits that would false-green Cell 3's re-offer.
func TestHelperModelAdmitsIdenticalRetry9824(t *testing.T) {
	f := newFixture9824(t)
	n0 := neighbor9824(7, "10.0.0.2", "02:00:00:00:00:01")
	alpha := []FabricSnapshot{fabricAlpha9824()}
	first := f.snap9824(10,
		[]ZoneSnapshot{{Name: "zone-a", ID: 1}, {Name: markerZone9824, ID: 77}},
		[]NeighborSnapshot{n0}, append([]FabricSnapshot(nil), alpha...))
	if err := stampSnapshotContentDigest(first); err != nil {
		t.Fatalf("stamp digest: %v", err)
	}
	f.model.seed(10, 0, first.ContentDigest, alpha)

	retry := *first
	retry.Neighbors = append([]NeighborSnapshot(nil), first.Neighbors...)
	var status ProcessStatus
	if err := f.model.hook(ControlRequest{Type: "apply_snapshot", Snapshot: &retry}, &status); err != nil {
		t.Fatalf("identical re-offer refused: %v — the #4036 idempotent-admit arm is broken", err)
	}
	changed := f.snap9824(10,
		[]ZoneSnapshot{{Name: "zone-a", ID: 1}, {Name: "other-zone", ID: 78}},
		[]NeighborSnapshot{n0}, append([]FabricSnapshot(nil), alpha...))
	if err := stampSnapshotContentDigest(changed); err != nil {
		t.Fatalf("stamp digest: %v", err)
	}
	if err := f.model.hook(ControlRequest{Type: "apply_snapshot", Snapshot: changed}, &status); err == nil {
		t.Fatal("different-content same-generation offer admitted, want a content conflict")
	} else if !isSnapshotContentConflict(err) {
		t.Fatalf("different-content refusal = %v, want a content-conflict refusal", err)
	}
	if gens := f.model.applyGenerations(); !equalUint64s(gens, []uint64{10, 10}) {
		t.Fatalf("offers = %v, want [10 10]", gens)
	}
	f.assertNoViolations(t)
}

// driftTerminal9824 is the terminal strand vector Cell R compares across its
// dual-numbering legs. Numbering legs (retained/installed/published/mgen)
// must match at +2; strand legs (unknown/debtZero/ctrlDisabled) must match
// exactly and show convergence.
type driftTerminal9824 struct {
	retained     uint64
	installed    uint64
	published    uint64
	mgen         uint64
	unknown      bool
	debtZero     bool
	ctrlDisabled bool
}

// TestCompileRebaseDriftRepairIsPreExistingShape9824 is Cell R: Astra's
// round-3 composition (resample β / lands-lost + generation-no-op fabric
// sync clearing debt and the helper's digest + equal-gen conflict + lost
// retry), run at fixed numbering (real apply) and pre-fix numbering
// (allocator AND retained generation emulated — decrementing only the
// snapshot would leave retry allocation on the fixed counter). Pre-#9642
// both legs stranded below installed (the conceded residual, #10041);
// #9642's deliberate retry adoption (debt consumes the possibly-landed
// retry generation — the updated 9520 conflict_then_transport_error cell
// pins it on this same tick path, and it is #10041's repair direction #1)
// repairs the trace, so both legs must now reach the identical CONVERGED
// terminal at +2 numbering: the repair is pre-existing shape at new
// numbers, not v4-created. #10041 handoff: r2 already converges via the
// rebase (Cell 3); r3-main (here) and r3-short (same shape) converge via
// retry adoption — #10041 owner to re-verify scope (docs/log/10064.md).
func TestCompileRebaseDriftRepairIsPreExistingShape9824(t *testing.T) {
	fixed := runDriftLeg9824(t, true)
	prefix := runDriftLeg9824(t, false)
	t.Logf("drift terminal vectors: fixed=%+v prefix=%+v", fixed, prefix)
	if fixed.retained != prefix.retained+2 || fixed.installed != prefix.installed+2 ||
		fixed.published != prefix.published+2 || fixed.mgen != prefix.mgen+2 {
		t.Fatalf("legs differ by more than numbering: fixed=%+v prefix=%+v", fixed, prefix)
	}
	if fixed.unknown != prefix.unknown ||
		fixed.debtZero != prefix.debtZero || fixed.ctrlDisabled != prefix.ctrlDisabled {
		t.Fatalf("terminal strand differs between legs: fixed=%+v prefix=%+v", fixed, prefix)
	}
	if fixed.unknown || !fixed.debtZero || fixed.ctrlDisabled {
		t.Fatalf("terminal strand not converged: %+v — want known + debt-clear + ctrl re-enabled", fixed)
	}
}

func runDriftLeg9824(t *testing.T, fixed bool) driftTerminal9824 {
	t.Helper()
	f := newFixture9824(t)
	n0 := neighbor9824(7, "10.0.0.2", "02:00:00:00:00:01")
	alpha := fabricAlpha9824()
	beta := fabricBeta9824()
	f.seedPublished(t, 7, baseZones9824(), []NeighborSnapshot{n0}, []FabricSnapshot{alpha})
	f.forcePendingXSK()
	// Neighbor sampling is stable; the script churns fabrics only.
	f.neighborFunc = func(*config.Config) []NeighborSnapshot { return []NeighborSnapshot{n0} }
	samples := [][]FabricSnapshot{{beta}, {alpha}}
	if fixed {
		// Failed-sync sample, compile resample, tick-1 resample, sync sample.
		samples = [][]FabricSnapshot{{alpha}, {alpha}, {beta}, {alpha}}
	}
	f.fabricFunc = func(*config.Config) []FabricSnapshot {
		if len(samples) == 0 {
			t.Fatalf("fabric sampler called more times than the script allows")
		}
		out := samples[0]
		samples = samples[1:]
		return append([]FabricSnapshot(nil), out...)
	}

	// Store Cα: the fixed leg drives the real deferred apply (reserve →
	// lost partial → resample α → rebase → defer); the pre-fix leg seeds
	// the equivalent post-store state with both allocator and retained
	// generation at pre-fix numbering.
	if fixed {
		epoch0 := f.m.partialUpdateEpoch.Load()
		reserved := f.m.bumpGeneration()
		compiled := f.snap9824(reserved,
			[]ZoneSnapshot{{Name: "zone-a", ID: 1}, {Name: markerZone9824, ID: 77}},
			[]NeighborSnapshot{n0}, []FabricSnapshot{func() FabricSnapshot { r := alpha; r.PeerMAC = ""; return r }()})
		compiled.partialUpdateEpoch = epoch0
		// Lost fabric partial during the build: debt marked, epoch moved.
		f.model.scriptPartialDrops(1)
		f.m.SyncFabricState()
		f.m.mu.Lock()
		debtMarked := f.m.partialOutcomeUnknown == partialFabrics
		epochMoved := f.m.partialUpdateEpoch.Load() == epoch0+1
		f.m.mu.Unlock()
		if !debtMarked || !epochMoved {
			t.Fatalf("premise broken: debt marked=%v epoch moved=%v — the lost partial did not register", debtMarked, epochMoved)
		}
		appliesBefore := f.model.countVerb("apply_snapshot")
		if _, err := f.apply(t, compiled); err != nil {
			t.Fatalf("deferred apply returned %v, want nil", err)
		}
		if got := f.model.countVerb("apply_snapshot"); got != appliesBefore {
			t.Fatalf("apply_snapshot requests during deferral = %d, want 0", got-appliesBefore)
		}
		f.m.mu.Lock()
		stored, pub, mgen := f.m.lastSnapshot.Generation, f.m.publishedSnapshot, f.m.generation
		storedFabrics := append([]FabricSnapshot(nil), f.m.lastSnapshot.Fabrics...)
		debtKept := f.m.partialOutcomeUnknown == partialFabrics
		f.m.mu.Unlock()
		if stored != reserved+2 || mgen != reserved+2 || pub != 7 {
			t.Fatalf("store = %d/%d/%d (stored/mgen/pub), want %d/%d/7", stored, mgen, pub, reserved+2, reserved+2)
		}
		if !debtKept {
			t.Fatal("premise broken: the deferral resolved the fabric debt — it must preserve it")
		}
		if !fabricSnapshotsEqual(storedFabrics, []FabricSnapshot{alpha}) {
			t.Fatalf("stored fabrics = %+v, want resampled α — the compile resample did not run", storedFabrics)
		}
		installed, _ := f.model.installedState()
		if stored <= installed {
			t.Fatalf("boundary broken: stored %d at-or-below helper-installed %d", stored, installed)
		}
	} else {
		// Pre-fix numbering: reserve 8 stored verbatim.
		stored := f.snap9824(8,
			[]ZoneSnapshot{{Name: "zone-a", ID: 1}, {Name: markerZone9824, ID: 77}},
			[]NeighborSnapshot{n0}, []FabricSnapshot{alpha})
		f.m.mu.Lock()
		f.m.lastSnapshot = stored
		f.m.generation = 8
		f.m.partialOutcomeUnknown = partialFabrics
		f.m.partialUpdateEpoch.Add(1)
		f.m.mu.Unlock()
	}
	f.endXSKWindow()
	f.m.mu.Lock()
	store := f.m.lastSnapshot.Generation
	f.m.mu.Unlock()

	// Tick 1: resample β into the COPY; offer lands, response lost. The
	// copy is never retained: rows, debt and counters stay pre-tick.
	f.model.scriptDrops(1)
	tick1base := f.model.countVerb("apply_snapshot")
	if err := f.tick(t); err == nil {
		t.Fatal("tick 1 returned nil, want the dropped-response transport error")
	} else if errors.Is(err, errHelperRejected) {
		t.Fatalf("tick 1 error = %v, want a TRANSPORT error, not a refusal", err)
	}
	if gens := f.model.applyGenerations()[tick1base:]; !equalUint64s(gens, []uint64{store}) {
		t.Fatalf("tick-1 offers = %v, want single [%d]", gens, store)
	}
	offered := f.lastApplyOfType(t, "apply_snapshot")
	if offered.Snapshot == nil || !fabricSnapshotsEqual(offered.Snapshot.Fabrics, []FabricSnapshot{beta}) {
		t.Fatalf("tick-1 offered fabrics = %+v, want resampled β", offered.Snapshot.Fabrics)
	}
	f.m.mu.Lock()
	retainedFabrics := append([]FabricSnapshot(nil), f.m.lastSnapshot.Fabrics...)
	retained, pub, mgen := f.m.lastSnapshot.Generation, f.m.publishedSnapshot, f.m.generation
	debtKept := f.m.partialOutcomeUnknown == partialFabrics
	f.m.mu.Unlock()
	if !fabricSnapshotsEqual(retainedFabrics, []FabricSnapshot{alpha}) {
		t.Fatalf("retained fabrics = %+v after a lost tick, want α — the copy leaked into retained state", retainedFabrics)
	}
	if retained != store || pub != 7 || mgen != store || !debtKept {
		t.Fatalf("post-tick-1 = retained %d pub %d mgen %d debt-kept %v, want %d/7/%d/true",
			retained, pub, mgen, debtKept, store, store)
	}
	if f.ctrl.stored.Enabled != 0 {
		t.Fatalf("ctrl.Enabled = %d after tick 1, want disabled 0", f.ctrl.stored.Enabled)
	}

	// The no-op writeback: sample α equals RETAINED α, so Go advances
	// nothing — but the send still flips the helper β→α (digest cleared)
	// and clears the debt.
	f.m.SyncFabricState()
	f.m.mu.Lock()
	mgenAfterSync := f.m.generation
	debt := f.m.partialOutcomeUnknown
	f.m.mu.Unlock()
	if mgenAfterSync != store {
		t.Fatalf("m.generation = %d after the α refresh, want still %d — the writeback was not a no-op", mgenAfterSync, store)
	}
	if debt != 0 {
		t.Fatalf("partial debt = %v after a successful sync, want clear", debt)
	}
	installed, digest := f.model.installedState()
	if digest != "" {
		t.Fatalf("helper digest = %q after the β→α fabric flip, want cleared", digest)
	}
	if installed != store {
		t.Fatalf("helper holds %d, want the landed %d", installed, store)
	}

	// Tick 2: retained Cα/store conflicts (empty installed digest); the
	// retry at store+1 lands and loses its response. The lost retry
	// generation is retained as retry debt (deliberate #9642 — debt
	// consumes the possibly-landed generation, the updated 9520
	// conflict_then_transport_error cell pins it on this tick path):
	// m.generation takes 11/9 with the helper.
	f.model.scriptDrops(1)
	tick2base := f.model.countVerb("apply_snapshot")
	if err := f.tick(t); err == nil {
		t.Fatal("tick 2 returned nil, want the dropped-retry transport error")
	} else if errors.Is(err, errHelperRejected) {
		t.Fatalf("tick 2 error = %v, want a TRANSPORT error, not a refusal", err)
	}
	if gens := f.model.applyGenerations()[tick2base:]; !equalUint64s(gens, []uint64{store, store + 1}) {
		t.Fatalf("tick-2 offers = %v, want [%d %d] (conflict + landed-lost retry)", gens, store, store+1)
	}
	f.m.mu.Lock()
	mgen, pub, retained = f.m.generation, f.m.publishedSnapshot, f.m.lastSnapshot.Generation
	f.m.mu.Unlock()
	installed, _ = f.model.installedState()
	if mgen != store+1 || pub != 7 || retained != store+1 || installed != store+1 {
		t.Fatalf("post-tick-2 = mgen %d pub %d retained %d installed %d, want %d/7/%d/%d (lost retry adopted)",
			mgen, pub, retained, installed, store+1, store+1, store+1)
	}
	if f.ctrl.stored.Enabled != 0 {
		t.Fatalf("ctrl.Enabled = %d after tick 2, want disabled 0", f.ctrl.stored.Enabled)
	}

	// Tick 3 (healthy): the retained offer is the landed retry generation
	// with identical content — it admits idempotently (#4036 arm, Cell 5)
	// and bookkeeping converges. Pre-#9642 this offered store below
	// installed store+1 and rollback-refused every tick (the #10041
	// residual); the retry adoption above is #10041's repair direction #1,
	// so this leg now proves the repair. Rollback-no-retry mechanics keep
	// their own pin (TestRollbackRefusalRetriesNothing9824).
	tick3base := f.model.countVerb("apply_snapshot")
	if err := f.tick(t); err != nil {
		t.Fatalf("tick 3 returned %v, want nil (identical admit of the adopted retry)", err)
	}
	if gens := f.model.applyGenerations()[tick3base:]; !equalUint64s(gens, []uint64{store + 1}) {
		t.Fatalf("tick-3 offers = %v, want single [%d] (identical re-offer, no conflict retry)", gens, store+1)
	}
	sent := f.lastApplyOfType(t, "apply_snapshot")
	if sent.Snapshot == nil || !snapshotHasZone(sent.Snapshot, markerZone9824) {
		t.Fatal("the converged apply_snapshot does not carry the COMPILED marker zone")
	}
	f.m.mu.Lock()
	mgen, pub, retained = f.m.generation, f.m.publishedSnapshot, f.m.lastSnapshot.Generation
	unknown := f.m.applySnapshotOutcomeUnknown
	debtZero := f.m.partialOutcomeUnknown == 0
	f.m.mu.Unlock()
	if mgen != store+1 || pub != store+1 || retained != store+1 {
		t.Fatalf("post-tick-3 = mgen %d pub %d retained %d, want all %d (not converged)",
			mgen, pub, retained, store+1)
	}
	if unknown || !debtZero {
		t.Fatalf("post-tick-3 unknown=%v debtZero=%v, want false/true — the admit did not settle the books", unknown, debtZero)
	}
	if f.ctrl.stored.Enabled != 1 {
		t.Fatalf("ctrl.Enabled = %d after tick 3, want re-enabled 1", f.ctrl.stored.Enabled)
	}

	// Tick 4: cessation — the gate is closed, nothing is offered.
	tick4base := f.model.countVerb("apply_snapshot")
	if err := f.tick(t); err != nil {
		t.Fatalf("tick 4 returned %v, want nil (cessation)", err)
	}
	if gens := f.model.applyGenerations()[tick4base:]; len(gens) != 0 {
		t.Fatalf("tick-4 offers = %v, want none (no cessation)", gens)
	}
	terminal := driftTerminal9824{
		retained: retained, installed: store + 1, published: pub, mgen: mgen,
		unknown: unknown, debtZero: debtZero,
		ctrlDisabled: f.ctrl.stored.Enabled == 0,
	}
	installedNow, _ := f.model.installedState()
	if installedNow != store+1 {
		t.Fatalf("helper holds %d at terminal, want %d", installedNow, store+1)
	}
	f.assertNoViolations(t)
	return terminal
}

// TestRollbackRefusalRetriesNothing9824 pins the rollback-refusal mechanics
// the old Cell R tick-3 carried: a below-installed offer is refused once,
// retried never, with frozen bookkeeping and fail-closed ctrl. FORCED setup,
// disclosed (GPT-P3 corrected the original "no natural trace" overclaim):
// one natural trace still offers below installed — a lost scheduler (or
// worker-arm) republish over a deferral, pinned end-to-end by
// TestDeferredTickRollsBackAfterLostSchedulerPublish9824 — while the rebase
// (Cell 3) and retry adoption (Cell R) close the others. The helper is
// hand-seeded ahead of retained to pin the gate in isolation; do not
// "naturalize" this into a reachable script.
func TestRollbackRefusalRetriesNothing9824(t *testing.T) {
	f := newFixture9824(t)
	n0 := neighbor9824(7, "10.0.0.2", "02:00:00:00:00:01")
	alpha := []FabricSnapshot{fabricAlpha9824()}
	seed := f.seedPublished(t, 7, baseZones9824(), []NeighborSnapshot{n0}, alpha)
	f.endXSKWindow()
	// Retained C@10 behind a helper holding 11: the next tick offers below
	// installed. Direct set, prefix-leg style — the mechanics need an open
	// gate, not a store narrative.
	stored := f.snap9824(10,
		[]ZoneSnapshot{{Name: "zone-a", ID: 1}, {Name: markerZone9824, ID: 77}},
		[]NeighborSnapshot{n0}, append([]FabricSnapshot(nil), alpha...))
	f.m.mu.Lock()
	f.m.lastSnapshot = stored
	f.m.generation = 10
	f.m.mu.Unlock()
	f.model.seed(11, 0, digest9824(t, seed), append([]FabricSnapshot(nil), alpha...))
	tickBase := f.model.countVerb("apply_snapshot")
	tickErr := f.tick(t)
	if tickErr == nil {
		t.Fatal("tick returned nil, want the rollback refusal")
	}
	if !errors.Is(tickErr, errHelperRejected) || !strings.Contains(tickErr.Error(), rollbackPrefix9824) {
		t.Fatalf("tick error = %v, want a ROLLBACK refusal", tickErr)
	}
	if gens := f.model.applyGenerations()[tickBase:]; !equalUint64s(gens, []uint64{10}) {
		t.Fatalf("offers = %v, want single [10] (refusal retries nothing)", gens)
	}
	sent := f.lastApplyOfType(t, "apply_snapshot")
	if sent.Snapshot == nil || !snapshotHasZone(sent.Snapshot, markerZone9824) {
		t.Fatal("the refused apply_snapshot does not carry the COMPILED marker zone")
	}
	f.m.mu.Lock()
	mgen, pub, retained := f.m.generation, f.m.publishedSnapshot, f.m.lastSnapshot.Generation
	unknown := f.m.applySnapshotOutcomeUnknown
	f.m.mu.Unlock()
	if mgen != 10 || pub != 7 || retained != 10 {
		t.Fatalf("bookkeeping moved after a refusal: mgen %d pub %d retained %d, want 10/7/10", mgen, pub, retained)
	}
	if unknown {
		t.Fatal("refusal set the unknown-outcome mark — a refusal proves the helper kept its state")
	}
	if f.ctrl.stored.Enabled != 0 {
		t.Fatalf("ctrl.Enabled = %d after the refusal, want disabled 0 (fail closed)", f.ctrl.stored.Enabled)
	}
	f.assertNoViolations(t)
}

// TestDeferredTickRollsBackAfterLostSchedulerPublish9824 pins the reachable
// below-installed tick offer GPT-P3 caught the rollback-mechanics header
// overclaiming away: over deferred retained G, a scheduler republish of
// m.generation+1 lands but loses its response — the direct-request path
// (UpdatePolicyScheduleState) commits nothing on failure, so retained/mgen
// stay G while the helper holds G+1 with the unknown-outcome mark set — and
// the mark suppresses the generation-only catch-up that would otherwise
// mistake the helper's G+1 status report for possession of G. The tick
// offers G below installed G+1: rollback refusal, no retry, frozen
// bookkeeping, fail-closed ctrl, mark kept. Handled, not stranded: the next
// commit's rebase offers strictly above and converges (tail of this cell).
// Same shape as a lost worker-arm republish (Cell 3 premise proves that
// path also commits nothing); the scheduler is the cited instance.
func TestDeferredTickRollsBackAfterLostSchedulerPublish9824(t *testing.T) {
	f := newFixture9824(t)
	n0 := neighbor9824(7, "10.0.0.2", "02:00:00:00:00:01")
	alpha := []FabricSnapshot{fabricAlpha9824()}
	f.seedPublished(t, 7, baseZones9824(), []NeighborSnapshot{n0}, alpha)
	f.forcePendingXSK()
	// No resample on any path (no partial verb crosses the epoch, no mark
	// until the scheduler's loss — and the scheduler resamples nothing with
	// nothing marked): echo retained content and prove it by zero calls.
	f.neighborFunc = func(*config.Config) []NeighborSnapshot { return []NeighborSnapshot{n0} }
	f.fabricFunc = func(*config.Config) []FabricSnapshot { return append([]FabricSnapshot(nil), alpha...) }

	// Deferred C@10 through the real apply (Cell-2 shape, zone-b content).
	epochB := f.m.partialUpdateEpoch.Load()
	reservedB := f.m.bumpGeneration()
	deferred := f.snap9824(reservedB,
		[]ZoneSnapshot{{Name: "zone-a", ID: 1}, {Name: "zone-b", ID: 2}},
		[]NeighborSnapshot{n0}, append([]FabricSnapshot(nil), alpha...))
	deferred.partialUpdateEpoch = epochB
	appliesBefore := f.model.countVerb("apply_snapshot")
	if _, err := f.apply(t, deferred); err != nil {
		t.Fatalf("deferral apply returned %v, want nil", err)
	}
	if got := f.model.countVerb("apply_snapshot"); got != appliesBefore {
		t.Fatalf("apply_snapshot requests during deferral = %d, want 0", got-appliesBefore)
	}
	publishedB, lastB, openB := f.gate()
	if !openB || publishedB != 7 || lastB != 10 {
		t.Fatalf("gate after deferral = published %d last %d open %v, want 7/10/open", publishedB, lastB, openB)
	}

	// The lost scheduler republish of unallocated m.generation+1, through
	// the real entry point. Direct-request failure commits nothing: Go's
	// counters stay G while the helper takes G+1 with the mark set.
	f.model.scriptDrops(1)
	schedErr := f.m.UpdatePolicyScheduleState(f.cfg, map[string]bool{})
	if schedErr == nil {
		t.Fatal("premise broken: the dropped scheduler publish returned nil")
	} else if errors.Is(schedErr, errHelperRejected) {
		t.Fatalf("premise broken: scheduler error = %v, want a TRANSPORT error, not a refusal", schedErr)
	}
	if gens := f.model.applyGenerations(); !equalUint64s(gens, []uint64{11}) {
		t.Fatalf("premise broken: scheduler offers = %v, want single unallocated [11]", gens)
	}
	f.m.mu.Lock()
	mgen, retainedGen, pub := f.m.generation, f.m.lastSnapshot.Generation, f.m.publishedSnapshot
	unknown := f.m.applySnapshotOutcomeUnknown
	f.m.mu.Unlock()
	if mgen != 10 || retainedGen != 10 || pub != 7 || !unknown {
		t.Fatalf("premise broken: mgen=%d retained=%d pub=%d unknown=%v, want 10/10/7/true — the lost republish must leave Go's counters untouched with the mark set", mgen, retainedGen, pub, unknown)
	}
	installed, _ := f.model.installedState()
	if installed != 11 {
		t.Fatalf("premise broken: helper holds %d, want unallocated 11", installed)
	}

	// The helper genuinely holds 11, so a status poll would report it;
	// mirror that report. The unknown-outcome mark must still suppress the
	// generation-only catch-up that would mistake it for possession of 10:
	// the tick below must OFFER (not skip), then be refused below installed.
	f.m.mu.Lock()
	f.m.lastStatus.LastSnapshotGeneration = 11
	f.m.mu.Unlock()
	tickBase := f.model.countVerb("apply_snapshot")
	tickErr := f.tick(t)
	if tickErr == nil {
		t.Fatal("tick returned nil, want the rollback refusal")
	}
	if !errors.Is(tickErr, errHelperRejected) || !strings.Contains(tickErr.Error(), rollbackPrefix9824) {
		t.Fatalf("tick error = %v, want a ROLLBACK refusal", tickErr)
	}
	if gens := f.model.applyGenerations()[tickBase:]; !equalUint64s(gens, []uint64{10}) {
		t.Fatalf("tick offers = %v, want single [10] (catch-up stood down, refusal retries nothing)", gens)
	}
	refused := f.lastApplyOfType(t, "apply_snapshot")
	if refused.Snapshot == nil || refused.Snapshot.Generation != 10 || !snapshotHasZone(refused.Snapshot, "zone-b") {
		t.Fatal("the refused offer is not the deferred C@10 snapshot")
	}
	if snapshotHasZone(refused.Snapshot, markerZone9824) {
		t.Fatal("the refused offer carries the compiled marker — the tick offered something other than retained")
	}
	f.m.mu.Lock()
	mgen, pub, retainedGen = f.m.generation, f.m.publishedSnapshot, f.m.lastSnapshot.Generation
	unknown = f.m.applySnapshotOutcomeUnknown
	f.m.mu.Unlock()
	if mgen != 10 || pub != 7 || retainedGen != 10 {
		t.Fatalf("bookkeeping moved after the refusal: mgen %d pub %d retained %d, want 10/7/10", mgen, pub, retainedGen)
	}
	if !unknown {
		t.Fatal("refusal cleared the unknown-outcome mark — a refusal proves the helper kept its state, and the scheduler's outcome is still unknown")
	}
	if f.ctrl.stored.Enabled != 0 {
		t.Fatalf("ctrl.Enabled = %d after the refusal, want disabled 0 (fail closed)", f.ctrl.stored.Enabled)
	}

	// Handled: the next commit's rebase offers strictly above installed
	// and converges with the marker.
	f.endXSKWindow()
	epochD := f.m.partialUpdateEpoch.Load()
	reservedD := f.m.bumpGeneration()
	compiled := f.snap9824(reservedD,
		[]ZoneSnapshot{{Name: "zone-a", ID: 1}, {Name: markerZone9824, ID: 77}},
		[]NeighborSnapshot{n0}, append([]FabricSnapshot(nil), alpha...))
	compiled.partialUpdateEpoch = epochD
	if _, err := f.apply(t, compiled); err != nil {
		t.Fatalf("recovery commit returned %v, want nil", err)
	}
	f.m.mu.Lock()
	stored, pub := f.m.lastSnapshot.Generation, f.m.publishedSnapshot
	unknown = f.m.applySnapshotOutcomeUnknown
	f.m.mu.Unlock()
	if stored != 13 || pub != 13 {
		t.Fatalf("recovery stored/published = %d/%d, want 13/13 (reserve 11 + rebase 2)", stored, pub)
	}
	if unknown {
		t.Fatal("recovery left the unknown-outcome mark set — the admit did not settle the books")
	}
	installed, _ = f.model.installedState()
	if installed != 13 {
		t.Fatalf("helper holds %d after recovery, want 13", installed)
	}
	if f.ctrl.stored.Enabled != 1 {
		t.Fatalf("ctrl.Enabled = %d after recovery, want re-enabled 1", f.ctrl.stored.Enabled)
	}
	sent := f.lastApplyOfType(t, "apply_snapshot")
	if sent.Snapshot == nil || !snapshotHasZone(sent.Snapshot, markerZone9824) {
		t.Fatal("the converged apply_snapshot does not carry the COMPILED marker zone")
	}
	if gens := f.model.applyGenerations(); !equalUint64s(gens, []uint64{11, 10, 13}) {
		t.Fatalf("wire offers = %v, want [11 10 13] (lost republish, refused tick, recovery)", gens)
	}
	if f.neighborCalls != 0 || f.fabricCalls != 0 {
		t.Fatalf("sampler calls = neighbors %d fabrics %d, want 0/0 — nothing here should resample", f.neighborCalls, f.fabricCalls)
	}
	f.assertNoViolations(t)
}

// TestCompileRebaseRefusesToWrapAtExhaustion9824 pins the allocator ceiling:
// increments saturate instead of wrapping, and the rebase refuses the commit
// fail-closed within two of math.MaxUint64 (previous-good stays retained AND
// published, nothing is offered). A daemon restart (new incarnation, H=0)
// recovers. Unreachable in practice; the guard exists so strictly-above holds
// unconditionally, not probabilistically.
func TestCompileRebaseRefusesToWrapAtExhaustion9824(t *testing.T) {
	newExhausted := func(t *testing.T, mgen uint64) (*fixture9824, *ConfigSnapshot) {
		t.Helper()
		f := newFixture9824(t)
		n0 := neighbor9824(7, "10.0.0.2", "02:00:00:00:00:01")
		alpha := []FabricSnapshot{fabricAlpha9824()}
		f.seedPublished(t, 7, baseZones9824(), []NeighborSnapshot{n0}, alpha)
		f.forcePendingXSK()
		f.m.mu.Lock()
		f.m.generation = mgen
		f.m.mu.Unlock()
		compiled := f.snap9824(0,
			[]ZoneSnapshot{{Name: "zone-a", ID: 1}, {Name: markerZone9824, ID: 77}},
			[]NeighborSnapshot{n0}, append([]FabricSnapshot(nil), alpha...))
		return f, compiled
	}
	assertRefused := func(t *testing.T, f *fixture9824, compiled *ConfigSnapshot, wantGen uint64) {
		t.Helper()
		appliesBefore := f.model.countVerb("apply_snapshot")
		_, err := f.apply(t, compiled)
		if err == nil {
			t.Fatal("exhausted apply returned nil, want the exhaustion refusal")
		}
		if !strings.Contains(err.Error(), "exhausted") {
			t.Fatalf("exhausted apply error = %v, want it to name exhaustion", err)
		}
		if got := f.model.countVerb("apply_snapshot"); got != appliesBefore {
			t.Fatalf("apply_snapshot requests on a refused commit = %d, want 0 — nothing may be offered", got-appliesBefore)
		}
		f.m.mu.Lock()
		retained, pub, mgen := f.m.lastSnapshot.Generation, f.m.publishedSnapshot, f.m.generation
		markerKept := snapshotHasZone(f.m.lastSnapshot, markerZone9824)
		f.m.mu.Unlock()
		if retained != 7 || pub != 7 || mgen != wantGen || markerKept {
			t.Fatalf("post-refusal = retained %d pub %d mgen %d marker %v, want 7/7/%d/false — previous-good must stay",
				retained, pub, mgen, markerKept, wantGen)
		}
	}

	// Boundary: reserve takes the last value, then the rebase refuses.
	f, compiled := newExhausted(t, math.MaxUint64-1)
	if reserved := f.m.bumpGeneration(); reserved != math.MaxUint64 {
		t.Fatalf("reserve at the boundary = %d, want MaxUint64 (no wrap)", reserved)
	}
	compiled.Generation = math.MaxUint64
	compiled.partialUpdateEpoch = f.m.partialUpdateEpoch.Load()
	assertRefused(t, f, compiled, math.MaxUint64)

	// Saturated: the reserve itself saturates (no wrap to zero), then the
	// rebase refuses.
	f, compiled = newExhausted(t, math.MaxUint64)
	if reserved := f.m.bumpGeneration(); reserved != math.MaxUint64 {
		t.Fatalf("reserve at saturation = %d, want MaxUint64 held (wrap to zero would offer below H)", reserved)
	}
	f.m.mu.Lock()
	if f.m.generation != math.MaxUint64 {
		t.Fatalf("m.generation = %d after a saturated reserve, want MaxUint64 held", f.m.generation)
	}
	f.m.mu.Unlock()
	compiled.Generation = math.MaxUint64
	compiled.partialUpdateEpoch = f.m.partialUpdateEpoch.Load()
	assertRefused(t, f, compiled, math.MaxUint64)

	// First refusal: entering apply at MaxUint64-1, where +=2 also wraps.
	// A MaxUint64-only guard would escape this case.
	f, compiled = newExhausted(t, math.MaxUint64-2)
	if reserved := f.m.bumpGeneration(); reserved != math.MaxUint64-1 {
		t.Fatalf("reserve below the boundary = %d, want MaxUint64-1", reserved)
	}
	compiled.Generation = math.MaxUint64 - 1
	compiled.partialUpdateEpoch = f.m.partialUpdateEpoch.Load()
	assertRefused(t, f, compiled, math.MaxUint64-1)

	// Accepted control: entering apply at MaxUint64-2 stores MaxUint64.
	f, compiled = newExhausted(t, math.MaxUint64-3)
	if reserved := f.m.bumpGeneration(); reserved != math.MaxUint64-2 {
		t.Fatalf("reserve below the boundary = %d, want MaxUint64-2", reserved)
	}
	compiled.Generation = math.MaxUint64 - 2
	compiled.partialUpdateEpoch = f.m.partialUpdateEpoch.Load()
	appliesBefore := f.model.countVerb("apply_snapshot")
	if _, err := f.apply(t, compiled); err != nil {
		t.Fatalf("boundary apply returned %v, want nil (MaxUint64-2 must still allocate)", err)
	}
	if got := f.model.countVerb("apply_snapshot"); got != appliesBefore {
		t.Fatalf("apply_snapshot requests during deferral = %d, want 0", got-appliesBefore)
	}
	f.m.mu.Lock()
	stored, pub, mgen := f.m.lastSnapshot.Generation, f.m.publishedSnapshot, f.m.generation
	f.m.mu.Unlock()
	if stored != math.MaxUint64 || mgen != math.MaxUint64 || pub != 7 {
		t.Fatalf("boundary store = %d/%d/%d (stored/mgen/pub), want MaxUint64/MaxUint64/7", stored, mgen, pub)
	}
	published, last, open := f.gate()
	if !open {
		t.Fatalf("gate CLOSED after the boundary store (published=%d last=%d)", published, last)
	}
	f.endXSKWindow()
	if err := f.tick(t); err != nil {
		t.Fatalf("boundary service tick returned %v, want nil", err)
	}
	if gens := f.model.applyGenerations()[appliesBefore:]; !equalUint64s(gens, []uint64{math.MaxUint64}) {
		t.Fatalf("boundary offers = %v, want single [MaxUint64]", gens)
	}
	sent := f.lastApplyOfType(t, "apply_snapshot")
	if sent.Snapshot == nil || !snapshotHasZone(sent.Snapshot, markerZone9824) {
		t.Fatal("the boundary apply_snapshot does not carry the marker zone")
	}

	// Partial bookkeeping saturates instead of wrapping.
	f, _ = newExhausted(t, math.MaxUint64)
	f.m.mu.Lock()
	f.m.persistResolvedFabricsLocked([]FabricSnapshot{fabricBeta9824()})
	if f.m.generation != math.MaxUint64 {
		t.Fatalf("m.generation = %d after a saturated partial, want MaxUint64 held", f.m.generation)
	}
	f.m.mu.Unlock()

	// FIB bookkeeping saturates instead of wrapping (the saturation precedes
	// the sends; the shim error below is the unprivileged environment, not
	// the assertion — m.generation is).
	f, _ = newExhausted(t, math.MaxUint64)
	n0 := neighbor9824(7, "10.0.0.2", "02:00:00:00:00:01")
	f.neighborFunc = func(*config.Config) []NeighborSnapshot { return []NeighborSnapshot{n0} }
	_, _ = f.m.BumpFIBGeneration()
	f.m.mu.Lock()
	if f.m.generation != math.MaxUint64 {
		t.Fatalf("m.generation = %d after a saturated FIB bump, want MaxUint64 held", f.m.generation)
	}
	f.m.mu.Unlock()
	f.assertNoViolations(t)
}
