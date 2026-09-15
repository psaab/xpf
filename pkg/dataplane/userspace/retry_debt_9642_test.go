package userspace

// #9642: retry debt for a timeout-but-landed apply_snapshot.
//
// A transport-error publish used to disable ctrl with no republish consumer: the
// next status tick re-enabled ctrl and re-synced the classifier maps to the
// retained snapshot while the helper might enforce the lost one. The fix retains
// the attempted snapshot as debt (adopted as m.lastSnapshot with publishedSnapshot
// held back), holds ctrl via snapshotRetryDebtLocked, skips the tick re-sync
// while indebted, and converges through syncSnapshotLocked.
//
// These cells are unprivileged by construction via the #6994/#9337 seams. The
// observable is always production-written map/snapshot state, never in-memory
// manager fields a severed write would leave untouched.

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// transportTimeout9642 models the #4036 case: a deadline that reports failure
// for a publish the helper may already have applied live. It must set the
func transportTimeout9642() error {
	return fmt.Errorf("read unix /run/xpf/userspace-dp.sock: %w", os.ErrDeadlineExceeded)
}

// debtHarness9642 carries the seamed manager plus the request/sync recorders.
// The control hook runs with m.mu held; harness state has its own leaf mutex.
type debtHarness9642 struct {
	m           *Manager
	statusCtrl  *fakeCtrlMap
	failCtrl    *fakeCtrlMap
	disableCtrl *fakeCtrlMap
	mu          sync.Mutex
	syncedTo    []*ConfigSnapshot
	sentSnaps   []ConfigSnapshot
	sentTypes   []string
	applyErr    error
	applyErrs   []error // scripted sequence; applyErr is the fallback
	statusGen   uint64
}

func (h *debtHarness9642) hook(req ControlRequest, status *ProcessStatus) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sentTypes = append(h.sentTypes, req.Type)
	if req.Type == "apply_snapshot" {
		if req.Snapshot != nil {
			h.sentSnaps = append(h.sentSnaps, *req.Snapshot)
		}
		err := h.applyErr
		if len(h.applyErrs) > 0 {
			err = h.applyErrs[0]
			h.applyErrs = h.applyErrs[1:]
		}
		if err == nil && status != nil {
			*status = h.reportStatusLocked()
		}
		return err
	}
	if status != nil {
		*status = h.reportStatusLocked()
	}
	return nil
}

// reportStatusLocked fills a helper status that satisfies every arming gate
// (cf. readyHelperStatus) while reporting the harness generation as applied.
// Caller holds h.mu.
func (h *debtHarness9642) reportStatusLocked() ProcessStatus {
	st := *readyHelperStatus()
	st.LastSnapshotGeneration = h.statusGen
	return st
}

func (h *debtHarness9642) syncCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.syncedTo)
}

func (h *debtHarness9642) applyCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, t := range h.sentTypes {
		if t == "apply_snapshot" {
			n++
		}
	}
	return n
}

// setScript publishes hook inputs under the harness mutex: a reconcile worker
// may already tick while the cell drives the next step, so bare writes race.
func (h *debtHarness9642) setScript(applyErr error, seq []error, gen uint64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.applyErr = applyErr
	h.applyErrs = seq
	h.statusGen = gen
}
func newDebtHarness9642(t *testing.T) *debtHarness9642 {
	t.Helper()
	h := &debtHarness9642{statusGen: 8}
	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	h.statusCtrl = &fakeCtrlMap{}
	h.failCtrl = &fakeCtrlMap{
		stored:     userspaceCtrlValue{Enabled: 1, MetadataVersion: userspaceMetadataVersion, Workers: 4, QueueCount: 4},
		haveStored: true,
	}
	h.disableCtrl = &fakeCtrlMap{
		stored:     userspaceCtrlValue{Enabled: 1, MetadataVersion: userspaceMetadataVersion, Workers: 4, QueueCount: 4},
		haveStored: true,
	}
	m.helperStatusCtrlMapHook = h.statusCtrl
	m.helperStatusBindingsMapHook = &fakeBindingsMap{}
	m.failClosedCtrlMapHook = h.failCtrl
	m.disableCtrlMapHook = h.disableCtrl
	m.syncClassifierMapsHook = func(s *ConfigSnapshot) error {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.syncedTo = append(h.syncedTo, s)
		return nil
	}
	m.controlRequestHook = h.hook
	m.xskLivenessProven = true
	m.lastStatus = ProcessStatus{
		ConfigSnapshotProtocolVersion: ProtocolVersion,
		LastSnapshotGeneration:        8,
	}
	m.helperStatusObserved = true
	h.m = m
	return h
}

// stopLoop9642 steals and cancels the reconcile worker a publish failure may
// have started, then genuinely joins it: the worker closes syncDone on exit,
// so waiting on that channel (without holding m.mu, which the exiting tick
// body needs) acknowledges a true worker exit rather than inferring one from
// a canceled context. A 5s ceiling turns a wedged worker into a loud failure
// instead of a silent leak. Idempotent; call after every loop-starting action
// so no background tick can consume scripted hook replies or race assertions.
func (h *debtHarness9642) stopLoop(t *testing.T) {
	t.Helper()
	h.m.mu.Lock()
	cancel, done := h.m.syncCancel, h.m.syncDone
	h.m.syncCancel, h.m.syncDone = nil, nil
	h.m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("status-loop worker did not exit after cancel; scripted hook state is unsafe")
		}
	}
}

func (h *debtHarness9642) loopRunning() bool {
	h.m.mu.Lock()
	defer h.m.mu.Unlock()
	return h.m.syncCancel != nil
}

// buildDebtPair9642 returns a retained Gen-8 snapshot and an attempted Gen-9
// snapshot. changedPlan selects the binding plan (Workers 1 vs 2 feed
// snapshotBindingPlanKey); same-plan pairs share it.
func buildDebtPair9642(t *testing.T, changedPlan bool) (retained, attempted *ConfigSnapshot) {
	t.Helper()
	var err error
	retained, err = buildSnapshot(&config.Config{}, config.UserspaceConfig{Workers: 1}, 8, 0)
	if err != nil {
		t.Fatalf("buildSnapshot retained: %v", err)
	}
	workers := 1
	if changedPlan {
		workers = 2
	}
	attempted, err = buildSnapshot(&config.Config{}, config.UserspaceConfig{Workers: workers}, 9, 0)
	if err != nil {
		t.Fatalf("buildSnapshot attempted: %v", err)
	}
	if got := snapshotBindingPlanKey(attempted) == snapshotBindingPlanKey(retained); got == changedPlan {
		t.Fatalf("plan-key premise broken: changedPlan=%v but keys equal=%v", changedPlan, got)
	}
	return retained, attempted
}

// seedPublished9642 installs the retained snapshot as the settled authority.
func (h *debtHarness9642) seedPublished(t *testing.T, retained *ConfigSnapshot) {
	t.Helper()
	h.m.mu.Lock()
	defer h.m.mu.Unlock()
	h.m.lastSnapshot = retained
	h.m.publishedSnapshot = retained.Generation
	h.m.publishedPlanKey = snapshotBindingPlanKey(retained)
	if hash, ok := snapshotContentHash(retained); ok {
		h.m.lastSnapshotHash = hash
	}
	h.m.generation = retained.Generation
}

// TestRetryDebtPlanChangingTransportFailureAdoptsDebt9642 is the lead cell: a
// plan-changing (bootstrap-arm) publish fails with a deadline. The attempted
// snapshot must become the retained authority with publication held back and
// the unknown-outcome mark set; the bootstrap arm performs no ctrl write
// itself (ctrl is already 0 from the fresh program), so the fail-closed map
// must be untouched by this call.
//
// RED-on-revert: delete the adopt arm and m.lastSnapshot stays at Gen 8 with
// published == last.Gen — the tick gate never opens and the latch never holds.
func TestRetryDebtPlanChangingTransportFailureAdoptsDebt9642(t *testing.T) {
	t.Parallel()
	h := newDebtHarness9642(t)
	defer h.stopLoop(t)
	retained, attempted := buildDebtPair9642(t, true /* changedPlan */)
	h.seedPublished(t, retained)
	h.mu.Lock()
	h.applyErr = transportTimeout9642()
	h.mu.Unlock()

	h.m.mu.Lock()
	var status ProcessStatus
	err := h.m.publishSnapshotFailClosedLocked(attempted, &status, false /*mapsMutatedInPlace*/)
	loopAlive := h.m.syncCancel != nil
	h.m.mu.Unlock()

	if err == nil {
		t.Fatal("publishSnapshotFailClosedLocked returned nil on a transport failure")
	}
	// The loop-ensure must have run even though this return never reaches the
	// normal apply path (#5873 shape): the debt's only consumer is the tick.
	if !loopAlive {
		t.Fatal("status loop not ensured on the failing first publish; the debt would be orphaned")
	}
	h.m.mu.Lock()
	defer h.m.mu.Unlock()
	if !h.m.applySnapshotOutcomeUnknown {
		t.Fatal("unknown-outcome mark not set on a deadline failure")
	}
	if h.m.lastSnapshot == nil || h.m.lastSnapshot.Generation != 9 {
		t.Fatalf("lastSnapshot.Generation = %v, want 9 (the attempted snapshot adopted as debt)",
			func() uint64 {
				if h.m.lastSnapshot == nil {
					return 0
				}
				return h.m.lastSnapshot.Generation
			}())
	}
	if !h.m.pendingHAStateClear {
		t.Fatal("standalone adopt must record the HA-clear obligation; the Compile-tail clear never ran")
	}
	if h.m.publishedSnapshot != 8 {
		t.Fatalf("publishedSnapshot = %d, want 8 (held back so the tick gate republishes)", h.m.publishedSnapshot)
	}
	if !h.m.snapshotRetryDebtLocked() {
		t.Fatal("snapshotRetryDebtLocked false in exactly the debt state")
	}
	if !reflect.DeepEqual(h.m.cfg, attempted.Userspace) {
		t.Fatalf("m.cfg = %+v, want the attempted process identity %+v (restart respawn feeds on it)",
			h.m.cfg, attempted.Userspace)
	}
	if h.failCtrl.haveStored && h.failCtrl.stored.Enabled != 1 {
		t.Fatalf("bootstrap arm wrote ctrl.Enabled=%d; the error returns unchanged on this arm (fail-closed was already programmed)",
			h.failCtrl.stored.Enabled)
	}
}

// TestRetryDebtSamePlanContentIdentity9642: a same-plan refresh fails with a
// deadline. Same binding plan, but the attempted snapshot carries different
// classifier content (an extra publishable neighbor). Adoption must carry the
// CONTENT, not just the generation — the retry must republish what the helper
// may hold, and the tick must not silently keep the old bytes.
//
// RED-on-revert: adoption that records only the generation (or none) leaves
// the retried bytes equal to the retained plan while the helper enforces new.
func TestRetryDebtSamePlanContentIdentity9642(t *testing.T) {
	t.Parallel()
	h := newDebtHarness9642(t)
	defer h.stopLoop(t)
	retained, attempted := buildDebtPair9642(t, false /* same plan */)
	extra := NeighborSnapshot{Ifindex: 5, IP: "10.0.0.99", MAC: "aa:bb:cc:dd:ee:99", State: "reachable"}
	if !neighborSnapshotPublishable(extra) {
		t.Fatal("fixture invalid: the extra neighbor must be publishable")
	}
	attempted.Neighbors = append(append([]NeighborSnapshot(nil), attempted.Neighbors...), extra)
	h.seedPublished(t, retained)
	h.mu.Lock()
	h.applyErr = transportTimeout9642()
	h.mu.Unlock()

	h.m.mu.Lock()
	var status ProcessStatus
	err := h.m.publishSnapshotFailClosedLocked(attempted, &status, true /*mapsMutatedInPlace*/)
	h.m.mu.Unlock()

	if err == nil {
		t.Fatal("publishSnapshotFailClosedLocked returned nil on a transport failure")
	}
	h.m.mu.Lock()
	defer h.m.mu.Unlock()
	if h.m.lastSnapshot == nil || h.m.lastSnapshot.Generation != 9 {
		t.Fatal("attempted snapshot not adopted on the same-plan arm")
	}
	found := false
	for _, n := range h.m.lastSnapshot.Neighbors {
		if n.IP == "10.0.0.99" {
			found = true
		}
	}
	if !found {
		t.Fatal("adopted debt lost the attempted classifier content (extra neighbor missing)")
	}
	if h.failCtrl.haveStored && h.failCtrl.stored.Enabled != 0 {
		t.Fatalf("same-plan transport failure left ctrl.Enabled=%d, want 0 (fail-closed)",
			h.failCtrl.stored.Enabled)
	}
}

// TestRetryDebtRefusalAdoptsNothing9642: an in-band refusal keeps today's #7468
// atomic retain byte-for-byte — authority pointer, generations, and mark all
// unchanged — with and without pre-existing debt.
//
// RED-on-revert: key adoption on error class (v1) and the refusal adopts.
func TestRetryDebtRefusalAdoptsNothing9642(t *testing.T) {
	t.Parallel()
	t.Run("no_prior_debt", func(t *testing.T) {
		t.Parallel()
		h := newDebtHarness9642(t)
		defer h.stopLoop(t)
		retained, attempted := buildDebtPair9642(t, false)
		h.seedPublished(t, retained)
		h.mu.Lock()
		h.applyErr = newHelperRejection("integrity preflight rejected")
		h.mu.Unlock()

		h.m.mu.Lock()
		var status ProcessStatus
		err := h.m.publishSnapshotFailClosedLocked(attempted, &status, true)
		h.m.mu.Unlock()

		if err == nil {
			t.Fatal("publishSnapshotFailClosedLocked returned nil on a refusal")
		}
		if !errors.Is(err, errHelperRejected) {
			t.Fatalf("refusal error lost its class: %v", err)
		}
		h.m.mu.Lock()
		defer h.m.mu.Unlock()
		if h.m.lastSnapshot != retained {
			t.Fatal("in-band refusal moved the retained authority; #7468 owns this path, not debt")
		}
		if h.m.applySnapshotOutcomeUnknown {
			t.Fatal("refusal set the unknown-outcome mark")
		}
		if h.m.snapshotRetryDebtLocked() {
			t.Fatal("refusal opened retry debt")
		}
	})
	t.Run("over_prior_debt", func(t *testing.T) {
		t.Parallel()
		h := newDebtHarness9642(t)
		defer h.stopLoop(t)
		retained, attempted := buildDebtPair9642(t, false)
		h.seedPublished(t, retained)
		// Establish real debt first, then refuse a follow-up publish.
		h.mu.Lock()
		h.applyErr = transportTimeout9642()
		h.mu.Unlock()
		h.m.mu.Lock()
		var status ProcessStatus
		if err := h.m.publishSnapshotFailClosedLocked(attempted, &status, true); err == nil {
			h.m.mu.Unlock()
			t.Fatal("premise: transport failure must fail the publish")
		}
		debt := h.m.lastSnapshot
		h.m.mu.Unlock()

		h.mu.Lock()
		h.applyErr = newHelperRejection("integrity preflight rejected")
		h.mu.Unlock()
		h.m.mu.Lock()
		if err := h.m.publishSnapshotFailClosedLocked(attempted, &status, true); err == nil {
			h.m.mu.Unlock()
			t.Fatal("refusal must fail the publish")
		}
		defer h.m.mu.Unlock()
		if h.m.lastSnapshot != debt {
			t.Fatal("refusal over prior debt replaced the debt authority with refused content")
		}
	})
}

// TestRetryDebtTickHoldsCtrlAndSkipsResync9642: with debt outstanding and the
// helper reporting the attempted generation as applied (the landed-but-lost
// case), the tick must neither arm ctrl nor touch the classifier maps.
//
// RED-on-revert: drop the latch disjunct and ctrl arms; drop the skip and the
// recorder sees a re-sync to the retained plan.
func TestRetryDebtTickHoldsCtrlAndSkipsResync9642(t *testing.T) {
	t.Parallel()
	h := newDebtHarness9642(t)
	defer h.stopLoop(t)
	retained, attempted := buildDebtPair9642(t, true)
	h.seedPublished(t, retained)
	h.mu.Lock()
	h.applyErr = transportTimeout9642()
	h.mu.Unlock()
	h.m.mu.Lock()
	var status ProcessStatus
	if err := h.m.publishSnapshotFailClosedLocked(attempted, &status, false); err == nil {
		h.m.mu.Unlock()
		t.Fatal("premise: transport failure must fail the publish")
	}
	h.mu.Lock()
	h.statusGen = 9
	h.mu.Unlock()
	st := h.reportStatusLocked()
	if err := h.m.applyHelperStatusLocked(&st); err != nil {
		h.m.mu.Unlock()
		t.Fatalf("applyHelperStatusLocked: %v", err)
	}
	h.m.mu.Unlock()

	if !h.statusCtrl.haveStored {
		t.Fatal("applyHelperStatusLocked wrote nothing to the ctrl map; the hold is unobservable")
	}
	if h.statusCtrl.stored.Enabled != 0 {
		t.Fatalf("ctrl.Enabled = %d with retry debt outstanding and an enabled-reporting helper, want 0",
			h.statusCtrl.stored.Enabled)
	}
	if n := h.syncCount(); n != 0 {
		t.Fatalf("classifier maps re-synced %d time(s) while indebted; the maps are already at the attempted plan", n)
	}
}

// TestRetryDebtFreeMarkKeepsTodayBehavior9642 discriminates the conjunction
// latch from a bare-mark latch: mark set with generations equal (exactly what
// an overlay/scheduler/worker-arm transport failure leaves) must re-enable
// ctrl and re-sync exactly as today.
//
// RED-on-revert: widen the latch to the bare mark and this cell reds.
func TestRetryDebtFreeMarkKeepsTodayBehavior9642(t *testing.T) {
	t.Parallel()
	h := newDebtHarness9642(t)
	defer h.stopLoop(t)
	retained, _ := buildDebtPair9642(t, false)
	h.seedPublished(t, retained)
	h.m.mu.Lock()
	h.m.applySnapshotOutcomeUnknown = true
	h.mu.Lock()
	h.statusGen = 8
	h.mu.Unlock()
	st := h.reportStatusLocked()
	if err := h.m.applyHelperStatusLocked(&st); err != nil {
		h.m.mu.Unlock()
		t.Fatalf("applyHelperStatusLocked: %v", err)
	}
	h.m.mu.Unlock()

	if !h.statusCtrl.haveStored || h.statusCtrl.stored.Enabled != 1 {
		t.Fatal("mark-without-generation-debt must arm ctrl exactly as today (conjunction latch, not bare mark)")
	}
	if n := h.syncCount(); n != 1 {
		t.Fatalf("classifier re-sync ran %d time(s), want exactly 1 (today's per-tick reconcile)", n)
	}
}

// TestRetryDebtRetryConvergesAndSteadies9642: the debt republishes on the next
// tick, lands, re-enables ctrl against the new plan in the same tick, clears
// the mark — and a follow-up steady-state tick reconciles normally (eventual
// readiness, not one publish).
//
// RED-on-revert: remove adoption and the gate stays closed (published == last
// generation), so syncSnapshotLocked sends nothing.
func TestRetryDebtRetryConvergesAndSteadies9642(t *testing.T) {
	t.Parallel()
	h := newDebtHarness9642(t)
	defer h.stopLoop(t)
	retained, attempted := buildDebtPair9642(t, false /* same plan: no restart branch on retry */)
	h.seedPublished(t, retained)
	h.mu.Lock()
	h.applyErr = transportTimeout9642()
	h.mu.Unlock()
	h.m.mu.Lock()
	var status ProcessStatus
	if err := h.m.publishSnapshotFailClosedLocked(attempted, &status, true /*mapsMutatedInPlace*/); err == nil {
		h.m.mu.Unlock()
		t.Fatal("premise: transport failure must fail the publish")
	}
	h.m.mu.Unlock()
	h.stopLoop(t)

	h.mu.Lock()
	h.applyErr = nil
	h.mu.Unlock()
	h.mu.Lock()
	h.statusGen = 9
	h.mu.Unlock()
	h.m.mu.Lock()
	if err := h.m.syncSnapshotLocked(); err != nil {
		h.m.mu.Unlock()
		t.Fatalf("syncSnapshotLocked retry: %v", err)
	}
	h.m.mu.Unlock()

	if n := h.applyCount(); n != 2 {
		t.Fatalf("apply_snapshot sent %d time(s), want 2 (failed attempt + converging retry)", n)
	}
	h.mu.Lock()
	retryBody := h.sentSnaps[len(h.sentSnaps)-1]
	h.mu.Unlock()
	if retryBody.Generation != 9 {
		t.Fatalf("retry published generation %d, want 9 (the debt, not a fresh build)", retryBody.Generation)
	}
	wantHash, ok1 := snapshotContentHash(attempted)
	gotHash, ok2 := snapshotContentHash(&retryBody)
	if !ok1 || !ok2 || wantHash != gotHash {
		t.Fatal("retry published different content than the attempted snapshot")
	}
	h.m.mu.Lock()
	defer h.m.mu.Unlock()
	if h.m.publishedSnapshot != 9 {
		t.Fatalf("publishedSnapshot = %d, want 9", h.m.publishedSnapshot)
	}
	if h.m.applySnapshotOutcomeUnknown {
		t.Fatal("unknown-outcome mark not cleared by the successful retry")
	}
	if h.m.snapshotRetryDebtLocked() {
		t.Fatal("debt predicate still true after a full apply succeeded")
	}
	if !h.statusCtrl.haveStored || h.statusCtrl.stored.Enabled != 1 {
		t.Fatal("ctrl not re-enabled by the retry's tail status apply")
	}
	// Eventual readiness: the next tick reconciles normally again.
	st := *readyHelperStatus()
	st.LastSnapshotGeneration = 9
	syncsBefore := h.syncCount()
	if err := h.m.applyHelperStatusLocked(&st); err != nil {
		t.Fatalf("steady-state applyHelperStatusLocked: %v", err)
	}
	if h.statusCtrl.stored.Enabled != 1 {
		t.Fatal("steady-state tick did not keep ctrl enabled")
	}
	if h.syncCount() != syncsBefore+1 {
		t.Fatal("steady-state tick did not resume the per-tick classifier reconcile")
	}
}

// TestRetryDebtRefusalAfterDebtFailsClosed9642: the retry itself is refused
// in-band. published != retained.Gen defeats the retain, so there is no
// rollback to the refused plan — ctrl stays disabled and the maps are
// untouched (#9337 preserved under debt).
func TestRetryDebtRefusalAfterDebtFailsClosed9642(t *testing.T) {
	t.Parallel()
	h := newDebtHarness9642(t)
	defer h.stopLoop(t)
	retained, attempted := buildDebtPair9642(t, false /* same plan: retry publishes without restart */)
	h.seedPublished(t, retained)
	h.mu.Lock()
	h.applyErr = transportTimeout9642()
	h.mu.Unlock()
	h.m.mu.Lock()
	var status ProcessStatus
	if err := h.m.publishSnapshotFailClosedLocked(attempted, &status, true); err == nil {
		h.m.mu.Unlock()
		t.Fatal("premise: transport failure must fail the publish")
	}
	h.m.mu.Unlock()
	h.stopLoop(t)

	h.mu.Lock()
	h.applyErr = newHelperRejection("snapshot integrity preflight rejected")
	h.mu.Unlock()
	h.m.mu.Lock()
	if err := h.m.syncSnapshotLocked(); err == nil {
		h.m.mu.Unlock()
		t.Fatal("refused retry must fail the deferred sync")
	}
	h.m.mu.Unlock()

	if h.failCtrl.haveStored && h.failCtrl.stored.Enabled != 0 {
		t.Fatalf("refused retry left ctrl.Enabled=%d, want 0", h.failCtrl.stored.Enabled)
	}
	if n := h.syncCount(); n != 0 {
		t.Fatalf("refused retry re-synced the classifier maps %d time(s); nothing may roll back to a refused plan", n)
	}
	h.m.mu.Lock()
	defer h.m.mu.Unlock()
	if h.m.publishedSnapshot != 8 {
		t.Fatalf("publishedSnapshot moved to %d on a refused retry", h.m.publishedSnapshot)
	}
	if !h.m.applySnapshotOutcomeUnknown {
		t.Fatal("refusal cleared pre-existing unknown-outcome state")
	}
}

// TestRetryDebtPartialUpdateHoldsPublication9642: a partial writeback while
// indebted bumps the generation (so the next debt publish carries the partial
// sections) but must not advance publishedSnapshot/hash — that would mark
// unknown content settled and close the gate.
func TestRetryDebtPartialUpdateHoldsPublication9642(t *testing.T) {
	t.Parallel()
	h := newDebtHarness9642(t)
	defer h.stopLoop(t)
	retained, attempted := buildDebtPair9642(t, false)
	h.seedPublished(t, retained)
	h.mu.Lock()
	h.applyErr = transportTimeout9642()
	h.mu.Unlock()
	h.m.mu.Lock()
	var status ProcessStatus
	if err := h.m.publishSnapshotFailClosedLocked(attempted, &status, true); err == nil {
		h.m.mu.Unlock()
		t.Fatal("premise: transport failure must fail the publish")
	}
	hashBefore := h.m.lastSnapshotHash
	h.m.advanceGenerationAfterPartialUpdateLocked()
	published, gen := h.m.publishedSnapshot, h.m.lastSnapshot.Generation
	hashAfter := h.m.lastSnapshotHash
	stillDebt := h.m.snapshotRetryDebtLocked()
	h.m.mu.Unlock()

	if published != 8 {
		t.Fatalf("publishedSnapshot = %d after a partial writeback while indebted, want 8 held", published)
	}
	if gen != 10 {
		t.Fatalf("lastSnapshot.Generation = %d, want 10 (bumped so the retry carries the partial)", gen)
	}
	if hashAfter != hashBefore {
		t.Fatal("lastSnapshotHash advanced while the outcome was unknown")
	}
	if !stillDebt {
		t.Fatal("debt predicate lost after a partial writeback; the gate would close")
	}
}

// TestRetryDebtWorkerArmInferenceRequiresPublication9642: an adopted-but-
// unlanded DeferWorkers=false snapshot must not drop a live worker-arm debt.
// Without the publication qualifier the flag check alone settles the debt
// before anything armed the workers.
//
// RED-on-revert: drop the publishedSnapshot conjunct and the first call
// returns nil with the debt silently dropped.
func TestRetryDebtWorkerArmInferenceRequiresPublication9642(t *testing.T) {
	t.Parallel()
	h := newDebtHarness9642(t)
	defer h.stopLoop(t)
	retained, attempted := buildDebtPair9642(t, false)
	h.seedPublished(t, retained)
	h.mu.Lock()
	h.applyErr = transportTimeout9642()
	h.mu.Unlock()
	h.m.mu.Lock()
	var status ProcessStatus
	if err := h.m.publishSnapshotFailClosedLocked(attempted, &status, true); err == nil {
		h.m.mu.Unlock()
		t.Fatal("premise: transport failure must fail the publish")
	}
	// The adopted debt carries DeferWorkers=false without ever landing; the
	// arm debt is live on top of it.
	h.m.lastSnapshot.DeferWorkers = false
	h.m.pendingWorkerArm = true
	h.m.mu.Unlock()
	h.mu.Lock()
	h.applyErr = transportTimeout9642()
	h.mu.Unlock()
	h.m.mu.Lock()
	err := h.m.retryDeferredWorkerArmLocked()
	pending := h.m.pendingWorkerArm
	h.m.mu.Unlock()
	if err == nil {
		t.Fatal("arm retry must fail on a transport error")
	}
	if !pending {
		t.Fatal("worker-arm debt dropped although the DeferWorkers=false snapshot was never published")
	}

	h.mu.Lock()
	h.applyErr = nil
	h.mu.Unlock()
	h.mu.Lock()
	h.statusGen = 10
	h.mu.Unlock()
	h.m.mu.Lock()
	if err := h.m.retryDeferredWorkerArmLocked(); err != nil {
		h.m.mu.Unlock()
		t.Fatalf("arm retry: %v", err)
	}
	pending = h.m.pendingWorkerArm
	published := h.m.publishedSnapshot
	h.m.mu.Unlock()
	if pending {
		t.Fatal("worker-arm debt not settled by the successful arm publish")
	}
	if published != 10 {
		t.Fatalf("publishedSnapshot = %d, want 10 (the arm publish generation)", published)
	}
}

// TestRetryDebtChangedPlanRestartKeepsConsumer9642 drives the real
// syncSnapshotLocked restart branch with a disposable helper process: teardown
// (stopLocked on a live sleep child — never the test runner), reset, the new
// loop ensure, and the republish, with only the spawn itself substituted.
//
// Case A (republish succeeds): debt settles and subsequent real status ticks
// run and re-enable ctrl. Deleting the restart-branch ensure leaves syncCancel
// nil and no tick ever runs — the assertion fails.
// Case B (republish fails, then succeeds): debt persists across the respawn
// with the consumer alive, then converges.
func TestRetryDebtChangedPlanRestartKeepsConsumer9642(t *testing.T) {
	// NOT parallel: this cell mutates the process-global statusLoopInterval.
	// Its subtests may run parallel with each other (same value), but the
	// global must not be touched while any other test runs.
	oldInterval := statusLoopInterval
	statusLoopInterval = 10 * time.Millisecond
	t.Cleanup(func() { statusLoopInterval = oldInterval })

	startSleep := func(t *testing.T) *exec.Cmd {
		t.Helper()
		cmd := exec.Command("sleep", "300")
		if err := cmd.Start(); err != nil {
			t.Fatalf("start sleep: %v", err)
		}
		t.Cleanup(func() {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		})
		return cmd
	}

	setup := func(t *testing.T, script []error) (*debtHarness9642, *exec.Cmd) {
		t.Helper()
		h := newDebtHarness9642(t)
		retained, attempted := buildDebtPair9642(t, true)
		h.seedPublished(t, retained)
		sleep1 := startSleep(t)
		h.m.mu.Lock()
		h.m.proc = sleep1
		h.m.mu.Unlock()
		h.mu.Lock()
		h.applyErr = transportTimeout9642()
		h.mu.Unlock()
		h.mu.Lock()
		h.statusGen = 9
		h.mu.Unlock()
		sleep2 := startSleep(t)
		h.m.restartBringupHook = func(config.UserspaceConfig) error {
			h.m.proc = sleep2
			return nil
		}
		h.m.mu.Lock()
		var status ProcessStatus
		if err := h.m.publishSnapshotFailClosedLocked(attempted, &status, false); err == nil {
			h.m.mu.Unlock()
			t.Fatal("premise: transport failure must fail the publish")
		}
		h.m.mu.Unlock()
		// Join the premise-started worker BEFORE scripting: with the 10ms
		// test tick a background pass would otherwise consume the scripted
		// replies and tear the fixture down ahead of runSync. runSync's own
		// restart-ensure starts a fresh worker deterministically.
		h.stopLoop(t)
		// Premise consumed the failure; subsequent sends follow the script
		// (case A: success; case B: one more deadline, then success).
		h.mu.Lock()
		h.applyErr = nil
		h.applyErrs = script
		h.mu.Unlock()
		return h, sleep1
	}
	runSync := func(t *testing.T, h *debtHarness9642) error {
		t.Helper()
		h.m.mu.Lock()
		defer h.m.mu.Unlock()
		return h.m.syncSnapshotLocked()
	}
	pollCount := func(h *debtHarness9642) int {
		h.mu.Lock()
		defer h.mu.Unlock()
		n := 0
		for _, typ := range h.sentTypes {
			if typ == "status" {
				n++
			}
		}
		return n
	}
	waitFor := func(t *testing.T, h *debtHarness9642, cond func() bool, what string) {
		t.Helper()
		// 15s, not 5s: the 10ms ticks this waits on starve under CI CPU
		// contention (one observed timeout in ~10 runs under lane-parallel
		// load, unreproduced in isolation). The ceiling only delays genuine
		// failures; the pass path returns on the first satisfied poll.
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			h.m.mu.Lock()
			ok := cond()
			h.m.mu.Unlock()
			if ok {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("timed out waiting for %s", what)
	}

	t.Run("republish_succeeds_ticks_continue", func(t *testing.T) {
		t.Parallel()
		h, _ := setup(t, nil)
		defer h.stopLoop(t)
		if err := runSync(t, h); err != nil {
			t.Fatalf("syncSnapshotLocked through the restart branch: %v", err)
		}
		h.m.mu.Lock()
		published, mark := h.m.publishedSnapshot, h.m.applySnapshotOutcomeUnknown
		h.m.mu.Unlock()
		if published != 9 || mark {
			t.Fatalf("debt not settled by the post-restart republish (published=%d mark=%v)", published, mark)
		}
		if !h.loopRunning() {
			t.Fatal("status loop dead after a successful respawn; liveness can never re-prove")
		}
		h.m.mu.Lock()
		h.m.ensureStatusLoopLocked()
		h.m.mu.Unlock()
		waitFor(t, h, func() bool { return pollCount(h) >= 3 }, "subsequent status ticks")
		waitFor(t, h, func() bool {
			return h.statusCtrl.haveStored && h.statusCtrl.stored.Enabled == 1
		}, "ctrl re-enable on ticks after the restart")
	})

	t.Run("republish_fails_then_recovers", func(t *testing.T) {
		t.Parallel()
		h, _ := setup(t, []error{transportTimeout9642()})
		defer h.stopLoop(t)
		if err := runSync(t, h); err == nil {
			t.Fatal("first post-restart republish must fail on the scripted deadline")
		}
		h.m.mu.Lock()
		published, mark, lastGen := h.m.publishedSnapshot, h.m.applySnapshotOutcomeUnknown, h.m.lastSnapshot.Generation
		h.m.mu.Unlock()
		if mark != true || published >= lastGen {
			t.Fatalf("debt lost across the failed post-restart republish (published=%d last=%d mark=%v)",
				published, lastGen, mark)
		}
		if !h.loopRunning() {
			t.Fatal("status loop dead after a failed post-restart republish; recovery can never arrive")
		}
		if err := runSync(t, h); err != nil {
			t.Fatalf("recovery republish: %v", err)
		}
		h.m.mu.Lock()
		published, mark = h.m.publishedSnapshot, h.m.applySnapshotOutcomeUnknown
		h.m.mu.Unlock()
		if published != 9 || mark {
			t.Fatalf("debt not settled by the recovery republish (published=%d mark=%v)", published, mark)
		}
	})
}

// TestRetryDebtFirstApplyRecovers9642: no retained authority at all. A
// first-apply transport failure must still adopt (otherwise the gate can never
// open and the new latch pins ctrl-0 forever), hold the tick, and converge.
func TestRetryDebtFirstApplyRecovers9642(t *testing.T) {
	t.Parallel()
	h := newDebtHarness9642(t)
	defer h.stopLoop(t)
	_, attempted := buildDebtPair9642(t, true)
	attempted.Generation = 1
	h.mu.Lock()
	h.applyErr = transportTimeout9642()
	h.mu.Unlock()

	h.m.mu.Lock()
	var status ProcessStatus
	if err := h.m.publishSnapshotFailClosedLocked(attempted, &status, false); err == nil {
		h.m.mu.Unlock()
		t.Fatal("first-apply publish must fail on a transport error")
	}
	h.m.mu.Unlock()

	h.m.mu.Lock()
	if h.m.lastSnapshot == nil || h.m.lastSnapshot.Generation != 1 {
		h.m.mu.Unlock()
		t.Fatal("first-apply failure did not adopt the attempted snapshot; nothing can ever republish it")
	}
	if h.m.publishedSnapshot != 0 {
		h.m.mu.Unlock()
		t.Fatalf("publishedSnapshot = %d on a first apply, want 0", h.m.publishedSnapshot)
	}
	if !h.m.snapshotRetryDebtLocked() {
		h.m.mu.Unlock()
		t.Fatal("debt predicate false on first-apply debt")
	}
	st := *readyHelperStatus()
	st.LastSnapshotGeneration = 1
	if err := h.m.applyHelperStatusLocked(&st); err != nil {
		h.m.mu.Unlock()
		t.Fatalf("applyHelperStatusLocked: %v", err)
	}
	h.m.mu.Unlock()
	if h.statusCtrl.haveStored && h.statusCtrl.stored.Enabled != 0 {
		t.Fatal("first-apply debt did not hold ctrl at 0 against an enabled-reporting helper")
	}
	if n := h.syncCount(); n != 0 {
		t.Fatalf("first-apply debt re-synced %d time(s); the nil-authority question is moot by the skip", n)
	}

	h.mu.Lock()
	h.applyErr = nil
	h.mu.Unlock()
	h.mu.Lock()
	h.statusGen = 1
	h.mu.Unlock()
	h.m.mu.Lock()
	if err := h.m.syncSnapshotLocked(); err != nil {
		h.m.mu.Unlock()
		t.Fatalf("first-apply retry: %v", err)
	}
	published, mark := h.m.publishedSnapshot, h.m.applySnapshotOutcomeUnknown
	enabled := h.statusCtrl.haveStored && h.statusCtrl.stored.Enabled == 1
	h.m.mu.Unlock()
	if published != 1 || mark || !enabled {
		t.Fatalf("first-apply debt did not converge (published=%d mark=%v ctrl-enabled=%v)",
			published, mark, enabled)
	}
}

// TestRetryDebtRestartBranchShape9642 binds both insertions the behavioral cell
// executes: the debt exemption conjunct on the startup gate and the loop ensure
// in the restart branch. Deleting either fails here; behavior is proven in
// TestRetryDebtChangedPlanRestartKeepsConsumer9642.
func TestRetryDebtRestartBranchShape9642(t *testing.T) {
	t.Parallel()
	src := goFunctionSource(t, "process_status.go", "syncSnapshotLocked")
	if !strings.Contains(src, "!m.snapshotRetryDebtLocked()") {
		t.Fatal("syncSnapshotLocked lost the debt exemption on the startup deferral gate")
	}
	if !strings.Contains(src, "m.ensureStatusLoopLocked()") {
		t.Fatal("syncSnapshotLocked lost the loop ensure in the restart branch")
	}
}

// TestRetryDebtOvertakenGenerationAdoptsAhead9642: partial writebacks commit
// under m.mu between Compile's pre-mu generation reservation and its publish.
// If they advance publishedSnapshot past the reserved generation, a transport
// failure must re-stamp the adopted debt ahead — otherwise published >= last
// generation closes both the gate and the latch on live debt.
//
// RED-on-revert: delete the re-stamp and the adopted Gen-9 sits at/below
// published 12 with the mark set but nothing holding or retrying.
func TestRetryDebtOvertakenGenerationAdoptsAhead9642(t *testing.T) {
	t.Parallel()
	h := newDebtHarness9642(t)
	defer h.stopLoop(t)
	retained, attempted := buildDebtPair9642(t, false)
	h.seedPublished(t, retained)
	h.m.mu.Lock()
	for range 4 {
		h.m.advanceGenerationAfterPartialUpdateLocked()
	}
	overtaken := h.m.publishedSnapshot
	h.m.mu.Unlock()
	if overtaken != 12 {
		t.Fatalf("premise broken: publishedSnapshot = %d, want 12 after four partial writebacks", overtaken)
	}
	h.mu.Lock()
	h.applyErr = transportTimeout9642()
	h.mu.Unlock()
	h.m.mu.Lock()
	var status ProcessStatus
	if err := h.m.publishSnapshotFailClosedLocked(attempted, &status, true); err == nil {
		h.m.mu.Unlock()
		t.Fatal("publish must fail on a transport error")
	}
	lastGen, published := h.m.lastSnapshot.Generation, h.m.publishedSnapshot
	debt := h.m.snapshotRetryDebtLocked()
	gen := h.m.generation
	h.m.mu.Unlock()

	if lastGen != 13 || published != 12 {
		t.Fatalf("adopted last=%d published=%d, want last=13 (re-stamped past published 12)", lastGen, published)
	}
	if gen < 13 {
		t.Fatalf("m.generation = %d, want >= 13 (never reuse a generation the helper may hold)", gen)
	}
	if !debt {
		t.Fatal("debt predicate false although the helper may hold the adopted content")
	}
}

// TestRetryDebtKnownUnsentClassification9642 binds the deterministic-local
// exclusion: digest, request-encoding, size, and unconfigured-socket failures
// prove the helper received nothing, so they set no debt even though the
// outcome recorder marks (all but stamp) and none is a refusal.
func TestRetryDebtKnownUnsentClassification9642(t *testing.T) {
	t.Parallel()
	t.Run("predicate_table", func(t *testing.T) {
		t.Parallel()
		if !isKnownUnsentFailure(errSnapshotDigest) {
			t.Fatal("digest failure not classified unsent")
		}
		if !isKnownUnsentFailure(&knownUnsentError{msg: "encode boom", cause: errControlRequestEncode}) {
			t.Fatal("request-encoding failure not classified unsent")
		}
		if !isKnownUnsentFailure(&knownUnsentError{msg: "too big", cause: errControlRequestTooLarge}) {
			t.Fatal("size rejection not classified unsent")
		}
		if !isKnownUnsentFailure(errControlSocketNotConfigured) {
			t.Fatal("unconfigured socket not classified unsent")
		}
		for name, err := range map[string]error{
			"transport deadline": transportTimeout9642(),
			"in-band refusal":    newHelperRejection("nope"),
		} {
			if isKnownUnsentFailure(err) {
				t.Fatalf("%s wrongly classified unsent", name)
			}
		}
		if isKnownUnsentFailure(nil) {
			t.Fatal("nil classified unsent")
		}
	})
	t.Run("size_reject_path_real", func(t *testing.T) {
		t.Parallel()
		m := New()
		m.cfg.ControlSocket = "/tmp/xpf-9642-nonexistent.sock"
		padLen := MaxControlRequestBytes + 1024
		req := ControlRequest{Type: "x" + strings.Repeat("y", padLen)}
		m.mu.Lock()
		_, err := m.requestDetailedLocked(req)
		m.mu.Unlock()
		if err == nil {
			t.Fatal("oversize request must be rejected pre-dial")
		}
		if !strings.Contains(err.Error(), "exceeding the dataplane") {
			t.Fatalf("size diagnostic text changed: %v", err)
		}
		if !isKnownUnsentFailure(err) {
			t.Fatalf("real size rejection not classified unsent: %v", err)
		}
	})
	t.Run("socket_unconfigured_path_real", func(t *testing.T) {
		t.Parallel()
		m := New()
		m.mu.Lock()
		_, err := m.requestDetailedLocked(ControlRequest{Type: "status"})
		m.mu.Unlock()
		if err == nil {
			t.Fatal("unconfigured socket must fail")
		}
		if !strings.Contains(err.Error(), "control socket not configured") {
			t.Fatalf("socket diagnostic text changed: %v", err)
		}
		if !isKnownUnsentFailure(err) {
			t.Fatalf("real unconfigured-socket error not classified unsent: %v", err)
		}
	})
	// Publish-level: an unconfigured socket marks (recorder ran) but must not
	// adopt — authority stays back and the debt predicate stays false — with
	// and without pre-existing debt.
	t.Run("publish_no_adopt_without_debt", func(t *testing.T) {
		t.Parallel()
		h := newDebtHarness9642(t)
		defer h.stopLoop(t)
		retained, attempted := buildDebtPair9642(t, false)
		h.seedPublished(t, retained)
		h.m.mu.Lock()
		h.m.controlRequestHook = nil
		h.m.cfg.ControlSocket = ""
		var status ProcessStatus
		err := h.m.publishSnapshotFailClosedLocked(attempted, &status, true)
		h.m.mu.Unlock()
		if err == nil {
			t.Fatal("unconfigured-socket publish must fail")
		}
		h.m.mu.Lock()
		defer h.m.mu.Unlock()
		if h.m.lastSnapshot != retained {
			t.Fatal("deterministic-local failure adopted debt; revert-to-old is the converging path")
		}
		if h.m.applySnapshotOutcomeUnknown {
			t.Fatal("deterministic-local failure marked unknown outcome; the helper provably received nothing (GPT-2 refinement)")
		}
		if h.m.snapshotRetryDebtLocked() {
			t.Fatal("debt predicate true without an adopted attempt")
		}
	})
	t.Run("publish_no_adopt_over_debt", func(t *testing.T) {
		t.Parallel()
		h := newDebtHarness9642(t)
		defer h.stopLoop(t)
		retained, attempted := buildDebtPair9642(t, false)
		h.seedPublished(t, retained)
		h.mu.Lock()
		h.applyErr = transportTimeout9642()
		h.mu.Unlock()
		h.m.mu.Lock()
		var status ProcessStatus
		if err := h.m.publishSnapshotFailClosedLocked(attempted, &status, true); err == nil {
			h.m.mu.Unlock()
			t.Fatal("premise: transport failure must fail the publish")
		}
		debt := h.m.lastSnapshot
		h.m.controlRequestHook = nil
		h.m.cfg.ControlSocket = ""
		if err := h.m.publishSnapshotFailClosedLocked(attempted, &status, true); err == nil {
			h.m.mu.Unlock()
			t.Fatal("unconfigured-socket publish must fail")
		}
		defer h.m.mu.Unlock()
		if h.m.lastSnapshot != debt {
			t.Fatal("deterministic-local failure replaced recoverable debt with known-unsent content")
		}
	})
}

// TestRetryDebtStartupDeferralExemption9642: the xskStartup new-plan deferral
// must not park an indebted publish (the latch freezes the liveness the wait
// needs), while every non-debt combination keeps today's decision.
func TestRetryDebtStartupDeferralExemption9642(t *testing.T) {
	t.Parallel()
	t.Run("debt_changed_unproven_publishes", func(t *testing.T) {
		t.Parallel()
		h := newDebtHarness9642(t)
		defer h.stopLoop(t)
		retained, attempted := buildDebtPair9642(t, true)
		h.seedPublished(t, retained)
		sleep1 := exec.Command("sleep", "300")
		if err := sleep1.Start(); err != nil {
			t.Fatalf("start sleep: %v", err)
		}
		t.Cleanup(func() {
			_ = sleep1.Process.Kill()
			_, _ = sleep1.Process.Wait()
		})
		sleep2 := exec.Command("sleep", "300")
		if err := sleep2.Start(); err != nil {
			t.Fatalf("start sleep: %v", err)
		}
		t.Cleanup(func() {
			_ = sleep2.Process.Kill()
			_, _ = sleep2.Process.Wait()
		})
		h.m.mu.Lock()
		h.m.proc = sleep1
		h.m.mu.Unlock()
		h.mu.Lock()
		h.applyErr = transportTimeout9642()
		h.mu.Unlock()
		h.m.mu.Lock()
		var status ProcessStatus
		if err := h.m.publishSnapshotFailClosedLocked(attempted, &status, false); err == nil {
			h.m.mu.Unlock()
			t.Fatal("premise: transport failure must fail the publish")
		}
		h.m.mu.Unlock()
		h.stopLoop(t)
		h.mu.Lock()
		h.applyErr = nil
		h.mu.Unlock()
		h.m.restartBringupHook = func(config.UserspaceConfig) error {
			h.m.proc = sleep2
			return nil
		}
		h.m.mu.Lock()
		h.m.xskLivenessProven = false
		h.m.xskLivenessFailed = false
		h.m.mu.Unlock()
		h.mu.Lock()
		h.statusGen = 9
		h.mu.Unlock()
		before := h.applyCount()
		h.m.mu.Lock()
		err := h.m.syncSnapshotLocked()
		h.m.mu.Unlock()
		if err != nil {
			t.Fatalf("indebted changed-plan publish must not defer: %v", err)
		}
		if h.applyCount() == before {
			t.Fatal("no apply_snapshot crossed: the startup deferral parked the debt")
		}
	})
	t.Run("no_debt_changed_unproven_defers", func(t *testing.T) {
		t.Parallel()
		h := newDebtHarness9642(t)
		defer h.stopLoop(t)
		retained, _ := buildDebtPair9642(t, true)
		// Deferred-changed-plan shape without debt: unpublished new plan,
		// unproven liveness, mark clear.
		h.m.mu.Lock()
		h.m.lastSnapshot = retained
		h.m.lastSnapshot.Generation = 9
		h.m.publishedSnapshot = 8
		// Deliberately unlike any real key (which starts workers=1;ring=0;):
		// the published plan must read as changed for the deferral to bite.
		h.m.publishedPlanKey = "workers=7;ring=7;deliberate-mismatch"
		h.m.xskLivenessProven = false
		h.m.xskLivenessFailed = false
		h.m.mu.Unlock()
		before := h.applyCount()
		h.m.mu.Lock()
		err := h.m.syncSnapshotLocked()
		h.m.mu.Unlock()
		if err != nil {
			t.Fatalf("deferral must return nil: %v", err)
		}
		if h.applyCount() != before {
			t.Fatal("non-debt changed-plan publish escaped the startup deferral")
		}
	})
}

// TestRetryDebtStandaloneHAClearDebt9642: adopting while standalone records the
// clear obligation the Compile tail never ran; the tick retries the idempotent
// clear (coalesced, recurring until snapshot settlement); clustered adopts
// record nothing and the retry stays suppressed while clustered.
func TestRetryDebtStandaloneHAClearDebt9642(t *testing.T) {
	t.Parallel()
	h := newDebtHarness9642(t)
	defer h.stopLoop(t)
	retained, attempted := buildDebtPair9642(t, false)
	h.seedPublished(t, retained)
	updateHACount := func() int {
		h.mu.Lock()
		defer h.mu.Unlock()
		n := 0
		for _, typ := range h.sentTypes {
			if typ == "update_ha_state" {
				n++
			}
		}
		return n
	}
	fail := func() {
		t.Helper()
		h.mu.Lock()
		h.applyErr = transportTimeout9642()
		h.mu.Unlock()
		h.m.mu.Lock()
		var status ProcessStatus
		if err := h.m.publishSnapshotFailClosedLocked(attempted, &status, true); err == nil {
			h.m.mu.Unlock()
			t.Fatal("transport failure must fail the publish")
		}
		h.m.mu.Unlock()
	}
	clearOnce := func() {
		t.Helper()
		h.mu.Lock()
		h.statusGen = 9
		h.mu.Unlock()
		h.m.mu.Lock()
		defer h.m.mu.Unlock()
		if err := h.m.clearHelperHAStateWithDebtLocked(); err != nil {
			t.Fatalf("standalone clear retry: %v", err)
		}
	}
	fail()
	h.m.mu.Lock()
	if !h.m.pendingHAStateClear {
		h.m.mu.Unlock()
		t.Fatal("standalone adopt did not record the HA-clear obligation")
	}
	h.m.mu.Unlock()
	clearsBefore := updateHACount()
	clearOnce()
	h.m.mu.Lock()
	if h.m.pendingHAStateClear {
		h.m.mu.Unlock()
		t.Fatal("successful clear did not settle the obligation")
	}
	h.m.mu.Unlock()
	if updateHACount() != clearsBefore+1 {
		t.Fatal("standalone clear did not send exactly one update_ha_state")
	}
	// A second failed retry re-arms the coalesced obligation (recurring until
	// snapshot settlement, not one-send-per-episode).
	fail()
	h.m.mu.Lock()
	pending := h.m.pendingHAStateClear
	h.m.mu.Unlock()
	if !pending {
		t.Fatal("repeat adoption did not re-arm the outstanding clear obligation")
	}
}

// TestRetryDebtClusteredAdoptSkipsHAClear9642: clustered adopts record no
// clear debt, and the tick retry stays suppressed while clustered.
func TestRetryDebtClusteredAdoptSkipsHAClear9642(t *testing.T) {
	t.Parallel()
	h := newDebtHarness9642(t)
	defer h.stopLoop(t)
	retained, attempted := buildDebtPair9642(t, false)
	h.seedPublished(t, retained)
	h.m.mu.Lock()
	h.m.clusterHA = true
	h.m.mu.Unlock()
	h.mu.Lock()
	h.applyErr = transportTimeout9642()
	h.mu.Unlock()
	h.m.mu.Lock()
	var status ProcessStatus
	if err := h.m.publishSnapshotFailClosedLocked(attempted, &status, true); err == nil {
		h.m.mu.Unlock()
		t.Fatal("transport failure must fail the publish")
	}
	if h.m.pendingHAStateClear {
		h.m.mu.Unlock()
		t.Fatal("clustered adopt recorded a standalone clear obligation")
	}
	h.m.pendingHAStateClear = true
	h.m.retryPendingHAStateClearLocked()
	h.m.mu.Unlock()
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, typ := range h.sentTypes {
		if typ == "update_ha_state" {
			t.Fatal("tick retry sent update_ha_state while clustered; that would wipe live RG state")
		}
	}
}

// TestRetryDebtHAPublishesDuringDebt9642: the debt latch gates ctrl only.
// With all RGs inactive, an unpublished inventory, and a due throttle, the
// daemon heartbeat path (UpdateHAWatchdog) still puts update_ha_state on the
// wire while ctrl stays disabled.
func TestRetryDebtHAPublishesDuringDebt9642(t *testing.T) {
	t.Parallel()
	h := newDebtHarness9642(t)
	defer h.stopLoop(t)
	retained, attempted := buildDebtPair9642(t, false)
	h.seedPublished(t, retained)
	h.mu.Lock()
	h.applyErr = transportTimeout9642()
	h.mu.Unlock()
	h.m.mu.Lock()
	var status ProcessStatus
	if err := h.m.publishSnapshotFailClosedLocked(attempted, &status, true); err == nil {
		h.m.mu.Unlock()
		t.Fatal("premise: transport failure must fail the publish")
	}
	h.m.mu.Unlock()
	h.stopLoop(t)
	h.m.haWatchdogMapWrite = func(int, uint64) error { return nil }
	h.m.mu.Lock()
	h.m.haGroups = map[int]HAGroupStatus{0: {RGID: 0, Active: false}}
	h.m.lastHASyncTime = time.Time{}
	h.m.mu.Unlock()
	if err := h.m.UpdateHAWatchdog(0, 1); err != nil {
		t.Fatalf("UpdateHAWatchdog during debt: %v", err)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	found := false
	for _, typ := range h.sentTypes {
		if typ == "update_ha_state" {
			found = true
		}
	}
	if !found {
		t.Fatal("no update_ha_state crossed while indebted; HA inventory must publish during debt")
	}
}

// TestRetryDebtDirectProducerConvertsViaPartial9642 (N1): an overlay-style
// failure (mark, generations equal — unlatched, reconciled as today)
// followed by a successful partial update opens generation debt: the latch
// engages and the forced full republish converges and re-enables.
func TestRetryDebtDirectProducerConvertsViaPartial9642(t *testing.T) {
	t.Parallel()
	h := newDebtHarness9642(t)
	defer h.stopLoop(t)
	retained, _ := buildDebtPair9642(t, false)
	h.seedPublished(t, retained)
	// Direct-producer failure shape: requestApplySnapshotLocked fails
	// transport without touching retained/published generations.
	other, err := buildSnapshot(&config.Config{}, config.UserspaceConfig{Workers: 1}, 8, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	h.mu.Lock()
	h.applyErr = transportTimeout9642()
	h.mu.Unlock()
	h.m.mu.Lock()
	if err := h.m.requestApplySnapshotLocked(other, nil); err == nil {
		h.m.mu.Unlock()
		t.Fatal("premise: direct transport failure must fail")
	}
	if h.m.snapshotRetryDebtLocked() {
		h.m.mu.Unlock()
		t.Fatal("premise broken: equal generations must not latch")
	}
	// Parent review round 2: the debt clock starts at the mark-setting
	// transition even though no latch (and no adoption) exists yet.
	clock := h.m.retryDebtSince
	if clock.IsZero() {
		h.m.mu.Unlock()
		t.Fatal("direct-producer unknown outcome did not stamp the debt clock")
	}
	st := h.reportStatusLocked()
	if err := h.m.applyHelperStatusLocked(&st); err != nil {
		h.m.mu.Unlock()
		t.Fatalf("applyHelperStatusLocked: %v", err)
	}
	if !h.statusCtrl.haveStored || h.statusCtrl.stored.Enabled != 1 {
		h.m.mu.Unlock()
		t.Fatal("mark-without-generation-debt must reconcile as today (ctrl enabled)")
	}
	// Successful partial update converts to generation debt.
	h.m.advanceGenerationAfterPartialUpdateLocked()
	if !h.m.snapshotRetryDebtLocked() {
		h.m.mu.Unlock()
		t.Fatal("partial success did not open generation debt on marked state")
	}
	if h.m.retryDebtSince.IsZero() || !h.m.retryDebtSince.Equal(clock) {
		h.m.mu.Unlock()
		t.Fatal("conversion reset or cleared the debt clock; recovery would report against the wrong age")
	}
	if err := h.m.applyHelperStatusLocked(&st); err != nil {
		h.m.mu.Unlock()
		t.Fatalf("applyHelperStatusLocked while converted: %v", err)
	}
	h.m.mu.Unlock()
	if h.statusCtrl.stored.Enabled != 0 {
		t.Fatal("converted debt did not hold ctrl at 0")
	}
	// Forced full republish converges and re-enables.
	h.mu.Lock()
	h.applyErr = nil
	h.mu.Unlock()
	h.mu.Lock()
	h.statusGen = 9
	h.mu.Unlock()
	h.m.mu.Lock()
	if err := h.m.syncSnapshotLocked(); err != nil {
		h.m.mu.Unlock()
		t.Fatalf("converted debt retry: %v", err)
	}
	enabled := h.statusCtrl.haveStored && h.statusCtrl.stored.Enabled == 1
	mark := h.m.applySnapshotOutcomeUnknown
	h.m.mu.Unlock()
	if mark || !enabled {
		t.Fatalf("converted debt did not converge (mark=%v ctrl-enabled=%v)", mark, enabled)
	}
}

// TestRetryDebtNeighborProgressesDuringDebt9642: partial neighbor updates
// still send while indebted, refresh the cached sections on success, and the
// next debt retry carries the fresh sections (published/hash held meanwhile).
func TestRetryDebtNeighborProgressesDuringDebt9642(t *testing.T) {
	t.Parallel()
	h := newDebtHarness9642(t)
	defer h.stopLoop(t)
	retained, attempted := buildDebtPair9642(t, false)
	h.seedPublished(t, retained)
	h.mu.Lock()
	h.applyErr = transportTimeout9642()
	h.mu.Unlock()
	h.m.mu.Lock()
	var status ProcessStatus
	if err := h.m.publishSnapshotFailClosedLocked(attempted, &status, true); err == nil {
		h.m.mu.Unlock()
		t.Fatal("premise: transport failure must fail the publish")
	}
	fresh := NeighborSnapshot{Ifindex: 7, IP: "10.0.1.1", MAC: "aa:bb:cc:dd:ee:01", State: "reachable"}
	if !neighborSnapshotPublishable(fresh) {
		h.m.mu.Unlock()
		t.Fatal("fixture invalid: fresh neighbor must be publishable")
	}
	h.m.lastSnapshot.Neighbors = append(append([]NeighborSnapshot(nil), h.m.lastSnapshot.Neighbors...), fresh)
	h.m.advanceGenerationAfterPartialUpdateLocked()
	if h.m.publishedSnapshot != 8 {
		h.m.mu.Unlock()
		t.Fatalf("publishedSnapshot moved to %d during indebted partial", h.m.publishedSnapshot)
	}
	retryGen := h.m.lastSnapshot.Generation
	h.m.mu.Unlock()

	h.mu.Lock()
	h.applyErr = nil
	h.mu.Unlock()
	h.mu.Lock()
	h.statusGen = retryGen
	h.mu.Unlock()
	h.m.mu.Lock()
	if err := h.m.syncSnapshotLocked(); err != nil {
		h.m.mu.Unlock()
		t.Fatalf("debt retry: %v", err)
	}
	h.m.mu.Unlock()
	h.mu.Lock()
	defer h.mu.Unlock()
	body := h.sentSnaps[len(h.sentSnaps)-1]
	for _, n := range body.Neighbors {
		if n.IP == "10.0.1.1" {
			return
		}
	}
	t.Fatal("debt retry did not carry the re-sampled neighbor section")
}

// TestRetryDebtLoggingContract9642: the debt-record transition Warns once;
// repeats are Debug; the tick caller Warns only for non-debt sync failures.
// Sequential on purpose: it swaps the process-wide slog default.
func TestRetryDebtLoggingContract9642(t *testing.T) {
	var buf syncBuffer9642
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	h := newDebtHarness9642(t)
	defer h.stopLoop(t)
	retained, attempted := buildDebtPair9642(t, false)
	h.seedPublished(t, retained)
	h.mu.Lock()
	h.applyErr = transportTimeout9642()
	h.mu.Unlock()
	fail := func() {
		t.Helper()
		h.m.mu.Lock()
		var status ProcessStatus
		_ = h.m.publishSnapshotFailClosedLocked(attempted, &status, true)
		h.m.mu.Unlock()
	}
	fail()
	if got := buf.count("retained as retry debt"); got != 1 {
		t.Fatalf("debt-record Warn fired %d time(s), want exactly 1", got)
	}
	h.m.mu.Lock()
	sinceSet, warnStamped := !h.m.retryDebtSince.IsZero(), !h.m.lastRetryDebtWarn.IsZero()
	h.m.mu.Unlock()
	if !sinceSet || !warnStamped {
		t.Fatal("adopt transition did not stamp the debt clock and Warn marker (rate limiter has no baseline)")
	}
	fail()
	if got := buf.count("retained as retry debt"); got != 1 {
		t.Fatalf("repeat failure re-Warned the debt record (%d total), want Debug only", got)
	}
	if got := buf.count("debt persists"); got != 1 {
		t.Fatalf("repeat failure Debug fired %d time(s), want 1", got)
	}
}

// syncBuffer9642 is a mutex-guarded slog sink so parallel ticks cannot race
// the count assertions (the logging cell itself stays sequential).
type syncBuffer9642 struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer9642) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer9642) count(substr string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.Count(s.buf.String(), substr)
}

// TestRetryDebtCompileRestartPathKeepsLoop9642 (§9.21): Compile's own restart
// path stops the helper, then a deterministic post-respawn protocol failure
// returns before the normal loop ensure. The loop must be alive on return even
// with pre-existing debt; deleting the ensure fails this cell.
func TestRetryDebtCompileRestartPathKeepsLoop9642(t *testing.T) {
	t.Parallel()
	h := newDebtHarness9642(t)
	defer h.stopLoop(t)
	ucfg := config.UserspaceConfig{Workers: 1}
	cfg := &config.Config{}
	retained, err := buildSnapshot(cfg, ucfg, 8, 0)
	if err != nil {
		t.Fatalf("buildSnapshot retained: %v", err)
	}
	snap, err := buildSnapshot(cfg, ucfg, 9, 0)
	if err != nil {
		t.Fatalf("buildSnapshot attempted: %v", err)
	}
	snap.partialUpdateEpoch = h.m.partialUpdateEpoch.Load()
	h.seedPublished(t, retained)
	h.m.mu.Lock()
	h.m.cfg = ucfg
	h.m.mu.Unlock()
	// Pre-existing debt, loop dead (post-restart shape): fail, then consume
	// the started worker without leaving it running.
	h.mu.Lock()
	h.applyErr = transportTimeout9642()
	h.mu.Unlock()
	h.m.mu.Lock()
	var status ProcessStatus
	if err := h.m.publishSnapshotFailClosedLocked(snap, &status, true); err == nil {
		h.m.mu.Unlock()
		t.Fatal("premise: transport failure must fail the publish")
	}
	cancel := h.m.syncCancel
	h.m.syncCancel = nil
	h.m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	// Deterministic protocol failure: the helper stands at an older version.
	h.m.mu.Lock()
	h.m.lastStatus.ConfigSnapshotProtocolVersion = ProtocolVersion - 1
	h.m.mu.Unlock()
	// applyCompiledSnapshot takes m.mu itself: never hold it across the call.
	_, err = h.m.applyCompiledSnapshot(cfg, &dataplane.CompileResult{}, snap, ucfg, UserspaceCapabilities{})
	h.m.mu.Lock()
	loopAlive := h.m.syncCancel != nil
	h.m.mu.Unlock()
	if err == nil {
		t.Fatal("protocol-mismatched apply must fail")
	}
	if !loopAlive {
		t.Fatal("status loop dead after the post-restart protocol failure; pre-existing debt is orphaned")
	}
}

// TestRetryDebtBlocksTakeoverReadiness9642 (parent review GPT-1): an indebted
// node must not advertise takeover readiness, and the reason must name the
// unpublished generation. Clearing the debt restores readiness on an
// otherwise healthy node.
//
// RED-on-revert: drop the gate and an indebted healthy-looking node reports
// ready=true — an RG handoff into a transit outage.
func TestRetryDebtBlocksTakeoverReadiness9642(t *testing.T) {
	t.Parallel()
	healthy := func(t *testing.T) *Manager {
		t.Helper()
		return &Manager{
			proc: &exec.Cmd{Process: &os.Process{Pid: 1}},
			lastStatus: ProcessStatus{
				Enabled:         true,
				ForwardingArmed: true,
				Capabilities:    UserspaceCapabilities{ForwardingSupported: true},
			},
			mode:              ModeUserspaceCompat,
			xskLivenessProven: true,
			eventStream:       boundEventStream(t),
		}
	}
	t.Run("indebted_not_ready", func(t *testing.T) {
		t.Parallel()
		m := healthy(t)
		snap, err := buildSnapshot(&config.Config{}, config.UserspaceConfig{Workers: 1}, 9, 0)
		if err != nil {
			t.Fatalf("buildSnapshot: %v", err)
		}
		m.mu.Lock()
		m.lastSnapshot = snap
		m.publishedSnapshot = 8
		m.applySnapshotOutcomeUnknown = true
		ready, reasons := m.takeoverReadyLocked()
		m.mu.Unlock()
		if ready {
			t.Fatal("TakeoverReady() = true with unpublished retry debt")
		}
		found := false
		for _, r := range reasons {
			if strings.Contains(r, "retry debt") && strings.Contains(r, "9") {
				found = true
			}
		}
		if !found {
			t.Fatalf("no generation-naming debt reason in %q", reasons)
		}
	})
	t.Run("settled_ready", func(t *testing.T) {
		t.Parallel()
		m := healthy(t)
		snap, err := buildSnapshot(&config.Config{}, config.UserspaceConfig{Workers: 1}, 9, 0)
		if err != nil {
			t.Fatalf("buildSnapshot: %v", err)
		}
		m.mu.Lock()
		m.lastSnapshot = snap
		m.publishedSnapshot = 9
		ready, reasons := m.takeoverReadyLocked()
		m.mu.Unlock()
		if !ready {
			t.Fatalf("TakeoverReady() = false on a settled healthy node: %q", reasons)
		}
	})
}

// TestRetryDebtHealthBesideMode9642 (parent review round 2, GPT-MAJOR): debt
// health is reported BESIDE the backend classification, never remapping it —
// a mode flip would install kernel blackhole routes that survive recovery.
// While indebted the mode stays the degraded mapping (compat with ctrl at 0,
// as today) with the debt flag + generation stamped; convergence clears the
// flag and restores ctrl with no sticky state.
//
// RED-on-revert: remap the mode on debt and the Compat assertion fails; drop
// the stamp and the flag assertions fail.
func TestRetryDebtHealthBesideMode9642(t *testing.T) {
	t.Parallel()
	h := newDebtHarness9642(t)
	defer h.stopLoop(t)
	retained, attempted := buildDebtPair9642(t, false)
	h.seedPublished(t, retained)
	h.mu.Lock()
	h.applyErr = transportTimeout9642()
	h.mu.Unlock()
	h.m.mu.Lock()
	var status ProcessStatus
	if err := h.m.publishSnapshotFailClosedLocked(attempted, &status, true); err == nil {
		h.m.mu.Unlock()
		t.Fatal("premise: transport failure must fail the publish")
	}
	h.m.mu.Unlock()
	h.stopLoop(t)
	h.m.mu.Lock()
	st := h.reportStatusLocked()
	if err := h.m.applyHelperStatusLocked(&st); err != nil {
		h.m.mu.Unlock()
		t.Fatalf("applyHelperStatusLocked: %v", err)
	}
	if h.m.mode != ModeUserspaceCompat {
		h.m.mu.Unlock()
		t.Fatalf("m.mode = %v while indebted, want the unchanged degraded mapping %v (debt must not remap classification)",
			h.m.mode, ModeUserspaceCompat)
	}
	if !h.m.lastStatus.SnapshotRetryDebt || h.m.lastStatus.SnapshotRetryDebtGeneration != 9 {
		h.m.mu.Unlock()
		t.Fatalf("helper_status debt health = (%v, gen %d), want (true, 9): health beside, not instead of, the mode",
			h.m.lastStatus.SnapshotRetryDebt, h.m.lastStatus.SnapshotRetryDebtGeneration)
	}
	h.m.mu.Unlock()
	// Through convergence: the retry lands, the flag clears, ctrl re-enables
	// against the new plan with the normal mode mapping.
	h.mu.Lock()
	h.applyErr = nil
	h.statusGen = 9
	h.mu.Unlock()
	h.m.mu.Lock()
	if err := h.m.syncSnapshotLocked(); err != nil {
		h.m.mu.Unlock()
		t.Fatalf("debt retry: %v", err)
	}
	debt, gen := h.m.lastStatus.SnapshotRetryDebt, h.m.lastStatus.SnapshotRetryDebtGeneration
	mode, enabled := h.m.mode, h.statusCtrl.stored.Enabled
	h.m.mu.Unlock()
	if debt || gen != 0 {
		t.Fatalf("debt health stuck after convergence (flag=%v gen=%d)", debt, gen)
	}
	if mode != ModeUserspaceCompat || enabled != 1 {
		t.Fatalf("post-convergence mode=%v ctrl=%d, want compat/1: recovery left sticky state", mode, enabled)
	}
}

// TestRetryDebtRecorderIgnoresDeterministicFailures9642 (parent review GPT-2):
// digest/marshal/size/socket failures change neither the mark nor the debt
// timestamps — the helper provably received nothing. A deferred-but-
// unpublished snapshot plus such a failure keeps today's posture (no latch).
func TestRetryDebtRecorderIgnoresDeterministicFailures9642(t *testing.T) {
	t.Parallel()
	sizeErr := &knownUnsentError{msg: "too big", cause: errControlRequestTooLarge}
	t.Run("no_mark_from_deterministic", func(t *testing.T) {
		t.Parallel()
		m := New()
		m.mu.Lock()
		defer m.mu.Unlock()
		for name, err := range map[string]error{
			"digest":  errSnapshotDigest,
			"encode":  &knownUnsentError{msg: "encode boom", cause: errControlRequestEncode},
			"size":    sizeErr,
			"socket":  errControlSocketNotConfigured,
			"wrapped": &knownUnsentError{msg: errControlSocketNotConfigured.Error(), cause: errControlSocketNotConfigured},
		} {
			m.recordApplySnapshotOutcomeLocked(err)
			if m.applySnapshotOutcomeUnknown {
				t.Fatalf("%s failure set the unknown-outcome mark", name)
			}
		}
	})
	t.Run("debt_preserved_and_unlatched", func(t *testing.T) {
		t.Parallel()
		m := New()
		m.mu.Lock()
		defer m.mu.Unlock()
		m.applySnapshotOutcomeUnknown = true
		m.retryDebtSince = time.Now().Add(-time.Minute)
		m.lastRetryDebtWarn = time.Now().Add(-time.Minute)
		m.recordApplySnapshotOutcomeLocked(sizeErr)
		if !m.applySnapshotOutcomeUnknown {
			t.Fatal("deterministic failure cleared pre-existing unknown-outcome state")
		}
		if m.retryDebtSince.IsZero() {
			t.Fatal("deterministic failure cleared the debt clock")
		}
	})
	t.Run("transport_sets_success_clears", func(t *testing.T) {
		t.Parallel()
		m := New()
		m.mu.Lock()
		defer m.mu.Unlock()
		m.recordApplySnapshotOutcomeLocked(transportTimeout9642())
		if !m.applySnapshotOutcomeUnknown {
			t.Fatal("transport failure did not set the mark")
		}
		m.retryDebtSince = time.Now()
		m.recordApplySnapshotOutcomeLocked(nil)
		if m.applySnapshotOutcomeUnknown || !m.retryDebtSince.IsZero() || !m.lastRetryDebtWarn.IsZero() {
			t.Fatal("successful apply did not clear mark and debt clocks")
		}
	})
	t.Run("deferred_gap_without_mark_stays_unlatched", func(t *testing.T) {
		t.Parallel()
		// Deferred-publication shape (pendingXSKStartup left Gen 8 ahead of
		// published 1) plus a deterministic failure: mark stays false, so
		// the latch must stay out and today's revert-to-old path owns it.
		m := New()
		snap, err := buildSnapshot(&config.Config{}, config.UserspaceConfig{Workers: 1}, 8, 0)
		if err != nil {
			t.Fatalf("buildSnapshot: %v", err)
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		m.lastSnapshot = snap
		m.publishedSnapshot = 1
		m.recordApplySnapshotOutcomeLocked(sizeErr)
		if m.snapshotRetryDebtLocked() {
			t.Fatal("latch engaged with no transport-unknown outcome behind the gap")
		}
	})
}

// TestRetryDebtWarnRateLimit9642 (parent review GPT-3): the repeat Warn is
// bounded (transition + at most once a minute), bound by a pure predicate on
// manager state so the boundary needs no clock or global mutation.
func TestRetryDebtWarnRateLimit9642(t *testing.T) {
	t.Parallel()
	now := time.Now()
	m := New()
	m.mu.Lock()
	defer m.mu.Unlock()
	snap, err := buildSnapshot(&config.Config{}, config.UserspaceConfig{Workers: 1}, 9, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	m.lastSnapshot = snap
	m.publishedSnapshot = 8
	m.applySnapshotOutcomeUnknown = true
	if !m.retryDebtWarnDueLocked(now) {
		t.Fatal("Warn not due on unseen debt (transition)")
	}
	m.lastRetryDebtWarn = now
	if m.retryDebtWarnDueLocked(now.Add(30 * time.Second)) {
		t.Fatal("Warn due 30s after the last one; the repeat must be rate-limited")
	}
	if !m.retryDebtWarnDueLocked(now.Add(61 * time.Second)) {
		t.Fatal("Warn not due past the minute boundary while debt persists")
	}
	m.applySnapshotOutcomeUnknown = false
	if m.retryDebtWarnDueLocked(now.Add(time.Hour)) {
		t.Fatal("Warn due with no debt outstanding")
	}
}

// TestRetryDebtRespawnFailureWarns9642 (parent review GPT-3): the restart
// branch's bring-up failure is terminal for the tick — no consumer, no retry
// — so it Warns every time with the debt state instead of fading to Debug.
func TestRetryDebtRespawnFailureWarns9642(t *testing.T) {
	var buf syncBuffer9642
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	h := newDebtHarness9642(t)
	defer h.stopLoop(t)
	retained, attempted := buildDebtPair9642(t, true)
	h.seedPublished(t, retained)
	sleep1 := exec.Command("sleep", "300")
	if err := sleep1.Start(); err != nil {
		t.Fatalf("start sleep: %v", err)
	}
	t.Cleanup(func() {
		_ = sleep1.Process.Kill()
		_, _ = sleep1.Process.Wait()
	})
	h.m.mu.Lock()
	h.m.proc = sleep1
	h.m.mu.Unlock()
	h.mu.Lock()
	h.applyErr = transportTimeout9642()
	h.statusGen = 9
	h.mu.Unlock()
	h.m.mu.Lock()
	var status ProcessStatus
	if err := h.m.publishSnapshotFailClosedLocked(attempted, &status, false); err == nil {
		h.m.mu.Unlock()
		t.Fatal("premise: transport failure must fail the publish")
	}
	h.m.mu.Unlock()
	h.stopLoop(t)
	// No bring-up hook: the real ensureProcessLocked finds no helper binary.
	h.m.mu.Lock()
	err := h.m.syncSnapshotLocked()
	loopDead := h.m.syncCancel == nil
	h.m.mu.Unlock()
	if err == nil {
		t.Fatal("respawn-failure sync must fail")
	}
	if !loopDead {
		t.Fatal("loop consumer must stay dead when bring-up fails (stale slot wedges every future ensure)")
	}
	if got := buf.count("no status-loop consumer until bring-up is retried"); got != 1 {
		t.Fatalf("consumer-loss Warn fired %d time(s), want exactly 1 (terminal boundary, always visible)", got)
	}
}
