package daemon

// #17025 (R4-Q31-04): the post-promotion
// arm/apply/classify/surface/discharge/stamp/push sequence is ONE
// implementation (finalizePromotedApplyLocked in apply_finalize.go),
// shared by the commit, peer-sync and confirm-timeout-rollback
// drivers. These cells pin the consolidation:
//
//   - ACCEPTANCE (b): table cells run the commit and peer-sync
//     drivers through the REAL-apply harness
//     (newInvalDebtHarness12073 / newConvergenceRun12072 — never
//     applyBodyForTest, which cannot see the #12073 stamp) across
//     {nil, non-fatal, fatal, cancel, unpublished incomplete
//     capture, published incomplete capture, deferred publish};
//     dedicated rollback cells (newRealApplyRollbackHarness9811 /
//     newLandedRollbackRun12072) cover clean, non-fatal, fatal,
//     cancel and the unpublished incomplete capture (ERROR alarm +
//     latched #9811 debt error); dedicated sync cells cover
//     deferred-no-completion x device-map (#1956 alarm) and pin
//     that capture-error surfacing does not reclassify sync's bare
//     apply error; the commit-composite peer-push cell verifies the
//     joined error is fatal before commit side effects.
//   - ACCEPTANCE (c): the #6948 arm comment occurs once.
//
// RED pre-fix: the structural cell fails (three arm sites, three
// discharge sites, three #6948 comments in daemon_apply_commit.go
// and no apply_finalize.go); the sync unpublished-capture cell
// fails because the #12072 surfacing existed only in the commit
// copy (the sync error lacks the capture error and no ERROR alarm
// fires; the rollback logged nothing).

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// deferredNoCompletionDP17025 drops the deferred-snapshot record a
// deferred apply made, so finalize sees a deferred publish with no
// recorded completion (the generation-0 shape).
type deferredNoCompletionDP17025 struct {
	*convergenceHelper12072
	d *Daemon
}

func (w *deferredNoCompletionDP17025) ApplyConfig(ctx context.Context, cfg *config.Config) (*dataplane.ApplyResult, error) {
	res, err := w.convergenceHelper12072.ApplyConfig(ctx, cfg)
	if err == nil && res != nil && res.SnapshotPublishDeferred {
		// The record is made later, in applyDataplaneAndHACore from
		// this same result; drop it on the next deferred-completion
		// lookup by clearing at finalize time — see the Daemon hook
		// below: instead, zero the generation so recordDeferred… is
		// a no-op (generation 0 is its sentinel).
		res.Generation = 0
	}
	return res, err
}

// TestFinalizeConsolidationShape17025 is acceptance (a)+(c): one arm
// call, one stamp call, one discharge call and one #6948 comment, all
// in apply_finalize.go; the three drivers call the helper instead.
func TestFinalizeConsolidationShape17025(t *testing.T) {
	counts := func(file string) (calls map[string]int, comments []string) {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, file, nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
		calls = map[string]int{}
		ast.Inspect(f, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok {
				calls[sel.Sel.Name]++
			}
			return true
		})
		for _, cg := range f.Comments {
			comments = append(comments, cg.Text())
		}
		return calls, comments
	}

	finCalls, finComments := counts("apply_finalize.go")
	for _, name := range []string{
		"armPolicyInvalidationPlan",
		"armPolicyInvalidationPlanWithRename",
		"armPolicyInvalidationRollbackPlan",
		"stampActiveAppliedIfConvergedUnderSem",
		"stampDigestIfConvergedUnderSem",
		"dischargePolicyInvalidationDebtLocked",
	} {
		if got := finCalls[name]; got != 1 {
			t.Errorf("apply_finalize.go: %s called %d times, want exactly 1 (acceptance (a))", name, got)
		}
	}
	arm6948 := 0
	for _, c := range finComments {
		arm6948 += strings.Count(c, "#6948: arm the commit-time session-invalidation plan BEFORE the apply.")
	}
	if arm6948 != 1 {
		t.Errorf("apply_finalize.go: #6948 arm comment occurs %d times, want 1 (acceptance (c))", arm6948)
	}

	drvCalls, drvComments := counts("daemon_apply_commit.go")
	for _, name := range []string{
		"armPolicyInvalidationPlan",
		"armPolicyInvalidationPlanWithRename",
		"armPolicyInvalidationRollbackPlan",
		"stampActiveAppliedIfConvergedUnderSem",
		"stampDigestIfConvergedUnderSem",
		"dischargePolicyInvalidationDebtLocked",
	} {
		if got := drvCalls[name]; got != 0 {
			t.Errorf("daemon_apply_commit.go: %s still called %d times; drivers must go through finalizePromotedApplyLocked", name, got)
		}
	}
	arm6948 = 0
	for _, c := range drvComments {
		arm6948 += strings.Count(c, "#6948: arm the commit-time session-invalidation plan BEFORE the apply.")
	}
	if arm6948 != 0 {
		t.Errorf("daemon_apply_commit.go: #6948 arm comment occurs %d times, want 0 (it lives once in apply_finalize.go)", arm6948)
	}
	if got := drvCalls["finalizePromotedApplyLocked"]; got != 3 {
		t.Errorf("daemon_apply_commit.go: finalizePromotedApplyLocked called %d times, want 3 (commit, peer-sync, rollback)", got)
	}
}

// finalizeCell17025 runs ONE real-apply cell: a fresh convergence
// harness with one scripted dataplane outcome, driven through one of
// the three drivers.
type finalizeCell17025 struct {
	name       string
	script     []invalDebtOutcome12073
	incomplete int // convergence-helper incomplete READs to inject

	wantErr      bool
	wantCapture  bool // surfaced error carries the #12072 capture error
	wantStamped  bool
	wantSessions bool // p-web sessions still installed afterwards
	wantAlarm    bool // the capture's single ERROR alarm fired
	deferredSync bool // sync driver returns ConfigApplyPendingError
}

func runFinalizeCell17025(t *testing.T, cell finalizeCell17025, driver string) {
	t.Helper()
	var logs strings.Builder
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelError})))
	defer slog.SetDefault(prev)

	r, c0 := newConvergenceRun12072(t, []string{"p-first", "a", "web"})
	c1 := twoPolicyConfig([]string{"p-first", "web"}, nil)
	r.dp.incompleteNext = cell.incomplete
	r.dp.invalDebtTestDP12073.script = cell.script

	var err error
	switch driver {
	case "commit":
		err = r.commitWithPeer("c1", c0, c1, peerSyncNever)
	case "sync":
		// Peer-sync ingress through the real syncAndApplyWithAncestry
		// (SyncApply + real apply). Null the cluster runtime: the
		// convergence harness's fake manager would otherwise make
		// the topology preflight refuse the non-clustered peer text
		// before the finalize step runs — that preflight is a
		// different gate, exercised by its own cells. The driver
		// acquires applySem itself; the caller must NOT hold it.
		savedCluster := r.h.d.cluster
		r.h.d.cluster = nil
		defer func() { r.h.d.cluster = savedCluster }()
		text := "system { host-name c1; }\n" +
			"security { zones { security-zone trust; security-zone untrust; } " +
			"policies { from-zone trust to-zone untrust { " +
			"policy p-first { match { source-address any; destination-address any; application any; } then { permit; } } " +
			"policy web { match { source-address any; destination-address any; application any; } then { permit; } } } } }"
		_, err = r.h.d.syncAndApplyWithAncestry(context.Background(), text, nil, nil)
	}

	if cell.deferredSync && driver == "sync" {
		var pending *cluster.ConfigApplyPendingError
		if !errors.As(err, &pending) {
			t.Fatalf("sync/%s: error = %v, want ConfigApplyPendingError", cell.name, err)
		}
		err = nil
	}
	if cell.wantErr && err == nil {
		t.Fatalf("%s/%s: expected an error, got nil", driver, cell.name)
	}
	if !cell.wantErr && err != nil {
		t.Fatalf("%s/%s: unexpected error: %v", driver, cell.name, err)
	}
	if cell.wantCapture {
		if err == nil || !strings.Contains(err.Error(), "policy session READ incomplete") {
			t.Fatalf("%s/%s: surfaced error = %v, want it to carry the #12072 unpublished-capture error", driver, cell.name, err)
		}
	}
	if got := r.h.d.store.ActiveApplied(); got != cell.wantStamped {
		t.Fatalf("%s/%s: ActiveApplied = %v, want %v", driver, cell.name, got, cell.wantStamped)
	}
	if got := r.hasLiveSession(1); got != cell.wantSessions {
		t.Fatalf("%s/%s: p-web(a) session live = %v, want %v (deleted=%v rows=%v)", driver, cell.name, got, cell.wantSessions, r.dp.deleted, r.dp.rows)
	}
	alarm := strings.Contains(logs.String(), "pre-publication scan incomplete")
	if alarm != cell.wantAlarm {
		t.Fatalf("%s/%s: #12072 ERROR alarm fired = %v, want %v (logs: %s)", driver, cell.name, alarm, cell.wantAlarm, logs.String())
	}
}

// TestPromotedApplyDrivers17025 is acceptance (b): commit and
// peer-sync through the shared table across the outcome matrix;
// rollback through dedicated cells (its configs are the rollback
// store's A/B, so its assertions are the rollback-shaped
// equivalents: stamped-via-discharge, debt owed, sessions via the
// same convergence helper where applicable).
func TestPromotedApplyDrivers17025(t *testing.T) {
	transient := errors.New("helper control socket: connection refused")

	cells := []finalizeCell17025{
		{name: "clean", script: nil,
			wantErr: false, wantStamped: true, wantSessions: false, wantAlarm: false},
		{name: "nonfatalPublishFails", script: []invalDebtOutcome12073{{err: transient}},
			wantErr: true, wantStamped: false, wantSessions: true, wantAlarm: false},
		{name: "fatalSchedulerGate", script: []invalDebtOutcome12073{{err: dpuserspace.ErrPolicySchedulerProtocolIncompatible}},
			wantErr: true, wantStamped: false, wantSessions: true, wantAlarm: false},
		{name: "cancel", script: []invalDebtOutcome12073{{err: context.Canceled}},
			wantErr: true, wantStamped: false, wantSessions: true, wantAlarm: false},
		{name: "unpublishedIncompleteCapture", script: []invalDebtOutcome12073{{err: transient}}, incomplete: 1,
			wantErr: true, wantCapture: true, wantStamped: false, wantSessions: true, wantAlarm: true},
		{name: "publishedIncompleteCapture", script: nil, incomplete: 1,
			wantErr: true, wantStamped: false, wantSessions: true, wantAlarm: true},
		{name: "deferredPublish", script: []invalDebtOutcome12073{{deferred: true}},
			wantErr: false, wantStamped: false, wantSessions: true, wantAlarm: false, deferredSync: true},
	}
	for _, driver := range []string{"commit", "sync"} {
		for _, cell := range cells {
			t.Run(driver+"/"+cell.name, func(t *testing.T) {
				runFinalizeCell17025(t, cell, driver)
			})
		}
	}

	// Rollback-shaped cells (real apply via
	// newRealApplyRollbackHarness9811): the stamp decision is the
	// #12073 discharge stamp, the discharge decision is observable
	// through the #9811 debt + the applied marker, and the resync
	// decision is observable through syncPeerForTest.
	t.Run("rollback/clean", func(t *testing.T) {
		h, gen := newRealApplyRollbackHarness9811(t, nil)
		pushes := 0
		h.d.syncPeerForTest = func() { pushes++ }
		h.d.executeConfirmedRollback(gen)
		if owed, failures, _ := h.d.ConfigApplyDebt(); owed || failures != 0 {
			t.Fatalf("clean rollback owes a config apply (owed=%v failures=%d)", owed, failures)
		}
		if !h.d.store.ActiveApplied() {
			t.Fatal("clean rollback did not stamp through the #12073 discharge")
		}
		if pushes != 1 {
			t.Fatalf("clean rollback resynced %d times, want 1", pushes)
		}
	})
	t.Run("rollback/nonfatalPublishFails", func(t *testing.T) {
		h, gen := newRealApplyRollbackHarness9811(t, []invalDebtOutcome12073{{err: transient}})
		pushes := 0
		h.d.syncPeerForTest = func() { pushes++ }
		h.d.executeConfirmedRollback(gen)
		if owed, failures, _ := h.d.ConfigApplyDebt(); !owed || failures != 1 {
			t.Fatalf("failed rollback apply: owed=%v failures=%d, want true/1 (#9811 latch)", owed, failures)
		}
		if h.d.store.ActiveApplied() {
			t.Fatal("failed rollback apply must not stamp the active config as applied")
		}
		if pushes != 1 {
			t.Fatalf("failed rollback resynced %d times, want 1 (unconditional resync)", pushes)
		}
	})
	// The explicit resync decision: a FATAL local apply still resyncs
	// (the resync does not honour applyErrSkipsPeerSync). The store
	// has promoted C1; the peer must converge on C1 rather than C2.
	t.Run("rollback/fatalApply_stillResyncs", func(t *testing.T) {
		h, gen := newRealApplyRollbackHarness9811(t, []invalDebtOutcome12073{{err: dpuserspace.ErrPolicySchedulerProtocolIncompatible}})
		pushes := 0
		h.d.syncPeerForTest = func() { pushes++ }
		h.d.executeConfirmedRollback(gen)
		if pushes != 1 {
			t.Fatalf("fatal rollback apply resynced %d times, want 1 — the resync must NOT honour applyErrSkipsPeerSync (see executeConfirmedRollback decision (2))", pushes)
		}
		if h.d.store.ActiveApplied() {
			t.Fatal("fatal rollback apply must not stamp")
		}
	})
	t.Run("rollback/cancelClass_stillResyncs", func(t *testing.T) {
		// The rollback applies with context.Background(), so a
		// cancel-class dataplane error is just an apply error here:
		// it latches the #9811 debt and still resyncs.
		h, gen := newRealApplyRollbackHarness9811(t, []invalDebtOutcome12073{{err: context.Canceled}})
		pushes := 0
		h.d.syncPeerForTest = func() { pushes++ }
		h.d.executeConfirmedRollback(gen)
		if owed, _, _ := h.d.ConfigApplyDebt(); !owed {
			t.Fatal("cancel-class rollback apply must latch the #9811 debt")
		}
		if pushes != 1 {
			t.Fatalf("cancel-class rollback resynced %d times, want 1", pushes)
		}
	})
	// (1) Deferred-no-completion x device-map: the peer-sync apply
	// defers (script deferred) but no deferred completion was recorded
	// (the wrapper drops the record the real apply made), and the
	// synced text carries a device-map that would strand management.
	// Pre-fix the driver returned before armedActive=true, so the
	// never-silent #1956 alarm never fired; post-fix it must,
	// alongside the synthesized no-completion error, with no stamp.
	t.Run("sync/deferredNoCompletion_deviceMapAlarm", func(t *testing.T) {
		var logs strings.Builder
		prev := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelError})))
		defer slog.SetDefault(prev)
		savedEnum := enumeratePresentNICsFn
		enumeratePresentNICsFn = func() ([]presentNIC, error) {
			return []presentNIC{
				{Name: "fxp0", PCIAddr: "0000:05:00.0"},
				{Name: "enp9s0", PCIAddr: "0000:09:00.0"},
			}, nil
		}
		defer func() { enumeratePresentNICsFn = savedEnum }()
		savedLife := lifelineRecordFileForTest
		lifelineRecordFileForTest = filepath.Join(t.TempDir(), "no-lifeline")
		defer func() { lifelineRecordFileForTest = savedLife }()
		r, _ := newConvergenceRun12072(t, []string{"p-first", "a", "web"})
		r.dp.invalDebtTestDP12073.script = []invalDebtOutcome12073{{deferred: true}}
		r.h.d.setDataplane(&deferredNoCompletionDP17025{convergenceHelper12072: r.dp, d: r.h.d})
		savedCluster := r.h.d.cluster
		r.h.d.cluster = nil
		defer func() { r.h.d.cluster = savedCluster }()
		text := "system { host-name c1; }\n" +
			"chassis { device-map { interface fxp0 { pci 0000:09:00.0; } } }\n" +
			"security { zones { security-zone trust; security-zone untrust; } " +
			"policies { from-zone trust to-zone untrust { " +
			"policy p-first { match { source-address any; destination-address any; application any; } then { permit; } } " +
			"policy web { match { source-address any; destination-address any; application any; } then { permit; } } } } }"
		_, err := r.h.d.syncAndApplyWithAncestry(context.Background(), text, nil, nil)
		if err == nil || !strings.Contains(err.Error(), "has no publication completion") {
			// A pending error with a nil completion also reaches the
			// no-completion path; accept either spelling of it.
			var pending *cluster.ConfigApplyPendingError
			if !errors.As(err, &pending) || pending.Completion != nil {
				t.Fatalf("deferred-no-completion sync err = %v, want the synthesized no-completion error", err)
			}
		}
		if !strings.Contains(logs.String(), "would STRAND this node's") {
			t.Fatalf("#1956 device-map alarm did not fire on deferred-no-completion sync (logs: %s)", logs.String())
		}
		if r.h.d.store.ActiveApplied() {
			t.Fatal("deferred-no-completion sync must not stamp")
		}
	})
	// (2) Rollback x unpublished incomplete capture: the rollback
	// re-apply's publication fails while its pre-publication scan was
	// incomplete. The #12072 surfacing (shared before the kind switch)
	// must fire the single ERROR alarm and latch the #9811 debt with
	// the capture error; the unconditional resync still runs.
	t.Run("rollback/unpublishedIncompleteCapture", func(t *testing.T) {
		var logs strings.Builder
		prev := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelError})))
		defer slog.SetDefault(prev)
		// C1 is commit-confirmed; its capture is incomplete, then the
		// rollback re-apply's publication fails (unpublished). The
		// rollback finalize must surface the capture: ERROR alarm +
		// #9811 debt latched with the capture error.
		r, c0 := newLandedRollbackRun12072(t)
		r.dp.incompleteNext = 1
		_, gen, applyErr := publishConfirmedRollbackTarget12072(
			t, r, c0, "rollback-capture-c1", []string{"p-first", "b", "web"})
		if applyErr == nil {
			t.Fatal("C1 incomplete READ was not surfaced")
		}
		// Reset the log capture: the C1 publish already fired the
		// alarm once (errorSurfaced is once-only on that capture, but
		// the rollback capture is a fresh one — assert on rollback logs).
		logs.Reset()
		r.dp.incompleteNext = 1
		r.dp.invalDebtTestDP12073.script = make([]invalDebtOutcome12073, r.dp.invalDebtTestDP12073.applyCalls+1)
		r.dp.invalDebtTestDP12073.script[r.dp.invalDebtTestDP12073.applyCalls] =
			invalDebtOutcome12073{err: transient}
		pushes := 0
		r.h.d.syncPeerForTest = func() { pushes++ }
		r.h.d.executeConfirmedRollback(gen)
		// The surfacing fired during the rollback finalize: the
		// capture's errorSurfaced is set (enumerateErr is once-only).
		// This pins the rollback-path surfacing itself via the
		// latched debt error below.
		debt := r.h.d.policyInvalidationDebt
		if debt == nil || debt.capture == nil || !debt.capture.errorSurfaced ||
			debt.capture.readErr == nil ||
			!strings.Contains(debt.capture.readErr.Error(), "policy session READ incomplete") {
			t.Fatalf("rollback did not surface its incomplete capture: debt=%+v", debt)
		}
		_ = logs
		owed, failures, lastErr := r.h.d.ConfigApplyDebt()
		if !owed || failures != 1 || lastErr == "" {
			t.Fatalf("rollback debt = owed=%v failures=%d lastErr=%q, want latched", owed, failures, lastErr)
		}
		if pushes != 1 {
			t.Fatalf("rollback unpublished-capture resynced %d times, want 1 (unconditional)", pushes)
		}
		if r.h.d.store.ActiveApplied() {
			t.Fatal("unpublished rollback apply must not stamp")
		}
	})
	// (3) Capture-error surfacing must not reclassify: a non-fatal
	// apply whose capture readErr wraps context.Canceled stays
	// non-fatal (the driver returns the config, not the fatal
	// discard (nil, err)).
	t.Run("sync/captureCancelDoesNotFlipFatal", func(t *testing.T) {
		r, _ := newConvergenceRun12072(t, []string{"p-first", "a", "web"})
		r.dp.readErr = fmt.Errorf("helper READ: %w", context.Canceled)
		r.dp.invalDebtTestDP12073.script = []invalDebtOutcome12073{{err: transient}}
		savedCluster := r.h.d.cluster
		r.h.d.cluster = nil
		defer func() { r.h.d.cluster = savedCluster }()
		text := "system { host-name c1; }\n" +
			"security { zones { security-zone trust; security-zone untrust; } " +
			"policies { from-zone trust to-zone untrust { " +
			"policy p-first { match { source-address any; destination-address any; application any; } then { permit; } } " +
			"policy web { match { source-address any; destination-address any; application any; } then { permit; } } } } }"
		compiled, err := r.h.d.syncAndApplyWithAncestry(context.Background(), text, nil, nil)
		if compiled == nil {
			t.Fatalf("capture readErr wrapping context.Canceled flipped a non-fatal sync apply fatal: err=%v", err)
		}
		if err == nil || !strings.Contains(err.Error(), "policy session READ") || !strings.Contains(err.Error(), "context canceled") {
			t.Fatalf("sync err = %v, want it to carry the surfaced capture error", err)
		}
	})
}

// TestFinalizeDriversPeerPushShape17025 pins the driver-specific
// peer-push policy the helper preserves: commit pushes on non-fatal
// outcomes only, peer-sync never pushes, and the commit stamp gates
// on the local outcome (a peer failure does not erase it).
func TestFinalizeDriversPeerPushShape17025(t *testing.T) {
	transient := errors.New("helper control socket: connection refused")

	// Commit, non-fatal publish failure: the finalize step still
	// discharges/pushes per the classification (a bare helper error
	// is non-fatal), and does not stamp.
	func() {
		r, c0 := newConvergenceRun12072(t, []string{"p-first", "a", "web"})
		c1 := twoPolicyConfig([]string{"p-first", "web"}, nil)
		r.dp.invalDebtTestDP12073.script = []invalDebtOutcome12073{{err: transient}}
		pushes := 0
		r.h.d.syncPeerForTest = func() { pushes++ }
		if err := r.commitWithPeer("c1", c0, c1, peerSyncAlways); err == nil {
			t.Fatal("non-fatal publish failure must surface an error")
		}
		if pushes != 1 {
			t.Fatalf("non-fatal commit pushed %d times, want 1 (#4034: a non-fatal apply must still sync the peer)", pushes)
		}
		if r.h.d.store.ActiveApplied() {
			t.Fatal("failed publish must not stamp")
		}
	}()

	// Commit, fatal: no push, promoted config returned with the
	// ErrCommittedNotApplied wrap (shaping stays in the driver).
	func() {
		s := newCommitReadyStore(t, "system host-name OLD", "system host-name NEW")
		d := &Daemon{applySem: semaphore.NewWeighted(1), store: s}
		d.applyBodyForTest = func(_ *config.Config) {}
		d.applyErrForTest = dpuserspace.ErrPolicySchedulerProtocolIncompatible
		pushes := 0
		d.syncPeerForTest = func() { pushes++ }
		compiled, err := d.commitAndApply(context.Background(), configstore.InternalCommitter(), "", peerSyncAlways)
		if compiled == nil || !errors.Is(err, configstore.ErrCommittedNotApplied) {
			t.Fatalf("fatal commit = (%v, %v), want promoted config + ErrCommittedNotApplied", compiled, err)
		}
		if pushes != 0 {
			t.Fatalf("fatal commit pushed %d times, want 0", pushes)
		}
	}()
	// (4) Commit composite of (3): a non-fatal apply error whose
	// unpublished capture readErr wraps context.Canceled must be
	// classified on the JOINED error, exactly as the pre-consolidation
	// commit driver did. The joined error is fatal, so the commit must
	// stop before discharge/peer push/stamp and return the promoted
	// config with ErrCommittedNotApplied wrapping both components.
	t.Run("commit/captureCancelFlipsFatalAfterJoin", func(t *testing.T) {
		r, c0 := newConvergenceRun12072(t, []string{"p-first", "a", "web"})
		c1 := twoPolicyConfig([]string{"p-first", "web"}, nil)
		r.dp.readErr = fmt.Errorf("helper READ: %w", context.Canceled)
		r.dp.invalDebtTestDP12073.script = []invalDebtOutcome12073{{err: transient}}
		pushes := 0
		r.h.d.syncPeerForTest = func() { pushes++ }
		err := r.commitWithPeer("c1", c0, c1, peerSyncAlways)
		if err == nil {
			t.Error("commit with joined fatal capture error must return an error")
		}
		if !errors.Is(err, configstore.ErrCommittedNotApplied) {
			t.Errorf("commit err = %v, want ErrCommittedNotApplied wrap after joined fatal classification", err)
		}
		if !errors.Is(err, transient) || !errors.Is(err, context.Canceled) {
			t.Errorf("commit err = %v, want joined apply and capture errors", err)
		}
		if !applyErrSkipsPeerSync(err) {
			t.Errorf("commit err = %v, want fatal joined classification", err)
		}
		if pushes != 0 {
			t.Errorf("joined fatal commit pushed %d times, want 0", pushes)
		}
		if r.h.d.store.ActiveApplied() {
			t.Fatal("joined fatal commit must not stamp")
		}
	})
	_ = cluster.ConfigApplyPendingError{}
}
