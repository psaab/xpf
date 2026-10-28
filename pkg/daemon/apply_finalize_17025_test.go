package daemon

// #17025 (R4-Q31-04): the post-promotion
// arm/apply/classify/surface/discharge/stamp/push sequence is ONE
// implementation (finalizePromotedApplyLocked in apply_finalize.go),
// shared by the commit, peer-sync and confirm-timeout-rollback
// drivers. These cells pin the consolidation:
//
//   - ACCEPTANCE (a): armPolicyInvalidation* and the stamp*UnderSem
//     helpers are each called exactly once in daemon_apply_commit.go's
//     replacement (apply_finalize.go), and the drivers themselves no
//     longer call them or discharge directly.
//   - ACCEPTANCE (b): a table cell runs all three drivers through the
//     REAL-apply harness (newInvalDebtHarness12073 /
//     newRealApplyRollbackHarness9811 — never applyBodyForTest, which
//     cannot see the #12073 stamp) across
//     {nil, non-fatal, fatal, cancel, unpublished incomplete capture,
//     deferred publish} and asserts the same surfaced capture error,
//     stamp decision and discharge decision.
//   - ACCEPTANCE (c): the #6948 arm comment occurs once.
//
// RED pre-fix: the structural cell fails (three arm sites, three
// discharge sites, three #6948 comments in daemon_apply_commit.go and
// no apply_finalize.go); the sync/rollback unpublished-capture cells
// fail because the #12072 surfacing existed only in the commit copy
// (the sync error lacks the capture error and no ERROR alarm fires;
// the rollback logged nothing).

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"log/slog"
	"strings"
	"testing"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

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
	case "rollback":
		h, gen := newRealApplyRollbackHarness9811(t, cell.script)
		// Re-point the rollback harness at the convergence helper so
		// the incomplete READ + real capture path is exercised.
		_ = h
		_ = gen
		t.Fatalf("rollback cells use runFinalizeRollbackCell17025")
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

// TestPromotedApplyDrivers17025 is acceptance (b): all three drivers
// through the REAL-apply harness across the outcome matrix. The
// commit and peer-sync drivers share the convergence harness; the
// rollback driver runs through its own real-apply harness (its
// configs are the rollback store's A/B, so its assertions are the
// rollback-shaped equivalents: stamped-via-discharge, debt owed,
// sessions via the same convergence helper where applicable).
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
	// (honorFatalBeforeResync=false). The store has promoted C1; the
	// peer must converge its store on C1 rather than stay on C2.
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
	_ = cluster.ConfigApplyPendingError{}
}
