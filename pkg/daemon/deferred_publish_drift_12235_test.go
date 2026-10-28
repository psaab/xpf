package daemon

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"golang.org/x/sync/semaphore"
)

const (
	deferredDriftHost12235 = "deferred-drift-12235"
	deferredDriftText12235 = "system { host-name " + deferredDriftHost12235 + "; }"
)

func deferredDriftDaemon12235(t *testing.T) (*Daemon, *runtimeOnlyApplyTestDP) {
	t.Helper()
	dp := &runtimeOnlyApplyTestDP{applyResult: &dataplane.ApplyResult{SnapshotPublishDeferred: true}}
	d, _ := reinjectProductionHarness9637(t, dp)
	d.applySem = semaphore.NewWeighted(1)
	return d, dp
}

func deferredDriftHAPush12235(t *testing.T, d *Daemon) <-chan error {
	t.Helper()
	err := d.handleConfigSync(deferredDriftText12235)
	var pending *cluster.ConfigApplyPendingError
	if !errors.As(err, &pending) || pending.Completion == nil {
		t.Fatalf("handleConfigSync = %v, want a ConfigApplyPendingError with a completion", err)
	}
	if d.store.ActiveApplied() {
		t.Fatal("deferred HA apply stamped the active digest before publication")
	}
	return pending.Completion
}

func deferredDriftAwait12235(t *testing.T, c <-chan error) (error, bool) {
	t.Helper()
	select {
	case err := <-c:
		return err, true
	case <-time.After(2 * time.Second):
		return nil, false
	}
}

func TestDeferredExactGenerationResolves12235(t *testing.T) {
	d, dp := deferredDriftDaemon12235(t)
	c := deferredDriftHAPush12235(t, d)
	d.policyInvalidationSnapshotPublished(dp.lastApply.Generation)
	if err, ok := deferredDriftAwait12235(t, c); !ok || err != nil {
		t.Fatalf("exact-generation completion = (%v, resolved=%v), want (nil, true)", err, ok)
	}
	if !d.store.ActiveApplied() {
		t.Fatal("published control generation did not stamp the applied marker")
	}
}

func TestDeferredLandingAtLaterGenerationResolves12235(t *testing.T) {
	d, dp := deferredDriftDaemon12235(t)
	c := deferredDriftHAPush12235(t, d)
	landed := dp.lastApply.Generation + 1
	for range 3 {
		d.policyInvalidationSnapshotPublished(landed)
	}
	if err, ok := deferredDriftAwait12235(t, c); !ok {
		t.Fatalf("deferred generation %d landed at %d but HA completion did not resolve", dp.lastApply.Generation, landed)
	} else if err != nil {
		t.Fatalf("landed snapshot resolved with %v", err)
	}
}

func TestDeferredRefusalAtLaterGenerationSurfaces12235(t *testing.T) {
	d, dp := deferredDriftDaemon12235(t)
	c := deferredDriftHAPush12235(t, d)
	refusal := errors.New("helper rejected deferred publish")
	generation := dp.lastApply.Generation + 1
	d.rejectDeferredSnapshotPublish(generation, refusal)
	if err, ok := deferredDriftAwait12235(t, c); !ok {
		t.Fatalf("refusal at drifted generation %d was not surfaced (recorded %d)", generation, dp.lastApply.Generation)
	} else if !errors.Is(err, refusal) {
		t.Fatalf("completion = %v, want refusal", err)
	}
}

func TestDeferredRefusedThenRedeferredSameConfigResolves12235(t *testing.T) {
	for _, tc := range []struct {
		name   string
		settle func(d *Daemon, gen uint64)
	}{
		{"second-publish-lands", func(d *Daemon, gen uint64) { d.policyInvalidationSnapshotPublished(gen) }},
		{"second-publish-refused", func(d *Daemon, gen uint64) {
			d.rejectDeferredSnapshotPublish(gen, errors.New("refused again"))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, dp := deferredDriftDaemon12235(t)
			c1 := deferredDriftHAPush12235(t, d)
			g1 := dp.lastApply.Generation
			refusal := errors.New("helper rejected deferred publish")
			d.rejectDeferredSnapshotPublish(g1, refusal)
			if err, ok := deferredDriftAwait12235(t, c1); !ok || !errors.Is(err, refusal) {
				t.Fatalf("first refusal = (%v, %v), want surfaced refusal", err, ok)
			}
			c2 := deferredDriftHAPush12235(t, d)
			g2 := dp.lastApply.Generation
			tc.settle(d, g2)
			if err, ok := deferredDriftAwait12235(t, c2); !ok {
				t.Fatalf("re-push completion at generation %d did not resolve", g2)
			} else if tc.name == "second-publish-lands" && err != nil {
				t.Fatalf("re-push publication completed with %v", err)
			} else if tc.name == "second-publish-refused" && err == nil {
				t.Fatal("second refusal was not surfaced to HA")
			}
		})
	}
}

type deferredDriftRouteLeakDP12235 struct {
	*runtimeOnlyApplyTestDP
	d         *Daemon
	published []uint64
}

func (p *deferredDriftRouteLeakDP12235) PublishRouteOverlaySnapshotWithLatch(
	*config.Config, []config.RouteOverlayEntry, map[string]bool, bool,
) (bool, error) {
	g := p.lastApply.Generation + 1
	p.published = append(p.published, g)
	p.d.policyInvalidationSnapshotPublished(g)
	return true, nil
}

func (p *deferredDriftRouteLeakDP12235) BumpFIBGeneration() (uint32, error) { return 1, nil }

func TestRouteLeakTailResolvesDeferredHACompletion12235(t *testing.T) {
	inner := &runtimeOnlyApplyTestDP{applyResult: &dataplane.ApplyResult{SnapshotPublishDeferred: true}}
	dp := &deferredDriftRouteLeakDP12235{runtimeOnlyApplyTestDP: inner}
	d, _ := reinjectProductionHarness9637(t, inner)
	d.setDataplane(dp)
	dp.d = d
	d.applySem = semaphore.NewWeighted(1)
	applyErr := d.handleConfigSync(deferredDriftText12235)
	var pending *cluster.ConfigApplyPendingError
	if !errors.As(applyErr, &pending) || pending.Completion == nil {
		t.Fatalf("handleConfigSync = %v, want pending publication with completion", applyErr)
	}
	c := pending.Completion
	if len(dp.published) == 0 {
		t.Fatal("route-leak tail did not run")
	}
	settled := inner.lastApply.Generation + 2
	for range 3 {
		d.policyInvalidationSnapshotPublished(settled)
	}
	if err, ok := deferredDriftAwait12235(t, c); !ok {
		t.Fatalf("route-leak tail published %v and status settled %d, but HA completion did not resolve", dp.published, settled)
	} else if err != nil {
		t.Fatalf("route-leak-tail publication completed with %v", err)
	}
}

func TestBackgroundDeferredApplyKeepsMarkerPending12235(t *testing.T) {
	d, _ := deferredDriftDaemon12235(t)
	if _, err := d.store.SyncApply(deferredDriftText12235, nil); err != nil {
		t.Fatalf("promote active config: %v", err)
	}
	d.store.MarkActiveApplied()
	if !d.store.ActiveApplied() {
		t.Fatal("test setup did not mark the active config applied")
	}
	if err := d.applyActiveConfigResult(); err != nil {
		t.Fatalf("applyActiveConfigResult: %v", err)
	}
	if d.store.ActiveApplied() {
		t.Fatal("background deferred apply marked its config applied before publication")
	}
}

func TestDeferredPublishFailureCallbackIsWired12235(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "daemon_apply_dataplane.go", nil, 0)
	if err != nil {
		t.Fatalf("parse daemon_apply_dataplane.go: %v", err)
	}
	found := false
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "applyDataplaneAndHACore" || fn.Body == nil {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) != 1 {
				return true
			}
			receiver, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || receiver.Sel.Name != "SetPolicySnapshotPublishFailure" {
				return true
			}
			callback, ok := call.Args[0].(*ast.SelectorExpr)
			if ok && callback.Sel.Name == "rejectDeferredSnapshotPublish" {
				if daemon, ok := callback.X.(*ast.Ident); ok && daemon.Name == "d" {
					found = true
				}
			}
			return true
		})
	}
	if !found {
		t.Fatal("applyDataplaneAndHACore does not wire the manager's in-band publish-refusal callback to the daemon")
	}
}

func TestCommittedDeferredApplyKeepsMarkerPending12235(t *testing.T) {
	d, _ := deferredDriftDaemon12235(t)
	cfg, err := d.store.SyncApply(deferredDriftText12235, nil)
	if err != nil {
		t.Fatalf("promote active config: %v", err)
	}
	d.store.MarkActiveApplied()
	if err := d.applySem.Acquire(t.Context(), 1); err != nil {
		t.Fatalf("acquire apply semaphore: %v", err)
	}
	_, applyErr := d.applyAndSyncCommittedForTest(cfg, cfg, peerSyncNever)
	d.applySem.Release(1)
	if applyErr != nil {
		t.Fatalf("applyAndSyncCommitted: %v", applyErr)
	}
	if d.store.ActiveApplied() {
		t.Fatal("commit path marked a deferred config applied before publication")
	}
}

// A background apply arms no invalidation plan, so it leaves no debt. When
// its publish defers and its tail fails, retiring the deferred record is the
// only thing that keeps the later publication from stamping it applied.
func TestBackgroundDeferredFailedTailNeverStamped12235(t *testing.T) {
	d, dp := deferredDriftDaemon12235(t)
	injected := errors.New("background deferred apply tail failure")
	d.reconcileDNSFn = func(cfg *config.Config, _ bool) error {
		if cfg != nil && cfg.System.HostName == deferredDriftHost12235 {
			return injected
		}
		return nil
	}
	if _, err := d.store.SyncApply(deferredDriftText12235, nil); err != nil {
		t.Fatalf("promote active config: %v", err)
	}
	if err := d.applyActiveConfigResult(); !errors.Is(err, injected) {
		t.Fatalf("premise: background apply = %v, want the tail failure", err)
	}
	if d.policyInvalidationDebt != nil || !dp.lastApply.SnapshotPublishDeferred {
		t.Fatalf("premise: want no debt and a deferred publish (debt=%v deferred=%v)",
			d.policyInvalidationDebt != nil, dp.lastApply.SnapshotPublishDeferred)
	}
	d.policyInvalidationSnapshotPublished(dp.lastApply.Generation + 1)
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if d.store.ActiveApplied() {
			t.Fatal("background deferred apply whose tail failed was stamped applied by its later publication")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A background deferral has no debt, so only its record's generation gate
// admits the status callback. A landing the manager reports at a newer
// generation must still settle the record and stamp the applied marker.
func TestBackgroundDeferredLandingAtLaterGenerationStamps12235(t *testing.T) {
	d, dp := deferredDriftDaemon12235(t)
	if _, err := d.store.SyncApply(deferredDriftText12235, nil); err != nil {
		t.Fatalf("promote active config: %v", err)
	}
	if err := d.applyActiveConfigResult(); err != nil {
		t.Fatalf("applyActiveConfigResult: %v", err)
	}
	deferredAt := dp.lastApply.Generation
	c := d.deferredSnapshotCompletion(deferredAt)
	if d.policyInvalidationDebt != nil || c == nil || d.store.ActiveApplied() {
		t.Fatalf("premise: want an unapplied deferral without debt (debt=%v completion=%v applied=%v)",
			d.policyInvalidationDebt != nil, c != nil, d.store.ActiveApplied())
	}
	landed := deferredAt + 1
	d.policyInvalidationSnapshotPublished(landed)
	if err, ok := deferredDriftAwait12235(t, c); !ok {
		t.Fatalf("background deferral at %d landed at %d but never settled", deferredAt, landed)
	} else if err != nil {
		t.Fatalf("background deferral landing resolved %v", err)
	}
	if !d.store.ActiveApplied() {
		t.Fatalf("background deferral landed at %d without stamping the applied marker", landed)
	}
}

// commitOtherConfigWhilePeerDeferred12235 leaves peer config A waiting for
// its deferred publication, then promotes a different config B and applies
// it through the commit path, publishing synchronously at a newer
// generation. On an RG0 secondary the store rejects local commits; only the
// commit-confirmed timeout revert can promote B there, and it runs the same
// applyConfigLocked tail.
func commitOtherConfigWhilePeerDeferred12235(t *testing.T, failTail bool) (*Daemon, <-chan error, uint64, uint64) {
	t.Helper()
	d, dp := deferredDriftDaemon12235(t)
	c := deferredDriftHAPush12235(t, d)
	g1 := dp.lastApply.Generation
	cfgA := d.store.ActiveConfig()
	dp.applyResult = &dataplane.ApplyResult{}
	injected := errors.New("config B apply tail failure")
	d.reconcileDNSFn = func(cfg *config.Config, _ bool) error {
		if failTail && cfg != nil && cfg.System.HostName == "local-b-12235" {
			return injected
		}
		return nil
	}
	cfgB, err := d.store.SyncApply("system { host-name local-b-12235; }", nil)
	if err != nil {
		t.Fatalf("promote config B: %v", err)
	}
	if err := d.applySem.Acquire(t.Context(), 1); err != nil {
		t.Fatalf("acquire apply semaphore: %v", err)
	}
	_, commitErr := d.applyAndSyncCommittedForTest(cfgA, cfgB, peerSyncNever)
	d.applySem.Release(1)
	if failTail != errors.Is(commitErr, injected) {
		t.Fatalf("premise: config B commit = %v, want tail failure %v", commitErr, failTail)
	}
	g2 := dp.lastApply.Generation
	if g2 <= g1 || dp.lastApply.SnapshotPublishDeferred {
		t.Fatalf("premise: config B did not publish synchronously above A (g1=%d g2=%d)", g1, g2)
	}
	return d, c, g1, g2
}

// B's successful apply tail settles A as superseded itself, without
// waiting for a status-loop callback.
func TestDeferredPeerConfigSupersededBySuccessfulCommit12235(t *testing.T) {
	_, c, g1, g2 := commitOtherConfigWhilePeerDeferred12235(t, false)
	select {
	case err := <-c:
		if !errors.Is(err, errDeferredSnapshotSuperseded) {
			t.Fatalf("peer config deferred at %d resolved %v after config B published at %d, want superseded",
				g1, err, g2)
		}
	default:
		t.Fatalf("peer config deferred at %d still waits after config B published at %d and its tail succeeded",
			g1, g2)
	}
}

// A failed tail skips that settlement, so the status callback for B's
// generation reaches A's record. A newer generation proves only that some
// snapshot landed; the helper enforces B, so A must be superseded, never
// acknowledged.
func TestDeferredPeerConfigNotAckedAfterFailedTailCommit12235(t *testing.T) {
	d, c, g1, g2 := commitOtherConfigWhilePeerDeferred12235(t, true)
	d.policyInvalidationSnapshotPublished(g2)
	err, ok := deferredDriftAwait12235(t, c)
	if !ok {
		t.Fatalf("peer config deferred at %d did not resolve after config B published at %d", g1, g2)
	}
	if !errors.Is(err, errDeferredSnapshotSuperseded) {
		t.Fatalf("peer config deferred at %d resolved %v after config B published at %d and failed its tail, want superseded",
			g1, err, g2)
	}
}

// A deferred peer config whose session invalidation is only partial after
// publication must NACK the waiting HA apply instead of leaving it to the
// apply-grace timeout.
func TestDeferredPartialInvalidationAfterPublishNacks12235(t *testing.T) {
	store, peerText, webID := newSyncReadyStore(t)
	d, _ := deferredDriftDaemon12235(t)
	d.store = store
	webSession := dataplane.SessionKey{
		SrcIP: [4]byte{10, 0, 0, 1}, DstIP: [4]byte{10, 0, 0, 2},
		SrcPort: 40001, DstPort: 80, Protocol: 6,
	}
	otherSession := dataplane.SessionKey{
		SrcIP: [4]byte{10, 0, 0, 9}, DstIP: [4]byte{10, 0, 0, 2},
		SrcPort: 40009, DstPort: 80, Protocol: 6,
	}
	inner := &invalDebtTestDP12073{
		script:          []invalDebtOutcome12073{{deferred: true}},
		relabelPolicyID: webID,
		v4: map[dataplane.SessionKey]dataplane.SessionValue{
			webSession:   {State: dataplane.SessStateEstablished, PolicyID: webID},
			otherSession: {State: dataplane.SessStateEstablished, PolicyID: webID},
		},
		v6: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{},
	}
	deleteErr := errors.New("partial v4 batch delete")
	d.setDataplane(&partialDeleteDP12301{
		invalDebtTestDP12073: inner,
		failV4Once:           true,
		deleteErr:            deleteErr,
	})
	syncErr := d.handleConfigSync(peerText)
	var pending *cluster.ConfigApplyPendingError
	if !errors.As(syncErr, &pending) || pending.Completion == nil {
		t.Fatalf("handleConfigSync = %v, want a pending publication with a completion", syncErr)
	}
	d.policyInvalidationSnapshotPublished(inner.lastApply.Generation)
	err, ok := deferredDriftAwait12235(t, pending.Completion)
	if !ok {
		t.Fatal("partial session invalidation after publication left the HA apply waiting")
	}
	if !errors.Is(err, deleteErr) {
		t.Fatalf("HA completion = %v, want the partial invalidation error", err)
	}
	if got := len(inner.v4); got != 1 {
		t.Fatalf("premise: %d deleted-policy sessions remain after the failed batch, want 1", got)
	}
	if d.store.ActiveApplied() {
		t.Fatal("partially invalidated peer config was stamped applied")
	}
}

// deferredScanFailureLanding12235 leaves a deferred commit of C1 whose
// status-loop prepublish READ was incomplete, so the post-publication
// discharge keeps the scan-failure debt. Master's #12072/#12323 invariant is
// that the applied marker stays withheld while that debt is outstanding.
func deferredScanFailureLanding12235(t *testing.T) (*convergenceRun12072, uint64) {
	t.Helper()
	r, _ := newConvergenceRun12072(t, []string{"p-first", "a", "b", "web"})
	c0, err := r.h.d.store.SyncApply(policySetFullClearConfigText12072(
		"dfr-c0", []string{"p-first", "a", "b", "web"}), nil)
	if err != nil {
		t.Fatalf("promote C0: %v", err)
	}
	r.h.d.store.MarkActiveApplied()
	c1, err := r.h.d.store.SyncApply(policySetFullClearConfigText12072(
		"dfr-c1", []string{"p-first", "b", "web"}), nil)
	if err != nil {
		t.Fatalf("promote C1: %v", err)
	}
	r.dp.applied, r.dp.helperCfg = c0, c0
	ids := dpuserspace.PolicyIDsByStableKey(c0)
	for i := range r.dp.rows {
		row := &r.dp.rows[i]
		row.PolicyID = ids[r.dp.ruleBySession[row.ExpectedRTFlowSessionID]]
	}
	r.h.dp.script = []invalDebtOutcome12073{{deferred: true}}
	if err := r.h.d.applySem.Acquire(t.Context(), 1); err != nil {
		t.Fatalf("acquire apply semaphore: %v", err)
	}
	_, applyErr := r.h.d.applyAndSyncCommittedForTest(c0, c1, peerSyncNever)
	r.h.d.applySem.Release(1)
	if applyErr != nil {
		t.Fatalf("deferred commit: %v", applyErr)
	}
	if r.h.d.store.ActiveApplied() {
		t.Fatal("premise: deferred commit marked C1 applied before publication")
	}
	debt := r.h.d.policyInvalidationDebt
	if debt == nil || debt.newCfg != c1 || debt.scanFailure != nil {
		t.Fatalf("premise: deferred commit debt = %+v, want clean C1 debt", debt)
	}
	gen := r.h.dp.lastApply.Generation
	// The status loop's candidate refresh just before the deferred publish
	// reads an incomplete session set.
	r.dp.incompleteNext = 1
	if err := r.h.d.capturePolicyInvalidationBeforeDeferredPublish(gen); err != nil {
		t.Fatalf("prepublish capture: %v", err)
	}
	if debt := r.h.d.policyInvalidationDebt; debt == nil || debt.scanFailure == nil {
		t.Fatalf("premise: incomplete prepublish READ did not retain scan debt: %+v", debt)
	}
	r.dp.applied, r.dp.helperCfg = c1, c1
	return r, gen
}

// Each dischargePolicyInvalidationAfterPublish call is one status-loop tick:
// the manager re-fires the committer on every settled tick, and the callback
// starts the worker because the debt is owed.
func TestDeferredLandingWithScanFailureDebtKeepsMarkerPending12235(t *testing.T) {
	r, gen := deferredScanFailureLanding12235(t)
	for tick := 1; tick <= 3; tick++ {
		r.h.d.dischargePolicyInvalidationAfterPublish(gen)
		debt := r.h.d.policyInvalidationDebt
		if debt == nil || debt.scanFailure == nil {
			t.Fatalf("tick %d: scan-failure debt was lost: %+v", tick, debt)
		}
		if r.h.d.store.ActiveApplied() {
			t.Fatalf("tick %d: the deferred landing certified C1 applied while its scan-failure debt is outstanding", tick)
		}
	}
}

// While that debt is outstanding the #4957 config-sync shortcut must stay off,
// so a peer re-push of the same config re-enters the apply instead of being
// acknowledged as converged.
func TestDeferredScanFailureKeepsConfigSyncShortcutOff12235(t *testing.T) {
	r, gen := deferredScanFailureLanding12235(t)
	for range 2 {
		r.h.d.dischargePolicyInvalidationAfterPublish(gen)
	}
	if debt := r.h.d.policyInvalidationDebt; debt == nil || debt.scanFailure == nil {
		t.Fatalf("premise: scan-failure debt not outstanding: %+v", debt)
	}
	// Standalone receiver: no RG0-primary refusal and no cluster-topology
	// preflight, so only the #4957 shortcut can skip the apply.
	r.h.d.cluster = nil
	attempts := r.dp.applyAttempts
	err := r.h.d.handleConfigSync(r.h.d.store.ShowActive())
	if r.dp.applyAttempts == attempts {
		t.Fatalf("re-push of the config with outstanding scan-failure debt took the #4957 converged shortcut (err=%v applied=%v)",
			err, r.h.d.store.ActiveApplied())
	}
}
