package daemon

import (
	"context"
	"errors"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

type failedTailCatchupDP12641 struct {
	*invalDebtTestDP12073
	applied *config.Config
}

func (d *failedTailCatchupDP12641) AppliedConfig() *config.Config { return d.applied }

func (d *failedTailCatchupDP12641) ApplyConfig(ctx context.Context, cfg *config.Config) (*dataplane.ApplyResult, error) {
	result, err := d.invalDebtTestDP12073.ApplyConfig(ctx, cfg)
	if err == nil && (result == nil || !result.SnapshotPublishDeferred) {
		d.applied = cfg
	}
	return result, err
}

func newFailedTailRun12641(t *testing.T) (*invalDebtHarness12073, *failedTailCatchupDP12641) {
	t.Helper()
	h := newInvalDebtHarness12073(t, []invalDebtOutcome12073{{deferred: true}})

	oldCfg, err := h.d.store.SyncApply(
		policySetConfigText12072("tail-c0-12641", []string{"p-first", "p-web", "p-ssh"}), nil)
	if err != nil {
		t.Fatalf("promote old config: %v", err)
	}
	h.d.store.MarkActiveApplied()
	newCfg, err := h.d.store.SyncApply(
		policySetConfigText12072("tail-c1-12641", []string{"p-first", "p-ssh"}), nil)
	if err != nil {
		t.Fatalf("promote target config: %v", err)
	}
	h.oldCfg, h.newCfg = oldCfg, newCfg
	dp := &failedTailCatchupDP12641{invalDebtTestDP12073: h.dp, applied: oldCfg}
	h.d.setDataplane(dp)
	return h, dp
}

// TestR50BaseFailedTailDeferredNeverStamped reproduces the peer-sync failure
// that #12072's catch-up must not convert into a successful apply marker. The
// dataplane defers publication, then the full apply fails in its tail. That
// failure NACKs the peer config; when status later reports the snapshot landed,
// the catch-up must not certify the partially converged config as applied.
func TestR50BaseFailedTailDeferredNeverStamped(t *testing.T) {
	h, dp := newFailedTailRun12641(t)
	injected := errors.New("host-inbound tail reconcile failed")
	h.d.reconcileDNSFn = func(*config.Config, bool) error { return injected }

	if err := h.commit(h.oldCfg, h.newCfg); !errors.Is(err, injected) {
		t.Fatalf("premise: peer apply error = %v, want tail failure %v", err, injected)
	}
	debt := h.d.policyInvalidationDebt
	if debt == nil || debt.appliedDigest != "" || !debt.tailFailed {
		t.Fatalf("premise: failed-tail deferred apply must retain flagged, unstamped debt: %+v", debt)
	}
	generation := h.dp.lastApply.Generation
	if generation == 0 || !h.dp.lastApply.SnapshotPublishDeferred {
		t.Fatalf("premise: dataplane did not defer snapshot publication: %+v", h.dp.lastApply)
	}
	// The status loop refreshes candidates before publishing. That recapture
	// replaces the debt record and must carry the failed-tail state forward.
	if err := h.d.capturePolicyInvalidationBeforeDeferredPublish(generation); err != nil {
		t.Fatalf("status-loop pre-publish capture: %v", err)
	}
	if debt := h.d.policyInvalidationDebt; debt == nil || !debt.tailFailed {
		t.Fatalf("status-loop recapture lost failed-tail state: %+v", debt)
	}
	// The status-loop confirms the exact helper target after the failed apply.
	// Its successful publication is not proof that the omitted tail converged.
	dp.applied = h.newCfg
	h.dp.relabelDeletedPolicySessions()
	h.d.dischargePolicyInvalidationAfterPublish(generation)
	if h.d.store.ActiveApplied() {
		t.Fatal("failed-tail deferred apply was stamped applied by status catch-up; a peer re-push would take the #4957 shortcut")
	}
}

func TestLostResponseDeferredCatchupStillStamps12641(t *testing.T) {
	h, dp := newFailedTailRun12641(t)
	if err := h.commit(h.oldCfg, h.newCfg); err != nil {
		t.Fatalf("successful deferred peer apply: %v", err)
	}
	debt := h.d.policyInvalidationDebt
	if debt == nil || debt.tailFailed || debt.appliedDigest == "" {
		t.Fatalf("premise: successful deferred apply debt = %+v", debt)
	}
	generation := h.dp.lastApply.Generation
	// Exercise #12072's lost-response case, where the apply result was not
	// retained on the debt but the status loop confirms this exact target.
	debt.appliedDigest = ""
	dp.applied = h.newCfg
	h.d.dischargePolicyInvalidationAfterPublish(generation)
	if !h.d.store.ActiveApplied() {
		t.Fatal("successful deferred apply with a lost response was not stamped by catch-up")
	}
}
func TestSameTargetRetryClearsFailedTail12641(t *testing.T) {

	h, _ := newFailedTailRun12641(t)
	injected := errors.New("host-inbound tail reconcile failed")
	h.d.reconcileDNSFn = func(*config.Config, bool) error { return injected }
	if err := h.commit(h.oldCfg, h.newCfg); !errors.Is(err, injected) {
		t.Fatalf("premise: peer apply error = %v, want tail failure %v", err, injected)
	}
	if debt := h.d.policyInvalidationDebt; debt == nil || !debt.tailFailed {
		t.Fatalf("premise: failed deferred tail was not retained: %+v", debt)
	}

	h.d.reconcileDNSFn = nil
	if err := h.d.applySem.Acquire(t.Context(), 1); err != nil {
		t.Fatalf("acquire apply semaphore: %v", err)
	}
	err := h.d.applyConfigLocked(context.Background(), h.newCfg)
	h.d.applySem.Release(1)
	if err != nil {
		t.Fatalf("same-target retry: %v", err)
	}
	if debt := h.d.policyInvalidationDebt; debt != nil {
		t.Fatalf("successful same-target retry left policy debt: %+v", debt)
	}
	if !h.d.store.ActiveApplied() {
		t.Fatal("successful same-target retry did not stamp the active config")
	}
}
func TestCatchupDoesNotStampMismatchedActiveConfig12641(t *testing.T) {
	h, dp := newFailedTailRun12641(t)
	if err := h.commit(h.oldCfg, h.newCfg); err != nil {
		t.Fatalf("successful deferred peer apply: %v", err)
	}
	debt := h.d.policyInvalidationDebt
	if debt == nil || debt.tailFailed {
		t.Fatalf("premise: successful deferred apply debt = %+v", debt)
	}
	generation := h.dp.lastApply.Generation
	debt.appliedDigest = ""
	dp.applied = h.newCfg
	if _, err := h.d.store.SyncApply("system { host-name superseding-target-12641; }", nil); err != nil {
		t.Fatalf("promote superseding active config: %v", err)
	}
	h.d.dischargePolicyInvalidationAfterPublish(generation)
	if h.d.store.ActiveApplied() {
		t.Fatal("catch-up stamped the superseding active config using the deferred target's successful publication")
	}
	if h.d.policyInvalidationDebt != debt {
		t.Fatalf("mismatched catch-up consumed target debt: before=%p after=%p", debt, h.d.policyInvalidationDebt)
	}
}
