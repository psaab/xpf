package daemon

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

type publishedTailApplyDP12301 struct {
	*invalDebtTestDP12073
	tailErr     error
	applyResult *dataplane.ApplyResult
}

func (d *publishedTailApplyDP12301) ApplyConfig(ctx context.Context, cfg *config.Config) (*dataplane.ApplyResult, error) {
	result, err := d.invalDebtTestDP12073.ApplyConfig(ctx, cfg)
	d.applyResult = result
	if err != nil {
		return result, err
	}
	return result, d.tailErr
}

type partialDeleteDP12301 struct {
	*invalDebtTestDP12073
	failV4Once bool
	deleteErr  error
}

func (d *partialDeleteDP12301) Sessions() dataplane.SessionStore {
	return dataplane.NewDataPlaneSessionStore(d)
}

func (d *partialDeleteDP12301) BatchDeleteSessions(keys []dataplane.SessionKey) (int, error) {
	if d.failV4Once {
		d.failV4Once = false
		if len(keys) > 0 {
			deleted, _ := d.invalDebtTestDP12073.BatchDeleteSessions(keys[:1])
			return deleted, d.deleteErr
		}
		return 0, d.deleteErr
	}
	return d.invalDebtTestDP12073.BatchDeleteSessions(keys)
}

func (d *partialDeleteDP12301) BatchDeleteSessionsV6(keys []dataplane.SessionKeyV6) (int, error) {
	return d.invalDebtTestDP12073.BatchDeleteSessionsV6(keys)
}

// A post-publish manager error carries a non-nil result because the new snapshot
// is already enforced. The commit must still invalidate sessions while returning
// the tail error to its operator.
func TestInvalidationDebtPublishedTailErrorLands12301(t *testing.T) {
	h := newInvalDebtHarness12073(t, nil)
	tailErr := fmt.Errorf("wrapped tail: %w", &dpuserspace.PublishedSnapshotTailError{})
	dp := &publishedTailApplyDP12301{invalDebtTestDP12073: h.dp, tailErr: tailErr}
	h.d.setDataplane(dp)

	err := h.commit(h.oldCfg, h.newCfg)
	if err == nil || !errors.Is(err, tailErr) {
		t.Fatalf("commit error = %v, want the published-tail error to remain visible", err)
	}
	if dp.applyResult == nil {
		t.Fatal("premise: tail error must accompany a non-nil enforced result")
	}
	if got := h.localDeleteCount(); got != 2 {
		t.Fatalf("published tail failure issued %d invalidation deletes, want 2", got)
	}
	if h.sessionsInstalled() {
		t.Fatal("published tail failure left deleted-policy sessions installed")
	}
}

// A status completion for C2 must not discharge merged C1→C3 debt after C3's
// publish failed. In C2, p-ssh remains permitted; deleting its C1 candidate is
// therefore a stale-generation discharge under the wrong enforcement.
func TestInvalidationDebtStaleGenerationCannotDischargeSupersedingTarget12301(t *testing.T) {
	transient := errors.New("C3 publish failed")
	h := newInvalDebtHarness12073(t, []invalDebtOutcome12073{{deferred: true}, {err: transient}})
	sshID := dpuserspace.PolicyIDsByStableKey(h.oldCfg)["trust->untrust/p-ssh"]
	sshSession := dataplane.SessionKey{
		SrcIP: [4]byte{10, 0, 0, 9}, DstIP: [4]byte{10, 0, 0, 2},
		SrcPort: 40009, DstPort: 22, Protocol: 6,
	}
	h.dp.v4[sshSession] = dataplane.SessionValue{State: dataplane.SessStateEstablished, PolicyID: sshID}
	oldGeneration := uint64(0)

	if err := h.commit(h.oldCfg, h.newCfg); err != nil {
		t.Fatalf("deferred C2 commit: %v", err)
	}
	oldGeneration = h.dp.lastApply.Generation
	c3 := twoPolicyConfig([]string{"p-first"}, nil)
	if err := h.commit(h.newCfg, c3); err == nil {
		t.Fatal("C3 publish failure must be returned")
	}

	h.d.dischargePolicyInvalidationAfterPublish(oldGeneration)
	if _, ok := h.dp.v4[sshSession]; !ok {
		t.Fatal("stale C2 completion discharged C1→C3 debt and deleted p-ssh under C2 enforcement")
	}
	if h.d.policyInvalidationDebt == nil {
		t.Fatal("stale completion consumed debt for an unpublished C3 target")
	}
}

// Partial delete failure must keep the original pre-publish candidates so a
// subsequent serialized discharge can retry the surviving row without a new
// timer or a post-publish re-enumeration.
func TestInvalidationDebtPartialDeleteRetainedAndRetried12301(t *testing.T) {
	h := newInvalDebtHarness12073(t, nil)
	sshSession := dataplane.SessionKey{
		SrcIP: [4]byte{10, 0, 0, 9}, DstIP: [4]byte{10, 0, 0, 2},
		SrcPort: 40009, DstPort: 22, Protocol: 6,
	}
	h.dp.v4[sshSession] = dataplane.SessionValue{State: dataplane.SessStateEstablished, PolicyID: h.webID}
	deleteErr := errors.New("partial v4 batch delete")
	dp := &partialDeleteDP12301{
		invalDebtTestDP12073: h.dp,
		failV4Once:           true,
		deleteErr:            deleteErr,
	}
	h.d.setDataplane(dp)

	if err := h.commit(h.oldCfg, h.newCfg); !errors.Is(err, deleteErr) {
		t.Fatalf("commit error = %v, want partial delete error", err)
	}
	if h.d.policyInvalidationDebt == nil {
		t.Fatal("partial delete failure dropped the invalidation debt")
	}
	if got := len(h.dp.v4); got != 1 {
		t.Fatalf("remaining target sessions after injected partial delete = %d, want 1", got)
	}

	if err := h.d.applySem.Acquire(context.Background(), 1); err != nil {
		t.Fatalf("acquire apply semaphore for retry: %v", err)
	}
	err := h.d.dischargePolicyInvalidationDebtLocked(h.oldCfg, h.newCfg)
	h.d.applySem.Release(1)
	if err != nil {
		t.Fatalf("retry debt discharge: %v", err)
	}
	if h.d.policyInvalidationDebt != nil {
		t.Fatal("successful retry retained discharged debt")
	}
	if got := len(h.dp.v4); got != 0 {
		t.Fatalf("target sessions after retry = %d, want 0", got)
	}
}

// The commit path withholds the applied marker while a deferred snapshot owes
// invalidation. The asynchronous landing/discharge must stamp the same active
// digest after the retained candidates have been cleared.
func TestInvalidationDebtAsyncDischargeStampsAppliedMarker12301(t *testing.T) {
	h := newInvalDebtHarness12073(t, []invalDebtOutcome12073{{deferred: true}})
	if _, err := h.d.store.SyncApply("system { host-name invalidation-debt-12301; }", nil); err != nil {
		t.Fatalf("promote target config: %v", err)
	}
	h.newCfg = h.d.store.ActiveConfig()
	if h.d.store.ActiveApplied() {
		t.Fatal("precondition: promoted config unexpectedly marked applied")
	}
	if err := h.commit(h.oldCfg, h.newCfg); err != nil {
		t.Fatalf("deferred commit: %v", err)
	}
	if h.d.policyInvalidationDebt == nil {
		t.Fatal("deferred snapshot must retain invalidation debt before landing")
	}

	generation := h.dp.lastApply.Generation
	if err := h.d.capturePolicyInvalidationBeforeDeferredPublish(generation); err != nil {
		t.Fatalf("pre-publish candidate refresh: %v", err)
	}
	h.dp.relabelDeletedPolicySessions()
	h.d.dischargePolicyInvalidationAfterPublish(generation)
	if h.d.policyInvalidationDebt != nil {
		t.Fatal("successful async discharge did not consume invalidation debt")
	}
	if !h.d.store.ActiveApplied() {
		t.Fatal("successful async debt discharge did not stamp the active config as applied")
	}
}
