package daemon

// #15056 (A32-03): the #9615 refused-target rollback branch promoted the
// store to the target and entered bootstrap — which relinquishes the cluster
// (#6742) — without the #3868 peer re-sync the ordinary rollback runs. The
// standby, which received the abandoned unconfirmed config (C2) via
// config-sync SyncApply with no confirm timer, therefore kept C2 as its
// permanent active and would serve it after a failover, with no timer or
// alarm on the serving node.
//
// These cells pin the fix: the refused branch re-syncs the promoted target
// to the peer BEFORE enterBootstrapMode stops cluster comms.

import (
	"strings"
	"sync"
	"testing"
)

// TestRefusedRollbackTargetResyncsPeerBeforeBootstrap_15056 is the defect
// cell. It arms a window over the refused target (reusing the #9615 harness),
// records the peer-push seam, and asserts the push fired exactly once, with
// the promoted rollback target — not the abandoned config — and strictly
// before the daemon entered bootstrap.
//
// RED on current master: the refused branch never calls
// resyncRolledBackConfigToPeer/pushCommittedConfigToPeer, so calls==0.
func TestRefusedRollbackTargetResyncsPeerBeforeBootstrap_15056(t *testing.T) {
	h := newDaemon9615(t)
	armWindowOver9615(t, h.s, refusedTarget9615)

	var mu sync.Mutex
	var order []string
	var syncedConfig string
	h.d.syncPeerForTest = func() {
		mu.Lock()
		defer mu.Unlock()
		order = append(order, "push")
		syncedConfig = h.d.store.ShowActive()
		// The push must happen while the node can still push: not yet in
		// bootstrap (cluster not yet relinquished).
		if h.d.inBootstrap() {
			order = append(order, "push-after-bootstrap")
		}
	}

	h.s.InvokeRollbackTimerForTesting(h.s.ConfirmGenForTesting())

	mu.Lock()
	gotOrder := append([]string(nil), order...)
	gotSynced := syncedConfig
	mu.Unlock()

	if len(gotOrder) != 1 || gotOrder[0] != "push" {
		t.Fatalf("the refused-target rollback must re-sync the promoted target to the peer "+
			"exactly once, before bootstrap entry; got events %v (the standby would keep the "+
			"abandoned unconfirmed config as its permanent active — #15056)", gotOrder)
	}
	if !strings.Contains(gotSynced, "refused-target") {
		t.Fatalf("peer re-sync pushed the wrong config; want the promoted rollback target "+
			"(host-name refused-target), got:\n%s", gotSynced)
	}
	if strings.Contains(gotSynced, "host-name abandoned") {
		t.Fatalf("peer re-sync pushed the abandoned unconfirmed config — it ran before "+
			"PromoteRollback:\n%s", gotSynced)
	}
	if !h.d.inBootstrap() {
		t.Fatal("the refused-target rollback must still enter the bootstrap safe state")
	}
	if len(h.applied) != 0 {
		t.Fatalf("a refused rollback target must not be applied locally: %v", h.applied)
	}
	if got := hostName9615(h.s); got != "refused-target" {
		t.Fatalf("the store must still revert to the target, got %q", got)
	}
}

// TestRefusedRollbackTargetResyncPeerAbsent_15056 is the peer-absent control:
// with no test seam the real push path runs and must no-op cleanly (nil
// cluster/sessionSync) while the local safe state is still taken. A fix that
// panicked or blocked without a peer would fail here.
func TestRefusedRollbackTargetResyncPeerAbsent_15056(t *testing.T) {
	h := newDaemon9615(t)
	armWindowOver9615(t, h.s, refusedTarget9615)

	// No syncPeerForTest seam: exercises the real pushCommittedConfigToPeer
	// nil-guards.
	h.s.InvokeRollbackTimerForTesting(h.s.ConfirmGenForTesting())

	if !h.d.inBootstrap() {
		t.Fatal("peer-absent refused rollback must still enter the bootstrap safe state")
	}
	if got := hostName9615(h.s); got != "refused-target" {
		t.Fatalf("peer-absent refused rollback must still revert the store, got %q", got)
	}
}

// TestHealthyRollbackTargetResyncUnchanged_15056 is the adjacent control:
// the ordinary appliable rollback already re-syncs via
// executeConfirmedRollback's #3868 call. Routing the refused branch through
// the same helper must not double-push the healthy path — it returns false
// from confirmRollbackTargetHandledAtFire, so only the ordinary call fires.
func TestHealthyRollbackTargetResyncUnchanged_15056(t *testing.T) {
	h := newDaemon9615(t)
	armWindowOver9615(t, h.s, healthyTarget9615)

	calls := 0
	h.d.syncPeerForTest = func() { calls++ }

	h.s.InvokeRollbackTimerForTesting(h.s.ConfirmGenForTesting())

	if calls != 1 {
		t.Fatalf("a healthy rollback must re-sync the peer exactly once (the ordinary "+
			"#3868 call, not a second push from the refused branch); got %d", calls)
	}
	if h.d.inBootstrap() {
		t.Fatal("a healthy target must not enter the bootstrap safe state")
	}
	if len(h.applied) != 1 || h.applied[0] != "healthy-target" {
		t.Fatalf("a healthy target must be applied once, got %v", h.applied)
	}
}
