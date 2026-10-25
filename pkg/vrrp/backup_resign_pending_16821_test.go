package vrrp

import (
	"testing"
	"time"

	"github.com/vishvananda/netlink"
)

// #16821 (R3-F08-04): the stepBackup resign arm consumed the resign
// token without clearing resignPending, so an already-BACKUP instance
// kept its pre-resign priority (contrary to the ResignRG doc, which
// promises the resigned instance keeps priority 0 until restored) and
// a later, unrelated step-down silently installed the stashed 0.
//
// Subject: ResignRG while already BACKUP -> stepBackup resign arm ->
// pending must be false and the effective priority 0 immediately;
// after a restore to 200 and a later MASTER tenure ending in an
// unrelated becomeBackup, the priority must stay 200.
//
// Control: no resign while BACKUP -> priority stays 200 throughout.
//
// RED on revert: drop applyPendingResign() from the stepBackup resign
// arm and the subject reads pending=true / priority 200 after the
// BACKUP resign, then 0 after the later step-down.

func cfgPriority16821(vi *vrrpInstance) int {
	vi.mu.RLock()
	defer vi.mu.RUnlock()
	return vi.cfg.Priority
}

// driveStepBackupResign runs one stepBackup iteration in a goroutine:
// the select blocks until the queued resign token is consumed.
func driveStepBackupResign(t *testing.T, vi *vrrpInstance) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		vi.stepBackup(time.NewTimer(time.Hour), time.NewTimer(time.Hour), time.NewTimer(time.Hour))
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("stepBackup did not consume the resign token")
	}
}

func TestBackupResignAppliesStashedPriority16821(t *testing.T) {
	m, vi := resignBarrierInstance(t, "xpf-16821-a0", func(*netlink.Addr) error { return nil })
	vi.setState(StateBackup)

	barrier := m.ResignRG(1)
	if !vi.resignIsPending() {
		t.Fatal("precondition: ResignRG must stash a pending resignation")
	}
	if got := vi.getPriority(); got != 200 {
		t.Fatalf("precondition: pending resign must keep pre-resign advert priority, got %d, want 200", got)
	}

	driveStepBackupResign(t, vi)
	waitBarrier(t, barrier, "already-BACKUP resign must resolve the barrier")
	if err := barrier.Err(); err != nil {
		t.Fatalf("barrier verdict = %v, want nil", err)
	}

	// The resignation is now actuated: pending cleared, priority 0.
	if vi.resignIsPending() {
		t.Fatal("resignPending still set after stepBackup consumed the resign token — " +
			"a later unrelated becomeBackup would silently install the stashed 0")
	}
	if got := cfgPriority16821(vi); got != 0 {
		t.Fatalf("cfg.Priority after BACKUP resign = %d, want 0 (ResignRG contract: resigned instance keeps 0 until restored)", got)
	}
	if got := vi.getPriority(); got != 0 {
		t.Fatalf("getPriority() after BACKUP resign = %d, want 0", got)
	}

	// Restore (the posture reconcile / cluster primary path), then a
	// later MASTER tenure ending in an unrelated step-down must NOT
	// resurrect the resolved resignation.
	m.UpdateRGPriority(1, 200)
	if got := vi.getPriority(); got != 200 {
		t.Fatalf("getPriority() after restore = %d, want 200", got)
	}
	vi.setState(StateMaster)
	vi.becomeBackup(time.NewTimer(time.Hour), time.NewTimer(time.Hour))
	if got := cfgPriority16821(vi); got != 200 {
		t.Fatalf("cfg.Priority after later unrelated step-down = %d, want 200 — stale resign stash leaked", got)
	}
	if got := vi.getPriority(); got != 200 {
		t.Fatalf("getPriority() after later unrelated step-down = %d, want 200", got)
	}
}

// TestBackupNoResignControl16821 is the positive control: without a
// resign while BACKUP, the same later step-down leaves priority 200.
func TestBackupNoResignControl16821(t *testing.T) {
	_, vi := resignBarrierInstance(t, "xpf-16821-b0", func(*netlink.Addr) error { return nil })
	vi.setState(StateBackup)

	if vi.resignIsPending() {
		t.Fatal("precondition: no resignation should be pending")
	}
	if got := vi.getPriority(); got != 200 {
		t.Fatalf("control priority = %d, want 200", got)
	}
	vi.setState(StateMaster)
	vi.becomeBackup(time.NewTimer(time.Hour), time.NewTimer(time.Hour))
	if got := cfgPriority16821(vi); got != 200 {
		t.Fatalf("control cfg.Priority after step-down = %d, want 200", got)
	}
}

// TestUpdateRGPrioritySupersedesPendingResign16821 pins the second
// acceptance leg: a restore that lands while the resign is still
// pending (run loop has not consumed the token) must drop the stash,
// so the token's later consumption cannot install 0 over the restore.
//
// RED on revert: remove discardPendingResign() from UpdateRGPriority
// and the post-restore priority reads 0 once the resign is consumed.
func TestUpdateRGPrioritySupersedesPendingResign16821(t *testing.T) {
	m, vi := resignBarrierInstance(t, "xpf-16821-c0", func(*netlink.Addr) error { return nil })
	vi.setState(StateBackup)

	m.ResignRG(1)
	if !vi.resignIsPending() {
		t.Fatal("precondition: ResignRG must stash a pending resignation")
	}
	m.UpdateRGPriority(1, 200)
	if vi.resignIsPending() {
		t.Fatal("UpdateRGPriority left resignPending set — a later becomeBackup would install the stale 0")
	}
	if got := vi.getPriority(); got != 200 {
		t.Fatalf("getPriority() after restore = %d, want 200", got)
	}

	// The queued token is still consumed (barrier resolves), but it
	// must not overwrite the restored priority.
	driveStepBackupResign(t, vi)
	if got := cfgPriority16821(vi); got != 200 {
		t.Fatalf("cfg.Priority after consuming superseded resign = %d, want 200", got)
	}
	if vi.resignIsPending() {
		t.Fatal("resignPending set after superseded resign was consumed")
	}
}

// TestUpdateConfigSupersedesPendingResign16821 pins the updateConfig
// leg: the debounced config path (driven by LocalPriorities on a
// cluster re-promotion) supersedes a pending resignation the same way.
//
// RED on revert: remove discardPendingResign() from updateConfigHeld
// and resignIsPending() stays true after the config restore.
func TestUpdateConfigSupersedesPendingResign16821(t *testing.T) {
	m, vi := resignBarrierInstance(t, "xpf-16821-d0", func(*netlink.Addr) error { return nil })
	vi.setState(StateBackup)

	m.ResignRG(1)
	if !vi.resignIsPending() {
		t.Fatal("precondition: ResignRG must stash a pending resignation")
	}
	vi.updateConfig(Instance{
		Interface:         "xpf-16821-d0",
		GroupID:           101,
		Priority:          200,
		AdvertiseInterval: 1000,
	})
	if vi.resignIsPending() {
		t.Fatal("updateConfig left resignPending set — a later becomeBackup would install the stale 0")
	}
	if got := vi.getPriority(); got != 200 {
		t.Fatalf("getPriority() after updateConfig restore = %d, want 200", got)
	}
	driveStepBackupResign(t, vi)
	if got := cfgPriority16821(vi); got != 200 {
		t.Fatalf("cfg.Priority after consuming superseded resign = %d, want 200", got)
	}
}

// TestMasterResignStillAppliesStash16821 guards the original A25-06
// MASTER path against the new clearing: a resign consumed from MASTER
// still ends at priority 0, and a restore-then-step-down stays 200.
func TestMasterResignStillAppliesStash16821(t *testing.T) {
	m, vi := resignBarrierInstance(t, "xpf-16821-e0", func(*netlink.Addr) error { return nil })
	vi.setState(StateMaster)

	barrier := m.ResignRG(1)
	if got := vi.getPriority(); got != 200 {
		t.Fatalf("routine advert priority while resign pending = %d, want 200 (A25-06)", got)
	}
	vi.becomeBackup(time.NewTimer(time.Hour), time.NewTimer(time.Hour))
	waitBarrier(t, barrier, "MASTER resign becomeBackup")
	if vi.resignIsPending() {
		t.Fatal("resignPending set after MASTER becomeBackup")
	}
	if got := vi.getPriority(); got != 0 {
		t.Fatalf("priority after MASTER resign = %d, want 0", got)
	}
	m.UpdateRGPriority(1, 200)
	vi.setState(StateMaster)
	vi.becomeBackup(time.NewTimer(time.Hour), time.NewTimer(time.Hour))
	if got := vi.getPriority(); got != 200 {
		t.Fatalf("priority after restore + later step-down = %d, want 200", got)
	}
}
