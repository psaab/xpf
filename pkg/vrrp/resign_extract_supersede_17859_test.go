package vrrp

import (
	"testing"

	"github.com/vishvananda/netlink"
)

// #17859: applyPendingResign used to clear resignPending and copy the
// stashed 0 out from under resignMu, then install that local copy into
// cfg.Priority only after re-acquiring mu. A cluster-authoritative
// priority restore (UpdateRGPriority / updateConfig) completing in that
// window writes the restored priority and discards — but the pending
// flag is already false, so the discard is a no-op and the extracted 0
// silently overwrites the restore. Nothing repairs cfg.Priority until
// the next posture reconcile.
//
// Subject: drive the exact window via the two real phases —
// extractPendingResign, restore, commitPendingResign — so the
// interleaving is deterministic (no scheduling luck, no -race needed:
// the bug is a wrong ORDER of correctly-synchronized writes).
//
// RED on revert (verified pre-merge): make commitPendingResign install
// unconditionally (drop the resignEpoch re-check, `superseded :=
// false`) and BOTH subjects fail with "cfg.Priority after commit = 0,
// want 200" — the exact cited defect. This also covers the
// updateConfig leg of the mechanism: subject B drives the same guard
// through the config path.
//
// Placement guard (not runtime-testable): updateConfigHeld must call
// discardPendingResignLocked INSIDE its mu critical section. A
// sequential test cannot discriminate the placement — after
// updateConfig returns, the observable state (cfg.Priority 200,
// epoch bumped) is identical either way; only a commit landing in the
// unlock→discard gap of a concurrent updateConfig can tell them
// apart, and no deterministic interleave into that gap exists without
// a production test hook (attempts deadlock or flake on the resignMu
// handshake). The requirement is therefore carried by the
// discardPendingResignLocked contract (Locked suffix: caller holds
// mu) and review, mirroring removeVIPsLocked.
//
// Controls: without a restore in the window the commit still installs
// the stashed 0 (#16821 contract); a restore before extraction leaves
// nothing to install; a restore after the commit wins by ordering.

func cfgPriority17859(t *testing.T, vi *vrrpInstance) int {
	t.Helper()
	vi.mu.RLock()
	defer vi.mu.RUnlock()
	return vi.cfg.Priority
}

// extractIntoWindow17859 stashes a pending resignation via the real
// ResignRG path, then extracts it, and asserts the cited window shape:
// pending flag cleared, cfg.Priority still at the pre-resign 200.
func extractIntoWindow17859(t *testing.T, m *Manager, vi *vrrpInstance) pendingResign {
	t.Helper()
	m.ResignRG(1)
	if !vi.resignIsPending() {
		t.Fatal("precondition: ResignRG must stash a pending resignation")
	}
	r, ok := vi.extractPendingResign()
	if !ok {
		t.Fatal("precondition: extraction must succeed while a resign is pending")
	}
	if vi.resignIsPending() {
		t.Fatal("extraction must clear the pending flag — that is the cited window")
	}
	if got := cfgPriority17859(t, vi); got != 200 {
		t.Fatalf("precondition: cfg.Priority inside the extraction window = %d, want 200 (not yet installed)", got)
	}
	if r.priority != 0 {
		t.Fatalf("precondition: extracted stash priority = %d, want 0", r.priority)
	}
	return r
}

// TestExtractedResignCannotOverwriteUpdateRGPriorityRestore17859 is
// subject A: the immediate restore path (posture reconcile driving the
// RG back to Primary) completes inside the extraction window.
func TestExtractedResignCannotOverwriteUpdateRGPriorityRestore17859(t *testing.T) {
	m, vi := resignBarrierInstance(t, "xpf-17859-a0", func(*netlink.Addr) error { return nil })
	vi.setState(StateBackup)

	r := extractIntoWindow17859(t, m, vi)

	m.UpdateRGPriority(1, 200)
	if got := cfgPriority17859(t, vi); got != 200 {
		t.Fatalf("cfg.Priority after restore = %d, want 200", got)
	}

	vi.commitPendingResign(r)

	if got := cfgPriority17859(t, vi); got != 200 {
		t.Fatalf("cfg.Priority after commit = %d, want 200 — an already-extracted resignation overwrote the newer restored priority (#17859)", got)
	}
	if vi.resignIsPending() {
		t.Fatal("resignPending set after commit")
	}
}

// TestExtractedResignCannotOverwriteUpdateConfigRestore17859 is
// subject B: the debounced config restore path (LocalPriorities on a
// cluster re-promotion) completes inside the extraction window.
func TestExtractedResignCannotOverwriteUpdateConfigRestore17859(t *testing.T) {
	m, vi := resignBarrierInstance(t, "xpf-17859-b0", func(*netlink.Addr) error { return nil })
	vi.setState(StateBackup)

	r := extractIntoWindow17859(t, m, vi)

	vi.updateConfig(Instance{
		Interface:         "xpf-17859-b0",
		GroupID:           101,
		Priority:          200,
		AdvertiseInterval: 1000,
	})
	if got := cfgPriority17859(t, vi); got != 200 {
		t.Fatalf("cfg.Priority after updateConfig restore = %d, want 200", got)
	}

	vi.commitPendingResign(r)

	if got := cfgPriority17859(t, vi); got != 200 {
		t.Fatalf("cfg.Priority after commit = %d, want 200 — an already-extracted resignation overwrote the newer restored priority (#17859)", got)
	}
	if vi.resignIsPending() {
		t.Fatal("resignPending set after commit")
	}
}

// TestExtractedResignStillInstallsWhenNotSuperseded17859 is the
// negative control: with NO restore in the window the commit must
// still install the stashed 0 — the #16821/#15213 contract (a resigned
// instance keeps priority 0 until restored) must not regress to a
// never-install guard.
func TestExtractedResignStillInstallsWhenNotSuperseded17859(t *testing.T) {
	m, vi := resignBarrierInstance(t, "xpf-17859-c0", func(*netlink.Addr) error { return nil })
	vi.setState(StateBackup)

	r := extractIntoWindow17859(t, m, vi)
	vi.commitPendingResign(r)

	if got := cfgPriority17859(t, vi); got != 0 {
		t.Fatalf("cfg.Priority after unsuperseded commit = %d, want 0 (resigned instance keeps 0 until restored)", got)
	}
	if got := vi.getPriority(); got != 0 {
		t.Fatalf("getPriority() after unsuperseded commit = %d, want 0", got)
	}
}

// TestRestoreBeforeExtractionLeavesNothingToInstall17859 pins the
// window's left edge: a restore that completes BEFORE extraction
// discards the stash, extraction finds nothing, and a later commit
// (run loop resuming) is a no-op — priority stays 200.
func TestRestoreBeforeExtractionLeavesNothingToInstall17859(t *testing.T) {
	m, vi := resignBarrierInstance(t, "xpf-17859-d0", func(*netlink.Addr) error { return nil })
	vi.setState(StateBackup)

	m.ResignRG(1)
	m.UpdateRGPriority(1, 200)
	if vi.resignIsPending() {
		t.Fatal("precondition: restore must discard the pending resignation")
	}

	r, ok := vi.extractPendingResign()
	if ok {
		t.Fatal("extraction must report nothing to install after the restore discarded the stash")
	}
	vi.commitPendingResign(r)

	if got := cfgPriority17859(t, vi); got != 200 {
		t.Fatalf("cfg.Priority after no-op commit = %d, want 200", got)
	}
}

// TestRestoreAfterCommitStillWins17859 pins the window's right edge:
// when the commit takes mu first, the install happens and the restore
// that follows overwrites it by ordinary ordering — the fix must not
// invert precedence by deferring installs that were never superseded.
func TestRestoreAfterCommitStillWins17859(t *testing.T) {
	m, vi := resignBarrierInstance(t, "xpf-17859-e0", func(*netlink.Addr) error { return nil })
	vi.setState(StateBackup)

	r := extractIntoWindow17859(t, m, vi)
	vi.commitPendingResign(r)
	if got := cfgPriority17859(t, vi); got != 0 {
		t.Fatalf("precondition: unsuperseded commit must install 0, got %d", got)
	}

	m.UpdateRGPriority(1, 200)
	if got := cfgPriority17859(t, vi); got != 200 {
		t.Fatalf("cfg.Priority after post-commit restore = %d, want 200", got)
	}
}
