package configstore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// newTestStoreAt constructs a Store at path, failing the test when the
// fail-closed constructor (#1893) reports an unusable config db.
func newTestStoreAt(t *testing.T, path string) *Store {
	t.Helper()
	s, err := New(path)
	if err != nil {
		t.Fatalf("New(%s): %v", path, err)
	}
	return s
}

// newTestStore creates a Store backed by a temp file for testing.
func newTestStore(t *testing.T) *Store {
	t.Helper()
	return newTestStoreAt(t, filepath.Join(t.TempDir(), "config"))
}

// #1319: end-to-end gate — CommitCheck/Commit must reject typed-leaf
// garbage like `set class-of-service schedulers x transmit-rate asd`
// BEFORE the existing compiler tries to parse it (and silently writes 0).
//
// SetFromInput prepends the `set ` keyword internally, so the test
// strings must NOT include it.
func TestCommitCheck_RejectsInvalidTransmitRate(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := s.SetFromInput("class-of-service schedulers be transmit-rate asd"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	_, err := s.CommitCheck()
	if err == nil {
		t.Fatal("expected CommitCheck to reject transmit-rate asd, got nil")
	}
	if !strings.Contains(err.Error(), "transmit-rate") {
		t.Fatalf("CommitCheck error should reference transmit-rate: %v", err)
	}
	// Commit should refuse the same way.
	if _, err := s.Commit(); err == nil {
		t.Fatal("expected Commit to reject transmit-rate asd, got nil")
	}
}

func TestCommitCheck_RejectsInvalidTransmitRateFromApplyGroups(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	for _, cmd := range []string{
		"groups bad class-of-service schedulers be transmit-rate asd",
		"apply-groups bad",
	} {
		if err := s.SetFromInput(cmd); err != nil {
			t.Fatalf("SetFromInput(%q): %v", cmd, err)
		}
	}
	_, err := s.CommitCheck()
	if err == nil {
		t.Fatal("expected CommitCheck to reject grouped transmit-rate asd, got nil")
	}
	if !strings.Contains(err.Error(), "transmit-rate") {
		t.Fatalf("CommitCheck error should reference transmit-rate: %v", err)
	}
}

func TestCommitCheck_AcceptsValidScheduler(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	for _, cmd := range []string{
		"class-of-service schedulers be transmit-rate 1g",
		"class-of-service schedulers be priority low",
		"class-of-service schedulers be buffer-size 16m",
	} {
		if err := s.SetFromInput(cmd); err != nil {
			t.Fatalf("SetFromInput(%q): %v", cmd, err)
		}
	}
	if _, err := s.CommitCheck(); err != nil {
		t.Fatalf("CommitCheck: unexpected error: %v", err)
	}
}

func TestCommitCheck_RejectsAmbiguousThreeColorPolicer(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	for _, cmd := range []string{
		"firewall three-color-policer bad single-rate color-blind",
		"firewall three-color-policer bad single-rate color-aware",
		"firewall three-color-policer bad single-rate committed-information-rate 10m",
		"firewall three-color-policer bad single-rate committed-burst-size 100k",
		"firewall three-color-policer bad single-rate excess-burst-size 200k",
	} {
		if err := s.SetFromInput(cmd); err != nil {
			t.Fatalf("SetFromInput(%q): %v", cmd, err)
		}
	}
	_, err := s.CommitCheck()
	if err == nil {
		t.Fatal("expected CommitCheck to reject ambiguous three-color policer, got nil")
	}
	if !strings.Contains(err.Error(), "cannot configure both color-blind and color-aware") {
		t.Fatalf("CommitCheck error = %v", err)
	}
}

func TestCommitCheck_RejectsAmbiguousThreeColorPolicerAcrossLoadOverrideBlocks(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	hier := `firewall {
    three-color-policer bad {
        single-rate {
            color-blind;
            committed-information-rate 10m;
            committed-burst-size 100k;
            excess-burst-size 200k;
        }
    }
    three-color-policer bad {
        two-rate {
            color-blind;
            committed-information-rate 10m;
            peak-information-rate 20m;
            committed-burst-size 100k;
            peak-burst-size 200k;
        }
    }
}`
	if err := s.LoadOverride(hier); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	_, err := s.CommitCheck()
	if err == nil {
		t.Fatal("expected CommitCheck to reject duplicate hierarchical single-rate/two-rate blocks")
	}
	if !strings.Contains(err.Error(), "cannot configure both single-rate and two-rate") {
		t.Fatalf("CommitCheck error = %v", err)
	}
}

func TestCommitCheck_RejectsAmbiguousThreeColorPolicerAcrossLoadOverrideSameModeSiblings(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	hier := `firewall {
    three-color-policer bad {
        single-rate {
            color-blind;
            committed-information-rate 10m;
            committed-burst-size 100k;
            excess-burst-size 200k;
        }
        single-rate {
            color-aware;
        }
    }
}`
	if err := s.LoadOverride(hier); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	_, err := s.CommitCheck()
	if err == nil {
		t.Fatal("expected CommitCheck to reject duplicate hierarchical single-rate color mode ambiguity")
	}
	if !strings.Contains(err.Error(), "cannot configure both color-blind and color-aware") {
		t.Fatalf("CommitCheck error = %v", err)
	}
}

func TestCommitCheck_RejectsThreeColorPolicerPeakBelowCommitted(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	for _, cmd := range []string{
		"firewall three-color-policer bad two-rate color-blind",
		"firewall three-color-policer bad two-rate committed-information-rate 20m",
		"firewall three-color-policer bad two-rate peak-information-rate 10m",
		"firewall three-color-policer bad two-rate committed-burst-size 100k",
		"firewall three-color-policer bad two-rate peak-burst-size 200k",
	} {
		if err := s.SetFromInput(cmd); err != nil {
			t.Fatalf("SetFromInput(%q): %v", cmd, err)
		}
	}
	_, err := s.CommitCheck()
	if err == nil {
		t.Fatal("expected CommitCheck to reject peak-information-rate below committed-information-rate")
	}
	if !strings.Contains(err.Error(), "peak-information-rate must be >= committed-information-rate") {
		t.Fatalf("CommitCheck error = %v", err)
	}
}

func TestEnterExitConfigure(t *testing.T) {
	s := newTestStore(t)

	if s.InConfigMode() {
		t.Error("should not be in config mode initially")
	}

	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if !s.InConfigMode() {
		t.Error("should be in config mode after enter")
	}

	// Double enter should fail
	if err := s.EnterConfigure(); err == nil {
		t.Error("expected error on double EnterConfigure")
	}

	s.ExitConfigure()
	if s.InConfigMode() {
		t.Error("should not be in config mode after exit")
	}
}

func TestSetAndCommit(t *testing.T) {
	s := newTestStore(t)

	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}

	// Set outside config mode should fail after exit
	cmds := []string{
		"interfaces eth0 unit 0 family inet address 10.0.0.1/24",
		"security zones security-zone trust interfaces eth0.0",
		"interfaces eth1 unit 0 family inet address 10.1.0.1/24",
		"security zones security-zone untrust interfaces eth1.0",
	}
	for _, cmd := range cmds {
		if err := s.SetFromInput(cmd); err != nil {
			t.Fatalf("SetFromInput(%q): %v", cmd, err)
		}
	}

	if !s.IsDirty() {
		t.Error("should be dirty after set")
	}

	// CommitCheck should succeed
	cfg, err := s.CommitCheck()
	if err != nil {
		t.Fatalf("CommitCheck: %v", err)
	}
	if cfg == nil {
		t.Fatal("CommitCheck returned nil config")
	}
	if len(cfg.Security.Zones) != 2 {
		t.Errorf("expected 2 zones, got %d", len(cfg.Security.Zones))
	}

	// Commit
	cfg, err = s.Commit()
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if s.IsDirty() {
		t.Error("should not be dirty after commit")
	}

	// Active should contain our config
	active := s.ShowActive()
	if !strings.Contains(active, "trust") {
		t.Error("active config missing 'trust'")
	}
	if !strings.Contains(active, "untrust") {
		t.Error("active config missing 'untrust'")
	}

	// Compiled active should be available
	if s.ActiveConfig() == nil {
		t.Error("ActiveConfig() returned nil after commit")
	}
	if len(s.ActiveConfig().Security.Zones) != 2 {
		t.Errorf("active config: expected 2 zones, got %d",
			len(s.ActiveConfig().Security.Zones))
	}
}

func TestSetOutsideConfigMode(t *testing.T) {
	s := newTestStore(t)

	// Set without entering config mode should fail
	s.SetFromInput("interfaces eth0 unit 0 family inet address 10.0.0.1/24")
	err := s.SetFromInput("security zones security-zone trust interfaces eth0.0")
	if err == nil {
		t.Error("expected error when setting outside config mode")
	}
}

func TestDeletePath(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}

	cmds := []string{
		"interfaces eth0 unit 0 family inet address 10.0.0.1/24",
		"security zones security-zone trust interfaces eth0.0",
		"interfaces eth1 unit 0 family inet address 10.1.0.1/24",
		"security zones security-zone trust interfaces eth1.0",
		"interfaces eth2 unit 0 family inet address 10.2.0.1/24",
		"security zones security-zone untrust interfaces eth2.0",
	}
	for _, cmd := range cmds {
		if err := s.SetFromInput(cmd); err != nil {
			t.Fatalf("SetFromInput: %v", err)
		}
	}

	// Delete one interface
	if err := s.DeleteFromInput("security zones security-zone trust interfaces eth1.0"); err != nil {
		t.Fatalf("DeleteFromInput: %v", err)
	}

	candidate := s.ShowCandidateSet()
	if strings.Contains(candidate, "eth1.0") {
		t.Error("eth1.0 should have been deleted")
	}
	if !strings.Contains(candidate, "eth0.0") {
		t.Error("eth0.0 should still exist")
	}

	// Commit and verify
	cfg, err := s.Commit()
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	trustZone := cfg.Security.Zones["trust"]
	if trustZone == nil {
		t.Fatal("trust zone missing")
	}
	if len(trustZone.Interfaces) != 1 || trustZone.Interfaces[0] != "eth0.0" {
		t.Errorf("trust zone interfaces: %v", trustZone.Interfaces)
	}
}

func TestShowCompare(t *testing.T) {
	s := newTestStore(t)

	// First commit
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	s.SetFromInput("interfaces eth0 unit 0 family inet address 10.0.0.1/24")
	s.SetFromInput("security zones security-zone trust interfaces eth0.0")
	if _, err := s.Commit(); err != nil {
		t.Fatal(err)
	}

	// Modify candidate
	s.SetFromInput("interfaces eth1 unit 0 family inet address 10.1.0.1/24")
	s.SetFromInput("security zones security-zone untrust interfaces eth1.0")

	diff := s.ShowCompare()
	if !strings.Contains(diff, "+") {
		t.Errorf("expected diff to contain additions, got:\n%s", diff)
	}
	if !strings.Contains(diff, "untrust") {
		t.Errorf("diff should mention untrust:\n%s", diff)
	}
}

func TestRollback(t *testing.T) {
	s := newTestStore(t)

	// Commit 1: trust zone
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	s.SetFromInput("interfaces eth0 unit 0 family inet address 10.0.0.1/24")
	s.SetFromInput("security zones security-zone trust interfaces eth0.0")
	cfg1, err := s.Commit()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg1.Security.Zones) != 1 {
		t.Fatalf("commit 1: expected 1 zone, got %d", len(cfg1.Security.Zones))
	}

	// Commit 2: add untrust zone
	s.SetFromInput("interfaces eth1 unit 0 family inet address 10.1.0.1/24")
	s.SetFromInput("security zones security-zone untrust interfaces eth1.0")
	cfg2, err := s.Commit()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg2.Security.Zones) != 2 {
		t.Fatalf("commit 2: expected 2 zones, got %d", len(cfg2.Security.Zones))
	}

	// Rollback to commit 1 (rollback 1)
	if err := s.Rollback(1); err != nil {
		t.Fatalf("Rollback(1): %v", err)
	}
	if !s.IsDirty() {
		t.Error("should be dirty after rollback")
	}

	// Commit the rollback
	cfg3, err := s.Commit()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg3.Security.Zones) != 1 {
		t.Errorf("after rollback: expected 1 zone, got %d", len(cfg3.Security.Zones))
	}
	if cfg3.Security.Zones["trust"] == nil {
		t.Error("after rollback: trust zone should exist")
	}
}

func TestRollbackZero(t *testing.T) {
	s := newTestStore(t)

	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	s.SetFromInput("interfaces eth0 unit 0 family inet address 10.0.0.1/24")
	s.SetFromInput("security zones security-zone trust interfaces eth0.0")
	if _, err := s.Commit(); err != nil {
		t.Fatal(err)
	}

	// Modify candidate
	s.SetFromInput("interfaces eth1 unit 0 family inet address 10.1.0.1/24")
	s.SetFromInput("security zones security-zone untrust interfaces eth1.0")
	if !s.IsDirty() {
		t.Error("should be dirty after modification")
	}

	// Rollback 0 = revert candidate to active
	if err := s.Rollback(0); err != nil {
		t.Fatalf("Rollback(0): %v", err)
	}
	if s.IsDirty() {
		t.Error("should not be dirty after rollback 0")
	}

	// Candidate should match active (no untrust)
	candidate := s.ShowCandidateSet()
	if strings.Contains(candidate, "untrust") {
		t.Error("candidate should not contain untrust after rollback 0")
	}
}

func TestDirtyFlag(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}

	if s.IsDirty() {
		t.Error("should not be dirty initially")
	}

	s.SetFromInput("interfaces eth0 unit 0 family inet address 10.0.0.1/24")
	s.SetFromInput("security zones security-zone trust interfaces eth0.0")
	if !s.IsDirty() {
		t.Error("should be dirty after set")
	}

	if _, err := s.Commit(); err != nil {
		t.Fatal(err)
	}
	if s.IsDirty() {
		t.Error("should not be dirty after commit")
	}
}

func TestCommitConfirmedAutoRollback(t *testing.T) {
	s := newTestStore(t)

	// Initial commit
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	s.SetFromInput("interfaces eth0 unit 0 family inet address 10.0.0.1/24")
	s.SetFromInput("security zones security-zone trust interfaces eth0.0")
	if _, err := s.Commit(); err != nil {
		t.Fatal(err)
	}

	// Track rollback executor invocation (#1922 Item 1a: the store now
	// hands the daemon a generation-keyed executor, not an apply callback).
	rollbackCalled := make(chan struct{}, 1)
	s.SetRollbackExecutor(func(gen uint64) {
		rollbackCalled <- struct{}{}
	})

	// Commit confirmed with very short timeout (use CommitConfirmed with 1 min)
	s.SetFromInput("interfaces eth1 unit 0 family inet address 10.1.0.1/24")
	s.SetFromInput("security zones security-zone untrust interfaces eth1.0")

	// We can't easily test the real timer with minutes, so verify the state tracking
	if !s.IsConfirmPending() {
		// Before commit confirmed, no timer
	}

	_, err := s.CommitConfirmed(1)
	if err != nil {
		t.Fatalf("CommitConfirmed: %v", err)
	}

	if !s.IsConfirmPending() {
		t.Error("should have pending confirm after CommitConfirmed")
	}

	// Confirm it
	if err := s.ConfirmCommit(); err != nil {
		t.Fatalf("ConfirmCommit: %v", err)
	}

	if s.IsConfirmPending() {
		t.Error("should not have pending confirm after ConfirmCommit")
	}
}

// #1922 Item 1a: PromoteRollback is the store-state promotion primitive
// for the commit-confirmed timeout rollback. It must honor the #1817
// confirmGen staleness guard and the (Item 1b, deferred) prevCfg==nil
// first-commit early-return.
func TestPromoteRollbackGenGuardAndFirstCommit(t *testing.T) {
	t.Run("stale gen is a no-op", func(t *testing.T) {
		s := newTestStore(t)
		if err := s.EnterConfigure(); err != nil {
			t.Fatal(err)
		}
		// Confirmed baseline A so the rollback target is non-nil.
		if err := s.SetFromInput("system host-name A"); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Commit(); err != nil {
			t.Fatal(err)
		}
		// Unconfirmed promote to B; rollback target = A.
		if err := s.SetFromInput("system host-name B"); err != nil {
			t.Fatal(err)
		}
		if _, err := s.CommitConfirmed(1); err != nil {
			t.Fatal(err)
		}
		gen := s.ConfirmGenForTesting()

		// A stale (superseded) generation must NOT roll back.
		if cfg, ok := s.PromoteRollback(gen - 1); ok || cfg != nil {
			t.Fatalf("PromoteRollback(stale gen) = (%v,%v), want (nil,false)", cfg, ok)
		}
		if got := s.ActiveConfig().System.HostName; got != "B" {
			t.Fatalf("stale-gen rollback mutated active to %q, want B", got)
		}

		// The matching generation rolls back to A and returns it.
		cfg, ok := s.PromoteRollback(gen)
		if !ok || cfg == nil {
			t.Fatalf("PromoteRollback(gen) = (%v,%v), want (cfg,true)", cfg, ok)
		}
		if cfg.System.HostName != "A" {
			t.Fatalf("PromoteRollback returned host-name %q, want A", cfg.System.HostName)
		}
		if got := s.ActiveConfig().System.HostName; got != "A" {
			t.Fatalf("after rollback active host-name = %q, want A", got)
		}

		// A second call with the same gen is now a no-op (confirmPrevTree
		// cleared) — the generation matches but the target is gone.
		if cfg, ok := s.PromoteRollback(gen); ok || cfg != nil {
			t.Fatalf("double PromoteRollback = (%v,%v), want (nil,false)", cfg, ok)
		}
	})

	t.Run("first-commit returns (nil,true): store reverts, no compiled to apply", func(t *testing.T) {
		s := newTestStore(t)
		if err := s.EnterConfigure(); err != nil {
			t.Fatal(err)
		}
		// FIRST commit confirmed on a fresh store. The rollback target
		// tree (confirmPrevTree) is the empty pre-config tree — NON-nil —
		// but the compiled config recorded at arm time is nil (a fresh
		// store has active=&ConfigTree{} but compiled=nil). PromoteRollback
		// must therefore promote the store back to the empty tree and
		// return (nil, TRUE) — NOT (nil,false). The daemon executor's
		// prevCfg==nil guard then skips the dataplane re-apply (which would
		// panic on a nil config). Re-applying that first-commit-to-bootstrap
		// case is #1922 Item 1b, DEFERRED to PR-2. (Codex r1 Critical: the
		// old guard keyed on confirmPrevTree==nil, which is never true for a
		// fresh store, so the nil compiled would reach applyConfigLocked.)
		if err := s.SetFromInput("system host-name First"); err != nil {
			t.Fatal(err)
		}
		if _, err := s.CommitConfirmed(1); err != nil {
			t.Fatal(err)
		}
		gen := s.ConfirmGenForTesting()

		prevCfg, ok := s.PromoteRollback(gen)
		if !ok {
			t.Fatalf("first-commit PromoteRollback should promote the empty baseline, got ok=false")
		}
		if prevCfg != nil {
			t.Fatalf("first-commit PromoteRollback prevCfg = %v, want nil (fresh store has no compiled config)", prevCfg)
		}
		if got := s.ActiveConfig(); got != nil && got.System.HostName != "" {
			t.Fatalf("after first-commit rollback active host-name = %q, want empty", got.System.HostName)
		}

		// With confirmPrevTree now cleared, a second call is a no-op.
		if cfg, ok := s.PromoteRollback(gen); ok || cfg != nil {
			t.Fatalf("double PromoteRollback after first-commit = (%v,%v), want (nil,false)", cfg, ok)
		}
	})
}

func TestConfirmWithoutPending(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}

	err := s.ConfirmCommit()
	if err == nil {
		t.Error("expected error when confirming without pending commit")
	}
}

func TestLoadAndSave(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")

	// Create and save config
	s1 := newTestStoreAt(t, path)
	if err := s1.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	s1.SetFromInput("interfaces eth0 unit 0 family inet address 10.0.0.1/24")
	s1.SetFromInput("security zones security-zone trust interfaces eth0.0")
	s1.SetFromInput("interfaces eth1 unit 0 family inet address 10.1.0.1/24")
	s1.SetFromInput("security zones security-zone untrust interfaces eth1.0")
	if _, err := s1.Commit(); err != nil {
		t.Fatal(err)
	}

	// Load in a new store
	s2 := newTestStoreAt(t, path)
	if err := s2.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Verify loaded config
	cfg := s2.ActiveConfig()
	if cfg == nil {
		t.Fatal("loaded config is nil")
	}
	if len(cfg.Security.Zones) != 2 {
		t.Errorf("loaded config: expected 2 zones, got %d", len(cfg.Security.Zones))
	}
}

func TestLoadNonexistent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nonexistent")

	s := newTestStoreAt(t, path)
	if err := s.Load(); err != nil {
		t.Fatalf("Load should not error on non-existent file: %v", err)
	}
}

func TestRollbackFilesPersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")

	s := newTestStoreAt(t, path)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}

	// Commit 1
	s.SetFromInput("interfaces eth0 unit 0 family inet address 10.0.0.1/24")
	s.SetFromInput("security zones security-zone trust interfaces eth0.0")
	if _, err := s.Commit(); err != nil {
		t.Fatal(err)
	}

	// Commit 2
	s.SetFromInput("interfaces eth1 unit 0 family inet address 10.1.0.1/24")
	s.SetFromInput("security zones security-zone untrust interfaces eth1.0")
	if _, err := s.Commit(); err != nil {
		t.Fatal(err)
	}

	// Check rollback file exists
	rollbackPath := filepath.Join(dir, "config.1")
	if _, err := os.Stat(rollbackPath); os.IsNotExist(err) {
		t.Error("rollback file config.1 should exist")
	}

	// Load in new store and check history
	s2 := newTestStoreAt(t, path)
	if err := s2.Load(); err != nil {
		t.Fatal(err)
	}

	entries := s2.ListHistory()
	if len(entries) < 1 {
		t.Errorf("expected at least 1 history entry, got %d", len(entries))
	}
}

func TestShowRollback(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}

	// Commit 1
	s.SetFromInput("interfaces eth0 unit 0 family inet address 10.0.0.1/24")
	s.SetFromInput("security zones security-zone trust interfaces eth0.0")
	if _, err := s.Commit(); err != nil {
		t.Fatal(err)
	}

	// Commit 2
	s.SetFromInput("interfaces eth1 unit 0 family inet address 10.1.0.1/24")
	s.SetFromInput("security zones security-zone untrust interfaces eth1.0")
	if _, err := s.Commit(); err != nil {
		t.Fatal(err)
	}

	// Show rollback 1 should show commit 1 state (without untrust)
	rb, err := s.ShowRollback(1)
	if err != nil {
		t.Fatalf("ShowRollback(1): %v", err)
	}
	if !strings.Contains(rb, "trust") {
		t.Error("rollback 1 should contain trust zone")
	}

	// Invalid rollback slot
	_, err = s.ShowRollback(100)
	if err == nil {
		t.Error("expected error for invalid rollback slot")
	}
}

func TestHistory(t *testing.T) {
	h := NewHistory(3) // small buffer

	if h.Len() != 0 {
		t.Errorf("empty history len: %d", h.Len())
	}

	for i := 0; i < 5; i++ {
		h.Push(&HistoryEntry{
			Timestamp: time.Now(),
			Comment:   "test",
		})
	}

	// Should only keep 3 most recent
	if h.Len() != 3 {
		t.Errorf("expected len 3, got %d", h.Len())
	}

	entries := h.List()
	if len(entries) != 3 {
		t.Errorf("expected 3 entries, got %d", len(entries))
	}

	// Get valid entry
	_, err := h.Get(0)
	if err != nil {
		t.Errorf("Get(0): %v", err)
	}

	// Get out of bounds
	_, err = h.Get(10)
	if err == nil {
		t.Error("expected error for out-of-bounds Get")
	}
}

func TestLoadOverride(t *testing.T) {
	s := newTestStore(t)

	// Initial commit with trust zone
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	s.SetFromInput("interfaces eth0 unit 0 family inet address 10.0.0.1/24")
	s.SetFromInput("security zones security-zone trust interfaces eth0.0")
	if _, err := s.Commit(); err != nil {
		t.Fatal(err)
	}

	// Load override replaces entire candidate
	hierConfig := `interfaces {
    eth2 {
        unit 0 {
            family inet {
                address 10.2.0.1/24;
            }
        }
    }
}
security {
    zones {
        security-zone dmz {
            interfaces {
                eth2.0;
            }
        }
    }
}`
	if err := s.LoadOverride(hierConfig); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}

	if !s.IsDirty() {
		t.Error("should be dirty after load override")
	}

	// Candidate should only have dmz, not trust
	candidate := s.ShowCandidateSet()
	if strings.Contains(candidate, "trust") {
		t.Error("candidate should not contain trust after override")
	}
	if !strings.Contains(candidate, "dmz") {
		t.Error("candidate should contain dmz after override")
	}

	// Commit and verify
	cfg, err := s.Commit()
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if cfg.Security.Zones["trust"] != nil {
		t.Error("trust zone should not exist after override commit")
	}
	if cfg.Security.Zones["dmz"] == nil {
		t.Error("dmz zone should exist after override commit")
	}
}

func TestLoadMergeHierarchical(t *testing.T) {
	s := newTestStore(t)

	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	s.SetFromInput("interfaces eth0 unit 0 family inet address 10.0.0.1/24")
	s.SetFromInput("security zones security-zone trust interfaces eth0.0")

	// Merge hierarchical config — should add untrust without removing trust
	hierConfig := `interfaces {
    eth1 {
        unit 0 {
            family inet {
                address 10.1.0.1/24;
            }
        }
    }
}
security {
    zones {
        security-zone untrust {
            interfaces {
                eth1.0;
            }
        }
    }
}`
	if err := s.LoadMerge(hierConfig); err != nil {
		t.Fatalf("LoadMerge: %v", err)
	}

	candidate := s.ShowCandidateSet()
	if !strings.Contains(candidate, "trust") {
		t.Error("candidate should still contain trust after merge")
	}
	if !strings.Contains(candidate, "untrust") {
		t.Error("candidate should contain untrust after merge")
	}

	cfg, err := s.Commit()
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if len(cfg.Security.Zones) != 2 {
		t.Errorf("expected 2 zones, got %d", len(cfg.Security.Zones))
	}
}

func TestLoadMergeSetFormat(t *testing.T) {
	s := newTestStore(t)

	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	s.SetFromInput("interfaces eth0 unit 0 family inet address 10.0.0.1/24")
	s.SetFromInput("security zones security-zone trust interfaces eth0.0")

	// Merge set-format commands
	s.SetFromInput("interfaces eth1 unit 0 family inet address 10.1.0.1/24")
	setConfig := `set security zones security-zone untrust interfaces eth1.0
set interfaces eth2 unit 0 family inet address 10.2.0.1/24
set security zones security-zone dmz interfaces eth2.0`

	if err := s.LoadMerge(setConfig); err != nil {
		t.Fatalf("LoadMerge (set format): %v", err)
	}

	cfg, err := s.Commit()
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if len(cfg.Security.Zones) != 3 {
		t.Errorf("expected 3 zones, got %d", len(cfg.Security.Zones))
	}
}

// TestLoadMergeRejectsGarbageLine pins #3442 M3: once flat set-format is
// detected (any line starts with a verb), a free-text / typo line must FAIL
// the merge instead of being materialized as a junk top-level node via the
// ParseSetVerb bare-path default. RED on revert: the pre-fix LoadMerge ran
// "not-a-set-line" through applyEditLine -> SetPath, creating a node, and
// returned nil.
func TestLoadMergeRejectsGarbageLine(t *testing.T) {
	s := newTestStore(t)

	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}

	s.SetFromInput("interfaces eth0 unit 0 family inet address 10.0.0.1/24")
	setConfig := `set security zones security-zone trust interfaces eth0.0
not-a-set-line
set interfaces eth1 unit 0 family inet address 10.1.0.1/24
set security zones security-zone untrust interfaces eth1.0`

	if err := s.LoadMerge(setConfig); err == nil {
		t.Fatal("expected LoadMerge to reject the garbage line, got nil")
	} else if !strings.Contains(err.Error(), "not-a-set-line") {
		t.Errorf("expected error to name the garbage line, got %v", err)
	}

	// The junk top-level node must NOT have been materialized.
	if candidate := s.ShowCandidateSet(); strings.Contains(candidate, "not-a-set-line") {
		t.Errorf("garbage line was materialized into the candidate:\n%s", candidate)
	}
}

// TestLoadFlatVerbGate pins the #3442 fold: the fail-closed gate recognizes
// exactly the verbs applyEditLine can replay (set/delete/deactivate/activate),
// tolerates a tab between verb and path, and rejects the interactive-only
// structural-edit verbs (annotate/copy/insert/rename) plus genuine garbage —
// none of which the flat-load replay path can handle.
func TestLoadFlatVerbGate(t *testing.T) {
	// All four replayable verbs in sequence must be accepted (count == 4).
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	supported := "set system host-name fw\ndeactivate system host-name\nactivate system host-name\ndelete system host-name"
	count, err := s.LoadSet(supported)
	if err != nil {
		t.Fatalf("LoadSet of supported verbs: %v", err)
	}
	if count != 4 {
		t.Errorf("expected 4 commands, got %d", count)
	}

	// A tab between the verb and the path must be tolerated (the lexer
	// treats tabs as whitespace; a literal-space-only gate would wrongly
	// reject this valid line).
	s.ExitConfigure()
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LoadSet("set\tsystem domain-name example.com"); err != nil {
		t.Fatalf("LoadSet of tab-separated set line: %v", err)
	}

	// Interactive-only structural-edit verbs and free-text garbage are NOT
	// replayable on the flat path and must be rejected.
	for _, bad := range []string{
		"annotate system \"a comment\"",
		"copy system to other",
		"insert system before other",
		"rename system to other",
		"not-a-set-line",
		"sett system host-name fw",
	} {
		s.ExitConfigure()
		if err := s.EnterConfigure(); err != nil {
			t.Fatal(err)
		}
		if _, err := s.LoadSet(bad); err == nil {
			t.Errorf("LoadSet(%q): expected rejection, got nil", bad)
		}
		// LoadMerge flat branch must reject identically (mixed with a valid
		// set line so isSetFormat is selected).
		if err := s.LoadMerge("set system host-name fw\n" + bad); err == nil {
			t.Errorf("LoadMerge with %q: expected rejection, got nil", bad)
		}
	}
}

func TestLoadMergeWithDelete(t *testing.T) {
	s := newTestStore(t)

	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	s.SetFromInput("interfaces eth0 unit 0 family inet address 10.0.0.1/24")
	s.SetFromInput("security zones security-zone trust interfaces eth0.0")
	s.SetFromInput("interfaces eth1 unit 0 family inet address 10.1.0.1/24")
	s.SetFromInput("security zones security-zone untrust interfaces eth1.0")

	// Merge with delete command
	setConfig := `delete security zones security-zone untrust
set interfaces eth2 unit 0 family inet address 10.2.0.1/24
set security zones security-zone dmz interfaces eth2.0`

	if err := s.LoadMerge(setConfig); err != nil {
		t.Fatalf("LoadMerge (with delete): %v", err)
	}

	candidate := s.ShowCandidateSet()
	if strings.Contains(candidate, "untrust") {
		t.Error("untrust should be deleted after merge")
	}
	if !strings.Contains(candidate, "dmz") {
		t.Error("dmz should exist after merge")
	}
}

func TestLoadOutsideConfigMode(t *testing.T) {
	s := newTestStore(t)

	err := s.LoadOverride("security { }")
	if err == nil {
		t.Error("expected error when loading outside config mode")
	}

	s.SetFromInput("interfaces eth0 unit 0 family inet address 10.0.0.1/24")
	err = s.LoadMerge("set security zones security-zone trust interfaces eth0.0")
	if err == nil {
		t.Error("expected error when loading outside config mode")
	}
}

func TestShowCompareRollback(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}

	// Commit 1: trust zone
	s.SetFromInput("interfaces eth0 unit 0 family inet address 10.0.0.1/24")
	s.SetFromInput("security zones security-zone trust interfaces eth0.0")
	if _, err := s.Commit(); err != nil {
		t.Fatal(err)
	}

	// Commit 2: add untrust
	s.SetFromInput("interfaces eth1 unit 0 family inet address 10.1.0.1/24")
	s.SetFromInput("security zones security-zone untrust interfaces eth1.0")
	if _, err := s.Commit(); err != nil {
		t.Fatal(err)
	}

	// Compare rollback 1 (commit 1) with current candidate (same as active after commit 2)
	diff, err := s.ShowCompareRollback(1)
	if err != nil {
		t.Fatalf("ShowCompareRollback: %v", err)
	}
	// Rollback 1 = trust only; candidate = trust + untrust
	// So diff should show untrust as added
	if !strings.Contains(diff, "+") || !strings.Contains(diff, "untrust") {
		t.Errorf("expected diff to show untrust as added:\n%s", diff)
	}
}

func TestShowActiveSetAndCandidateSet(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}

	s.SetFromInput("interfaces eth0 unit 0 family inet address 10.0.0.1/24")
	s.SetFromInput("security zones security-zone trust interfaces eth0.0")
	if _, err := s.Commit(); err != nil {
		t.Fatal(err)
	}

	activeSet := s.ShowActiveSet()
	if !strings.Contains(activeSet, "set security") {
		t.Errorf("ShowActiveSet should contain 'set' commands: %s", activeSet)
	}

	candidateSet := s.ShowCandidateSet()
	if !strings.Contains(candidateSet, "set security") {
		t.Errorf("ShowCandidateSet should contain 'set' commands: %s", candidateSet)
	}

	// They should be the same after a clean commit
	if activeSet != candidateSet {
		t.Error("active and candidate set output should match after commit")
	}
}

func TestExportJSON(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}

	s.SetFromInput("interfaces eth0 unit 0 family inet address 10.0.0.1/24")
	s.SetFromInput("security zones security-zone trust interfaces eth0.0")
	if _, err := s.Commit(); err != nil {
		t.Fatal(err)
	}

	data, err := s.ExportJSON()
	if err != nil {
		t.Fatalf("ExportJSON: %v", err)
	}
	if len(data) == 0 {
		t.Error("exported JSON should not be empty")
	}
	if !strings.Contains(string(data), "trust") {
		t.Error("exported JSON should contain zone name")
	}
}

func TestCommitDiffSummary(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}

	// First commit: add trust zone
	s.SetFromInput("interfaces eth0 unit 0 family inet address 10.0.0.1/24")
	s.SetFromInput("security zones security-zone trust interfaces eth0.0")
	if _, err := s.Commit(); err != nil {
		t.Fatal(err)
	}

	// Second commit: add untrust zone
	s.SetFromInput("interfaces eth1 unit 0 family inet address 10.1.0.1/24")
	s.SetFromInput("security zones security-zone untrust interfaces eth1.0")

	// Check diff summary before commit
	summary := s.CommitDiffSummary()
	if summary == "" {
		t.Error("expected non-empty diff summary")
	}
	if !strings.Contains(summary, "added") {
		t.Errorf("diff summary should mention 'added': %s", summary)
	}

	// Commit and verify summary clears
	if _, err := s.Commit(); err != nil {
		t.Fatal(err)
	}
	summary = s.CommitDiffSummary()
	if summary != "" {
		t.Errorf("expected empty diff summary after commit, got: %s", summary)
	}
}

func TestListCommitHistory(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}

	// Initially no history
	entries, err := s.ListCommitHistory(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}

	// Commit and check history
	s.SetFromInput("interfaces eth0 unit 0 family inet address 10.0.0.1/24")
	s.SetFromInput("security zones security-zone trust interfaces eth0.0")
	if _, err := s.Commit(); err != nil {
		t.Fatal(err)
	}

	entries, err = s.ListCommitHistory(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Action != "commit" {
		t.Errorf("expected action 'commit', got %q", entries[0].Action)
	}
}

func TestRescueConfig(t *testing.T) {
	s := newTestStore(t)

	// Initially no rescue config
	content, err := s.LoadRescueConfig()
	if err != nil {
		t.Fatal(err)
	}
	if content != "" {
		t.Errorf("expected empty rescue config, got %q", content)
	}

	// Delete non-existent should error
	if err := s.DeleteRescueConfig(); err == nil {
		t.Fatal("expected error deleting non-existent rescue config")
	}

	// Set some active config
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	s.SetFromInput("system host-name test-rescue")
	if _, err := s.Commit(); err != nil {
		t.Fatal(err)
	}

	// Save rescue
	if err := s.SaveRescueConfig(); err != nil {
		t.Fatal(err)
	}

	// Load rescue — should contain host-name
	content, err = s.LoadRescueConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(content, "host-name test-rescue") {
		t.Errorf("rescue config missing host-name, got: %s", content)
	}

	// Delete rescue
	if err := s.DeleteRescueConfig(); err != nil {
		t.Fatal(err)
	}

	// Verify deleted
	content, err = s.LoadRescueConfig()
	if err != nil {
		t.Fatal(err)
	}
	if content != "" {
		t.Errorf("expected empty after delete, got %q", content)
	}
}

func TestArchiveConfig(t *testing.T) {
	s := newTestStore(t)
	archiveDir := filepath.Join(t.TempDir(), "archive")

	// Set some active config
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	s.SetFromInput("system host-name test-archive")
	if _, err := s.Commit(); err != nil {
		t.Fatal(err)
	}

	// Archive
	if err := s.ArchiveConfig(archiveDir, 10); err != nil {
		t.Fatal(err)
	}

	// Check archive file exists
	entries, err := os.ReadDir(archiveDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 archive file, got %d", len(entries))
	}
	if !strings.HasPrefix(entries[0].Name(), "config-") || !strings.HasSuffix(entries[0].Name(), ".conf") {
		t.Errorf("unexpected archive filename: %s", entries[0].Name())
	}

	// Verify content
	data, err := os.ReadFile(filepath.Join(archiveDir, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "host-name test-archive") {
		t.Errorf("archive missing host-name, got: %s", string(data))
	}
}

func TestArchiveRotation(t *testing.T) {
	s := newTestStore(t)
	archiveDir := filepath.Join(t.TempDir(), "archive")

	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	s.SetFromInput("system host-name rotation-test")
	if _, err := s.Commit(); err != nil {
		t.Fatal(err)
	}

	// Seed five current-format XPF snapshots, then apply maxArchives=3 rotation.
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := range 5 {
		ts := base.Add(time.Duration(i) * time.Second)
		if err := writeArchive(archiveDir, 0, "test", ts, uint64(i+1)); err != nil {
			t.Fatal(err)
		}
	}

	// Run rotation
	rotateArchives(archiveDir, 3)

	entries, err := os.ReadDir(archiveDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Errorf("expected 3 archives after rotation, got %d", len(entries))
	}
}

func TestAutoArchiveOnCommit(t *testing.T) {
	s := newTestStore(t)
	archiveDir := filepath.Join(t.TempDir(), "archive")

	// Configure auto-archive
	s.SetArchiveConfig(archiveDir, 10)

	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	s.SetFromInput("system host-name auto-archive-test")
	if _, err := s.Commit(); err != nil {
		t.Fatal(err)
	}

	// Wait briefly for the goroutine
	time.Sleep(100 * time.Millisecond)

	entries, err := os.ReadDir(archiveDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("expected 1 auto-archive file, got %d", len(entries))
	}
}

func TestAnnotate(t *testing.T) {
	s := newTestStore(t)
	s.EnterConfigure()

	// Set up a config tree
	if err := s.Set([]string{"system", "host-name", "fw1"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Set([]string{"system", "domain-name", "example.com"}); err != nil {
		t.Fatal(err)
	}

	// Annotate the system node
	if err := s.Annotate([]string{"system"}, "System settings"); err != nil {
		t.Fatal(err)
	}

	// Show the candidate and check annotation is present
	text := s.ShowCandidate()
	if !strings.Contains(text, "/* System settings */") {
		t.Errorf("annotation not in show output:\n%s", text)
	}

	// Annotate a non-existent path
	if err := s.Annotate([]string{"nonexistent"}, "bad"); err == nil {
		t.Error("expected error annotating non-existent path")
	}

	// Annotate outside config mode
	s.ExitConfigure()
	if err := s.Annotate([]string{"system"}, "bad"); err == nil {
		t.Error("expected error annotating outside config mode")
	}
}

// TestAnnotateRejectsCommentDelimiter is the #3900 guard: an annotation
// containing a `*/` (or `/*`) block-comment delimiter must be rejected up
// front, because it would close the `/* */` comment early and inject the
// trailing text as configuration on the next Format→Parse round-trip
// (HA config sync, rollback/archive reload).
func TestAnnotateRejectsCommentDelimiter(t *testing.T) {
	s := newTestStore(t)
	s.EnterConfigure()
	if err := s.Set([]string{"system", "host-name", "fw1"}); err != nil {
		t.Fatal(err)
	}

	// The exact injection payload from the issue.
	err := s.Annotate([]string{"system"}, "note */ set system host-name pwned; /* end")
	if err == nil {
		t.Fatal("Annotate must reject an annotation containing a '*/' comment delimiter")
	}
	if !strings.Contains(err.Error(), "comment delimiter") {
		t.Errorf("error should mention comment delimiter: %v", err)
	}
	// The bare `/*` open half must be rejected too.
	if err := s.Annotate([]string{"system"}, "danger /* swallow"); err == nil {
		t.Fatal("Annotate must reject an annotation containing a '/*' comment delimiter")
	}
	// The rejected annotation must NOT have been applied, so the candidate
	// stays injection-free through a format round-trip.
	text := s.ShowCandidate()
	if strings.Contains(text, "pwned") || strings.Contains(text, "set system host-name") {
		t.Errorf("rejected annotation leaked into candidate:\n%s", text)
	}
	// A benign annotation still works.
	if err := s.Annotate([]string{"system"}, "primary firewall"); err != nil {
		t.Errorf("benign annotation must be accepted: %v", err)
	}
}

// TestAnnotateMultiKeyContainers is the #4587 guard: `annotate` must resolve a
// path through NAMED / multi-key containers (security-zone <name>, from-zone
// <z> to-zone <z> policy <p>, interfaces <name> unit <n>, family inet), not
// only a chain of pure single-key nodes like `system`. The old hand-rolled
// walk consumed one path token per node but matched it against ANY key in a
// node's Keys, so it entered a multi-key node on its first key and then failed
// to find the argument token as a child ("path not found"). This test RED-s on
// revert for every multi-key path below while the single-key `system` case
// stays green.
func TestAnnotateMultiKeyContainers(t *testing.T) {
	s := newTestStore(t)
	s.EnterConfigure()

	// Build a config exercising each multi-key container shape.
	setup := [][]string{
		{"security", "zones", "security-zone", "trust", "host-inbound-traffic", "system-services", "ssh"},
		{"security", "zones", "security-zone", "trust", "description", "trusted-side"},
		{"security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy", "allow-web", "match", "source-address", "any"},
		{"interfaces", "ge-0/0/0", "unit", "0", "family", "inet", "address", "10.0.0.1/24"},
	}
	for _, p := range setup {
		if err := s.Set(p); err != nil {
			t.Fatalf("setup Set(%v): %v", p, err)
		}
	}

	// Each of these paths crosses at least one multi-key node. On the old
	// walk every one returned "path not found"; navigatePath consumes the
	// multi-key node as a unit so they resolve. Distinct comments let the
	// show-output assertion pin each annotation to its target.
	cases := []struct {
		path    []string
		comment string
	}{
		// Named container: security-zone <name>.
		{[]string{"security", "zones", "security-zone", "trust"}, "zone-trust-note"},
		// Terminal leaf reached THROUGH the named container.
		{[]string{"security", "zones", "security-zone", "trust", "description"}, "zone-desc-note"},
		// from-zone <z> to-zone <z> policy <p> (four-key context + keyed policy).
		{[]string{"security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy", "allow-web"}, "policy-note"},
		// interfaces <name> unit <n>.
		{[]string{"interfaces", "ge-0/0/0", "unit", "0"}, "unit-note"},
		// family inet (multi-key leaf-container).
		{[]string{"interfaces", "ge-0/0/0", "unit", "0", "family", "inet"}, "family-note"},
	}
	for _, c := range cases {
		if err := s.Annotate(c.path, c.comment); err != nil {
			t.Errorf("Annotate(%v) must resolve a multi-key path: %v", c.path, err)
		}
	}

	text := s.ShowCandidate()
	for _, c := range cases {
		want := "/* " + c.comment + " */"
		if !strings.Contains(text, want) {
			t.Errorf("annotation %q not in show output for path %v:\n%s", want, c.path, text)
		}
	}

	// The single-key `system` case must still work, byte-identically.
	if err := s.Set([]string{"system", "host-name", "fw1"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Annotate([]string{"system"}, "system-note"); err != nil {
		t.Fatalf("single-key annotate must still work: %v", err)
	}
	if text := s.ShowCandidate(); !strings.Contains(text, "/* system-note */") {
		t.Errorf("single-key annotation missing:\n%s", text)
	}

	// A non-existent multi-key path still returns a clear error and mutates
	// nothing.
	if err := s.Annotate([]string{"security", "zones", "security-zone", "does-not-exist"}, "nope"); err == nil {
		t.Error("expected error annotating a non-existent multi-key path")
	}
}

func TestLoadSet(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	input := "set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24\nset security zones security-zone trust interfaces ge-0/0/0\nset system host-name test-fw"
	count, err := s.LoadSet(input)
	if err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Errorf("expected 3 commands, got %d", count)
	}
	// Verify the config was applied
	text := s.ShowCandidate()
	if !strings.Contains(text, "ge-0/0/0") {
		t.Error("expected interface in candidate config")
	}

	// Comments and blank lines are skipped, but a malformed non-comment line
	// must FAIL the whole load (#3442 M4) — never silently dropped.
	s.ExitConfigure()
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	input2 := "# comment line\nset system host-name fw2\n\nset system domain-name example.com\nnot-a-set-line"
	count2, err := s.LoadSet(input2)
	if err == nil {
		t.Fatalf("expected error on malformed line, got nil (count=%d)", count2)
	}
	if !strings.Contains(err.Error(), "not-a-set-line") {
		t.Errorf("expected error to name the malformed line, got %v", err)
	}

	// A clean comment/blank-only-plus-verbs body still succeeds.
	s.ExitConfigure()
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	input3 := "# comment line\nset system host-name fw3\n\nset system domain-name example.com"
	count3, err := s.LoadSet(input3)
	if err != nil {
		t.Fatalf("LoadSet clean body: %v", err)
	}
	if count3 != 2 {
		t.Errorf("expected 2 commands, got %d", count3)
	}

	// Test outside config mode
	s.ExitConfigure()
	_, err = s.LoadSet("set system host-name bad")
	if err == nil {
		t.Error("expected error outside config mode")
	}
}

func TestConfigureExclusive(t *testing.T) {
	s := newTestStore(t)

	if err := s.EnterConfigureExclusive("test"); err != nil {
		t.Fatal(err)
	}
	if !s.IsExclusiveLocked() {
		t.Error("expected exclusive lock")
	}
	if !s.InConfigMode() {
		t.Error("expected config mode")
	}

	// Second enter should fail (config already locked)
	if err := s.EnterConfigure(); err == nil {
		t.Error("expected error on second EnterConfigure while exclusive")
	}
	if err := s.EnterConfigureExclusive("other"); err == nil {
		t.Error("expected error on second EnterConfigureExclusive")
	}

	// Exit should release the exclusive lock
	s.ExitConfigure()
	if s.IsExclusiveLocked() {
		t.Error("expected lock released after exit")
	}
	if s.InConfigMode() {
		t.Error("expected not in config mode after exit")
	}

	// Should be able to enter again after exit
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("re-enter after exclusive exit: %v", err)
	}
	s.ExitConfigure()
}

func TestCommitWithDescription(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}

	s.SetFromInput("interfaces eth0 unit 0 family inet address 10.0.0.1/24")
	s.SetFromInput("security zones security-zone trust interfaces eth0.0")
	cfg, err := s.CommitWithDescription("initial trust zone setup")
	if err != nil {
		t.Fatalf("CommitWithDescription: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if len(cfg.Security.Zones) != 1 {
		t.Errorf("expected 1 zone, got %d", len(cfg.Security.Zones))
	}

	// Verify journal has the description
	entries, err := s.ListCommitHistory(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 commit entry, got %d", len(entries))
	}
	if entries[0].Detail != "initial trust zone setup" {
		t.Errorf("expected detail 'initial trust zone setup', got %q", entries[0].Detail)
	}
	if entries[0].Action != "commit" {
		t.Errorf("expected action 'commit', got %q", entries[0].Action)
	}

	// Verify history entry has comment
	histEntries := s.ListHistory()
	if len(histEntries) != 1 {
		t.Fatalf("expected 1 history entry, got %d", len(histEntries))
	}
	if histEntries[0].Comment != "initial trust zone setup" {
		t.Errorf("expected comment 'initial trust zone setup', got %q", histEntries[0].Comment)
	}

	// Second commit without description should still work
	s.SetFromInput("interfaces eth1 unit 0 family inet address 10.1.0.1/24")
	s.SetFromInput("security zones security-zone untrust interfaces eth1.0")
	cfg2, err := s.Commit()
	if err != nil {
		t.Fatalf("Commit (no desc): %v", err)
	}
	if len(cfg2.Security.Zones) != 2 {
		t.Errorf("expected 2 zones, got %d", len(cfg2.Security.Zones))
	}

	entries, err = s.ListCommitHistory(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 commit entries, got %d", len(entries))
	}
	// Second entry should have no detail
	if entries[1].Detail != "" {
		t.Errorf("expected empty detail for second commit, got %q", entries[1].Detail)
	}
}

func TestEditPath(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}

	// Initially empty
	if len(s.GetEditPath()) != 0 {
		t.Error("edit path should be empty initially")
	}

	// Set edit path
	s.SetEditPath([]string{"security", "zones"})
	ep := s.GetEditPath()
	if len(ep) != 2 || ep[0] != "security" || ep[1] != "zones" {
		t.Errorf("expected [security zones], got %v", ep)
	}

	// Navigate up
	s.NavigateUp()
	ep = s.GetEditPath()
	if len(ep) != 1 || ep[0] != "security" {
		t.Errorf("expected [security], got %v", ep)
	}

	// Navigate up from single element
	s.NavigateUp()
	if len(s.GetEditPath()) != 0 {
		t.Error("edit path should be empty after navigating up from single element")
	}

	// Navigate up from empty (no-op)
	s.NavigateUp()
	if len(s.GetEditPath()) != 0 {
		t.Error("edit path should remain empty")
	}

	// Navigate top
	s.SetEditPath([]string{"security", "zones", "trust"})
	s.NavigateTop()
	if len(s.GetEditPath()) != 0 {
		t.Error("edit path should be empty after top")
	}

	// Exit configure resets edit path
	s.SetEditPath([]string{"security"})
	s.ExitConfigure()
	if len(s.GetEditPath()) != 0 {
		t.Error("edit path should be empty after exit configure")
	}
}

func TestCopyConfig(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	// NOTE: deliberately no `interfaces` under trust here. Copying a zone that
	// owns an interface would duplicate that interface into trust2, and the
	// #3072 interface-multi-zone commit gate (correctly) rejects an interface
	// assigned to two zones — so a zone-with-interface Copy cannot commit. This
	// test exercises Copy of nested zone content (host-inbound) + that the
	// copied zone exists, which does not require an interface.
	cmds := []string{
		"security zones security-zone trust host-inbound-traffic system-services ping",
	}
	for _, cmd := range cmds {
		if err := s.SetFromInput(cmd); err != nil {
			t.Fatalf("set %q: %v", cmd, err)
		}
	}
	if err := s.Copy(
		[]string{"security", "zones", "security-zone", "trust"},
		[]string{"security", "zones", "security-zone", "trust2"},
	); err != nil {
		t.Fatalf("Copy: %v", err)
	}
	if !s.IsDirty() {
		t.Error("should be dirty after copy")
	}
	_, err := s.Commit()
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	cfg := s.ActiveConfig()
	if cfg == nil {
		t.Fatal("compiled config is nil")
	}
	if _, ok := cfg.Security.Zones["trust"]; !ok {
		t.Error("trust zone should still exist")
	}
	if _, ok := cfg.Security.Zones["trust2"]; !ok {
		t.Error("trust2 zone should exist after copy")
	}
}

func TestRenameConfig(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	cmds := []string{
		"interfaces eth0 unit 0 family inet address 10.0.0.1/24",
		"security zones security-zone oldname interfaces eth0.0",
	}
	for _, cmd := range cmds {
		if err := s.SetFromInput(cmd); err != nil {
			t.Fatalf("set %q: %v", cmd, err)
		}
	}
	if err := s.Rename(
		[]string{"security", "zones", "security-zone", "oldname"},
		[]string{"security", "zones", "security-zone", "newname"},
	); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	_, err := s.Commit()
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	cfg := s.ActiveConfig()
	if _, ok := cfg.Security.Zones["oldname"]; ok {
		t.Error("oldname should not exist after rename")
	}
	if _, ok := cfg.Security.Zones["newname"]; !ok {
		t.Error("newname should exist after rename")
	}
}

func TestCopyNotInConfigMode(t *testing.T) {
	s := newTestStore(t)
	err := s.Copy([]string{"a"}, []string{"b"})
	if err == nil || !strings.Contains(err.Error(), "not in configuration mode") {
		t.Errorf("expected config mode error, got: %v", err)
	}
}

func TestRenameNotInConfigMode(t *testing.T) {
	s := newTestStore(t)
	err := s.Rename([]string{"a"}, []string{"b"})
	if err == nil || !strings.Contains(err.Error(), "not in configuration mode") {
		t.Errorf("expected config mode error, got: %v", err)
	}
}

// #1526 — the DPDK retirement reject must fire at the Store boundary
// for both CommitCheck (raw error) and Commit (wrapped error). The
// gRPC and REST surfaces both forward Commit's wrapped text, so we
// lock in the wrapping contract here: any future change that drops
// the "commit check failed: " prefix from Commit or changes the
// underlying retirement substring breaks this test.
const dpdkRetirementSubstr = "the DPDK dataplane backend has been retired; use 'set system dataplane-type userspace' (see #1525)"

func TestCommit_RejectsDPDKDataplaneType(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := s.SetFromInput("system dataplane-type dpdk"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}

	// CommitCheck returns the raw compile-error text.
	_, ccErr := s.CommitCheck()
	if ccErr == nil {
		t.Fatal("CommitCheck succeeded for dataplane-type dpdk; expected retirement reject")
	}
	if !strings.Contains(ccErr.Error(), dpdkRetirementSubstr) {
		t.Fatalf("CommitCheck error = %q, want substring %q", ccErr.Error(), dpdkRetirementSubstr)
	}
	// CommitCheck should NOT prepend "commit check failed: " — the
	// wrapping happens in Commit, not CommitCheck.
	if strings.HasPrefix(ccErr.Error(), "commit check failed:") {
		t.Fatalf("CommitCheck unexpectedly wrapped its error with 'commit check failed:' prefix: %q", ccErr.Error())
	}

	// Commit wraps the same compile error as "commit check failed: ...".
	_, cmErr := s.Commit()
	if cmErr == nil {
		t.Fatal("Commit succeeded for dataplane-type dpdk; expected retirement reject")
	}
	if !strings.Contains(cmErr.Error(), dpdkRetirementSubstr) {
		t.Fatalf("Commit error = %q, want substring %q", cmErr.Error(), dpdkRetirementSubstr)
	}
	// Lock the wrap surface so gRPC / REST contract drift is caught.
	if !strings.HasPrefix(cmErr.Error(), "commit check failed:") {
		t.Fatalf("Commit error missing 'commit check failed:' wrap prefix: %q", cmErr.Error())
	}
}

// TestCommit_AcceptsUserspaceDataplaneType is the negative control:
// the migration target (`set system dataplane-type userspace`) must
// commit cleanly without warnings about DPDK retirement.
func TestCommit_AcceptsUserspaceDataplaneType(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := s.SetFromInput("system dataplane-type userspace"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if _, err := s.CommitCheck(); err != nil {
		t.Fatalf("CommitCheck for userspace dataplane-type: %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit for userspace dataplane-type: %v", err)
	}
}

// TestLoad_PersistedDPDKDataplaneTypeRewrittenByLoad exercises the
// rewriteRetiredDataplaneType bridge introduced by #1558 (eBPF
// retirement) and re-confirmed for DPDK at #1528. A pre-#1526
// persisted `set system dataplane-type dpdk` must survive
// Store.Load() so the daemon can come up rather than failing to
// load entirely (operational blackout). The rewrite strips the
// retired leaf so the compiled config carries no DataplaneType
// (defaulting to userspace); the operator's next commit persists
// the cleanup. See pkg/configstore/dataplane_retire.go.
func TestLoad_PersistedDPDKDataplaneTypeRewrittenByLoad(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config")

	// Write a tree containing dataplane-type dpdk directly via
	// the db API (commit path would reject it).
	writer := newTestStoreAt(t, cfgPath)
	tree := &config.ConfigTree{}
	path, err := config.ParseSetCommand("set system dataplane-type dpdk")
	if err != nil {
		t.Fatalf("ParseSetCommand: %v", err)
	}
	if err := tree.SetPath(path); err != nil {
		t.Fatalf("SetPath: %v", err)
	}
	if err := writer.db.WriteActive(tree); err != nil {
		t.Fatalf("db.WriteActive: %v", err)
	}

	// Fresh reader store on the same disk path. Load() must succeed
	// because rewriteRetiredDataplaneType strips the dpdk leaf to
	// empty before compile (#1558 / #1525). ActiveConfig must be
	// non-nil with DataplaneType empty (defaults to userspace).
	reader := newTestStoreAt(t, cfgPath)
	if err := reader.Load(); err != nil {
		t.Fatalf("Load() rejected persisted dpdk dataplane-type: %v", err)
	}
	active := reader.ActiveConfig()
	if active == nil {
		t.Fatal("ActiveConfig() returned nil after Load with persisted dpdk")
	}
	if active.System.DataplaneType != "" {
		t.Fatalf("ActiveConfig().System.DataplaneType = %q, want \"\" (rewritten by Load)",
			active.System.DataplaneType)
	}
}

// TestLoad_PersistedDPDKDataplaneTypeWithSubStanzaRewrittenByLoad
// (Codex r5 lock-in from plan v3.2/v3.3) — exercises the full
// comprehensive legacy DPDK shape (dataplane-type + cores + memory +
// socket-mem + rx-mode + ports + adaptive sub-block) through
// Store.Load to confirm:
//
//  1. rewriteRetiredDataplaneType strips `system dataplane-type dpdk`
//     to empty so the compile path succeeds.
//  2. The orphan sub-stanza (cores, memory, ports, etc) does not
//     cause schemaValidateExpandedTree or compileExpanded to fail.
//
// If a future PR types a `system dataplane` leaf in setSchema (so
// config.SchemaValidate's generic walker validates it), this test fires
// and forces the author to coordinate with rewriteRetiredDataplaneType.
func TestLoad_PersistedDPDKDataplaneTypeWithSubStanzaRewrittenByLoad(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config")

	writer := newTestStoreAt(t, cfgPath)
	tree := &config.ConfigTree{}
	for _, line := range []string{
		"set system dataplane-type dpdk",
		"set system dataplane cores 2-5",
		"set system dataplane memory 2048",
		"set system dataplane socket-mem \"1024,1024\"",
		"set system dataplane rx-mode adaptive",
		"set system dataplane rx-mode idle-threshold 256",
		"set system dataplane rx-mode resume-threshold 32",
		"set system dataplane rx-mode sleep-timeout 100",
		"set system dataplane ports 0000:03:00.0 interface wan0",
		"set system dataplane ports 0000:03:00.0 rx-mode polling",
		"set system dataplane ports 0000:03:00.0 cores 2-3",
		"set system dataplane ports 0000:06:00.0 interface trust0",
	} {
		path, err := config.ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	if err := writer.db.WriteActive(tree); err != nil {
		t.Fatalf("db.WriteActive: %v", err)
	}

	reader := newTestStoreAt(t, cfgPath)
	if err := reader.Load(); err != nil {
		t.Fatalf("Load() rejected persisted full DPDK sub-stanza: %v", err)
	}
	active := reader.ActiveConfig()
	if active == nil {
		t.Fatal("ActiveConfig() returned nil after Load with persisted full DPDK sub-stanza")
	}
	if active.System.DataplaneType != "" {
		t.Fatalf("ActiveConfig().System.DataplaneType = %q, want \"\" (rewritten by Load)",
			active.System.DataplaneType)
	}
}
