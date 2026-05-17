package configstore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// newTestStore creates a Store backed by a temp file for testing.
func newTestStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	return New(path)
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
		"security zones security-zone trust interfaces eth0.0",
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
		"security zones security-zone trust interfaces eth0.0",
		"security zones security-zone trust interfaces eth1.0",
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
	s.SetFromInput("security zones security-zone trust interfaces eth0.0")
	if _, err := s.Commit(); err != nil {
		t.Fatal(err)
	}

	// Modify candidate
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
	s.SetFromInput("security zones security-zone trust interfaces eth0.0")
	cfg1, err := s.Commit()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg1.Security.Zones) != 1 {
		t.Fatalf("commit 1: expected 1 zone, got %d", len(cfg1.Security.Zones))
	}

	// Commit 2: add untrust zone
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
	s.SetFromInput("security zones security-zone trust interfaces eth0.0")
	if _, err := s.Commit(); err != nil {
		t.Fatal(err)
	}

	// Modify candidate
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
	s.SetFromInput("security zones security-zone trust interfaces eth0.0")
	if _, err := s.Commit(); err != nil {
		t.Fatal(err)
	}

	// Track rollback callback
	rollbackCalled := make(chan struct{}, 1)
	s.SetCentralRollbackHandler(func(cfg *config.Config) {
		rollbackCalled <- struct{}{}
	})

	// Commit confirmed with very short timeout (use CommitConfirmed with 1 min)
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
	s1 := New(path)
	if err := s1.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	s1.SetFromInput("security zones security-zone trust interfaces eth0.0")
	s1.SetFromInput("security zones security-zone untrust interfaces eth1.0")
	if _, err := s1.Commit(); err != nil {
		t.Fatal(err)
	}

	// Load in a new store
	s2 := New(path)
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

	s := New(path)
	if err := s.Load(); err != nil {
		t.Fatalf("Load should not error on non-existent file: %v", err)
	}
}

func TestRollbackFilesPersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")

	s := New(path)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}

	// Commit 1
	s.SetFromInput("security zones security-zone trust interfaces eth0.0")
	if _, err := s.Commit(); err != nil {
		t.Fatal(err)
	}

	// Commit 2
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
	s2 := New(path)
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
	s.SetFromInput("security zones security-zone trust interfaces eth0.0")
	if _, err := s.Commit(); err != nil {
		t.Fatal(err)
	}

	// Commit 2
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
	s.SetFromInput("security zones security-zone trust interfaces eth0.0")
	if _, err := s.Commit(); err != nil {
		t.Fatal(err)
	}

	// Load override replaces entire candidate
	hierConfig := `security {
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
	s.SetFromInput("security zones security-zone trust interfaces eth0.0")

	// Merge hierarchical config — should add untrust without removing trust
	hierConfig := `security {
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
	s.SetFromInput("security zones security-zone trust interfaces eth0.0")

	// Merge set-format commands
	setConfig := `set security zones security-zone untrust interfaces eth1.0
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

func TestLoadMergeWithDelete(t *testing.T) {
	s := newTestStore(t)

	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	s.SetFromInput("security zones security-zone trust interfaces eth0.0")
	s.SetFromInput("security zones security-zone untrust interfaces eth1.0")

	// Merge with delete command
	setConfig := `delete security zones security-zone untrust
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
	s.SetFromInput("security zones security-zone trust interfaces eth0.0")
	if _, err := s.Commit(); err != nil {
		t.Fatal(err)
	}

	// Commit 2: add untrust
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
	s.SetFromInput("security zones security-zone trust interfaces eth0.0")
	if _, err := s.Commit(); err != nil {
		t.Fatal(err)
	}

	// Second commit: add untrust zone
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

	// Create 5 archives with maxArchives=3
	for i := 0; i < 5; i++ {
		// Write with unique timestamps by using direct file creation
		filename := filepath.Join(archiveDir, "config-20260101-00000"+string(rune('0'+i))+".conf")
		os.MkdirAll(archiveDir, 0755)
		os.WriteFile(filename, []byte("test"), 0644)
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

	// Test with comments and blank lines
	s.ExitConfigure()
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	input2 := "# comment line\nset system host-name fw2\n\nset system domain-name example.com\nnot-a-set-line"
	count2, err := s.LoadSet(input2)
	if err != nil {
		t.Fatal(err)
	}
	if count2 != 2 {
		t.Errorf("expected 2 commands, got %d", count2)
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
	cmds := []string{
		"security zones security-zone trust interfaces eth0.0",
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
