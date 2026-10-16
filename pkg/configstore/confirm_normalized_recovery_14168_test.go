package configstore

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #14168: Store.Load normalizes the active tree it reads from disk
// (rewriteRetiredDataplaneType + SanitizeTreeControlChars) BEFORE
// recoverPendingConfirmLocked compares GuardedHash/PreviousHash against
// guardedConfigHash(s.active). A record armed by an older build binds the
// RAW on-disk tree, so a guarded generation that needed either rewrite was
// misclassified as stale and its auto-rollback was discarded. The PrevTree
// carried in the same record was likewise never normalized, so an expired
// rollback restored an uncompilable raw target.

func parse14168(t *testing.T, text string) *config.ConfigTree {
	t.Helper()
	tree, errs := config.NewParser(text).Parse()
	if len(errs) != 0 {
		t.Fatalf("parse fixture: %v", errs)
	}
	return tree
}

// legacyTree14168 is a tree as an older build could have committed it:
// a retired dataplane-type leaf and a control character in a free-text
// description — both repaired by Load on the active tree only (pre-fix).
func legacyTree14168(t *testing.T, host, desc string) *config.ConfigTree {
	t.Helper()
	return parse14168(t, "system {\n"+
		" host-name "+host+";\n"+
		" dataplane-type ebpf;\n"+
		"}\n"+
		"interfaces {\n"+
		" ge-0-0-0 {\n"+
		"  description \""+desc+"\";\n"+
		" }\n"+
		"}\n")
}

func seedLegacyConfirm14168(t *testing.T, path string, rec *confirmRecord, active *config.ConfigTree) {
	t.Helper()
	s0 := newTestStoreAt(t, path)
	if err := s0.db.WriteActive(active); err != nil {
		t.Fatalf("WriteActive: %v", err)
	}
	if err := s0.db.WriteConfirm(rec); err != nil {
		t.Fatalf("WriteConfirm: %v", err)
	}
}

func assertNormalized14168(t *testing.T, tree *config.ConfigTree, wantDesc string) {
	t.Helper()
	if tree == nil {
		t.Fatal("tree is nil")
	}
	// FormatSet renders set-style lines (quoted values expand escapes), so
	// assert on the hierarchical Format, which carries the raw value.
	formatted := tree.Format()
	if strings.Contains(formatted, "ebpf") {
		t.Fatalf("retired dataplane-type survived normalization:\n%s", formatted)
	}
	if strings.Contains(formatted, "new\nvalue") || strings.Contains(formatted, "old\nvalue") ||
		strings.Contains(formatted, "orig\nvalue") {
		t.Fatalf("control character survived normalization:\n%q", formatted)
	}
	if !strings.Contains(formatted, wantDesc) {
		t.Fatalf("sanitized description %q missing:\n%s", wantDesc, formatted)
	}
}

// Expired window: the guarded active needed Load normalization, and the
// rollback target needs it too. Recovery must recognize the generation via
// its raw on-disk hash and roll back to a compilable normalized target.
func TestConfirmRecoveryNormalizedActiveExpiredRollsBack14168(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	active := legacyTree14168(t, "Confirmed", "new\\nvalue")
	prev := legacyTree14168(t, "Base", "old\\nvalue")
	seedLegacyConfirm14168(t, path, &confirmRecord{
		Deadline:    time.Now().Add(-time.Minute),
		PrevTree:    prev,
		GuardedHash: guardedConfigHash(active),
	}, active)

	s := newTestStoreAt(t, path)
	if err := s.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if s.IsConfirmPending() {
		t.Fatal("expired window must not remain pending after recovery rollback")
	}
	cfg := s.ActiveConfig()
	if cfg == nil {
		t.Fatal("rollback to the normalized previous tree must compile")
	}
	if cfg.System.HostName != "Base" {
		t.Fatalf("host-name = %q, want Base (guarded generation was misclassified as stale)", cfg.System.HostName)
	}
	assertNormalized14168(t, s.ActiveTree(), "old value")
	// The rollback writes the normalized target durably.
	disk, _, err := s.db.ReadActiveMeta()
	if err != nil {
		t.Fatalf("ReadActiveMeta: %v", err)
	}
	assertNormalized14168(t, disk, "old value")
	if rec, err := s.db.ReadConfirm(); err != nil || rec != nil {
		t.Fatalf("confirm record after recovery = (%+v, %v), want absent", rec, err)
	}
}

// Live window: recovery must re-arm (not stale-drop), and the timer rollback
// must promote the normalized — compilable — previous tree.
func TestConfirmRecoveryNormalizedActiveLiveRearms14168(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	active := legacyTree14168(t, "Confirmed", "new\\nvalue")
	prev := legacyTree14168(t, "Base", "old\\nvalue")
	seedLegacyConfirm14168(t, path, &confirmRecord{
		Deadline:    time.Now().Add(30 * time.Minute),
		PrevTree:    prev,
		GuardedHash: guardedConfigHash(active),
	}, active)

	s := newTestStoreAt(t, path)
	if err := s.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	t.Cleanup(func() { s.CancelConfirmTimerForTesting() })
	if !s.IsConfirmPending() {
		t.Fatal("live window over a normalized active was dropped as stale; no rollback timer remains")
	}
	if got := s.ActiveConfig().System.HostName; got != "Confirmed" {
		t.Fatalf("live window must keep the guarded config standing, host-name = %q", got)
	}
	if s.confirmPrevTree == nil {
		t.Fatal("re-armed window has no rollback target")
	}
	assertNormalized14168(t, s.confirmPrevTree, "old value")
	if s.confirmPrevCfg == nil {
		t.Fatal("normalized rollback target must compile at re-arm")
	}

	s.InvokeRollbackTimerForTesting(s.ConfirmGenForTesting())
	if got := s.ActiveConfig().System.HostName; got != "Base" {
		t.Fatalf("timer rollback host-name = %q, want Base", got)
	}
	assertNormalized14168(t, s.ActiveTree(), "old value")
}

// Provisional record: the candidate is not yet durable, so the disk active
// is the PREVIOUS generation. Its raw hash (PreviousHash) must match the
// normalized effective tree, and the previous deadline (expired) governs.
func TestConfirmRecoveryNormalizedPreviousAlias14168(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	diskActive := legacyTree14168(t, "Pending", "new\\nvalue")
	candidate := legacyTree14168(t, "Candidate", "new\\nvalue")
	prev := legacyTree14168(t, "Original", "orig\\nvalue")
	seedLegacyConfirm14168(t, path, &confirmRecord{
		Deadline:         time.Now().Add(30 * time.Minute),
		PreviousDeadline: time.Now().Add(-time.Minute),
		PrevTree:         prev,
		GuardedHash:      guardedConfigHash(candidate),
		PreviousHash:     guardedConfigHash(diskActive),
	}, diskActive)

	s := newTestStoreAt(t, path)
	if err := s.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if s.IsConfirmPending() {
		t.Fatal("expired previous-generation window must roll back, not re-arm on the candidate deadline")
	}
	if got := s.ActiveConfig().System.HostName; got != "Original" {
		t.Fatalf("host-name = %q, want Original (PreviousHash alias was lost to normalization)", got)
	}
	assertNormalized14168(t, s.ActiveTree(), "orig value")
}

// First-commit rules stay separate: a FIRST window whose guarded candidate
// needed normalization still rolls back to the never-committed marker,
// rather than being stale-dropped into a permanent first commit.
func TestConfirmRecoveryNormalizedFirstCommit14168(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	active := legacyTree14168(t, "FirstEver", "new\\nvalue")
	seedLegacyConfirm14168(t, path, &confirmRecord{
		Deadline:    time.Now().Add(-time.Minute),
		PrevTree:    &config.ConfigTree{},
		FirstCommit: true,
		GuardedHash: guardedConfigHash(active),
	}, active)

	s := newTestStoreAt(t, path)
	if err := s.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if s.EverCommitted() {
		t.Fatal("expired FIRST window over a normalized candidate was stale-dropped; the unconfirmed first commit now stands as committed")
	}
	if s.IsConfirmPending() {
		t.Fatal("expired FIRST window must not remain pending")
	}
	if rec, err := s.db.ReadConfirm(); err != nil || rec != nil {
		t.Fatalf("confirm record after FIRST recovery = (%+v, %v), want absent", rec, err)
	}
}

// Control: normalization aliases must not weaken the #5835 stale guard. A
// record guarding an unrelated generation is still discarded.
func TestConfirmRecoveryNormalizedStaleStillDropped14168(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	active := legacyTree14168(t, "Confirmed", "new\\nvalue")
	other := legacyTree14168(t, "Other", "old\\nvalue")
	prev := legacyTree14168(t, "Base", "old\\nvalue")
	seedLegacyConfirm14168(t, path, &confirmRecord{
		Deadline:     time.Now().Add(-time.Minute),
		PrevTree:     prev,
		GuardedHash:  guardedConfigHash(other),
		PreviousHash: guardedConfigHash(other),
	}, active)

	s := newTestStoreAt(t, path)
	if err := s.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if s.IsConfirmPending() {
		t.Fatal("stale record must not re-arm")
	}
	if got := s.ActiveConfig().System.HostName; got != "Confirmed" {
		t.Fatalf("stale record resurrected a rollback: host-name = %q, want Confirmed", got)
	}
}
