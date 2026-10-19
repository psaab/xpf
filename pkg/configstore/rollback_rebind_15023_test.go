package configstore

// #15023 (A19-01): the #14578 rollback-metadata rebind hashed whatever
// bytes were on disk, so a stale or tombstoned slot was blessed and
// `rollback N` returned a different generation's config after restart,
// with the degraded flag cleared. The rebind must hash the in-memory
// Format(), rewrite diverged slots durably (or record an invalid
// identity), always record the tombstone marker for tombstones, and
// keep rollbackPersistDegraded set unless the slot was rewritten.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/fsatomic"
)

func tree15023(t *testing.T, host string) *config.ConfigTree {
	t.Helper()
	tree, errs := config.NewParser("system { host-name " + host + "; }\n").Parse()
	if len(errs) != 0 {
		t.Fatalf("parse tree for %q: %v", host, errs[0])
	}
	return tree
}

// seed15023 saves history [slot1, slot2, slot3] most-recent-first plus a
// durable active.json, so rebindRollbackMetadataLocked's precondition
// (caller just durably wrote active) holds.
func seed15023(t *testing.T, s *Store, hosts ...string) {
	t.Helper()
	// Push oldest-first; List() is most-recent-first.
	for i := len(hosts) - 1; i >= 0; i-- {
		s.history.Push(&HistoryEntry{Config: tree15023(t, hosts[i])})
	}
	s.saveRollbackFiles()
	if s.RollbackHistoryDegraded() {
		t.Fatal("PREMISE: seed saveRollbackFiles degraded")
	}
	activeTree := tree15023(t, "active")
	if err := s.writeActive(activeTree); err != nil {
		t.Fatalf("PREMISE: writeActive: %v", err)
	}
	s.active = activeTree
}

func staleSlotRebindFixture(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "xpf.conf")
	s := newTestStoreAt(t, path)
	max := s.history.MaxSize()
	s.history = NewHistory(max)
	seed15023(t, s, "hostA", "hostB", "hostC")
	// Simulate a prior slot-write failure / crash during a
	// commit-confirmed slot shift: slot 3 on disk still holds another
	// generation's config (hostStale), while the in-memory entry at
	// that index is hostC.
	if err := os.WriteFile(s.rollbackPath(3), []byte(tree15023(t, "hostStale").Format()), 0600); err != nil {
		t.Fatalf("PREMISE: corrupt slot 3: %v", err)
	}
	// A prior degraded state that a merely-successful rehash must not clear.
	s.rollbackPersistDegraded = true
	s.rebindRollbackMetadataLocked()
	return s, path
}

// Live leg: stale disk bytes at slot 3 must not be blessed. The slot is
// rewritten to the in-memory entry (hostC), so after restart rollback 3
// is hostC — never hostStale — and the degraded flag clears only because
// the slot was actually rewritten.
func TestRebindDoesNotBlessStaleLiveSlot_15023(t *testing.T) {
	s, path := staleSlotRebindFixture(t)

	disk, err := os.ReadFile(s.rollbackPath(3))
	if err != nil {
		t.Fatalf("read slot 3: %v", err)
	}
	if strings.Contains(string(disk), "hostStale") {
		t.Fatalf("slot 3 still holds the stale generation after rebind: %q", disk)
	}
	if !strings.Contains(string(disk), "hostC") {
		t.Fatalf("slot 3 was not rewritten to the in-memory entry hostC: %q", disk)
	}
	if s.RollbackHistoryDegraded() {
		t.Error("RollbackHistoryDegraded = true after the slot was durably rewritten, want false")
	}

	restarted := newTestStoreAt(t, path)
	restarted.loadRollbackHistory()
	entries := restarted.history.List()
	if len(entries) != 3 {
		t.Fatalf("loaded %d history entries, want 3", len(entries))
	}
	for i, want := range []string{"hostA", "hostB", "hostC"} {
		if entries[i].Config == nil {
			t.Fatalf("slot %d tombstoned after rebind, want %s", i+1, want)
		}
		if got := entries[i].Config.Format(); !strings.Contains(got, want) {
			t.Errorf("rollback %d = %q, want %s (stale generation blessed)", i+1, got, want)
		}
	}
}

// Fail-closed leg: when the diverged slot cannot be rewritten, the
// rebind must stay degraded and record an invalid identity so the next
// load tombstones the slot instead of admitting the stale bytes
// (rb3=hostB-or-REFUSED acceptance: here REFUSED).
func TestRebindStaysDegradedWhenStaleSlotRewriteFails_15023(t *testing.T) {
	path := filepath.Join(t.TempDir(), "xpf.conf")
	s := newTestStoreAt(t, path)
	max := s.history.MaxSize()
	s.history = NewHistory(max)
	seed15023(t, s, "hostA", "hostB", "hostC")
	if err := os.WriteFile(s.rollbackPath(3), []byte(tree15023(t, "hostStale").Format()), 0600); err != nil {
		t.Fatalf("PREMISE: corrupt slot 3: %v", err)
	}
	s.rollbackPersistDegraded = true

	restoreRollbackSeams(t)
	inner := rbWriteFileDurable
	rbWriteFileDurable = func(p string, data []byte, perm os.FileMode, opts ...fsatomic.Option) error {
		if filepath.Clean(p) == filepath.Clean(s.rollbackPath(3)) {
			return errors.New("injected slot 3 rewrite failure (ENOSPC)")
		}
		return inner(p, data, perm, opts...)
	}
	s.rebindRollbackMetadataLocked()
	rbWriteFileDurable = inner

	if !s.RollbackHistoryDegraded() {
		t.Error("RollbackHistoryDegraded = false after a failed stale-slot rewrite, want true (degraded stays set)")
	}

	restarted := newTestStoreAt(t, path)
	restarted.loadRollbackHistory()
	entries := restarted.history.List()
	if len(entries) != 3 {
		t.Fatalf("loaded %d history entries, want 3 positions preserved", len(entries))
	}
	if entries[0].Config == nil || !strings.Contains(entries[0].Config.Format(), "hostA") {
		t.Errorf("slot 1 should stay hostA, got %#v", entries[0])
	}
	if entries[1].Config == nil || !strings.Contains(entries[1].Config.Format(), "hostB") {
		t.Errorf("slot 2 should stay hostB, got %#v", entries[1])
	}
	if entries[2].Config != nil {
		t.Errorf("slot 3 admitted the stale generation after a failed rewrite: %s; want tombstone (REFUSED)", entries[2].Config.Format())
	}
}

// Tombstone leg: a tombstone entry whose slot file still holds a prior
// generation's config (its marker write previously failed) must always
// record — and restore — the marker, never hash the old disk bytes.
func TestRebindDoesNotBlessTombstonedSlot_15023(t *testing.T) {
	path := filepath.Join(t.TempDir(), "xpf.conf")
	s := newTestStoreAt(t, path)
	max := s.history.MaxSize()
	s.history = NewHistory(max)
	seed15023(t, s, "hostA", "hostB", "hostC")

	// Slot 2 becomes a tombstone in memory, but its file still holds
	// hostB's bytes (the marker write never landed).
	entries := s.history.List()
	entries[1].Config = nil
	if got, err := os.ReadFile(s.rollbackPath(2)); err != nil || !strings.Contains(string(got), "hostB") {
		t.Fatalf("PREMISE: slot 2 should still hold hostB bytes, got %q err=%v", got, err)
	}
	s.rollbackPersistDegraded = true
	s.rebindRollbackMetadataLocked()

	disk, err := os.ReadFile(s.rollbackPath(2))
	if err != nil {
		t.Fatalf("read slot 2: %v", err)
	}
	if string(disk) != rollbackTombstoneMarker {
		t.Fatalf("slot 2 = %q after rebind, want the tombstone marker %q", disk, rollbackTombstoneMarker)
	}
	if s.RollbackHistoryDegraded() {
		t.Error("RollbackHistoryDegraded = true after the marker was durably rewritten, want false")
	}

	restarted := newTestStoreAt(t, path)
	restarted.loadRollbackHistory()
	loaded := restarted.history.List()
	if len(loaded) != 3 {
		t.Fatalf("loaded %d history entries, want 3", len(loaded))
	}
	if loaded[0].Config == nil || !strings.Contains(loaded[0].Config.Format(), "hostA") {
		t.Errorf("slot 1 should stay hostA, got %#v", loaded[0])
	}
	if loaded[1].Config != nil {
		t.Errorf("slot 2 resurrected a config after rebind: %s; want tombstone", loaded[1].Config.Format())
	}
	if loaded[2].Config == nil || !strings.Contains(loaded[2].Config.Format(), "hostC") {
		t.Errorf("slot 3 should stay hostC, got %#v", loaded[2])
	}
}

// Control: a healthy ladder whose disk bytes already match memory is
// rebound without rewriting any slot file (identities unchanged) and
// stays healthy after restart — neighbouring legitimate behaviour.
func TestRebindHealthyLadderUnchanged_15023(t *testing.T) {
	path := filepath.Join(t.TempDir(), "xpf.conf")
	s := newTestStoreAt(t, path)
	max := s.history.MaxSize()
	s.history = NewHistory(max)
	seed15023(t, s, "hostA", "hostB", "hostC")

	before := make([]rollbackSlotIdentity, 3)
	for i := 1; i <= 3; i++ {
		id, ok := rollbackSlotIdentityForPath(s.rollbackPath(i))
		if !ok {
			t.Fatalf("PREMISE: slot %d has no identity", i)
		}
		before[i-1] = id
	}
	s.rebindRollbackMetadataLocked()
	if s.RollbackHistoryDegraded() {
		t.Fatal("healthy rebind degraded")
	}
	for i := 1; i <= 3; i++ {
		id, ok := rollbackSlotIdentityForPath(s.rollbackPath(i))
		if !ok || id != before[i-1] {
			t.Errorf("slot %d identity changed on a no-op rebind: before=%+v after=%+v ok=%v", i, before[i-1], id, ok)
		}
	}

	restarted := newTestStoreAt(t, path)
	restarted.loadRollbackHistory()
	entries := restarted.history.List()
	if len(entries) != 3 {
		t.Fatalf("loaded %d history entries, want 3", len(entries))
	}
	for i, want := range []string{"hostA", "hostB", "hostC"} {
		if entries[i].Config == nil || !strings.Contains(entries[i].Config.Format(), want) {
			t.Errorf("rollback %d broken on healthy rebind: %#v, want %s", i+1, entries[i], want)
		}
	}
}
