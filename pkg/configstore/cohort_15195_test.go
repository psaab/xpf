package configstore

import (
	"strings"
	"testing"
)

// #15195 A01-06 store leg: Store.Rename records rename ancestry (lineage)
// whenever RenamePath succeeds. With a missing source that partially matched
// a different object, the store both corrupted the candidate and recorded
// phantom lineage. After the fix the rename fails, the candidate is unchanged,
// and no ancestry is recorded.

func TestStoreRenameMissingSourceNoPhantomLineage_15195(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	// Build firewall filter F1/term T1 hierarchically via candidate load:
	// SetFromInput would build a different node shape; use the candidate tree
	// directly through a hierarchical set is not available, so author via
	// multiple flat sets that produce [filter F1] / [term T1] nodes.
	for _, cmd := range []string{
		"firewall filter F1 term T1 then accept",
		"firewall filter F1 term T2 then discard",
	} {
		if err := s.SetFromInput(cmd); err != nil {
			t.Fatalf("set %q: %v", cmd, err)
		}
	}
	before := s.candidate.Format()

	// Missing source: skips the F1 name key (names no node).
	src := []string{"firewall", "filter", "term", "T2"}
	dst := []string{"firewall", "filter", "term", "RENAMED"}
	if err := s.Rename(src, dst); err == nil {
		t.Fatalf("Store.Rename with missing source %v succeeded via partial match (#15195 A01-06)", src)
	} else if !strings.Contains(err.Error(), "source not found") {
		t.Fatalf("Store.Rename error = %q, want 'source not found'", err)
	}
	if got := s.candidate.Format(); got != before {
		t.Fatalf("failed store rename mutated candidate:\nbefore:\n%s\nafter:\n%s", before, got)
	}
	if n := len(s.PendingRenameAncestry()); n != 0 {
		t.Fatalf("failed rename recorded %d phantom ancestry entries (#15195 A01-06)", n)
	}

	// Legit control: exact rename still succeeds and records lineage.
	if err := s.Rename(
		[]string{"firewall", "filter", "F1", "term", "T2"},
		[]string{"firewall", "filter", "F1", "term", "T2x"}); err != nil {
		t.Fatalf("legit Store.Rename: %v", err)
	}
	if n := len(s.PendingRenameAncestry()); n != 1 {
		t.Fatalf("legit rename recorded %d ancestry entries, want 1", n)
	}
}
