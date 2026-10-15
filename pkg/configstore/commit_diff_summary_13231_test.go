package configstore

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestCommitDiffSummaryDuplicateLines_13231 pins multiset correctness:
// a statement present once in active and twice in candidate is one addition,
// even though the old map[string]bool set collapsed the duplicate.
func TestCommitDiffSummaryDuplicateLines_13231(t *testing.T) {
	s := newTestStore(t)
	s.active = &config.ConfigTree{Children: []*config.Node{
		{Keys: []string{"system"}, Children: []*config.Node{{Keys: []string{"host-name", "fw"}, IsLeaf: true}}},
	}}
	s.candidate = &config.ConfigTree{Children: []*config.Node{
		{Keys: []string{"system"}, Children: []*config.Node{
			{Keys: []string{"host-name", "fw"}, IsLeaf: true},
			{Keys: []string{"host-name", "fw"}, IsLeaf: true},
		}},
	}}
	if got, want := s.CommitDiffSummary(), "1 statement(s) changed (1 added, 0 removed)"; got != want {
		t.Fatalf("duplicate-line diff = %q, want %q", got, want)
	}
	// Reverse: duplicate removal counts once per extra occurrence.
	s.active, s.candidate = s.candidate, s.active
	if got, want := s.CommitDiffSummary(), "1 statement(s) changed (0 added, 1 removed)"; got != want {
		t.Fatalf("duplicate-line reverse diff = %q, want %q", got, want)
	}
}
