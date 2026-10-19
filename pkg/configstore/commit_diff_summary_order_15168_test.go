package configstore

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15168 (B24-01): CommitDiffSummary sorted the flat set lines before
// comparing, so a pure reorder of first-match policies counted as zero
// changes. It must be order-aware: a moved ordered sibling counts as one
// removed + one added statement.

func policyTree15168(order []string) *config.ConfigTree {
	policies := &config.Node{Keys: []string{"policies"}}
	for _, name := range order {
		action := "permit"
		if name == "deny-ssh" {
			action = "deny"
		}
		policies.Children = append(policies.Children, &config.Node{
			Keys: []string{"policy", name},
			Children: []*config.Node{
				{Keys: []string{"then", action}, IsLeaf: true},
			},
		})
	}
	return &config.ConfigTree{Children: []*config.Node{
		{Keys: []string{"security"}, Children: []*config.Node{policies}},
	}}
}

func TestCommitDiffSummaryReorder15168(t *testing.T) {
	s := newTestStore(t)
	s.active = policyTree15168([]string{"deny-ssh", "allow-all"})
	s.candidate = policyTree15168([]string{"allow-all", "deny-ssh"})
	if got := s.CommitDiffSummary(); got == "" {
		t.Fatalf("reordered first-match policies summarized as no changes; want non-empty")
	}
	// Identical order is the control: no changes.
	s.candidate = policyTree15168([]string{"deny-ssh", "allow-all"})
	if got := s.CommitDiffSummary(); got != "" {
		t.Fatalf("identical order summarized as changed: %q", got)
	}
}
