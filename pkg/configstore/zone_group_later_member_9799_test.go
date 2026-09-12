package configstore

import (
	"strings"
	"testing"
)

// TestLaterZoneGroupMemberThroughTheStore9799 is #9799's acceptance through the
// Store: show of the later member prints the group, and delete and deactivate
// refuse it with guidance instead of reporting no node.
func TestLaterZoneGroupMemberThroughTheStore9799(t *testing.T) {
	s := newTestStore(t)
	enterCfg(t, s)
	if err := s.LoadOverride("security { zones { security-zone [ zga zgb ] { tcp-rst; } } }\n"); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if got := s.ShowCandidatePath([]string{"security", "zones", "security-zone", "zgb"}); !strings.Contains(got, "zga") || !strings.Contains(got, "tcp-rst") {
		t.Fatalf("show of the later member must print the group, got %q", got)
	}
	before := s.ShowCandidateSet()
	if err := s.DeleteFromInput("security zones security-zone zgb"); err == nil || !strings.Contains(err.Error(), "#9799") {
		t.Fatalf("delete of the later member: want the #9799 refusal, got %v", err)
	}
	if err := s.DeactivateFromInput("security zones security-zone zgb"); err == nil || !strings.Contains(err.Error(), "#9799") {
		t.Fatalf("deactivate of the later member: want the #9799 refusal, got %v", err)
	}
	if after := s.ShowCandidateSet(); after != before {
		t.Fatalf("a refused edit changed the candidate:\nbefore %s\nafter  %s", before, after)
	}
}
