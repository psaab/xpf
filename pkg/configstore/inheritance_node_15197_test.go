package configstore

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15197 A03-01 at the store layer: the Store knows its cluster node ID
// (SetNodeID, from /etc/xpf/node-id) but the Show*Inheritance renderers
// never threaded it into the formatters, so every ${node} HA config fell
// back to the raw tree and expansion failures were silent.

const nodeInheritStoreText15197 = `groups {
    node0 { system { host-name fw0; } }
    node1 { system { host-name fw1; } }
}
apply-groups "${node}";
system { domain-name example.com; }
`

func storeWithActive15197(t *testing.T, nodeID int, text string) *Store {
	t.Helper()
	s := newTestStore(t)
	if nodeID >= 0 {
		s.SetNodeID(nodeID)
	}
	tree, perrs := config.NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture must parse: %v", perrs)
	}
	// Install as candidate + active via the store's own fields is not
	// exported; use EnterConfigure + candidate mutation through the
	// public commit path instead: load the text as the candidate.
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	// Replace candidate tree contents.
	s.mu.Lock()
	*s.candidate = *tree
	s.mu.Unlock()
	return s
}

func TestShowCandidateInheritanceUsesStoreNode15197(t *testing.T) {
	s := storeWithActive15197(t, 1, nodeInheritStoreText15197)
	out, err := s.ShowCandidateInheritance()
	if err != nil {
		t.Fatalf("ShowCandidateInheritance: %v", err)
	}
	if !strings.Contains(out, "was inherited from group 'node1'") {
		t.Errorf("candidate inheritance must annotate node1:\n%s", out)
	}
	if !strings.Contains(out, "host-name fw1") || strings.Contains(out, "host-name fw0") {
		t.Errorf("candidate inheritance must show fw1 only:\n%s", out)
	}
}

func TestShowCandidatePathInheritanceUsesStoreNode15197(t *testing.T) {
	s := storeWithActive15197(t, 1, nodeInheritStoreText15197)
	out, err := s.ShowCandidatePathInheritance([]string{"system"})
	if err != nil {
		t.Fatalf("ShowCandidatePathInheritance: %v", err)
	}
	if !strings.Contains(out, "host-name fw1") {
		t.Errorf("candidate path inheritance must show fw1:\n%s", out)
	}
	if strings.Contains(out, "host-name fw0") {
		t.Errorf("candidate path inheritance leaked fw0:\n%s", out)
	}
}

func TestShowInheritanceRedactedUsesStoreNode15197(t *testing.T) {
	s := storeWithActive15197(t, 1, nodeInheritStoreText15197)
	out, err := s.ShowCandidateInheritanceRedacted([]string{"system"})
	if err != nil {
		t.Fatalf("ShowCandidateInheritanceRedacted: %v", err)
	}
	if !strings.Contains(out, "host-name fw1") || strings.Contains(out, "host-name fw0") {
		t.Errorf("redacted path inheritance must show fw1 only:\n%s", out)
	}
}

func TestShowActiveInheritanceUsesStoreNode15197(t *testing.T) {
	s := storeWithActive15197(t, 0, nodeInheritStoreText15197)
	// Promote candidate to active for the active-view check.
	s.mu.Lock()
	s.active = s.candidate.Clone()
	s.mu.Unlock()
	out, err := s.ShowActiveInheritance()
	if err != nil {
		t.Fatalf("ShowActiveInheritance: %v", err)
	}
	if !strings.Contains(out, "was inherited from group 'node0'") {
		t.Errorf("active inheritance must annotate node0:\n%s", out)
	}
	out, err = s.ShowActivePathInheritance([]string{"system"})
	if err != nil {
		t.Fatalf("ShowActivePathInheritance: %v", err)
	}
	if !strings.Contains(out, "host-name fw0") || strings.Contains(out, "host-name fw1") {
		t.Errorf("active path inheritance must show fw0 only:\n%s", out)
	}
	out, err = s.ShowActiveInheritanceRedacted([]string{"system"})
	if err != nil {
		t.Fatalf("ShowActiveInheritanceRedacted: %v", err)
	}
	if !strings.Contains(out, "host-name fw0") || strings.Contains(out, "host-name fw1") {
		t.Errorf("redacted active inheritance must show fw0 only:\n%s", out)
	}
}

func TestShowInheritanceUndefinedGroupErrors15197(t *testing.T) {
	text := `groups { G { system { host-name fw0; } } } apply-groups missing; system { domain-name example.com; }`
	s := storeWithActive15197(t, 1, text)
	if out, err := s.ShowCandidateInheritance(); err == nil {
		t.Fatalf("undefined group must error, got:\n%s", out)
	}
	if out, err := s.ShowCandidatePathInheritance([]string{"system"}); err == nil {
		t.Fatalf("path: undefined group must error, got:\n%s", out)
	}
}
