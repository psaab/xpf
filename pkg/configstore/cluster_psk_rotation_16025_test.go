package configstore

import (
	"strings"
	"testing"
)

// #16025 fold 2: the staged-rotation exception must be gated on the
// persisted/current primary, not candidate shape. A fresh store whose
// first candidate authors short-primary + strong-additional must reject;
// the same candidate commits only after a short-primary config is the
// active/persisted state (seeded here via tolerant Load, as an upgraded
// legacy cluster would be).

func setCluster16025(t *testing.T, s *Store, lines ...string) {
	t.Helper()
	for _, line := range lines {
		if err := s.SetFromInput(line); err != nil {
			t.Fatalf("SetFromInput %q: %v", line, err)
		}
	}
}

func TestFreshCandidateShortPrimaryStagedStrongRejects16025(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	setCluster16025(t, s,
		"chassis cluster cluster-id 1",
		"chassis cluster authentication-key legacy-short",
		"chassis cluster additional-authentication-key 1234567890123456",
	)
	if _, err := s.CommitCheck(); err == nil {
		t.Fatal("fresh candidate with short primary + strong additional passed CommitCheck; exception requires persisted short primary")
	} else if !strings.Contains(err.Error(), "authentication-key") {
		t.Fatalf("fresh rejection should name authentication-key: %v", err)
	}
	if _, err := s.Commit(); err == nil {
		t.Fatal("fresh candidate committed short primary with staged strong additional")
	}
}

func TestPersistedShortPrimaryStagedRotationCommits16025(t *testing.T) {
	s := newTestStore(t)
	// Directly seed compiled/active via SyncApply (tolerant ingress).
	text := "chassis {\n cluster {\n  cluster-id 1;\n  authentication-key legacy-short;\n }\n}\n"
	if _, err := s.SyncApply(text, nil); err != nil {
		t.Fatalf("SyncApply seeding short-primary active: %v", err)
	}
	if s.ActiveConfig() == nil {
		t.Fatal("seeded active config nil")
	}
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	setCluster16025(t, s,
		"chassis cluster cluster-id 1",
		"chassis cluster authentication-key legacy-short",
		"chassis cluster additional-authentication-key 1234567890123456",
	)
	if _, err := s.CommitCheck(); err != nil {
		t.Fatalf("persisted short primary + staged strong additional rejected at CommitCheck: %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("persisted staged rotation rejected at Commit: %v", err)
	}
	s.ExitConfigure()
	// Steps 3/4: swap staged key into primary, old to additional.
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure 2: %v", err)
	}
	setCluster16025(t, s,
		"chassis cluster cluster-id 1",
		"chassis cluster authentication-key 1234567890123456",
		"chassis cluster additional-authentication-key legacy-short",
	)
	if _, err := s.Commit(); err != nil {
		t.Fatalf("swap-to-strong primary commit rejected: %v", err)
	}
}
