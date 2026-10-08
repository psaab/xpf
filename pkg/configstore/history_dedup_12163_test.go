package configstore

import (
	"strings"
	"testing"
)

// TestSyncApplyIdenticalRepushPreservesDistinctHistory12163 pins the #12163
// store contract: a persistent apply NACK must not churn rollback history.
//
// The daemon's configSyncReconcileLoop re-pushes the peer config every 30 s,
// and the #4957 converged shortcut requires ActiveApplied() — so a config
// whose apply keeps failing falls through to syncAndApply on EVERY tick.
// SyncApply promotes active BEFORE applyConfigLocked runs, so each failed
// retry re-pushes the identical text. Without dedup, every re-push evicts one
// distinct slot, and 50 ticks (~25 min) wipe the whole 50-slot ring: failover
// then has no rollback targets left.
//
// This fixture mirrors that storm at the store seam: seed three distinct
// configs, never stamp the applied marker (persistent NACK), then re-push the
// current text more times than the ring holds. The distinct predecessors must
// survive, and a later DIFFERENT config must still push (dedup only skips
// identical-text re-pushes).
func TestSyncApplyIdenticalRepushPreservesDistinctHistory12163(t *testing.T) {
	s := newTestStore(t)
	confA := "system {\n    host-name node-a-12163;\n}\n"
	confB := "system {\n    host-name node-b-12163;\n}\n"
	confC := "system {\n    host-name node-c-12163;\n}\n"
	for _, conf := range []string{confA, confB, confC} {
		if _, err := s.SyncApply(conf, nil); err != nil {
			t.Fatalf("SyncApply seed: %v", err)
		}
	}
	if s.ActiveApplied() {
		t.Fatal("fixture: promoted-but-unstamped sync must read not-applied (the NACK premise)")
	}
	before := len(s.ListHistory())

	// The NACK storm: re-push the CURRENT text more times than the ring
	// holds. 60 pushes into a 50-slot ring evicts every distinct entry
	// without dedup.
	for i := 0; i < 60; i++ {
		if _, err := s.SyncApply(confC, nil); err != nil {
			t.Fatalf("SyncApply identical re-push %d: %v", i, err)
		}
	}

	entries := s.ListHistory()
	for _, marker := range []string{"node-a-12163", "node-b-12163"} {
		found := false
		for _, e := range entries {
			if e != nil && e.Config != nil && strings.Contains(e.Config.Format(), marker) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("distinct history entry %q evicted by identical re-pushes; "+
				"rollback history must survive a persistent apply NACK", marker)
		}
	}
	if got := len(entries); got != before {
		t.Fatalf("identical re-pushes grew history: %d -> %d; want no growth "+
			"(each identical re-push must skip the history push)", before, got)
	}

	// A genuinely DIFFERENT config must still push (dedup is
	// identical-text only): the displaced C becomes the new head.
	confD := "system {\n    host-name node-d-12163;\n}\n"
	if _, err := s.SyncApply(confD, nil); err != nil {
		t.Fatalf("SyncApply distinct config: %v", err)
	}
	after := s.ListHistory()
	if len(after) != before+1 {
		t.Fatalf("distinct push history len = %d, want %d", len(after), before+1)
	}
	if after[0] == nil || after[0].Config == nil ||
		!strings.Contains(after[0].Config.Format(), "node-c-12163") {
		t.Fatalf("distinct push did not push the displaced config to the head")
	}
}
