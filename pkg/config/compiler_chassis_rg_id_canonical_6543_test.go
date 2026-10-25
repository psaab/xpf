package config

import "testing"

// #6543: two SPELLINGS of one redundancy-group id must compile to ONE record.
//
// `strconv.Atoi` maps `1`, `01`, `001` and `+1` to the same int, but the AST
// keeps them as distinct instances — and so did the compiler, which appended
// one *RedundancyGroup per instance. A config carrying
//
//	set chassis cluster redundancy-group 1 node 0 priority 200
//	set chassis cluster redundancy-group 01 preempt
//
// committed clean as TWO records with ID=1: one holding the operator's
// priority map and one holding an EMPTY map. Everything downstream keys
// redundancy groups by the int id, so cluster.Manager.UpdateConfig's id-keyed
// last-wins loop overwrote LocalPriority with the map-miss zero and node 0 ran
// RG 1 at priority 0 instead of 200. The #4880 priority-range gate could not
// catch it: it iterated the empty-map record and passed vacuously.
//
// FAIL-ON-REVERT: restore the per-instance
// `ch.Cluster.RedundancyGroups = append(ch.Cluster.RedundancyGroups, rg)`
// (i.e. drop the byID fold in compileChassis) and every "one record" assertion
// below sees 2.
//
// The runtime half of this property — that the merged record is the one
// cluster.Manager actually elects from — is bound in
// pkg/cluster/rg_id_canonical_6543_test.go.

func rgSpellingSetLines(spellings ...string) []string {
	lines := []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key test-cluster-psk-6543",
		"set chassis cluster node 0",
	}
	// The FIRST spelling carries the node priorities; every later spelling
	// carries a different statement, so a record that displaces another is
	// visibly missing one half.
	lines = append(lines,
		"set chassis cluster no-private-rg-election",
		"set chassis cluster redundancy-group "+spellings[0]+" node 0 priority 200",
		"set chassis cluster redundancy-group "+spellings[0]+" node 1 priority 100")
	for _, s := range spellings[1:] {
		lines = append(lines, "set chassis cluster redundancy-group "+s+" preempt")
	}
	return lines
}

// compileRGs compiles the set lines and returns the redundancy groups.
func compileRGs(t *testing.T, lines []string) []*RedundancyGroup {
	t.Helper()
	cfg, err := CompileConfig(buildTree(t, lines))
	if err != nil {
		t.Fatalf("commit rejected: %v", err)
	}
	if cfg.Chassis.Cluster == nil {
		t.Fatal("no chassis cluster compiled")
	}
	return cfg.Chassis.Cluster.RedundancyGroups
}

// TestTwoSpellingsOfOneRGIDCompileToOneRecord is the core RED-on-revert.
func TestTwoSpellingsOfOneRGIDCompileToOneRecord(t *testing.T) {
	for _, alt := range []string{"01", "001", "+1"} {
		t.Run("alt="+alt, func(t *testing.T) {
			rgs := compileRGs(t, rgSpellingSetLines("1", alt))
			if len(rgs) != 1 {
				ids := make([]int, len(rgs))
				for i, rg := range rgs {
					ids[i] = rg.ID
				}
				t.Fatalf("spellings 1 and %s compiled to %d redundancy-group "+
					"records (ids %v) — everything downstream keys by the int "+
					"id, so the extra record silently displaces the real one",
					alt, len(rgs), ids)
			}
			rg := rgs[0]
			if rg.ID != 1 {
				t.Fatalf("merged record has id %d, want 1", rg.ID)
			}
			// Both halves survive the merge: the priorities from spelling `1`
			// AND the preempt from the alternate spelling.
			if got := rg.NodePriorities[0]; got != 200 {
				t.Errorf("node 0 priority %d, want 200 — the operator's "+
					"configured priority was lost in the merge", got)
			}
			if got := rg.NodePriorities[1]; got != 100 {
				t.Errorf("node 1 priority %d, want 100", got)
			}
			if !rg.Preempt {
				t.Errorf("preempt from spelling %q was lost in the merge", alt)
			}
		})
	}
}

// TestThreeSpellingsOfOneRGIDCompileToOneRecord: the fold is not a
// two-instance special case.
func TestThreeSpellingsOfOneRGIDCompileToOneRecord(t *testing.T) {
	rgs := compileRGs(t, rgSpellingSetLines("1", "01", "001"))
	if len(rgs) != 1 {
		t.Fatalf("three spellings of id 1 compiled to %d records", len(rgs))
	}
	if rgs[0].NodePriorities[0] != 200 || !rgs[0].Preempt {
		t.Fatalf("merged record lost a half: %+v", rgs[0])
	}
}

// TestRepeatedHierarchicalRGBlockCompilesToOneRecord: the SAME spelling
// repeated as two hierarchical blocks is two AST nodes too (SetPath merges
// same-name flat-set children, the hierarchical parser does not), so it hit
// the identical split. Junos merges repeated blocks; so must this.
func TestRepeatedHierarchicalRGBlockCompilesToOneRecord(t *testing.T) {
	src := `chassis {
    cluster {
        cluster-id 1;
        authentication-key test-cluster-psk-6543;
        node 0;
        redundancy-group 1 {
            node 0 priority 200;
        }
        no-private-rg-election;
        redundancy-group 1 {
            preempt;
        }
    }
}
`
	tree, perrs := NewParser(src).Parse()
	if len(perrs) != 0 {
		t.Fatalf("parse: %v", perrs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("commit rejected: %v", err)
	}
	rgs := cfg.Chassis.Cluster.RedundancyGroups
	if len(rgs) != 1 {
		t.Fatalf("a repeated hierarchical redundancy-group 1 block compiled "+
			"to %d records", len(rgs))
	}
	if rgs[0].NodePriorities[0] != 200 {
		t.Errorf("node 0 priority %d, want 200", rgs[0].NodePriorities[0])
	}
	if !rgs[0].Preempt {
		t.Errorf("preempt from the second block was lost")
	}
}

// TestDistinctRGIDsAreNotMerged is the negative control: the fold must key on
// the canonical id, not collapse every redundancy-group into one.
func TestDistinctRGIDsAreNotMerged(t *testing.T) {
	lines := []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key test-cluster-psk-6543",
		"set chassis cluster node 0",
		"set chassis cluster no-private-rg-election",
		"set chassis cluster redundancy-group 0 node 0 priority 200",
		"set chassis cluster redundancy-group 1 node 0 priority 150",
		"set chassis cluster redundancy-group 2 node 0 priority 100",
	}
	rgs := compileRGs(t, lines)
	if len(rgs) != 3 {
		t.Fatalf("three distinct ids compiled to %d records", len(rgs))
	}
	want := map[int]int{0: 200, 1: 150, 2: 100}
	for _, rg := range rgs {
		if got := rg.NodePriorities[0]; got != want[rg.ID] {
			t.Errorf("rg %d node 0 priority %d, want %d", rg.ID, got, want[rg.ID])
		}
	}
	// First-appearance order is preserved so the compiled slice (and every
	// first-error message derived from it) stays deterministic.
	for i, rg := range rgs {
		if rg.ID != i {
			t.Errorf("record %d has id %d — first-appearance order not preserved", i, rg.ID)
		}
	}
}

// TestPriorityRangeGateSeesTheMergedRecord: the #4880 gate must range-check
// the priorities the operator actually wrote, even when they were written
// under a different spelling from the rest of the group's body. Before the
// merge the out-of-range priority lived on one record while the gate happily
// passed over the other.
func TestPriorityRangeGateSeesTheMergedRecord(t *testing.T) {
	lines := []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key test-cluster-psk-6543",
		"set chassis cluster node 0",
		"set chassis cluster no-private-rg-election",
		"set chassis cluster redundancy-group 01 node 0 priority 255",
		"set chassis cluster redundancy-group 1 preempt",
	}
	_, err := CompileConfig(buildTree(t, lines))
	if err == nil {
		t.Fatal("commit accepted an out-of-range node priority (255, the " +
			"RFC 5798 IP-owner reserved value) written under an alternate " +
			"spelling of the redundancy-group id")
	}
	if !stringContainsAll(err.Error(), "redundancy-group 1", "priority 255", "out of range") {
		t.Fatalf("error %q does not name the out-of-range priority", err.Error())
	}
}
