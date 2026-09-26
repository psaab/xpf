package config

import (
	"strings"
	"testing"
)

// Tests for #10002: a NON-NUMERIC or explicitly empty chassis-cluster
// redundancy-group / per-RG node identity on the TOLERANT load / peer-sync
// path Atoi-coerced to 0 in compileChassis and merged into the real
// redundancy-group / node 0 record (leaf last-wins), silently mis-assigning
// cluster ownership / priority. The #5694 AST gate already warned (lenient) /
// refused (strict), and #9723 drops tolerant NEGATIVE rg ids — but a malformed
// alias still landed on zero or a quoted-empty node token bypassed the gate.
//
// The fix drops the malformed identity at fold time: a non-numeric or
// explicitly empty `redundancy-group <name>` instance contributes no record,
// and a non-numeric or explicitly empty RG-scoped `node <id>` statement writes
// no priority. The #5694 warning stays and names the tolerant drop/ignore, so
// the config still boots (#1960 no-brick). Strict commit still refuses via the
// pre-walk gate before compileChassis ever runs, so strict behavior is
// unchanged.
//
// FAIL-ON-REVERT: restore the Atoi-then-default-zero coercion in compileChassis
// / compileRGNodePriority and the alias cells below go RED — a phantom RG 0
// appears, or the real zero record's priorities / preempt carry the alias's
// values.

// TestTolerantPathDropsNonNumericRedundancyGroup_10002 proves a lone
// non-numeric RG identity mints NO phantom redundancy-group 0 on the tolerant
// path — and that the drop is announced rather than silent.
func TestTolerantPathDropsNonNumericRedundancyGroup_10002(t *testing.T) {
	cfg, err := CompileConfigLenient(flatTreeFromSets(t,
		"set chassis cluster redundancy-group reth0 node 0 priority 100"))
	if err != nil {
		t.Fatalf("the tolerant path must not refuse: %v", err)
	}
	if n := len(cfg.Chassis.Cluster.RedundancyGroups); n != 0 {
		t.Fatalf("tolerant compile minted %d redundancy group(s) from a non-numeric alias, want 0", n)
	}
	assertWarns(t, cfg.Warnings, "reth0", "redundancy-group instance is dropped")
}

// TestTolerantPathAliasDoesNotModifyRealZeroRecord_10002 is the load-bearing
// cell: an alias alongside a REAL redundancy-group 0 must leave the zero
// record's leaves untouched. The alias is compiled LAST (author order), so
// pre-fix its leaves overwrite the real ones via the leaf last-wins fold; the
// preempt assertion is additionally order-proof (no statement un-sets it).
func TestTolerantPathAliasDoesNotModifyRealZeroRecord_10002(t *testing.T) {
	cfg, err := CompileConfigLenient(flatTreeFromSets(t,
		"set chassis cluster redundancy-group 0 node 0 priority 200",
		"set chassis cluster redundancy-group 0 node 1 priority 100",
		"set chassis cluster redundancy-group reth0 node 0 priority 1",
		"set chassis cluster redundancy-group reth0 node 1 priority 2",
		"set chassis cluster redundancy-group reth0 preempt",
	))
	if err != nil {
		t.Fatalf("the tolerant path must not refuse: %v", err)
	}
	rgs := cfg.Chassis.Cluster.RedundancyGroups
	if len(rgs) != 1 || rgs[0].ID != 0 {
		t.Fatalf("want exactly redundancy-group 0, got %v", rgIDs(rgs))
	}
	if got := rgs[0].NodePriorities; len(got) != 2 || got[0] != 200 || got[1] != 100 {
		t.Fatalf("alias overwrote the real zero record's priorities: %v, want map[0:200 1:100]", got)
	}
	if rgs[0].Preempt {
		t.Fatal("alias set preempt on the real zero record")
	}
}

// TestTolerantPathDropsNonNumericNodeStatement_10002 proves a non-numeric
// per-RG node identity writes NO priority to node 0 — across the flat-set and
// the hierarchical packed one-liner shapes.
func TestTolerantPathDropsNonNumericNodeStatement_10002(t *testing.T) {
	t.Run("flat set", func(t *testing.T) {
		cfg, err := CompileConfigLenient(flatTreeFromSets(t,
			"set chassis cluster redundancy-group 1 node 0 priority 200",
			"set chassis cluster redundancy-group 1 node 1 priority 100",
			"set chassis cluster redundancy-group 1 node one priority 7",
		))
		if err != nil {
			t.Fatalf("the tolerant path must not refuse: %v", err)
		}
		rg := findRG(t, cfg, 1)
		if got := rg.NodePriorities; len(got) != 2 || got[0] != 200 || got[1] != 100 {
			t.Fatalf("alias node identity overwrote node 0's priority: %v, want map[0:200 1:100]", got)
		}
		assertWarns(t, cfg.Warnings, `"one"`, "node statement is ignored")
	})

	t.Run("hierarchical packed one-liner", func(t *testing.T) {
		cfg, err := CompileConfigLenient(hierTree(t, `chassis {
    cluster {
        redundancy-group 1 {
            node 0 priority 200;
            node foo priority 7;
        }
    }
}`))
		if err != nil {
			t.Fatalf("the tolerant path must not refuse: %v", err)
		}
		rg := findRG(t, cfg, 1)
		if got := rg.NodePriorities; len(got) != 1 || got[0] != 200 {
			t.Fatalf("alias node identity overwrote node 0's priority: %v, want map[0:200]", got)
		}
		assertWarns(t, cfg.Warnings, `"foo"`, "node statement is ignored")
	})
}

// TestTolerantPathNodeAliasAloneLeavesEmptyPriorities_10002 proves the drop
// granularity on the node side: a group whose identity is VALID is kept, while
// its malformed node statement contributes nothing (not a node-0 priority).
func TestTolerantPathNodeAliasAloneLeavesEmptyPriorities_10002(t *testing.T) {
	cfg, err := CompileConfigLenient(flatTreeFromSets(t,
		"set chassis cluster redundancy-group 2 node bogus priority 200"))
	if err != nil {
		t.Fatalf("the tolerant path must not refuse: %v", err)
	}
	rg := findRG(t, cfg, 2)
	if len(rg.NodePriorities) != 0 {
		t.Fatalf("malformed node statement wrote priorities %v, want none", rg.NodePriorities)
	}
	assertWarns(t, cfg.Warnings, `"bogus"`, "node statement is ignored")
}

// TestTolerantPathAliasAndNegativeDropsCompose_10002 proves the #10002
// non-numeric drop composes with the #9723 negative-id drop: a config carrying
// a valid RG 0, a negative RG, and an alias keeps exactly RG 0, unmodified,
// with both drops announced.
func TestTolerantPathAliasAndNegativeDropsCompose_10002(t *testing.T) {
	cfg, err := CompileConfigLenient(flatTreeFromSets(t,
		"set chassis cluster redundancy-group 0 node 0 priority 200",
		"set chassis cluster redundancy-group 0 node 1 priority 100",
		"set chassis cluster redundancy-group -1 node 0 priority 200",
		"set chassis cluster redundancy-group reth0 node 0 priority 1",
		"set chassis cluster redundancy-group reth0 preempt",
	))
	if err != nil {
		t.Fatalf("the tolerant path must not refuse: %v", err)
	}
	rgs := cfg.Chassis.Cluster.RedundancyGroups
	if len(rgs) != 1 || rgs[0].ID != 0 {
		t.Fatalf("want exactly redundancy-group 0, got %v", rgIDs(rgs))
	}
	if got := rgs[0].NodePriorities; len(got) != 2 || got[0] != 200 || got[1] != 100 {
		t.Fatalf("dropped identities modified the real zero record: %v", got)
	}
	if rgs[0].Preempt {
		t.Fatal("alias set preempt on the real zero record")
	}
	assertWarns(t, cfg.Warnings, "redundancy-group -1 dropped", "#9723")
	assertWarns(t, cfg.Warnings, `"reth0"`, "redundancy-group instance is dropped")
}

// TestStrictPathStillRefusesNonNumericIdentities_10002 pins the strict side of
// the #10002 contract: commit still hard-refuses a non-numeric RG / node
// identity, naming the token (unchanged — the pre-walk gate errors before
// compileChassis runs).
func TestStrictPathStillRefusesNonNumericIdentities_10002(t *testing.T) {
	cases := []struct {
		name string
		cmds []string
		want string
	}{
		{"non-numeric redundancy-group id",
			[]string{"set chassis cluster redundancy-group reth0 node 0 priority 100"},
			`"reth0"`},
		{"non-numeric per-RG node id",
			[]string{"set chassis cluster redundancy-group 1 node one priority 100"},
			`"one"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(flatTreeFromSets(t, tc.cmds...))
			if err == nil {
				t.Fatal("strict commit accepted a malformed chassis identity; want reject")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error should name the bad token %s: %v", tc.want, err)
			}
		})
	}
}

// TestTolerantPathKeepsLegitimateZeroIdentities_10002 is the false-drop guard:
// numeric zero spellings still fold into the real zero record on the tolerant
// path (the fix drops only tokens Atoi rejects, exactly the set the #5694
// gate flags).
func TestTolerantPathKeepsLegitimateZeroIdentities_10002(t *testing.T) {
	cfg, err := CompileConfigLenient(flatTreeFromSets(t,
		"set chassis cluster redundancy-group 0 node 0 priority 200",
		"set chassis cluster redundancy-group 00 node 1 priority 100",
	))
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	rgs := cfg.Chassis.Cluster.RedundancyGroups
	if len(rgs) != 1 || rgs[0].ID != 0 {
		t.Fatalf("want exactly redundancy-group 0, got %v", rgIDs(rgs))
	}
	if got := rgs[0].NodePriorities; len(got) != 2 || got[0] != 200 || got[1] != 100 {
		t.Fatalf("legitimate zero identities lost priorities: %v", got)
	}
}

// FAIL-ON-REVERT: without the compiled RG0 preempt gate, this strict config
// passes and CheckText's commit-check path would accept the day-0 config too.
func TestStrictPathRejectsRG0Preempt_10754(t *testing.T) {
	_, err := CompileConfig(flatTreeFromSets(t,
		"set chassis cluster authentication-key test-cluster-psk-10754",
		"set chassis cluster cluster-id 1",
		"set chassis cluster node 0",
		"set chassis cluster redundancy-group 0 node 0 priority 200",
		"set chassis cluster redundancy-group 0 node 1 priority 100",
		"set chassis cluster redundancy-group 0 preempt",
	))
	if err == nil || !strings.Contains(err.Error(), "redundancy-group 0 preempt") {
		t.Fatalf("strict compile must reject RG0 preempt with a specific error, got %v", err)
	}
}

// Existing persisted configs remain bootable, but RG0 preempt must not reach
// cluster election; supported RG1 preempt remains active.
func TestTolerantPathIgnoresRG0Preempt_10754(t *testing.T) {
	cfg, err := CompileConfigLenient(flatTreeFromSets(t,
		"set chassis cluster redundancy-group 00 preempt",
		"set chassis cluster redundancy-group 1 preempt",
	))
	if err != nil {
		t.Fatalf("tolerant compile must keep legacy config bootable: %v", err)
	}
	if findRG(t, cfg, 0).Preempt {
		t.Fatal("RG0 preempt must be ignored on the tolerant path")
	}
	if !findRG(t, cfg, 1).Preempt {
		t.Fatal("supported RG1 preempt was not preserved")
	}
	assertWarns(t, cfg.Warnings, "redundancy-group 0 preempt", "ignored on tolerant path")
}

// TestTolerantPathDropsQuotedEmptyNodeIdentity_10002 covers the explicit empty
// token shape (`node "" priority <v>`), which nodeVal intentionally represents
// as "". A real node-0 sentinel must survive both flat-set and packed forms,
// and the tolerant warning must say that the node statement was ignored.
func TestTolerantPathDropsQuotedEmptyNodeIdentity_10002(t *testing.T) {
	cases := []struct {
		name  string
		build func(t *testing.T) *ConfigTree
	}{
		{
			"flat set",
			func(t *testing.T) *ConfigTree {
				return build5636Tree(t,
					"set chassis cluster redundancy-group 1 node 0 priority 200",
					`set chassis cluster redundancy-group 1 node "" priority 7`,
				)
			},
		},
		{
			"hierarchical packed one-liner",
			func(t *testing.T) *ConfigTree {
				return hierTree(t, `chassis {
    cluster {
        redundancy-group 1 {
            node 0 priority 200;
            node "" priority 7;
        }
    }
}`)
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfigLenient(tc.build(t))
			if err != nil {
				t.Fatalf("the tolerant path must not refuse: %v", err)
			}
			rg := findRG(t, cfg, 1)
			if got := rg.NodePriorities; len(got) != 1 || got[0] != 200 {
				t.Fatalf("quoted-empty node identity overwrote node 0: %v, want map[0:200]", got)
			}
			assertWarns(t, cfg.Warnings, `""`, "node statement is ignored")
		})
	}
}

// TestStrictPathRejectsQuotedEmptyNodeIdentity_10002 proves the same explicit
// empty token remains a strict commit error in flat-set and packed forms.
func TestStrictPathRejectsQuotedEmptyNodeIdentity_10002(t *testing.T) {
	cases := []struct {
		name  string
		build func(t *testing.T) *ConfigTree
	}{
		{
			"flat set",
			func(t *testing.T) *ConfigTree {
				return build5636Tree(t,
					"set chassis cluster authentication-key test-cluster-psk-6611",
					"set chassis cluster redundancy-group 1 node 0 priority 200",
					`set chassis cluster redundancy-group 1 node "" priority 7`,
				)
			},
		},
		{
			"hierarchical packed one-liner",
			func(t *testing.T) *ConfigTree {
				return hierTree(t, `chassis {
    cluster {
        authentication-key test-cluster-psk-6611;
        redundancy-group 1 {
            node 0 priority 200;
            node "" priority 7;
        }
    }
}`)
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(tc.build(t))
			if err == nil {
				t.Fatal("strict commit accepted a quoted-empty chassis identity; want reject")
			}
			if !strings.Contains(err.Error(), `""`) ||
				!strings.Contains(err.Error(), "chassis cluster") {
				t.Fatalf("strict error should name the empty chassis identity: %v", err)
			}
		})
	}
}

func rgIDs(rgs []*RedundancyGroup) []int {
	var ids []int
	for _, rg := range rgs {
		ids = append(ids, rg.ID)
	}
	return ids
}

func findRG(t *testing.T, cfg *Config, id int) *RedundancyGroup {
	t.Helper()
	for _, rg := range cfg.Chassis.Cluster.RedundancyGroups {
		if rg.ID == id {
			return rg
		}
	}
	t.Fatalf("redundancy-group %d missing, have %v", id, rgIDs(cfg.Chassis.Cluster.RedundancyGroups))
	return nil
}

func assertWarns(t *testing.T, warnings []string, wants ...string) {
	t.Helper()
	for _, w := range warnings {
		ok := true
		for _, want := range wants {
			if !strings.Contains(w, want) {
				ok = false
				break
			}
		}
		if ok {
			return
		}
	}
	t.Fatalf("no warning contains %q; got %v", wants, warnings)
}
