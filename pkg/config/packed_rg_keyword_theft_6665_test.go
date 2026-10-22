package config

import (
	"fmt"
	"testing"
)

// packedRG6665 compiles a fully-PACKED redundancy-group instance line — the
// body on the instance node's own Keys, which is the only shape that reaches
// the splitter.
func packedRG6665(t *testing.T, body string) *RedundancyGroup {
	t.Helper()
	text := fmt.Sprintf(`chassis {
    cluster {
        cluster-id 1;
        node 0;
        authentication-key "test-cluster-psk-value";
        redundancy-group 1 %s
    }
}
`, body)
	cfg, err := CompileConfig(parseHierText(t, text))
	if err != nil {
		t.Fatalf("compile %q: %v", body, err)
	}
	if cfg.Chassis.Cluster == nil || len(cfg.Chassis.Cluster.RedundancyGroups) == 0 {
		t.Fatalf("no redundancy group compiled from %q", body)
	}
	for _, rg := range cfg.Chassis.Cluster.RedundancyGroups {
		if rg != nil && rg.ID == 1 {
			return rg
		}
	}
	t.Fatalf("redundancy-group 1 not found for %q", body)
	return nil
}

// containerRG6665 compiles the SAME statement in the container spelling, which
// never reaches the splitter and is therefore the correct answer by
// construction.
func containerRG6665(t *testing.T, body string) *RedundancyGroup {
	t.Helper()
	return packedRG6665(t, "{ "+body+" }")
}

// TestPackedRGDoesNotStealAKeywordFromTheValueSlot_6665 is the fail-on-revert
// gate.
//
// The splitter matched a statement keyword WHEREVER it appeared, including in a
// value slot, so an interface whose name spells a keyword was consumed as that
// statement: the monitor was silently dropped AND an unrelated statement was
// fabricated. `pkg/cluster` then ranges an empty InterfaceMonitors, so the group
// accrues no link-down debt and never demotes.
//
// The oracle is the CONTAINER spelling of the same statement, which cannot reach
// the splitter. Asserting packed == container is what makes this a test of the
// defect rather than of a hand-written expectation.
func TestPackedRGDoesNotStealAKeywordFromTheValueSlot_6665(t *testing.T) {
	// Every keyword in the dispatch table, in the one free-form identifier slot
	// the stanza has. A single-keyword case would leave the others silent — and
	// the bare-flag spellings below were still SILENT at HEAD even after #6658's
	// arity gate, which only fires on trailing tokens.
	for kw := range redundancyGroupStatements {
		t.Run(kw+"/with-weight", func(t *testing.T) {
			body := "interface-monitor " + kw + " weight 255;"
			got := packedRG6665(t, body)
			want := containerRG6665(t, body)
			assertMonitorsAgree6665(t, kw, got, want)
		})
		t.Run(kw+"/bare", func(t *testing.T) {
			body := "interface-monitor " + kw + ";"
			got := packedRG6665(t, body)
			want := containerRG6665(t, body)
			assertMonitorsAgree6665(t, kw, got, want)
		})
	}
}

func assertMonitorsAgree6665(t *testing.T, kw string, got, want *RedundancyGroup) {
	t.Helper()
	if len(got.InterfaceMonitors) != len(want.InterfaceMonitors) {
		t.Fatalf("packed compiled %d interface-monitors, container compiled %d — the keyword %q "+
			"was stolen out of the interface-name slot, so the group monitors nothing and "+
			"never demotes on link-down\npacked=%+v\ncontainer=%+v",
			len(got.InterfaceMonitors), len(want.InterfaceMonitors), kw,
			got.InterfaceMonitors, want.InterfaceMonitors)
	}
	for i := range want.InterfaceMonitors {
		// Compare the POINTED-TO values: InterfaceMonitors holds pointers, so a
		// bare != compares addresses and reds on two identical monitors.
		g, w := got.InterfaceMonitors[i], want.InterfaceMonitors[i]
		if (g == nil) != (w == nil) {
			t.Fatalf("monitor %d: packed %v, container %v", i, g, w)
		}
		if g != nil && *g != *w {
			t.Fatalf("monitor %d: packed %+v, container %+v", i, *g, *w)
		}
	}
	// The theft's second half: an unrelated statement fabricated from the
	// stolen keyword. Compare the flags and the ip-monitoring block too.
	if got.Preempt != want.Preempt {
		t.Fatalf("Preempt: packed %v, container %v — a stolen %q fabricated a statement the "+
			"operator never wrote", got.Preempt, want.Preempt, kw)
	}
	if got.StrictVIPOwnership != want.StrictVIPOwnership {
		t.Fatalf("StrictVIPOwnership: packed %v, container %v", got.StrictVIPOwnership, want.StrictVIPOwnership)
	}
	if (got.IPMonitoring == nil) != (want.IPMonitoring == nil) {
		t.Fatalf("IPMonitoring: packed nil=%v, container nil=%v — a stolen %q fabricated an "+
			"ip-monitoring block", got.IPMonitoring == nil, want.IPMonitoring == nil, kw)
	}
}

// TestPackedRGStillSplitsRealStatements_6665 is the over-reach guard.
//
// A splitter that stopped opening statements would satisfy the gate above
// completely and would re-break #6588 — the whole point of which is that a
// packed instance line compiles its body at all. This pins that a genuine
// multi-statement packed line still splits.
func TestPackedRGStillSplitsRealStatements_6665(t *testing.T) {
	rg := packedRG6665(t, "interface-monitor ge-0/0/0 weight 255 preempt;")
	if len(rg.InterfaceMonitors) != 1 {
		t.Fatalf("expected 1 monitor, got %+v", rg.InterfaceMonitors)
	}
	if rg.InterfaceMonitors[0].Interface != "ge-0/0/0" || rg.InterfaceMonitors[0].Weight != 255 {
		t.Fatalf("monitor = %+v, want {ge-0/0/0 255}", rg.InterfaceMonitors[0])
	}
	if !rg.Preempt {
		t.Fatal("the trailing `preempt` must still open a statement — reserving a value slot " +
			"must not stop the splitter splitting")
	}
}

// TestRGStatementArityAgreesWithTheNoArgSSOT_6665 binds the value-slot table to
// the tree's existing statement-arity SSOT.
//
// `redundancyGroupNoArgStatements` already declares which statements take NO
// argument — it is what the #6658 arity gate rejects trailing tokens against. A
// statement that takes no argument must reserve no value slot (or the token
// after it would be swallowed instead of opening a statement), and a statement
// that DOES take one must reserve exactly one (or a keyword in its value
// position is stolen). Two tables disagreeing about the same question is how the
// next statement rejoins the theft class.
//
// setSchema is deliberately not the oracle here: `interface-monitor` is declared
// `children: nil` with a documented rationale (typing it would flip SetPath's
// container grouping), so the schema does not carry the arity this splitter
// needs — which is exactly why the arity lives in its own table.
func TestRGStatementArityAgreesWithTheNoArgSSOT_6665(t *testing.T) {
	if len(redundancyGroupStatements) == 0 || len(redundancyGroupNoArgStatements) == 0 {
		t.Fatal("a source table is EMPTY — this agreement check would pass vacuously")
	}
	for kw := range redundancyGroupStatements {
		reserved := redundancyGroupStatementArity(kw)
		if redundancyGroupNoArgStatements[kw] {
			if reserved != 0 {
				t.Errorf("%q takes no argument per redundancyGroupNoArgStatements but reserves "+
					"%d value token(s); the token after it would be swallowed instead of "+
					"opening a statement", kw, reserved)
			}
			continue
		}
		// ip-monitoring is the one value-bearing statement whose first token is
		// itself a sub-keyword (family / global-weight / global-threshold), not
		// a free-form name, so there is no identifier slot to steal from.
		if kw == "ip-monitoring" {
			continue
		}
		if reserved == 0 {
			t.Errorf("%q takes an argument but reserves no value slot — a keyword in its value "+
				"position would be stolen as a statement (#6665)", kw)
		}
	}
	// And no arity for a statement that does not exist: dead policy that reads
	// as coverage.
	for _, kw := range []string{"preempt", "strict-vip-ownership", "node",
		"gratuitous-arp-count", "interface-monitor", "ip-monitoring"} {
		if _, ok := redundancyGroupStatements[kw]; !ok {
			t.Errorf("this test names %q, which is no longer a redundancy-group statement", kw)
		}
	}
}
