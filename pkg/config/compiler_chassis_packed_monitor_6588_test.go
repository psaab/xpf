package config

import (
	"fmt"
	"strings"
	"testing"
)

// #6588: a chassis-cluster redundancy-group monitor authored in the PACKED
// hierarchical spelling — one statement directly under `redundancy-group`, no
// nested block — compiled to NOTHING.
//
//	redundancy-group 1 {
//	    interface-monitor ge-0/0/0 weight 255;   <- packed
//	}
//
// The parser produces ONE leaf with Keys=["interface-monitor","ge-0/0/0",
// "weight","255"] and NO children, while compileChassis enumerated monitors by
// iterating child.Children only. Result: rgs=1, monitors=0. `commit` succeeded
// with no error and no warning, so the operator had link tracking configured
// and a redundancy group that never demoted on link-down — a failover
// FAIL-OPEN. The same drop hit `ip-monitoring` (packed global-weight /
// global-threshold, and a packed `family inet <addr> weight <n>` target), which
// installs demotion debt through the very same election path.
//
// This is the chassis-cluster instance of the #2419 / #3843 dual-shape class:
// a compiler reading a statement that may pack inline MUST read the node's own
// Keys tail as well as its Children.
//
// FAIL-ON-REVERT: restore the `range child.Children` enumeration in
// compileChassis and every Packed subtest below fails with an assertion naming
// the missing monitor / target. The Hierarchical and FlatSet subtests are the
// negative control — they exercise only the shapes that already worked and
// stay GREEN with and without the fix.

// packedIfMonConfig returns a hierarchical config text whose redundancy group
// carries rgBody verbatim.
func packedMonitorConfig(rgBody string) string {
	return `chassis {
    cluster {
        authentication-key test-cluster-psk-6588;
        cluster-id 1;
        redundancy-group 1 {
            node 0 priority 200;
` + rgBody + `
        }
    }
}`
}

// compileMonitorText parses hierarchical config text and returns the single
// compiled redundancy group.
func compileMonitorText(t *testing.T, text string) *RedundancyGroup {
	t.Helper()
	p := NewParser(text)
	tree, perrs := p.Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return onlyRG6588(t, cfg)
}

func onlyRG6588(t *testing.T, cfg *Config) *RedundancyGroup {
	t.Helper()
	if cfg == nil || cfg.Chassis.Cluster == nil {
		t.Fatal("compiled config carries no chassis cluster")
	}
	rgs := cfg.Chassis.Cluster.RedundancyGroups
	if len(rgs) != 1 {
		t.Fatalf("expected 1 redundancy-group, got %d", len(rgs))
	}
	return rgs[0]
}

func describeMonitors(mons []*InterfaceMonitor) string {
	if len(mons) == 0 {
		return "<none>"
	}
	parts := make([]string, 0, len(mons))
	for _, m := range mons {
		parts = append(parts, fmt.Sprintf("%s weight %d", m.Interface, m.Weight))
	}
	return strings.Join(parts, ", ")
}

// TestChassisInterfaceMonitorAllThreeSpellings_6588 pins that the flat-set,
// container-hierarchical and packed-hierarchical spellings of the SAME
// interface-monitor all compile to the SAME typed monitor.
func TestChassisInterfaceMonitorAllThreeSpellings_6588(t *testing.T) {
	// Negative control: the two shapes that already worked before the fix.
	t.Run("FlatSet", func(t *testing.T) {
		tree := buildTree(t, []string{
			"set chassis cluster cluster-id 1",
			"set chassis cluster authentication-key test-cluster-psk-6588",
			"set chassis cluster redundancy-group 1 node 0 priority 200",
			"set chassis cluster redundancy-group 1 interface-monitor ge-0/0/0 weight 255",
		})
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		assertSingleMonitor(t, onlyRG6588(t, cfg), "ge-0/0/0", 255)
	})
	t.Run("ContainerHierarchical", func(t *testing.T) {
		rg := compileMonitorText(t, packedMonitorConfig(
			"            interface-monitor {\n                ge-0/0/0 weight 255;\n            }"))
		assertSingleMonitor(t, rg, "ge-0/0/0", 255)
	})

	// The #6588 defect: the packed one-liner.
	t.Run("Packed", func(t *testing.T) {
		rg := compileMonitorText(t, packedMonitorConfig(
			"            interface-monitor ge-0/0/0 weight 255;"))
		assertSingleMonitor(t, rg, "ge-0/0/0", 255)
	})
}

func assertSingleMonitor(t *testing.T, rg *RedundancyGroup, iface string, weight int) {
	t.Helper()
	if len(rg.InterfaceMonitors) != 1 {
		t.Fatalf("expected exactly 1 interface-monitor (%s weight %d), got %d: %s — "+
			"a redundancy group with zero compiled monitors never demotes on link-down",
			iface, weight, len(rg.InterfaceMonitors), describeMonitors(rg.InterfaceMonitors))
	}
	m := rg.InterfaceMonitors[0]
	if m.Interface != iface || m.Weight != weight {
		t.Fatalf("monitor = %s weight %d, want %s weight %d",
			m.Interface, m.Weight, iface, weight)
	}
}

// TestChassisInterfaceMonitorPackedMultiple_6588 pins that several packed
// one-liners under the same redundancy group each produce their own monitor —
// the shape a hand-written config uses for a multi-link group.
func TestChassisInterfaceMonitorPackedMultiple_6588(t *testing.T) {
	rg := compileMonitorText(t, packedMonitorConfig(
		"            interface-monitor ge-0/0/0 weight 255;\n"+
			"            interface-monitor ge-0/0/1 weight 100;"))
	if len(rg.InterfaceMonitors) != 2 {
		t.Fatalf("expected 2 interface-monitors, got %d: %s",
			len(rg.InterfaceMonitors), describeMonitors(rg.InterfaceMonitors))
	}
	want := map[string]int{"ge-0/0/0": 255, "ge-0/0/1": 100}
	for _, m := range rg.InterfaceMonitors {
		w, ok := want[m.Interface]
		if !ok {
			t.Fatalf("unexpected monitor %s in %s", m.Interface, describeMonitors(rg.InterfaceMonitors))
		}
		if m.Weight != w {
			t.Fatalf("monitor %s weight = %d, want %d", m.Interface, m.Weight, w)
		}
		delete(want, m.Interface)
	}
	if len(want) != 0 {
		t.Fatalf("monitors missing from the compiled group: %v (got %s)",
			want, describeMonitors(rg.InterfaceMonitors))
	}
}

// TestChassisInterfaceMonitorPackedNoWeight_6588 pins the weight-less packed
// spelling: it must still produce a monitor (with the pre-existing 0 default),
// not vanish.
func TestChassisInterfaceMonitorPackedNoWeight_6588(t *testing.T) {
	rg := compileMonitorText(t, packedMonitorConfig(
		"            interface-monitor ge-0/0/0;"))
	assertSingleMonitor(t, rg, "ge-0/0/0", 0)
}

// TestChassisInterfaceMonitorPackedNestedWeight_6588 pins the packed instance
// with a nested weight block — `interface-monitor ge-0/0/0 { weight 255; }`.
// The interface name packs onto the statement keys while the weight arrives as
// a child, so both halves must be read.
func TestChassisInterfaceMonitorPackedNestedWeight_6588(t *testing.T) {
	rg := compileMonitorText(t, packedMonitorConfig(
		"            interface-monitor ge-0/0/0 {\n                weight 255;\n            }"))
	assertSingleMonitor(t, rg, "ge-0/0/0", 255)
}

// TestChassisInterfaceMonitorPackedWeightRangeGated_6588 pins the issue's
// second-order consequence: because the packed shape compiled to zero
// monitors, the #6549 weight range gate — which runs on the COMPILED int —
// never saw a packed weight, so an out-of-range one was accepted at commit.
// Now that the packed shape compiles, the existing gate covers it for free.
func TestChassisInterfaceMonitorPackedWeightRangeGated_6588(t *testing.T) {
	for _, weight := range []int{-100, -1, 256, 1000} {
		t.Run(fmt.Sprintf("weight_%d", weight), func(t *testing.T) {
			text := packedMonitorConfig(fmt.Sprintf(
				"            interface-monitor ge-0/0/0 weight %d;", weight))
			p := NewParser(text)
			tree, perrs := p.Parse()
			if len(perrs) > 0 {
				t.Fatalf("parse: %v", perrs)
			}
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("expected commit to reject the packed out-of-range "+
					"interface-monitor weight %d (#6549 gates the compiled int), got nil error",
					weight)
			}
			if !strings.Contains(err.Error(), "interface-monitor ge-0/0/0") {
				t.Fatalf("error %q does not name the offending interface-monitor", err)
			}
			if !strings.Contains(err.Error(), "out of range 0..255") {
				t.Fatalf("error %q does not state the admitted range", err)
			}
		})
	}
}

// TestChassisIPMonitoringPackedShapes_6588 covers the sibling site: the same
// Children-only enumeration dropped a packed `ip-monitoring` statement and a
// packed `family inet <addr> weight <n>` target. ip-monitoring installs
// redundancy-group demotion debt through the same election path as
// interface-monitor, so the fail-open is identical in kind.
func TestChassisIPMonitoringPackedShapes_6588(t *testing.T) {
	tests := []struct {
		name       string
		rgBody     string
		wantWeight int
		wantThresh int
		wantAddr   string
		wantTgtWgt int
	}{
		// Negative control: the fully-hierarchical shapes that already worked.
		{
			name: "ControlNestedFamilyBlock",
			rgBody: "            ip-monitoring {\n" +
				"                global-weight 255;\n" +
				"                global-threshold 2;\n" +
				"                family {\n" +
				"                    inet {\n" +
				"                        10.0.1.1 weight 100;\n" +
				"                    }\n" +
				"                }\n" +
				"            }",
			wantWeight: 255, wantThresh: 2, wantAddr: "10.0.1.1", wantTgtWgt: 100,
		},
		{
			name: "ControlCompoundFamilyBlock",
			rgBody: "            ip-monitoring {\n" +
				"                global-weight 255;\n" +
				"                global-threshold 2;\n" +
				"                family inet {\n" +
				"                    10.0.1.1 weight 100;\n" +
				"                }\n" +
				"            }",
			wantWeight: 255, wantThresh: 2, wantAddr: "10.0.1.1", wantTgtWgt: 100,
		},
		// #6588: packed spellings.
		{
			name: "PackedFamilyLeafInsideBlock",
			rgBody: "            ip-monitoring {\n" +
				"                global-weight 255;\n" +
				"                global-threshold 2;\n" +
				"                family inet 10.0.1.1 weight 100;\n" +
				"            }",
			wantWeight: 255, wantThresh: 2, wantAddr: "10.0.1.1", wantTgtWgt: 100,
		},
		{
			name: "PackedInetLeafInsideFamilyBlock",
			rgBody: "            ip-monitoring {\n" +
				"                global-weight 255;\n" +
				"                global-threshold 2;\n" +
				"                family {\n" +
				"                    inet 10.0.1.1 weight 100;\n" +
				"                }\n" +
				"            }",
			wantWeight: 255, wantThresh: 2, wantAddr: "10.0.1.1", wantTgtWgt: 100,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rg := compileMonitorText(t, packedMonitorConfig(tc.rgBody))
			if rg.IPMonitoring == nil {
				t.Fatal("redundancy group carries no compiled ip-monitoring — " +
					"a dropped stanza never demotes the group on probe failure")
			}
			if rg.IPMonitoring.GlobalWeight != tc.wantWeight {
				t.Fatalf("global-weight = %d, want %d", rg.IPMonitoring.GlobalWeight, tc.wantWeight)
			}
			if rg.IPMonitoring.GlobalThreshold != tc.wantThresh {
				t.Fatalf("global-threshold = %d, want %d", rg.IPMonitoring.GlobalThreshold, tc.wantThresh)
			}
			if len(rg.IPMonitoring.Targets) != 1 {
				t.Fatalf("expected exactly 1 ip-monitoring target (%s weight %d), got %d",
					tc.wantAddr, tc.wantTgtWgt, len(rg.IPMonitoring.Targets))
			}
			got := rg.IPMonitoring.Targets[0]
			if got.Address != tc.wantAddr || got.Weight != tc.wantTgtWgt {
				t.Fatalf("target = %s weight %d, want %s weight %d",
					got.Address, got.Weight, tc.wantAddr, tc.wantTgtWgt)
			}
		})
	}
}

// TestChassisIPMonitoringFullyPacked_6588 covers the one-liner form where the
// whole ip-monitoring statement packs onto a single line.
func TestChassisIPMonitoringFullyPacked_6588(t *testing.T) {
	t.Run("GlobalWeightOnly", func(t *testing.T) {
		rg := compileMonitorText(t, packedMonitorConfig(
			"            ip-monitoring global-weight 255;"))
		if rg.IPMonitoring == nil {
			t.Fatal("redundancy group carries no compiled ip-monitoring")
		}
		if rg.IPMonitoring.GlobalWeight != 255 {
			t.Fatalf("global-weight = %d, want 255", rg.IPMonitoring.GlobalWeight)
		}
	})
	t.Run("FamilyTargetOnly", func(t *testing.T) {
		rg := compileMonitorText(t, packedMonitorConfig(
			"            ip-monitoring family inet 10.0.1.1 weight 100;"))
		if rg.IPMonitoring == nil {
			t.Fatal("redundancy group carries no compiled ip-monitoring")
		}
		if len(rg.IPMonitoring.Targets) != 1 {
			t.Fatalf("expected exactly 1 ip-monitoring target, got %d",
				len(rg.IPMonitoring.Targets))
		}
		got := rg.IPMonitoring.Targets[0]
		if got.Address != "10.0.1.1" || got.Weight != 100 {
			t.Fatalf("target = %s weight %d, want 10.0.1.1 weight 100", got.Address, got.Weight)
		}
	})
}

// ---------------------------------------------------------------------------
// #6588 review round 2 — three MAJORs found inside the code this PR touched.
// ---------------------------------------------------------------------------

// compileMonitorTextErr is compileMonitorText's counterpart for configs that
// must be REJECTED at strict commit.
func compileMonitorTextErr(t *testing.T, text string) error {
	t.Helper()
	p := NewParser(text)
	tree, perrs := p.Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	_, err := CompileConfig(tree)
	return err
}

func flatMonitorTree(t *testing.T, extra ...string) *ConfigTree {
	t.Helper()
	return buildTree(t, append([]string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key test-cluster-psk-6588",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
	}, extra...))
}

// MAJOR 1 -------------------------------------------------------------------

// TestChassisIPMonitoringWeightRangeGated_6588 pins that the ip-monitoring
// weights are range-gated in ALL THREE spellings.
//
// #6549 deliberately left these to their typed schema leaves
// (ValidateInteger(0,255)) instead of the compiled-int gate it added for
// interface-monitor. That was sound while the packed spelling compiled to
// nothing — but SchemaValidate walks the AST from setSchema and a packed
// statement sits BELOW the depth it reaches (pinned by
// TestChassisPackedShapeBypassesSchemaWalk_6588), so once #6588 made the packed
// shape compile, an out-of-range packed weight would have reached the runtime
// with no commit-side gate on any path. The gate now lives on the compiled int
// beside its interface-monitor sibling, which is the only layer all three
// spellings pass through.
func TestChassisIPMonitoringWeightRangeGated_6588(t *testing.T) {
	for _, bad := range []struct {
		what  string
		want  string
		flat  string
		cont  string
		packd string
	}{
		{
			what: "global-weight", want: "global-weight 300 is out of range 0..255",
			flat:  "set chassis cluster redundancy-group 1 ip-monitoring global-weight 300",
			cont:  "            ip-monitoring {\n                global-weight 300;\n            }",
			packd: "            ip-monitoring global-weight 300;",
		},
		{
			what: "global-threshold", want: "global-threshold 256 is out of range 0..255",
			flat:  "set chassis cluster redundancy-group 1 ip-monitoring global-threshold 256",
			cont:  "            ip-monitoring {\n                global-threshold 256;\n            }",
			packd: "            ip-monitoring global-threshold 256;",
		},
		{
			what: "target weight", want: "family inet 10.0.1.1 weight -100 is out of range 0..255",
			flat:  "set chassis cluster redundancy-group 1 ip-monitoring family inet 10.0.1.1 weight -100",
			cont:  "            ip-monitoring {\n                family {\n                    inet {\n                        10.0.1.1 weight -100;\n                    }\n                }\n            }",
			packd: "            ip-monitoring family inet 10.0.1.1 weight -100;",
		},
	} {
		t.Run(bad.what+"/FlatSet", func(t *testing.T) {
			_, err := CompileConfig(flatMonitorTree(t, bad.flat))
			assertErrContains(t, err, bad.want)
		})
		t.Run(bad.what+"/ContainerHierarchical", func(t *testing.T) {
			assertErrContains(t, compileMonitorTextErr(t, packedMonitorConfig(bad.cont)), bad.want)
		})
		t.Run(bad.what+"/Packed", func(t *testing.T) {
			assertErrContains(t, compileMonitorTextErr(t, packedMonitorConfig(bad.packd)), bad.want)
		})
	}
}

// TestChassisIPMonitoringInRangeStillCommits_6588 is the MAJOR-1 negative
// control: every legal ip-monitoring value, including both boundaries, must
// still commit AND compile verbatim. It passes with and without the gate.
func TestChassisIPMonitoringInRangeStillCommits_6588(t *testing.T) {
	for _, w := range []int{0, 1, 128, 254, 255} {
		t.Run(fmt.Sprintf("weight_%d", w), func(t *testing.T) {
			rg := compileMonitorText(t, packedMonitorConfig(fmt.Sprintf(
				"            ip-monitoring {\n"+
					"                global-weight %d;\n"+
					"                global-threshold %d;\n"+
					"                family inet {\n"+
					"                    10.0.1.1 weight %d;\n"+
					"                }\n"+
					"            }", w, w, w)))
			if rg.IPMonitoring == nil {
				t.Fatal("redundancy group carries no compiled ip-monitoring")
			}
			if rg.IPMonitoring.GlobalWeight != w || rg.IPMonitoring.GlobalThreshold != w {
				t.Fatalf("global-weight/threshold = %d/%d, want %d/%d (the gate must not alter an in-range value)",
					rg.IPMonitoring.GlobalWeight, rg.IPMonitoring.GlobalThreshold, w, w)
			}
			if len(rg.IPMonitoring.Targets) != 1 || rg.IPMonitoring.Targets[0].Weight != w {
				t.Fatalf("targets = %+v, want one target with weight %d", rg.IPMonitoring.Targets, w)
			}
		})
	}
}

// TestChassisPackedShapeBypassesSchemaWalk_6588 is the load-bearing evidence
// for WHERE the MAJOR-1 gate had to go: the typed-leaf gate cannot see a packed
// statement, so a schema validator can never cover it. SchemaValidate accepts
// an ip-monitoring weight the compiled-int gate rejects.
func TestChassisPackedShapeBypassesSchemaWalk_6588(t *testing.T) {
	p := NewParser(packedMonitorConfig("            ip-monitoring family inet 10.0.1.1 weight -100;"))
	tree, perrs := p.Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	if err := SchemaValidate(tree, nil); err != nil {
		t.Fatalf("SchemaValidate unexpectedly saw the packed statement (%v) — if the typed "+
			"leaf now reaches it, the compiled-int gate's rationale needs revisiting", err)
	}
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("the compiled-int gate must reject what SchemaValidate cannot see")
	}
}

// MAJOR 2 -------------------------------------------------------------------

// TestChassisInterfaceMonitorBracketList_6588 pins the #2419 bracketed-list
// collapse for monitors. The lexer strips `[`/`]`, so
// `interface-monitor [ ge-0/0/0 ge-0/0/1 ge-0/0/2 ]` lands as N names on ONE
// node's Keys in EVERY spelling. Compiling only the first name is the same
// failover fail-open as dropping the statement, one monitor at a time.
func TestChassisInterfaceMonitorBracketList_6588(t *testing.T) {
	want := []string{"ge-0/0/0", "ge-0/0/1", "ge-0/0/2"}
	// No weight anywhere on these lines, so every monitor must carry the
	// documented #6549 default. Asserted explicitly rather than skipped — see
	// assertMonitors.
	zeros := []int{0, 0, 0}

	t.Run("FlatSet", func(t *testing.T) {
		cfg, err := CompileConfig(flatMonitorTree(t,
			"set chassis cluster redundancy-group 1 interface-monitor [ ge-0/0/0 ge-0/0/1 ge-0/0/2 ]"))
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		assertMonitors(t, onlyRG6588(t, cfg), want, zeros)
	})
	t.Run("ContainerHierarchical", func(t *testing.T) {
		assertMonitors(t, compileMonitorText(t, packedMonitorConfig(
			"            interface-monitor {\n                [ ge-0/0/0 ge-0/0/1 ge-0/0/2 ];\n            }")), want, zeros)
	})
	t.Run("Packed", func(t *testing.T) {
		assertMonitors(t, compileMonitorText(t, packedMonitorConfig(
			"            interface-monitor [ ge-0/0/0 ge-0/0/1 ge-0/0/2 ];")), want, zeros)
	})
	// A weight-less bracketed list must still yield one monitor per name.
	t.Run("PackedNoWeight", func(t *testing.T) {
		assertMonitors(t, compileMonitorText(t, packedMonitorConfig(
			"            interface-monitor [ ge-0/0/0 ge-0/0/1 ];")),
			[]string{"ge-0/0/0", "ge-0/0/1"}, []int{0, 0})
	})
}

// TestChassisInterfaceMonitorBracketListWeight_6588 pins WHICH monitors a
// bracketed list's weight lands on — the half of the bracket contract the
// name-only assertions above cannot see.
//
// A weight written after a bracketed list applies to EVERY member. The obvious
// implementation attaches it to the PRECEDING name only, which leaves
// `[ ge-0/0/0 ge-0/0/1 ] weight 255` compiled as ge-0/0/0=0, ge-0/0/1=255: the
// first link is monitored but deducts nothing when it fails, so the group does
// not demote. That is a failover fail-open, and it is WORSE than the master
// behaviour this PR replaced (which compiled one monitor at 255 and dropped the
// rest) because the operator sees both interfaces echoed back by `show
// configuration` and by `show chassis cluster status`.
//
// FAIL-ON-REVERT: restore the positional attachment in monitorEntryNodes
// (append the `weight` tokens to the last name started, instead of collecting
// them candidate-scoped) and every subtest marked BINDING below fails naming
// the zero weight. The two CONTROL subtests carry the weight in a children
// block, where it is candidate-scoped in both implementations — they are green
// either way and are here to pin that the two spellings agree, not to catch the
// positional regression.
func TestChassisInterfaceMonitorBracketListWeight_6588(t *testing.T) {
	pair := []string{"ge-0/0/0", "ge-0/0/1"}

	// BINDING: inline weight after a bracketed list, in every spelling that
	// reaches monitorEntryNodes.
	t.Run("PackedInline", func(t *testing.T) {
		assertMonitors(t, compileMonitorText(t, packedMonitorConfig(
			"            interface-monitor [ ge-0/0/0 ge-0/0/1 ] weight 255;")),
			pair, []int{255, 255})
	})
	t.Run("PackedInlineThreeMembers", func(t *testing.T) {
		assertMonitors(t, compileMonitorText(t, packedMonitorConfig(
			"            interface-monitor [ ge-0/0/0 ge-0/0/1 ge-0/0/2 ] weight 100;")),
			[]string{"ge-0/0/0", "ge-0/0/1", "ge-0/0/2"}, []int{100, 100, 100})
	})
	t.Run("ContainerHierarchicalInline", func(t *testing.T) {
		assertMonitors(t, compileMonitorText(t, packedMonitorConfig(
			"            interface-monitor {\n                [ ge-0/0/0 ge-0/0/1 ] weight 255;\n            }")),
			pair, []int{255, 255})
	})
	t.Run("FlatSetInline", func(t *testing.T) {
		cfg, err := CompileConfig(flatMonitorTree(t,
			"set chassis cluster redundancy-group 1 interface-monitor [ ge-0/0/0 ge-0/0/1 ] weight 255"))
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		assertMonitors(t, onlyRG6588(t, cfg), pair, []int{255, 255})
	})
	// BINDING, one level up: the whole redundancy-group body packed onto the
	// instance line still splits the list AND spreads the weight.
	t.Run("PackedRedundancyGroupBodyInline", func(t *testing.T) {
		assertMonitors(t, compileRGText(t, packedRGConfig(
			"        redundancy-group 1 interface-monitor [ ge-0/0/0 ge-0/0/1 ] weight 255;")),
			pair, []int{255, 255})
	})

	t.Run("FlatSetInlineThreeNames", func(t *testing.T) {
		cfg, err := CompileConfig(flatMonitorTree(t,
			"set chassis cluster redundancy-group 1 interface-monitor [ ge-0/0/0 ge-0/0/1 ge-0/0/2 ] weight 100"))
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		assertMonitors(t, onlyRG6588(t, cfg),
			[]string{"ge-0/0/0", "ge-0/0/1", "ge-0/0/2"}, []int{100, 100, 100})
	})

	// The range gate must see EVERY member, not just the one the weight was
	// written next to. Under the positional regression ge-0/0/0 carries weight
	// 0 and the offending 300 reaches only the last member, so the error names
	// the wrong interface.
	t.Run("OutOfRangeRejectedForAllMembers", func(t *testing.T) {
		assertErrContains(t, compileMonitorTextErr(t, packedMonitorConfig(
			"            interface-monitor [ ge-0/0/0 ge-0/0/1 ] weight 300;")),
			"interface-monitor ge-0/0/0 weight 300 is out of range 0..255")
	})
	// Two inline weights inside one bracketed statement are ambiguous about
	// which member each belongs to. Rejecting matches the duplicate-weight gate
	// rather than silently picking one.
	t.Run("AmbiguousPerMemberWeightsRejected", func(t *testing.T) {
		assertErrContains(t, compileMonitorTextErr(t, packedMonitorConfig(
			"            interface-monitor [ ge-0/0/0 weight 100 ge-0/0/1 weight 200 ];")),
			"weight specified 2 times with different values")
	})

	// CONTROL: the children-block spelling. The weight is candidate-scoped by
	// construction here, so this stays green under the positional regression;
	// it pins that the block and inline spellings agree.
	t.Run("PackedChildrenBlock", func(t *testing.T) {
		assertMonitors(t, compileMonitorText(t, packedMonitorConfig(
			"            interface-monitor [ ge-0/0/0 ge-0/0/1 ] {\n                weight 255;\n            }")),
			pair, []int{255, 255})
	})
	t.Run("ContainerHierarchicalChildrenBlock", func(t *testing.T) {
		assertMonitors(t, compileMonitorText(t, packedMonitorConfig(
			"            interface-monitor {\n                [ ge-0/0/0 ge-0/0/1 ] {\n                    weight 255;\n                }\n            }")),
			pair, []int{255, 255})
	})
	// CONTROL: a single name with an inline weight is unaffected by how the
	// attribute is scoped. Green in both worlds.
	t.Run("ControlSingleNameInlineWeight", func(t *testing.T) {
		assertMonitors(t, compileMonitorText(t, packedMonitorConfig(
			"            interface-monitor ge-0/0/0 weight 255;")),
			[]string{"ge-0/0/0"}, []int{255})
	})
}

// TestChassisRedundancyGroupBareContainerShape_6588 pins the SECOND node shape
// namedInstances returns.
//
// namedInstances yields either the `redundancy-group <id>` node itself
// (Keys[0]=="redundancy-group", so the body starts at Keys[2]) or, for a bare
// `redundancy-group { ... }` wrapper, a CHILD whose Keys[0] IS the instance id
// (so the body starts at Keys[1]). redundancyGroupBody used a fixed skip of 2,
// which on the second shape swallowed the statement KEYWORD and opened a node
// named after a value — matching no dispatch entry, so every statement was
// dropped, election priority included.
//
// Reachability through the shipped parser is lower than the packed-instance
// shape (no Junos output and no SetPath path emits a bare wrapper), but the
// discrimination is fixed rather than documented: all four redundancyGroupBody
// readers depend on it, so leaving it would make the AST gates blind here while
// LOOKING like they covered it.
//
// This suite was deleted by the b3158d315 dispatch-table refactor along with
// the bracket-inline-weight coverage above, and is restored rather than
// rewritten — the `Keys[0]` discrimination it guards is untouched by that
// refactor and was left unguarded by its removal.
//
// FAIL-ON-REVERT: pin skip back to 2 in redundancyGroupBody and every subtest
// below fails naming the lost statement.
func TestChassisRedundancyGroupBareContainerShape_6588(t *testing.T) {
	t.Run("PackedInterfaceMonitor", func(t *testing.T) {
		assertMonitors(t, compileRGText(t, packedRGConfig(
			"        redundancy-group {\n            1 interface-monitor ge-0/0/0 weight 255;\n        }")),
			[]string{"ge-0/0/0"}, []int{255})
	})
	t.Run("PackedNodePriority", func(t *testing.T) {
		rg := compileRGText(t, packedRGConfig(
			"        redundancy-group {\n            1 node 0 priority 200;\n        }"))
		if got, ok := rg.NodePriorities[0]; !ok || got != 200 {
			t.Fatalf("bare `redundancy-group { 1 node 0 priority 200; }` lost the election "+
				"priority: NodePriorities = %v", rg.NodePriorities)
		}
	})
	t.Run("PackedPreempt", func(t *testing.T) {
		rg := compileRGText(t, packedRGConfig(
			"        redundancy-group {\n            1 preempt;\n        }"))
		if !rg.Preempt {
			t.Fatal("bare `redundancy-group { 1 preempt; }` lost `preempt`")
		}
	})
	t.Run("GatesStillReachIt", func(t *testing.T) {
		assertErrContains(t, compileMonitorTextErr(t, packedRGConfig(
			"        redundancy-group {\n            1 interface-monitor ge-0/0/0 weight nope;\n        }")),
			`weight "nope" is not an integer`)
	})
	// The gates added after the refactor must reach this shape too, or the
	// bare wrapper becomes the one spelling that admits what they reject.
	t.Run("IPMonitoringGlobalGateStillReachesIt", func(t *testing.T) {
		assertErrContains(t, compileMonitorTextErr(t, packedRGConfig(
			"        redundancy-group {\n            1 ip-monitoring global-weight nope;\n        }")),
			`global-weight "nope" is not an integer`)
	})
	t.Run("NoArgArityGateStillReachesIt", func(t *testing.T) {
		assertErrContains(t, compileMonitorTextErr(t, packedRGConfig(
			"        redundancy-group {\n            1 preempt delay 5;\n        }")),
			"preempt: takes no argument")
	})
	// NEGATIVE CONTROL: the nested-block form under a bare wrapper already
	// worked (its body arrives as real children) and must be unchanged. Green
	// with and without the fix.
	t.Run("ControlBareWrapperNestedBlock", func(t *testing.T) {
		assertMonitors(t, compileRGText(t, packedRGConfig(
			"        redundancy-group {\n            1 {\n                interface-monitor ge-0/0/0 weight 255;\n            }\n        }")),
			[]string{"ge-0/0/0"}, []int{255})
	})
	// NEGATIVE CONTROL: the ordinary `redundancy-group <id>` shape still uses
	// skip 2. Green in both worlds.
	t.Run("ControlOrdinaryInstanceShape", func(t *testing.T) {
		assertMonitors(t, compileRGText(t, packedRGConfig(
			"        redundancy-group 1 interface-monitor ge-0/0/0 weight 255;")),
			[]string{"ge-0/0/0"}, []int{255})
	})
}

// TestChassisIPMonitoringBracketTargets_6588 covers the same collapse on the
// ip-monitoring target list.
func TestChassisIPMonitoringBracketTargets_6588(t *testing.T) {
	t.Run("NoWeight", func(t *testing.T) {
		assertIPMonTargets(t, compileMonitorText(t, packedMonitorConfig(
			"            ip-monitoring family inet [ 10.0.1.1 10.0.2.1 10.0.3.1 ];")),
			[]string{"10.0.1.1", "10.0.2.1", "10.0.3.1"}, []int{0, 0, 0})
	})
	// BINDING, same shape as the interface-monitor case: ip-monitoring targets
	// are split by the SAME monitorEntryNodes, so a positional weight
	// attachment leaves the first probe target deducting nothing on failure.
	t.Run("InlineWeight", func(t *testing.T) {
		assertIPMonTargets(t, compileMonitorText(t, packedMonitorConfig(
			"            ip-monitoring family inet [ 10.0.1.1 10.0.2.1 ] weight 100;")),
			[]string{"10.0.1.1", "10.0.2.1"}, []int{100, 100})
	})
	t.Run("InlineWeightThreeTargets", func(t *testing.T) {
		assertIPMonTargets(t, compileMonitorText(t, packedMonitorConfig(
			"            ip-monitoring family inet [ 10.0.1.1 10.0.2.1 10.0.3.1 ] weight 200;")),
			[]string{"10.0.1.1", "10.0.2.1", "10.0.3.1"}, []int{200, 200, 200})
	})
	t.Run("InlineWeightInsideFamilyBlock", func(t *testing.T) {
		assertIPMonTargets(t, compileMonitorText(t, packedMonitorConfig(
			"            ip-monitoring {\n                family inet {\n                    [ 10.0.1.1 10.0.2.1 ] weight 100;\n                }\n            }")),
			[]string{"10.0.1.1", "10.0.2.1"}, []int{100, 100})
	})
	t.Run("PackedRedundancyGroupBodyInlineWeight", func(t *testing.T) {
		assertIPMonTargets(t, compileRGText(t, packedRGConfig(
			"        redundancy-group 1 ip-monitoring family inet [ 10.0.1.1 10.0.2.1 ] weight 100;")),
			[]string{"10.0.1.1", "10.0.2.1"}, []int{100, 100})
	})
}

// TestChassisInterfaceMonitorSingleEntryNotSplit_6588 is the MAJOR-2 negative
// control the review asked for: a single NON-bracketed packed monitor must
// still compile to exactly ONE entry, with its weight intact. The splitter must
// not shred `ge-0/0/0 weight 255` into an entry per token. Passes with and
// without the split.
func TestChassisInterfaceMonitorSingleEntryNotSplit_6588(t *testing.T) {
	t.Run("PackedWithWeight", func(t *testing.T) {
		assertSingleMonitor(t, compileMonitorText(t, packedMonitorConfig(
			"            interface-monitor ge-0/0/0 weight 255;")), "ge-0/0/0", 255)
	})
	t.Run("ContainerWithWeight", func(t *testing.T) {
		assertSingleMonitor(t, compileMonitorText(t, packedMonitorConfig(
			"            interface-monitor {\n                ge-0/0/0 weight 255;\n            }")), "ge-0/0/0", 255)
	})
	t.Run("PackedNestedWeightBlock", func(t *testing.T) {
		assertSingleMonitor(t, compileMonitorText(t, packedMonitorConfig(
			"            interface-monitor ge-0/0/0 {\n                weight 255;\n            }")), "ge-0/0/0", 255)
	})
	t.Run("FlatSetWithWeight", func(t *testing.T) {
		cfg, err := CompileConfig(flatMonitorTree(t,
			"set chassis cluster redundancy-group 1 interface-monitor ge-0/0/0 weight 255"))
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		assertSingleMonitor(t, onlyRG6588(t, cfg), "ge-0/0/0", 255)
	})
	t.Run("SingleIPMonitorTarget", func(t *testing.T) {
		rg := compileMonitorText(t, packedMonitorConfig(
			"            ip-monitoring family inet 10.0.1.1 weight 100;"))
		if rg.IPMonitoring == nil || len(rg.IPMonitoring.Targets) != 1 {
			t.Fatalf("expected exactly 1 ip-monitoring target, got %+v", rg.IPMonitoring)
		}
		if got := rg.IPMonitoring.Targets[0]; got.Address != "10.0.1.1" || got.Weight != 100 {
			t.Fatalf("target = %s weight %d, want 10.0.1.1 weight 100", got.Address, got.Weight)
		}
	})
}

// MAJOR 4 -------------------------------------------------------------------

// TestChassisMonitorWeightMalformedRejected_6588 pins that a weight which is
// PRESENT but not an integer is rejected at commit in every spelling. Before
// the gate it compiled to the 0 default: the operator configured link tracking,
// commit succeeded, and the monitor going down deducted NOTHING — the same
// silent-nothing class as the packed-statement drop this PR fixes. The compiled
// struct cannot express it (a failed Atoi is indistinguishable from `weight 0`),
// so the check runs on the AST.
func TestChassisMonitorWeightMalformedRejected_6588(t *testing.T) {
	const want = `weight "nope" is not an integer`

	t.Run("InterfaceMonitor/FlatSet", func(t *testing.T) {
		_, err := CompileConfig(flatMonitorTree(t,
			"set chassis cluster redundancy-group 1 interface-monitor ge-0/0/0 weight nope"))
		assertErrContains(t, err, want)
	})
	t.Run("InterfaceMonitor/ContainerHierarchical", func(t *testing.T) {
		assertErrContains(t, compileMonitorTextErr(t, packedMonitorConfig(
			"            interface-monitor {\n                ge-0/0/0 weight nope;\n            }")), want)
	})
	t.Run("InterfaceMonitor/Packed", func(t *testing.T) {
		assertErrContains(t, compileMonitorTextErr(t, packedMonitorConfig(
			"            interface-monitor ge-0/0/0 weight nope;")), want)
	})
	t.Run("InterfaceMonitor/PackedNestedWeightBlock", func(t *testing.T) {
		assertErrContains(t, compileMonitorTextErr(t, packedMonitorConfig(
			"            interface-monitor ge-0/0/0 {\n                weight nope;\n            }")), want)
	})
	t.Run("InterfaceMonitor/WeightWithNoValue", func(t *testing.T) {
		assertErrContains(t, compileMonitorTextErr(t, packedMonitorConfig(
			"            interface-monitor ge-0/0/0 weight;")), `weight "" is not an integer`)
	})
	t.Run("IPMonitoringTarget/Packed", func(t *testing.T) {
		assertErrContains(t, compileMonitorTextErr(t, packedMonitorConfig(
			"            ip-monitoring family inet 10.0.1.1 weight nope;")), want)
	})
	t.Run("IPMonitoringTarget/ContainerHierarchical", func(t *testing.T) {
		assertErrContains(t, compileMonitorTextErr(t, packedMonitorConfig(
			"            ip-monitoring {\n                family inet {\n                    10.0.1.1 weight nope;\n                }\n            }")), want)
	})
}

// TestChassisMonitorWeightMalformedTolerantNoBrick_6588 pins the #1960 posture:
// an already-persisted or peer-synced config carrying a malformed weight must
// still BOOT, with a warning.
func TestChassisMonitorWeightMalformedTolerantNoBrick_6588(t *testing.T) {
	p := NewParser(packedMonitorConfig("            interface-monitor ge-0/0/0 weight nope;"))
	tree, perrs := p.Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must not reject a malformed monitor weight (no-brick), got %v", err)
	}
	if !warningsContain(cfg.Warnings, `weight "nope" is not an integer`) {
		t.Fatalf("lenient compile should have warned; warnings=%v", cfg.Warnings)
	}
	// The monitor itself still compiles, with the documented 0 default.
	assertSingleMonitor(t, onlyRG6588(t, cfg), "ge-0/0/0", 0)
}

// TestChassisMonitorWeightValidStillCommits_6588 is the MAJOR-4 negative
// control: a well-formed weight — and a monitor with no weight at all, the
// documented 0 default from #6549 — must still commit. Passes with and without
// the gate.
func TestChassisMonitorWeightValidStillCommits_6588(t *testing.T) {
	for _, w := range []int{0, 1, 128, 255} {
		t.Run(fmt.Sprintf("weight_%d", w), func(t *testing.T) {
			assertSingleMonitor(t, compileMonitorText(t, packedMonitorConfig(fmt.Sprintf(
				"            interface-monitor ge-0/0/0 weight %d;", w))), "ge-0/0/0", w)
		})
	}
	t.Run("NoWeightAtAll", func(t *testing.T) {
		assertSingleMonitor(t, compileMonitorText(t, packedMonitorConfig(
			"            interface-monitor ge-0/0/0;")), "ge-0/0/0", 0)
	})
}

// Duplicates ----------------------------------------------------------------

// TestChassisMonitorWeightDuplicateRejected_6588 pins that a duplicate weight
// is rejected rather than resolved differently per spelling. Before the gate,
// `weight 100 weight 200` inline compiled to 200 (the inline scan overwrote)
// while `{ weight 100; weight 200; }` compiled to 100 (FindChild returns the
// first) — the answer depended on how the operator happened to write it.
func TestChassisMonitorWeightDuplicateRejected_6588(t *testing.T) {
	const want = "weight specified 2 times with different values"

	t.Run("InlineTail", func(t *testing.T) {
		assertErrContains(t, compileMonitorTextErr(t, packedMonitorConfig(
			"            interface-monitor ge-0/0/0 weight 100 weight 200;")), want)
	})
	t.Run("NestedBlock", func(t *testing.T) {
		assertErrContains(t, compileMonitorTextErr(t, packedMonitorConfig(
			"            interface-monitor ge-0/0/0 {\n                weight 100;\n                weight 200;\n            }")), want)
	})
	t.Run("InlineAndNested", func(t *testing.T) {
		assertErrContains(t, compileMonitorTextErr(t, packedMonitorConfig(
			"            interface-monitor ge-0/0/0 weight 100 {\n                weight 200;\n            }")), want)
	})
	t.Run("IdenticalRepeat", func(t *testing.T) {
		// Same value twice is still ambiguous authoring, but the message must
		// not claim a value conflict that does not exist.
		err := compileMonitorTextErr(t, packedMonitorConfig(
			"            interface-monitor ge-0/0/0 weight 100 weight 100;"))
		assertErrContains(t, err, "weight specified 2 times")
		if err != nil && strings.Contains(err.Error(), "different values") {
			t.Fatalf("error %q claims differing values for an identical repeat", err)
		}
	})
}

// ip-monitoring GLOBALS ------------------------------------------------------

// TestChassisIPMonitoringGlobalWeightUnusableRejected_6588 pins the gate on the
// two GROUP-WIDE ip-monitoring values.
//
// The original #6588 weight gate walked only the ENTRY lists —
// interface-monitor names and `family inet` addresses — because those are what
// monitorEntryNodes produces. global-weight and global-threshold are properties
// of the ip-monitoring statement, not entries of a list, so nothing looked at
// them: `ip-monitoring global-weight nope;` committed clean and compiled to 0.
//
// That is the worst instance of the class, not a lesser one. A malformed
// PER-TARGET weight costs the group that one target's demotion debt; a
// malformed GLOBAL weight is zero debt for the whole group, so no number of
// failing probes demotes it and failover never happens. And unlike the
// value-position collision documented on redundancyGroupStatements, a typo'd
// weight is ordinary operator input.
func TestChassisIPMonitoringGlobalWeightUnusableRejected_6588(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{"MalformedGlobalWeightPacked", "            ip-monitoring global-weight nope;",
			`global-weight "nope" is not an integer`},
		{"MalformedGlobalThresholdPacked", "            ip-monitoring global-threshold nope;",
			`global-threshold "nope" is not an integer`},
		{"MalformedGlobalWeightBlock",
			"            ip-monitoring {\n                global-weight nope;\n            }",
			`global-weight "nope" is not an integer`},
		// A keyword with no value at all must be reported as malformed, not
		// mistaken for the legal "property absent" case.
		{"GlobalWeightWithNoValue", "            ip-monitoring global-weight;",
			`global-weight "" is not an integer`},
		{"DuplicateGlobalWeightPacked",
			"            ip-monitoring global-weight 100 global-weight 200;",
			"global-weight specified 2 times with different values"},
		{"DuplicateGlobalWeightBlock",
			"            ip-monitoring {\n                global-weight 100;\n                global-weight 200;\n            }",
			"global-weight specified 2 times with different values"},
		{"DuplicateGlobalThresholdPacked",
			"            ip-monitoring global-threshold 1 global-threshold 2;",
			"global-threshold specified 2 times with different values"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertErrContains(t, compileMonitorTextErr(t, packedMonitorConfig(tc.body)), tc.want)
		})
	}

	// An identical repeat is still ambiguous authoring, but the message must
	// not claim a value conflict that does not exist.
	t.Run("IdenticalRepeatNotCalledAConflict", func(t *testing.T) {
		err := compileMonitorTextErr(t, packedMonitorConfig(
			"            ip-monitoring global-weight 100 global-weight 100;"))
		assertErrContains(t, err, "global-weight specified 2 times")
		if err != nil && strings.Contains(err.Error(), "different values") {
			t.Fatalf("error %q claims differing values for an identical repeat", err)
		}
	})

	// The gate must reach the packed instance line too, or that one spelling
	// admits what every other rejects.
	t.Run("PackedRedundancyGroupBody", func(t *testing.T) {
		assertErrContains(t, compileMonitorTextErr(t, packedRGConfig(
			"        redundancy-group 1 ip-monitoring global-weight nope;")),
			`global-weight "nope" is not an integer`)
	})
}

// TestChassisIPMonitoringGlobalsValidStillCommit_6588 is the negative control:
// every legal global still commits and compiles verbatim, including both
// boundaries and the absent case. Green with and without the gate.
func TestChassisIPMonitoringGlobalsValidStillCommit_6588(t *testing.T) {
	for _, w := range []int{0, 1, 128, 255} {
		t.Run(fmt.Sprintf("weight_%d", w), func(t *testing.T) {
			rg := compileMonitorText(t, packedMonitorConfig(fmt.Sprintf(
				"            ip-monitoring global-weight %d global-threshold %d;", w, w)))
			if rg.IPMonitoring == nil {
				t.Fatal("redundancy group carries no compiled ip-monitoring")
			}
			if rg.IPMonitoring.GlobalWeight != w || rg.IPMonitoring.GlobalThreshold != w {
				t.Fatalf("global-weight/threshold = %d/%d, want %d/%d",
					rg.IPMonitoring.GlobalWeight, rg.IPMonitoring.GlobalThreshold, w, w)
			}
		})
	}
	t.Run("GlobalsAbsent", func(t *testing.T) {
		rg := compileMonitorText(t, packedMonitorConfig(
			"            ip-monitoring family inet 10.0.1.1 weight 100;"))
		if rg.IPMonitoring == nil {
			t.Fatal("redundancy group carries no compiled ip-monitoring")
		}
		if rg.IPMonitoring.GlobalWeight != 0 || rg.IPMonitoring.GlobalThreshold != 0 {
			t.Fatalf("absent globals must stay at the 0 default, got %d/%d",
				rg.IPMonitoring.GlobalWeight, rg.IPMonitoring.GlobalThreshold)
		}
	})
}

// TestChassisIPMonitoringGlobalMalformedTolerantNoBrick_6588 pins the #1960
// posture for the new gate: an already-persisted or peer-synced config carrying
// a malformed global must still BOOT, with a warning, keeping the 0 default.
func TestChassisIPMonitoringGlobalMalformedTolerantNoBrick_6588(t *testing.T) {
	p := NewParser(packedMonitorConfig("            ip-monitoring global-weight nope;"))
	tree, perrs := p.Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must not reject a malformed ip-monitoring global (no-brick), got %v", err)
	}
	if !warningsContain(cfg.Warnings, `global-weight "nope" is not an integer`) {
		t.Fatalf("lenient compile should have warned; warnings=%v", cfg.Warnings)
	}
	rg := onlyRG6588(t, cfg)
	if rg.IPMonitoring == nil || rg.IPMonitoring.GlobalWeight != 0 {
		t.Fatalf("lenient compile must keep the 0 default, got %+v", rg.IPMonitoring)
	}
}

// TestIPMonitoringGlobalTokensMatchesCompilerRead_6588 pins the claim that
// makes the gate trustworthy: it reads the SAME token the compiler does.
//
// compileRGIPMonitoring picks a global with findNamedNode + nodeVal (first
// wins); the gate collects every value with ipMonitoringGlobalTokens. If those
// two ever disagreed about which token is the value, the gate could pass a
// string the compiler never parses — or reject one it does. Asserting the
// correspondence directly is cheaper than hoping the two stay aligned, and it
// is not a tautology: they are separate traversals with separate call sites.
func TestIPMonitoringGlobalTokensMatchesCompilerRead_6588(t *testing.T) {
	for _, body := range []string{
		"            ip-monitoring global-weight 255;",
		"            ip-monitoring global-weight 255 global-threshold 2;",
		"            ip-monitoring {\n                global-weight 255;\n                global-threshold 2;\n            }",
		"            ip-monitoring global-weight 100 global-weight 200;",
		"            ip-monitoring global-weight;",
		"            ip-monitoring family inet 10.0.1.1 weight 100;",
	} {
		t.Run(strings.TrimSpace(body), func(t *testing.T) {
			p := NewParser(packedMonitorConfig(body))
			tree, perrs := p.Parse()
			if len(perrs) > 0 {
				t.Fatalf("parse: %v", perrs)
			}
			var checked int
			for _, chassis := range tree.Children {
				if chassis.Name() != "chassis" {
					continue
				}
				for _, cluster := range chassis.Children {
					if cluster.Name() != "cluster" {
						continue
					}
					for _, rgInst := range namedInstances(cluster.FindChildren("redundancy-group")) {
						for _, child := range redundancyGroupBody(rgInst.node) {
							if child.Name() != "ip-monitoring" {
								continue
							}
							props := packedStatementProps(child, 1, isIPMonitoringProp)
							for _, name := range []string{"global-weight", "global-threshold"} {
								toks := ipMonitoringGlobalTokens(props, name)
								node := findNamedNode(props, name)
								if len(toks) == 0 {
									if node != nil {
										t.Fatalf("%s: gate sees no tokens but the compiler found a node", name)
									}
									continue
								}
								if node == nil {
									t.Fatalf("%s: gate sees %q but the compiler found no node", name, toks)
								}
								if got := nodeVal(node); got != toks[0] {
									t.Fatalf("%s: compiler reads %q, gate's first token is %q — "+
										"the gate would validate a value the compiler never uses",
										name, got, toks[0])
								}
								checked++
							}
						}
					}
				}
			}
			if checked == 0 && strings.Contains(body, "global-") {
				t.Fatal("this case reached no global comparison — it verifies nothing")
			}
		})
	}
}

// no-argument statement arity --------------------------------------------

// TestChassisRGNoArgStatementTrailingTokensRejected_6588 pins the arity gate on
// the two FLAG statements.
//
// compileRGPreempt / compileRGStrictVIPOwnership set a bool and never read the
// node, so anything else written on the statement was discarded in silence.
// Reachable by ordinary typing, and `preempt delay <n>` / `limit` / `period`
// are real Junos SRX options xpf does not implement — accepting them silently
// tells the operator they configured a preempt delay that does not exist.
// SchemaValidate accepts all of these (pinned below), so the AST gate is the
// only layer that sees them.
func TestChassisRGNoArgStatementTrailingTokensRejected_6588(t *testing.T) {
	for _, tc := range []struct {
		name string
		text string
		want string
	}{
		{"PreemptTrailingTokensPacked",
			"        redundancy-group 1 preempt weight 255;", "preempt: takes no argument"},
		{"PreemptJunosDelayPacked",
			"        redundancy-group 1 preempt delay 5;", "preempt: takes no argument"},
		{"StrictVIPOwnershipTrailingToken",
			"        redundancy-group 1 strict-vip-ownership bogus;",
			"strict-vip-ownership: takes no argument"},
		{"PreemptBlockBody",
			"        redundancy-group 1 {\n            preempt {\n                delay 5;\n            }\n        }",
			"preempt: takes no argument but carries a"},
		{"PreemptTrailingTokensContainer",
			"        redundancy-group 1 {\n            preempt delay 5;\n        }",
			"preempt: takes no argument"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertErrContains(t, compileMonitorTextErr(t, packedRGConfig(tc.text)), tc.want)
		})
	}

	// The schema walker does not see any of this — evidence for why the gate
	// runs on the AST rather than as a typed leaf.
	t.Run("SchemaValidateCannotSeeIt", func(t *testing.T) {
		tree := flatMonitorTree(t, "set chassis cluster redundancy-group 1 preempt delay 5")
		if err := SchemaValidate(tree, nil); err != nil {
			t.Fatalf("SchemaValidate unexpectedly rejected it (%v) — if the schema now covers "+
				"this, the AST gate's rationale needs revisiting", err)
		}
		if _, err := CompileConfig(tree); err == nil {
			t.Fatal("the AST gate must reject what SchemaValidate cannot see")
		}
	})
}

// TestChassisRGNoArgStatementCleanStillCommits_6588 is the arity negative
// control: the bare flags, alone and packed alongside other statements, must
// still commit. Green with and without the gate.
func TestChassisRGNoArgStatementCleanStillCommits_6588(t *testing.T) {
	t.Run("PreemptAlone", func(t *testing.T) {
		if rg := compileRGText(t, packedRGConfig("        redundancy-group 1 preempt;")); !rg.Preempt {
			t.Fatal("preempt lost")
		}
	})
	t.Run("BothFlagsPackedWithNeighbours", func(t *testing.T) {
		rg := compileRGText(t, packedRGConfig(
			"        redundancy-group 1 node 0 priority 200 preempt strict-vip-ownership gratuitous-arp-count 8;"))
		if !rg.Preempt || !rg.StrictVIPOwnership {
			t.Fatalf("preempt=%v strict-vip-ownership=%v, want both true", rg.Preempt, rg.StrictVIPOwnership)
		}
		if rg.GratuitousARPCount != 8 {
			t.Fatalf("gratuitous-arp-count = %d, want 8", rg.GratuitousARPCount)
		}
	})
	t.Run("FlatSet", func(t *testing.T) {
		cfg, err := CompileConfig(flatMonitorTree(t,
			"set chassis cluster redundancy-group 1 preempt",
			"set chassis cluster redundancy-group 1 strict-vip-ownership"))
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		rg := onlyRG6588(t, cfg)
		if !rg.Preempt || !rg.StrictVIPOwnership {
			t.Fatalf("preempt=%v strict-vip-ownership=%v, want both true", rg.Preempt, rg.StrictVIPOwnership)
		}
	})
}

// TestChassisRGNoArgTolerantNoBrick_6588 pins the #1960 posture for the arity
// gate: a persisted config with a stray token still BOOTS, with a warning, and
// the flag still compiles.
func TestChassisRGNoArgTolerantNoBrick_6588(t *testing.T) {
	p := NewParser(packedRGConfig("        redundancy-group 1 preempt delay 5;"))
	tree, perrs := p.Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must not reject a stray token on a flag statement (no-brick), got %v", err)
	}
	if !warningsContain(cfg.Warnings, "preempt: takes no argument") {
		t.Fatalf("lenient compile should have warned; warnings=%v", cfg.Warnings)
	}
	if rg := onlyRG6588(t, cfg); !rg.Preempt {
		t.Fatal("lenient compile must still set Preempt")
	}
}

func assertErrContains(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected commit to be rejected with %q, got nil error", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error %q does not contain %q", err, want)
	}
}

// assertMonitors compares the compiled monitors by NAME **and** by WEIGHT.
//
// Both arms are MANDATORY, and there is deliberately no name-only wrapper.
// This helper used to have an optional weight arm reached through an
// `assertMonitorNames(t, rg, want)` shim that passed nil, and every caller in
// this file went through that shim — so the weight arm was dead code and every
// bracketed-list case here was weight-less. That is not a hypothetical gap: it
// let `interface-monitor [ ge-0/0/0 ge-0/0/1 ] weight 255` compile to
// ge-0/0/0=0, ge-0/0/1=255 with the whole bracket suite green. A monitor that
// exists with weight 0 deducts nothing when its link fails, so the group does
// not demote — the same runtime outcome as no monitor at all, which is exactly
// what these tests exist to watch for.
//
// A caller that genuinely expects the weight-less default says so by passing
// explicit zeros. That is an assertion (the documented #6549 default), not a
// skip, and it cannot rot into one.
func assertMonitors(t *testing.T, rg *RedundancyGroup, want []string, wantWeights []int) {
	t.Helper()
	// Refuse a silently-partial check: a short wantWeights would leave the
	// tail of the monitor list unasserted, which is how the weight arm went
	// dead in the first place.
	if len(wantWeights) != len(want) {
		t.Fatalf("assertMonitors misuse: %d names %v but %d weights %v — every monitor "+
			"must be asserted by weight as well as by name",
			len(want), want, len(wantWeights), wantWeights)
	}
	if len(rg.InterfaceMonitors) != len(want) {
		t.Fatalf("expected %d interface-monitors %v, got %d: %s — a bracketed list must "+
			"compile to one monitor per name, not one monitor for the first name",
			len(want), want, len(rg.InterfaceMonitors), describeMonitors(rg.InterfaceMonitors))
	}
	for i, w := range want {
		if rg.InterfaceMonitors[i].Interface != w {
			t.Fatalf("monitor[%d] = %q, want %q (got %s)",
				i, rg.InterfaceMonitors[i].Interface, w, describeMonitors(rg.InterfaceMonitors))
		}
	}
	for i := range want {
		if got := rg.InterfaceMonitors[i].Weight; got != wantWeights[i] {
			t.Fatalf("monitor %s weight = %d, want %d (got %s) — a monitor compiled at "+
				"weight 0 deducts NOTHING when its link fails, so the redundancy group "+
				"does not demote",
				rg.InterfaceMonitors[i].Interface, got, wantWeights[i],
				describeMonitors(rg.InterfaceMonitors))
		}
	}
}

// assertIPMonTargets is the ip-monitoring counterpart, and exists for the same
// reason: the target list is built by the SAME monitorEntryNodes splitter, so a
// weight-less address assertion leaves the identical hole.
func assertIPMonTargets(t *testing.T, rg *RedundancyGroup, want []string, wantWeights []int) {
	t.Helper()
	if len(wantWeights) != len(want) {
		t.Fatalf("assertIPMonTargets misuse: %d addresses %v but %d weights %v",
			len(want), want, len(wantWeights), wantWeights)
	}
	if rg.IPMonitoring == nil {
		t.Fatal("redundancy group carries no compiled ip-monitoring")
	}
	got := rg.IPMonitoring.Targets
	describe := func() string {
		if len(got) == 0 {
			return "<none>"
		}
		parts := make([]string, 0, len(got))
		for _, tg := range got {
			parts = append(parts, fmt.Sprintf("%s weight %d", tg.Address, tg.Weight))
		}
		return strings.Join(parts, ", ")
	}
	if len(got) != len(want) {
		t.Fatalf("ip-monitoring targets = %s, want %v — a bracketed list must compile to "+
			"one target per address", describe(), want)
	}
	for i := range want {
		if got[i].Address != want[i] {
			t.Fatalf("target[%d] = %q, want %q (got %s)", i, got[i].Address, want[i], describe())
		}
		if got[i].Weight != wantWeights[i] {
			t.Fatalf("target %s weight = %d, want %d (got %s) — a target compiled at weight 0 "+
				"deducts NOTHING when its probe fails, so the redundancy group does not demote",
				got[i].Address, got[i].Weight, wantWeights[i], describe())
		}
	}
}

// ---------------------------------------------------------------------------
// #6588 review round 3 — the same Children-only bug ONE LEVEL UP.
// ---------------------------------------------------------------------------

// packedRGConfig returns hierarchical config text carrying clusterBody directly
// under `cluster`, so the redundancy-group statement itself can be written in
// the packed form. Everything here is driven through the REAL parser
// (NewParser -> CompileConfig): a hand-built AST would let the test assume the
// node shape instead of observing it, which is exactly the mistake that let
// this shape survive two review rounds.
func packedRGConfig(clusterBody string) string {
	return `chassis {
    cluster {
        authentication-key test-cluster-psk-6588;
        cluster-id 1;
` + clusterBody + `
    }
}`
}

func compileRGText(t *testing.T, text string) *RedundancyGroup {
	t.Helper()
	p := NewParser(text)
	tree, perrs := p.Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return onlyRG6588(t, cfg)
}

// TestChassisRedundancyGroupPackedBody_6588 pins the one-level-up packed
// spelling: the whole redundancy-group body written on the instance line.
//
//	redundancy-group 1 interface-monitor ge-0/0/0 weight 255;
//
// namedInstances resolves the instance NAME across both shapes (it reads
// Keys[1]) but returns the node with the body still on Keys, so a caller
// walking `.Children` saw an EMPTY group and compiled every statement to
// nothing — with no error.
//
// The `node <id> priority <p>` case is the severe one: it is the redundancy-
// group election priority. Dropped, the operator sets a priority, sees it
// echoed by `show configuration`, and the cluster elects on defaults — so the
// WRONG NODE can hold the group, a superset of "the group never demotes".
//
// FAIL-ON-REVERT: change redundancyGroupBody back to rgNode.Children and every
// Packed subtest below fails with an assertion naming the lost statement.
func TestChassisRedundancyGroupPackedBody_6588(t *testing.T) {
	t.Run("InterfaceMonitor", func(t *testing.T) {
		rg := compileRGText(t, packedRGConfig(
			"        redundancy-group 1 interface-monitor ge-0/0/0 weight 255;"))
		if len(rg.InterfaceMonitors) != 1 {
			t.Fatalf("packed redundancy-group body lost `interface-monitor ge-0/0/0 weight 255`: "+
				"got %d monitors (%s)", len(rg.InterfaceMonitors), describeMonitors(rg.InterfaceMonitors))
		}
		if rg.InterfaceMonitors[0].Interface != "ge-0/0/0" || rg.InterfaceMonitors[0].Weight != 255 {
			t.Fatalf("monitor = %s, want ge-0/0/0 weight 255", describeMonitors(rg.InterfaceMonitors))
		}
	})

	t.Run("NodePriority", func(t *testing.T) {
		rg := compileRGText(t, packedRGConfig(
			"        redundancy-group 1 node 0 priority 200;"))
		if got, ok := rg.NodePriorities[0]; !ok || got != 200 {
			t.Fatalf("packed redundancy-group body lost `node 0 priority 200`: NodePriorities = %v — "+
				"a dropped election priority means the cluster elects on defaults and the WRONG "+
				"node can hold the group", rg.NodePriorities)
		}
	})

	t.Run("Preempt", func(t *testing.T) {
		rg := compileRGText(t, packedRGConfig("        redundancy-group 1 preempt;"))
		if !rg.Preempt {
			t.Fatal("packed redundancy-group body lost `preempt`: Preempt = false")
		}
	})

	t.Run("StrictVIPOwnership", func(t *testing.T) {
		rg := compileRGText(t, packedRGConfig("        redundancy-group 1 strict-vip-ownership;"))
		if !rg.StrictVIPOwnership {
			t.Fatal("packed redundancy-group body lost `strict-vip-ownership`")
		}
	})

	t.Run("GratuitousARPCount", func(t *testing.T) {
		rg := compileRGText(t, packedRGConfig("        redundancy-group 1 gratuitous-arp-count 8;"))
		if rg.GratuitousARPCount != 8 {
			t.Fatalf("packed redundancy-group body lost `gratuitous-arp-count 8`: got %d",
				rg.GratuitousARPCount)
		}
	})

	t.Run("IPMonitoring", func(t *testing.T) {
		rg := compileRGText(t, packedRGConfig(
			"        redundancy-group 1 ip-monitoring global-weight 255;"))
		if rg.IPMonitoring == nil {
			t.Fatal("packed redundancy-group body lost `ip-monitoring global-weight 255`: IPMonitoring is nil")
		}
		if rg.IPMonitoring.GlobalWeight != 255 {
			t.Fatalf("global-weight = %d, want 255", rg.IPMonitoring.GlobalWeight)
		}
	})

	// Several statements on one instance line must each survive — the tail is
	// split at redundancy-group statement keywords, not folded into the first.
	t.Run("MultipleStatementsOnOneLine", func(t *testing.T) {
		rg := compileRGText(t, packedRGConfig(
			"        redundancy-group 1 node 0 priority 200 preempt gratuitous-arp-count 8;"))
		if got, ok := rg.NodePriorities[0]; !ok || got != 200 {
			t.Fatalf("lost `node 0 priority 200` from a multi-statement packed body: %v", rg.NodePriorities)
		}
		if !rg.Preempt {
			t.Fatal("lost `preempt` from a multi-statement packed body")
		}
		if rg.GratuitousARPCount != 8 {
			t.Fatalf("lost `gratuitous-arp-count 8` from a multi-statement packed body: got %d",
				rg.GratuitousARPCount)
		}
	})
}

// TestChassisRedundancyGroupContainerBodyUnchanged_6588 is the round-3 negative
// control: the already-working container form must compile exactly as before,
// every statement intact. It passes with and without redundancyGroupBody.
func TestChassisRedundancyGroupContainerBodyUnchanged_6588(t *testing.T) {
	rg := compileRGText(t, packedRGConfig(
		"        redundancy-group 1 {\n"+
			"            node 0 priority 200;\n"+
			"            node 1 priority 100;\n"+
			"            preempt;\n"+
			"            strict-vip-ownership;\n"+
			"            gratuitous-arp-count 8;\n"+
			"            interface-monitor ge-0/0/0 weight 255;\n"+
			"            ip-monitoring {\n"+
			"                global-weight 200;\n"+
			"                family inet {\n"+
			"                    10.0.1.1 weight 100;\n"+
			"                }\n"+
			"            }\n"+
			"        }"))
	if rg.NodePriorities[0] != 200 || rg.NodePriorities[1] != 100 {
		t.Fatalf("NodePriorities = %v, want {0:200, 1:100}", rg.NodePriorities)
	}
	if !rg.Preempt || !rg.StrictVIPOwnership {
		t.Fatalf("preempt=%v strict-vip-ownership=%v, want both true", rg.Preempt, rg.StrictVIPOwnership)
	}
	if rg.GratuitousARPCount != 8 {
		t.Fatalf("gratuitous-arp-count = %d, want 8", rg.GratuitousARPCount)
	}
	if len(rg.InterfaceMonitors) != 1 || rg.InterfaceMonitors[0].Weight != 255 {
		t.Fatalf("monitors = %s, want one ge-0/0/0 weight 255", describeMonitors(rg.InterfaceMonitors))
	}
	if rg.IPMonitoring == nil || rg.IPMonitoring.GlobalWeight != 200 ||
		len(rg.IPMonitoring.Targets) != 1 || rg.IPMonitoring.Targets[0].Weight != 100 {
		t.Fatalf("ip-monitoring = %+v, want global-weight 200 with one target weight 100", rg.IPMonitoring)
	}
}

// TestChassisRedundancyGroupPackedBodyReachesGates_6588 pins that the round-2
// gates see the one-level-up packed shape too. Making the body compile without
// bringing the gates along would admit, through the packed instance line
// only, exactly what round 2 closed everywhere else.
func TestChassisRedundancyGroupPackedBodyReachesGates_6588(t *testing.T) {
	t.Run("MalformedWeightStillRejected", func(t *testing.T) {
		assertErrContains(t, compileMonitorTextErr(t, packedRGConfig(
			"        redundancy-group 1 interface-monitor ge-0/0/0 weight nope;")),
			`weight "nope" is not an integer`)
	})
	t.Run("OutOfRangeWeightStillRejected", func(t *testing.T) {
		assertErrContains(t, compileMonitorTextErr(t, packedRGConfig(
			"        redundancy-group 1 interface-monitor ge-0/0/0 weight 300;")),
			"weight 300 is out of range 0..255")
	})
	t.Run("DuplicateWeightStillRejected", func(t *testing.T) {
		assertErrContains(t, compileMonitorTextErr(t, packedRGConfig(
			"        redundancy-group 1 interface-monitor ge-0/0/0 weight 100 weight 200;")),
			"weight specified 2 times with different values")
	})
	t.Run("BracketListStillSplits", func(t *testing.T) {
		assertMonitors(t, compileRGText(t, packedRGConfig(
			"        redundancy-group 1 interface-monitor [ ge-0/0/0 ge-0/0/1 ];")),
			[]string{"ge-0/0/0", "ge-0/0/1"}, []int{0, 0})
	})
	t.Run("BracketListWeightReachesEveryMember", func(t *testing.T) {
		assertMonitors(t, compileRGText(t, packedRGConfig(
			"        redundancy-group 1 interface-monitor [ ge-0/0/0 ge-0/0/1 ] weight 255;")),
			[]string{"ge-0/0/0", "ge-0/0/1"}, []int{255, 255})
	})
	t.Run("IPMonitoringRangeStillGated", func(t *testing.T) {
		assertErrContains(t, compileMonitorTextErr(t, packedRGConfig(
			"        redundancy-group 1 ip-monitoring global-weight 300;")),
			"global-weight 300 is out of range 0..255")
	})
	// #5694 identity gate: a malformed RG-scoped node id must still be caught
	// when the whole body is packed onto the instance line.
	t.Run("MalformedNodeIDStillRejected", func(t *testing.T) {
		assertErrContains(t, compileMonitorTextErr(t, packedRGConfig(
			"        redundancy-group 1 node bogus priority 200;")),
			"redundancy-group node")
	})
}

// TestRedundancyGroupStatementsSurvivePackedLine_6588 replaces the deleted
// source-parsing drift guard.
//
// That guard modelled compileChassis's source text — it extracted the `case
// "..."` literals of one switch — and passed while a 7th statement was still
// dropped from a packed multi-statement line in three ways: a case on a named
// CONSTANT rather than a literal, a statement handled by a helper called
// outside the switch, and a nested switch in a `default:` arm. Both consumers
// now derive from redundancyGroupStatements, so the drift it was watching for
// cannot occur and re-asserting it would prove a tautology.
//
// What is still worth pinning is the PROPERTY the drift mattered for, and this
// derives its cases from the table rather than restating them: every registered
// statement must survive being written on a packed line ALONGSIDE another
// statement. That is the spelling the fold bug hides in — the same statement
// ALONE on a line works even when the splitter does not know it, which is what
// let a developer see it work and ship the bug.
//
// Because the cases come from the table, a statement added later is covered the
// moment it is registered, with no list here to update.
func TestRedundancyGroupStatementsSurvivePackedLine_6588(t *testing.T) {
	if len(redundancyGroupStatements) < 6 {
		t.Fatalf("redundancyGroupStatements has %d entries, expected at least the 6 known "+
			"statements — this test derives its cases from that table and would otherwise "+
			"verify almost nothing", len(redundancyGroupStatements))
	}

	// One well-formed instance of each statement, keyed by table entry. A new
	// table entry with no sample here fails the completeness check below rather
	// than being skipped silently.
	samples := map[string]struct {
		text   string
		assert func(t *testing.T, rg *RedundancyGroup)
	}{
		"node": {"node 0 priority 200", func(t *testing.T, rg *RedundancyGroup) {
			if got, ok := rg.NodePriorities[0]; !ok || got != 200 {
				t.Fatalf("node priority lost: %v", rg.NodePriorities)
			}
		}},
		"gratuitous-arp-count": {"gratuitous-arp-count 8", func(t *testing.T, rg *RedundancyGroup) {
			if rg.GratuitousARPCount != 8 {
				t.Fatalf("gratuitous-arp-count = %d, want 8", rg.GratuitousARPCount)
			}
		}},
		"preempt": {"preempt", func(t *testing.T, rg *RedundancyGroup) {
			if !rg.Preempt {
				t.Fatal("preempt lost")
			}
		}},
		"strict-vip-ownership": {"strict-vip-ownership", func(t *testing.T, rg *RedundancyGroup) {
			if !rg.StrictVIPOwnership {
				t.Fatal("strict-vip-ownership lost")
			}
		}},
		"interface-monitor": {"interface-monitor ge-0/0/0 weight 255", func(t *testing.T, rg *RedundancyGroup) {
			if len(rg.InterfaceMonitors) != 1 || rg.InterfaceMonitors[0].Weight != 255 {
				t.Fatalf("interface-monitor lost: %s", describeMonitors(rg.InterfaceMonitors))
			}
		}},
		"ip-monitoring": {"ip-monitoring global-weight 255", func(t *testing.T, rg *RedundancyGroup) {
			if rg.IPMonitoring == nil || rg.IPMonitoring.GlobalWeight != 255 {
				t.Fatalf("ip-monitoring lost: %+v", rg.IPMonitoring)
			}
		}},
		"allow-degraded-routing-takeover": {"allow-degraded-routing-takeover", func(t *testing.T, rg *RedundancyGroup) {
			if !rg.AllowDegradedRoutingTakeover {
				t.Fatal("allow-degraded-routing-takeover lost")
			}
		}},
	}

	// This completeness check is also the trip-wire for the splitter's
	// over-match route (see redundancyGroupStatements' doc comment): the
	// splitter matches a registered keyword wherever the token appears in a
	// packed tail, including in entry-NAME position, so a keyword that can also
	// spell an interface name or an IP address would be STOLEN from the
	// statement it belongs to and the packed and container spellings would
	// disagree. No current keyword can (names are ge-*/xe-*, reth*, fxp*, em*,
	// lo0, st0, ae*, fab*, irb, vlan). Registering a new statement fails here
	// until a sample is added — that is the moment to check the new keyword
	// against those shapes.
	for stmt := range redundancyGroupStatements {
		if _, ok := samples[stmt]; !ok {
			t.Errorf("redundancyGroupStatements registers %q but this test has no sample for "+
				"it, so its packed-line behaviour is unverified — add one", stmt)
		}
	}

	// Requiring a sample to EXIST is not enough: it must be a sample OF the
	// statement it is filed under. Without this, an entry could be satisfied by
	// text that compiles some other statement entirely — a placeholder keyed
	// `review-placeholder` whose text is `preempt`, with a Preempt assertion,
	// passed every check in this test while `review-placeholder` never appeared
	// in the input and its handler was never dispatched. The completeness check
	// then guarantees nothing, which is worse than not having it, because the
	// next person reads a green test as coverage.
	for stmt, s := range samples {
		if s.text != stmt && !strings.HasPrefix(s.text, stmt+" ") {
			t.Errorf("sample for %q is %q, which does not begin with the statement keyword — "+
				"the case compiles some OTHER statement while appearing to cover %q",
				stmt, s.text, stmt)
		}
	}

	// Pair every statement with a DIFFERENT one on the same packed line, in both
	// orders. A statement the splitter does not know folds into its neighbour,
	// and only the multi-statement spelling exposes that.
	for a, sa := range samples {
		if _, ok := redundancyGroupStatements[a]; !ok {
			continue
		}
		for b, sb := range samples {
			if b == a {
				continue
			}
			t.Run(a+"_then_"+b, func(t *testing.T) {
				dispatched := instrumentRGDispatch(t)
				rg := compileRGText(t, packedRGConfig(
					"        redundancy-group 1 "+sa.text+" "+sb.text+";"))
				sa.assert(t, rg)
				sb.assert(t, rg)
				// The typed assertions above can be satisfied by the WRONG
				// statement — `preempt` sets rg.Preempt no matter which key
				// the sample is filed under. Requiring the handler registered
				// under each key to have actually run is what ties the case to
				// its table entry.
				for _, stmt := range []string{a, b} {
					if !dispatched(stmt) {
						t.Errorf("compiling this packed line never dispatched the handler "+
							"registered under %q, so the case does not exercise the statement "+
							"it is filed under", stmt)
					}
				}
			})
		}
	}
}

// instrumentRGDispatch wraps every redundancyGroupStatements handler so a test
// can ask which ones a compile actually reached, and restores the table when
// the test ends.
//
// Wrapping preserves the table's KEYS, so isRedundancyGroupStatement and the
// packed-line splitter behave identically while instrumented — the test
// observes dispatch without changing what is dispatched.
func instrumentRGDispatch(t *testing.T) func(stmt string) bool {
	t.Helper()
	orig := make(map[string]func(*RedundancyGroup, *Node), len(redundancyGroupStatements))
	fired := make(map[string]bool, len(redundancyGroupStatements))
	for name, fn := range redundancyGroupStatements {
		orig[name] = fn
		name, fn := name, fn
		redundancyGroupStatements[name] = func(rg *RedundancyGroup, child *Node) {
			fired[name] = true
			fn(rg, child)
		}
	}
	t.Cleanup(func() {
		for name, fn := range orig {
			redundancyGroupStatements[name] = fn
		}
	})
	return func(stmt string) bool { return fired[stmt] }
}

// TestRedundancyGroupNoArgStatementsAreRegistered_6588 keeps
// redundancyGroupNoArgStatements in step with the dispatch table. Arity cannot
// be derived from a handler's type, so the flag set is written by hand; a name
// in it that is not a registered statement means the arity gate is guarding a
// statement the compiler does not have.
func TestRedundancyGroupNoArgStatementsAreRegistered_6588(t *testing.T) {
	for stmt := range redundancyGroupNoArgStatements {
		if _, ok := redundancyGroupStatements[stmt]; !ok {
			t.Errorf("redundancyGroupNoArgStatements lists %q but redundancyGroupStatements "+
				"does not register it — the arity gate guards a statement that is never "+
				"compiled", stmt)
		}
	}
}
