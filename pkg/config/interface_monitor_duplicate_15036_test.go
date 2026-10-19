package config

import (
	"strings"
	"testing"
)

// #15036 (A15-01): re-setting an interface-monitor weight appends a SECOND
// monitor for the same interface instead of replacing the first.
//
//	redundancy-group 1 {
//	    interface-monitor ge-0/0/1 weight 100;
//	    interface-monitor ge-0/0/1 weight 255;
//	}
//
// compileRGInterfaceMonitors appended per entry with no dedup, so the
// compiled group carried [{ge-0/0/1,100} {ge-0/0/1,255}]. The two runtime
// consumers then disagreed about which weight was live:
//
//   - pkg/cluster/monitor.go pollInterfaceMonitors shares one dampening
//     key per (rg,iface); on the first down-transition it calls
//     SetMonitorWeight with the FIRST entry's weight (100), so the group
//     stays primary behind a dead monitored link.
//   - pkg/cluster/election.go reconcileMonitorDebtsLocked builds a
//     last-wins desired map, so an unrelated later commit reapplies 255.
//
// Fix: fold entries by interface last-wins in compileRGInterfaceMonitors
// and strict-reject the duplicate in validateMonitorWeightTokensAST (the
// AST gate, since the fold erases the duplicate from the compiled
// struct); the tolerant path keeps the folded single monitor and warns
// (#1960 no-brick), mirroring the sibling chassis gates.
//
// FAIL-ON-REVERT: remove the fold in compileRGInterfaceMonitors and the
// duplicate-monitors subtests fail with 2 monitors; remove the strict
// duplicate rejection and the strict-reject subtests compile clean.

// duplicateMonitorConfig returns a hierarchical config whose redundancy
// group carries rgBody verbatim (same shape as packedMonitorConfig).
func duplicateMonitorConfig(rgBody string) string {
	return packedMonitorConfig(rgBody)
}

func TestInterfaceMonitorDuplicateStrictRejects_15036(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{
			name: "PackedDuplicateDifferentWeight",
			body: "            interface-monitor ge-0/0/1 weight 100;\n" +
				"            interface-monitor ge-0/0/1 weight 255;",
		},
		{
			name: "PackedDuplicateSameWeight",
			body: "            interface-monitor ge-0/0/1 weight 100;\n" +
				"            interface-monitor ge-0/0/1 weight 100;",
		},
		{
			// Bracketed list collapses both names onto one node's Keys;
			// a repeat inside the list is the same duplicate.
			name: "BracketListRepeat",
			body: "            interface-monitor [ ge-0/0/1 ge-0/0/1 ] weight 255;",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := NewParser(duplicateMonitorConfig(tc.body))
			tree, perrs := p.Parse()
			if len(perrs) > 0 {
				t.Fatalf("parse: %v", perrs)
			}
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("duplicate interface-monitor ge-0/0/1 must be rejected at commit, compiled clean")
			}
			if !strings.Contains(err.Error(), "duplicate interface-monitor") ||
				!strings.Contains(err.Error(), "ge-0/0/1") {
				t.Fatalf("error = %q, want a duplicate interface-monitor ge-0/0/1 rejection", err)
			}
		})
	}
}

// TestInterfaceMonitorDuplicateContainerStrictRejects_15036 pins the
// container-hierarchical spelling: two `ge-0/0/1` children under one
// `interface-monitor { ... }` block.
func TestInterfaceMonitorDuplicateContainerStrictRejects_15036(t *testing.T) {
	text := `chassis {
    cluster {
        authentication-key test-cluster-psk-15036;
        cluster-id 1;
        redundancy-group 1 {
            node 0 priority 200;
            interface-monitor {
                ge-0/0/1 weight 100;
                ge-0/0/1 weight 255;
            }
        }
    }
}`
	p := NewParser(text)
	tree, perrs := p.Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("duplicate interface-monitor in container spelling must be rejected at commit")
	}
	if !strings.Contains(err.Error(), "duplicate interface-monitor") {
		t.Fatalf("error = %q, want duplicate interface-monitor", err)
	}
}

// TestInterfaceMonitorDuplicateFlatSet_15036 pins the flat-set spelling.
// SetPath keeps both `set ... interface-monitor ge-0/0/1 weight <n>` lines
// as sibling statements (the leaf is untyped, children==nil), so the same
// duplicate reaches the compiler here too.
func TestInterfaceMonitorDuplicateFlatSet_15036(t *testing.T) {
	tree := buildTree(t, []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key test-cluster-psk-15036",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set chassis cluster redundancy-group 1 interface-monitor ge-0/0/1 weight 100",
		"set chassis cluster redundancy-group 1 interface-monitor ge-0/0/1 weight 255",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("duplicate interface-monitor via flat set must be rejected at commit")
	}
	if !strings.Contains(err.Error(), "duplicate interface-monitor") {
		t.Fatalf("error = %q, want duplicate interface-monitor", err)
	}
}

// TestInterfaceMonitorDuplicateLenientFoldsLastWins_15036 pins the #1960
// no-brick tolerant path: an already-persisted or peer-pushed config
// carrying the duplicate still boots, with a warning, and compiles to
// exactly ONE monitor carrying the LAST weight — so the poll path and the
// debt reconciler read the same single weight before and after any
// re-commit.
func TestInterfaceMonitorDuplicateLenientFoldsLastWins_15036(t *testing.T) {
	body := "            interface-monitor ge-0/0/1 weight 100;\n" +
		"            interface-monitor ge-0/0/1 weight 255;"
	p := NewParser(duplicateMonitorConfig(body))
	tree, perrs := p.Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must not brick on a duplicate monitor: %v", err)
	}
	rg := onlyRG6588(t, cfg)
	if len(rg.InterfaceMonitors) != 1 {
		t.Fatalf("lenient duplicate must fold to exactly 1 monitor, got %d: %s",
			len(rg.InterfaceMonitors), describeMonitors(rg.InterfaceMonitors))
	}
	m := rg.InterfaceMonitors[0]
	if m.Interface != "ge-0/0/1" || m.Weight != 255 {
		t.Fatalf("folded monitor = %s weight %d, want ge-0/0/1 weight 255 (last-wins)",
			m.Interface, m.Weight)
	}
	foundWarn := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "duplicate interface-monitor") && strings.Contains(w, "ge-0/0/1") {
			foundWarn = true
		}
	}
	if !foundWarn {
		t.Fatalf("lenient duplicate must warn; warnings = %v", cfg.Warnings)
	}
}

// TestInterfaceMonitorDistinctInterfacesStillCompile_15036 is the
// control: two DIFFERENT interfaces are legitimate and must keep both
// monitors, in authored order, with their own weights.
func TestInterfaceMonitorDistinctInterfacesStillCompile_15036(t *testing.T) {
	rg := compileMonitorText(t, duplicateMonitorConfig(
		"            interface-monitor ge-0/0/0 weight 100;\n"+
			"            interface-monitor ge-0/0/1 weight 255;"))
	if len(rg.InterfaceMonitors) != 2 {
		t.Fatalf("expected 2 distinct monitors, got %d: %s",
			len(rg.InterfaceMonitors), describeMonitors(rg.InterfaceMonitors))
	}
	if rg.InterfaceMonitors[0].Interface != "ge-0/0/0" || rg.InterfaceMonitors[0].Weight != 100 ||
		rg.InterfaceMonitors[1].Interface != "ge-0/0/1" || rg.InterfaceMonitors[1].Weight != 255 {
		t.Fatalf("monitors = %s, want [ge-0/0/0 weight 100, ge-0/0/1 weight 255]",
			describeMonitors(rg.InterfaceMonitors))
	}
}
