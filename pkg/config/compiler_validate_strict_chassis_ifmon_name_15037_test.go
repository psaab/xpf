package config

import (
	"os"
	"strings"
	"testing"
)

// #15037 (A15-03): a redundancy-group `interface-monitor <name>` was never
// checked against the interfaces the config actually defines. The monitor
// (pkg/cluster/monitor.go pollInterfaceMonitors) resolves the name with
// LinuxIfName and LinkByName; only a name whose FPC slot belongs to the PEER
// is skipped. A RETH name (reth0 — slot -1) or a name defined nowhere has no
// netdev on EITHER node, so both nodes count it down: each subtracts the
// weight, both redundancy-group weights hit 0, and election.go's
// weight<=0 -> secondary leaves the RG owned by NEITHER node from one
// clean-committed line.
//
// FAIL-ON-REVERT: remove the interface-monitor name check from
// validateChassisClusterStrict and the reject subtests below go green on
// the BAD configs. The defined / peer-slot / fabric / dash-spelling
// subtests pin that the gate does not over-reject the shapes the shipped
// cluster configs carry, and the tolerant subtest pins #1960 no-brick.

// ifMonNameSetLines returns flat-set lines for one redundancy group
// monitoring iface, plus any extra lines (interface definitions).
func ifMonNameSetLines(iface string, extra ...string) []string {
	lines := []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key test-cluster-psk-6611",
		"set chassis cluster no-private-rg-election",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set chassis cluster redundancy-group 1 interface-monitor " + iface + " weight 255",
	}
	return append(lines, extra...)
}

func TestChassisInterfaceMonitorUndefinedNameFailsCommit_15037(t *testing.T) {
	cases := []struct {
		name  string
		iface string
		extra []string
	}{
		{"reth name", "reth0", []string{
			"set interfaces reth0 redundant-ether-options redundancy-group 1",
			"set interfaces ge-0/0/0 gigether-options redundant-parent reth0",
			"set interfaces ge-7/0/0 gigether-options redundant-parent reth0",
		}},
		{"undefined physical typo beside declared member", "ge-0/0/99", []string{
			"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/30",
		}},
		{"undefined non-physical", "nosuch0", nil},
		{"unit suffix", "ge-0/0/0.0", []string{
			"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/30",
		}},
		{"peer typo not matching declared RETH member tail", "ge-0/0/99", []string{
			"set interfaces ge-7/0/1 gigether-options redundant-parent reth0",
			"set interfaces reth0 redundant-ether-options redundancy-group 1",
		}},
		{"same-slot nonmember beside declared RETH member", "ge-7/0/99", []string{
			"set interfaces ge-7/0/1 gigether-options redundant-parent reth0",
			"set interfaces reth0 redundant-ether-options redundancy-group 1",
		}},
		{"peer tail whose local twin belongs to different RETH group", "ge-0/0/1", []string{
			"set interfaces ge-7/0/1 gigether-options redundant-parent reth0",
			"set interfaces reth0 redundant-ether-options redundancy-group 2",
			"set interfaces ge-7/0/2 gigether-options redundant-parent reth1",
			"set interfaces reth1 redundant-ether-options redundancy-group 1",
		}},
		{"empty-adjacent fabric name", "fab0", []string{
			"set interfaces fab0 unit 0 family inet address 10.99.0.1/30",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTree(t, ifMonNameSetLines(tc.iface, tc.extra...))
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("expected commit to reject interface-monitor %q "+
					"(no such physical interface is defined, so the monitor "+
					"counts it down on both nodes and the redundancy group is "+
					"owned by neither), got nil error", tc.iface)
			}
			if !strings.Contains(err.Error(), "interface-monitor "+tc.iface) {
				t.Fatalf("error %q does not name the offending interface-monitor %q", err, tc.iface)
			}
		})
	}
}

func TestChassisInterfaceMonitorDefinedNameCommits_15037(t *testing.T) {
	cases := []struct {
		name  string
		iface string
		extra []string
	}{
		{"defined local member", "ge-0/0/0", []string{
			"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/30",
		}},
		{"defined peer member", "ge-7/0/0", []string{
			"set interfaces ge-7/0/0 unit 0 family inet address 10.0.0.2/30",
		}},
		{"dash spelling of defined", "ge-0-0-0", []string{
			"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/30",
		}},
		{"peer-only member via fabric", "ge-7/0/0", []string{
			"set interfaces fab1 fabric-options member-interfaces ge-7/0/0",
		}},
		{"local member via fabric", "ge-0/0/0", []string{
			"set interfaces fab0 fabric-options member-interfaces ge-0/0/0",
		}},
		{"reth member defined only as redundant-parent", "ge-0/0/0", []string{
			"set interfaces ge-0/0/0 gigether-options redundant-parent reth0",
			"set interfaces reth0 redundant-ether-options redundancy-group 1",
		}},
		{"stanza-less physical name (nothing declared anywhere)", "ge-0/0/0", nil},
		{"peer member of declared RETH in single-node view (fw1 shape)", "ge-0/0/1", []string{
			"set interfaces ge-7/0/1 gigether-options redundant-parent reth0",
			"set interfaces reth0 redundant-ether-options redundancy-group 1",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTree(t, ifMonNameSetLines(tc.iface, tc.extra...))
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("interface-monitor %q with a defined/attributable "+
					"physical interface must commit, got %v", tc.iface, err)
			}
			mons := onlyRGInterfaceMonitors(t, cfg)
			if len(mons) != 1 || mons[0].Interface != tc.iface {
				t.Fatalf("expected the single monitor %q to compile, got %+v", tc.iface, mons)
			}
		})
	}
}

// #16574: the fabric cases above carried NO other physical interface, so
// the declared set was {fabric member} only via the member arm — but on
// the broken code the member arm never ran outside `groups`, the set
// stayed empty, and the empty-set fallback in
// interfaceMonitorNameAttributable (`len(declared) == 0 -> true`)
// admitted the monitor anyway. The cell therefore passed even with the
// arm deleted. Every case below declares an UNRELATED physical interface
// (ge-0/0/5), which makes the set non-empty, so the fabric member is
// admitted ONLY if the `interfaces > fabN > fabric-options >
// member-interfaces` arm actually mints it.
//
// FAIL-ON-REVERT / MUTANT: delete (or gate out) the member-interfaces
// case in collectPhysicalInterfaces and every commit case below goes
// red with the strict fabric refusal, while the stray-path reject case
// stays red in both states (it pins that the fix does not widen to any
// member-interfaces spelling anywhere).
func TestChassisInterfaceMonitorFabricMemberWithOtherPhysical_16574(t *testing.T) {
	const unrelated = "set interfaces ge-0/0/5 unit 0 family inet address 10.0.0.1/30"

	commit := []struct {
		name  string
		iface string
		extra []string
	}{
		{"flat-set local fabric member beside unrelated physical", "ge-0/0/0", []string{
			"set interfaces fab0 fabric-options member-interfaces ge-0/0/0",
			unrelated,
		}},
		{"flat-set peer fabric member beside unrelated physical", "ge-7/0/0", []string{
			"set interfaces fab1 fabric-options member-interfaces ge-7/0/0",
			unrelated,
		}},
		{"flat-set bracket fabric members beside unrelated physical", "ge-0/0/1", []string{
			"set interfaces fab0 fabric-options member-interfaces [ ge-0/0/0 ge-0/0/1 ]",
			unrelated,
		}},
		{"dash spelling of fabric member beside unrelated physical", "ge-0-0-0", []string{
			"set interfaces fab0 fabric-options member-interfaces ge-0/0/0",
			unrelated,
		}},
	}
	for _, tc := range commit {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTree(t, ifMonNameSetLines(tc.iface, tc.extra...))
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("interface-monitor %q naming a fabric "+
					"member-interfaces entry must commit even when "+
					"another physical interface is declared (#16574), "+
					"got %v", tc.iface, err)
			}
			mons := onlyRGInterfaceMonitors(t, cfg)
			if len(mons) != 1 || mons[0].Interface != tc.iface {
				t.Fatalf("expected the single monitor %q to compile, got %+v", tc.iface, mons)
			}
		})
	}

	// Hierarchical spellings: the names sit on the member-interfaces
	// node's own Keys (single / bracket) or on leaf children (block),
	// at depth 3 below a top-level `interfaces` node.
	hier := []struct {
		name string
		src  string
	}{
		{"hier single fabric member beside unrelated physical", `
chassis {
    cluster {
        cluster-id 1;
        authentication-key test-cluster-psk-6611;
        no-private-rg-election;
        redundancy-group 1 {
            node 0 priority 200;
            interface-monitor ge-0/0/0 weight 255;
        }
    }
}
interfaces {
    fab0 { fabric-options { member-interfaces ge-0/0/0; } }
    ge-0/0/5 { unit 0 { family inet { address 10.0.0.1/30; } } }
}
`},
		{"hier block fabric members beside unrelated physical", `
chassis {
    cluster {
        cluster-id 1;
        authentication-key test-cluster-psk-6611;
        no-private-rg-election;
        redundancy-group 1 {
            node 0 priority 200;
            interface-monitor ge-0/0/0 weight 255;
        }
    }
}
interfaces {
    fab0 { fabric-options { member-interfaces { ge-0/0/0; ge-7/0/0; } } }
    ge-0/0/5 { unit 0 { family inet { address 10.0.0.1/30; } } }
}
`},
		{"hier bracket fabric members beside unrelated physical", `
chassis {
    cluster {
        cluster-id 1;
        authentication-key test-cluster-psk-6611;
        no-private-rg-election;
        redundancy-group 1 {
            node 0 priority 200;
            interface-monitor ge-0/0/0 weight 255;
        }
    }
}
interfaces {
    fab0 { fabric-options { member-interfaces [ ge-0/0/0 ge-7/0/0 ]; } }
    ge-0/0/5 { unit 0 { family inet { address 10.0.0.1/30; } } }
}
`},
	}
	for _, tc := range hier {
		t.Run(tc.name, func(t *testing.T) {
			p := NewParser(tc.src)
			tree, perrs := p.Parse()
			if len(perrs) > 0 {
				t.Fatalf("parse: %v", perrs)
			}
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("hierarchical fabric member-interfaces entry "+
					"must attribute its member beside an unrelated "+
					"physical interface (#16574), got %v", err)
			}
			mons := onlyRGInterfaceMonitors(t, cfg)
			if len(mons) != 1 || mons[0].Interface != "ge-0/0/0" {
				t.Fatalf("expected the single ge-0/0/0 monitor to compile, got %+v", mons)
			}
		})
	}

	// Negative control: a member-interfaces entry under a NON-fabric
	// interface is not a fabric member-interfaces entry. The monitor
	// naming only that entry's member, beside the unrelated declared
	// interface, must still be strict-rejected — the fix mints on the
	// `interfaces > fabN > fabric-options` path only, not on any
	// member-interfaces spelling anywhere in the tree.
	t.Run("member-interfaces under non-fabric interface does not attribute", func(t *testing.T) {
		tree := buildTree(t, ifMonNameSetLines("ge-0/0/9",
			"set interfaces ge-0/0/5 fabric-options member-interfaces ge-0/0/9",
			unrelated))
		_, err := CompileConfig(tree)
		if err == nil {
			t.Fatalf("interface-monitor ge-0/0/9 naming only a " +
				"member-interfaces entry under a non-fabric interface " +
				"must be rejected, got nil error")
		}
		if !strings.Contains(err.Error(), "interface-monitor ge-0/0/9") {
			t.Fatalf("error %q does not name the offending interface-monitor", err)
		}
	})
}

func TestChassisInterfaceMonitorUndefinedNameTolerantWarns_15037(t *testing.T) {
	tree := buildTree(t, ifMonNameSetLines("reth0",
		"set interfaces reth0 redundant-ether-options redundancy-group 1"))

	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must not reject an undefined interface-monitor "+
			"name (no-brick #1960), got %v", err)
	}
	if !warningsContain(cfg.Warnings, "interface-monitor reth0") {
		t.Fatalf("lenient compile should have warned about the undefined "+
			"interface-monitor; warnings=%v", cfg.Warnings)
	}
	// The monitor stays compiled verbatim — the warning is the signal, the
	// runtime behaviour for a leniently-loaded name is unchanged.
	mons := onlyRGInterfaceMonitors(t, cfg)
	if len(mons) != 1 || mons[0].Interface != "reth0" {
		t.Fatalf("lenient compile should preserve the monitor, got %+v", mons)
	}
}

// TestShippedConfigsHaveOnlyPhysicalInterfaceMonitors_15037 points the gate
// at the configs we actually ship: every interface-monitor they carry must
// name a defined or fabric/member-attributable PHYSICAL interface. This is
// the #6751 lesson — a gate no shipped config is run against reports a
// value indistinguishable from healthy.
func TestShippedConfigsHaveOnlyPhysicalInterfaceMonitors_15037(t *testing.T) {
	files := []string{
		"../../docs/ha-cluster.conf",
		"../../docs/ha-cluster-loss.conf",
		"../../docs/ha-cluster-userspace.conf",
		"../../test/incus/xpf-cluster-fw0.conf",
		"../../test/incus/xpf-cluster-fw1.conf",
		"../../examples/deploy/ha-pair.conf",
	}
	checked := 0
	for _, rel := range files {
		raw, err := os.ReadFile(rel)
		if err != nil {
			t.Errorf("read %s: %v (if this file moved, update this list — a "+
				"config that drops off it stops being gated)", rel, err)
			continue
		}
		p := NewParser(string(raw))
		tree, perrs := p.Parse()
		if len(perrs) > 0 {
			t.Errorf("parse %s: %v", rel, perrs)
			continue
		}
		// Compile for BOTH nodes: apply-groups ${node} selects different
		// per-node interface stanzas, and both personalities must pass.
		for _, node := range []int{0, 1} {
			if _, err := CompileConfigForNode(tree, node); err != nil {
				t.Errorf("%s node %d: shipped config must commit (every "+
					"interface-monitor names a physical interface): %v", rel, node, err)
			}
		}
		checked++
	}
	if checked != len(files) {
		t.Fatalf("checked %d of %d shipped configs", checked, len(files))
	}
}
