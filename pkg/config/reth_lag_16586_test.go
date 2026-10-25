package config

import (
	"strings"
	"testing"
)

// #16586: a Junos reth LAG (two or more child links per node) committed
// strict-clean without a diagnostic. RethToPhysical binds only the
// lexically-first local child; the others came up zoneless with a
// duplicate 169.254 RG source and no virtual MAC.
//
// FAIL-ON-REVERT: drop the validateRethMultiChildAST dispatch in
// compileTree (compiler.go) and the reject subtests below go green on
// the BAD config; drop the lenient flag and the tolerant subtest bricks.

func rethLAGLines(extra ...string) []string {
	return append([]string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key test-cluster-psk-16586",
		"set chassis cluster reth-count 2",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set chassis cluster redundancy-group 1 node 1 priority 100",
		"set interfaces reth1 redundant-ether-options redundancy-group 1",
		"set interfaces reth1 unit 0 family inet address 10.0.61.1/24",
		"set security zones security-zone trust interfaces reth1.0",
	}, extra...)
}

func TestRethLAGMultiChildPerNodeRejected16586(t *testing.T) {
	cases := []struct {
		name    string
		lines   []string
		wantSub []string
	}{
		{
			name: "flat-two-plus-two",
			lines: rethLAGLines(
				"set interfaces ge-0/0/1 gigether-options redundant-parent reth1",
				"set interfaces ge-0/0/2 gigether-options redundant-parent reth1",
				"set interfaces ge-7/0/1 gigether-options redundant-parent reth1",
				"set interfaces ge-7/0/2 gigether-options redundant-parent reth1",
			),
			// Deterministic first error: node 0 sorts before node 1.
			wantSub: []string{"reth1", "node 0", "ge-0/0/2", "#16586"},
		},
		{
			name: "single-node-two-children",
			lines: rethLAGLines(
				"set interfaces ge-0/0/1 gigether-options redundant-parent reth1",
				"set interfaces ge-0/0/2 gigether-options redundant-parent reth1",
			),
			wantSub: []string{"reth1", "node 0", "ge-0/0/2", "#16586"},
		},
		{
			name: "three-children",
			lines: rethLAGLines(
				"set interfaces ge-0/0/1 gigether-options redundant-parent reth1",
				"set interfaces ge-0/0/2 gigether-options redundant-parent reth1",
				"set interfaces ge-0/0/3 gigether-options redundant-parent reth1",
			),
			wantSub: []string{"reth1", "ge-0/0/2", "ge-0/0/3", "#16586"},
		},
		{
			name: "node1-only-two-children",
			lines: rethLAGLines(
				"set interfaces ge-7/0/1 gigether-options redundant-parent reth1",
				"set interfaces ge-7/0/2 gigether-options redundant-parent reth1",
			),
			wantSub: []string{"reth1", "node 1", "ge-7/0/2", "#16586"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfig(buildTree(t, tc.lines))
			if err == nil {
				t.Fatalf("expected strict reject of reth LAG, got nil (cfg=%v)", cfg != nil)
			}
			for _, sub := range tc.wantSub {
				if !strings.Contains(err.Error(), sub) {
					t.Errorf("error %q missing %q", err.Error(), sub)
				}
			}
			// Tolerant path must NOT brick (#1960) — and must warn
			// naming the ignored child.
			lcfg, lerr := CompileConfigLenient(buildTree(t, tc.lines))
			if lerr != nil {
				t.Fatalf("lenient compile must not reject (no-brick), got %v", lerr)
			}
			joined := strings.Join(lcfg.Warnings, "\n")
			if !strings.Contains(joined, "#16586") || !strings.Contains(joined, "reth1") {
				t.Fatalf("lenient warnings must name reth1/#16586; warnings=%v", lcfg.Warnings)
			}
			ignored := tc.wantSub[2]
			if !strings.Contains(joined, ignored) {
				t.Fatalf("lenient warnings must name ignored child %q; warnings=%v", ignored, lcfg.Warnings)
			}
		})
	}
}

func TestRethLAGGroupedPerNodeRejected16586(t *testing.T) {
	lines := []string{
		"set groups node0 chassis cluster node 0",
		"set groups node0 interfaces ge-0/0/1 gigether-options redundant-parent reth1",
		"set groups node0 interfaces ge-0/0/2 gigether-options redundant-parent reth1",
		"set groups node1 chassis cluster node 1",
		"set groups node1 interfaces ge-7/0/1 gigether-options redundant-parent reth1",
		"set groups node1 interfaces ge-7/0/2 gigether-options redundant-parent reth1",
		`set apply-groups "${node}"`,
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key test-cluster-psk-16586",
		"set chassis cluster reth-count 2",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set chassis cluster redundancy-group 1 node 1 priority 100",
		"set interfaces reth1 redundant-ether-options redundancy-group 1",
		"set interfaces reth1 unit 0 family inet address 10.0.61.1/24",
		"set security zones security-zone trust interfaces reth1.0",
	}
	// Generic and BOTH node views must reject identically (HA symmetry):
	// the children exist only inside per-node groups.
	if _, err := CompileConfig(buildTree(t, lines)); err == nil {
		t.Fatal("generic CompileConfig accepted grouped reth LAG")
	} else if !strings.Contains(err.Error(), "ge-0/0/2") {
		t.Fatalf("generic error must name ge-0/0/2, got %q", err.Error())
	}
	for _, nid := range []int{0, 1} {
		if _, err := CompileConfigForNode(buildTree(t, lines), nid); err == nil {
			t.Fatalf("CompileConfigForNode(%d) accepted grouped reth LAG", nid)
		}
		lcfg, lerr := CompileConfigForNodeLenient(buildTree(t, lines), nid)
		if lerr != nil {
			t.Fatalf("CompileConfigForNodeLenient(%d) bricked: %v", nid, lerr)
		}
		if !strings.Contains(strings.Join(lcfg.Warnings, "\n"), "#16586") {
			t.Fatalf("node %d lenient warnings missing #16586; %v", nid, lcfg.Warnings)
		}
	}
}

// TestRethSingleChildPerNodeUnchanged16586 is the tightening control:
// the canonical 1+1 cluster spelling and a single-node single child
// must commit exactly as before, with no #16586 diagnostic.
func TestRethSingleChildPerNodeUnchanged16586(t *testing.T) {
	cases := []struct {
		name  string
		lines []string
	}{
		{
			name: "canonical-one-plus-one",
			lines: rethLAGLines(
				"set interfaces ge-0/0/1 gigether-options redundant-parent reth1",
				"set interfaces ge-7/0/1 gigether-options redundant-parent reth1",
			),
		},
		{
			name: "single-node-single-child",
			lines: rethLAGLines(
				"set interfaces ge-0/0/1 gigether-options redundant-parent reth1",
			),
		},
		{
			// Slash and dash spellings of the SAME port are one child
			// (the #7795 collision gate owns that pair on strict).
			name: "dash-alias-is-one-port",
			lines: rethLAGLines(
				"set interfaces ge-0-0-1 gigether-options redundant-parent reth1",
				"set interfaces ge-7/0/1 gigether-options redundant-parent reth1",
			),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfig(buildTree(t, tc.lines))
			if err != nil {
				t.Fatalf("one-child-per-node control must commit, got %v", err)
			}
			if strings.Contains(strings.Join(cfg.Warnings, "\n"), "#16586") {
				t.Fatalf("control must not carry #16586 warning; %v", cfg.Warnings)
			}
		})
	}
	// Grouped canonical 1+1 (the shipped docs/ha-cluster shape).
	grouped := []string{
		"set groups node0 chassis cluster node 0",
		"set groups node0 interfaces ge-0/0/1 gigether-options redundant-parent reth1",
		"set groups node1 chassis cluster node 1",
		"set groups node1 interfaces ge-7/0/1 gigether-options redundant-parent reth1",
		`set apply-groups "${node}"`,
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key test-cluster-psk-16586",
		"set chassis cluster reth-count 2",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set chassis cluster redundancy-group 1 node 1 priority 100",
		"set interfaces reth1 redundant-ether-options redundancy-group 1",
		"set interfaces reth1 unit 0 family inet address 10.0.61.1/24",
		"set security zones security-zone trust interfaces reth1.0",
	}
	for _, nid := range []int{0, 1} {
		cfg, err := CompileConfigForNode(buildTree(t, grouped), nid)
		if err != nil {
			t.Fatalf("grouped 1+1 node %d must commit, got %v", nid, err)
		}
		if strings.Contains(strings.Join(cfg.Warnings, "\n"), "#16586") {
			t.Fatalf("grouped 1+1 node %d must not carry #16586; %v", nid, cfg.Warnings)
		}
	}
}
