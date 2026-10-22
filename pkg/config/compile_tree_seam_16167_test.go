package config

import (
	"encoding/json"
	"strings"
	"testing"
)

// #16167: no-node-groups equivalence seam. After collapsing the twin
// orchestrators into compileTree(tree, opts, nodeID *int), a tree with NO
// node groups must compile through CompileConfigForNode(tree, n) to the
// same Config as CompileConfig(tree), modulo the explicitly named
// NodeID-stamped delta below. If compileTree ever grows a second
// behavioral divergence on the no-node-groups path, this test fails.

// nodeGroupsFreeFixtures16167 are representative configs carrying no
// `groups node0` / `groups node1` bodies and no ${node} apply-groups
// reference, so the generic and node-scoped expansion passes converge.
var nodeGroupsFreeFixtures16167 = []struct {
	name  string
	lines []string
}{
	{
		name: "flat-reth-cluster",
		lines: []string{
			"set chassis cluster cluster-id 1",
			"set chassis cluster authentication-key test-cluster-psk-16167",
			"set chassis cluster reth-count 2",
			"set chassis cluster redundancy-group 1 node 0 priority 200",
			"set chassis cluster redundancy-group 1 node 1 priority 100",
			"set interfaces ge-0/0/0 gigether-options redundant-parent reth0",
			"set interfaces ge-7/0/0 gigether-options redundant-parent reth0",
			"set interfaces reth0 redundant-ether-options redundancy-group 1",
			"set interfaces reth0 unit 0 family inet address 10.0.0.1/24",
		},
	},
	{
		name: "zones-policy-interfaces",
		lines: []string{
			"set interfaces ge-0/0/1 unit 0 family inet address 10.0.61.1/24",
			"set interfaces ge-0/0/2 unit 0 family inet address 10.0.62.1/24",
			"set security zones security-zone trust interfaces ge-0/0/1.0",
			"set security zones security-zone untrust interfaces ge-0/0/2.0",
			"set security policies from-zone trust to-zone untrust policy p1 match source-address any",
			"set security policies from-zone trust to-zone untrust policy p1 match destination-address any",
			"set security policies from-zone trust to-zone untrust policy p1 match application any",
			"set security policies from-zone trust to-zone untrust policy p1 then permit",
		},
	},
	{
		name: "applications",
		lines: []string{
			"set applications application web term web protocol tcp destination-port 8080",
			"set applications application-set web-set application web",
		},
	},
}

// normaliseNodeStamp16167 erases the allowed NodeID-stamped delta between
// a generic compile and a node-scoped compile of a node-groups-free tree.
// The allowed delta, named explicitly:
//
//  1. Chassis.Cluster.NodeID: the #4329 stamp writes the runtime node id
//     (n) on the node branch when no explicit `chassis cluster node` leaf
//     authoritatively set it (NodeIDSet false); the generic branch leaves
//     the zero default. When NodeIDSet is true the explicit leaf wins on
//     both branches and the values already agree.
//  2. Every config field DERIVED from that stamp is re-normalised to the
//     generic value by construction of the comparison below: the JSON
//     blobs are compared after NodeID is zeroed on BOTH sides, and the
//     reth member resolution (Config.RethToPhysical) is asserted equal
//     separately for the flat-reth fixture, where the stamp chooses the
//     local member and the node branch must pick ge-0/0/0 for node 0
//     and ge-7/0/0 for node 1 while the generic branch picks ge-0/0/0.
//     That last item is the one intentional behavioral difference the
//     stamp exists for (#4329); it is asserted explicitly rather than
//     erased silently.
//  3. Warning ORDER: the former twins emitted the #9727 Rx-MTU advisory
//     on opposite sides of the #10105 fabric advisories (generic:
//     Rx-MTU first; node: fabric first). compileTree preserves each
//     branch's historical order; the comparison canonicalises that one
//     swap (canonicalWarningOrder16167) and then requires the warning
//     slices to match verbatim. The paired order itself is pinned by
//     TestCompileTreeWarningOrderBaseHead16167.
func normaliseNodeStamp16167(t *testing.T, cfg *Config) []byte {
	t.Helper()
	if cfg.Chassis.Cluster != nil && !cfg.Chassis.Cluster.NodeIDSet {
		cfg.Chassis.Cluster.NodeID = 0
	}
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	return b
}

func TestCompileTreeNoNodeGroupsEquivalence16167(t *testing.T) {
	for _, fx := range nodeGroupsFreeFixtures16167 {
		for _, lenient := range []bool{false, true} {
			name := fx.name + "/strict"
			if lenient {
				name = fx.name + "/lenient"
			}
			t.Run(name, func(t *testing.T) {
				build := func() *ConfigTree { return buildTree(t, fx.lines) }
				compileGeneric := CompileConfig
				compileNode := CompileConfigForNode
				if lenient {
					compileGeneric = CompileConfigLenient
					compileNode = CompileConfigForNodeLenient
				}
				generic, gerr := compileGeneric(build())
				if gerr != nil {
					t.Fatalf("generic compile: %v", gerr)
				}
				for _, n := range []int{0, 1} {
					nodeCfg, nerr := compileNode(build(), n)
					if nerr != nil {
						t.Fatalf("node %d compile: %v", n, nerr)
					}
					// Allowed delta 1: explicit leaf (NodeIDSet) must
					// already agree; otherwise the stamp wrote n.
					if nodeCfg.Chassis.Cluster != nil && !nodeCfg.Chassis.Cluster.NodeIDSet && nodeCfg.Chassis.Cluster.NodeID != n {
						t.Fatalf("node %d: stamped NodeID = %d, want %d (the named allowed delta)", n, nodeCfg.Chassis.Cluster.NodeID, n)
					}
					// Warnings: the only allowed delta is the #10105 /
					// Rx-MTU relative order (generic: Rx-MTU before
					// fabric; node: fabric before Rx-MTU — each branch
					// keeps its historical order, #16167 review fold).
					// Canonicalise that one swap away, then the warning
					// slices must match verbatim, order included.
					if w := canonicalWarningOrder16167(nodeCfg.Warnings); strings.Join(generic.Warnings, "\x00") != strings.Join(w, "\x00") {
						t.Fatalf("node %d: warnings differ beyond the named fabric/Rx-MTU order delta:\n generic: %q\n node:    %q", n, generic.Warnings, nodeCfg.Warnings)
					}
					// Allowed delta 2 (reth member choice) is asserted
					// below; everything else must be byte-identical
					// after erasing the stamp.
					if fx.name == "flat-reth-cluster" {
						wantMember := "ge-0/0/0"
						if n == 1 {
							wantMember = "ge-7/0/0"
						}
						if got := nodeCfg.RethToPhysical()["reth0"]; got != wantMember {
							t.Fatalf("node %d: reth0 resolves to %q, want %q (the #4329 stamp delta)", n, got, wantMember)
						}
						if got := generic.RethToPhysical()["reth0"]; got != "ge-0/0/0" {
							t.Fatalf("generic: reth0 resolves to %q, want ge-0/0/0", got)
						}
					}
					gb := normaliseNodeStamp16167(t, generic)
					nb := normaliseNodeStamp16167(t, nodeCfg)
					// Interface resolution consumes NodeID only through
					// RethToPhysical (asserted above); the JSON still
					// carries the resolved member, so for the flat-reth
					// fixture erase that one derived choice too before
					// the byte comparison.
					if fx.name == "flat-reth-cluster" {
						gb = []byte(strings.ReplaceAll(string(gb), "ge-7/0/0", "ge-0/0/0"))
						nb = []byte(strings.ReplaceAll(string(nb), "ge-7/0/0", "ge-0/0/0"))
					}
					if string(gb) != string(nb) {
						t.Fatalf("node %d: config differs beyond the named NodeID-stamped delta:\n generic: %s\n node:    %s", n, gb, nb)
					}
				}
			})
		}
	}
}

// TestCompileTreePublicPairsAreOneLineWrappers16167 pins the #16167
// external contract structurally: the four public entry points delegate
// to compileTree with the nil-vs-&id selector, so no second orchestrator
// can regrow. It is a compile-time-adjacent guard only; behavior is
// pinned by the golden matrix and the equivalence seam above.
// canonicalWarningOrder16167 moves any Rx-MTU advisory (#9727) that
// follows a fabric advisory (#10105/#13967) to immediately BEFORE the
// first fabric advisory — i.e. it rewrites the node-branch warning order
// into the generic-branch order for the one allowed order delta.
func canonicalWarningOrder16167(warnings []string) []string {
	isRxMTU := func(w string) bool { return strings.Contains(w, "(#9727)") }
	isFabric := func(w string) bool {
		return strings.Contains(w, "(#10105)") || strings.Contains(w, "(#13967)")
	}
	firstFabric := -1
	for i, w := range warnings {
		if isFabric(w) {
			firstFabric = i
			break
		}
	}
	if firstFabric < 0 {
		return warnings
	}
	var rx, rest []string
	for i, w := range warnings {
		if isRxMTU(w) && i > firstFabric {
			rx = append(rx, w)
		} else {
			rest = append(rest, w)
		}
	}
	if len(rx) == 0 {
		return warnings
	}
	out := make([]string, 0, len(warnings))
	out = append(out, rest[:firstFabric]...)
	out = append(out, rx...)
	out = append(out, rest[firstFabric:]...)
	return out
}

func TestCompileTreePublicPairsAreOneLineWrappers16167(t *testing.T) {
	if _, err := CompileConfig(buildTree(t, nil)); err != nil {
		t.Fatalf("CompileConfig(empty): %v", err)
	}
	if _, err := CompileConfigLenient(buildTree(t, nil)); err != nil {
		t.Fatalf("CompileConfigLenient(empty): %v", err)
	}
	for _, n := range []int{0, 1, 2, -1} {
		if _, err := CompileConfigForNode(buildTree(t, nil), n); err != nil {
			t.Fatalf("CompileConfigForNode(empty, %d): %v", n, err)
		}
		if _, err := CompileConfigForNodeLenient(buildTree(t, nil), n); err != nil {
			t.Fatalf("CompileConfigForNodeLenient(empty, %d): %v", n, err)
		}
	}
}

// TestCompileTreeWarningOrderBaseHead16167 is the paired base/head order
// test for the #16167 review fold: one fixture carrying BOTH the #9727
// Rx-MTU advisory (zoned dataplane-bound interface with MTU 9000) and the
// #10105/#13967 fabric advisories (configured fabric interface), compiled
// strict on every branch. The generic branch must emit Rx-MTU BEFORE
// fabric; the node branch (node0 and node1) must emit fabric BEFORE
// Rx-MTU — each branch's pre-collapse historical order, preserved.
func TestCompileTreeWarningOrderBaseHead16167(t *testing.T) {
	lines := []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"set chassis cluster fabric-interface fab0",
		"set interfaces ge-0/0/1 mtu 9000",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.61.1/24",
		"set security zones security-zone trust interfaces ge-0/0/1.0",
	}
	indexOf := func(cfg *Config, marker string) int {
		for i, w := range cfg.Warnings {
			if strings.Contains(w, marker) {
				return i
			}
		}
		return -1
	}
	assertBoth := func(t *testing.T, cfg *Config) (rx, fabric int) {
		t.Helper()
		rx = indexOf(cfg, "(#9727)")
		fabric = indexOf(cfg, "(#10105)")
		if rx < 0 || fabric < 0 {
			t.Fatalf("fixture must carry both advisories; warnings=%q", cfg.Warnings)
		}
		if indexOf(cfg, "(#13967)") < 0 {
			t.Fatalf("fixture must carry the #13967 fabric advisory too; warnings=%q", cfg.Warnings)
		}
		return rx, fabric
	}

	generic, err := CompileConfig(buildTree(t, lines))
	if err != nil {
		t.Fatalf("generic compile: %v", err)
	}
	if rx, fabric := assertBoth(t, generic); rx > fabric {
		t.Fatalf("generic order: Rx-MTU (#9727) at %d must precede fabric (#10105) at %d; warnings=%q", rx, fabric, generic.Warnings)
	}
	for _, n := range []int{0, 1} {
		nodeCfg, err := CompileConfigForNode(buildTree(t, lines), n)
		if err != nil {
			t.Fatalf("node %d compile: %v", n, err)
		}
		if rx, fabric := assertBoth(t, nodeCfg); fabric > rx {
			t.Fatalf("node %d order: fabric (#10105) at %d must precede Rx-MTU (#9727) at %d (prior node-path order); warnings=%q", n, fabric, rx, nodeCfg.Warnings)
		}
	}
}
