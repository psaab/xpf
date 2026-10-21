package config

import (
	"fmt"
	"testing"
)

// #9192 — one authored BGP neighbor could occupy several AST nodes, and
// compileBGP appended one *BGPNeighbor per NODE.
//
// A bare declaration and a later sub-leaf are separate nodes, because SetPath
// does not reuse a node it has already marked IsLeaf:
//
//	set protocols bgp group G neighbor 10.0.2.2
//	set protocols bgp group G neighbor 10.0.2.2 import PS
//	  -> [neighbor 10.0.2.2]
//	     [neighbor 10.0.2.2] > [import PS]
//
// That is ordinary flat-set authoring, and it produced TWO entries for one
// peer. The rendered FRR output was redundant rather than wrong, which is why
// nothing caught it — but the duplication is invisible in the typed config's
// contract, so anything reasoning over `BGP.Neighbors` AS A SET OF PEERS is
// wrong by construction. Two consumers were already caught by it on #9007: a
// duplicate-address check that reported "configured in more than one group
// (G and G)" and false-rejected a legitimate config, and a first-wins dedup at
// the renderer that silently dropped the policy-bearing entry along with its
// `activate` and `route-map … in` lines.

func bgpTree9192(t *testing.T, lines ...string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, l := range lines {
		p, err := ParseSetCommand(l)
		if err != nil {
			t.Fatalf("parse %q: %v", l, err)
		}
		if err := tree.SetPath(p); err != nil {
			t.Fatalf("setpath %q: %v", l, err)
		}
	}
	return tree
}

func bgpCompile9192(t *testing.T, tree *ConfigTree) []*BGPNeighbor {
	t.Helper()
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if cfg.Protocols.BGP == nil {
		t.Fatal("no BGP compiled — the fixture is broken, so every assertion below " +
			"would pass over an empty slice")
	}
	return cfg.Protocols.BGP.Neighbors
}

func bgpHier9192(t *testing.T, text string) []*BGPNeighbor {
	t.Helper()
	tree, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	return bgpCompile9192(t, tree)
}

// TestBGPNeighborNodesMergeIntoOnePeer9192 is the issue's own fixture.
func TestBGPNeighborNodesMergeIntoOnePeer9192(t *testing.T) {
	ns := bgpCompile9192(t, bgpTree9192(t,
		"set protocols bgp group G type external",
		"set protocols bgp group G peer-as 65001",
		"set protocols bgp group G neighbor 10.0.2.2",
		"set protocols bgp group G neighbor 10.0.2.2 import PS",
	))
	if len(ns) != 1 {
		for i, n := range ns {
			t.Logf("  [%d] addr=%s group=%q peer-as=%d import=%v", i, n.Address, n.GroupName, n.PeerAS, n.Import)
		}
		t.Fatalf("#9192: one authored neighbor compiled to %d BGPNeighbor entries, want 1", len(ns))
	}
	// The union, both halves: the group default the BARE node carried and the
	// policy the EXTENDED node carried must both be present. Asserting only the
	// count would pass for a merge that kept the wrong entry.
	if ns[0].PeerAS != 65001 {
		t.Errorf("peer-as inherited from the group is %d, want 65001 — the merge kept an "+
			"entry that never got the group defaults", ns[0].PeerAS)
	}
	if len(ns[0].Import) != 1 || ns[0].Import[0] != "PS" {
		t.Errorf("import is %v, want [PS] — the merge dropped the policy-bearing node, "+
			"which is exactly the first-wins dedup that was reverted on #9007", ns[0].Import)
	}
}

// TestBGPNeighborMergeUnionsEveryField9192 is the per-field union coverage.
//
// A merge changes what every downstream reader sees, so a count assertion is not
// enough: the question is whether each field a node carries SURVIVES, in either
// node order.
//
// EVERY ROW CARRIES ITS OWN POSITIVE CONTROL. The single-node spelling is
// compiled first and the field must be observably set there; without that, a row
// whose leaf the compiler does not read at all would pass at the zero value in
// all three spellings and report the merge as working.
func TestBGPNeighborMergeUnionsEveryField9192(t *testing.T) {
	const addr = "10.0.2.2"
	base := []string{
		"set protocols bgp group G type external",
		"set protocols bgp group G peer-as 65001",
	}
	set := func(leaf string) string {
		return "set protocols bgp group G neighbor " + addr + " " + leaf
	}
	bare := "set protocols bgp group G neighbor " + addr

	for _, tc := range []struct {
		name string
		leaf string
		read func(*BGPNeighbor) string
		want string
	}{
		{"description", "description xpfdesc", func(n *BGPNeighbor) string { return n.Description }, "xpfdesc"},
		{"hold-time", "hold-time 45", func(n *BGPNeighbor) string { return fmt.Sprint(n.HoldTime) }, "45"},
		{"passive", "passive", func(n *BGPNeighbor) string { return fmt.Sprint(n.Passive) }, "true"},
		{"local-address", "local-address 10.0.2.1", func(n *BGPNeighbor) string { return n.LocalAddress }, "10.0.2.1"},
		{"local-as", "local-as 65100", func(n *BGPNeighbor) string { return fmt.Sprint(n.LocalAS) }, "65100"},
		{"peer-as override", "peer-as 65002", func(n *BGPNeighbor) string { return fmt.Sprint(n.PeerAS) }, "65002"},
		{"multihop", "multihop 4", func(n *BGPNeighbor) string { return fmt.Sprint(n.MultihopTTL) }, "4"},
		{"route-reflector-client", "route-reflector-client", func(n *BGPNeighbor) string { return fmt.Sprint(n.RouteReflectorClient) }, "true"},
		{"default-originate", "default-originate", func(n *BGPNeighbor) string { return fmt.Sprint(n.DefaultOriginate) }, "true"},
		{"remove-private", "remove-private", func(n *BGPNeighbor) string { return fmt.Sprint(n.RemovePrivateAS) }, "true"},
		{"loops", "loops 3", func(n *BGPNeighbor) string { return fmt.Sprint(n.AllowASIn) }, "3"},
		{"authentication-key", "authentication-key sekret", func(n *BGPNeighbor) string { return n.AuthPassword.Reveal() }, "sekret"},
		{"import", "import PS", func(n *BGPNeighbor) string { return fmt.Sprint(n.Import) }, "[PS]"},
		{"export", "export PX", func(n *BGPNeighbor) string { return fmt.Sprint(n.Export) }, "[PX]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// POSITIVE CONTROL: one node, the leaf must be observable.
			one := bgpCompile9192(t, bgpTree9192(t, append(append([]string{}, base...), set(tc.leaf))...))
			if len(one) != 1 {
				t.Fatalf("single-node fixture gave %d neighbors, want 1", len(one))
			}
			if got := tc.read(one[0]); got != tc.want {
				t.Fatalf("POSITIVE CONTROL: the single-node spelling reads %q, want %q. This "+
					"row cannot observe its own field, so the two-node arms below would pass "+
					"at the zero value whatever the merge did", got, tc.want)
			}
			for _, order := range []struct {
				name  string
				lines []string
			}{
				{"bare first", append(append([]string{}, base...), bare, set(tc.leaf))},
				{"bare last", append(append([]string{}, base...), set(tc.leaf), bare)},
			} {
				ns := bgpCompile9192(t, bgpTree9192(t, order.lines...))
				if len(ns) != 1 {
					t.Errorf("%s: %d neighbors, want 1", order.name, len(ns))
					continue
				}
				if got := tc.read(ns[0]); got != tc.want {
					t.Errorf("%s: %s reads %q after the merge, want %q — the field the "+
						"extended node carried was lost", order.name, tc.name, got, tc.want)
				}
			}
		})
	}
}

// TestBGPNeighborMergeNeverFoldsDistinctPeers9192 is the control the issue asks
// for: two genuinely distinct neighbors must never fold.
//
// The cross-group row is the one that matters. #9007 is the CROSS-GROUP case —
// two groups naming one address with divergent peer-as, timers and
// authentication keys — which is genuinely ambiguous, is resolved by render
// order, and is rejected at commit by PR #9191. Folding it here would silently
// resolve an ambiguity the operator is supposed to be told about, so the merge
// key is the PAIR and not the address.
func TestBGPNeighborMergeNeverFoldsDistinctPeers9192(t *testing.T) {
	t.Run("different addresses", func(t *testing.T) {
		ns := bgpCompile9192(t, bgpTree9192(t,
			"set protocols bgp group G peer-as 65001",
			"set protocols bgp group G neighbor 10.0.2.2 description first",
			"set protocols bgp group G neighbor 10.0.2.3 description second",
		))
		if len(ns) != 2 {
			t.Fatalf("two distinct addresses compiled to %d entries, want 2", len(ns))
		}
		if ns[0].Description == ns[1].Description {
			t.Errorf("the two entries carry the same description %q, so this control cannot "+
				"tell a preserved pair from one entry duplicated", ns[0].Description)
		}
	})
	t.Run("cross-group, one address (#9007)", func(t *testing.T) {
		ns := bgpCompile9192(t, bgpTree9192(t,
			"set protocols bgp group A peer-as 65001",
			"set protocols bgp group A neighbor 10.0.2.2",
			"set protocols bgp group B peer-as 65002",
			"set protocols bgp group B neighbor 10.0.2.2 description second",
		))
		if len(ns) != 2 {
			t.Fatalf("#9192: the cross-group case folded to %d entries, want 2. That is "+
				"#9007's ambiguous shape — divergent peer-as, timers and authentication "+
				"keys — and folding it silently resolves an ambiguity PR #9191 rejects at "+
				"commit", len(ns))
		}
		if ns[0].GroupName == ns[1].GroupName {
			t.Errorf("both entries name group %q; the control is not exercising the "+
				"cross-group shape", ns[0].GroupName)
		}
		if ns[0].PeerAS == ns[1].PeerAS {
			t.Errorf("both entries carry peer-as %d, so the DIVERGENCE that makes #9007 "+
				"ambiguous is absent from this fixture", ns[0].PeerAS)
		}
	})
}

// TestBGPNeighborOwnPolicyChainSurvivesTheMerge9192 covers the one piece of
// per-neighbor STATE the merge had to move out of the node loop.
//
// `neighborOwnExport` / `neighborOwnImport` implement Junos most-specific-LEVEL-
// wins (#5277): the neighbor's FIRST own export replaces the inherited group
// list, and later same-level entries accumulate. They were plain locals, which
// was correct while one node meant one neighbor. With several nodes per
// neighbor a per-node flag would make the SECOND node's first `export` wipe the
// FIRST node's own list — turning the union into a last-node-wins drop,
// silently. They are keyed on the neighbor instead.
func TestBGPNeighborOwnPolicyChainSurvivesTheMerge9192(t *testing.T) {
	t.Run("own export replaces the group list, across nodes", func(t *testing.T) {
		ns := bgpCompile9192(t, bgpTree9192(t,
			"set protocols bgp group G peer-as 65001",
			"set protocols bgp group G export GE",
			"set protocols bgp group G neighbor 10.0.2.2",
			"set protocols bgp group G neighbor 10.0.2.2 export NE1",
		))
		if len(ns) != 1 {
			t.Fatalf("%d neighbors, want 1", len(ns))
		}
		if got := fmt.Sprint(ns[0].Export); got != "[NE1]" {
			t.Errorf("export is %s, want [NE1] — the neighbor's OWN export must REPLACE the "+
				"inherited group list (#5277), not merge with it", got)
		}
	})
	t.Run("two own entries across two blocks accumulate", func(t *testing.T) {
		ns := bgpHier9192(t, `protocols { bgp { group G { peer-as 65001; export GE; `+
			`neighbor 10.0.2.2 { export NE1; } neighbor 10.0.2.2 { export NE2; } } } }`)
		if len(ns) != 1 {
			t.Fatalf("%d neighbors, want 1", len(ns))
		}
		if got := fmt.Sprint(ns[0].Export); got != "[NE1 NE2]" {
			t.Errorf("export is %s, want [NE1 NE2]. [NE2] alone means the own-export flag "+
				"was reset per NODE and the second block wiped the first; [GE NE2] means it "+
				"never fired at all", got)
		}
	})
	t.Run("a neighbor that sets only import keeps the group export", func(t *testing.T) {
		ns := bgpHier9192(t, `protocols { bgp { group G { peer-as 65001; export GE; `+
			`neighbor 10.0.2.2 { description D; } neighbor 10.0.2.2 { import NI; } } } }`)
		if len(ns) != 1 {
			t.Fatalf("%d neighbors, want 1", len(ns))
		}
		if got := fmt.Sprint(ns[0].Export); got != "[GE]" {
			t.Errorf("export is %s, want [GE] — setting import must not disturb the "+
				"inherited group export", got)
		}
		if got := fmt.Sprint(ns[0].Import); got != "[NI]" {
			t.Errorf("import is %s, want [NI]", got)
		}
		if ns[0].Description != "D" {
			t.Errorf("description is %q, want D — the first block's field was lost", ns[0].Description)
		}
	})
}

// TestBGPNeighborMergeTwoGroupBlocksLenient9192 pins the one shape whose
// behaviour this merge CHANGES rather than repairs, so it is a recorded decision
// instead of a side effect.
//
// Two `group G` blocks naming one address share the merge key. That config is
// REJECTED at strict commit by the #5180 duplicate-block gate — "each block is
// compiled independently with its own state, so settings authored in one block
// do not reach children authored in the other — the config is silently split,
// not merged" — so it is reachable only on the lenient boot / HA-sync path
// (#1960 no-brick). There the merged neighbor keeps the FIRST block's
// group-level defaults and unions both blocks' per-neighbor statements, rather
// than producing two entries whose group defaults disagree and which the
// renderer emits BOTH of.
func TestBGPNeighborMergeTwoGroupBlocksLenient9192(t *testing.T) {
	const text = `protocols { bgp { group G { type external; peer-as 65001; neighbor 10.0.2.2; } ` +
		`group G { hold-time 30; neighbor 10.0.2.2 { description second; } } } }`
	tree, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	// The reason this is lenient-only, asserted rather than asserted-about.
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("#9192: two same-name `group` blocks are expected to be REJECTED at strict " +
			"commit by the #5180 duplicate-block gate. If that gate moved, this cell is " +
			"describing a shape operators can now commit and the note above is wrong")
	}
	ns := bgpCompile9192(t, tree)
	if len(ns) != 1 {
		t.Fatalf("#9192: the two blocks compiled to %d entries on the lenient path, want 1", len(ns))
	}
	if ns[0].PeerAS != 65001 {
		t.Errorf("peer-as is %d, want 65001 — the FIRST block's group defaults are kept", ns[0].PeerAS)
	}
	if ns[0].HoldTime != 0 {
		t.Errorf("hold-time is %d, want 0. The SECOND block's group-level defaults are NOT "+
			"applied to an already-created neighbor; re-applying them would wipe the first "+
			"block's per-neighbor overrides, which is the drop this merge exists to prevent",
			ns[0].HoldTime)
	}
	if ns[0].Description != "second" {
		t.Errorf("description is %q, want \"second\" — the per-neighbor statements of BOTH "+
			"blocks are unioned even though only the first block's group defaults are kept",
			ns[0].Description)
	}
}
