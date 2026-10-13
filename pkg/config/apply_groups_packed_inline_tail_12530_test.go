package config

import (
	"strings"
	"testing"
)

// #12530: a packed group leaf naming a schema container, with a tail outside
// the schema grammar, was OVERRIDDEN away whenever the inline config already
// had that container, so post-expansion gates never saw the tail. The tail now
// merges one level down through mergeNodes, as an expandable #7648 body does:
// it meets the container's own same-instance children and its
// apply-groups-except.
//
// Every inline unit here carries an address AND an input filter. The first
// version of the fix appended the tail beside the inline container, so a group
// line on the interface (`ge-0/0/0 unit 0 <tail>`) became a second `unit 0`.
// The compiler keeps the later of two same-numbered units, so a tolerant Load
// or HA SyncApply compiled the unit with no address and no filter, and strict
// commit failed with a duplicate-unit error instead of the gate's diagnostic.

const firewall12530 = `firewall { family inet { filter protect { term t { then accept; } } ` +
	`filter f { term t { then accept; } } } }`

// inlineUnit12530 is the inline interface, with optional statements written
// on the interface and on the unit.
func inlineUnit12530(interfaceStmt, unitStmt string) string {
	return `interfaces { ge-0/0/0 { ` + interfaceStmt + `unit 0 { ` + unitStmt +
		`family inet { filter { input protect; } address 10.0.0.1/24; } } } } ` + firewall12530
}

type packedTailSpelling12530 struct{ depth, src string }

// packedTailSpellings12530 packs one group tail on the interface, one level
// above the inline unit, and on the unit itself. The block spelling, which the
// container merge already handled, is the control both packed ones must match.
func packedTailSpellings12530(tail string) []packedTailSpelling12530 {
	return []packedTailSpelling12530{
		{"interface", `groups { g { interfaces { ge-0/0/0 unit 0 ` + tail + `; } } } apply-groups g; ` +
			inlineUnit12530("", "")},
		{"unit", `groups { g { interfaces { ge-0/0/0 { unit 0 ` + tail + `; } } } } apply-groups g; ` +
			inlineUnit12530("", "")},
		{"block", `groups { g { interfaces { ge-0/0/0 { unit 0 { ` + tail + `; } } } } } apply-groups g; ` +
			inlineUnit12530("", "")},
	}
}

// assertInlineUnitIntact12530 requires the inline unit's address and input
// filter to survive the merge.
func assertInlineUnitIntact12530(t *testing.T, cfg *Config) {
	t.Helper()
	var unit *InterfaceUnit
	if ifc := cfg.Interfaces.Interfaces["ge-0/0/0"]; ifc != nil {
		unit = ifc.Units[0]
	}
	if unit == nil {
		t.Fatal("inline ge-0/0/0 unit 0 did not compile")
	}
	if len(unit.Addresses) != 1 || unit.Addresses[0] != "10.0.0.1/24" || unit.FilterInputV4 != "protect" {
		t.Fatalf("inline unit 0 compiled addresses %v and input filter %q; want [10.0.0.1/24] and protect",
			unit.Addresses, unit.FilterInputV4)
	}
}

// Gated tails reach their gate under the inline unit. Strict commit fails with
// the gate's own diagnostic rather than a duplicate unit, and a tolerant
// compile warns once and keeps the inline unit whole.
func TestPackedApplyGroupUnsupportedTailSurvivesInlinePeer12530(t *testing.T) {
	for _, tc := range []struct{ name, tail, want string }{
		{"filter", "filter input f", "#12090"},
		{"unit-mac", "mac 00:11:22:33:44:55", "#2008 H10"},
	} {
		for _, sp := range packedTailSpellings12530(tc.tail) {
			t.Run(tc.name+"/"+sp.depth, func(t *testing.T) {
				_, err := CompileConfig(hierTree(t, sp.src))
				if err == nil || !strings.Contains(err.Error(), tc.want) ||
					strings.Contains(err.Error(), "is declared") {
					t.Fatalf("strict compile error = %v; want the %s diagnostic and no duplicate unit", err, tc.want)
				}
				cfg, err := CompileConfigLenient(hierTree(t, sp.src))
				if err != nil {
					t.Fatalf("lenient compile: %v", err)
				}
				count := 0
				for _, warning := range cfg.Warnings {
					if strings.Contains(warning, tc.want) {
						count++
					}
				}
				if count != 1 {
					t.Fatalf("lenient warnings = %q; want exactly one %s warning", cfg.Warnings, tc.want)
				}
				assertInlineUnitIntact12530(t, cfg)
			})
		}
	}
}

// Tails no gate rejects committed on master, where the override dropped them,
// and still commit. They now merge into the inline unit, as the block spelling
// `ge-0/0/0 { unit 0 { <tail>; } }` does, and that unit stays whole on both
// compile paths.
func TestPackedApplyGroupUngatedTailMergesIntoInlineUnit12530(t *testing.T) {
	for _, tail := range []string{"family mpls", "family iso", "frobnicate 7"} {
		for _, sp := range packedTailSpellings12530(tail) {
			t.Run(tail+"/"+sp.depth, func(t *testing.T) {
				tree := hierTree(t, sp.src)
				if err := tree.ExpandGroups(); err != nil {
					t.Fatalf("expand groups: %v", err)
				}
				var units []*Node
				for _, n := range tree.Children {
					if n.Name() == "interfaces" {
						if ifc := n.FindChild("ge-0/0/0"); ifc != nil {
							units = ifc.FindChildren("unit")
						}
					}
				}
				merged := false
				if len(units) == 1 {
					for _, c := range units[0].Children {
						merged = merged || keysEqual(c.Keys, strings.Fields(tail))
					}
				}
				if !merged {
					t.Fatalf("expanded ge-0/0/0 has %d unit node(s); want the inline unit 0 holding %q", len(units), tail)
				}

				cfg, err := CompileConfig(hierTree(t, sp.src))
				if err != nil {
					t.Fatalf("strict compile: %v", err)
				}
				assertInlineUnitIntact12530(t, cfg)
				cfg, err = CompileConfigLenient(hierTree(t, sp.src))
				if err != nil {
					t.Fatalf("lenient compile: %v", err)
				}
				assertInlineUnitIntact12530(t, cfg)
			})
		}
	}
}

// apply-groups-except stops a packed tail exactly as it stops an expanded body
// (#9422/#9862): the outer group, also when the line comes from a nested
// group, and a nested contributor, named on the peer or on the unit below it.
// Each control, the same config without the exclusion, must reject, so the
// excluded commit proves the exclusion rather than a dropped tail.
func TestPackedApplyGroupTailHonoursApplyGroupsExcept12530(t *testing.T) {
	for _, chain := range []struct {
		name, except string
		groups       func(body string) string
	}{
		{"outer", "g", func(body string) string { return `g { ` + body + ` }` }},
		{"nested", "h", func(body string) string { return `g { apply-groups h; } h { ` + body + ` }` }},
		{"outer-via-nested", "g", func(body string) string { return `g { apply-groups h; } h { ` + body + ` }` }},
	} {
		for _, site := range []struct {
			name, body  string
			onInterface bool
		}{
			{"unit-packed/except-on-unit", `interfaces { ge-0/0/0 { unit 0 filter input f; } }`, false},
			{"interface-packed/except-on-interface", `interfaces { ge-0/0/0 unit 0 filter input f; }`, true},
			{"interface-packed/except-on-unit", `interfaces { ge-0/0/0 unit 0 filter input f; }`, false},
		} {
			t.Run(chain.name+"/"+site.name, func(t *testing.T) {
				build := func(stmt string) *ConfigTree {
					interfaceStmt, unitStmt := "", stmt
					if site.onInterface {
						interfaceStmt, unitStmt = stmt, ""
					}
					return hierTree(t, `groups { `+chain.groups(site.body)+` } apply-groups g; `+
						inlineUnit12530(interfaceStmt, unitStmt))
				}
				assertCommitRejects(t, build(""), "#12090")
				cfg, err := CompileConfig(build("apply-groups-except " + chain.except + "; "))
				if err != nil {
					t.Fatalf("apply-groups-except %s did not stop the packed tail: %v", chain.except, err)
				}
				assertInlineUnitIntact12530(t, cfg)
			})
		}
	}
}

// The tail is charged like a #7648 expanded body (#6767): once when it is
// synthesized, before the merge, and once by the merge itself. Merging
// `ge-0/0/0 unit 0 frobnicate 7` into the inline unit costs 5 units: the group
// leaf, then at the interface and again at the unit, the synthesized tail plus
// its merge. A budget one unit short must refuse it.
func TestPackedApplyGroupTailChargesExpansionBudget12530(t *testing.T) {
	merge := func(left int) error {
		dst := hierTree(t, `interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } } }`).Children[0]
		src := hierTree(t, `interfaces { ge-0/0/0 unit 0 frobnicate 7; }`).Children[0]
		budget := &groupExpandBudget{work: maxGroupExpandWork - left}
		return mergeNodes(&dst.Children, src.Children, [][]string{dst.Keys}, budget, "g", nil, nil, false, false)
	}
	if err := merge(5); err != nil {
		t.Fatalf("a budget holding the merge's full cost refused it: %v", err)
	}
	if err := merge(4); err == nil || !strings.Contains(err.Error(), "work budget") {
		t.Fatalf("a budget one unit short accepted the merge (err=%v); the synthesized tail went uncharged", err)
	}
}

func TestPackedApplyGroupFilterTailWithoutInlinePeerStillRejected12530(t *testing.T) {
	src := `groups { g { interfaces { ge-0/0/0 { unit 0 filter input f; } } } } ` +
		`apply-groups g; interfaces { ge-0/0/0 { description inline; } } ` +
		`firewall { family inet { filter f { term t { then accept; } } } }`
	assertCommitRejects(t, hierTree(t, src), "#12090")
	assertLenientWarns(t, hierTree(t, src), "#12090")
}
