package config

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

const screenBody9801 = `screen { ids-option edge { icmp { ping-death; } } } `

// zones9801 compiles text on the strict path and summarizes every compiled
// zone by name.
func zones9801(t *testing.T, text string) map[string]string {
	t.Helper()
	tree, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture must parse: %v", perrs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict compile %q: %v", text, err)
	}
	out := map[string]string{}
	for name, z := range cfg.Security.Zones {
		out[name] = fmt.Sprintf("tcp-rst=%v screen=%q", z.TCPRst, z.ScreenProfile)
	}
	return out
}

func zoneNames9801(zones map[string]string) string {
	var names []string
	for n := range zones {
		names = append(names, n)
	}
	sort.Strings(names)
	return strings.Join(names, " ")
}

// expand9801 parses text and expands its groups.
func expand9801(t *testing.T, text string) *ConfigTree {
	t.Helper()
	tree, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture must parse: %v", perrs)
	}
	if err := tree.ExpandGroups(); err != nil {
		t.Fatalf("expand: %v", err)
	}
	return tree
}

// #9801: a `<*>` group must reach a zone written as a leaf exactly as it reaches
// the braced spelling of the same zone. Measured at 36dfa8e5a, every leaf row
// below compiled without the group's statement.
func TestWildcardGroupAppliesToLeafZone9801(t *testing.T) {
	group := func(stmt string) string {
		return `groups { G { security { zones { security-zone <*> { ` + stmt + ` } } } } } apply-groups G; `
	}
	for _, c := range []struct{ name, text, want string }{
		{"tcp-rst, leaf zone", group(`tcp-rst;`) + `security { zones { security-zone trust; } }`, `tcp-rst=true screen=""`},
		{"tcp-rst, braced zone (control)", group(`tcp-rst;`) + `security { zones { security-zone trust { } } }`, `tcp-rst=true screen=""`},
		{"screen, leaf zone", group(`screen edge;`) + `security { ` + screenBody9801 + `zones { security-zone trust; } }`, `tcp-rst=false screen="edge"`},
		{"screen, braced zone (control)", group(`screen edge;`) + `security { ` + screenBody9801 + `zones { security-zone trust { } } }`, `tcp-rst=false screen="edge"`},
	} {
		t.Run(c.name, func(t *testing.T) {
			zones := zones9801(t, c.text)
			if got := zoneNames9801(zones); got != "trust" {
				t.Errorf("compiled zones [%s], want [trust] (#9801)", got)
			}
			if got := zones["trust"]; got != c.want {
				t.Errorf("zone trust compiled %s, want %s: the group must reach the zone (#9801)", got, c.want)
			}
		})
	}
}

// The expanded tree must carry the zone as the container its braced spelling
// is, so every reader of the expanded tree, display inheritance included, sees
// the group's statement under it.
func TestWildcardGroupTurnsLeafZoneIntoContainer9801(t *testing.T) {
	const text = `groups { G { security { zones { security-zone <*> { tcp-rst; } } } } } apply-groups G; security { zones { security-zone trust; } }`
	tree, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture must parse: %v", perrs)
	}
	if err := tree.ExpandGroups(); err != nil {
		t.Fatalf("expand: %v", err)
	}
	var zone *Node
	for _, sec := range tree.FindChildren("security") {
		for _, zs := range sec.Children {
			if len(zs.Keys) != 1 || zs.Keys[0] != "zones" {
				continue
			}
			for _, z := range zs.Children {
				if len(z.Keys) == 2 && z.Keys[0] == "security-zone" && z.Keys[1] == "trust" {
					zone = z
				}
			}
		}
	}
	if zone == nil {
		t.Fatalf("no zone trust in the expanded tree")
	}
	if zone.IsLeaf || zone.FindChild("tcp-rst") == nil {
		t.Errorf("expanded zone trust: IsLeaf=%v with %d children, want a container holding the group's tcp-rst (#9801)", zone.IsLeaf, len(zone.Children))
	}
}

// The leaf-destination merge is scoped to zones. An interface written as a leaf
// compiles no interface at all (#9838), so a wildcard group must not turn it
// into one. This cell pins the scope, so widening it is a deliberate change
// made with #9838.
func TestWildcardLeafMergeIsScopedToZones9801(t *testing.T) {
	const text = `groups { G { interfaces { <*> { description fromgroup; } } } } apply-groups G; interfaces { ge-0/0/0; ge-0/0/1 { unit 0; } }`
	tree, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture must parse: %v", perrs)
	}
	if err := tree.ExpandGroups(); err != nil {
		t.Fatalf("expand: %v", err)
	}
	var leaf, braced *Node
	for _, ifs := range tree.FindChildren("interfaces") {
		for _, n := range ifs.Children {
			switch {
			case len(n.Keys) == 1 && n.Keys[0] == "ge-0/0/0":
				leaf = n
			case len(n.Keys) == 1 && n.Keys[0] == "ge-0/0/1":
				braced = n
			}
		}
	}
	if braced == nil || braced.FindChild("description") == nil {
		t.Fatalf("CONTROL: the braced interface did not take the group: %+v", braced)
	}
	if leaf == nil || !leaf.IsLeaf || len(leaf.Children) != 0 {
		t.Errorf("the leaf interface ge-0/0/0 was converted by the wildcard merge: %+v (#9801 is scoped to zones; #9838)", leaf)
	}
}

// The zone conversion also needs the zones schema. A `security-zone` leaf under
// any other parent is not a zone, and stays a leaf.
func TestWildcardLeafZoneMergeNeedsTheZonesSchema9801(t *testing.T) {
	tree := expand9801(t, `groups { G { interfaces { security-zone <*> { tcp-rst; } } } } apply-groups G; interfaces { security-zone trust; }`)
	var leaf *Node
	for _, ifs := range tree.FindChildren("interfaces") {
		for _, n := range ifs.Children {
			if len(n.Keys) == 2 && n.Keys[0] == "security-zone" && n.Keys[1] == "trust" {
				leaf = n
			}
		}
	}
	if leaf == nil {
		t.Fatalf("fixture: no security-zone trust under interfaces")
	}
	if !leaf.IsLeaf || len(leaf.Children) != 0 {
		t.Errorf("security-zone trust under interfaces: IsLeaf=%v with %d children, want an untouched leaf: only a zone under security zones takes the wildcard merge (#9801)", leaf.IsLeaf, len(leaf.Children))
	}
}

// #9831: a group's zone statement must not be dropped by an inline statement
// naming a DIFFERENT zone. Measured at ed313e4c9, the first row compiled
// only [trust].
func TestGroupZoneLeafKeepsItsIdentity9831(t *testing.T) {
	t.Run("zone beside another zone's inline leaf", func(t *testing.T) {
		zones := zones9801(t, `groups { G { security { zones { security-zone zga; } } } } apply-groups G; security { zones { security-zone trust; } }`)
		if got := zoneNames9801(zones); got != "trust zga" {
			t.Errorf("compiled zones [%s], want [trust zga]: the group's zone was dropped (#9831)", got)
		}
	})
	t.Run("same zone, inline braced body still wins", func(t *testing.T) {
		const text = `groups { G { security { zones { security-zone trust; } } } } apply-groups G; security { zones { security-zone trust { tcp-rst; } } }`
		zones := zones9801(t, text)
		if got := zoneNames9801(zones); got != "trust" {
			t.Errorf("compiled zones [%s], want [trust] (#9831)", got)
		}
		if got := zones["trust"]; got != `tcp-rst=true screen=""` {
			t.Errorf("zone trust compiled %s, want the inline tcp-rst (#9831)", got)
		}
		// The group's leaf names the inline zone, so it merges into it rather
		// than sitting beside it as a second node for the same zone.
		n := 0
		for _, sec := range expand9801(t, text).FindChildren("security") {
			for _, zs := range sec.Children {
				if len(zs.Keys) != 1 || zs.Keys[0] != "zones" {
					continue
				}
				for _, z := range zs.Children {
					if len(z.Keys) == 2 && z.Keys[0] == "security-zone" && z.Keys[1] == "trust" {
						n++
					}
				}
			}
		}
		if n != 1 {
			t.Errorf("expanded tree has %d security-zone trust nodes, want 1: the group's leaf must merge into the inline zone (#9831)", n)
		}
	})
	t.Run("scalar leaf, inline value still wins (control)", func(t *testing.T) {
		tree := expand9801(t, `groups { G { system { host-name fromgroup; } } } apply-groups G; system { host-name inline; }`)
		var got []string
		for _, sys := range tree.FindChildren("system") {
			for _, n := range sys.Children {
				if len(n.Keys) > 0 && n.Keys[0] == "host-name" {
					got = append(got, strings.Join(n.Keys, " "))
				}
			}
		}
		if strings.Join(got, ",") != "host-name inline" {
			t.Errorf("expanded host-name nodes %q, want [host-name inline]: the zone rule does not reach a scalar, so the inline value overrides the group's (#9831)", got)
		}
	})
}

// #9831: a group's security-zone statement that carries keys past the zone name
// is judged as the same text written inline, whatever spelling the inline zone
// has. With the first identity rule (0195e18b4), the braced rows committed with
// the extra keys dropped, although master refused them; the leaf rows commit
// that way at master (ad2ba883a) too.
func TestGroupZoneStatementTailIsJudgedAsInline9831(t *testing.T) {
	const g = `groups { G { security { zones { %s } } } } apply-groups G; security { zones { %s } }`
	for _, c := range []struct{ name, group, inline, want string }{
		{"list beside the braced first member", `security-zone [ zga zgb ];`, `security-zone zga { tcp-rst; }`, `only zone "zga" compiles, and "zgb" is dropped`},
		{"list beside the leaf first member", `security-zone [ zga zgb ];`, `security-zone zga;`, `only zone "zga" compiles, and "zgb" is dropped`},
		{"mistyped statement beside a braced zone", `security-zone trust scren edge;`, `security-zone trust { }`, `only zone "trust" compiles, and "scren edge" is dropped`},
		{"mistyped statement beside a leaf zone", `security-zone trust scren edge;`, `security-zone trust;`, `only zone "trust" compiles, and "scren edge" is dropped`},
	} {
		t.Run(c.name, func(t *testing.T) {
			text := fmt.Sprintf(g, c.group, c.inline)
			tree, perrs := NewParser(text).Parse()
			if len(perrs) > 0 {
				t.Fatalf("fixture must parse: %v", perrs)
			}
			if _, err := CompileConfig(tree); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("strict %q: want the #9656 refusal containing %q, got %v: the group's extra keys must not be dropped silently (#9831)", text, c.want, err)
			}
		})
	}
	t.Run("apply-macro statement beside a leaf zone (control)", func(t *testing.T) {
		zones := zones9801(t, fmt.Sprintf(g, `security-zone trust apply-macro M;`, `security-zone trust;`))
		if got := zoneNames9801(zones); got != "trust" {
			t.Errorf("compiled zones [%s], want [trust] (#9831)", got)
		}
	})
}

// The zone rule does not reach a value list. A schema-generic identity rule
// matched a group's `next-hop 192.0.2.2;` against the inline list
// `[ 192.0.2.1 192.0.2.2 ]` by its first member, adopted it, and compiled a
// duplicate next hop; the reversed list did not (d64625101, Codex review round
// 1). Master compiles both rows without a duplicate.
func TestGroupValueListGetsNoDuplicate9831(t *testing.T) {
	for _, c := range []struct{ name, inline, want string }{
		{"group value second in the inline list", `next-hop [ 192.0.2.1 192.0.2.2 ];`, "192.0.2.1 192.0.2.2"},
		{"group value first in the inline list", `next-hop [ 192.0.2.2 192.0.2.1 ];`, "192.0.2.2 192.0.2.1"},
	} {
		t.Run(c.name, func(t *testing.T) {
			text := `groups { G { routing-options { static { route 10.0.0.0/8 { next-hop 192.0.2.2; } } } } } apply-groups G; routing-options { static { route 10.0.0.0/8 { ` + c.inline + ` } } }`
			tree, perrs := NewParser(text).Parse()
			if len(perrs) > 0 {
				t.Fatalf("fixture must parse: %v", perrs)
			}
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("strict compile %q: %v", text, err)
			}
			var hops []string
			for _, r := range cfg.RoutingOptions.StaticRoutes {
				for _, nh := range r.NextHops {
					hops = append(hops, nh.Address)
				}
			}
			if got := strings.Join(hops, " "); got != c.want {
				t.Errorf("compiled next hops [%s], want [%s]: a group value already in the inline list must not be added again (#9831)", got, c.want)
			}
		})
	}
}

// A packed group zone statement beside the inline braced zone of the same name
// merges into it through #7648, as one zone statement. Measured on group
// expansion alone: the compile path folds the packed statement before expansion
// (#8662), but expansions of an unnormalised tree do not.
func TestGroupPackedZoneStatementMergesIntoBracedZone9831(t *testing.T) {
	tree := expand9801(t, `groups { G { security { zones { security-zone trust tcp-rst; } } } } apply-groups G; security { zones { security-zone trust { } } }`)
	var stmts []string
	rst := false
	for _, sec := range tree.FindChildren("security") {
		for _, zs := range sec.Children {
			if len(zs.Keys) != 1 || zs.Keys[0] != "zones" {
				continue
			}
			for _, z := range zs.Children {
				if len(z.Keys) >= 2 && z.Keys[0] == "security-zone" {
					stmts = append(stmts, strings.Join(z.Keys, " "))
					if z.FindChild("tcp-rst") != nil {
						rst = true
					}
				}
			}
		}
	}
	if strings.Join(stmts, ",") != "security-zone trust" || !rst {
		t.Errorf("expanded zone statements %q (tcp-rst merged: %v), want one `security-zone trust` holding the group's tcp-rst (#7648, #9831)", stmts, rst)
	}
}

// The zone rule does not reach keys the compiler canonicalises. A schema-generic
// identity rule treated a group's `ospf area 0 area-type stub;` and an inline
// `area 0.0.0.0;` as different instances and compiled two areas for one
// (9d1424e09, Codex review round 2). Master compiles one area. Only the count is
// pinned: whether the group's `area-type` should reach the area is #9859.
func TestGroupCanonicalAliasGetsNoSecondInstance9831(t *testing.T) {
	const text = `groups { G { protocols { ospf { area 0 area-type stub; } } } } apply-groups G; protocols { ospf { area 0.0.0.0; } }`
	tree, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture must parse: %v", perrs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict compile %q: %v", text, err)
	}
	var ids []string
	if cfg.Protocols.OSPF != nil {
		for _, a := range cfg.Protocols.OSPF.Areas {
			ids = append(ids, a.ID)
		}
	}
	if len(ids) != 1 {
		t.Errorf("compiled OSPF areas %v, want one area: `area 0` and `area 0.0.0.0` name the same area (#9831)", ids)
	}
}
