package config

import (
	"sort"
	"testing"
)

// #9656 (M40): the #8662 normalizer fans a security-zone group out into one
// zone statement per member. Measured at e09f425dd, strict commit accepted each
// of these, and none compiled zone zgb:
//
//	security-zone [ zga zgb ] screen edge;   zga with no screen, no zgb
//	security-zone [ zga zgb ];               no zgb
//	security-zone [ zga zgb ] { }            no zgb
//
// Each group spelling is checked against the LONGHAND, one statement per zone.
// The normalized trees must be equal.
func TestZoneGroupNormalizesToLonghand9656(t *testing.T) {
	cells := []struct{ name, group, longhand string }{
		{"packed body",
			`security-zone [ zga zgb ] screen edge;`,
			`security-zone zga { screen edge; } security-zone zgb { screen edge; }`},
		{"packed body without brackets",
			`security-zone zga zgb screen edge;`,
			`security-zone zga { screen edge; } security-zone zgb { screen edge; }`},
		{"bare leaf",
			`security-zone [ zga zgb ];`,
			`security-zone zga; security-zone zgb;`},
		{"braced body",
			`security-zone [ zga zgb ] { screen edge; }`,
			`security-zone zga { screen edge; } security-zone zgb { screen edge; }`},
		{"packed head with a braced body",
			`security-zone [ zga zgb ] interfaces { ge-0/0/0.0; }`,
			`security-zone zga { interfaces { ge-0/0/0.0; } } security-zone zgb { interfaces { ge-0/0/0.0; } }`},
		{"three members",
			`security-zone [ za zb zc ] screen edge;`,
			`security-zone za { screen edge; } security-zone zb { screen edge; } security-zone zc { screen edge; }`},
		{"quoted packed body",
			`security-zone [ zga zgb ] description "two words";`,
			`security-zone zga { description "two words"; } security-zone zgb { description "two words"; }`},
		{"quoted member",
			`security-zone [ "zg a" zgb ] screen edge;`,
			`security-zone "zg a" { screen edge; } security-zone zgb { screen edge; }`},
		{"bracketed packed body",
			`security-zone [ zga zgb ] interfaces [ ge-0/0/0.0 ge-0/0/1.0 ];`,
			`security-zone zga { interfaces [ ge-0/0/0.0 ge-0/0/1.0 ]; } security-zone zgb { interfaces [ ge-0/0/0.0 ge-0/0/1.0 ]; }`},
		{"braced group naming a zone after a flag keyword",
			`security-zone [ zga zgb tcp-rst ] { tcp-rst; }`,
			`security-zone zga { tcp-rst; } security-zone zgb { tcp-rst; } security-zone tcp-rst { tcp-rst; }`},
		{"braced group naming a zone after a leaf keyword",
			`security-zone [ zga zgb screen ] { screen edge; }`,
			`security-zone zga { screen edge; } security-zone zgb { screen edge; } security-zone screen { screen edge; }`},
		{"braced group naming a zone after an apply keyword",
			`security-zone [ zga zgb apply-groups ] { tcp-rst; }`,
			`security-zone zga { tcp-rst; } security-zone zgb { tcp-rst; } security-zone apply-groups { tcp-rst; }`},
		{"packed wildcard head with a braced body",
			`security-zone [ zga zgb ] interfaces ge-0/0/0.0 { host-inbound-traffic { system-services { ping; } } }`,
			`security-zone zga { interfaces ge-0/0/0.0 { host-inbound-traffic { system-services { ping; } } } } security-zone zgb { interfaces ge-0/0/0.0 { host-inbound-traffic { system-services { ping; } } } }`},
		{"packed apply-macro head with a braced body",
			`security-zone [ zga zgb ] apply-macro M { k v; }`,
			`security-zone zga { apply-macro M { k v; } } security-zone zgb { apply-macro M { k v; } }`},
		{"inactive group",
			`inactive: security-zone [ zga zgb ] screen edge;`,
			`inactive: security-zone zga { screen edge; } inactive: security-zone zgb { screen edge; }`},
		{"packed apply-groups",
			`security-zone [ zga zgb ] apply-groups G;`,
			`security-zone zga { apply-groups G; } security-zone zgb { apply-groups G; }`},
		{"braced apply-groups",
			`security-zone [ zga zgb ] { apply-groups G; }`,
			`security-zone zga { apply-groups G; } security-zone zgb { apply-groups G; }`},
		{"single zone is left to the fold",
			`security-zone zga screen edge;`,
			`security-zone zga { screen edge; }`},
	}
	wraps := []struct{ name, pre, post string }{
		{"top level", `security { zones { `, ` } }`},
		{"inside groups", `groups { G { security { zones { `, ` } } } }`},
	}
	for _, c := range cells {
		for _, w := range wraps {
			t.Run(c.name+"/"+w.name, func(t *testing.T) {
				g := parse8921(t, "group", w.pre+c.group+w.post)
				l := parse8921(t, "longhand", w.pre+c.longhand+w.post)
				if g == nil || l == nil {
					return
				}
				normalizeCompactStanzas(g)
				normalizeCompactStanzas(l)
				if !sameTree8921(g, l) {
					t.Errorf("group %q normalizes to a different tree than longhand %q (#9656)\n group:\n%s longhand:\n%s",
						c.group, c.longhand, treeText8921(g), treeText8921(l))
				}
			})
		}
	}
}

// A group reached through a compact head fans out the same way. The single-zone
// rows are CONTROLS: they fail if the head fold itself does not reach `zones`,
// which is a different defect from the fan-out.
func TestZoneGroupUnderCompactHeadNormalizesToLonghand9656(t *testing.T) {
	const longhand = `security { zones { security-zone zga { screen edge; } security-zone zgb { screen edge; } } }`
	const single = `security { zones { security-zone zga { screen edge; } } }`
	cells := []struct {
		name, text, want string
		control          bool
	}{
		{"security zones head", `security zones security-zone [ zga zgb ] screen edge;`, longhand, false},
		{"zones head", `security { zones security-zone [ zga zgb ] screen edge; }`, longhand, false},
		{"security zones head, single zone", `security zones security-zone zga screen edge;`, single, true},
		{"zones head, single zone", `security { zones security-zone zga screen edge; }`, single, true},
	}
	for _, c := range cells {
		t.Run(c.name, func(t *testing.T) {
			g := parse8921(t, "compact", c.text)
			l := parse8921(t, "longhand", c.want)
			if g == nil || l == nil {
				return
			}
			normalizeCompactStanzas(g)
			normalizeCompactStanzas(l)
			if sameTree8921(g, l) {
				return
			}
			label := "group"
			if c.control {
				label = "CONTROL"
			}
			t.Errorf("%s %q normalizes to a different tree than %q (#9656)\n got:\n%s want:\n%s",
				label, c.text, c.want, treeText8921(g), treeText8921(l))
		})
	}
}

// The flat-set shape fans out the same way. The tree is built the way the CLI
// builds it (ParseSetCommandGrouped then SetPathQuotedGrouped, as
// configstore's store_command.go does), where a bracket widens the node's key
// group.
func TestZoneGroupFlatSetNormalizesToLonghand9656(t *testing.T) {
	build := func(t *testing.T, cmds []string) *ConfigTree {
		t.Helper()
		tree := &ConfigTree{}
		for _, cmd := range cmds {
			path, quoted, grouped, err := ParseSetCommandGrouped(cmd)
			if err != nil {
				t.Fatalf("ParseSetCommandGrouped(%q): %v", cmd, err)
			}
			if len(path) > 0 && path[0] == "set" {
				t.Fatalf("fixture: ParseSetCommandGrouped(%q) kept the set verb: %q", cmd, path)
			}
			if err := tree.SetPathQuotedGrouped(path, quoted, grouped); err != nil {
				t.Fatalf("SetPathQuotedGrouped(%q): %v", cmd, err)
			}
		}
		return tree
	}
	cells := []struct {
		name            string
		group, longhand []string
	}{
		{"bracketed group with a body",
			[]string{`set security zones security-zone [ zga zgb ] screen edge`},
			[]string{`set security zones security-zone zga screen edge`, `set security zones security-zone zgb screen edge`}},
		{"bare bracketed group",
			[]string{`set security zones security-zone [ zga zgb ]`},
			[]string{`set security zones security-zone zga`, `set security zones security-zone zgb`}},
	}
	for _, c := range cells {
		t.Run(c.name, func(t *testing.T) {
			g := build(t, c.group)
			l := build(t, c.longhand)
			normalizeCompactStanzas(g)
			normalizeCompactStanzas(l)
			if !sameTree8921(g, l) {
				t.Errorf("flat group %q normalizes to a different tree than longhand %q (#9656)\n group:\n%s longhand:\n%s",
					c.group, c.longhand, treeText8921(g), treeText8921(l))
			}
		})
	}
}

// A fan-out whose clones would exceed the node budget is not performed. The
// statement is left as parsed, and bracketedGroupInstances8794 compiles it with
// one shared body, as it did before #9656. The #9656 Codex review measured the
// unbounded version: 10,000 members over a 10,000-statement body cloned about
// 100 million nodes.
func TestZoneGroupFanOutRespectsNodeBudget9656(t *testing.T) {
	const body = `security { zones { security-zone [ za zb zc ] { tcp-rst; description d; } } }`
	const tail = `security { zones { security-zone [ za zb zc ] tcp-rst; } }`
	// body: 3 members × (1 zone node + 2 body nodes) = 9 nodes.
	// tail: 3 members × (1 zone node + 1 tail node) = 6 nodes.
	for _, c := range []struct {
		text         string
		budget, want int
	}{{body, 8, 1}, {body, 9, 3}, {tail, 5, 1}, {tail, 6, 3}} {
		text := c.text
		tr := parse8921(t, "group", text)
		if tr == nil {
			return
		}
		var zones *Node
		for _, sec := range tr.FindChildren("security") {
			for _, z := range sec.Children {
				if len(z.Keys) == 1 && z.Keys[0] == "zones" {
					zones = z
				}
			}
		}
		if zones == nil {
			t.Fatalf("fixture: no zones node in %q", text)
		}
		expandZoneGroupsWithin9656(zones, zonesSchema9656.children["security-zone"], c.budget)
		if got := len(zones.Children); got != c.want {
			t.Errorf("%q with budget %d: %d zone statement(s) after the fan-out, want %d (#9656)", text, c.budget, got, c.want)
		}
	}
}

// An apply statement keyword ends the member list. setSchema does not declare
// apply-groups, apply-groups-except or apply-macro inside a zone (#9685).
// Without that stop, each of these single zones would be read as the three
// zones trust, <keyword> and G.
func TestZoneGroupStopsAtApplyKeyword9656(t *testing.T) {
	for _, kw := range []string{"apply-groups", "apply-groups-except", "apply-macro"} {
		text := `security { zones { security-zone trust ` + kw + ` G; } }`
		tr := parse8921(t, kw, text)
		if tr == nil {
			continue
		}
		normalizeCompactStanzas(tr)
		var names []string
		for _, sec := range tr.FindChildren("security") {
			for _, zs := range sec.Children {
				if len(zs.Keys) != 1 || zs.Keys[0] != "zones" {
					continue
				}
				for _, z := range zs.Children {
					if len(z.Keys) >= 2 && z.Keys[0] == "security-zone" {
						names = append(names, z.Keys[1])
					}
				}
			}
		}
		if len(names) != 1 || names[0] != "trust" {
			t.Errorf("%q: normalized zone statements name %v, want only [trust] (#9656)", text, names)
		}
	}
}

// The zone-ID collision gate enumerates zones from the normalized tree
// (compileConfigWithOpts runs normalizeCompactStanzas before
// validateZoneIDCollisionAST). It must therefore see every zone the compiler
// creates. A zone the compiler creates but the ID machinery cannot see is the
// disagreement #8794's first fix introduced.
func TestZoneGroupEnumerationAgrees9656(t *testing.T) {
	const screens = `security { screen { ids-option edge { icmp { ping-death; } } } } `
	for _, group := range []string{
		`security-zone [ zga zgb ] screen edge;`,
		`security-zone [ zga zgb ];`,
		`security-zone [ zga zgb ] { }`,
	} {
		text := screens + `security { zones { ` + group + ` } }`
		tr, perrs := NewParser(text).Parse()
		if len(perrs) > 0 {
			t.Fatalf("%q: fixture must parse: %v", group, perrs)
		}
		cfg, err := compileConfigWithOpts(tr.Clone(), compileOpts{})
		if err != nil {
			t.Errorf("%q: strict compile: %v", group, err)
			continue
		}
		var compiled []string
		for name := range cfg.Security.Zones {
			compiled = append(compiled, name)
		}
		sort.Strings(compiled)
		if want := []string{"zga", "zgb"}; len(compiled) != 2 || compiled[0] != want[0] || compiled[1] != want[1] {
			t.Errorf("%q: compiled zones %v, want [zga zgb] (#9656)", group, compiled)
		}
		norm := tr.Clone()
		normalizeCompactStanzas(norm)
		names := map[string]struct{}{}
		for _, sec := range norm.FindChildren("security") {
			collectZoneNamesAST(sec, names)
		}
		for _, zn := range compiled {
			if _, ok := names[zn]; !ok {
				t.Errorf("%q: zone %q is compiled but absent from collectZoneNamesAST on the normalized tree (#9656)", group, zn)
			}
		}
		if len(names) != len(compiled) {
			t.Errorf("%q: collectZoneNamesAST sees %d zone(s), the compiler creates %d (#9656)", group, len(names), len(compiled))
		}
	}
}
