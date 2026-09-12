package config

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

// #9802: a wildcard-keyed instance inside a group container the destination
// LACKS was adopted wholesale, wildcard key and all, so it compiled as an
// instance literally named `<*>`. That is #9423's phantom reached by the route
// its fixtures cannot take: they all put the parent container in the target, so
// the wildcard reaches the wildcard branch and "applies nothing, invents
// nothing". Measured at master ef390f3ac, every row below compiled the phantom
// and strict commit accepted it.
func TestGroupWildcardUnderMissingContainerInventsNothing9802(t *testing.T) {
	const screen = `screen { ids-option edge { icmp { ping-death; } } } `
	const zoneGroup = `groups { G { security { zones { security-zone <*> { tcp-rst; } } } } } apply-groups G; `
	for _, c := range []struct{ name, text string }{
		{"zone wildcard, target has no zones block", zoneGroup + `security { ` + screen + `}`},
		{"zone wildcard, bodyless", `groups { G { security { zones { security-zone <*>; } } } } apply-groups G; security { ` + screen + `}`},
		{"zone wildcard, target has no security stanza at all", zoneGroup + `system { host-name p; }`},
	} {
		t.Run(c.name, func(t *testing.T) {
			tree, perrs := NewParser(c.text).Parse()
			if len(perrs) > 0 {
				t.Fatalf("fixture must parse: %v", perrs)
			}
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("strict compile %q: %v", c.text, err)
			}
			for name := range cfg.Security.Zones {
				if strings.ContainsAny(name, "<>*") {
					t.Errorf("compiled a phantom zone %q: a wildcard matched nothing, so it must invent nothing (#9802, #9423)", name)
				}
			}
		})
	}
	t.Run("interface wildcard, target has no interfaces", func(t *testing.T) {
		const text = `groups { G { interfaces { <*> { description fromgroup; } } } } apply-groups G; security { zones { security-zone trust { } } }`
		tree, perrs := NewParser(text).Parse()
		if len(perrs) > 0 {
			t.Fatalf("fixture must parse: %v", perrs)
		}
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("strict compile: %v", err)
		}
		for name := range cfg.Interfaces.Interfaces {
			if strings.ContainsAny(name, "<>*") {
				t.Errorf("compiled a phantom interface %q (#9802, #9423)", name)
			}
		}
	})
	t.Run("a body that was only wildcard leaves no empty stanza", func(t *testing.T) {
		const text = `groups { G { security { zones { security-zone <*> { tcp-rst; } } } } } apply-groups G; security { screen { ids-option edge { icmp { ping-death; } } } }`
		tree, perrs := NewParser(text).Parse()
		if len(perrs) > 0 {
			t.Fatalf("fixture must parse: %v", perrs)
		}
		if err := tree.ExpandGroups(); err != nil {
			t.Fatalf("expand: %v", err)
		}
		for _, sec := range tree.FindChildren("security") {
			for _, ch := range sec.Children {
				if len(ch.Keys) == 1 && ch.Keys[0] == "zones" {
					t.Errorf("an empty `zones` stanza was adopted: the group's whole body was wildcard-keyed, so the container adds nothing (#9802)")
				}
			}
		}
	})
	t.Run("the group's concrete instance survives the prune", func(t *testing.T) {
		const text = `groups { G { security { zones { security-zone zg { } security-zone <*> { tcp-rst; } } } } } apply-groups G; security { screen { ids-option edge { icmp { ping-death; } } } }`
		tree, perrs := NewParser(text).Parse()
		if len(perrs) > 0 {
			t.Fatalf("fixture must parse: %v", perrs)
		}
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("strict compile: %v", err)
		}
		var names []string
		for n := range cfg.Security.Zones {
			names = append(names, n)
		}
		sort.Strings(names)
		if strings.Join(names, " ") != "zg" {
			t.Errorf("compiled zones %v, want [zg]: the wildcard is dropped and the group's own zone kept (#9802)", names)
		}
	})
}

// The prune is scoped to a wildcard in an INSTANCE-NAME position. A wildcard in
// a zone's `interfaces` MEMBER slot is not an instance key: it is adopted as
// today and stays loudly refused by the interface-reference check, which is
// what TestGroupKeyWildcardLeafMemberStillRefused9423 pins. A schema-shape
// predicate pruned it (the zone member slot is declared as a wildcard child
// WITH children, exactly like a dynamic instance name), which turned that
// refusal silent; this cell is the guard for that.
func TestGroupWildcardMemberStaysRefused9802(t *testing.T) {
	const realIface = `interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } } } `
	const memberGroup = `groups { G { security { zones { security-zone trust { interfaces { <ge-*>; } } } } } } apply-groups G; `
	for _, c := range []struct{ name, text string }{
		{"target has no security stanza", memberGroup + realIface},
		{"target has no zones block", memberGroup + realIface + `security { screen { ids-option edge { icmp { ping-death; } } } }`},
		{"beside an instance wildcard in the same group",
			`groups { G { security { zones { security-zone <*> { tcp-rst; } security-zone trust { interfaces { <ge-*>; } } } } } } apply-groups G; ` + realIface},
	} {
		t.Run(c.name, func(t *testing.T) {
			tree, perrs := NewParser(c.text).Parse()
			if len(perrs) > 0 {
				t.Fatalf("fixture must parse: %v", perrs)
			}
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("strict accepted a wildcard zone member; it must stay refused (#9802, #9423)")
			}
			if !strings.Contains(err.Error(), "<ge-*>") {
				t.Errorf("refused, but the message does not name the token: %v (#9802)", err)
			}
		})
	}
}

// #9802: a group container merged into the FIRST same-keyed destination and
// stopped, so a level the operator spread over two blocks received the group in
// only one of them. Measured at master ef390f3ac, every row below compiled
// without the group's statement in the second block, and strict commit accepted
// it. Split top-level stanzas are a supported spelling: #5691, fixed by #5741,
// made the AST pre-passes aggregate across all roots.
func TestGroupContainerReachesEverySameKeyedStanza9802(t *testing.T) {
	const screen = `screen { ids-option edge { icmp { ping-death; } } } `
	const zoneGroup = `groups { G { security { zones { security-zone <*> { tcp-rst; } } } } } apply-groups G; `
	for _, c := range []struct {
		name, text string
		want       string
	}{
		{"zones in a second security stanza, braced zone",
			zoneGroup + `security { ` + screen + `} security { zones { security-zone trust { } } }`,
			"trust=true"},
		{"zones in a second security stanza, zone written as a leaf",
			zoneGroup + `security { ` + screen + `} security { zones { security-zone trust; } }`,
			"trust=true"},
		{"zones stanza first (control)",
			zoneGroup + `security { zones { security-zone trust { } } } security { ` + screen + `}`,
			"trust=true"},
		{"two zones blocks in one security stanza",
			zoneGroup + `security { zones { security-zone trust { } } zones { security-zone untrust { } } }`,
			"trust=true untrust=true"},
	} {
		t.Run(c.name, func(t *testing.T) {
			tree, perrs := NewParser(c.text).Parse()
			if len(perrs) > 0 {
				t.Fatalf("fixture must parse: %v", perrs)
			}
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("strict compile %q: %v", c.text, err)
			}
			var got []string
			for n, z := range cfg.Security.Zones {
				got = append(got, fmt.Sprintf("%s=%v", n, z.TCPRst))
			}
			sort.Strings(got)
			if strings.Join(got, " ") != c.want {
				t.Errorf("compiled zones %v, want [%s]: every same-keyed stanza must receive the group (#9802)", got, c.want)
			}
		})
	}
	t.Run("two interfaces stanzas", func(t *testing.T) {
		const text = `groups { G { interfaces { <*> { description fromgroup; } } } } apply-groups G; interfaces { ge-0/0/1 { unit 0; } } interfaces { ge-0/0/0 { unit 0; } }`
		tree, perrs := NewParser(text).Parse()
		if len(perrs) > 0 {
			t.Fatalf("fixture must parse: %v", perrs)
		}
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("strict compile: %v", err)
		}
		var missing []string
		for _, n := range []string{"ge-0/0/0", "ge-0/0/1"} {
			ifc := cfg.Interfaces.Interfaces[n]
			if ifc == nil || ifc.Description != "fromgroup" {
				missing = append(missing, n)
			}
		}
		if len(missing) > 0 {
			t.Errorf("interfaces %v did not receive the group's description: every same-keyed stanza must receive it (#9802)", missing)
		}
	})
	t.Run("a concrete group block is not duplicated across stanzas (control)", func(t *testing.T) {
		const text = `groups { G { security { zones { security-zone zg { } } } } } apply-groups G; security { screen { ids-option edge { icmp { ping-death; } } } } security { zones { security-zone trust { } } }`
		tree, perrs := NewParser(text).Parse()
		if len(perrs) > 0 {
			t.Fatalf("fixture must parse: %v", perrs)
		}
		tr2, _ := NewParser(text).Parse()
		if err := tr2.ExpandGroups(); err != nil {
			t.Fatalf("expand: %v", err)
		}
		n := 0
		for _, sec := range tr2.FindChildren("security") {
			for _, zs := range sec.Children {
				if len(zs.Keys) != 1 || zs.Keys[0] != "zones" {
					continue
				}
				for _, z := range zs.Children {
					if len(z.Keys) >= 2 && z.Keys[0] == "security-zone" && z.Keys[1] == "zg" {
						n++
					}
				}
			}
		}
		if n != 1 {
			t.Errorf("the group's zone zg appears %d times in the expanded tree, want 1: only wildcard-keyed children fan out (#9802)", n)
		}
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("strict compile: %v", err)
		}
		if _, ok := cfg.Security.Zones["zg"]; !ok {
			t.Errorf("the group's zone zg did not compile (#9802)")
		}
	})
}
