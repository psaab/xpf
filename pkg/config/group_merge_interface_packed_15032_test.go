package config

import (
	"fmt"
	"sort"
	"testing"
)

// #15032 (A03-03): an interface instance written brace-elided
// (`ge-0/0/0 unit 0 family inet address A;`) is a leaf whose Keys run
// names the interface, so group merge was blind to it:
//   - a `<*>` group filter was not bound (keysMatchWildcard needs equal
//     key lengths, and the wildcard arm visited only non-leaf dst);
//   - an exact-name group container twinned it, and compileInterfaces'
//     last-wins map assignment kept only the group twin, losing the
//     inline address.
// The braced spelling of the same inline config takes both. The packed
// rows below must equal their braced controls.

func compileIfaces15032(t *testing.T, text string) map[string]map[int][]string {
	t.Helper()
	tree, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture must parse: %v", perrs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict compile %q: %v", text, err)
	}
	out := map[string]map[int][]string{}
	for name, ifc := range cfg.Interfaces.Interfaces {
		units := map[int][]string{}
		for num, u := range ifc.Units {
			addrs := append([]string(nil), u.Addresses...)
			sort.Strings(addrs)
			// include filter so wildcard-filter rows are observable
			units[num] = append(addrs, fmt.Sprintf("filter=%q", u.FilterInputV4))
		}
		out[name] = units
	}
	return out
}

func TestInterfacePackedLeafTakesExactNameGroup15032(t *testing.T) {
	group := `groups { G { interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.0.2/24; } } } } } } apply-groups G; `
	for _, c := range []struct{ name, text string }{
		{"packed inline", group + `interfaces { ge-0/0/0 unit 0 family inet address 10.0.0.1/24; }`},
		{"braced inline (control)", group + `interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } } }`},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := compileIfaces15032(t, c.text)
			units, ok := got["ge-0/0/0"]
			if !ok {
				t.Fatalf("compiled interfaces %v, want ge-0/0/0 (#15032)", got)
			}
			addrs := units[0]
			// inline address must survive AND group address must merge (braced control has both)
			want := `[10.0.0.1/24 10.0.0.2/24 filter=""]`
			if fmt.Sprint(addrs) != want {
				t.Errorf("ge-0/0/0 unit 0 = %v, want %s: packed inline must equal braced control (#15032)", addrs, want)
			}
		})
	}
}

func TestInterfacePackedLeafTakesWildcardGroup15032(t *testing.T) {
	// Need a defined filter so strict compile does not fail on undefined F1;
	// define firewall filter F1.
	pre := `firewall { family inet { filter F1 { term t { then accept; } } } } `
	group := `groups { G { interfaces { <*> { unit 0 { family inet { filter { input F1; } } } } } } } apply-groups G; `
	for _, c := range []struct{ name, text string }{
		{"packed inline", pre + group + `interfaces { ge-0/0/0 unit 0 family inet address 10.0.0.1/24; }`},
		{"braced inline (control)", pre + group + `interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } } }`},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := compileIfaces15032(t, c.text)
			units, ok := got["ge-0/0/0"]
			if !ok {
				t.Fatalf("compiled interfaces %v, want ge-0/0/0 (#15032)", got)
			}
			want := `[10.0.0.1/24 filter="F1"]`
			if fmt.Sprint(units[0]) != want {
				t.Errorf("ge-0/0/0 unit 0 = %v, want %s: <*> group must reach packed interface (#15032)", units[0], want)
			}
		})
	}
}

// Expanded-tree shape: after group expansion the packed inline must be
// ONE ge-0/0/0 container (not a packed leaf twin beside a group container).
func TestInterfacePackedLeafNotTwinned15032(t *testing.T) {
	text := `groups { G { interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.0.2/24; } } } } } } apply-groups G; interfaces { ge-0/0/0 unit 0 family inet address 10.0.0.1/24; }`
	tree := expand9801(t, text)
	n := 0
	for _, ifs := range tree.FindChildren("interfaces") {
		for _, ch := range ifs.Children {
			if len(ch.Keys) > 0 && ch.Keys[0] == "ge-0/0/0" {
				n++
				if ch.IsLeaf {
					t.Errorf("ge-0/0/0 remains a packed leaf after expansion: %v (#15032)", ch.Keys)
				}
			}
		}
	}
	if n != 1 {
		t.Errorf("expanded tree has %d ge-0/0/0 nodes, want 1 (#15032)", n)
	}
}

// Control: bare leaf interface still refused by #9838 and not created by wildcard.
func TestInterfaceBareLeafStillRefused15032(t *testing.T) {
	text := `groups { G { interfaces { <*> { description fromgroup; } } } } apply-groups G; interfaces { ge-0/0/0; ge-0/0/1 { unit 0; } }`
	tree, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	if _, err := CompileConfig(tree); err == nil {
		t.Errorf("bare leaf ge-0/0/0 must still be refused (#9838/#15032 control)")
	}
}
