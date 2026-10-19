package config

import (
	"reflect"
	"sort"
	"testing"
)

// #15062 (A01-01): a top-level brace-elided interface
// `interfaces <name> { ... }` committed clean and compiled phantom
// interfaces, losing the named interface.
//
// Mechanism: the parser builds Keys=["interfaces","ge-0/0/0"] with the
// interface body as Children. compileSections dispatches on Name()
// ("interfaces") and ignores Keys[1:], so compileInterfaces received
// the `interfaces` node itself and turned every body child (`unit`,
// ...) into an InterfaceConfig named child.Name(). Measured at
// 43a7851561: the elided spelling compiled one interface named "unit"
// with no units; the braced spelling compiled ge-0/0/0 with unit 0 and
// its address. For fxp0 on the day-0 CheckText path this drops the
// management interface's address/DHCP/MTU on a clean strict commit.
//
// Fix: normalizeElidedInterface15062 folds the elided node into the
// braced shape inside normalizeCompactStanzas, which every compile
// core and SchemaValidate (via normalizeCompactForValidation) run
// before reading the tree — the #9620 routing-instance pattern. No
// (container, head) scope pair can name an operator-chosen interface
// name (#8879), so the fold is keyed on the top-level stanza itself.
//
// The 8879 cell is also updated: it asserted only err==nil for this
// spelling. It now compares compiled values (see
// TestInstanceNamePairCannotBeAdmitted8879).

var elidedInterfaceCells15062 = []struct {
	name, elided, braced string
}{
	{"unit address",
		`interfaces ge-0/0/0 { unit 0 { family inet { address 10.9.9.1/24; } } }`,
		`interfaces { ge-0/0/0 { unit 0 { family inet { address 10.9.9.1/24; } } } }`},
	{"fxp0 day-0 shape",
		`interfaces fxp0 { unit 0 { family inet { address 10.9.9.2/24; } } }`,
		`interfaces { fxp0 { unit 0 { family inet { address 10.9.9.2/24; } } } }`},
	{"mtu and description",
		`interfaces ge-0/0/1 { description uplink; mtu 9000; unit 0 { family inet { dhcp; } } }`,
		`interfaces { ge-0/0/1 { description uplink; mtu 9000; unit 0 { family inet { dhcp; } } } }`},
	{"packed tail past name",
		`interfaces ge-0/0/0 unit 0 { family inet { address 10.9.9.1/24; } }`,
		`interfaces { ge-0/0/0 unit 0 { family inet { address 10.9.9.1/24; } } }`},
	{"packed leaf tail",
		`interfaces ge-0/0/0 unit 0 family inet dhcp;`,
		`interfaces { ge-0/0/0 unit 0 family inet dhcp; }`},
	{"two units",
		`interfaces xe-0/0/0 { vlan-tagging; unit 0 { family inet { address 10.0.0.1/24; } } unit 1 { vlan-id 10; family inet6 { address 2001:db8::1/64; } } }`,
		`interfaces { xe-0/0/0 { vlan-tagging; unit 0 { family inet { address 10.0.0.1/24; } } unit 1 { vlan-id 10; family inet6 { address 2001:db8::1/64; } } } }`},
}

func TestElidedInterfaceNormalizesToTheBracedTree15062(t *testing.T) {
	for _, c := range elidedInterfaceCells15062 {
		for _, wrap := range []struct{ name, pre, post string }{
			{"top level", ``, ``},
			{"inside groups", `groups { G { `, ` } }`},
		} {
			t.Run(c.name+"/"+wrap.name, func(t *testing.T) {
				elided := parse8921(t, "elided", wrap.pre+c.elided+wrap.post)
				braced := parse8921(t, "braced", wrap.pre+c.braced+wrap.post)
				if elided == nil || braced == nil {
					return
				}
				normalizeCompactStanzas(elided)
				normalizeCompactStanzas(braced)
				if !sameTree8921(elided, braced) {
					t.Errorf("elided %q normalizes to a different tree than braced %q (#15062)\n elided:\n%s braced:\n%s",
						c.elided, c.braced, treeText8921(elided), treeText8921(braced))
				}
			})
		}
	}
}

func compileText15062(t *testing.T, txt string) *Config {
	t.Helper()
	tree, perrs := NewParser(txt).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture must parse: %v", perrs[0])
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile %q: %v", txt, err)
	}
	return cfg
}

func ifaceDigest15062(cfg *Config) map[string]ifaceDigestEntry15062 {
	out := make(map[string]ifaceDigestEntry15062)
	for name, ic := range cfg.Interfaces.Interfaces {
		e := ifaceDigestEntry15062{MTU: ic.MTU, Description: ic.Description, Disable: ic.Disable}
		units := make([]int, 0, len(ic.Units))
		for u := range ic.Units {
			units = append(units, u)
		}
		sort.Ints(units)
		for _, u := range units {
			uu := ic.Units[u]
			e.Units = append(e.Units, unitDigest15062{
				Number: uu.Number, Addresses: append([]string(nil), uu.Addresses...), DHCP: uu.DHCP,
			})
		}
		out[name] = e
	}
	return out
}

type ifaceDigestEntry15062 struct {
	MTU         int
	Description string
	Disable     bool
	Units       []unitDigest15062
}

type unitDigest15062 struct {
	Number    int
	Addresses []string
	DHCP      bool
}

// TestElidedInterfaceCompilesIdentically15062 is the value-comparing
// regression the issue requires: the elided and braced forms must
// compile to the same interfaces, with no phantom (`unit`, `family`)
// and the named interface's address/DHCP/MTU intact. Fails on
// origin/master (phantom "unit", named interface lost).
func TestElidedInterfaceCompilesIdentically15062(t *testing.T) {
	for _, c := range elidedInterfaceCells15062 {
		t.Run(c.name, func(t *testing.T) {
			elided := ifaceDigest15062(compileText15062(t, c.elided))
			braced := ifaceDigest15062(compileText15062(t, c.braced))
			if !reflect.DeepEqual(elided, braced) {
				t.Errorf("elided %q compiled differently from braced %q (#15062)\n elided: %+v\n braced: %+v",
					c.elided, c.braced, elided, braced)
			}
			for phantom := range elided {
				if phantom == "unit" || phantom == "family" {
					t.Errorf("elided %q compiled phantom interface %q (#15062)", c.elided, phantom)
				}
			}
		})
	}
	// Named controls: the braced form itself must keep working.
	cfg := compileText15062(t, `interfaces { fxp0 { unit 0 { family inet { address 10.9.9.2/24; } } } }`)
	if _, ok := cfg.Interfaces.Interfaces["fxp0"]; !ok {
		t.Fatalf("braced fxp0 missing from compiled config: %+v", cfg.Interfaces.Interfaces)
	}
}

// TestElidedInterfaceLeavesNeighbourShapesAlone15062 pins adjacent
// legitimate shapes through the same normalizer: a bare leaf name, a
// top-level apply-groups, and the ordinary braced form must not be
// rewritten into something else.
func TestElidedInterfaceLeavesNeighbourShapesAlone15062(t *testing.T) {
	for _, txt := range []string{
		`interfaces ge-0/0/0;`,
		`interfaces apply-groups G;`,
		`interfaces { ge-0/0/0 { unit 0 { family inet { dhcp; } } } }`,
	} {
		tree := parse8921(t, "neighbour", txt)
		if tree == nil {
			return
		}
		before := treeText8921(tree)
		normalizeCompactStanzas(tree)
		if txt == `interfaces { ge-0/0/0 { unit 0 { family inet { dhcp; } } } }` {
			// Braced form may be further folded internally, but must
			// still compile to the named interface.
			cfg := compileText15062(t, txt)
			if _, ok := cfg.Interfaces.Interfaces["ge-0/0/0"]; !ok {
				t.Errorf("braced control lost ge-0/0/0: %+v", cfg.Interfaces.Interfaces)
			}
			continue
		}
		if got := treeText8921(tree); got != before {
			t.Errorf("neighbour shape %q was rewritten (#15062)\n before:\n%s after:\n%s", txt, before, got)
		}
	}
}
