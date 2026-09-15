package config

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// #9017. `set firewall family any filter BLOCK term T1 then discard` committed
// clean and minted ZERO filters -- a deny-everything-not-matched filter that
// displayed in `show` and enforced nothing. The hierarchical spelling worked,
// which is why it stayed invisible.

func firewallFlatSet9017(t *testing.T, lines ...string) *ConfigTree {
	t.Helper()
	tr := &ConfigTree{}
	for _, l := range lines {
		p, err := ParseSetCommand(l)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", l, err)
		}
		tr.SetPath(p)
	}
	return tr
}

// TestFlatSetFamilyAnyMintsBothFilters9017 is the defect itself.
func TestFlatSetFamilyAnyMintsBothFilters9017(t *testing.T) {
	for _, tc := range []struct {
		family      string
		gateAccepts bool
		inet, inet6 int
	}{
		{"inet", true, 1, 0},
		{"inet6", true, 0, 1},
		// The reported defect: `any` compiles to BOTH, via the
		// `case "any": dests = {Inet, Inet6}` that compiler_firewall.go has
		// always had and that the flat-set path could never reach.
		{"any", true, 1, 1},
		// The half the originating report did not state: ANY undeclared
		// address-family token collapsed the same way, so a typo silently
		// voided the filter. A fix aimed only at `any` leaves this live.
		{"inett", false, 0, 0},
	} {
		t.Run(tc.family, func(t *testing.T) {
			tr := firewallFlatSet9017(t,
				"set firewall family "+tc.family+" filter BLOCK term T1 from protocol tcp",
				"set firewall family "+tc.family+" filter BLOCK term T1 then discard")

			// NAME THE CHANNEL. The undeclared-family refusal is a COMPILER
			// prewalk gate, not a typed-leaf schema check, so it is
			// CompileConfig (the strict commit path) that must reject —
			// SchemaValidateWithDefinitions passes `inett` and always did.
			// Asserting the wrong channel here would have read as "the fix
			// does not work".
			c, cerr := CompileConfig(tr)
			if (cerr == nil) != tc.gateAccepts {
				t.Fatalf("strict compile accepted=%v, want %v (err=%v)", cerr == nil, tc.gateAccepts, cerr)
			}
			if !tc.gateAccepts {
				// The refusal must NAME the token. A generic message sends the
				// operator to re-read a filter that is spelled correctly.
				if !strings.Contains(cerr.Error(), tc.family) {
					t.Errorf("refusal does not name the offending token %q: %v", tc.family, cerr)
				}
				// #1960: the TOLERANT path must warn, not brick. A config an
				// older binary persisted still has to boot.
				lc, lerr := CompileConfigLenient(tr)
				if lerr != nil {
					t.Errorf("the LENIENT path rejected an unknown family; a persisted or "+
						"peer-synced config would fail to load (#1960): %v", lerr)
				} else if lc != nil {
					var warned bool
					for _, w := range lc.Warnings {
						if strings.Contains(w, tc.family) {
							warned = true
						}
					}
					if !warned {
						t.Errorf("the lenient path accepted family %q with NO warning — "+
							"silent is the state #9017 is about", tc.family)
					}
				}
				return
			}
			if got := len(c.Firewall.FiltersInet); got != tc.inet {
				t.Errorf("FiltersInet = %d, want %d", got, tc.inet)
			}
			if got := len(c.Firewall.FiltersInet6); got != tc.inet6 {
				t.Errorf("FiltersInet6 = %d, want %d", got, tc.inet6)
			}
		})
	}
}

// TestFlatSetAndHierarchicalFamilyAnyAgree9017 is the assertion the issue names
// as the one that would have caught this: the two spellings of the SAME
// configuration must compile to the same typed filter set.
//
// It is stronger than counting filters, and deliberately so -- "both spellings
// mint zero" would satisfy a count-based check, which is the levelling-down
// shape. The hierarchical arm is asserted non-empty first so that a comparison
// of two empty sets cannot pass.
func TestFlatSetAndHierarchicalFamilyAnyAgree9017(t *testing.T) {
	flat := firewallFlatSet9017(t,
		"set firewall family any filter BLOCK term T1 from protocol tcp",
		"set firewall family any filter BLOCK term T1 then discard")

	root, perrs := NewParser(`firewall {
		family any {
			filter BLOCK {
				term T1 {
					from { protocol tcp; }
					then { discard; }
				}
			}
		}
	}`).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse hierarchical: %v", perrs)
	}
	hier := &ConfigTree{Children: root.Children}

	cf, err := CompileConfig(flat)
	if err != nil {
		t.Fatalf("compile flat: %v", err)
	}
	ch, err := CompileConfig(hier)
	if err != nil {
		t.Fatalf("compile hierarchical: %v", err)
	}

	// Reference arm: without this, comparing two empty filter sets passes.
	if len(ch.Firewall.FiltersInet) == 0 || len(ch.Firewall.FiltersInet6) == 0 {
		t.Fatalf("the HIERARCHICAL control minted nothing (inet=%d inet6=%d) — the "+
			"comparison below would be between two empty sets and would prove nothing",
			len(ch.Firewall.FiltersInet), len(ch.Firewall.FiltersInet6))
	}
	if !reflect.DeepEqual(cf.Firewall.FiltersInet, ch.Firewall.FiltersInet) {
		t.Errorf("flat-set and hierarchical `family any` disagree on FiltersInet:\n flat: %+v\n hier: %+v",
			cf.Firewall.FiltersInet, ch.Firewall.FiltersInet)
	}
	if !reflect.DeepEqual(cf.Firewall.FiltersInet6, ch.Firewall.FiltersInet6) {
		t.Errorf("flat-set and hierarchical `family any` disagree on FiltersInet6:\n flat: %+v\n hier: %+v",
			cf.Firewall.FiltersInet6, ch.Firewall.FiltersInet6)
	}
}

// TestFamilyAnyAgreesAcrossEVERYSpelling9017 is the cell that catches the half
// the schema declaration did NOT fix.
//
// Declaring `any` was necessary and not sufficient. `normalizeCompactStanzas`
// splits a packed `family <af> filter F { … }` into `family <af>` > `filter F`
// before the compiler runs, and its scope is a (container, head) pair table
// that listed only `inet filter` and `inet6 filter`. Without `any filter` there
// too, the compact spelling stayed packed, compileFirewall's
// `afNode.FindChildren("filter")` found nothing, and the filter silently
// vanished -- reproducing the EXACT zero-filter outcome #9017 reports, in a
// spelling the original probe did not use.
//
// Note where the scope pair comes from: after a compoundKey descent the
// container asked about is the SUB-KEY (`inet`), not the compound keyword
// (`family`). Looking for a `family filter` entry finds nothing and reads as
// "this is not scoped at all", which is the wrong conclusion.
func TestFamilyAnyAgreesAcrossEVERYSpelling9017(t *testing.T) {
	spellings := []struct{ name, tmpl string }{
		{"braced", `firewall { family %s { filter F { term T { from { protocol tcp; } then { discard; } } } } }`},
		{"compact filter", `firewall { family %s filter F { term T { from { protocol tcp; } then { discard; } } } }`},
		{"compact stanza body", `firewall { family %s { filter F { term T { from protocol tcp; then discard; } } } }`},
	}
	for _, fam := range []string{"inet", "inet6", "any"} {
		var want4, want6 int
		switch fam {
		case "inet":
			want4, want6 = 1, 0
		case "inet6":
			want4, want6 = 0, 1
		case "any":
			want4, want6 = 1, 1
		}
		for _, sp := range spellings {
			t.Run(fam+"/"+sp.name, func(t *testing.T) {
				root, perrs := NewParser(fmt.Sprintf(sp.tmpl, fam)).Parse()
				if len(perrs) > 0 {
					t.Fatalf("parse: %v", perrs)
				}
				c, err := CompileConfig(&ConfigTree{Children: root.Children})
				if err != nil {
					t.Fatalf("compile: %v", err)
				}
				if got := len(c.Firewall.FiltersInet); got != want4 {
					t.Errorf("FiltersInet = %d, want %d", got, want4)
				}
				if got := len(c.Firewall.FiltersInet6); got != want6 {
					t.Errorf("FiltersInet6 = %d, want %d", got, want6)
				}
			})
		}
	}
}

// TestFirewallFamiliesAcceptTheSameGrammar9017 guards the copied filter
// grammars, including the implicit-inet spelling. A family that accepts a
// match another spelling does not would reintroduce the defect.
func TestFirewallFamiliesAcceptTheSameGrammar9017(t *testing.T) {
	fam := schemaFirewall.children["family"]
	// The undeclared-token gate is a compiler prewalk check, NOT
	// `closedWorld: true` on this node. closedWorld INHERITS, so arming it here
	// closed the whole filter grammar beneath `family` and began rejecting
	// `from source-prefix-list trusted` — valid, shipped configuration. Assert
	// it stays off, so nobody re-applies the fix that was measured and backed
	// out.
	if fam.closedWorld {
		t.Error("`firewall family` is closedWorld again. That flag INHERITS: it closes the " +
			"entire filter grammar beneath it and rejects valid config such as " +
			"`from source-prefix-list trusted`. The undeclared-family gate is " +
			"validateFirewallFilterFamilyTokensAST (#9017).")
	}
	get := func(f string) map[string]*schemaNode {
		n := fam.children[f]
		if n == nil {
			t.Fatalf("family %q is not declared", f)
		}
		return n.children["filter"].children["term"].children["from"].children
	}
	inet, inet6, any := get("inet"), get("inet6"), get("any")
	root := schemaFirewall.children["filter"]
	if root == nil {
		t.Fatal("implicit-inet filter grammar is not declared")
	}
	implicit := root.children["term"].children["from"].children
	if len(inet) == 0 {
		t.Fatal("positive control failed: the inet `from` grammar is empty, so the " +
			"comparisons below are between empty sets")
	}
	for _, pair := range []struct {
		name string
		a, b map[string]*schemaNode
	}{
		{"inet vs any", inet, any},
		{"inet vs inet6", inet, inet6},
		{"inet vs implicit inet", inet, implicit},
	} {
		var only []string
		for k := range pair.a {
			if _, ok := pair.b[k]; !ok {
				only = append(only, "-"+k)
			}
		}
		for k := range pair.b {
			if _, ok := pair.a[k]; !ok {
				only = append(only, "+"+k)
			}
		}
		if len(only) > 0 {
			t.Errorf("%s: firewall families accept different `from` grammars: %s — a match "+
				"one family accepts and another does not is #9017 returning one keyword at "+
				"a time", pair.name, fmt.Sprint(only))
		}
	}
}
