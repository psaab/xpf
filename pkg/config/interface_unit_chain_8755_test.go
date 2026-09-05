package config

import (
	"reflect"
	"testing"
)

// #8755: a brace-elided interface unit silently loses its address or its
// firewall filter, on a commit that reports success with zero warnings.
//
// TWO SYMPTOMS, TWO MECHANISMS. They present identically and they are not the
// same defect -- measured, because a shared shape is not a shared cause:
//
//	family inet address 10.0.0.1/24;   ONE chain link needed. (inet, address)
//	                                   was unadmitted, so the pass folded ZERO
//	                                   times and the statement stayed one node.
//	family inet filter input f1;       TWO links needed. (inet, filter) was
//	                                   ALREADY admitted, the pass folded ONCE to
//	                                   `family inet` + `filter input f1`, and
//	                                   then stopped: (filter, input) was not in.
//
// The filter half had a scope entry that fired and delivered nothing. That is
// the shape worth naming -- an admitted pair reads as coverage.
//
// THE INSTRUMENT IS THREE-WAY AND THE ASSERTIONS ARE ABSOLUTE. A packed-vs-
// braced comparison goes green whenever BOTH spellings drop the value, which is
// exactly this defect's shape, so every case also compiles a BASELINE with the
// statement removed and asserts the COMPILED FIELD rather than a relation:
// FilterInputV4 == "f1", Addresses == ["10.0.0.1/24"].
type unitCase8755 struct {
	name     string
	braced   string
	packed   string
	baseline string
	check    func(*InterfaceUnit) error
	// wantFoldsBefore is what the pass did to the packed spelling BEFORE this
	// change: 0 for the address half (no link), 1 for the filter half (the
	// first link fired and left the binding unreached).
	wantFoldsAfter int
}

const filterDefs8755 = "firewall {\n family inet {\n  filter f1 {\n   term t1 { from { protocol tcp; } then { accept; } }\n  }\n }\n family inet6 {\n  filter f6 {\n   term t1 { from { next-header tcp; } then { accept; } }\n  }\n }\n}\n"

func unitText8755(inner string) string {
	return filterDefs8755 + "interfaces {\n ge-0-0-0 {\n  unit 0 {\n" + inner + "\n  }\n }\n}\n"
}

func unitOf8755(cfg *Config) (*InterfaceUnit, error) {
	if cfg == nil {
		return nil, errf8755("nil config")
	}
	ifc := cfg.Interfaces.Interfaces["ge-0-0-0"]
	if ifc == nil {
		return nil, errf8755("interface ge-0-0-0 absent from the compiled config")
	}
	for _, u := range ifc.Units {
		if u != nil && u.Number == 0 {
			return u, nil
		}
	}
	return nil, errf8755("interface ge-0-0-0 unit 0 absent from the compiled config")
}

func errf8755(s string) error { return &strErr8755{s} }

type strErr8755 struct{ s string }

func (e *strErr8755) Error() string { return e.s }

func compileUnit8755(t *testing.T, text string, skipNormalize bool) (*InterfaceUnit, error) {
	t.Helper()
	tree, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		return nil, errf8755("parse error")
	}
	cfg, err := compileConfigWithOpts(tree, compileOpts{skipCompactNormalize: skipNormalize})
	if err != nil {
		return nil, err
	}
	return unitOf8755(cfg)
}

func unitCases8755() []unitCase8755 {
	return []unitCase8755{
		{
			name:     "family inet address",
			braced:   unitText8755("   family inet {\n    address 10.0.0.1/24;\n   }"),
			packed:   unitText8755("   family inet address 10.0.0.1/24;"),
			baseline: unitText8755("   family inet {\n   }"),
			check: func(u *InterfaceUnit) error {
				if !reflect.DeepEqual(u.Addresses, []string{"10.0.0.1/24"}) {
					return errf8755("Addresses = " + sprint8755(u.Addresses) + `, want ["10.0.0.1/24"]`)
				}
				return nil
			},
			wantFoldsAfter: 1,
		},
		{
			name:     "family inet6 address",
			braced:   unitText8755("   family inet6 {\n    address 2001:db8::1/64;\n   }"),
			packed:   unitText8755("   family inet6 address 2001:db8::1/64;"),
			baseline: unitText8755("   family inet6 {\n   }"),
			check: func(u *InterfaceUnit) error {
				if !reflect.DeepEqual(u.Addresses, []string{"2001:db8::1/64"}) {
					return errf8755("Addresses = " + sprint8755(u.Addresses) + `, want ["2001:db8::1/64"]`)
				}
				return nil
			},
			wantFoldsAfter: 1,
		},
		{
			name:     "family inet filter input -- the fail-open",
			braced:   unitText8755("   family inet {\n    filter { input f1; }\n   }"),
			packed:   unitText8755("   family inet filter input f1;"),
			baseline: unitText8755("   family inet {\n   }"),
			check: func(u *InterfaceUnit) error {
				if u.FilterInputV4 != "f1" {
					return errf8755("FilterInputV4 = " + u.FilterInputV4 + `, want "f1" -- the interface commits with NO filter applied`)
				}
				if u.FilterOutputV4 != "" {
					return errf8755("FilterOutputV4 = " + u.FilterOutputV4 + ", want empty -- an input filter landed on the output hook")
				}
				return nil
			},
			wantFoldsAfter: 2,
		},
		{
			name:     "family inet filter output",
			braced:   unitText8755("   family inet {\n    filter { output f1; }\n   }"),
			packed:   unitText8755("   family inet filter output f1;"),
			baseline: unitText8755("   family inet {\n   }"),
			check: func(u *InterfaceUnit) error {
				if u.FilterOutputV4 != "f1" {
					return errf8755("FilterOutputV4 = " + u.FilterOutputV4 + `, want "f1"`)
				}
				if u.FilterInputV4 != "" {
					return errf8755("FilterInputV4 = " + u.FilterInputV4 + ", want empty -- an output filter landed on the input hook")
				}
				return nil
			},
			wantFoldsAfter: 2,
		},
		{
			name:     "family inet6 filter input",
			braced:   unitText8755("   family inet6 {\n    filter { input f6; }\n   }"),
			packed:   unitText8755("   family inet6 filter input f6;"),
			baseline: unitText8755("   family inet6 {\n   }"),
			check: func(u *InterfaceUnit) error {
				if u.FilterInputV6 != "f6" {
					return errf8755("FilterInputV6 = " + u.FilterInputV6 + `, want "f6"`)
				}
				if u.FilterInputV4 != "" {
					return errf8755("FilterInputV4 = " + u.FilterInputV4 + ", want empty -- an inet6 filter landed on the inet hook")
				}
				return nil
			},
			wantFoldsAfter: 2,
		},
	}
}

func sprint8755(v []string) string {
	s := "["
	for i, x := range v {
		if i > 0 {
			s += " "
		}
		s += x
	}
	return s + "]"
}

func TestElidedInterfaceUnitKeepsItsAddressAndFilter8755(t *testing.T) {
	for _, c := range unitCases8755() {
		c := c
		t.Run(c.name, func(t *testing.T) {
			// The BASELINE leg. If the braced spelling compiles the same as the
			// statement being absent, the braced form delivers nothing and there
			// is no verdict to draw about the packed one -- an agreement check
			// would have reported success here.
			bu, err := compileUnit8755(t, c.baseline, false)
			if err != nil {
				t.Fatalf("baseline: %v", err)
			}
			if c.check(bu) == nil {
				t.Fatalf("the BASELINE (statement removed) already satisfies the expectation, so this " +
					"case cannot distinguish a delivered value from a default. Fixture is wrong, not the pass.")
			}
			br, err := compileUnit8755(t, c.braced, false)
			if err != nil {
				t.Fatalf("braced: %v", err)
			}
			if err := c.check(br); err != nil {
				t.Fatalf("BRACED reference does not deliver: %v -- with the reference broken nothing "+
					"below is a verdict about the elided spelling", err)
			}
			pk, err := compileUnit8755(t, c.packed, false)
			if err != nil {
				t.Fatalf("packed: %v", err)
			}
			if err := c.check(pk); err != nil {
				t.Errorf("the BRACE-ELIDED spelling does not deliver: %v\n"+
					"This is the #8755 silent loss: the commit reports success with zero warnings and "+
					"the interface runs without what was authored. On a filter that is a FAIL-OPEN, and "+
					"it emits FEWER warnings than the correct spelling because nothing is left to warn "+
					"about. Do not relax this expectation to make it green.", err)
			}
			// The fold count is recorded because a green above with zero folds
			// would mean the compiler started reading the packed tail directly
			// and this scope entry became decorative.
			tree, _ := NewParser(c.packed).Parse()
			if got := normalizeCompactStanzas(tree); got != c.wantFoldsAfter {
				t.Errorf("folds = %d, want %d. The chain length changed: this pair's admission is "+
					"either no longer needed or no longer sufficient, and either way the note in "+
					"compact_normalize_8662.go is now describing something else (#8755).",
					got, c.wantFoldsAfter)
			}
		})
	}
}

// The two symptoms need DIFFERENT NUMBERS OF CHAIN LINKS, which is the finding
// most likely to be flattened back into "one defect" by a later reader.
//
// It is measured against the scope as it stood BEFORE this change -- production
// minus the four pairs added for #8755 -- so the claim is about what the fix
// did, not about a hypothetical predicate.
func TestTheTwoSymptomsNeedDifferentChainLengths8755(t *testing.T) {
	added := map[string]bool{
		"inet address": true, "inet6 address": true,
		"filter input": true, "filter output": true,
	}
	scopeBefore := func(kw, head string) bool {
		if added[kw+" "+head] {
			return false
		}
		return compactNormalizeInScope(kw, head)
	}
	foldsWith := func(text string, scope func(string, string) bool) (int, *InterfaceUnit) {
		tree, _ := NewParser(text).Parse()
		n := normalizeCompactStanzasWithScope(tree, scope)
		cfg, err := compileConfigWithOpts(tree, compileOpts{skipCompactNormalize: true})
		if err != nil || cfg == nil {
			return n, nil
		}
		u, _ := unitOf8755(cfg)
		return n, u
	}
	for _, tc := range []struct {
		name                    string
		text                    string
		foldsBefore, foldsAfter int
		delivered               func(*InterfaceUnit) bool
		why                     string
	}{
		{
			name: "address needs ONE link, and it was not admitted at all",
			text: unitText8755("   family inet address 10.0.0.1/24;"),
			// Nothing was admitted, so the pass never touched the statement --
			// it stayed a single node `family inet address 10.0.0.1/24`.
			foldsBefore: 0, foldsAfter: 1,
			delivered: func(u *InterfaceUnit) bool { return u != nil && len(u.Addresses) == 1 },
			why:       "(inet, address) was unadmitted, so the pass folded nothing",
		},
		{
			name: "filter needs TWO links, and the first was ALREADY admitted",
			text: unitText8755("   family inet filter input f1;"),
			// (inet, filter) was in scope, so the pass DID fire -- and left
			// `filter input f1` packed, because (filter, input) was not. A scope
			// entry that fires and delivers nothing reads as coverage.
			foldsBefore: 1, foldsAfter: 2,
			delivered: func(u *InterfaceUnit) bool { return u != nil && u.FilterInputV4 == "f1" },
			why:       "(inet, filter) fired and (filter, input) did not, so the binding stayed unreached",
		},
	} {
		nBefore, uBefore := foldsWith(tc.text, scopeBefore)
		nAfter, uAfter := foldsWith(tc.text, compactNormalizeInScope)
		if nBefore != tc.foldsBefore || nAfter != tc.foldsAfter {
			t.Errorf("%s: folds before=%d after=%d, want %d/%d", tc.name, nBefore, nAfter, tc.foldsBefore, tc.foldsAfter)
		}
		if tc.delivered(uBefore) {
			t.Errorf("%s: the value was ALREADY delivered under the pre-#8755 scope, so this case is "+
				"not measuring the fix -- something else started reading the packed tail", tc.name)
		}
		if !tc.delivered(uAfter) {
			t.Errorf("%s: the value is STILL not delivered with the new scope entries in place", tc.name)
		}
		t.Logf("%-56s folds %d -> %d   %s", tc.name, nBefore, nAfter, tc.why)
	}
}
