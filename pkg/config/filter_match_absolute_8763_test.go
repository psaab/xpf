package config

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// #8763 follow-up: the ten SECURITY-relevant leaves of the family-only set,
// asserted as ABSOLUTE OUTCOMES and measured in BOTH AST shapes.
//
// TWO THINGS THIS DOES THAT THE LANDING CELL DOES NOT.
//
// 1. IT ASSERTS THE VALUE, not a relation between spellings. The landing cell
// compares packed against braced against a baseline, which proves the fold
// changes the compiled config in the same way the braced spelling does. That
// cannot see a value the compiler reads and then places WRONGLY -- both
// spellings would move together and the comparison stays green. `then next` is
// the live example: it is undeclared, so both spellings leave Action empty and
// an agreement check passes on a term that does nothing. Here the expected
// compiled field is written out, and every OTHER match field must stay empty,
// so a value landing in the wrong place reds.
//
// 2. IT WALKS THE FLAT `set` SHAPE TOO. The landing measurement used NewParser
// only. The two shapes are not interchangeable: flat `set` groups tokens into a
// CHAIN of single-key nodes, so a leaf can end up a CHILD of its sibling rather
// than beside it, and a reader that walks one level never sees it. That is what
// made #8778's first fix look complete when it was not. A verdict that does not
// name the shape it walked is only half a verdict.
//
// The negative half matters as much as the positive one: a firewall term that
// matches MORE than it was authored to match is a fail-open, and the two that
// landed today (#8778 `snmp community clients` -> allow-all, #8781
// `from next-header` -> a term matching every protocol) were both of that shape.
type absCase8763 struct {
	name   string
	body   string // the `from`/`then` statement, brace-elided
	braced string // the same statement, braced
	flat   string // the same statement as a flat `set` line suffix
	// prereq is a statement the GATE requires alongside the one under
	// measurement -- `icmp-code` is refused without an `icmp-type`. It is held
	// BRACED and identical across all three legs, so it never varies with the
	// spelling being measured.
	prereqHier string
	prereqFlat string
	check      func(*FirewallFilterTerm) error
}

func termOf8763(cfg *Config) (*FirewallFilterTerm, error) {
	if cfg == nil {
		return nil, fmt.Errorf("nil config")
	}
	f := cfg.Firewall.FiltersInet["f1"]
	if f == nil {
		return nil, fmt.Errorf("filter f1 absent from the compiled config")
	}
	if len(f.Terms) != 1 {
		return nil, fmt.Errorf("filter f1 has %d terms, want 1", len(f.Terms))
	}
	return f.Terms[0], nil
}

// noOtherMatchFields reports any match field that is populated other than the
// ones named. It is the "and not what it should not" half.
func noOtherMatchFields(tr *FirewallFilterTerm, allowed ...string) error {
	ok := map[string]bool{}
	for _, a := range allowed {
		ok[a] = true
	}
	populated := map[string]bool{
		"SourceAddresses":   len(tr.SourceAddresses) > 0,
		"DestAddresses":     len(tr.DestAddresses) > 0,
		"DSCPs":             len(tr.DSCPs) > 0,
		"Protocols":         len(tr.Protocols) > 0,
		"DestinationPorts":  len(tr.DestinationPorts) > 0,
		"SourcePorts":       len(tr.SourcePorts) > 0,
		"SourcePortsExcept": len(tr.SourcePortsExcept) > 0,
		"DestPortsExcept":   len(tr.DestPortsExcept) > 0,
		"ICMPTypes":         len(tr.ICMPTypes) > 0,
		"ICMPCodes":         len(tr.ICMPCodes) > 0,
		"TCPFlags":          len(tr.TCPFlags) > 0,
		"RoutingInstance":   tr.RoutingInstance != "",
		"ForwardingClass":   tr.ForwardingClass != "",
		"Policer":           tr.Policer != "",
	}
	var extra []string
	for f, on := range populated {
		if on && !ok[f] {
			extra = append(extra, f)
		}
	}
	if len(extra) > 0 {
		return fmt.Errorf("unexpected populated field(s) %v -- the term matches more than it was authored to match", extra)
	}
	// Nothing may be silently bucketed as unrecognised either.
	for name, got := range map[string][]string{
		"UnknownFrom":      tr.UnknownFrom,
		"ValuelessFrom":    tr.ValuelessFrom, // #9875: same unplaced-value census
		"UnknownAddresses": tr.UnknownAddresses,
		"UnknownPorts":     tr.UnknownPorts,
		"UnknownICMPTypes": tr.UnknownICMPTypes,
		"UnknownICMPCodes": tr.UnknownICMPCodes,
		"UnknownActions":   tr.UnknownActions,
	} {
		if len(got) > 0 {
			return fmt.Errorf("%s = %v -- the value was accepted at commit and then not placed", name, got)
		}
	}
	return nil
}

func eqStrs8763(field string, got, want []string) error {
	if !reflect.DeepEqual(got, want) {
		return fmt.Errorf("%s = %v, want %v", field, got, want)
	}
	return nil
}

func absCases8763() []absCase8763 {
	return []absCase8763{
		{name: "from source-address", body: "from source-address 198.51.100.77/32;", braced: "from { source-address 198.51.100.77/32; }", flat: "from source-address 198.51.100.77/32",
			check: func(tr *FirewallFilterTerm) error {
				if err := eqStrs8763("SourceAddresses", tr.SourceAddresses, []string{"198.51.100.77/32"}); err != nil {
					return err
				}
				return noOtherMatchFields(tr, "SourceAddresses")
			}},
		{name: "from destination-address", body: "from destination-address 203.0.113.77/32;", braced: "from { destination-address 203.0.113.77/32; }", flat: "from destination-address 203.0.113.77/32",
			check: func(tr *FirewallFilterTerm) error {
				if err := eqStrs8763("DestAddresses", tr.DestAddresses, []string{"203.0.113.77/32"}); err != nil {
					return err
				}
				return noOtherMatchFields(tr, "DestAddresses")
			}},
		{name: "from source-port", body: "from source-port 51479;", braced: "from { source-port 51479; }", flat: "from source-port 51479",
			check: func(tr *FirewallFilterTerm) error {
				if err := eqStrs8763("SourcePorts", tr.SourcePorts, []string{"51479"}); err != nil {
					return err
				}
				return noOtherMatchFields(tr, "SourcePorts")
			}},
		{name: "from destination-port", body: "from destination-port 51477;", braced: "from { destination-port 51477; }", flat: "from destination-port 51477",
			check: func(tr *FirewallFilterTerm) error {
				if err := eqStrs8763("DestinationPorts", tr.DestinationPorts, []string{"51477"}); err != nil {
					return err
				}
				return noOtherMatchFields(tr, "DestinationPorts")
			}},
		{name: "from tcp-flags", body: "from tcp-flags syn;", braced: "from { tcp-flags syn; }", flat: "from tcp-flags syn",
			check: func(tr *FirewallFilterTerm) error {
				if err := eqStrs8763("TCPFlags", tr.TCPFlags, []string{"syn"}); err != nil {
					return err
				}
				return noOtherMatchFields(tr, "TCPFlags")
			}},
		{name: "from icmp-type", body: "from icmp-type 13;", braced: "from { icmp-type 13; }", flat: "from icmp-type 13",
			check: func(tr *FirewallFilterTerm) error {
				if !reflect.DeepEqual(tr.ICMPTypes, []int{13}) {
					return fmt.Errorf("ICMPTypes = %v, want [13]", tr.ICMPTypes)
				}
				return noOtherMatchFields(tr, "ICMPTypes")
			}},
		{name: "from icmp-code", body: "from icmp-code 7;", braced: "from { icmp-code 7; }", flat: "from icmp-code 7",
			// The gate refuses a code without a type ("an ICMP code is
			// meaningful only together with a type"), so the type is a
			// prerequisite rather than part of what is measured.
			prereqHier: "from { icmp-type 3; }", prereqFlat: "from icmp-type 3",
			check: func(tr *FirewallFilterTerm) error {
				if !reflect.DeepEqual(tr.ICMPCodes, []int{7}) {
					return fmt.Errorf("ICMPCodes = %v, want [7]", tr.ICMPCodes)
				}
				if !reflect.DeepEqual(tr.ICMPTypes, []int{3}) {
					return fmt.Errorf("ICMPTypes = %v, want [3] (the prerequisite)", tr.ICMPTypes)
				}
				return noOtherMatchFields(tr, "ICMPCodes", "ICMPTypes")
			}},
		{name: "then policer", body: "then policer polprobe77;", braced: "then { policer polprobe77; }", flat: "then policer polprobe77",
			check: func(tr *FirewallFilterTerm) error {
				if tr.Policer != "polprobe77" {
					return fmt.Errorf("Policer = %q, want %q", tr.Policer, "polprobe77")
				}
				return noOtherMatchFields(tr, "Policer")
			}},
		{name: "then forwarding-class", body: "then forwarding-class fcprobe77;", braced: "then { forwarding-class fcprobe77; }", flat: "then forwarding-class fcprobe77",
			check: func(tr *FirewallFilterTerm) error {
				if tr.ForwardingClass != "fcprobe77" {
					return fmt.Errorf("ForwardingClass = %q, want %q", tr.ForwardingClass, "fcprobe77")
				}
				return noOtherMatchFields(tr, "ForwardingClass")
			}},
		{name: "then routing-instance", body: "then routing-instance riprobe77;", braced: "then { routing-instance riprobe77; }", flat: "then routing-instance riprobe77",
			check: func(tr *FirewallFilterTerm) error {
				if tr.RoutingInstance != "riprobe77" {
					return fmt.Errorf("RoutingInstance = %q, want %q", tr.RoutingInstance, "riprobe77")
				}
				return noOtherMatchFields(tr, "RoutingInstance")
			}},
	}
}

const absPreamble8763 = "class-of-service {\n forwarding-classes {\n  class fcprobe77 queue-num 3;\n }\n}\n" +
	"routing-instances {\n riprobe77 {\n  instance-type virtual-router;\n }\n}\n" +
	"firewall {\n policer polprobe77 {\n  if-exceeding { bandwidth-limit 10m; burst-size-limit 1500; }\n  then { discard; }\n }\n}\n"

// hierarchical builds the BRACED compound-key shape an operator writes:
// `firewall { family inet { filter f1 { term t1 { … } } } }`.
func absHier8763(prereq, stmt string) string {
	body := stmt
	if prereq != "" {
		body = prereq + "\n    " + stmt
	}
	return absPreamble8763 + "firewall {\n family inet {\n  filter f1 {\n   term t1 {\n    " + body + "\n   }\n  }\n }\n}\n"
}

// absFlat8763 builds the SAME configuration through ParseSetCommand + SetPath.
// NewParser must not be used for flat-set text: it treats newlines as
// whitespace and merges every line into one node, which silently turns the
// measurement into a statement about a tree nobody has.
func absFlat8763(t *testing.T, prereq, stmtSuffix string) *ConfigTree {
	t.Helper()
	lines := []string{
		"set class-of-service forwarding-classes class fcprobe77 queue-num 3",
		"set routing-instances riprobe77 instance-type virtual-router",
		"set firewall policer polprobe77 if-exceeding bandwidth-limit 10m",
		"set firewall policer polprobe77 if-exceeding burst-size-limit 1500",
		"set firewall policer polprobe77 then discard",
		"set firewall family inet filter f1 term t1 " + stmtSuffix,
	}
	if prereq != "" {
		lines = append(lines, "set firewall family inet filter f1 term t1 "+prereq)
	}
	tree := &ConfigTree{}
	for _, l := range lines {
		path, err := ParseSetCommand(l)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", l, err)
		}
		tree.SetPath(path)
	}
	return tree
}

func compileTree8763(tree *ConfigTree, skipNormalize bool) (*Config, error) {
	return compileConfigWithOpts(tree, compileOpts{skipCompactNormalize: skipNormalize})
}

func TestSecurityMatchLeavesLandTheAuthoredValue8763(t *testing.T) {
	for _, c := range absCases8763() {
		c := c
		t.Run(c.name, func(t *testing.T) {
			// Three spellings, one expectation. Each is compiled with the pass
			// ON, which is production; the packed one is ALSO compiled with it
			// off, to record whether the pass is what delivers the value.
			type leg struct {
				label string
				tree  *ConfigTree
				skip  bool
			}
			mk := func(text string) *ConfigTree {
				tr, perrs := NewParser(text).Parse()
				if len(perrs) > 0 {
					t.Fatalf("parse: %v", perrs)
				}
				return tr
			}
			legs := []leg{
				{"hierarchical BRACED", mk(absHier8763(c.prereqHier, c.braced)), false},
				{"hierarchical PACKED", mk(absHier8763(c.prereqHier, c.body)), false},
				{"flat set", absFlat8763(t, c.prereqFlat, c.flat), false},
			}
			for _, l := range legs {
				cfg, err := compileTree8763(l.tree, l.skip)
				if err != nil {
					t.Fatalf("%s: compile: %v", l.label, err)
				}
				tr, err := termOf8763(cfg)
				if err != nil {
					t.Fatalf("%s: %v", l.label, err)
				}
				if err := c.check(tr); err != nil {
					t.Errorf("%s: %v\n"+
						"This leaf is part of a firewall term. A field that is empty when it should "+
						"hold a value makes the term match MORE than authored, which on an `accept` "+
						"term is a fail-open; a value in the WRONG field is the same defect wearing a "+
						"populated struct. Do not satisfy this by relaxing the expectation (#8763).",
						l.label, err)
				}
			}
			// Record whether the packed spelling needs the pass at all. This is
			// evidence about the fold, kept separate from the assertions above
			// so a change in it cannot quietly weaken them.
			off, errOff := compileTree8763(mk(absHier8763(c.prereqHier, c.body)), true)
			state := "delivers WITHOUT the pass (the packed tail is read directly)"
			if errOff != nil {
				state = "rejected with the pass off"
			} else if tr, err := termOf8763(off); err != nil || c.check(tr) != nil {
				state = "needs the pass: dropped when the fold is disabled"
			}
			t.Logf("%-24s %s", c.name, state)
		})
	}
}

// The flat-set leg is only evidence if the flat tree is actually SHAPED
// differently from the hierarchical one. If SetPath happened to produce the
// same node layout, running both would be one measurement reported twice --
// the "two independent confirmations sharing one premise are one" trap.
func TestFlatAndHierarchicalTreesReallyDiffer8763(t *testing.T) {
	flat := absFlat8763(t, "", "from source-address 198.51.100.77/32")
	hier, perrs := NewParser(absHier8763("", "from source-address 198.51.100.77/32;")).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	fs, hs := shape8763(flat.Children, 0), shape8763(hier.Children, 0)
	if fs == hs {
		t.Errorf("the flat and hierarchical trees have IDENTICAL shape, so the flat leg in "+
			"TestSecurityMatchLeavesLandTheAuthoredValue8763 is not a second measurement:\n%s", fs)
	}
	t.Logf("flat-set shape:\n%s", fs)
	t.Logf("hierarchical shape:\n%s", hs)
}

func shape8763(nodes []*Node, depth int) string {
	var b strings.Builder
	for _, n := range nodes {
		if n == nil {
			continue
		}
		b.WriteString(strings.Repeat("  ", depth))
		b.WriteString(strings.Join(n.Keys, " "))
		b.WriteString("\n")
		b.WriteString(shape8763(n.Children, depth+1))
	}
	return b.String()
}

// noOtherMatchFields decides the "and not what it should not" half, and against
// the ten cases above its failure arms NEVER EXECUTE -- every one of them
// populates exactly the fields it names, so a mutation that neutered this
// function would leave all ten green. A guard's arithmetic cannot be tested by
// data that never reaches the branch, so it is exercised here against terms
// built to reach it.
func TestNoOtherMatchFieldsCatchesTheOverMatch8763(t *testing.T) {
	for _, tc := range []struct {
		name    string
		term    *FirewallFilterTerm
		allowed []string
		wantErr string
	}{
		{"exactly what was authored", &FirewallFilterTerm{SourceAddresses: []string{"a"}}, []string{"SourceAddresses"}, ""},
		{"a SECOND match field populated -- the term matches more than authored",
			&FirewallFilterTerm{SourceAddresses: []string{"a"}, Protocols: []string{"tcp"}}, []string{"SourceAddresses"}, "Protocols"},
		{"the value landed in the WRONG field",
			&FirewallFilterTerm{DestAddresses: []string{"a"}}, []string{"SourceAddresses"}, "DestAddresses"},
		{"an action field leaked in", &FirewallFilterTerm{Policer: "p"}, []string{"SourceAddresses"}, "Policer"},
		{"accepted at commit then bucketed as unrecognised",
			&FirewallFilterTerm{SourceAddresses: []string{"a"}, UnknownFrom: []string{"ttl"}}, []string{"SourceAddresses"}, "UnknownFrom"},
		{"accepted at commit then bucketed as valueless (#9875)",
			&FirewallFilterTerm{SourceAddresses: []string{"a"}, ValuelessFrom: []string{"protocol"}}, []string{"SourceAddresses"}, "ValuelessFrom"},
		{"an empty slice is not populated", &FirewallFilterTerm{SourceAddresses: []string{"a"}, Protocols: []string{}}, []string{"SourceAddresses"}, ""},
	} {
		err := noOtherMatchFields(tc.term, tc.allowed...)
		switch {
		case tc.wantErr == "" && err != nil:
			t.Errorf("%s: unexpected error %v", tc.name, err)
		case tc.wantErr != "" && err == nil:
			t.Errorf("%s: expected an error naming %q, got none -- the over-match arm did not fire",
				tc.name, tc.wantErr)
		case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
			t.Errorf("%s: error %q does not name %q; a mutation caught by the WRONG arm reads as a "+
				"working guard", tc.name, err, tc.wantErr)
		}
	}
}

// The three legs are the measurement. If one is dropped the cell keeps passing
// with less coverage and nothing says so, which is how a shape-specific defect
// (#8778: flat `set` nests a leaf UNDER its sibling, so a one-level reader never
// sees it) survives a green suite.
func TestSecurityLeavesAreMeasuredInBothASTShapes8763(t *testing.T) {
	const want = 3
	c := absCases8763()[0]
	legs := []string{"hierarchical BRACED", "hierarchical PACKED", "flat set"}
	if len(legs) != want {
		t.Fatalf("leg count changed")
	}
	// prove each leg really compiles something distinct rather than being a label
	seen := map[string]bool{}
	for _, txt := range []string{absHier8763(c.prereqHier, c.braced), absHier8763(c.prereqHier, c.body)} {
		seen[txt] = true
	}
	if len(seen) != 2 {
		t.Error("the braced and packed hierarchical legs are the same text, so one of them is not a measurement")
	}
	if got := shape8763(absFlat8763(t, c.prereqFlat, c.flat).Children, 0); got == "" {
		t.Error("the flat-set leg built an empty tree: ParseSetCommand/SetPath produced nothing")
	}
}
