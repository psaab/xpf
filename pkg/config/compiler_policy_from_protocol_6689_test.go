package config

import (
	"strings"
	"testing"
)

// #6689: `from { protocol { bgp; ospf; static; } }` compiled to [bgp] alone.
// The protocol reader followed a single-child CHAIN (Children[0] at each
// level), and the nested-block spelling files one leaf child per protocol as
// SIBLINGS, so only the first was ever reached.
//
// This fails OPEN. With `then reject` the operator's intent is to filter BGP,
// OSPF and static; the compiled policy filtered BGP alone, so the OSPF and
// static routes meant to be excluded were accepted and installed. The authored
// config renders back intact, so there is no diagnostic.

func policyProtocolsFromBlock(t *testing.T, body string) []string {
	t.Helper()
	p := NewParser(body)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse %q: %v", body, errs)
	}
	return policyProtocolsOf(t, tree)
}

// policyProtocolsFromSet drives the flat-set path the way CLAUDE.md requires:
// ParseSetCommand + SetPath, never NewParser.
func policyProtocolsFromSet(t *testing.T, cmds ...string) []string {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return policyProtocolsOf(t, tree)
}

func policyProtocolsOf(t *testing.T, tree *ConfigTree) []string {
	t.Helper()
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	ps := cfg.PolicyOptions.PolicyStatements["p1"]
	if ps == nil {
		t.Fatal("policy-statement p1 absent from compiled config")
	}
	var got []string
	for _, term := range ps.Terms {
		got = append(got, term.FromProtocols...)
	}
	return got
}

func assertProtocols6689(t *testing.T, spelling string, got, want []string) {
	t.Helper()
	if len(got) != len(want) || strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("%s: FromProtocols = %v, want %v", spelling, got, want)
	}
}

// Test_6689_FromProtocolEveryHierarchicalSpelling covers the brace-parsed
// spellings. The nested block is the one that dropped two of three.
func Test_6689_FromProtocolEveryHierarchicalSpelling(t *testing.T) {
	want := []string{"bgp", "ospf", "static"}

	assertProtocols6689(t, "nested block `protocol { bgp; ospf; static; }`",
		policyProtocolsFromBlock(t,
			`policy-options { policy-statement p1 { term t1 { from { protocol { bgp; ospf; static; } } then reject; } } }`),
		want)

	assertProtocols6689(t, "bracket list `protocol [ bgp ospf static ];`",
		policyProtocolsFromBlock(t,
			`policy-options { policy-statement p1 { term t1 { from { protocol [ bgp ospf static ]; } then reject; } } }`),
		want)

	assertProtocols6689(t, "repeated `protocol bgp; protocol ospf; protocol static;`",
		policyProtocolsFromBlock(t,
			`policy-options { policy-statement p1 { term t1 { from { protocol bgp; protocol ospf; protocol static; } then reject; } } }`),
		want)
}

// Test_6689_FromProtocolEveryFlatSetSpelling pins the flat-set spellings that
// already worked, so the fold cannot regress them.
func Test_6689_FromProtocolEveryFlatSetSpelling(t *testing.T) {
	want := []string{"bgp", "ospf", "static"}

	assertProtocols6689(t, "flat-set bracket list",
		policyProtocolsFromSet(t,
			"set policy-options policy-statement p1 term t1 from protocol [ bgp ospf static ]",
			"set policy-options policy-statement p1 term t1 then reject"),
		want)

	assertProtocols6689(t, "flat-set repeated",
		policyProtocolsFromSet(t,
			"set policy-options policy-statement p1 term t1 from protocol bgp",
			"set policy-options policy-statement p1 term t1 from protocol ospf",
			"set policy-options policy-statement p1 term t1 from protocol static",
			"set policy-options policy-statement p1 term t1 then reject"),
		want)
}

// Test_6689_FromProtocolSpellingsAgree binds the AGREEMENT rather than one
// spelling's value: whatever the compiler makes of a protocol list, every
// spelling of that same list must make the same thing of it. That is the
// property the defect violated — four spellings compiled all three protocols
// while the fifth compiled one — and it is what keeps a future reader of one
// shape from drifting from the others.
func Test_6689_FromProtocolSpellingsAgree(t *testing.T) {
	nested := policyProtocolsFromBlock(t,
		`policy-options { policy-statement p1 { term t1 { from { protocol { bgp; ospf; static; } } then reject; } } }`)
	bracket := policyProtocolsFromBlock(t,
		`policy-options { policy-statement p1 { term t1 { from { protocol [ bgp ospf static ]; } then reject; } } }`)
	flat := policyProtocolsFromSet(t,
		"set policy-options policy-statement p1 term t1 from protocol [ bgp ospf static ]",
		"set policy-options policy-statement p1 term t1 then reject")

	if strings.Join(nested, ",") != strings.Join(bracket, ",") {
		t.Errorf("nested block %v disagrees with hierarchical bracket %v", nested, bracket)
	}
	if strings.Join(nested, ",") != strings.Join(flat, ",") {
		t.Errorf("nested block %v disagrees with flat-set bracket %v", nested, flat)
	}
}

// Test_6689_FromProtocolTwoTermsStayDistinct guards the descent from
// over-collecting: `protocol` nodes in different terms must not bleed into one
// another, and a term with no `from protocol` must compile an empty list.
func Test_6689_FromProtocolTwoTermsStayDistinct(t *testing.T) {
	p := NewParser(`policy-options { policy-statement p1 {
		term t1 { from { protocol { bgp; ospf; } } then reject; }
		term t2 { from { protocol { static; } } then accept; }
		term t3 { then accept; }
	} }`)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	ps := cfg.PolicyOptions.PolicyStatements["p1"]
	if ps == nil {
		t.Fatal("policy-statement p1 absent")
	}
	byName := map[string][]string{}
	for _, term := range ps.Terms {
		byName[term.Name] = term.FromProtocols
	}
	assertProtocols6689(t, "term t1", byName["t1"], []string{"bgp", "ospf"})
	assertProtocols6689(t, "term t2", byName["t2"], []string{"static"})
	if len(byName["t3"]) != 0 {
		t.Errorf("term t3: FromProtocols = %v, want empty", byName["t3"])
	}
}
