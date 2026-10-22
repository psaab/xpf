package config

import (
	"reflect"
	"testing"
)

// #6684 / #6685: a stanza body written PACKED onto one line must compile
// identically to the same body written NESTED.
//
// The tests below assert EQUALITY of the two compiled results rather than
// checking the packed form against a hand-written expectation. That is the
// property the issues actually ask for ("compiles identically to the nested
// spelling"), and it cannot drift: if someone changes what the nested form
// compiles to, the packed form has to move with it or the test reds.
//
// Both defects were silent and both failed in the security-relevant direction —
// a syslog host with ZERO facilities ships nothing, a filter term with an EMPTY
// action does not discard — while the instance itself survived, so
// `show configuration` displayed exactly what the operator wrote.

func compileBraced6684(t *testing.T, src string) *Config {
	t.Helper()
	tree, perrs := NewParser(src).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse %q: %v", src, perrs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile %q: %v", src, err)
	}
	return cfg
}

func TestPackedSyslogHostBodyMatchesNested_6684(t *testing.T) {
	cases := []struct{ name, nested, packed string }{
		{
			"facility severity pair",
			`system { syslog { host 10.0.0.1 { any any; } } }`,
			`system { syslog { host 10.0.0.1 any any; } }`,
		},
		{
			"a specific facility and severity",
			`system { syslog { host 10.0.0.1 { authorization info; } } }`,
			`system { syslog { host 10.0.0.1 authorization info; } }`,
		},
		{
			"source-address modifier",
			`system { syslog { host 10.0.0.1 { source-address 10.9.9.9; } } }`,
			`system { syslog { host 10.0.0.1 source-address 10.9.9.9; } }`,
		},
		{
			"port modifier",
			`system { syslog { host 10.0.0.1 { port 5514; } } }`,
			`system { syslog { host 10.0.0.1 port 5514; } }`,
		},
		{
			"allow-duplicates flag",
			`system { syslog { host 10.0.0.1 { allow-duplicates; } } }`,
			`system { syslog { host 10.0.0.1 allow-duplicates; } }`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nested := compileBraced6684(t, tc.nested).System.Syslog.Hosts
			packed := compileBraced6684(t, tc.packed).System.Syslog.Hosts

			// Anti-vacuity: if the NESTED spelling compiled nothing, the
			// equality below would hold for two empty results and prove
			// nothing at all.
			if len(nested) != 1 {
				t.Fatalf("nested spelling compiled %d hosts, want 1 — the fixture is not exercising the stanza", len(nested))
			}
			if !reflect.DeepEqual(nested, packed) {
				t.Errorf("packed body compiled differently from nested (#6684)\n nested = %+v\n packed = %+v",
					*nested[0], hostsOrNil6684(packed))
			}
		})
	}
}

func hostsOrNil6684(hosts []*SyslogHostConfig) any {
	if len(hosts) == 0 {
		return "<no hosts>"
	}
	return *hosts[0]
}

func TestPackedFilterTermBodyMatchesNested_6685(t *testing.T) {
	// Every terminal action, plus the argument-bearing `then` modifiers the
	// issue calls out — an expansion that split the tail on whitespace would
	// get `forwarding-class be` and `count c1` wrong while still passing for
	// the bare `discard` the issue happens to name.
	cases := []struct{ name, body string }{
		{"discard", `then discard`},
		{"accept", `then accept`},
		{"reject", `then reject`},
		{"count with an argument", `then count c1`},
		{"forwarding-class with an argument", `then forwarding-class be`},
		{"dscp with an argument", `then dscp 46`},
		{"log", `then log`},
		{"a from condition, not a then action", `from protocol tcp`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nestedSrc := `firewall { family inet { filter f1 { term t1 { ` + tc.body + `; } } } }`
			packedSrc := `firewall { family inet { filter f1 { term t1 ` + tc.body + `; } } }`

			nested := compileBraced6684(t, nestedSrc).Firewall.FiltersInet["f1"]
			packed := compileBraced6684(t, packedSrc).Firewall.FiltersInet["f1"]

			if nested == nil || len(nested.Terms) != 1 {
				t.Fatalf("nested spelling compiled no term — the fixture is not exercising the stanza")
			}
			if packed == nil || len(packed.Terms) != 1 {
				t.Fatalf("packed spelling compiled no term at all: %+v", packed)
			}
			if !reflect.DeepEqual(nested.Terms, packed.Terms) {
				t.Errorf("packed body compiled differently from nested (#6685)\n nested = %+v\n packed = %+v",
					*nested.Terms[0], *packed.Terms[0])
			}
		})
	}
}

// TestPackedBodyLeavesUnmodelledTailAlone_6685 pins the conservative half. The
// expander is schema-driven; a tail that leaves the modelled grammar must
// return the node's real children rather than inventing a shape, because
// guessing would be a new way to compile something the operator did not write.
func TestPackedBodyLeavesUnmodelledTailAlone_6685(t *testing.T) {
	node := &Node{Keys: []string{"term", "t1", "not-a-real-keyword", "x"}}
	got := packedBodyChildren(node, schemaForPath("firewall", "family", "inet", "filter", "term"))
	if len(got) != 0 {
		t.Errorf("an unmodelled tail must not be expanded, got %d synthesized children", len(got))
	}

	// A nil schema must be inert too — never panic, never invent.
	if got := packedBodyChildren(node, nil); len(got) != 0 {
		t.Errorf("a nil schema must not expand, got %d children", len(got))
	}
}

// TestPackedBodyDoesNotMutateTheAST_6685 matters because `show configuration`
// renders from the same tree the compiler walks: expanding in place would
// rewrite the operator's one-liner into nested form on display.
func TestPackedBodyDoesNotMutateTheAST_6685(t *testing.T) {
	tree, perrs := NewParser(`firewall { family inet { filter f1 { term t1 then discard; } } }`).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	var term *Node
	var walk func(n *Node)
	walk = func(n *Node) {
		if n.Keys[0] == "term" {
			term = n
			return
		}
		for _, c := range n.Children {
			walk(c)
		}
	}
	for _, c := range tree.Children {
		walk(c)
	}
	if term == nil {
		t.Fatal("did not find the term node")
	}
	before := append([]string(nil), term.Keys...)
	childrenBefore := len(term.Children)

	_ = packedBody(term, schemaForPath("firewall", "family", "inet", "filter", "term"))

	if !reflect.DeepEqual(before, term.Keys) {
		t.Errorf("expansion mutated the node's Keys: %v -> %v", before, term.Keys)
	}
	if len(term.Children) != childrenBefore {
		t.Errorf("expansion mutated the node's Children: %d -> %d", childrenBefore, len(term.Children))
	}
}

// TestPackedFromStatementMatchesNestedFromBlock verifies the defect found while
// building the table above, on the side the issues all assumed was correct.
//
// `term t1 { from protocol tcp; }` writes the condition as a one-line STATEMENT
// inside the term block, which packs it onto the `from` node's own Keys exactly
// as the term-level packing does one level up. compileFilterFrom read children,
// so the condition was silently dropped — and a filter term with NO match
// conditions matches EVERYTHING. A term meant to discard only TCP discarded
// everything; a term meant to accept only TCP accepted everything.
//
// Confirmed pre-existing on origin/master before the fix:
//
//	term t1 { from protocol tcp; }     -> Protocols=[]     WRONG
//	term t1 { from { protocol tcp; } } -> Protocols=[tcp]  correct
func TestPackedFromStatementMatchesNestedFromBlock(t *testing.T) {
	cases := []struct{ name, cond string }{
		{"protocol", `protocol tcp`},
		{"source-address", `source-address 10.0.0.0/8`},
		{"destination-address", `destination-address 192.168.0.0/16`},
		{"destination-port", `destination-port 443`},
		{"source-port", `source-port 1024`},
		{"dscp", `dscp 46`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			block := `firewall { family inet { filter f1 { term t1 { from { ` + tc.cond + `; } then discard; } } } }`
			stmt := `firewall { family inet { filter f1 { term t1 { from ` + tc.cond + `; then discard; } } } }`

			blockTerms := compileBraced6684(t, block).Firewall.FiltersInet["f1"].Terms
			stmtTerms := compileBraced6684(t, stmt).Firewall.FiltersInet["f1"].Terms

			if len(blockTerms) != 1 {
				t.Fatalf("the from-BLOCK spelling compiled no term — fixture is not exercising the stanza")
			}
			// Anti-vacuity: the block spelling must actually record a
			// condition, or "equal" would mean "both empty" — which is the
			// exact bug, passing as a green.
			if reflect.DeepEqual(*blockTerms[0], FirewallFilterTerm{Name: "t1", Action: FilterActionDiscard, TerminalActions: []FilterAction{FilterActionDiscard}}) {
				t.Fatalf("the from-BLOCK spelling recorded no match condition either; the fixture cannot detect the defect")
			}
			if !reflect.DeepEqual(blockTerms, stmtTerms) {
				t.Errorf("a one-line `from %s;` compiled differently from the `from { %s; }` block\n block = %+v\n stmt  = %+v",
					tc.cond, tc.cond, *blockTerms[0], *stmtTerms[0])
			}
		})
	}
}
