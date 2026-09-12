package config

import (
	"strings"
	"testing"
)

// #9620 H9: a firewall filter term written on one line lost its terminating
// action, and that is a DENY that PERMITS.
//
//	term t1 then count C1 discard;      compiled Action="" Count=""
//	term t1 { then count C1 discard; }  compiled Action=discard Count=C1
//
// Traced through the real filter engine rather than inferred, because
// "compiles to an empty action" and "permits the packet" are different claims:
//
//	MODIFIER-ONLY SOLE TERM -> action=Accept
//	CONTROL, discard KEPT   -> action=Discard
//
// The chain is: the elision leaves `Action=""`; the snapshot builder sets
// `NextTerm` for a modifier-only term (Junos fall-through); the Rust evaluator
// applies modifiers and continues; nothing later terminates, so
// `FilterResult::default()` returns `FilterAction::Accept`. `show` prints
// `then accept` for an empty action too, so nothing contradicts it on screen.
//
// THE MECHANISM WAS IN THE READER, NOT THE ELISION. `packedBodyChildren` built a
// strictly NESTED chain, refining one schema level per statement. That is right
// only while every statement is a child of the one before it. `count` is a child
// of `then` and so is `discard` -- a SIBLING -- so after consuming `count C1`
// the walk asked `resolveSchemaChild(count, "discard")`, got nil, and discarded
// the whole body under "outside the modelled grammar, do not guess".
//
// The walk now keeps its open levels and attaches each statement to the DEEPEST
// open level that declares it. That is the same "a run that stops where it
// should pop" shape as H11, which is why one mechanism covers both members.

// termJSON9620H9 compiles text and returns the strict verdict with the whole
// compiled config, so a row compares everything rather than a chosen field.
func termJSON9620H9(t *testing.T, text string) (string, string) {
	t.Helper()
	return compiledConfigJSON9620(t, text)
}

// The defect and its braced twin, both statement orders. Equality with the
// braced spelling is the claim; "Action is non-empty" would be satisfied by an
// action the operator did not write.
func TestPackedTermThenCompilesLikeBraced9620H9(t *testing.T) {
	for _, tc := range []struct{ name, packed, braced string }{
		{
			name:   "then count C1 discard",
			packed: "firewall { family inet { filter f1 { term t1 then count C1 discard; } } }",
			braced: "firewall { family inet { filter f1 { term t1 { then { count C1; discard; } } } } }",
		},
		{
			name:   "then discard count C1 (reversed)",
			packed: "firewall { family inet { filter f1 { term t1 then discard count C1; } } }",
			braced: "firewall { family inet { filter f1 { term t1 { then { discard; count C1; } } } } }",
		},
		{
			// The `term from … then` member, which the #9620 notes recorded as
			// "accepted and compiled wrong at base, and remain so". One mechanism
			// covers it: the run pops back to the TERM to open `then` as a
			// sibling of `from`.
			name:   "from protocol tcp then discard",
			packed: "firewall { family inet { filter f1 { term t1 from protocol tcp then discard; } } }",
			braced: "firewall { family inet { filter f1 { term t1 { from { protocol tcp; } then { discard; } } } } }",
		},
		{
			name:   "two from conditions and two then statements",
			packed: "firewall { family inet { filter f1 { term t1 from protocol tcp source-port 80 then count C1 discard; } } }",
			braced: "firewall { family inet { filter f1 { term t1 { from { protocol tcp; source-port 80; } then { count C1; discard; } } } } }",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sp, jp := termJSON9620H9(t, tc.packed)
			sb, jb := termJSON9620H9(t, tc.braced)
			if sp != "OK" || sb != "OK" {
				t.Fatalf("both spellings must commit: packed=%s braced=%s", sp, sb)
			}
			if jp != jb {
				t.Fatalf("the packed spelling must compile like the braced one\npacked: %s\nbraced: %s", jp, jb)
			}
			if strings.Contains(jp, `"Action":""`) {
				t.Fatalf("a term with an empty Action FALLS THROUGH and the filter's trailing "+
					"default ACCEPTS, so a discard would permit: %s", jp)
			}
		})
	}
}

// The pop must not turn a legitimately NESTED chain into siblings. `filter input
// f1` under a family is one parent per statement, and every existing #9620 H11
// cell depends on it staying nested.
func TestPopKeepsASingleParentChainNested9620H9(t *testing.T) {
	for _, tc := range []struct{ name, packed, braced string }{
		{
			name:   "unit family filter input",
			packed: "interfaces { ge-0/0/0 { unit 0 { family inet filter input f1; } } }",
			braced: "interfaces { ge-0/0/0 { unit 0 { family inet { filter { input f1; } } } } }",
		},
		{
			name:   "unit family address then filter",
			packed: "interfaces { ge-0/0/0 { unit 0 { family inet address 10.0.0.1/24 filter input f1; } } }",
			braced: "interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; filter { input f1; } } } } }",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const prefix = "firewall { family inet { filter f1 { term t0 { then accept; } } } } "
			sp, jp := termJSON9620H9(t, prefix+tc.packed)
			sb, jb := termJSON9620H9(t, prefix+tc.braced)
			if sp != "OK" || sb != "OK" {
				t.Fatalf("both spellings must commit: packed=%s braced=%s", sp, sb)
			}
			if jp != jb {
				t.Fatalf("a single-parent chain must stay nested\npacked: %s\nbraced: %s", jp, jb)
			}
		})
	}
}

// CONTROL: the policy-options terms an earlier attempt at H9 broke. They are
// unchanged by this mechanism because it changes the READER, not the admission —
// nothing about the policy site's grammar is touched. These pass at master and
// must keep passing.
func TestPolicyOptionsTermsAreUnchanged9620H9(t *testing.T) {
	for _, tc := range []struct{ name, packed, braced string }{
		{
			name:   "then accept community add C",
			packed: "policy-options { policy-statement P { term t1 then accept community add C; } }",
			braced: "policy-options { policy-statement P { term t1 { then { accept; community add C; } } } }",
		},
		{
			name:   "then accept load-balance local-preference",
			packed: "policy-options { policy-statement P { term t1 then accept load-balance per-packet local-preference 200; } }",
			braced: "policy-options { policy-statement P { term t1 { then { accept; load-balance per-packet; local-preference 200; } } } }",
		},
		{
			name:   "from protocol ospf then accept",
			packed: "policy-options { policy-statement P { term t1 from protocol ospf then accept; } }",
			braced: "policy-options { policy-statement P { term t1 { from { protocol ospf; } then accept; } } }",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sp, jp := termJSON9620H9(t, tc.packed)
			sb, jb := termJSON9620H9(t, tc.braced)
			if sp != "OK" || sb != "OK" {
				t.Fatalf("both spellings must commit: packed=%s braced=%s", sp, sb)
			}
			if jp != jb {
				t.Fatalf("a policy-options term must compile alike in both spellings\npacked: %s\nbraced: %s", jp, jb)
			}
		})
	}
}

// The root-level SIBLING case, which is the bug this change introduced and then
// fixed. Popping back to the container used to append to the first statement
// instead of the body, so `from protocol tcp then discard;` produced
// `from { protocol tcp; then { discard; } }` and the commit gate refused it as
// "`from then` is not enforced by the dataplane" — a refusal that reads like a
// deliberate gate rather than a structural fault.
//
// Asserted on the expansion itself, because the compiled config cannot
// distinguish "nested wrongly then refused" from "refused for a real reason".
func TestPoppedStatementsAreBodySiblings9620H9(t *testing.T) {
	tree, perrs := NewParser(
		"firewall { family inet { filter f1 { term t1 from protocol tcp then count C1 discard; } } }").Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture must parse: %v", perrs)
	}
	normalizeCompactStanzas(tree)

	var term *Node
	var find func([]*Node)
	find = func(ns []*Node) {
		for _, n := range ns {
			if n == nil {
				continue
			}
			if len(n.Keys) > 0 && n.Keys[0] == "term" {
				term = n
				return
			}
			find(n.Children)
		}
	}
	find(tree.Children)
	if term == nil {
		t.Fatalf("fixture must produce a term node")
	}

	body := packedBody(term, schemaForPath("firewall", "family", "inet", "filter", "term"))
	var names []string
	for _, ch := range body.Children {
		names = append(names, ch.Name())
	}
	if len(names) != 2 || names[0] != "from" || names[1] != "then" {
		t.Fatalf("`from` and `then` must be SIBLINGS in the expanded body, got %v", names)
	}
	for _, ch := range body.Children {
		if ch.Name() == "from" {
			for _, g := range ch.Children {
				if g.Name() == "then" {
					t.Fatalf("`then` nested under `from`: the pop appended to the first statement " +
						"instead of the body, which the commit gate reports as `from then` not enforced")
				}
			}
		}
	}
}
