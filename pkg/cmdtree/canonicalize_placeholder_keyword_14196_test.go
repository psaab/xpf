package cmdtree

import (
	"strings"
	"testing"
)

// #14196: a literal <placeholder> name — or any `<`-prefix of one — is NOT a
// keyword.
//
// resolveTreeWord resolved every unique keyword prefix including the
// `<host>` placeholder key, and Canonicalize marked a placeholder filled
// only on its unmatched-word arm. A surplus literal after a real value
// therefore re-resolved as a fake keyword:
//
//	ping 192.0.2.1 <      -> canonicalized OK as "ping 192.0.2.1 <host>"
//	ping 192.0.2.1 <host> -> canonicalized OK as "ping 192.0.2.1 <host>"
//	ping 192.0.2.1 <h     -> canonicalized OK as "ping 192.0.2.1 <host>"
//
// The login-class gate judged that polluted string while the handler ran
// the target before it, so an anchored `deny-commands "^ping 192.0.2.1$"`
// matched neither the full form nor the keyword-only prefix (which stops
// at the target) and the denied ping ran. The end-to-end authorization
// cell lives in pkg/cli; this file pins the canonicalizer contract it
// rests on, on the real tree and on a synthetic tree so the rule is bound
// to the mechanism rather than to today's ping node.
func TestPlaceholderNamesAreNotKeywords14196(t *testing.T) {
	// REFUSED: the surplus placeholder word has no empty value slot to
	// take. These canonicalized OK on master, each rewritten to carry a
	// fake `<host>` / `<destination>` / `<count>` keyword.
	for _, line := range []string{
		// The reported shape, in all three literal spellings.
		"ping 192.0.2.1 <",
		"ping 192.0.2.1 <host>",
		"ping 192.0.2.1 <h",
		// The same hole after a complete option list.
		"ping 192.0.2.1 count 5 <",
		"ping 192.0.2.1 count 5 <host>",
		// And on the sibling Options node.
		"traceroute 192.0.2.1 <",
		"traceroute 192.0.2.1 <host>",
		// A placeholder that takes children: the slot is already filled
		// by the real destination, so the literal is a second value.
		"show route 10.0.0.0 <destination>",
		"show route 10.0.0.0 <",
		// An Options placeholder filled by a real count.
		"show security log 5 <count>",
		"show security log 5 <",
	} {
		if got, res := Canonicalize(OperationalTree, strings.Fields(line)); res == CanonicalOK {
			t.Errorf("%q canonicalized OK as %q; the literal placeholder word is a "+
				"surplus value with no slot, so a restricted class must fail closed "+
				"rather than judge a string carrying a fake keyword", line, strings.Join(got, " "))
		}
	}

	// CONTROLS: a literal angle-bracket word in an EMPTY value slot is
	// operator data, consumed once and kept raw — exactly like any other
	// value. Refusing these would refuse a lawful (if odd) target for
	// every restricted class, and rewriting them would change the command.
	for _, tc := range []struct{ line, canon string }{
		{"ping <host>", "ping <host>"},
		{"ping <", "ping <"},
		{"ping < count 5", "ping < count 5"},
		{"ping <host> count 5", "ping <host> count 5"},
		{"show route <destination> exact", "show route <destination> exact"},
		{"show route < exact", "show route < exact"},
		{"show security log <count>", "show security log <count>"},
		{"show security log <", "show security log <"},
		// Genuine keyword abbreviation is untouched by the exclusion.
		{"ping 192.0.2.1 coun 5", "ping 192.0.2.1 count 5"},
		{"show route 10.0.0.0 exact", "show route 10.0.0.0 exact"},
	} {
		got, res := Canonicalize(OperationalTree, strings.Fields(tc.line))
		if res != CanonicalOK {
			t.Errorf("%q: result %v, want CanonicalOK — a value-slot word must still "+
				"be consumed as data", tc.line, res)
			continue
		}
		if strings.Join(got, " ") != tc.canon {
			t.Errorf("%q: canon %q, want %q — a value slot keeps the raw word", tc.line, strings.Join(got, " "), tc.canon)
		}
	}
}

// The rule is a property of the resolver, not of the ping node: the same
// shapes on a purpose-built tree (#9505's synthetic-tree discipline, so the
// cell does not depend on which real commands declare placeholders today).
func TestPlaceholderNamesAreNotKeywordsSynthetic14196(t *testing.T) {
	tree := syntheticTree9505()
	for _, line := range []string{
		"opts t1 <target>",
		"opts t1 <",
		"opts t1 <t",
	} {
		if got, res := Canonicalize(tree, strings.Fields(line)); res == CanonicalOK {
			t.Errorf("%q canonicalized OK as %q; want a refusal — the placeholder "+
				"slot is already filled", line, strings.Join(got, " "))
		}
	}
	for _, tc := range []struct{ line, canon string }{
		{"opts <target>", "opts <target>"},
		{"opts <", "opts <"},
		{"opts <target> port 22", "opts <target> port 22"},
		// The placeholder slot is still empty after a typed option, so the
		// literal is its one value there — kept raw like any other value.
		{"opts port 22 <target>", "opts port 22 <target>"},
	} {
		got, res := Canonicalize(tree, strings.Fields(tc.line))
		if res != CanonicalOK || strings.Join(got, " ") != tc.canon {
			t.Errorf("%q: canon %q result %v, want %q CanonicalOK", tc.line, strings.Join(got, " "), res, tc.canon)
		}
	}
}
