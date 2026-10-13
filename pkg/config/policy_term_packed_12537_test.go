package config

import (
	"strings"
	"testing"
)

// packedTermLeaf12537 parses text and returns the packed `term` leaf at path.
func packedTermLeaf12537(t *testing.T, text string, path ...string) *Node {
	t.Helper()
	tree, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse %q: %v", text, perrs)
	}
	nodes := tree.Children
	var n *Node
	for _, keyword := range path {
		n = nil
		for _, c := range nodes {
			if c.Name() == keyword {
				n = c
				break
			}
		}
		if n == nil {
			t.Fatalf("parse %q: no %q", text, keyword)
		}
		nodes = n.Children
	}
	if !n.IsLeaf {
		t.Fatalf("parse %q: %q is not a packed leaf", text, n.Keys)
	}
	return n
}

func policyTermLine12537(t *testing.T, line string) *Node {
	t.Helper()
	return packedTermLeaf12537(t, "policy-options { policy-statement P { "+line+"; } }",
		"policy-options", "policy-statement", "term")
}

func bodyShape12537(nodes []*Node) string {
	parts := make([]string, 0, len(nodes))
	for _, n := range nodes {
		s := "[" + strings.Join(n.Keys, " ") + "]"
		if len(n.Children) > 0 {
			s += "{" + bodyShape12537(n.Children) + "}"
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, " ")
}

// TestPolicyTermBodyUsesCompilerReaders12537 pins the rebuilt shapes: one
// `from` container of splitPolicyTermFromRun11779 parts — an unknown word an
// opaque leaf, a second or then-first `from` joining the same container, a
// clause word ending an opaque part — and one `then` container holding one
// statement per action, with a tail token on the action it follows.
func TestPolicyTermBodyUsesCompilerReaders12537(t *testing.T) {
	termSchema := schemaForPath("policy-options", "policy-statement", "term")
	for _, tc := range []struct{ line, want string }{
		{"term T from route-filter 10.0.0.0/8 orlonger reject",
			"[from]{[route-filter 10.0.0.0/8 orlonger] [reject]}"},
		{"term T from protocol static bgp prefix-list PA PB",
			"[from]{[protocol static bgp] [prefix-list PA PB]}"},
		{"term T from protocol static from route-filter 10.0.0.0/8 orlonger reject",
			"[from]{[protocol static] [route-filter 10.0.0.0/8 orlonger] [reject]}"},
		{"term T from neighbor 10.0.0.1 then accept",
			"[from]{[neighbor 10.0.0.1]} [then]{[accept]}"},
		{"term T from route-filter 10.0.0.0/8 orlonger then local-preference 200 reject bogus",
			"[from]{[route-filter 10.0.0.0/8 orlonger]} [then]{[local-preference 200] [reject bogus]}"},
		{"term T then community add C1 accept from protocol static bgp",
			"[then]{[community add C1] [accept]} [from]{[protocol static bgp]}"},
		{"term T then rejct accept", "[then]{[rejct] [accept]}"},
	} {
		got := bodyShape12537(policyTermBody12537(termSchema, policyTermLine12537(t, tc.line), false))
		if got != tc.want {
			t.Errorf("%s:\n got %s\nwant %s", tc.line, got, tc.want)
		}
	}
}

// TestPolicyTermBodyScope12537 pins where the rebuild declines: a firewall
// filter term (its grammar is not the routing-policy one, #12696 review B1), a
// tail that opens no clause, and an inline peer whose `then` opens with an
// unknown action word, which keeps its packed line for the direct reader.
func TestPolicyTermBodyScope12537(t *testing.T) {
	fwTerm := packedTermLeaf12537(t,
		"firewall { family inet { filter F { term T from source-address 10.0.0.0/8 except then accept; } } }",
		"firewall", "family", "filter", "term")
	if body := policyTermBody12537(schemaForPath("firewall", "family", "inet", "filter", "term"), fwTerm, false); body != nil {
		t.Errorf("firewall term rebuilt as %s, want it left to the generic path", bodyShape12537(body))
	}
	termSchema := schemaForPath("policy-options", "policy-statement", "term")
	for _, tc := range []struct {
		line   string
		inline bool
	}{
		{"term T bogus then accept", false},
		{"term T then rejct accept", true},
		{"term T from route-filter 10.0.0.0/8 orlonger then rejct", true},
	} {
		if body := policyTermBody12537(termSchema, policyTermLine12537(t, tc.line), tc.inline); body != nil {
			t.Errorf("%s (inline=%v) rebuilt as %s, want nil", tc.line, tc.inline, bodyShape12537(body))
		}
	}
}
