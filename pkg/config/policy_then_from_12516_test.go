package config

import (
	"strings"
	"testing"
)

// #12516: SetPath replays a then-first policy term line as the term's `from`
// clause plus its actions. These cells pin where the scan splits, which
// spellings it refuses, and the provenance each half keeps.

func parseSet12516(t *testing.T, line string) (path []string, quoted, grouped []bool, closed bool) {
	t.Helper()
	_, path, quoted, grouped, closed, err := ParseSetVerbGroupedClosed(line)
	if err != nil {
		t.Fatalf("parse %q: %v", line, err)
	}
	return path, quoted, grouped, closed
}

func TestPolicyTermThenFromSplit12516(t *testing.T) {
	const ps = "set policy-options policy-statement P term T "
	cases := []struct {
		name, line string
		from       int    // index of the `from` that starts the clause; -1 for none
		err        string // substring of the refusal; "" for none
	}{
		{"accept", ps + "then accept from protocol static", 7, ""},
		{"reject", ps + "then reject from protocol static", 7, ""},
		{"group mount", "set groups G policy-options policy-statement P term T then reject from protocol static", 9, ""},
		{"group wildcard policy", "set groups G policy-options policy-statement <*> term T then accept from protocol static", 9, ""},
		// The trigger follows the schema walk, not fixed offsets: a bracket
		// group widens the policy-statement node and moves every later token.
		{"bracket-widened policy name", "set policy-options policy-statement [ P1 P2 ] term T then accept from protocol static", 8, ""},
		{"metric prefix", ps + "then metric 10 accept from protocol static", 9, ""},
		{"local-preference prefix", ps + "then local-preference 200 accept from route-filter 10.0.0.0/8 exact", 9, ""},
		{"next-hop prefix", ps + "then next-hop self accept from protocol static", 9, ""},
		{"community add prefix", ps + "then community add C1 accept from protocol static", 10, ""},
		{"community value list absorbs", ps + "then community add C1 from protocol static", 9, ""},
		{"prepend run", ps + "then as-path-prepend 65001 65002 from protocol static", 9, ""},
		{"next policy", ps + "then next policy from route-filter 10.0.0.0/8 exact", 8, ""},
		{"quoted from at a clause position", ps + `then accept "from" route-filter 10.0.0.0/8 exact`, 7, ""},
		{"unquoted from in an operand slot", ps + "then metric from protocol static", 7, ""},
		{"quoted then", "set policy-options policy-statement P term T \"then\" accept from protocol static", 7, ""},
		{"bracketed action", ps + "then [ accept ] from protocol static", 7, ""},
		{"bracketed then group", ps + "[ then accept ] from protocol static", 7, ""},
		{"policy named from", "set policy-options policy-statement from term T then accept from protocol static", 7, ""},
		{"term named from", "set policy-options policy-statement P term from then accept from protocol static", 7, ""},
		{"community named from", ps + "then community add from accept", -1, ""},
		{"quoted community named from", ps + `then community add "from" accept`, -1, ""},
		{"bare community named from", ps + "then community from accept", -1, ""},
		{"community named from, then the clause", ps + "then community add from accept from protocol static", 10, ""},
		{"quoted from in an operand slot", ps + `then metric "from" accept`, -1, `operand slot of "then metric"`},
		{"bracketed from", ps + "then accept [ from protocol static ]", -1, "bracketed"},
		{"bracketed community member", ps + "then community delete [ C1 from ] accept", -1, "bracketed"},
		{"from-first spelling", ps + "from protocol static then accept", -1, ""},
		{"no from", ps + "then accept", -1, ""},
		{"firewall filter term", "set firewall family inet filter F term T then accept from protocol tcp", -1, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path, quoted, grouped, _ := parseSet12516(t, tc.line)
			_, fromAt, err := policyTermThenFromSplit12516(path, quoted, grouped)
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) || !strings.Contains(err.Error(), "#12516") {
					t.Fatalf("err = %v, want a #12516 refusal naming %q", err, tc.err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected refusal: %v", err)
			}
			if fromAt != tc.from {
				t.Fatalf("from index = %d, want %d (path %q)", fromAt, tc.from, path)
			}
			if fromAt >= 0 && path[fromAt] != "from" {
				t.Fatalf("split token = %q, want from", path[fromAt])
			}
		})
	}
}

func child12516(t *testing.T, nodes []*Node, keys ...string) *Node {
	t.Helper()
	for _, n := range nodes {
		if keysEqual(n.Keys, keys) {
			return n
		}
	}
	t.Fatalf("no node %q among %d siblings", keys, len(nodes))
	return nil
}

func termNode12516(t *testing.T, tree *ConfigTree) *Node {
	t.Helper()
	po := child12516(t, tree.Children, "policy-options")
	ps := child12516(t, po.Children, "policy-statement", "P")
	return child12516(t, ps.Children, "term", "T")
}

// The `from` half keeps the quote and bracket provenance (and the closed bit)
// of the tokens it carries, and nothing of the clause stays under `then`.
func TestPolicyTermThenFromSplitKeepsProvenance12516(t *testing.T) {
	for _, tc := range []struct {
		name   string
		line   string
		closed bool
	}{
		{"closed list", `set policy-options policy-statement P term T then metric 10 accept "from" protocol [ static bgp ]`, true},
		{"unclosed list", `set policy-options policy-statement P term T then metric 10 accept "from" protocol [ static bgp`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path, quoted, grouped, closed := parseSet12516(t, tc.line)
			tree := &ConfigTree{}
			if err := tree.SetPathQuotedGrouped(path, quoted, grouped, closed); err != nil {
				t.Fatalf("SetPathQuotedGrouped: %v", err)
			}
			term := termNode12516(t, tree)
			from := child12516(t, term.Children, "from")
			if !from.KeyQuoted(0) {
				t.Fatalf("from keys quoted = %v, want the authored quote kept", from.KeysQuoted)
			}
			proto := child12516(t, from.Children, "protocol", "static", "bgp")
			if !proto.KeyBracketed(1) || !proto.KeyBracketed(2) || proto.KeyBracketed(0) {
				t.Fatalf("protocol bracket provenance = %v, want [false true true]", proto.KeysBracketed)
			}
			if proto.BracketedClosed != tc.closed {
				t.Fatalf("protocol BracketedClosed = %v, want %v", proto.BracketedClosed, tc.closed)
			}
			then := child12516(t, term.Children, "then")
			var walk func([]*Node)
			walk = func(nodes []*Node) {
				for _, n := range nodes {
					for _, k := range n.Keys {
						if k == "from" || k == "protocol" {
							t.Fatalf("then subtree still carries %q in %q", k, n.Keys)
						}
					}
					walk(n.Children)
				}
			}
			walk(then.Children)

			cfg, err := CompileConfig(tree)
			if !tc.closed {
				if err == nil || !strings.Contains(err.Error(), "list did not close") {
					t.Fatalf("CompileConfig err = %v, want the #11779 unclosed-list refusal", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("CompileConfig: %v", err)
			}
			got := cfg.PolicyOptions.PolicyStatements["P"].Terms[0]
			if got.Action != "accept" || !got.HasMetric || got.Metric != 10 ||
				strings.Join(got.FromProtocols, ",") != "static,bgp" {
				t.Fatalf("compiled term = %+v, want accept, metric 10, protocols static,bgp", got)
			}
		})
	}
}

// A refused spelling fails before the walk creates any node.
func TestPolicyTermThenFromRefusalDoesNotMutate12516(t *testing.T) {
	for _, line := range []string{
		`set policy-options policy-statement P term T then accept [ from protocol static ]`,
		`set policy-options policy-statement P term T then metric "from" accept`,
	} {
		path, quoted, grouped, closed := parseSet12516(t, line)
		tree := &ConfigTree{}
		if err := tree.SetPathQuotedGrouped(path, quoted, grouped, closed); err == nil {
			t.Fatalf("%q: SetPathQuotedGrouped succeeded, want a #12516 refusal", line)
		}
		if len(tree.Children) != 0 {
			t.Fatalf("%q: refused set left %q behind", line, tree.FormatSet())
		}
	}
}

// delete, deactivate, and activate name one statement; a then-first line with
// a from clause is two after replay, so each verb refuses it before mutating.
func TestPolicyTermThenFromVerbsRefused12516(t *testing.T) {
	const line = "set policy-options policy-statement P term T then metric 10 accept from route-filter 10.0.0.0/8 exact"
	path, quoted, grouped, closed := parseSet12516(t, line)
	tree := &ConfigTree{}
	if err := tree.SetPathQuotedGrouped(path, quoted, grouped, closed); err != nil {
		t.Fatalf("SetPathQuotedGrouped: %v", err)
	}
	// A spelling SetPath refuses outright is refused by the verbs too.
	bracketed, _, bracketedGroups, _ := parseSet12516(t, "set policy-options policy-statement P term T then accept [ from route-filter 10.0.0.0/8 exact ]")
	before := tree.FormatSet()
	for _, tc := range []struct {
		verb, want string
		apply      func(*ConfigTree) error
	}{
		{"delete", "stored as separate from and then statements", func(c *ConfigTree) error { return c.DeletePathGrouped(path, grouped) }},
		{"deactivate", "stored as separate from and then statements", func(c *ConfigTree) error { return c.DeactivatePathGrouped(path, grouped) }},
		{"activate", "stored as separate from and then statements", func(c *ConfigTree) error { return c.ActivatePathGrouped(path, grouped) }},
		{"delete", "bracketed", func(c *ConfigTree) error { return c.DeletePathGrouped(bracketed, bracketedGroups) }},
		{"deactivate", "bracketed", func(c *ConfigTree) error { return c.DeactivatePathGrouped(bracketed, bracketedGroups) }},
		{"activate", "bracketed", func(c *ConfigTree) error { return c.ActivatePathGrouped(bracketed, bracketedGroups) }},
	} {
		err := tc.apply(tree)
		if err == nil || !strings.HasPrefix(err.Error(), tc.verb+" ") || !strings.Contains(err.Error(), tc.want) ||
			!strings.Contains(err.Error(), "#12516") {
			t.Fatalf("%s err = %v, want a #12516 refusal naming the verb and %q", tc.verb, err, tc.want)
		}
		if got := tree.FormatSet(); got != before {
			t.Fatalf("%s mutated the tree:\n%s\nwant\n%s", tc.verb, got, before)
		}
	}
}
