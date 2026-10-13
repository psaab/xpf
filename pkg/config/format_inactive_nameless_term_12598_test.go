package config

import (
	"strings"
	"testing"
)

// #12598: FormatSetForLoadMerge emitted a one-key deactivate
// (`deactivate ... term`) for an inactive nameless term. Flat replay
// prefix-matches that one-key path against `term ok`.

func inactiveTermDeactivateLines(t *testing.T, src string) []string {
	t.Helper()
	tree, errs := NewParser(src).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	var out []string
	for _, line := range strings.Split(tree.FormatSetForLoadMerge(), "\n") {
		if strings.HasPrefix(line, "deactivate ") {
			out = append(out, line)
		}
	}
	return out
}

func TestFormatSetInactiveNamelessTerm12598(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{"inactive nameless after named", "policy-options {\n policy-statement P {\n  term ok { then accept; }\n  inactive: term { then reject; }\n }\n}"},
		{"inactive nameless first", "policy-options {\n policy-statement P {\n  inactive: term { then reject; }\n  term ok { then accept; }\n }\n}"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := inactiveTermDeactivateLines(t, tc.src)
			if len(got) != 1 {
				t.Fatalf("deactivate lines = %q, want exactly one", got)
			}
			if got[0] == "deactivate policy-options policy-statement P term" {
				t.Fatalf("one-key deactivate targets first term, got %q", got[0])
			}
		})
	}
	t.Run("inactive named control", func(t *testing.T) {
		got := inactiveTermDeactivateLines(t, "policy-options {\n policy-statement P {\n  term ok { then accept; }\n  inactive: term named { then reject; }\n }\n}")
		want := "deactivate policy-options policy-statement P term named"
		if len(got) != 1 || got[0] != want {
			t.Fatalf("deactivate lines = %q, want [%q]", got, want)
		}
	})
	t.Run("public FormatSet unchanged", func(t *testing.T) {
		tree, errs := NewParser("policy-options { policy-statement P { term ok { then accept; } inactive: term { then reject; } } }").Parse()
		if len(errs) > 0 {
			t.Fatalf("parse: %v", errs)
		}
		want := "deactivate policy-options policy-statement P term\n"
		if got := tree.FormatSet(); !strings.Contains(got, want) {
			t.Fatalf("public FormatSet changed: want existing line %q in:\n%s", want, got)
		}
	})
}

func TestFormatSetInactiveMultiStatementNamelessTerm12598(t *testing.T) {
	src := "policy-options {\n policy-statement P {\n  term ok { then accept; }\n  inactive: term { from protocol bgp; then reject; }\n }\n}"
	tree, errs := NewParser(src).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	lines := strings.Split(strings.TrimSpace(tree.FormatSetForLoadMerge()), "\n")
	var deactivations []string
	for _, line := range lines {
		if strings.HasPrefix(line, "deactivate ") {
			deactivations = append(deactivations, line)
		}
	}
	want := []string{
		"deactivate policy-options policy-statement P term from",
		"deactivate policy-options policy-statement P term then",
	}
	if len(deactivations) != len(want) {
		t.Fatalf("deactivate lines = %q, want %q", deactivations, want)
	}
	for i := range want {
		if deactivations[i] != want[i] {
			t.Fatalf("deactivate lines = %q, want %q", deactivations, want)
		}
	}
	replayed := &ConfigTree{}
	for _, line := range lines {
		verb, path, quoted, grouped, err := ParseSetVerbGrouped(line)
		if err != nil {
			t.Fatalf("ParseSetVerbGrouped(%q): %v", line, err)
		}
		if verb == "deactivate" {
			err = replayed.DeactivatePathGrouped(path, grouped)
		} else {
			err = replayed.SetPathQuotedGrouped(path, quoted, grouped)
		}
		if err != nil {
			t.Fatalf("%s: %v", line, err)
		}
	}
	var terms []*Node
	var walk func(*Node)
	walk = func(n *Node) {
		if n.Name() == "term" {
			terms = append(terms, n)
		}
		for _, child := range n.Children {
			walk(child)
		}
	}
	for _, root := range replayed.Children {
		walk(root)
	}
	if len(terms) != 3 || terms[0].Inactive || !terms[1].Inactive || !terms[2].Inactive {
		t.Fatalf("replayed term activity = %#v, want named active and both flattened body terms inactive", terms)
	}
}

// End-to-end replay: deactivate must land on the authored inactive node,
// never on a sibling term sharing the `term` prefix.
func TestFormatSetInactiveNamelessTermReplay12598(t *testing.T) {
	src := "policy-options {\n policy-statement P {\n  term ok { then accept; }\n  inactive: term { then reject; }\n }\n}"
	tree, errs := NewParser(src).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	replayed := &ConfigTree{}
	for _, line := range strings.Split(strings.TrimSpace(tree.FormatSetForLoadMerge()), "\n") {
		verb, path, quoted, grouped, err := ParseSetVerbGrouped(line)
		if err != nil {
			t.Fatalf("ParseSetVerbGrouped(%q): %v", line, err)
		}
		var aerr error
		switch verb {
		case "deactivate":
			aerr = replayed.DeactivatePathGrouped(path, grouped)
		default:
			aerr = replayed.SetPathQuotedGrouped(path, quoted, grouped)
		}
		if aerr != nil {
			t.Fatalf("%s: %v", line, aerr)
		}
	}
	// Find terms under P.
	var terms []*Node
	var walk func(n *Node)
	walk = func(n *Node) {
		if n.Name() == "term" {
			terms = append(terms, n)
		}
		for _, c := range n.Children {
			walk(c)
		}
	}
	for _, c := range replayed.Children {
		walk(c)
	}
	if len(terms) != 2 {
		t.Fatalf("replayed terms = %d, want 2 (%#v)", len(terms), terms)
	}
	okTerm, nameless := terms[0], terms[1]
	if len(okTerm.Keys) != 2 || okTerm.Keys[1] != "ok" || okTerm.Inactive {
		t.Fatalf("term ok wrongly deactivated or lost: keys=%q inactive=%v", okTerm.Keys, okTerm.Inactive)
	}
	if len(nameless.Keys) != 2 || nameless.Keys[0] != "term" || nameless.Keys[1] != "then" || !nameless.Inactive {
		t.Fatalf("flattened nameless term not deactivated: keys=%q inactive=%v", nameless.Keys, nameless.Inactive)
	}
	if got := replayed.FormatSetForLoadMerge(); !strings.Contains(got, "deactivate policy-options policy-statement P term then") {
		t.Fatalf("round-trip lost or misdirected inactive marker: %q", got)
	}
}
