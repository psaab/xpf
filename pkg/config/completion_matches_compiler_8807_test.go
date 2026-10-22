package config

import "testing"

// Two leaves the COMPILER reads more of than the SCHEMA declared, so completion
// under-offered while compilation was correct.
//
// This is docs/config-schema.md's rule running BACKWARDS. That rule says adding
// a schema leaf is a compiler-behaviour change, because the packed reader
// resolves its tail through the schema and an undeclared-but-compiled leaf is
// dropped SILENTLY. Here the compiler is AHEAD of the schema instead: it reads
// `then reject <message-type>` from Keys[1] or from a child, and it iterates the
// policy-statement `then` node's children — while the schema declared neither.
// Nothing was dropped, because neither compiler path consults the schema. The
// symptom moved to the other surface: `?` help and tab-completion offered
// nothing, so an operator could not discover a statement that commits fine once
// typed. Two directions, two very different symptoms, one relationship.
//
// BOTH HALVES ARE ASSERTED IN ONE CELL, and that is deliberate. A completion
// guard that only asserts n>0 on the fixed paths is satisfied by a completer
// that matches everything; one that only asserts the control is satisfied by a
// completer that regressed the fix. Either assertion alone is satisfied by a
// stuck answer, so they have to fail together or the guard proves nothing.
//
// AND THE COMPILED RESULT IS PINNED ALONGSIDE. A schema declaration is NOT
// monotone: schema flags feed merge, completion, validation and compilation, so
// "additive to the schema" is not a reason to skip measuring compilation. Every
// spelling below was captured before the declaration and must still deliver the
// same value after it — including the typo rejection, which comes from the
// compiler's UnknownActions and not from the schema, and apply-groups
// inheritance, which is where an earlier schema change caused a live regression.
func TestCompletionMatchesCompiler8807(t *testing.T) {
	// ---- half 1: the newly declared paths offer what the compiler reads ----
	comp := func(t *testing.T, toks ...string) []string {
		t.Helper()
		var out []string
		for _, c := range CompleteSetPathWithValues(toks, nil) {
			out = append(out, c.Name)
		}
		return out
	}
	has := func(names []string, want string) bool {
		for _, n := range names {
			if n == want {
				return true
			}
		}
		return false
	}
	for _, af := range []string{"inet", "inet6"} {
		got := comp(t, "firewall", "family", af, "filter", "f1", "term", "t1", "then", "reject", "")
		if len(got) == 0 || !has(got, "tcp-reset") {
			t.Errorf("family %s `then reject <TAB>` offered %d completions %v — the compiler "+
				"accepts a message type here, so an operator who cannot see the list must "+
				"already know it", af, len(got), got)
		}
	}
	if got := comp(t, "policy-options", "policy-statement", "ps1", "then", ""); len(got) != 2 ||
		!has(got, "accept") || !has(got, "reject") {
		t.Errorf("`policy-statement <p> then <TAB>` offered %v, want exactly accept+reject — "+
			"the compiler iterates this node's children and reads those two", got)
	}

	// ---- half 2: the CONTROL, which is what makes half 1 a measurement ----
	// A completer that matched everything would satisfy half 1 and fail here
	// only if this path's count is checked exactly.
	if got := comp(t, "firewall", "family", "inet", "filter", "f1", "term", "t1", "then", ""); len(got) != 12 {
		t.Errorf("control: `term <t> then <TAB>` offered %d completions, want 12. This path "+
			"was already correct and is untouched by this change; if it moved, the "+
			"completer changed rather than the two declarations, and half 1 above is "+
			"measuring the completer instead of the schema", len(got))
	}

	// ---- and the compiled result, unchanged in every spelling ----
	rejOf := func(t *testing.T, body string) (action FilterAction, msg string, rejected bool) {
		t.Helper()
		text := `firewall { family inet { filter f1 { term t1 { from { protocol tcp; } ` + body + ` } } } }`
		tree, perrs := NewParser(text).Parse()
		if len(perrs) > 0 {
			t.Fatalf("fixture must parse: %v", perrs)
		}
		cfg, err := CompileConfig(tree)
		if err != nil || cfg == nil {
			return FilterActionUnset, "", true
		}
		for _, f := range cfg.Firewall.FiltersInet {
			for _, tm := range f.Terms {
				return tm.Action, tm.RejectMessageType, false
			}
		}
		t.Fatal("no term compiled")
		return FilterActionUnset, "", false
	}
	for _, c := range []struct {
		name, body, msg string
		action          FilterAction
	}{
		{name: "bare", body: `then { reject; }`, action: FilterActionReject, msg: ""},
		{name: "packed", body: `then reject tcp-reset;`, action: FilterActionReject, msg: "tcp-reset"},
		{name: "braced", body: `then { reject tcp-reset; }`, action: FilterActionReject, msg: "tcp-reset"},
		{name: "child form", body: `then { reject { tcp-reset; } }`, action: FilterActionReject, msg: "tcp-reset"},
	} {
		a, m, rej := rejOf(t, c.body)
		if rej || a != c.action || m != c.msg {
			t.Errorf("%s: Action=%q Msg=%q rejected=%v, want %q/%q. Declaring the message "+
				"types must not change what any spelling compiles to", c.name, a, m, rej, c.action, c.msg)
		}
	}
	// The typo gate is the compiler's, not the schema's, and must still fire.
	if _, _, rejected := rejOf(t, `then reject nonsense;`); !rejected {
		t.Error("`then reject nonsense` now COMMITS. Declaring the valid types must not " +
			"turn a rejected typo into an accepted one — the gate is compiler-side " +
			"(UnknownActions) and declaring children must leave it reachable")
	}

	// policy-statement default action, every spelling.
	polOf := func(t *testing.T, body string) string {
		t.Helper()
		tree, perrs := NewParser(`policy-options { policy-statement ps1 { ` + body + ` } }`).Parse()
		if len(perrs) > 0 {
			t.Fatalf("fixture must parse: %v", perrs)
		}
		cfg, err := CompileConfig(tree)
		if err != nil || cfg == nil {
			t.Fatalf("must commit: %v", err)
		}
		for _, ps := range cfg.PolicyOptions.PolicyStatements {
			return ps.DefaultAction
		}
		return "<none>"
	}
	for _, c := range []struct{ body, want string }{
		{`then { reject; }`, "reject"},
		{`then reject;`, "reject"},
		{`then { accept; }`, "accept"},
	} {
		if got := polOf(t, c.body); got != c.want {
			t.Errorf("policy-statement %q -> DefaultAction=%q, want %q", c.body, got, c.want)
		}
	}

	// apply-groups inheritance on a newly declared leaf — the surface where an
	// earlier schema change caused a live regression, so it is measured rather
	// than reasoned about.
	tree, perrs := NewParser(`groups { g1 { firewall { family inet { filter f1 { term t1 { then { reject tcp-reset; } } } } } } }
firewall { family inet { filter f1 { term t1 { from { protocol tcp; } } } } }
apply-groups g1;`).Parse()
	if len(perrs) > 0 {
		t.Fatalf("group fixture must parse: %v", perrs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil || cfg == nil {
		t.Fatalf("group fixture must commit: %v", err)
	}
	for _, f := range cfg.Firewall.FiltersInet {
		for _, tm := range f.Terms {
			if tm.Action != FilterActionReject || tm.RejectMessageType != "tcp-reset" {
				t.Errorf("apply-groups inheritance: Action=%q Msg=%q, want reject/tcp-reset. "+
					"Declaring children changes how a group's value merges, which is how a "+
					"schema flag stops being additive", tm.Action, tm.RejectMessageType)
			}
		}
	}
}
