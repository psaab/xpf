package config

import "testing"

// The flat `set` spelling MERGES into an existing instance; hand-written
// hierarchical text with a repeated instance block does NOT — it produces two.
//
// This cell exists because three separate people got that wrong on ONE issue in
// ONE day, each writing hierarchical text through NewParser as a stand-in for
// what a CLI `set` session produces, and each drawing a conclusion the flat
// spelling does not support. CLAUDE.md names the rule outright ("Testing flat
// set syntax: ALWAYS use ParseSetCommand() + tree.SetPath() loop, NEVER
// NewParser()"), and prose did not stop it, so the difference is pinned here
// where someone reasoning about a packed spelling can run into it.
//
// It is not carelessness. Hand-written hierarchical text LOOKS like a faithful
// rendering of a CLI session, and the merge behaviour is the entire difference
// between the two. A fixture that gets it wrong does not fail — it produces a
// different, plausible config and answers a question nobody asked.
func TestFlatSetMergesWhereHierarchicalDuplicates(t *testing.T) {
	const zones = "set security zones security-zone trust\nset security zones security-zone untrust"
	base := []string{
		"set security policies from-zone trust to-zone untrust policy p1 match source-address any",
		"set security policies from-zone trust to-zone untrust policy p1 match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p1 match application any",
		"set security policies from-zone trust to-zone untrust policy p1 then permit",
	}
	const schedDef = "set schedulers scheduler S daily start-time 09:00:00 stop-time 17:00:00"
	const schedRef = "set security policies from-zone trust to-zone untrust policy p1 scheduler-name S"

	policiesOf := func(t *testing.T, cfg *Config) []*Policy {
		t.Helper()
		var out []*Policy
		for _, z := range cfg.Security.Policies {
			if z == nil {
				continue
			}
			for _, p := range z.Policies {
				if p != nil {
					out = append(out, p)
				}
			}
		}
		return out
	}

	// FLAT SET: a second `set` naming the same policy MERGES into it.
	t.Run("flatSetMerges", func(t *testing.T) {
		tree := &ConfigTree{}
		cmds := append([]string{}, base...)
		cmds = append(cmds, schedDef, schedRef)
		for _, line := range []string{zones} {
			for _, c := range splitLines(line) {
				applySet(t, tree, c)
			}
		}
		for _, c := range cmds {
			applySet(t, tree, c)
		}
		// Both compile paths, because the whole point of the confusion was that
		// they can disagree — here they must not.
		for _, lenient := range []bool{false, true} {
			cfg, err := compileEither(tree, lenient)
			if err != nil {
				t.Fatalf("lenient=%v: flat set must compile: %v", lenient, err)
			}
			got := policiesOf(t, cfg)
			if len(got) != 1 {
				t.Fatalf("lenient=%v: flat set produced %d policies, want 1 — a second `set` "+
					"naming the same policy MERGES; if this now duplicates, every fixture that "+
					"used hierarchical text as a stand-in for `set` was accidentally right and "+
					"every one that used `set` is now wrong", lenient, len(got))
			}
			if got[0].SchedulerName != "S" {
				t.Errorf("lenient=%v: merged policy scheduler-name = %q, want %q — the second "+
					"`set` line did not merge its leaf into the existing policy",
					lenient, got[0].SchedulerName, "S")
			}
			if len(got[0].Match.SourceAddresses) == 0 {
				t.Errorf("lenient=%v: merged policy lost its match criteria — the merge "+
					"REPLACED rather than combined", lenient)
			}
		}
	})

	// HIERARCHICAL: a repeated instance block does NOT merge. This is the shape
	// that reaches production through a hand-edited file, a config written by an
	// older build, or an HA peer push — the population the LENIENT path exists
	// to accept — and NOT through the CLI.
	t.Run("hierarchicalDuplicates", func(t *testing.T) {
		const text = `schedulers { scheduler S { daily { start-time 09:00; stop-time 17:00; } } }
security { zones { security-zone trust; security-zone untrust; }
policies { from-zone trust to-zone untrust {
    policy p1 { match { source-address any; destination-address any; application any; } then { permit; } }
    policy p1 scheduler-name S;
} } }`
		tree, perrs := NewParser(text).Parse()
		if len(perrs) > 0 {
			t.Fatalf("fixture must parse: %v", perrs)
		}
		cfg, err := compileConfigWithOpts(tree, lenientCompileOpts())
		if err != nil || cfg == nil {
			t.Fatalf("the LENIENT path must accept a duplicate block — that is what it is for: %v", err)
		}
		got := policiesOf(t, cfg)
		if len(got) != 2 {
			t.Fatalf("hierarchical duplicate produced %d policies, want 2 — if this now merges, "+
				"the two spellings have converged and the #8690 `wrong-remedy` reasoning needs "+
				"re-deriving", len(got))
		}
		// The operator's policy is the one carrying match criteria. Identify it
		// by that rather than by index, so a reordering does not silently
		// invert the assertion.
		var operator, dup *Policy
		for _, p := range got {
			if len(p.Match.SourceAddresses) > 0 {
				operator = p
			} else {
				dup = p
			}
		}
		if operator == nil || dup == nil {
			t.Fatalf("expected one policy with match criteria and one without; got %d policies", len(got))
		}
		if operator.SchedulerName != "" {
			t.Errorf("the operator's policy has scheduler-name %q — if the duplicate now merges "+
				"its leaf in, the #8690 harm is fixed and that entry should be re-measured",
				operator.SchedulerName)
		}
		if dup.Action != PolicyDeny {
			t.Errorf("the spurious duplicate's action = %v, want PolicyDeny — a policy with no "+
				"terminal action defaults to deny on the tolerant load path", dup.Action)
		}
	})
}

func applySet(t *testing.T, tree *ConfigTree, cmd string) {
	t.Helper()
	path, err := ParseSetCommand(cmd)
	if err != nil {
		t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
	}
	if err := tree.SetPath(path); err != nil {
		t.Fatalf("SetPath(%q): %v", cmd, err)
	}
}

func splitLines(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == '\n' {
			if cur != "" {
				out = append(out, cur)
			}
			cur = ""
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func compileEither(tree *ConfigTree, lenient bool) (*Config, error) {
	if lenient {
		return CompileConfigLenient(tree)
	}
	return CompileConfig(tree)
}
