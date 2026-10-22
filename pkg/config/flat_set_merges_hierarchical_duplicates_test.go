package config

import (
	"strings"
	"testing"
)

// The flat `set` spelling MERGES into an existing instance, structurally, for
// every container. Hand-written hierarchical text with a repeated instance
// block does NOT — it produces two — everywhere except the containers #8752
// folds.
//
// #8752 UPDATE. This cell used to state the contrast as unconditional, and it
// was pinned at `security policies ... policy`. The #8752 fold merges a
// repeated `policy` on the TOLERANT path, so at that one container the two
// spellings have now converged, and the sub-test that discriminated there can
// no longer see the substitution trap it was built to catch. The trap did not
// go away with it: the fold is scoped to a PAIR LIST, not to a shape, so every
// container outside that list still duplicates where `set` merges. The
// discriminating sub-test therefore moved to `security nat source rule-set`,
// measured (not assumed) to still show the split, and `policy` kept a
// sub-test asserting the CONVERGENCE instead — which doubles as the top-level
// regression guard for the fold.
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
//
// The moved sub-test is doing a second job now: it is the only executable
// statement of where the #8752 fold STOPS. If the fold is later widened to
// `nat source rule-set`, this cell goes red and the person widening it has to
// choose a still-unfolded container deliberately, rather than discovering
// later that the trap became undetectable.
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

	// HIERARCHICAL at `policy`: CONVERGED by #8752. A repeated instance block
	// used to produce two policies here; the tolerant-path fold now merges it
	// into the first occurrence, so the two spellings agree at this container.
	// This is the top-level regression guard for that fold — it asserts the
	// operator-visible RESULT (one policy, carrying both the leaf from the
	// duplicate and its own match criteria), not the mechanism.
	t.Run("hierarchicalConvergedForPolicy", func(t *testing.T) {
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
		cfg, err := compileTree(tree, lenientCompileOpts(), nil)
		if err != nil || cfg == nil {
			t.Fatalf("the LENIENT path must accept a duplicate block — that is what it is for: %v", err)
		}
		got := policiesOf(t, cfg)
		if len(got) != 1 {
			t.Fatalf("hierarchical duplicate produced %d policies, want 1 — #8752 folds a "+
				"repeated `policy` into the first occurrence on the tolerant path; if this "+
				"is 2 again the fold has regressed and the duplicate is once more shadowing "+
				"the operator's policy with a default-deny", len(got))
		}
		if got[0].SchedulerName != "S" {
			t.Errorf("merged policy scheduler-name = %q, want %q — the fold must carry the "+
				"duplicate's leaf ONTO the surviving policy, not just discard the duplicate",
				got[0].SchedulerName, "S")
		}
		if len(got[0].Match.SourceAddresses) == 0 {
			t.Errorf("merged policy lost its match criteria — the fold REPLACED rather than " +
				"combined, which would be a worse outcome than the duplicate it replaced")
		}
		if got[0].Action != PolicyPermit {
			t.Errorf("merged policy action = %v, want PolicyPermit — the operator's `then "+
				"permit` must survive the fold; a policy with no terminal action defaults to "+
				"deny, which is exactly the #8752 harm", got[0].Action)
		}
		// The whole point of merging rather than dropping: the tolerant path
		// must still TELL the operator, because a strict commit rejects this.
		var warned bool
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "duplicate policy name") {
				warned = true
			}
		}
		if !warned {
			t.Errorf("the fold merged silently — warnings=%v; merging without warning turns a "+
				"config a strict commit REJECTS into one that loads with no diagnostic",
				cfg.Warnings)
		}
	})

	// HIERARCHICAL outside the fold's scope: still duplicates where `set`
	// merges. This is the sub-test that carries the original purpose of this
	// cell — the substitution trap — after #8752 removed the contrast at
	// `policy`. The container was MEASURED to still split, not assumed:
	// hierarchical gives two rule-sets of one rule each, flat `set` gives one
	// rule-set of two rules.
	t.Run("hierarchicalStillDuplicatesOutsideFoldScope", func(t *testing.T) {
		const text = `security { nat { source {
    rule-set rs1 { from zone trust; to zone untrust; rule r1 { match { source-address 10.0.0.0/8; } then { source-nat { interface; } } } }
    rule-set rs1 { rule r2 { match { source-address 192.168.0.0/16; } then { source-nat { interface; } } } }
} } }`
		tree, perrs := NewParser(text).Parse()
		if len(perrs) > 0 {
			t.Fatalf("fixture must parse: %v", perrs)
		}
		cfg, err := compileTree(tree, lenientCompileOpts(), nil)
		if err != nil || cfg == nil {
			t.Fatalf("lenient compile: %v", err)
		}
		if n := len(cfg.Security.NAT.Source); n != 2 {
			t.Fatalf("hierarchical duplicate `rule-set rs1` produced %d rule-sets, want 2 — "+
				"if this is now 1, the #8752 fold (or something like it) has been widened to "+
				"cover `nat source rule-set`, and this cell must move to a container that is "+
				"still unfolded. Do NOT delete it: it is the only executable statement that "+
				"hand-written hierarchical text is not a stand-in for a `set` session, and "+
				"three people got that wrong on one issue in one day", n)
		}

		tree2 := &ConfigTree{}
		for _, c := range []string{
			"set security nat source rule-set rs1 from zone trust",
			"set security nat source rule-set rs1 to zone untrust",
			"set security nat source rule-set rs1 rule r1 match source-address 10.0.0.0/8",
			"set security nat source rule-set rs1 rule r1 then source-nat interface",
			"set security nat source rule-set rs1 rule r2 match source-address 192.168.0.0/16",
			"set security nat source rule-set rs1 rule r2 then source-nat interface",
		} {
			applySet(t, tree2, c)
		}
		cfg2, err := compileTree(tree2, lenientCompileOpts(), nil)
		if err != nil || cfg2 == nil {
			t.Fatalf("flat set must compile: %v", err)
		}
		if n := len(cfg2.Security.NAT.Source); n != 1 {
			t.Fatalf("flat `set` produced %d rule-sets, want 1 — `set` MERGES; the contrast "+
				"with the hierarchical spelling above is the entire point of this cell", n)
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
