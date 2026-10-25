package config

import (
	"strings"
	"testing"
)

func TestPolicyThenNextPolicyCompilesEverySpelling11780(t *testing.T) {
	compileFlat := func(t *testing.T, commands ...string) *PolicyTerm {
		t.Helper()
		tree := &ConfigTree{}
		for _, command := range commands {
			path, err := ParseSetCommand(command)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", command, err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("SetPath(%q): %v", command, err)
			}
		}
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("CompileConfigLenient: %v", err)
		}
		return cfg.PolicyOptions.PolicyStatements["p1"].Terms[0]
	}
	compileHierarchical := func(t *testing.T, text string) *PolicyTerm {
		t.Helper()
		tree, parseErrors := NewParser(text).Parse()
		if len(parseErrors) != 0 {
			t.Fatalf("parse: %v", parseErrors)
		}
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("CompileConfigLenient: %v", err)
		}
		return cfg.PolicyOptions.PolicyStatements["p1"].Terms[0]
	}

	cases := []struct {
		name                string
		term                *PolicyTerm
		wantLocalPreference bool
	}{
		{
			name: "flat set separate commands",
			term: compileFlat(t,
				"set policy-options policy-statement p1 term t1 then local-preference 200",
				"set policy-options policy-statement p1 term t1 then next policy"),
			wantLocalPreference: true,
		},
		{
			name: "flat set packed modifiers",
			term: compileFlat(t,
				"set policy-options policy-statement p1 term t1 then local-preference 200 next policy"),
			wantLocalPreference: true,
		},
		{
			name:                "hierarchical siblings",
			term:                compileHierarchical(t, `policy-options { policy-statement p1 { term t1 { then { local-preference 200; next policy; } } } }`),
			wantLocalPreference: true,
		},
		{
			name: "hierarchical packed action",
			term: compileHierarchical(t, `policy-options { policy-statement p1 { term t1 { then next policy; } } }`),
		},
		{
			name: "hierarchical inline term tail",
			term: compileHierarchical(t, `policy-options { policy-statement p1 { term t1 then next policy; } }`),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !tc.term.NextPolicy {
				t.Fatalf("then next policy was dropped: compiled term = %+v", tc.term)
			}
			if tc.wantLocalPreference &&
				(!tc.term.HasLocalPreference || tc.term.LocalPreference != 200) {
				t.Fatalf("next policy lost the preceding set action: compiled term = %+v", tc.term)
			}
		})
	}
}

func TestNextPolicySequenceCountsIncludeSkippedDefaults11780(t *testing.T) {
	first := &PolicyStatement{
		Name:          "first",
		DefaultAction: "reject",
		Terms:         []*PolicyTerm{{Name: "continue", NextPolicy: true}},
	}
	second := &PolicyStatement{
		Name:  "second",
		Terms: []*PolicyTerm{{Name: "accept", Action: "accept"}},
	}
	if got := RouteMapSequenceCount(&PolicyOptionsConfig{}, first); got != 2 {
		t.Fatalf("single-policy term/default sequence count = %d, want 2", got)
	}
	chain := map[string]*PolicyStatement{"first": first, "second": second}
	if got := ComposedChainSequenceCount(&PolicyOptionsConfig{}, chain, []string{"first", "second"}); got != 3 {
		t.Fatalf("chain count = %d, want first term + bypassable default + second term", got)
	}

	first.Terms[0].NextPolicy = false
	if got := ComposedChainSequenceCount(&PolicyOptionsConfig{}, chain, []string{"first", "second"}); got != 1 {
		t.Fatalf("terminating chain count without next policy = %d, want only first term", got)
	}
}

func TestPolicyThenNestedRejectStillTerminates11780(t *testing.T) {
	compileHierarchical := func(t *testing.T, text string) *PolicyTerm {
		t.Helper()
		tree, parseErrors := NewParser(text).Parse()
		if len(parseErrors) != 0 {
			t.Fatalf("parse: %v", parseErrors)
		}
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("CompileConfigLenient: %v", err)
		}
		return cfg.PolicyOptions.PolicyStatements["p1"].Terms[0]
	}
	term := compileHierarchical(t, `policy-options { policy-statement p1 { term t1 { then { reject; } } } }`)
	if term.Action != "reject" {
		t.Fatalf("nested then-reject was dropped: compiled term = %+v", term)
	}
	if term.NextPolicy {
		t.Fatalf("nested then-reject must not set NextPolicy: %+v", term)
	}
	// Control: nested accept still terminates.
	term = compileHierarchical(t, `policy-options { policy-statement p1 { term t1 { then { accept; } } } }`)
	if term.Action != "accept" || term.NextPolicy {
		t.Fatalf("nested then-accept regressed: %+v", term)
	}
}

func TestMalformedNextPolicyFailsClosed11780(t *testing.T) {
	tree, parseErrors := NewParser(`policy-options { policy-statement p1 { term t1 { then next polic; } } }`).Parse()
	if len(parseErrors) != 0 {
		t.Fatalf("parse: %v", parseErrors)
	}
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("strict compile accepted malformed `then next polic`")
	}

	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	term := cfg.PolicyOptions.PolicyStatements["p1"].Terms[0]
	if term.NextPolicy || term.Action != "reject" {
		t.Fatalf("malformed next-policy must compile as a terminal reject, got %+v", term)
	}
	if len(cfg.Warnings) == 0 {
		t.Fatal("lenient compile accepted malformed next-policy without a warning")
	}
}

func TestMalformedNextPolicyRejectDominatesFollowingAccept11780(t *testing.T) {
	tree, parseErrors := NewParser(`policy-options { policy-statement p1 { term t1 { then { next polic; accept; } } } }`).Parse()
	if len(parseErrors) != 0 {
		t.Fatalf("parse: %v", parseErrors)
	}
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("strict compile accepted malformed next-policy followed by accept")
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	term := cfg.PolicyOptions.PolicyStatements["p1"].Terms[0]
	if term.NextPolicy || term.Action != "reject" {
		t.Fatalf("malformed next-policy must dominate later actions and fail closed, got %+v", term)
	}
	if len(cfg.Warnings) == 0 {
		t.Fatal("lenient compile accepted malformed next-policy without a warning")
	}
}

func TestNextPolicyCannotConflictWithTerminalAction11780(t *testing.T) {
	cases := []struct {
		name   string
		action string
		text   string
	}{
		{
			name:   "hierarchical accept siblings",
			action: "accept",
			text:   `policy-options { policy-statement p1 { term t1 { then { accept; next policy; } } } }`,
		},
		{
			name:   "hierarchical reject siblings",
			action: "reject",
			text:   `policy-options { policy-statement p1 { term t1 { then { reject; next policy; } } } }`,
		},
		{
			name:   "hierarchical packed action",
			action: "accept",
			text:   `policy-options { policy-statement p1 { term t1 { then accept next policy; } } }`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree, parseErrors := NewParser(tc.text).Parse()
			if len(parseErrors) != 0 {
				t.Fatalf("parse: %v", parseErrors)
			}
			if _, err := CompileConfig(tree); err == nil {
				t.Fatal("strict compile accepted a term with both a terminal action and next-policy")
			}
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("lenient compile: %v", err)
			}
			term := cfg.PolicyOptions.PolicyStatements["p1"].Terms[0]
			if !term.NextPolicy || term.Action != tc.action {
				t.Fatalf("lenient compile must retain both authored actions for show/fail-closed rendering, got %+v", term)
			}
			if len(cfg.Warnings) == 0 {
				t.Fatal("lenient compile accepted conflicting actions without a warning")
			}
		})
	}
}

// #16872: `then next term` is a documented Junos flow-control action
// (skip to the next term of the same policy; modifiers still apply).
// It must commit in every spelling, set NextTerm (not NextPolicy), keep
// Action empty, and preserve modifiers. FAIL-ON-REVERT: restoring the
// policy-only enum / invalid-next recording makes every cell strict-fail
// and the lenient cells compile to reject.
func TestPolicyThenNextTermCompilesEverySpelling16872(t *testing.T) {
	compileFlat := func(t *testing.T, commands ...string) *PolicyTerm {
		t.Helper()
		tree := &ConfigTree{}
		for _, command := range commands {
			path, err := ParseSetCommand(command)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", command, err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("SetPath(%q): %v", command, err)
			}
		}
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig(strict) rejected `then next term`: %v", err)
		}
		return cfg.PolicyOptions.PolicyStatements["p1"].Terms[0]
	}
	compileHierarchical := func(t *testing.T, text string) *PolicyTerm {
		t.Helper()
		tree, parseErrors := NewParser(text).Parse()
		if len(parseErrors) != 0 {
			t.Fatalf("parse: %v", parseErrors)
		}
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig(strict) rejected `then next term`: %v", err)
		}
		return cfg.PolicyOptions.PolicyStatements["p1"].Terms[0]
	}
	cases := []struct {
		name                string
		term                *PolicyTerm
		wantLocalPreference bool
	}{
		{
			name: "flat set separate commands",
			term: compileFlat(t,
				"set policy-options policy-statement p1 term t1 then local-preference 200",
				"set policy-options policy-statement p1 term t1 then next term"),
			wantLocalPreference: true,
		},
		{
			name: "flat set packed modifiers",
			term: compileFlat(t,
				"set policy-options policy-statement p1 term t1 then local-preference 200 next term"),
			wantLocalPreference: true,
		},
		{
			name:                "hierarchical siblings",
			term:                compileHierarchical(t, `policy-options { policy-statement p1 { term t1 { then { local-preference 200; next term; } } } }`),
			wantLocalPreference: true,
		},
		{
			name: "hierarchical packed action",
			term: compileHierarchical(t, `policy-options { policy-statement p1 { term t1 { then next term; } } }`),
		},
		{
			name: "hierarchical inline term tail",
			term: compileHierarchical(t, `policy-options { policy-statement p1 { term t1 then next term; } }`),
		},
		{
			name:                "term-line spelling",
			term:                compileHierarchical(t, `policy-options { policy-statement p1 { term t1 then local-preference 200 next term; } }`),
			wantLocalPreference: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !tc.term.NextTerm {
				t.Fatalf("then next term was dropped: compiled term = %+v", tc.term)
			}
			if tc.term.NextPolicy {
				t.Fatalf("next term must not set NextPolicy: %+v", tc.term)
			}
			if tc.term.Action != "" {
				t.Fatalf("next term must keep Action empty (fall-through), got %q", tc.term.Action)
			}
			if tc.wantLocalPreference &&
				(!tc.term.HasLocalPreference || tc.term.LocalPreference != 200) {
				t.Fatalf("next term lost the preceding set action: compiled term = %+v", tc.term)
			}
		})
	}
}

// #16872: lenient compile of `then next term` must NOT turn the term
// into a reject (the pre-fix tolerant defect: silent route withdrawal).
func TestPolicyThenNextTermLenientDoesNotReject16872(t *testing.T) {
	tree, parseErrors := NewParser(`policy-options { policy-statement p1 { term t1 { then { local-preference 200; next term; } } term t2 { then accept; } } }`).Parse()
	if len(parseErrors) != 0 {
		t.Fatalf("parse: %v", parseErrors)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	term := cfg.PolicyOptions.PolicyStatements["p1"].Terms[0]
	if !term.NextTerm || term.Action != "" || !term.HasLocalPreference || term.LocalPreference != 200 {
		t.Fatalf("lenient next-term must fall through with modifiers, got %+v", term)
	}
}

// #16872: Junos skips any accept/reject in a `then next term` statement,
// so `next term` beside a terminal is contradictory: strict rejects
// (naming both), lenient warns and forces the term to reject with both
// continuation markers cleared (routing terms have no poison sentinel,
// so the compiled term itself must fail closed — otherwise FRR would
// render the retained accept as a terminating permit). Both action
// orders are covered.
func TestNextTermCannotConflictWithTerminalAction16872(t *testing.T) {
	for _, tc := range []struct {
		name string
		then string
	}{
		{"accept-then-next-term", "accept; next term;"},
		{"next-term-then-accept", "next term; accept;"},
		{"reject-then-next-term", "reject; next term;"},
		{"next-term-then-reject", "next term; reject;"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			text := `policy-options { policy-statement p1 { term t1 { then { ` + tc.then + ` } } } }`
			tree, parseErrors := NewParser(text).Parse()
			if len(parseErrors) != 0 {
				t.Fatalf("parse: %v", parseErrors)
			}
			if _, err := CompileConfig(tree); err == nil {
				t.Fatal("strict compile accepted next term + terminal")
			} else if !strings.Contains(err.Error(), "next term") {
				t.Fatalf("strict error must name next term, got %v", err)
			}
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("lenient compile: %v", err)
			}
			term := cfg.PolicyOptions.PolicyStatements["p1"].Terms[0]
			if term.Action != "reject" || term.NextTerm || term.NextPolicy {
				t.Fatalf("lenient conflicting term must fail closed to reject with markers cleared, got %+v", term)
			}
			if len(cfg.Warnings) == 0 {
				t.Fatal("lenient accepted conflicting actions without a warning")
			}
		})
	}
}

// #16872: `next term` and `next policy` are mutually exclusive Junos
// flow-control actions (specify one). Both set — inline, or one side
// inherited via groups (#15259 materialisation) — must strict-reject
// and fail closed (reject, markers cleared) on the tolerant path, so
// the mixed term cannot silently jump past later terms/defaults.
// Repeated identical continuations and modifier-only controls stay legal.
func TestNextTermNextPolicyMixedContinuation16872(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{"inline-next-term-then-policy", `policy-options { policy-statement p1 { term t1 { then { next term; next policy; } } } }`},
		{"inline-next-policy-then-term", `policy-options { policy-statement p1 { term t1 { then { next policy; next term; } } } }`},
		{"group-policy-inline-term", `groups { G { policy-options { policy-statement P { term t1 { then next policy; } } } } }
policy-options { policy-statement P { term t1 { then next term; } apply-groups G; } }`},
		{"group-term-inline-policy", `groups { G { policy-options { policy-statement P { term t1 { then next term; } } } } }
policy-options { policy-statement P { term t1 { then next policy; } apply-groups G; } }`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := CompileConfig(hierTree(t, tc.src)); err == nil {
				t.Fatal("strict compile accepted mixed next term + next policy")
			} else if !strings.Contains(err.Error(), "next term") || !strings.Contains(err.Error(), "next policy") {
				t.Fatalf("strict error must name both continuations, got %v", err)
			}
			cfg, err := CompileConfigLenient(hierTree(t, tc.src))
			if err != nil {
				t.Fatalf("lenient compile: %v", err)
			}
			var term *PolicyTerm
			for _, ps := range cfg.PolicyOptions.PolicyStatements {
				if len(ps.Terms) > 0 {
					term = ps.Terms[0]
				}
			}
			if term == nil || term.Action != "reject" || term.NextTerm || term.NextPolicy {
				t.Fatalf("lenient mixed term must fail closed to reject with markers cleared, got %+v", term)
			}
			if len(cfg.Warnings) == 0 {
				t.Fatal("lenient accepted mixed continuations without a warning")
			}
		})
	}
	// Repeated identical continuation stays legal in both spellings.
	for _, src := range []string{
		`policy-options { policy-statement p1 { term t1 { then { next term; next term; } } } }`,
		`policy-options { policy-statement p1 { term t1 { then { next policy; next policy; } } } }`,
		`groups { G { policy-options { policy-statement P { term t1 { then next term; } } } } }
policy-options { policy-statement P { term t1 { then next term; } apply-groups G; } }`,
	} {
		if _, err := CompileConfig(hierTree(t, src)); err != nil {
			t.Fatalf("repeated identical continuation rejected: %v\n%s", err, src)
		}
	}
}
