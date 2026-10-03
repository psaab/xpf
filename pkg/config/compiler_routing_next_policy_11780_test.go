package config

import "testing"

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
