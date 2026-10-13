package config

import (
	"strings"
	"testing"
)

func namelessPolicyTermTree12521(t *testing.T, body string) *ConfigTree {
	t.Helper()
	return hierTree(t, `policy-options {
    policy-statement P {
        term {
            `+body+`
        }
    }
}`)
}

func TestPolicyNamelessTermRejected12521(t *testing.T) {
	for _, tc := range []struct {
		name  string
		body  string
		first string
	}{
		{name: "then-accept", body: "then accept;", first: "then"},
		{name: "then-reject", body: "then reject;", first: "then"},
		{name: "brace-then-reject", body: "then { reject; }", first: "then"},
		{name: "brace-then-accept", body: "then { accept; }", first: "then"},
		{name: "from-and-then", body: "from { protocol bgp; } then { accept; }", first: "from"},
		{name: "packed-multi-key", body: "then local-preference 200 accept;", first: "then"},
		{name: "multi-key-block-mutation-killer", body: "then accept { }", first: "then"},
		{name: "multi-key-compact-block-mutation-killer", body: "T from protocol bgp { }", first: "T"},
		{name: "multi-key-from", body: "from protocol bgp;", first: "from"},
		{name: "empty-term", body: "", first: ""},
		{name: "leaf-body-token", body: "foo;", first: "foo"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(namelessPolicyTermTree12521(t, tc.body))
			if err == nil {
				t.Fatalf("nameless `term { %s }` committed cleanly, want strict reject", tc.body)
			}
			for _, want := range []string{
				"policy-statement \"P\"", "nameless",
				"starting with " + `"` + tc.first + `"`,
				"#12521", "give every term an explicit name",
			} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("error = %q, want diagnostic containing %q", err, want)
				}
			}
		})
	}
}

func TestPolicyNamelessTermLenientWarnsAndNeutralizes12521(t *testing.T) {
	for _, tc := range []struct {
		name  string
		body  string
		first string
	}{
		{name: "then-accept", body: "then accept;", first: "then"},
		{name: "then-reject", body: "then reject;", first: "then"},
		{name: "from-and-then", body: "from { protocol static; } then accept;", first: "from"},
		{name: "packed-local-preference", body: "then local-preference 200 accept;", first: "then"},
		{name: "multiple-then-statements", body: "then accept; then reject;", first: "then"},
		{name: "leaf-body-token", body: "foo;", first: "foo"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfigLenient(namelessPolicyTermTree12521(t, tc.body))
			if err != nil {
				t.Fatalf("lenient compile must boot: %v", err)
			}
			warnings := strings.Join(cfg.Warnings, "\n")
			for _, want := range []string{
				"policy-statement \"P\"", "nameless",
				"starting with " + `"` + tc.first + `"`, "#12521",
			} {
				if !strings.Contains(warnings, want) {
					t.Fatalf("warnings = %q, want diagnostic containing %q", warnings, want)
				}
			}
			ps := cfg.PolicyOptions.PolicyStatements["P"]
			if ps == nil || len(ps.Terms) != 1 {
				t.Fatalf("lenient compile terms = %#v, want one neutralized term", ps)
			}
			term := ps.Terms[0]
			if !term.nameless || term.Action != "" ||
				len(term.FromProtocols) != 0 || term.HasLocalPreference ||
				len(term.RouteFilters) != 0 || len(term.PrefixList) != 0 {
				t.Fatalf("lenient term = %#v, want one nameless neutral placeholder", term)
			}
		})
	}
}

func TestPolicyNamelessPlaceholderDoesNotReplaceNamedTerm12521(t *testing.T) {
	cfg, err := CompileConfigLenient(hierTree(t, `policy-options {
    policy-statement P {
        term { then accept; }
        term then { then reject; }
    }
}`))
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	ps := cfg.PolicyOptions.PolicyStatements["P"]
	if ps == nil || len(ps.Terms) != 2 {
		t.Fatalf("compiled terms = %#v, want nameless placeholder plus named term", ps)
	}
	if ps.Terms[0].Action != "" || ps.Terms[1].Name != "then" || ps.Terms[1].Action != "reject" {
		t.Fatalf("compiled terms = %#v, want named term then reject preserved", ps.Terms)
	}
}

func TestPolicyNamelessPlaceholderDoesNotReplaceNamedTermAcrossRoots12521(t *testing.T) {
	tree := hierTree(t, `policy-options {
    policy-statement P {
        term { then accept; }
    }
}
policy-options {
    policy-statement P {
        term then { then reject; }
    }
}`)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	ps := cfg.PolicyOptions.PolicyStatements["P"]
	if ps == nil || len(ps.Terms) != 2 {
		t.Fatalf("compiled terms = %#v, want placeholder plus named term", ps)
	}
	if ps.Terms[0].Action != "" || ps.Terms[1].Name != "then" || ps.Terms[1].Action != "reject" {
		t.Fatalf("compiled terms = %#v, want named term then reject preserved", ps.Terms)
	}
}

func TestPolicyNamedTermStillCompiles12521(t *testing.T) {
	cfg, err := CompileConfig(hierTree(t, `policy-options {
    policy-statement P {
        term T { then accept; }
    }
}`))
	if err != nil {
		t.Fatalf("named policy term must remain valid: %v", err)
	}
	ps := cfg.PolicyOptions.PolicyStatements["P"]
	if ps == nil || len(ps.Terms) != 1 || ps.Terms[0].Name != "T" || ps.Terms[0].Action != "accept" {
		t.Fatalf("named policy statement = %#v, want term T accept", ps)
	}
}

func TestPolicyNamedNestedTermStillCompiles12521(t *testing.T) {
	cfg, err := CompileConfig(hierTree(t, `policy-options {
    policy-statement P {
        term { T { then accept; } }
    }
}`))
	if err != nil {
		t.Fatalf("named nested policy term must remain valid: %v", err)
	}
	ps := cfg.PolicyOptions.PolicyStatements["P"]
	if ps == nil || len(ps.Terms) != 1 || ps.Terms[0].Name != "T" || ps.Terms[0].Action != "accept" {
		t.Fatalf("named nested policy statement = %#v, want term T accept", ps)
	}
}

func TestPolicyNamelessTermInAppliedGroupRejected12521(t *testing.T) {
	tree := hierTree(t, `groups {
    G {
        policy-options {
            policy-statement P {
                term { then { reject; } }
            }
        }
    }
}
apply-groups G;`)
	_, err := CompileConfig(tree)
	if err == nil || !strings.Contains(err.Error(), "#12521") {
		t.Fatalf("CompileConfig applied-group error = %v, want strict #12521 rejection", err)
	}
}

func TestPolicyExplicitFlatSetTermStillCompiles12521(t *testing.T) {
	tree := &ConfigTree{}
	path, err := ParseSetCommand("set policy-options policy-statement P term T then accept")
	if err != nil {
		t.Fatalf("ParseSetCommand: %v", err)
	}
	if err := tree.SetPath(path); err != nil {
		t.Fatalf("SetPath: %v", err)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("explicit flat-set term must remain valid: %v", err)
	}
	ps := cfg.PolicyOptions.PolicyStatements["P"]
	if ps == nil || len(ps.Terms) != 1 || ps.Terms[0].Name != "T" || ps.Terms[0].Action != "accept" {
		t.Fatalf("flat-set policy statement = %#v, want term T accept", ps)
	}
}

func TestPolicyNamelessMixedContainerDoesNotLowerNestedTerm12521(t *testing.T) {
	tree := hierTree(t, `policy-options {
    policy-statement EXPORT-STATIC {
        term { T { from { protocol static; } then accept; } then reject; }
    }
}`)
	if _, err := CompileConfig(tree); err == nil || !strings.Contains(err.Error(), "#12521") {
		t.Fatalf("strict mixed-container compile error = %v, want #12521 rejection", err)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant mixed-container compile: %v", err)
	}
	ps := cfg.PolicyOptions.PolicyStatements["EXPORT-STATIC"]
	if ps == nil || len(ps.Terms) != 1 {
		t.Fatalf("compiled mixed-container terms = %#v, want one neutral marker", ps)
	}
	term := ps.Terms[0]
	if !term.nameless || term.Name != "then" || term.Action != "" || len(term.FromProtocols) != 0 {
		t.Fatalf("compiled mixed-container term = %#v, want only neutral malformed body", term)
	}
	warnings := strings.Join(cfg.Warnings, "\n")
	if !strings.Contains(warnings, "#12521") {
		t.Fatalf("tolerant mixed-container warnings = %q, want #12521", cfg.Warnings)
	}
}

func TestPolicyNamedNestedTermWarnsOnlyOnTolerantPath12521(t *testing.T) {
	tree := hierTree(t, `policy-options {
    policy-statement P {
        term { T { then accept; } }
    }
}`)
	strict, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict nested-term compile: %v", err)
	}
	if strings.Contains(strings.Join(strict.Warnings, "\n"), "#12521") {
		t.Fatalf("strict nested-term warnings = %q, want none for #12521", strict.Warnings)
	}
	tolerant, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant nested-term compile: %v", err)
	}
	ps := tolerant.PolicyOptions.PolicyStatements["P"]
	if ps == nil || len(ps.Terms) != 1 || ps.Terms[0].Name != "T" || ps.Terms[0].Action != "accept" {
		t.Fatalf("tolerant nested-term compile = %#v, want T accept", ps)
	}
	warnings := strings.Join(tolerant.Warnings, "\n")
	for _, want := range []string{`policy-statement "P"`, `term "T"`, "#12521"} {
		if !strings.Contains(warnings, want) {
			t.Fatalf("tolerant nested-term warnings = %q, want %q", warnings, want)
		}
	}
}

func TestPolicyNamelessTolerantWarnsForEveryTermInStableOrder12521(t *testing.T) {
	tree := hierTree(t, `policy-options {
    policy-statement C { term { then reject; } }
    policy-statement A {
        term { then accept; }
        term { from protocol static; }
    }
}
policy-options {
    policy-statement B { term { then accept; } }
}`)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	var got []string
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "#12521") && strings.Contains(warning, "nameless") {
			got = append(got, warning)
		}
	}
	if len(got) != 4 {
		t.Fatalf("#12521 nameless warnings = %q, want 4 diagnostics", got)
	}
	wantPolicies := []string{`policy-statement "A"`, `policy-statement "A"`, `policy-statement "B"`, `policy-statement "C"`}
	wantFirst := []string{"then", "from", "", ""}
	for i, item := range got {
		if !strings.Contains(item, wantPolicies[i]) ||
			(wantFirst[i] != "" && !strings.Contains(item, `starting with "`+wantFirst[i]+`"`)) {
			t.Fatalf("#12521 warnings = %q, want deterministic A(term order), B, C", got)
		}
	}
}

func TestPolicyEmptyNamedTermIsPreserved12521(t *testing.T) {
	tree := hierTree(t, `policy-options {
    policy-statement P { term "" { then reject; } }
}`)
	for _, compile := range []struct {
		name string
		fn   func(*ConfigTree) (*Config, error)
	}{
		{name: "strict", fn: CompileConfig},
		{name: "tolerant", fn: CompileConfigLenient},
	} {
		t.Run(compile.name, func(t *testing.T) {
			cfg, err := compile.fn(tree)
			if err != nil {
				t.Fatalf("compile empty named term: %v", err)
			}
			ps := cfg.PolicyOptions.PolicyStatements["P"]
			if ps == nil || len(ps.Terms) != 1 || ps.Terms[0].Name != "" || ps.Terms[0].Action != "reject" {
				t.Fatalf("empty named term = %#v, want one empty-name reject term", ps)
			}
		})
	}
}
