package config

import (
	"strings"
	"testing"
)

// #15031: the generic-compile ${node} fallback used to expand without
// vars first and, on the undefined-"${node}" error, retry with
// node=node0 vars on the SAME tree. The failed first pass had already
// merged every group applied before the ${node} reference and stripped
// its apply-groups node, so the retry never re-merged it and its
// group provenance (#12823/#12923) was lost: a later group's
// default-policy met the first group's stanza as if it were authored
// inline, took the inline-wins override, and the conflicting pair the
// #11821/#11367/#12821 gates judge never materialized. A standalone
// (generic / check-config) compile therefore accepted — permit-first,
// fail-open — a default-policy conflict the fresh node0 compile
// (CompileConfigForNode(tree, 0)) rejects.
//
// nodeFallbackConflict15031 builds the witness: GA (applied first,
// permit) plus the node0 group selected through "${node}" (deny). GA
// must precede the ${node} reference so the doomed plain pass merges
// it before failing.
func nodeFallbackConflict15031(gaStanza, nodeStanza string) string {
	return "groups {\n" +
		"    GA { security { policies { " + gaStanza + " } } }\n" +
		"    node0 { security { policies { " + nodeStanza + " } } }\n" +
		"}\n" +
		"apply-groups [ GA \"${node}\" ];\n" +
		"security { policies { } }\n"
}

func TestNodeFallbackDefaultPolicyConflictRejected15031(t *testing.T) {
	cases := []struct {
		name    string
		text    string
		errSub  []string
		warnSub []string
	}{
		{
			name:    "flat permit then flat deny via node var",
			text:    nodeFallbackConflict15031("default-policy permit-all;", "default-policy deny-all;"),
			errSub:  []string{"default-policy", "permit-all", "deny-all", "#11821"},
			warnSub: []string{"default-policy", "permit-all", "deny-all", "#11821"},
		},
		{
			name:    "flat deny then flat permit via node var (order independent)",
			text:    nodeFallbackConflict15031("default-policy deny-all;", "default-policy permit-all;"),
			errSub:  []string{"default-policy", "deny-all", "permit-all", "#11821"},
			warnSub: []string{"default-policy", "deny-all", "permit-all", "#11821"},
		},
		{
			name:    "block permit then block deny via node var",
			text:    nodeFallbackConflict15031("default-policy { permit-all; }", "default-policy { deny-all; }"),
			errSub:  []string{"default-policy", "2 children"},
			warnSub: []string{"default-policy", "#11367"},
		},
		{
			name:    "flat permit then block deny via node var",
			text:    nodeFallbackConflict15031("default-policy permit-all;", "default-policy { deny-all; }"),
			errSub:  []string{"default-policy", "permit-all", "deny-all", "#11821"},
			warnSub: []string{"default-policy", "permit-all", "deny-all", "#11821"},
		},
		{
			name:    "block permit then flat deny via node var",
			text:    nodeFallbackConflict15031("default-policy { permit-all; }", "default-policy deny-all;"),
			errSub:  []string{"default-policy", "permit-all", "deny-all", "#11821"},
			warnSub: []string{"default-policy", "permit-all", "deny-all", "#11821"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The fresh node0 compile is the oracle: it rejects.
			if _, err := CompileConfigForNode(defaultPolicyTree11821(t, tc.text), 0); err == nil {
				t.Fatal("oracle: fresh node0 compile accepted the conflict (test is not exercising the claimed divergence)")
			}
			// Strict generic compile must reject identically.
			_, err := CompileConfig(defaultPolicyTree11821(t, tc.text))
			if err == nil {
				t.Fatal("strict generic compile accepted a ${node}-fallback default-policy conflict the node0 compile rejects (#15031)")
			}
			for _, want := range tc.errSub {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("strict error %q does not name %q", err, want)
				}
			}
			// The fallback warning contract is preserved.
			// (Strict compile errors, so check the warning on lenient.)
			cfg, err := CompileConfigLenient(defaultPolicyTree11821(t, tc.text))
			if err != nil {
				t.Fatalf("lenient generic compile: %v", err)
			}
			if cfg.Security.DefaultPolicy != PolicyDeny {
				t.Fatalf("lenient ${node}-fallback conflict = %v, want deny (fail-closed)", cfg.Security.DefaultPolicy)
			}
			foundConflict, foundFallback := false, false
			for _, w := range cfg.Warnings {
				matched := true
				for _, want := range tc.warnSub {
					if !strings.Contains(w, want) {
						matched = false
						break
					}
				}
				if matched {
					foundConflict = true
				}
				if strings.Contains(w, `apply-groups "${node}" resolved using default node0`) {
					foundFallback = true
				}
			}
			if !foundConflict {
				t.Fatalf("lenient compile omitted conflict warning naming %v: %v", tc.warnSub, cfg.Warnings)
			}
			if !foundFallback {
				t.Fatalf("lenient compile omitted the ${node} node0-fallback warning: %v", cfg.Warnings)
			}
		})
	}
}

// The atomic fallback must produce exactly the fresh node0 expansion:
// both default-policy stanzas materialize for the gates, and the
// expanded trees are Format-identical.
func TestNodeFallbackExpansionMatchesFreshNode015031(t *testing.T) {
	text := nodeFallbackConflict15031("default-policy permit-all;", "default-policy deny-all;")

	fallback := defaultPolicyTree11821(t, text)
	used, err := fallback.ExpandGroupsNodeFallback15031(true)
	if err != nil {
		t.Fatalf("fallback expansion: %v", err)
	}
	if !used {
		t.Fatal("fallback expansion did not report the node0 vars expansion")
	}

	fresh := defaultPolicyTree11821(t, text)
	if err := fresh.ExpandGroupsWithVarsTagged(map[string]string{"node": "node0"}); err != nil {
		t.Fatalf("fresh node0 expansion: %v", err)
	}
	if fallback.Format() != fresh.Format() {
		t.Fatalf("fallback expansion differs from fresh node0 expansion:\nfallback:\n%s\nfresh:\n%s", fallback.Format(), fresh.Format())
	}

	stanzas := 0
	actions := map[string]bool{}
	for _, security := range fallback.FindChildren("security") {
		for _, policies := range security.FindChildren("policies") {
			for _, stanza := range policies.Children {
				if stanza.Name() != "default-policy" {
					continue
				}
				stanzas++
				if action := defaultPolicyAction11821(stanza); action != "" {
					actions[action] = true
				}
			}
		}
	}
	if stanzas != 2 || !actions["permit-all"] || !actions["deny-all"] {
		t.Fatalf("fallback tree carries %d stanzas %v, want both permit-all and deny-all", stanzas, actions)
	}

	// Without a ${node} reference the helper is a plain single pass.
	plain := defaultPolicyTree11821(t, twoGroupsDefaultPolicyConfig12923(
		"default-policy permit-all;", "default-policy deny-all;", "security { policies { } }\n"))
	used, err = plain.ExpandGroupsNodeFallback15031(true)
	if err != nil {
		t.Fatalf("plain expansion: %v", err)
	}
	if used {
		t.Fatal("plain expansion without ${node} reported a node fallback")
	}
}

// Legitimate ${node} configs keep compiling through the generic path:
// identical group actions stay accepted, an authored inline stanza
// still overrides both groups silently, and a benign node0-only group
// resolves to its own value with the fallback warning.
func TestNodeFallbackLegitimateConfigsStayGreen15031(t *testing.T) {
	t.Run("identical actions via node var", func(t *testing.T) {
		text := nodeFallbackConflict15031("default-policy deny-all;", "default-policy { deny-all; }")
		cfg, err := CompileConfig(defaultPolicyTree11821(t, text))
		if err != nil {
			t.Fatalf("strict generic compile rejected identical group actions: %v", err)
		}
		if cfg.Security.DefaultPolicy != PolicyDeny {
			t.Fatalf("default-policy = %v, want deny", cfg.Security.DefaultPolicy)
		}
	})

	t.Run("inline overrides both groups via node var", func(t *testing.T) {
		text := "groups {\n" +
			"    GA { security { policies { default-policy permit-all; } } }\n" +
			"    node0 { security { policies { default-policy deny-all; } } }\n" +
			"}\n" +
			"apply-groups [ GA \"${node}\" ];\n" +
			"security { policies { default-policy reject-all; } }\n"
		cfg, err := CompileConfig(defaultPolicyTree11821(t, text))
		if err != nil {
			t.Fatalf("strict generic compile rejected inline override: %v", err)
		}
		if cfg.Security.DefaultPolicy != PolicyReject {
			t.Fatalf("default-policy = %v, want inline reject", cfg.Security.DefaultPolicy)
		}
	})

	t.Run("benign node0 group resolves with fallback warning", func(t *testing.T) {
		text := "groups {\n" +
			"    node0 { security { policies { default-policy permit-all; } } }\n" +
			"    node1 { security { policies { default-policy deny-all; } } }\n" +
			"}\n" +
			"apply-groups \"${node}\";\n" +
			"security { policies { } }\n"
		cfg, err := CompileConfig(defaultPolicyTree11821(t, text))
		if err != nil {
			t.Fatalf("strict generic compile rejected benign ${node} config: %v", err)
		}
		if cfg.Security.DefaultPolicy != PolicyPermit {
			t.Fatalf("default-policy = %v, want node0 permit", cfg.Security.DefaultPolicy)
		}
		found := false
		for _, w := range cfg.Warnings {
			if strings.Contains(w, `apply-groups "${node}" resolved using default node0`) {
				found = true
			}
		}
		if !found {
			t.Fatalf("generic compile omitted the ${node} fallback warning: %v", cfg.Warnings)
		}
		// The node-aware compile of the same text agrees.
		cfg0, err := CompileConfigForNode(defaultPolicyTree11821(t, text), 0)
		if err != nil {
			t.Fatalf("node0 compile: %v", err)
		}
		if cfg0.Security.DefaultPolicy != cfg.Security.DefaultPolicy {
			t.Fatalf("node0 default-policy %v != generic %v", cfg0.Security.DefaultPolicy, cfg.Security.DefaultPolicy)
		}
	})

	t.Run("genuinely undefined group still rejected by name", func(t *testing.T) {
		text := "groups {\n" +
			"    GA { security { policies { default-policy permit-all; } } }\n" +
			"}\n" +
			"apply-groups [ GA MISSING \"${node}\" ];\n" +
			"security { policies { } }\n"
		_, err := CompileConfig(defaultPolicyTree11821(t, text))
		if err == nil || !strings.Contains(err.Error(), `undefined group "MISSING"`) {
			t.Fatalf("generic compile = %v, want undefined group MISSING rejection", err)
		}
	})
}
