package config

import (
	"strings"
	"testing"
)

// #12923: two apply-groups carrying different default-policy actions merged
// first-applied-wins with no diagnostic. The flat leaf spelling never
// materialized a stanza pair for #11821/#12821 to see, so a permit-first
// pair silently failed open.

// twoGroupsDefaultPolicyConfig12923 builds GA/GB with their default-policy
// spellings and the main-tree tail; GA is always applied first.
func twoGroupsDefaultPolicyConfig12923(gaStanza, gbStanza, tail string) string {
	return "groups {\n" +
		"    GA { security { policies { " + gaStanza + " } } }\n" +
		"    GB { security { policies { " + gbStanza + " } } }\n" +
		"}\n" +
		"apply-groups [ GA GB ];\n" +
		tail
}

func TestTwoApplyGroupsDefaultPolicyConflict12923(t *testing.T) {
	cases := []struct {
		name    string
		text    string
		errSub  []string // strict error substrings
		warnSub []string // lenient warning substrings (one warning)
	}{
		{
			name: "flat permit then flat deny",
			text: twoGroupsDefaultPolicyConfig12923(
				"default-policy permit-all;", "default-policy deny-all;",
				"security { policies { } }\n"),
			errSub:  []string{"default-policy", "permit-all", "deny-all", "#11821"},
			warnSub: []string{"default-policy", "permit-all", "deny-all", "#11821"},
		},
		{
			name: "flat deny then flat permit (order independent)",
			text: twoGroupsDefaultPolicyConfig12923(
				"default-policy deny-all;", "default-policy permit-all;",
				"security { policies { } }\n"),
			errSub:  []string{"default-policy", "deny-all", "permit-all", "#11821"},
			warnSub: []string{"default-policy", "deny-all", "permit-all", "#11821"},
		},
		{
			name: "flat permit then block deny",
			text: twoGroupsDefaultPolicyConfig12923(
				"default-policy permit-all;", "default-policy { deny-all; }",
				"security { policies { } }\n"),
			errSub:  []string{"default-policy", "permit-all", "deny-all", "#11821"},
			warnSub: []string{"default-policy", "permit-all", "deny-all", "#11821"},
		},
		{
			name: "block permit then flat deny",
			text: twoGroupsDefaultPolicyConfig12923(
				"default-policy { permit-all; }", "default-policy deny-all;",
				"security { policies { } }\n"),
			errSub:  []string{"default-policy", "permit-all", "deny-all", "#11821"},
			warnSub: []string{"default-policy", "permit-all", "deny-all", "#11821"},
		},
		{
			name: "block permit then block deny",
			text: twoGroupsDefaultPolicyConfig12923(
				"default-policy { permit-all; }", "default-policy { deny-all; }",
				"security { policies { } }\n"),
			errSub:  []string{"default-policy", "2 children"},
			warnSub: []string{"default-policy", "#11367"},
		},
		{
			name: "no security stanza in main tree",
			text: twoGroupsDefaultPolicyConfig12923(
				"default-policy permit-all;", "default-policy deny-all;", ""),
			errSub:  []string{"default-policy", "permit-all", "deny-all", "#11821"},
			warnSub: []string{"default-policy", "permit-all", "deny-all", "#11821"},
		},
		{
			name: "apply-groups inside the policies block",
			text: "groups {\n" +
				"    GA { security { policies { default-policy permit-all; } } }\n" +
				"    GB { security { policies { default-policy deny-all; } } }\n" +
				"}\n" +
				"security { policies { apply-groups [ GA GB ]; } }\n",
			errSub:  []string{"default-policy", "permit-all", "deny-all", "#11821"},
			warnSub: []string{"default-policy", "permit-all", "deny-all", "#11821"},
		},
		{
			name: "nested groups flat over flat",
			text: "groups {\n" +
				"    INNER { security { policies { default-policy deny-all; } } }\n" +
				"    OUTER { security { policies { default-policy permit-all; } } apply-groups INNER; }\n" +
				"}\n" +
				"apply-groups OUTER;\n" +
				"security { policies { } }\n",
			errSub:  []string{"default-policy", "permit-all", "deny-all", "#11821"},
			warnSub: []string{"default-policy", "permit-all", "deny-all", "#11821"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(defaultPolicyTree11821(t, tc.text))
			if err == nil {
				t.Fatal("strict compile accepted two apply-groups with conflicting default-policy actions")
			}
			for _, want := range tc.errSub {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("strict error %q does not name %q", err, want)
				}
			}
			cfg, err := CompileConfigLenient(defaultPolicyTree11821(t, tc.text))
			if err != nil {
				t.Fatalf("lenient compile: %v", err)
			}
			if cfg.Security.DefaultPolicy != PolicyDeny {
				t.Fatalf("lenient conflicting groups = %v, want deny (fail-closed)", cfg.Security.DefaultPolicy)
			}
			found := false
			for _, w := range cfg.Warnings {
				matched := true
				for _, want := range tc.warnSub {
					if !strings.Contains(w, want) {
						matched = false
						break
					}
				}
				if matched {
					found = true
				}
			}
			if !found {
				t.Fatalf("lenient compile omitted conflict warning naming %v: %v", tc.warnSub, cfg.Warnings)
			}
		})
	}
}

// The merged tree must materialize both stanzas so the #11821/#12821 gates
// can see the pair instead of resolving it by group order.
func TestTwoApplyGroupsDefaultPolicyMaterializesBothStanzas12923(t *testing.T) {
	text := twoGroupsDefaultPolicyConfig12923(
		"default-policy permit-all;", "default-policy deny-all;",
		"security { policies { } }\n")
	tree := defaultPolicyTree11821(t, text)
	if err := tree.ExpandGroups(); err != nil {
		t.Fatalf("ExpandGroups: %v", err)
	}
	stanzas := 0
	actions := map[string]bool{}
	for _, security := range tree.FindChildren("security") {
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
		t.Fatalf("expanded tree carries %d stanzas %v, want both permit-all and deny-all", stanzas, actions)
	}
}

// Identical actions across two groups stay legal in every shape mix.
func TestTwoApplyGroupsDefaultPolicySameAction12923(t *testing.T) {
	cases := []struct {
		name string
		text string
		want PolicyAction
	}{
		{"flat over flat", twoGroupsDefaultPolicyConfig12923(
			"default-policy permit-all;", "default-policy permit-all;",
			"security { policies { } }\n"), PolicyPermit},
		{"flat over block", twoGroupsDefaultPolicyConfig12923(
			"default-policy deny-all;", "default-policy { deny-all; }",
			"security { policies { } }\n"), PolicyDeny},
		{"block over flat", twoGroupsDefaultPolicyConfig12923(
			"default-policy { reject-all; }", "default-policy reject-all;",
			"security { policies { } }\n"), PolicyReject},
		{"nested same action", "groups {\n" +
			"    INNER { security { policies { default-policy deny-all; } } }\n" +
			"    OUTER { security { policies { default-policy deny-all; } } apply-groups INNER; }\n" +
			"}\n" +
			"apply-groups OUTER;\n" +
			"security { policies { } }\n", PolicyDeny},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfig(defaultPolicyTree11821(t, tc.text))
			if err != nil {
				t.Fatalf("strict compile rejected identical group default-policy actions: %v", err)
			}
			if cfg.Security.DefaultPolicy != tc.want {
				t.Fatalf("default-policy = %v, want %v", cfg.Security.DefaultPolicy, tc.want)
			}
			cfg2, err := CompileConfigLenient(defaultPolicyTree11821(t, tc.text))
			if err != nil {
				t.Fatalf("lenient compile: %v", err)
			}
			if cfg2.Security.DefaultPolicy != tc.want {
				t.Fatalf("lenient default-policy = %v, want %v", cfg2.Security.DefaultPolicy, tc.want)
			}
			for _, w := range cfg2.Warnings {
				if strings.Contains(w, "default-policy") {
					t.Fatalf("identical group actions produced default-policy warning: %q", w)
				}
			}
		})
	}
}

// An authored inline stanza still overrides both groups silently (#12823
// doctrine) — only group-adopted peers form a conflict pair.
func TestTwoApplyGroupsDefaultPolicyInlineOverrideStays12923(t *testing.T) {
	cases := []struct {
		name   string
		inline string
		want   PolicyAction
	}{
		{"flat inline", "default-policy reject-all;", PolicyReject},
		{"block inline", "default-policy { reject-all; }", PolicyReject},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			text := twoGroupsDefaultPolicyConfig12923(
				"default-policy permit-all;", "default-policy deny-all;",
				"security { policies { "+tc.inline+" } }\n")
			cfg, err := CompileConfig(defaultPolicyTree11821(t, text))
			if err != nil {
				t.Fatalf("strict compile rejected inline override over two groups: %v", err)
			}
			if cfg.Security.DefaultPolicy != tc.want {
				t.Fatalf("default-policy = %v, want inline value %v", cfg.Security.DefaultPolicy, tc.want)
			}
			cfg2, err := CompileConfigLenient(defaultPolicyTree11821(t, text))
			if err != nil {
				t.Fatalf("lenient compile: %v", err)
			}
			if cfg2.Security.DefaultPolicy != tc.want {
				t.Fatalf("lenient default-policy = %v, want %v", cfg2.Security.DefaultPolicy, tc.want)
			}
			for _, w := range cfg2.Warnings {
				if strings.Contains(w, "default-policy") &&
					(strings.Contains(w, "#11367") || strings.Contains(w, "#11821") || strings.Contains(w, "#12821")) {
					t.Fatalf("inline override over groups warned: %q", w)
				}
			}
		})
	}
}
