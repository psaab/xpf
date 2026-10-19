package config

import (
	"strings"
	"testing"
)

// #15662: Junos `match application-excluded` was omitted from the policy
// match schema, unsupportedPolicyMatchLeaves, and compilePolicy. In
// flat-set form after `application <name>` the token collapsed onto the
// application leaf as a bogus application value (strict misdiagnosed it as
// an undefined application; tolerant compiled it as a positive value); as a
// standalone hierarchical/flat leaf it was silently dropped on tolerant load,
// turning a negated match into a positive permit.
//
// The fix registers `application-excluded` as a sibling boundary in the
// policy `match` schemas and in unsupportedPolicyMatchLeaves, so both the
// standalone and collapsed occurrences are deterministically rejected on
// strict commit (#3113, naming application-excluded, not #3144) and warned +
// poisoned (LenientContentDropped) on tolerant load.

func appExcludedPolicy(t *testing.T, cfg *Config, name string) *Policy {
	t.Helper()
	for _, zpp := range cfg.Security.Policies {
		for _, p := range zpp.Policies {
			if p.Name == name {
				return p
			}
		}
	}
	for _, p := range cfg.Security.GlobalPolicies {
		if p.Name == name {
			return p
		}
	}
	t.Fatalf("policy %q not found", name)
	return nil
}

func TestApplicationExcludedRejectedStrict15662(t *testing.T) {
	cases := []struct {
		name string
		tree func(t *testing.T) *ConfigTree
	}{
		{
			name: "zone-pair hierarchical standalone",
			tree: func(t *testing.T) *ConfigTree {
				return buildValuelessMatchHierTree(t, zonePairHier(
					`source-address any; destination-address any; application junos-http; application-excluded;`))
			},
		},
		{
			name: "global hierarchical standalone",
			tree: func(t *testing.T) *ConfigTree {
				return buildValuelessMatchHierTree(t, globalHier(
					`source-address any; destination-address any; application junos-http; application-excluded;`))
			},
		},
		{
			name: "zone-pair flat-set standalone",
			tree: func(t *testing.T) *ConfigTree {
				return buildValuelessMatchFlatTree(t, []string{
					"set security zones security-zone trust",
					"set security zones security-zone untrust",
					"set security policies from-zone trust to-zone untrust policy p match source-address any",
					"set security policies from-zone trust to-zone untrust policy p match destination-address any",
					"set security policies from-zone trust to-zone untrust policy p match application junos-http",
					"set security policies from-zone trust to-zone untrust policy p match application-excluded",
					"set security policies from-zone trust to-zone untrust policy p then permit",
				})
			},
		},
		{
			name: "zone-pair flat-set collapsed after application",
			tree: func(t *testing.T) *ConfigTree {
				return buildValuelessMatchFlatTree(t, []string{
					"set security zones security-zone trust",
					"set security zones security-zone untrust",
					"set security policies from-zone trust to-zone untrust policy p match source-address any",
					"set security policies from-zone trust to-zone untrust policy p match destination-address any",
					"set security policies from-zone trust to-zone untrust policy p match application junos-http application-excluded",
					"set security policies from-zone trust to-zone untrust policy p then permit",
				})
			},
		},
		{
			name: "global flat-set collapsed after application",
			tree: func(t *testing.T) *ConfigTree {
				return buildValuelessMatchFlatTree(t, []string{
					"set security policies global policy g match source-address any",
					"set security policies global policy g match destination-address any",
					"set security policies global policy g match application junos-http application-excluded",
					"set security policies global policy g then permit",
				})
			},
		},
		{
			name: "zone-pair bracketed application list carrying application-excluded",
			tree: func(t *testing.T) *ConfigTree {
				return buildValuelessMatchFlatTree(t, []string{
					"set security zones security-zone trust",
					"set security zones security-zone untrust",
					"set security policies from-zone trust to-zone untrust policy p match source-address any",
					"set security policies from-zone trust to-zone untrust policy p match destination-address any",
					"set security policies from-zone trust to-zone untrust policy p match application [ junos-http application-excluded ]",
					"set security policies from-zone trust to-zone untrust policy p then permit",
				})
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(tc.tree(t))
			if err == nil {
				t.Fatalf("strict CompileConfig accepted application-excluded; want #3113 rejection")
			}
			if !strings.Contains(err.Error(), "#3113") {
				t.Fatalf("error = %q, want #3113 marker (not a #3144 undefined-application misdiagnosis)", err.Error())
			}
			if !strings.Contains(err.Error(), `"application-excluded"`) {
				t.Fatalf("error = %q, want application-excluded leaf named", err.Error())
			}
		})
	}
}

func TestApplicationExcludedLenientWarnsAndPoisons15662(t *testing.T) {
	cases := []struct {
		name string
		tree func(t *testing.T) *ConfigTree
		pol  string
	}{
		{
			name: "zone-pair hierarchical standalone",
			tree: func(t *testing.T) *ConfigTree {
				return buildValuelessMatchHierTree(t, zonePairHier(
					`source-address any; destination-address any; application junos-http; application-excluded;`))
			},
			pol: "p",
		},
		{
			name: "global hierarchical standalone",
			tree: func(t *testing.T) *ConfigTree {
				return buildValuelessMatchHierTree(t, globalHier(
					`source-address any; destination-address any; application junos-http; application-excluded;`))
			},
			pol: "g",
		},
		{
			name: "zone-pair flat-set collapsed after application",
			tree: func(t *testing.T) *ConfigTree {
				return buildValuelessMatchFlatTree(t, []string{
					"set security zones security-zone trust",
					"set security zones security-zone untrust",
					"set security policies from-zone trust to-zone untrust policy p match source-address any",
					"set security policies from-zone trust to-zone untrust policy p match destination-address any",
					"set security policies from-zone trust to-zone untrust policy p match application junos-http application-excluded",
					"set security policies from-zone trust to-zone untrust policy p then permit",
				})
			},
			pol: "p",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfigLenient(tc.tree(t))
			if err != nil {
				t.Fatalf("lenient compile must still boot: %v", err)
			}
			pol := appExcludedPolicy(t, cfg, tc.pol)
			if !pol.LenientContentDropped {
				t.Fatalf("policy %q with application-excluded not poisoned (LenientContentDropped=false); negated match would compile as positive", tc.pol)
			}
			joined := strings.Join(cfg.Warnings, "\n")
			if !strings.Contains(joined, "#3113") || !strings.Contains(joined, "application-excluded") {
				t.Fatalf("warnings = %q, want #3113 warning naming application-excluded", joined)
			}
		})
	}
}

// TestApplicationExcludedSchemaRecognizesSibling15662 pins the schema side:
// `application-excluded` must validate as a known flag leaf under both policy
// match schemas (so SetPath stops multi-value consumption at it and
// SchemaValidate does not report an unknown keyword).
func TestApplicationExcludedSchemaRecognizesSibling15662(t *testing.T) {
	for _, cmds := range [][]string{
		{
			"set security zones security-zone trust",
			"set security zones security-zone untrust",
			"set security policies from-zone trust to-zone untrust policy p match source-address any",
			"set security policies from-zone trust to-zone untrust policy p match destination-address any",
			"set security policies from-zone trust to-zone untrust policy p match application junos-http",
			"set security policies from-zone trust to-zone untrust policy p match application-excluded",
			"set security policies from-zone trust to-zone untrust policy p then permit",
		},
		{
			"set security policies global policy g match source-address any",
			"set security policies global policy g match destination-address any",
			"set security policies global policy g match application junos-http",
			"set security policies global policy g match application-excluded",
			"set security policies global policy g then permit",
		},
	} {
		tree := buildValuelessMatchFlatTree(t, cmds)
		if err := SchemaValidate(tree, nil); err != nil {
			t.Fatalf("SchemaValidate rejected application-excluded as unknown: %v", err)
		}
	}
}
