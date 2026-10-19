package config

import (
	"strings"
	"testing"
)

// #15200 (A07-02): `source-address-excluded` / `destination-address-excluded`
// are boolean modifiers with no operand in Junos. compilePolicy sets the flag
// off the leaf name alone and ignores any Keys[1:]/children, so
// `match source-address-excluded <x>` silently dropped <x> with no warning
// or poison on every path — including strict, where #9878's closed-world
// schema should have caught it (the schema declares these leaves with no
// args/children, but SchemaValidate is not consulted by CompileConfig and
// the tolerant path only slog.Warns schema errors). The fix treats any
// operand under `*-address-excluded` as dropped content: strict rejects,
// tolerant warns and poisons via LenientContentDropped.

func excludedOperandPolicy(t *testing.T, cfg *Config, name string) *Policy {
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

func TestExcludedOperandRejectedStrict15200(t *testing.T) {
	cases := []struct {
		name string
		tree func(t *testing.T) *ConfigTree
		leaf string
	}{
		{
			name: "zone-pair source hierarchical operand",
			tree: func(t *testing.T) *ConfigTree {
				return buildValuelessMatchHierTree(t, zonePairHier(
					`source-address any; source-address-excluded bad-value; destination-address any; application any;`))
			},
			leaf: "source-address-excluded",
		},
		{
			name: "zone-pair destination hierarchical operand",
			tree: func(t *testing.T) *ConfigTree {
				return buildValuelessMatchHierTree(t, zonePairHier(
					`source-address any; destination-address any; destination-address-excluded bad-value; application any;`))
			},
			leaf: "destination-address-excluded",
		},
		{
			name: "zone-pair source flat-set operand",
			tree: func(t *testing.T) *ConfigTree {
				return buildValuelessMatchFlatTree(t, []string{
					"set security zones security-zone trust",
					"set security zones security-zone untrust",
					"set security policies from-zone trust to-zone untrust policy p match source-address any",
					"set security policies from-zone trust to-zone untrust policy p match source-address-excluded bad-value",
					"set security policies from-zone trust to-zone untrust policy p match destination-address any",
					"set security policies from-zone trust to-zone untrust policy p match application any",
					"set security policies from-zone trust to-zone untrust policy p then permit",
				})
			},
			leaf: "source-address-excluded",
		},
		{
			name: "zone-pair destination flat-set operand",
			tree: func(t *testing.T) *ConfigTree {
				return buildValuelessMatchFlatTree(t, []string{
					"set security zones security-zone trust",
					"set security zones security-zone untrust",
					"set security policies from-zone trust to-zone untrust policy p match source-address any",
					"set security policies from-zone trust to-zone untrust policy p match destination-address any",
					"set security policies from-zone trust to-zone untrust policy p match destination-address-excluded bad-value",
					"set security policies from-zone trust to-zone untrust policy p match application any",
					"set security policies from-zone trust to-zone untrust policy p then permit",
				})
			},
			leaf: "destination-address-excluded",
		},
		{
			name: "zone-pair block child operand",
			tree: func(t *testing.T) *ConfigTree {
				return buildValuelessMatchHierTree(t, zonePairHier(
					`source-address any; source-address-excluded { bad-value; } destination-address any; application any;`))
			},
			leaf: "source-address-excluded",
		},
		{
			name: "global destination hierarchical operand",
			tree: func(t *testing.T) *ConfigTree {
				return buildValuelessMatchHierTree(t, globalHier(
					`source-address any; destination-address any; destination-address-excluded bad-value; application any;`))
			},
			leaf: "destination-address-excluded",
		},
		{
			name: "global source flat-set operand",
			tree: func(t *testing.T) *ConfigTree {
				return buildValuelessMatchFlatTree(t, []string{
					"set security policies global policy g match source-address any",
					"set security policies global policy g match source-address-excluded bad-value",
					"set security policies global policy g match destination-address any",
					"set security policies global policy g match application any",
					"set security policies global policy g then permit",
				})
			},
			leaf: "source-address-excluded",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(tc.tree(t))
			if err == nil {
				t.Fatalf("strict CompileConfig accepted operand under %q; want #15200 rejection", tc.leaf)
			}
			if !strings.Contains(err.Error(), "#15200") {
				t.Fatalf("error = %q, want #15200 marker", err.Error())
			}
			if !strings.Contains(err.Error(), tc.leaf) {
				t.Fatalf("error = %q, want leaf %q named", err.Error(), tc.leaf)
			}
			if !strings.Contains(err.Error(), "bad-value") {
				t.Fatalf("error = %q, want dropped operand %q named", err.Error(), "bad-value")
			}
		})
	}
}

func TestExcludedOperandLenientWarnsAndPoisons15200(t *testing.T) {
	cases := []struct {
		name string
		tree func(t *testing.T) *ConfigTree
		pol  string
		leaf string
	}{
		{
			name: "zone-pair source hierarchical",
			tree: func(t *testing.T) *ConfigTree {
				return buildValuelessMatchHierTree(t, zonePairHier(
					`source-address any; source-address-excluded bad-value; destination-address any; application any;`))
			},
			pol: "p", leaf: "source-address-excluded",
		},
		{
			name: "zone-pair destination flat-set",
			tree: func(t *testing.T) *ConfigTree {
				return buildValuelessMatchFlatTree(t, []string{
					"set security zones security-zone trust",
					"set security zones security-zone untrust",
					"set security policies from-zone trust to-zone untrust policy p match source-address any",
					"set security policies from-zone trust to-zone untrust policy p match destination-address any",
					"set security policies from-zone trust to-zone untrust policy p match destination-address-excluded bad-value",
					"set security policies from-zone trust to-zone untrust policy p match application any",
					"set security policies from-zone trust to-zone untrust policy p then permit",
				})
			},
			pol: "p", leaf: "destination-address-excluded",
		},
		{
			name: "global source hierarchical",
			tree: func(t *testing.T) *ConfigTree {
				return buildValuelessMatchHierTree(t, globalHier(
					`source-address any; source-address-excluded bad-value; destination-address any; application any;`))
			},
			pol: "g", leaf: "source-address-excluded",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfigLenient(tc.tree(t))
			if err != nil {
				t.Fatalf("lenient compile must still boot: %v", err)
			}
			pol := excludedOperandPolicy(t, cfg, tc.pol)
			if !pol.LenientContentDropped {
				t.Fatalf("policy %q with operand under %q not poisoned (LenientContentDropped=false)", tc.pol, tc.leaf)
			}
			joined := strings.Join(cfg.Warnings, "\n")
			if !strings.Contains(joined, "#15200") || !strings.Contains(joined, tc.leaf) || !strings.Contains(joined, "bad-value") {
				t.Fatalf("warnings = %q, want #15200 warning naming %q and bad-value", joined, tc.leaf)
			}
		})
	}
}

// TestExcludedOperandBareModifierStaysClean15200 is the control: a bare
// `*-address-excluded` with no operand is valid Junos and must stay
// unpoisoned with the flag set, on both strict and lenient paths.
func TestExcludedOperandBareModifierStaysClean15200(t *testing.T) {
	tree := buildValuelessMatchHierTree(t, zonePairHier(
		`source-address any; source-address-excluded; destination-address any; destination-address-excluded; application any;`))
	for _, compile := range []struct {
		name string
		fn   func(*ConfigTree) (*Config, error)
	}{
		{"strict", CompileConfig},
		{"lenient", CompileConfigLenient},
	} {
		cfg, err := compile.fn(tree)
		if err != nil {
			t.Fatalf("%s compile rejected bare excluded modifiers: %v", compile.name, err)
		}
		pol := excludedOperandPolicy(t, cfg, "p")
		if pol.LenientContentDropped {
			t.Fatalf("%s: bare excluded modifiers poisoned", compile.name)
		}
		if !pol.Match.SourceAddressExcluded || !pol.Match.DestinationAddressExcluded {
			t.Fatalf("%s: excluded flags not set: %+v", compile.name, pol.Match)
		}
		if strings.Contains(strings.Join(cfg.Warnings, "\n"), "#15200") {
			t.Fatalf("%s: bare excluded modifiers warned #15200: %v", compile.name, cfg.Warnings)
		}
	}
}
