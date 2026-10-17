package config

import (
	"strings"
	"testing"
)

// #14412 (DR13-H5): a credential leaf packed onto a container line after a
// non-scoped head, or spelled case-variant, was invisible to both the schema
// walker (open-world branch ignored leftover Keys) and the #10707 walker
// (descended node.Children only; a packed node has none). The adjacency
// therefore formed unauthenticated on a clean, warning-free commit while
// `show configuration` displayed the authentication the operator wrote.

func parseHier14412(t *testing.T, src string) *ConfigTree {
	t.Helper()
	tree, errs := NewParser(src).Parse()
	if len(errs) > 0 {
		t.Fatalf("Parse: %v", errs)
	}
	return tree
}

func hasWarning14412(cfg *Config, token string) bool {
	if cfg == nil {
		return false
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#10707") && strings.Contains(w, token) {
			return true
		}
	}
	return false
}

var packedCredentialCases14412 = []struct {
	name  string
	src   string
	token string
}{
	{
		name: "ospf interface misplaced after passive",
		src: `protocols { ospf { area 0.0.0.0 {
			interface ge-0/0/0.0 passive authentication-key SECRET14412; } } }`,
		token: "authentication-key",
	},
	{
		name: "ospf area misplaced packed tail",
		src: `protocols { ospf {
			area 0.0.0.0 authentication-key SECRET14412 interface ge-0/0/0.0; } }`,
		token: "authentication-key",
	},
	{
		name: "ospf interface misplaced simple-password after passive",
		src: `protocols { ospf { area 0.0.0.0 {
			interface ge-0/0/0.0 passive simple-password SECRET14412; } } }`,
		token: "simple-password",
	},
	{
		name: "isis interface case-variant packed tail",
		src: `protocols { isis { net 49.0001.0000.0000.0001.00;
			interface ge-0/0/0.0 Authentication-Key SECRET14412 authentication-type md5; } }`,
		token: "Authentication-Key",
	},
	{
		name: "bgp neighbor case-variant packed tail",
		src: `routing-options { autonomous-system 65000; }
			protocols { bgp { group g { type external; peer-as 65001;
			neighbor 192.0.2.1 Authentication-Key SECRET14412; } } }`,
		token: "Authentication-Key",
	},
}

// Strict channel: SchemaValidate must reject naming the dropped token, and
// must never echo the secret value.
func TestPackedTailCredentialStrictReject14412(t *testing.T) {
	for _, tc := range packedCredentialCases14412 {
		t.Run(tc.name, func(t *testing.T) {
			err := SchemaValidate(parseHier14412(t, tc.src), nil)
			if err == nil {
				t.Fatalf("SchemaValidate accepted packed-tail credential %q; want strict reject (#14412)", tc.token)
			}
			if !strings.Contains(err.Error(), tc.token) {
				t.Fatalf("strict error must name dropped token %q, got: %v", tc.token, err)
			}
			if strings.Contains(err.Error(), "SECRET14412") {
				t.Fatalf("strict error must not echo the secret value, got: %v", err)
			}
		})
	}
}

// Lenient/compiler channel: #10707 must warn naming the token (CompileConfig
// surfaces prewalk warnings on both strict and tolerant compiles).
func TestPackedTailCredentialWarns10707_14412(t *testing.T) {
	for _, tc := range packedCredentialCases14412 {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfig(parseHier14412(t, tc.src))
			if err != nil {
				// A strict-compile rejection naming the token also satisfies
				// the criterion; the silent path is the defect.
				if !strings.Contains(err.Error(), tc.token) {
					t.Fatalf("compile error must name dropped token %q, got: %v", tc.token, err)
				}
				return
			}
			if !hasWarning14412(cfg, tc.token) {
				t.Fatalf("CompileConfig silently dropped packed-tail credential %q; warnings=%v (#14412)", tc.token, cfg.Warnings)
			}
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "SECRET14412") {
					t.Fatalf("warning must not echo the secret value: %q", w)
				}
			}
		})
	}
}

// Controls: the CHILD-node forms keep their existing #10707 warnings.
func TestPackedTailCredentialChildControlsKeep10707_14412(t *testing.T) {
	cases := []struct {
		name, src, token string
	}{
		{
			name: "ospf interface misplaced child",
			src: `protocols { ospf { area 0.0.0.0 {
				interface ge-0/0/0.0 { passive; authentication-key SECRET14412; } } } }`,
			token: "authentication-key",
		},
		{
			name: "isis interface case-variant child",
			src: `protocols { isis { net 49.0001.0000.0000.0001.00;
				interface ge-0/0/0.0 { Authentication-Key SECRET14412; authentication-type md5; } } }`,
			token: "Authentication-Key",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfig(parseHier14412(t, tc.src))
			if err != nil {
				t.Fatalf("child control must stay warn-only at compile, got: %v", err)
			}
			if !hasWarning14412(cfg, tc.token) {
				t.Fatalf("child-node form lost its #10707 warning for %q; warnings=%v", tc.token, cfg.Warnings)
			}
		})
	}
}

// Controls: valid packed tails must still compile, with no credential warning
// or strict rejection for the validly-placed credential.
func TestPackedTailCredentialValidPackedTails14412(t *testing.T) {
	cases := []struct {
		name, src, token string
	}{
		{
			name: "isis interface valid packed authentication-key",
			src: `protocols { isis { net 49.0001.0000.0000.0001.00;
				interface ge-0/0/0.0 authentication-key SECRET14412; } }`,
			token: "authentication-key",
		},
		{
			name: "ospf interface valid packed authentication chain",
			src: `protocols { ospf { area 0.0.0.0 {
				interface ge-0/0/0.0 authentication md5 1 key SECRET14412; } } }`,
			token: "simple-password",
		},
		{
			name:  "ospf interface valid packed non-credential tail",
			src:   `protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0 passive cost 10; } } }`,
			token: "authentication-key",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := SchemaValidate(parseHier14412(t, tc.src), nil); err != nil {
				t.Fatalf("SchemaValidate rejected valid packed tail: %v (#14412)", err)
			}
			// Compile is asserted only where the config is complete enough
			// for the orthogonal compiled-config gates (e.g. #9105 needs an
			// authentication-type beside a key); the #14412 claim for a lone
			// validly packed key is the schema-walk acceptance above plus
			// the absence of a #10707 credential warning below.
			cfg, err := CompileConfig(parseHier14412(t, tc.src))
			if err != nil {
				if strings.Contains(err.Error(), "#14412") ||
					(strings.Contains(err.Error(), tc.token) && !strings.Contains(err.Error(), "#9105")) {
					t.Fatalf("CompileConfig rejected valid packed tail: %v (#14412)", err)
				}
				return
			}
			if hasWarning14412(cfg, tc.token) {
				t.Fatalf("valid packed tail drew a #10707 warning for %q; warnings=%v", tc.token, cfg.Warnings)
			}
		})
	}
}

// Control: a credential keyword authored as a quoted value is a value
// (#9635), not a dropped statement head.
func TestPackedTailCredentialQuotedValueNotFlagged14412(t *testing.T) {
	src := `protocols { ospf { area 0.0.0.0 {
		interface ge-0/0/0.0 passive "authentication-key"; } } }`
	if err := SchemaValidate(parseHier14412(t, src), nil); err != nil {
		t.Fatalf("SchemaValidate flagged a quoted value token: %v (#14412/#9635)", err)
	}
}
