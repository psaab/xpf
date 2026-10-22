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
			err := SchemaValidate(parseHier14412(t, tc.src))
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

// Controls: the CHILD-node (braced) forms are NOT warn-only at compile.
// #16108 re-verification: the OSPF braced `authentication-key` is a
// refusal stub (#14402), so SchemaValidate rejects it (never a #10707
// warning — exact-case children of a stanza resolve, so the open-world
// walker stays silent by design); the IS-IS case-variant child's
// `authentication-type md5` without a (case-exact) key strict-rejects via
// #14399 and warns on the lenient path. The original #14412 assertion
// (warn-only via CompileConfig) was never satisfiable on master.
func TestPackedTailCredentialChildControls16108(t *testing.T) {
	// OSPF braced child: exact-case refusal stub — strict reject naming
	// the token, no secret echo; compile must not be silent either.
	ospfSrc := `protocols { ospf { area 0.0.0.0 {
		interface ge-0/0/0.0 { passive; authentication-key SECRET14412; } } } }`
	if err := SchemaValidate(parseHier14412(t, ospfSrc)); err == nil ||
		!strings.Contains(err.Error(), "authentication-key") {
		t.Fatalf("ospf braced authentication-key must strict-reject (#14402), got: %v", err)
	} else if strings.Contains(err.Error(), "SECRET14412") {
		t.Fatalf("strict error must not echo the secret value, got: %v", err)
	}
	// CompileConfig alone does not schema-gate (#14402 premise: "compiler
	// doesn't gate, schema is gate"); the decisive channel is above.
	// IS-IS case-variant child: lenient compile warns (#10707 for the
	// case-variant key and/or #14399 for the keyless type); strict
	// compile rejects via #14399. Never silently accepted.
	isisSrc := `protocols { isis { net 49.0001.0000.0000.0001.00;
		interface ge-0/0/0.0 { Authentication-Key SECRET14412; authentication-type md5; } } }`
	cfg, err := CompileConfigLenient(parseHier14412(t, isisSrc))
	if err != nil {
		t.Fatalf("isis lenient compile must warn, not error: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "Authentication-Key") || strings.Contains(w, "#14399") {
			found = true
		}
		if strings.Contains(w, "SECRET14412") {
			t.Fatalf("warning must not echo the secret value: %q", w)
		}
	}
	if !found {
		t.Fatalf("isis case-variant child lost its warning; warnings=%v", cfg.Warnings)
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
			if err := SchemaValidate(parseHier14412(t, tc.src)); err != nil {
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

// Fold (#16108 review): a credential-spelled token in a VALUE position of
// a nested packed grammar is consumed, not a dropped head. The OSPF MD5
// key may literally be the bare token `authentication-key`
// (`authentication md5 1 key authentication-key`); the pre-fold predicate
// scanned every tail token against the interface grammar and rejected it
// as a dropped refusal stub. Assert strict acceptance, no #10707 warning,
// and that the compiled key is preserved verbatim. The reported dropped
// head (`passive authentication-key SECRET`) stays rejected by
// TestPackedTailCredentialStrictReject14412 above.
func TestPackedTailCredentialValuePosition16108(t *testing.T) {
	src := `protocols { ospf { area 0.0.0.0 {
		interface ge-0/0/0.0 authentication md5 1 key authentication-key; } } }`
	if err := SchemaValidate(parseHier14412(t, src)); err != nil {
		t.Fatalf("SchemaValidate rejected credential value in value position: %v (#16108)", err)
	}
	cfg, err := CompileConfig(parseHier14412(t, src))
	if err != nil {
		t.Fatalf("CompileConfig rejected credential value in value position: %v (#16108)", err)
	}
	if hasWarning14412(cfg, "authentication-key") {
		t.Fatalf("credential value drew a #10707 warning; warnings=%v (#16108)", cfg.Warnings)
	}
	if cfg.Protocols.OSPF == nil || len(cfg.Protocols.OSPF.Areas) == 0 ||
		len(cfg.Protocols.OSPF.Areas[0].Interfaces) == 0 {
		t.Fatalf("no ospf interface compiled: %+v", cfg.Protocols)
	}
	iface := cfg.Protocols.OSPF.Areas[0].Interfaces[0]
	if iface.AuthType != "md5" || iface.AuthKey.Reveal() != "authentication-key" {
		t.Fatalf("compiled AuthType=%q AuthKey=%q, want md5/authentication-key (#16108)",
			iface.AuthType, iface.AuthKey.Reveal())
	}
	// Same for the simple-password value position.
	src2 := `protocols { ospf { area 0.0.0.0 {
		interface ge-0/0/0.0 authentication simple-password authentication-key; } } }`
	if err := SchemaValidate(parseHier14412(t, src2)); err != nil {
		t.Fatalf("SchemaValidate rejected simple-password value: %v (#16108)", err)
	}
	cfg2, err := CompileConfig(parseHier14412(t, src2))
	if err != nil {
		t.Fatalf("CompileConfig rejected simple-password value: %v (#16108)", err)
	}
	if cfg2.Protocols.OSPF.Areas[0].Interfaces[0].AuthKey.Reveal() != "authentication-key" {
		t.Fatalf("simple-password AuthKey=%q, want authentication-key (#16108)",
			cfg2.Protocols.OSPF.Areas[0].Interfaces[0].AuthKey.Reveal())
	}
}

// Control: a credential keyword authored as a quoted value is a value
// (#9635), not a dropped statement head.
func TestPackedTailCredentialQuotedValueNotFlagged14412(t *testing.T) {
	src := `protocols { ospf { area 0.0.0.0 {
		interface ge-0/0/0.0 passive "authentication-key"; } } }`
	if err := SchemaValidate(parseHier14412(t, src)); err != nil {
		t.Fatalf("SchemaValidate flagged a quoted value token: %v (#14412/#9635)", err)
	}
}
