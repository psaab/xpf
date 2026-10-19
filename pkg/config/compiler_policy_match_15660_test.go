package config

import (
	"strings"
	"testing"
)

// Tests for #15660 (V1-01): a global policy's `match from-zone` / `match
// to-zone` leaf short-circuited policyUnsupportedMatchLeafFindings before its
// collapsed tail was scanned. Because from-zone/to-zone are multi:true
// leaves, a trailing non-sibling keyword collapses onto the leaf's own node
// (the #2419 collapse), exactly as for `application` (#3142):
//
//	set ... global policy p match from-zone any dynamic-application junos:FTP
//	set ... global policy p match from-zone [ any to-zone untrust ]
//
// hit `if isGlobal && globalOnlyPolicyMatchLeaves[leaf] { continue }` and
// returned no finding, so strict commit misdiagnosed the bogus tokens as
// undefined zones and tolerant load published an unscoped permit with
// LenientContentDropped=false.
//
// The fix scans firewallMatchValues(m) for global-only leaves exactly like
// supported leaves: unsupported match-leaf keywords are flagged as direct
// unsupported leaves, and a fused from-zone/to-zone keyword is flagged as a
// swallowed structural token. Legitimate zone lists (including a lone `any`)
// are never one of those keywords and must not be over-rejected.
//
// Flat-set syntax MUST be built with ParseSetCommand/SetPath — bracketed
// lists (`[ a b ]`) require the lexer's bracket stripping, which
// strings.Fields does not do.
func build15660Tree(t *testing.T, cmds ...string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}

func global15660Base(extra ...string) []string {
	cmds := []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies global policy p match source-address any",
		"set security policies global policy p match destination-address any",
		"set security policies global policy p match application any",
	}
	cmds = append(cmds, extra...)
	return append(cmds, "set security policies global policy p then permit")
}

// TestGlobalPolicyZoneLeafCollapsedUnsupportedRejected15660 is the
// fail-on-revert anchor: an unsupported match-leaf keyword collapsed onto a
// global from-zone/to-zone leaf's tail must be hard-rejected at commit with
// the #3113 unsupported-leaf diagnostic. Reverting the global-leaf tail scan
// makes strict commit either accept (tolerant widening) or reject with the
// wrong (undefined-zone) diagnostic, turning these RED.
func TestGlobalPolicyZoneLeafCollapsedUnsupportedRejected15660(t *testing.T) {
	cases := []struct {
		name string
		cmds []string
		want string
	}{
		{
			name: "from-zone any dynamic-application",
			cmds: global15660Base(
				"set security policies global policy p match from-zone any dynamic-application junos:FTP",
			),
			want: `global policy "p" match "dynamic-application"`,
		},
		{
			name: "from-zone trust source-identity",
			cmds: global15660Base(
				"set security policies global policy p match from-zone trust source-identity authenticated-user",
			),
			want: `global policy "p" match "source-identity"`,
		},
		{
			name: "to-zone any url-category",
			cmds: global15660Base(
				"set security policies global policy p match to-zone any url-category Enhanced_Search_Engines",
			),
			want: `global policy "p" match "url-category"`,
		},
		{
			name: "to-zone untrust dynamic-application-group",
			cmds: global15660Base(
				"set security policies global policy p match to-zone untrust dynamic-application-group grp",
			),
			want: `global policy "p" match "dynamic-application-group"`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := build15660Tree(t, tc.cmds...)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("CompileConfig accepted a collapsed unsupported leaf on a global zone leaf; want #3113 rejection (#15660)")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("CompileConfig error = %q, want substring %q (wrong-reason rejection is the pre-fix misdiagnosis)", err.Error(), tc.want)
			}
			if !strings.Contains(err.Error(), "#3113") {
				t.Fatalf("CompileConfig error = %q, want #3113 reference", err.Error())
			}
		})
	}
}

// hier15660 parses hierarchical (brace) syntax, the form in which a fused
// zone keyword actually collapses onto one leaf: flat `set` lines stop at
// the registered sibling keyword (SetPath), but a missing semicolon or a
// bracketed list in a brace block leaves `to-zone` on the from-zone leaf's
// Keys (probe-verified).
func hier15660(t *testing.T, matchFrom string) *ConfigTree {
	t.Helper()
	src := "security {\n zones { security-zone trust; security-zone untrust; }\n" +
		" policies { global { policy p {\n" +
		"  match {\n   source-address any; destination-address any; application any;\n   " + matchFrom + "\n  }\n" +
		"  then { permit; }\n } } }\n}\n"
	tree, errs := NewParser(src).Parse()
	if len(errs) > 0 {
		t.Fatalf("NewParser: %v", errs)
	}
	return tree
}

// TestGlobalPolicyZoneLeafFusedZoneTokenRejected15660 covers the fused
// from-zone/to-zone spelling: the sibling zone keyword (and its operand)
// collapse onto the first zone leaf instead of becoming their own leaf.
// That token is match context, never a zone value, so it must be rejected
// with the swallowed-keyword diagnostic rather than consumed as a bogus
// zone operand.
func TestGlobalPolicyZoneLeafFusedZoneTokenRejected15660(t *testing.T) {
	cases := []struct {
		name string
		from string
		want string
	}{
		{
			name: "from-zone any to-zone untrust fused (missing semicolon)",
			from: "from-zone any\n     to-zone untrust;",
			want: `"to-zone"`,
		},
		{
			name: "to-zone any from-zone trust fused (missing semicolon)",
			from: "to-zone any\n     from-zone trust;",
			want: `"from-zone"`,
		},
		{
			name: "from-zone bracket fused to-zone",
			from: "from-zone [ any to-zone untrust ];",
			want: `"to-zone"`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := hier15660(t, tc.from)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("CompileConfig accepted a fused zone keyword on a global zone leaf; want swallowed-token rejection (#15660)")
			}
			if !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "absorbed the reserved") {
				t.Fatalf("CompileConfig error = %q, want swallowed-keyword diagnostic naming %s", err.Error(), tc.want)
			}
		})
	}
}

// TestGlobalPolicyZoneLeafCollapsedLenientPoisoned15660 proves the tolerant
// load / peer-sync path does NOT hard-fail, but marks the policy
// LenientContentDropped so the userspace snapshot builder poisons it
// instead of publishing an unscoped permit (#5575/#1960).
func TestGlobalPolicyZoneLeafCollapsedLenientPoisoned15660(t *testing.T) {
	t.Run("from-zone collapsed dynamic-application (flat set)", func(t *testing.T) {
		tree := build15660Tree(t, global15660Base(
			"set security policies global policy p match from-zone any dynamic-application junos:FTP",
		)...)
		assertLenientPoisoned15660(t, tree, "dynamic-application")
	})
	t.Run("from-zone fused to-zone (hierarchical)", func(t *testing.T) {
		tree := hier15660(t, "from-zone any\n     to-zone untrust;")
		assertLenientPoisoned15660(t, tree, "to-zone")
	})
}

func assertLenientPoisoned15660(t *testing.T, tree *ConfigTree, want string) {
	t.Helper()
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient hard-failed; want warn-and-boot: %v", err)
	}
	if len(cfg.Security.GlobalPolicies) != 1 {
		t.Fatalf("GlobalPolicies = %d, want 1", len(cfg.Security.GlobalPolicies))
	}
	pol := cfg.Security.GlobalPolicies[0]
	if !pol.LenientContentDropped {
		t.Fatalf("LenientContentDropped = false, want true: collapsed content on a global zone leaf must poison the tolerant rule (#15660)")
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, want) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("CompileConfigLenient warnings = %v, want a warning naming %q", cfg.Warnings, want)
	}
}

// TestGlobalPolicyZoneLeafLegitValuesNotOverRejected15660 proves the tail
// scan does NOT over-reject legitimate global zone scopes: a lone `any`, a
// bracketed multi-zone list, and separate from-zone/to-zone leaves are real
// zone values, never unsupported/swallowed keywords.
func TestGlobalPolicyZoneLeafLegitValuesNotOverRejected15660(t *testing.T) {
	cases := []struct {
		name  string
		extra []string
	}{
		{
			name: "explicit any both sides",
			extra: []string{
				"set security policies global policy p match from-zone any",
				"set security policies global policy p match to-zone any",
			},
		},
		{
			name: "bracketed zone list",
			extra: []string{
				"set security policies global policy p match from-zone [ trust untrust ]",
				"set security policies global policy p match to-zone untrust",
			},
		},
		{
			name: "separate zone leaves",
			extra: []string{
				"set security policies global policy p match from-zone trust",
				"set security policies global policy p match to-zone untrust",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := build15660Tree(t, global15660Base(tc.extra...)...)
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("CompileConfig over-rejected a legit global zone scope: %v", err)
			}
			if len(cfg.Security.GlobalPolicies) != 1 {
				t.Fatalf("GlobalPolicies = %d, want 1", len(cfg.Security.GlobalPolicies))
			}
			if cfg.Security.GlobalPolicies[0].LenientContentDropped {
				t.Fatalf("legit global zone scope marked LenientContentDropped; want clean compile")
			}
		})
	}
}
