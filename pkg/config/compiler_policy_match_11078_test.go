package config

import (
	"strings"
	"testing"
)

// Tests for #11078: the #3142 collapsed-tail scan flagged only 3 unsupported
// match leaves (dynamic-application, url-category, source-identity). Their
// Junos siblings dynamic-application-group and source-end-user-profile were
// outside the enumeration: written after a supported leaf's value in flat-set
// form they collapse onto the tail as bogus operands, invisible to the
// direct-child scan, and the policy silently arms widened (the same fail-open
// #3113/#3142 closed for the covered names).
//
// The fix extends unsupportedPolicyMatchLeaves to the full unsupported
// dimension set, so flat-set forms with those leaves are rejected/flagged
// exactly like direct children. Audit: Junos OS CLI `match` carries exactly
// these 5 unified-policy dimensions beyond xpf's supported subset; alleged
// extras (destination-identity, user-role) are source-identity values /
// Security Director abstractions, not CLI match leaves, so enumerating them
// would over-reject legitimate values.
//
// Flat-set syntax MUST be built with ParseSetCommand/SetPath — bracketed
// lists (`[ a b ]`) require the lexer's bracket stripping, which
// strings.Fields does not do.
func build11078Tree(t *testing.T, cmds ...string) *ConfigTree {
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

// TestPolicyMatchSiblingTailEscapeRejected is the fail-on-revert anchor: an
// unsupported sibling keyword (dynamic-application-group /
// source-end-user-profile) collapsed onto a supported leaf's tail must be
// hard-rejected at commit, exactly like a direct child. Reverting
// unsupportedPolicyMatchLeaves to the 3-name set turns every one of these
// cases GREEN (committed widened, or rejected by the wrong gate) and so RED.
func TestPolicyMatchSiblingTailEscapeRejected(t *testing.T) {
	// zoneDefs makes the zone-pair escape policies OTHERWISE valid: both
	// zones are defined and both address criteria are present, so neither the
	// undefined-zone gate nor the #3044 missing-criterion gate fires — the
	// ONLY thing that can reject these with the #3113 leaf name is the
	// collapsed-tail check.
	zoneDefs := []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
	}
	cases := []struct {
		name string
		cmds []string
		want string // substring expected in the commit error
	}{
		{
			name: "zone-pair application any dynamic-application-group",
			cmds: []string{
				"set security policies from-zone trust to-zone untrust policy p match source-address any",
				"set security policies from-zone trust to-zone untrust policy p match destination-address any",
				"set security policies from-zone trust to-zone untrust policy p match application any dynamic-application-group junos:web",
				"set security policies from-zone trust to-zone untrust policy p then permit",
			},
			want: `from-zone trust to-zone untrust policy "p" match "dynamic-application-group"`,
		},
		{
			name: "zone-pair application any source-end-user-profile",
			cmds: []string{
				"set security policies from-zone trust to-zone untrust policy p match source-address any",
				"set security policies from-zone trust to-zone untrust policy p match destination-address any",
				"set security policies from-zone trust to-zone untrust policy p match application any source-end-user-profile corporate-laptops",
				"set security policies from-zone trust to-zone untrust policy p then permit",
			},
			want: `from-zone trust to-zone untrust policy "p" match "source-end-user-profile"`,
		},
		{
			name: "global application any dynamic-application-group",
			cmds: []string{
				"set security policies global policy g match source-address any",
				"set security policies global policy g match destination-address any",
				"set security policies global policy g match application any dynamic-application-group junos:web",
				"set security policies global policy g then permit",
			},
			want: `global policy "g" match "dynamic-application-group"`,
		},
		{
			name: "global application any source-end-user-profile",
			cmds: []string{
				"set security policies global policy g match source-address any",
				"set security policies global policy g match destination-address any",
				"set security policies global policy g match application any source-end-user-profile corporate-laptops",
				"set security policies global policy g then permit",
			},
			want: `global policy "g" match "source-end-user-profile"`,
		},
		{
			name: "zone-pair bracketed application list carrying dynamic-application-group",
			cmds: []string{
				"set security policies from-zone trust to-zone untrust policy p match source-address any",
				"set security policies from-zone trust to-zone untrust policy p match destination-address any",
				"set security policies from-zone trust to-zone untrust policy p match application [ junos-http dynamic-application-group ]",
				"set security policies from-zone trust to-zone untrust policy p then permit",
			},
			want: `from-zone trust to-zone untrust policy "p" match "dynamic-application-group"`,
		},
		{
			name: "zone-pair source-address tail carrying source-end-user-profile",
			cmds: []string{
				"set security policies from-zone trust to-zone untrust policy p match source-address any source-end-user-profile corporate-laptops",
				"set security policies from-zone trust to-zone untrust policy p match destination-address any",
				"set security policies from-zone trust to-zone untrust policy p match application any",
				"set security policies from-zone trust to-zone untrust policy p then permit",
			},
			want: `from-zone trust to-zone untrust policy "p" match "source-end-user-profile"`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Defining trust/untrust is harmless for the global cases.
			tree := build11078Tree(t, append(append([]string{}, zoneDefs...), tc.cmds...)...)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("CompileConfig accepted a sibling-keyword tail escape; want commit rejection (#11078)")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("CompileConfig error = %q, want substring %q", err.Error(), tc.want)
			}
			if !strings.Contains(err.Error(), "#3113") {
				t.Fatalf("CompileConfig error = %q, want #3113 reference", err.Error())
			}
		})
	}
}

// TestPolicyMatchSiblingTailEscapeLenientWarns proves the tolerant
// load/peer-sync path (CompileConfigLenient) does NOT fail on the sibling
// tail escape — it compiles and records a warning naming the keyword, so an
// already-persisted config still boots (#1960 fail-closed-on-load).
func TestPolicyMatchSiblingTailEscapeLenientWarns(t *testing.T) {
	cases := []struct {
		name string
		cmds []string
		want string // keyword expected in the lenient warning
	}{
		{
			name: "dynamic-application-group",
			cmds: []string{
				"set security zones security-zone trust",
				"set security zones security-zone untrust",
				"set security policies from-zone trust to-zone untrust policy p match source-address any",
				"set security policies from-zone trust to-zone untrust policy p match destination-address any",
				"set security policies from-zone trust to-zone untrust policy p match application any dynamic-application-group junos:web",
				"set security policies from-zone trust to-zone untrust policy p then permit",
			},
			want: "dynamic-application-group",
		},
		{
			name: "source-end-user-profile",
			cmds: []string{
				"set security zones security-zone trust",
				"set security zones security-zone untrust",
				"set security policies from-zone trust to-zone untrust policy p match source-address any",
				"set security policies from-zone trust to-zone untrust policy p match destination-address any",
				"set security policies from-zone trust to-zone untrust policy p match application any source-end-user-profile corporate-laptops",
				"set security policies from-zone trust to-zone untrust policy p then permit",
			},
			want: "source-end-user-profile",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := build11078Tree(t, tc.cmds...)
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("CompileConfigLenient hard-failed on a sibling tail escape; want warn-and-boot: %v", err)
			}
			found := false
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "#3113") && strings.Contains(w, tc.want) {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("CompileConfigLenient warnings = %v, want a #3113 warning naming %q", cfg.Warnings, tc.want)
			}
		})
	}
}
