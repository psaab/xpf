package config

import (
	"testing"
)

// #4415 L12 → #4626 M03: a scoped global policy's from-zone/to-zone match
// context is a zone SET (config.PolicyMatch.FromZones / .ToZones). A Junos zone
// LIST (`match from-zone [ a b ]`) collapses via the #2419 lexer onto one
// leaf's Keys (["from-zone","a","b"]); the compiler now accumulates EVERY value
// via firewallMatchValues into the set (the pre-#4626 code kept only "a" and
// silently DROPPED "b" — a security-relevant miscompile that #4415 L12
// fail-closed rejected with `scalar: true`).
//
// This file replaces the L12 RED-guard (which asserted the list was REJECTED at
// schema validation) with the POSITIVE M03 behavior: the list now COMMITS and
// both zones populate.
//
// Flat-set syntax MUST be built with ParseSetCommand/SetPath (never NewParser),
// per the project's set-syntax testing rule.

func buildGlobalZone4415Tree(t *testing.T, cmds ...string) *ConfigTree {
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

// TestGlobalPolicyZoneListAccepted4626 is the M03 fail-on-revert anchor: a
// zone LIST scope is accepted by SchemaValidate (the leaves carry `multi: true`,
// not `scalar: true`) AND the compiler populates BOTH zones. Reverting the
// schema `multi` marker or the compiler firewallMatchValues accumulation turns
// these assertions RED.
func TestGlobalPolicyZoneListAccepted4626(t *testing.T) {
	base := []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security zones security-zone dmz",
	}

	cases := []struct {
		name      string
		matchLine string
		wantFrom  []string
		wantTo    []string
	}{
		{
			name:      "from-zone list accepted, both zones populate",
			matchLine: "set security policies global policy p match from-zone [ trust dmz ]",
			// sorted+deduped by the compiler
			wantFrom: []string{"dmz", "trust"},
			wantTo:   nil,
		},
		{
			name:      "to-zone list accepted, both zones populate",
			matchLine: "set security policies global policy p match to-zone [ untrust dmz ]",
			wantFrom:  nil,
			wantTo:    []string{"dmz", "untrust"},
		},
		{
			name:      "single from-zone stays a one-element set",
			matchLine: "set security policies global policy p match from-zone trust",
			wantFrom:  []string{"trust"},
			wantTo:    nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmds := append(append([]string(nil), base...), tc.matchLine,
				"set security policies global policy p match application any",
				"set security policies global policy p then deny",
			)
			tree := buildGlobalZone4415Tree(t, cmds...)
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("CompileConfigLenient: %v", err)
			}
			// The zone LIST must no longer be schema-rejected.
			if err := SchemaValidate(tree); err != nil {
				t.Fatalf("SchemaValidate rejected a multi-zone scope: %v", err)
			}
			if len(cfg.Security.GlobalPolicies) != 1 {
				t.Fatalf("GlobalPolicies = %d, want 1", len(cfg.Security.GlobalPolicies))
			}
			m := cfg.Security.GlobalPolicies[0].Match
			if !eqStrSlice(m.FromZones, tc.wantFrom) {
				t.Errorf("Match.FromZones = %q, want %q", m.FromZones, tc.wantFrom)
			}
			if !eqStrSlice(m.ToZones, tc.wantTo) {
				t.Errorf("Match.ToZones = %q, want %q", m.ToZones, tc.wantTo)
			}
		})
	}
}

func eqStrSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
