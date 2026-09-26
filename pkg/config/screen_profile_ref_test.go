package config

import (
	"strings"
	"testing"
)

// TestZoneUndefinedScreenProfileFailsCommit asserts that a security zone whose
// `screen <name>` references a screen-ids-option profile the configuration
// never defines is HARD-REJECTED at commit (#3066).
//
// This is the fail-on-revert guard for the screen-bypass fail-open bug: before
// the fix such a reference was only a warning, the commit succeeded, and at
// runtime the userspace dataplane fails OPEN (screen/mod.rs returns
// ScreenVerdict::Pass for a missing profile), silently skipping every screen
// check for the zone while the operator believes screening is active. Remove
// validateScreenProfileReferencesStrict (or its dispatch in compiler.go) and
// this subtest goes green on the BAD config, which is exactly the regression
// this test exists to catch.
func TestZoneUndefinedScreenProfileFailsCommit(t *testing.T) {
	tree := buildTree(t, []string{
		// "wan-screen" is defined; the zone references the typo "wan-scren".
		"set security screen ids-option wan-screen tcp land",
		"set security zones security-zone untrust screen wan-scren",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("expected commit to reject a zone referencing an undefined screen profile, got nil error")
	}
	if !strings.Contains(err.Error(), `undefined screen profile "wan-scren"`) {
		t.Fatalf("error %q does not name the undefined screen profile", err.Error())
	}
}

// TestZoneDefinedScreenProfileCommit asserts that a zone referencing a screen
// profile that IS defined commits cleanly (#3066 anti-over-reject), and that a
// zone with no screen reference at all is unaffected.
func TestZoneDefinedScreenProfileCommit(t *testing.T) {
	tree := buildTree(t, []string{
		"set security screen ids-option wan-screen tcp land",
		"set security zones security-zone untrust screen wan-screen",
		// a zone with no screen reference must not be flagged
		"set security zones security-zone trust",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("strict commit rejected a zone with a defined (or absent) screen profile: %v", err)
	}
}

// TestZoneUndefinedScreenProfileLenientDowngradesToWarning asserts the tolerant
// load / peer-sync path downgrades the undefined-screen-profile reference to a
// warning instead of failing the compile, so an already-persisted or
// peer-synced config carrying a stale screen reference still boots (#3066 /
// #1960 no-brick).
func TestZoneUndefinedScreenProfileLenientDowngradesToWarning(t *testing.T) {
	tree := buildTree(t, []string{
		"set security screen ids-option wan-screen tcp land",
		"set security zones security-zone untrust screen wan-scren",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must not fail on a stale screen reference: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "zone screen profile reference (downgraded to warning on tolerant path)") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected a downgraded screen-profile-reference warning, got warnings: %v", cfg.Warnings)
	}
}

// TestZoneQuotedEmptyScreenProfileFailsCommit distinguishes `screen ""` from a
// zone with no screen statement at all (#10973). The token-present scalar leaf
// passes schema arity, so the compiled reference gate must reject it explicitly.
func TestZoneQuotedEmptyScreenProfileFailsCommit(t *testing.T) {
	for _, tc := range []struct {
		name string
		tree func(*testing.T) *ConfigTree
	}{
		{
			name: "hierarchical",
			tree: func(t *testing.T) *ConfigTree {
				t.Helper()
				p := NewParser(`security { zones { security-zone trust { screen ""; } } }`)
				tree, parseErrs := p.Parse()
				if len(parseErrs) != 0 {
					t.Fatalf("parse: %v", parseErrs)
				}
				return tree
			},
		},
		{
			name: "flat-set",
			tree: func(t *testing.T) *ConfigTree {
				t.Helper()
				path, quoted, grouped, err := ParseSetCommandGrouped(`set security zones security-zone trust screen ""`)
				if err != nil {
					t.Fatalf("parse set command: %v", err)
				}
				tree := &ConfigTree{}
				if err := tree.SetPathQuotedGrouped(path, quoted, grouped); err != nil {
					t.Fatalf("SetPathQuotedGrouped: %v", err)
				}
				return tree
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := tc.tree(t)
			if err := SchemaValidate(tree, nil); err != nil {
				t.Fatalf("the quoted empty value is present and satisfies scalar arity: %v", err)
			}
			if _, err := CompileConfig(tree); err == nil {
				t.Fatal("strict commit accepted a quoted-empty screen profile")
			} else if !strings.Contains(err.Error(), `security zone "trust"`) ||
				!strings.Contains(err.Error(), "empty screen profile") {
				t.Fatalf("strict error must name the zone and empty profile binding, got %v", err)
			}
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("lenient compile must retain this existing config: %v", err)
			}
			zone := cfg.Security.Zones["trust"]
			if zone == nil || !zone.ScreenProfileConfigured || zone.ScreenProfile != "" {
				t.Fatalf("lenient compile lost the authored empty binding: %+v", zone)
			}
			if !strings.Contains(strings.Join(cfg.Warnings, "\n"), `security zone "trust" has an empty screen profile reference`) {
				t.Fatalf("lenient compile must warn with the zone name, got %v", cfg.Warnings)
			}
		})
	}
}
