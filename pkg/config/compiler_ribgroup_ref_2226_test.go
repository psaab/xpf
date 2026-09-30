package config

import (
	"strings"
	"testing"
)

// #2226: commit-time strict validation of a rib-group `import-rib <rib>`
// cross-reference. An import-rib naming a rib that resolves to no real
// routing table (a typo, a non-existent routing-instance, or unparseable
// garbage) compiled cleanly and then, at apply time, mapped to a bare
// table 0 — which differs from any routing-instance's (>= 100) source
// table — so the applier installed an `ip rule from all lookup
// <sourceTable> pref 33000` for a rib that does not exist: a silent
// mis-leak of the source table into the main lookup with no diagnostic.
//
// validateRibGroupImportRibReferencesStrict now hard-rejects the dangling
// reference at commit; the applier's resolveRibTable ok=false guard is the
// runtime backstop (tested in pkg/routing/rules_test.go).
//
// Each case is exercised in BOTH AST shapes (flat-set via ParseSetCommand
// + SetPath, hierarchical via NewParser), in both directions: an
// UNDEFINED import-rib is hard-rejected at commit (the fail-on-revert
// assertion — neuter the validator and the reject disappears), and a
// DEFINED import-rib commits cleanly with no false reject.

func TestRibGroupImportRibUndefinedRejectedFlatSet(t *testing.T) {
	tree := buildTree(t, []string{
		"set routing-instances dmz-vr instance-type virtual-router",
		"set routing-instances dmz-vr interface-routes rib-group inet dmz-leak",
		"set routing-options rib-groups dmz-leak import-rib does-not-exist.inet.0",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected commit rejection for import-rib does-not-exist.inet.0, got nil")
	}
	if !strings.Contains(err.Error(), "undefined rib") ||
		!strings.Contains(err.Error(), "does-not-exist.inet.0") {
		t.Fatalf("error = %v, want it to name the undefined rib", err)
	}
}

// A bare garbage token (no ".inet" suffix at all) is also undefined.
func TestRibGroupImportRibGarbageRejected(t *testing.T) {
	tree := buildTree(t, []string{
		"set routing-instances dmz-vr instance-type virtual-router",
		"set routing-instances dmz-vr interface-routes rib-group inet dmz-leak",
		"set routing-options rib-groups dmz-leak import-rib garbage",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected commit rejection for import-rib garbage, got nil")
	}
	if !strings.Contains(err.Error(), "undefined rib") ||
		!strings.Contains(err.Error(), "garbage") {
		t.Fatalf("error = %v, want it to name the undefined rib", err)
	}
}

func TestRibGroupImportRibUndefinedRejectedHierarchical(t *testing.T) {
	input := `routing-instances {
    dmz-vr {
        instance-type virtual-router;
        interface-routes {
            rib-group inet dmz-leak;
        }
    }
}
routing-options {
    rib-groups {
        dmz-leak {
            import-rib does-not-exist.inet.0;
        }
    }
}
`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected commit rejection for import-rib does-not-exist.inet.0, got nil")
	}
	if !strings.Contains(err.Error(), "undefined rib") {
		t.Fatalf("error = %v, want undefined-rib rejection", err)
	}
}

// A defined rib-group importing a defined instance's rib + the main table
// commits cleanly (no false reject).
func TestRibGroupImportRibDefinedCommitsFlatSet(t *testing.T) {
	tree := buildTree(t, []string{
		"set routing-instances tunnel-vr instance-type virtual-router",
		"set routing-instances dmz-vr instance-type virtual-router",
		"set routing-instances dmz-vr interface-routes rib-group inet dmz-leak",
		"set routing-options rib-groups dmz-leak import-rib dmz-vr.inet.0",
		"set routing-options rib-groups dmz-leak import-rib tunnel-vr.inet.0",
		"set routing-options rib-groups dmz-leak import-rib inet.0",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("defined import-ribs must commit cleanly, got: %v", err)
	}
	rg := cfg.RoutingOptions.RibGroups["dmz-leak"]
	if rg == nil {
		t.Fatal("rib-group dmz-leak missing from compiled config")
	}
	if len(rg.ImportRibs) != 3 {
		t.Fatalf("import-rib list = %v, want 3 entries", rg.ImportRibs)
	}
}

// inet6.0 and "<instance>.inet6.0" are valid main-table / VRF rib names.
func TestRibGroupImportRibInet6Commits(t *testing.T) {
	tree := buildTree(t, []string{
		"set routing-instances vpn-vr instance-type virtual-router",
		"set routing-instances vpn-vr interface-routes rib-group inet6 v6-leak",
		"set routing-options rib-groups v6-leak import-rib vpn-vr.inet6.0",
		"set routing-options rib-groups v6-leak import-rib inet6.0",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("inet6 import-ribs must commit cleanly, got: %v", err)
	}
}

// The strict reject is downgraded to a warning on the tolerant load /
// peer-sync path so an already-persisted config carrying the typo still
// boots (#1960 fail-closed-on-load class).
func TestRibGroupImportRibUndefinedLenientWarns(t *testing.T) {
	tree := buildTree(t, []string{
		"set routing-instances dmz-vr instance-type virtual-router",
		"set routing-instances dmz-vr interface-routes rib-group inet dmz-leak",
		"set routing-options rib-groups dmz-leak import-rib does-not-exist.inet.0",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient path must boot through undefined import-rib, got: %v", err)
	}
	if !warningsContain(cfg.Warnings, "rib-group import-rib reference") {
		t.Fatalf("expected a downgraded import-rib-reference warning, got: %v", cfg.Warnings)
	}
}

// #2253: a malformed family token (".inetX.0", ".inetfoo.0", ".inet60.0",
// trailing garbage) whose prefix IS a DEFINED routing-instance must still be
// hard-rejected at commit. The previous loose ".inet" substring match
// resolved these onto the defined instance — a sloppy rib name silently
// leaking into the operator's real target table. The exact ".inet.0" /
// ".inet6.0" suffix match rejects them. Restoring the substring match makes
// each of these commit cleanly (the fail-on-revert assertion). The commit
// gate (this test) and the runtime applier (pkg/routing) MUST agree, so both
// use the same exact-suffix matcher (#2226 gate↔runtime consistency).
func TestRibGroupImportRibMalformedFamilyRejected(t *testing.T) {
	malformed := []string{
		"dmz-vr.inet9.0",
		"dmz-vr.inetX.0",
		"dmz-vr.inetfoo.0",
		"dmz-vr.inet60.0",
		"dmz-vr.inet.0.garbage",
	}
	for _, ribName := range malformed {
		t.Run(ribName, func(t *testing.T) {
			tree := buildTree(t, []string{
				"set routing-instances dmz-vr instance-type virtual-router",
				"set routing-instances dmz-vr interface-routes rib-group inet dmz-leak",
				"set routing-options rib-groups dmz-leak import-rib " + ribName,
			})
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("expected commit rejection for malformed import-rib %q, got nil", ribName)
			}
			if !strings.Contains(err.Error(), "undefined rib") ||
				!strings.Contains(err.Error(), ribName) {
				t.Fatalf("error = %v, want it to name the malformed rib %q", err, ribName)
			}
		})
	}
}

// #2253: the exact-suffix family matcher mirrored from
// pkg/routing.ribInstanceFromName. Pins acceptance of valid
// "<instance>.inet.0" / "<instance>.inet6.0" and rejection of malformed
// family tokens + trailing garbage + empty-prefix forms.
func TestRibInstanceFromNameConfig(t *testing.T) {
	tests := []struct {
		ribName  string
		instance string
		ok       bool
	}{
		{"vrf1.inet.0", "vrf1", true},
		{"vrf1.inet6.0", "vrf1", true},
		{"a.b.inet.0", "a.b", true},
		{"inet.0", "", false},
		{"inet6.0", "", false},
		{"vrf1.inet9.0", "", false},
		{"vrf1.inetX.0", "", false},
		{"vrf1.inetfoo.0", "", false},
		{"vrf1.inet60.0", "", false},
		{"vrf1.inet.0.garbage", "", false},
		{".inet.0", "", false},
		{".inet6.0", "", false},
		{"garbage", "", false},
		{"", "", false},
	}
	for _, tt := range tests {
		instance, ok := ribInstanceFromName(tt.ribName)
		if instance != tt.instance || ok != tt.ok {
			t.Errorf("ribInstanceFromName(%q) = (%q, %v), want (%q, %v)",
				tt.ribName, instance, ok, tt.instance, tt.ok)
		}
	}
}

func TestGlobalInterfaceRoutesRibGroupRejectedStrict11311(t *testing.T) {
	cases := []struct {
		name  string
		lines []string
		group string
	}{
		{
			name:  "inet",
			group: "global-v4",
			lines: []string{
				"set routing-instances blue instance-type virtual-router",
				"set routing-options interface-routes rib-group inet global-v4",
				"set routing-options rib-groups global-v4 import-rib inet.0",
				"set routing-options rib-groups global-v4 import-rib blue.inet.0",
			},
		},
		{
			name:  "inet6",
			group: "global-v6",
			lines: []string{
				"set routing-instances blue instance-type virtual-router",
				"set routing-options interface-routes rib-group inet6 global-v6",
				"set routing-options rib-groups global-v6 import-rib inet6.0",
				"set routing-options rib-groups global-v6 import-rib blue.inet6.0",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(buildTree(t, tc.lines))
			if err == nil {
				t.Fatal("expected strict rejection for an unimplemented global interface-routes rib-group")
			}
			if !strings.Contains(err.Error(), tc.group) ||
				!strings.Contains(err.Error(), "not implemented") {
				t.Fatalf("error = %v, want it to identify the global group as unimplemented", err)
			}
		})
	}
}

func TestGlobalInterfaceRoutesRibGroupWarnedTolerant11311(t *testing.T) {
	cases := []struct {
		name  string
		lines []string
		group string
	}{
		{
			name:  "inet",
			group: "global-v4",
			lines: []string{
				"set routing-instances blue instance-type virtual-router",
				"set routing-options interface-routes rib-group inet global-v4",
				"set routing-options rib-groups global-v4 import-rib inet.0",
				"set routing-options rib-groups global-v4 import-rib blue.inet.0",
			},
		},
		{
			name:  "inet6",
			group: "global-v6",
			lines: []string{
				"set routing-instances blue instance-type virtual-router",
				"set routing-options interface-routes rib-group inet6 global-v6",
				"set routing-options rib-groups global-v6 import-rib inet6.0",
				"set routing-options rib-groups global-v6 import-rib blue.inet6.0",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfigLenient(buildTree(t, tc.lines))
			if err != nil {
				t.Fatalf("tolerant load must retain the unsupported selector: %v", err)
			}
			if !warningsContain(cfg.Warnings, "global interface-routes rib-group") ||
				!warningsContain(cfg.Warnings, tc.group) ||
				!warningsContain(cfg.Warnings, "not implemented") {
				t.Fatalf("warnings = %v, want an explicit warning for group %q", cfg.Warnings, tc.group)
			}
		})
	}
}

func TestPerInstanceInterfaceRoutesRibGroupStillCommits11311(t *testing.T) {
	tree := buildTree(t, []string{
		"set routing-instances blue instance-type virtual-router",
		"set routing-instances blue routing-options interface-routes rib-group inet per-instance",
		"set routing-options rib-groups per-instance import-rib inet.0",
		"set routing-options rib-groups per-instance import-rib blue.inet.0",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("the supported per-instance import-into-main path must still commit: %v", err)
	}
	if warningsContain(cfg.Warnings, "global interface-routes rib-group") {
		t.Fatalf("supported per-instance rib-group received global-selector warning: %v", cfg.Warnings)
	}
}
