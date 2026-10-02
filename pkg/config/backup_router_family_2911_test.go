package config

import (
	"strings"
	"testing"
)

// #2911: commit-time validation for `system backup-router` whose EXPLICIT
// destination prefix is a different address family than the next-hop. Such a
// config cannot install the backup route into management table 999 and must be
// rejected rather than silently omit the route at commit time. The matched and
// empty-destination cases ensure only explicit mismatches fail.
//
// All tests use the production ParseSetCommand + SetPath path (buildTree),
// never NewParser (the flat-set gotcha in CLAUDE.md).

func hasBackupRouterFamilyWarning(cfg *Config) bool {
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "does not match next-hop family") {
			return true
		}
	}
	return false
}

// v6 next-hop + explicit v4 destination → mismatch → rejected at commit.
func TestBackupRouterV6NextHopV4DestRejected(t *testing.T) {
	tree := buildTree(t, []string{
		"set system backup-router 2001:db8::1 destination 0.0.0.0/0",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("v6 next-hop with v4 destination must be rejected (family mismatch)")
	}
	if !strings.Contains(err.Error(), "backup-router") ||
		!strings.Contains(err.Error(), "does not match next-hop family") {
		t.Fatalf("error should name backup-router + the family mismatch, got: %v", err)
	}
}

// v4 next-hop + explicit v6 destination → mismatch → rejected at commit.
func TestBackupRouterV4NextHopV6DestRejected(t *testing.T) {
	tree := buildTree(t, []string{
		"set system backup-router 192.168.50.1 destination ::/0",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("v4 next-hop with v6 destination must be rejected (family mismatch)")
	}
	if !strings.Contains(err.Error(), "does not match next-hop family") {
		t.Fatalf("error should name the family mismatch, got: %v", err)
	}
}

// Matched-family explicit destinations commit cleanly (v6+v6, v4+v4).
func TestBackupRouterMatchedFamilyCommits(t *testing.T) {
	cases := []struct {
		name string
		line string
	}{
		{"v6+v6", "set system backup-router 2001:db8::1 destination ::/0"},
		{"v6+v6-prefix", "set system backup-router 2001:db8::1 destination 2001:db8:1::/48"},
		{"v4+v4", "set system backup-router 192.168.50.1 destination 0.0.0.0/0"},
		{"v4+v4-prefix", "set system backup-router 192.168.50.1 destination 10.0.0.0/8"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTree(t, []string{tc.line})
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("matched-family backup-router should compile, got: %v", err)
			}
			if hasBackupRouterFamilyWarning(cfg) {
				t.Fatalf("matched-family backup-router must not warn, warnings=%v", cfg.Warnings)
			}
		})
	}
}

// Empty destination still commits and leaves the family-aware default to the
// table-999 netlink reconciler — no mismatch reject for v4 OR v6 next-hop.
// Guards against a #2907 regression.
func TestBackupRouterEmptyDestCommits(t *testing.T) {
	for _, nh := range []string{"2001:db8::1", "192.168.50.1"} {
		tree := buildTree(t, []string{
			"set system backup-router " + nh,
		})
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("empty-destination backup-router (%s) must compile (#2907 default), got: %v", nh, err)
		}
		if cfg.System.BackupRouter != nh {
			t.Fatalf("backup-router next-hop not stored: got %q want %q", cfg.System.BackupRouter, nh)
		}
		if cfg.System.BackupRouterDst != "" {
			t.Fatalf("empty destination should stay empty for the netlink reconciler to default: %q", cfg.System.BackupRouterDst)
		}
		if hasBackupRouterFamilyWarning(cfg) {
			t.Fatalf("empty destination must not warn, warnings=%v", cfg.Warnings)
		}
	}
}

// The lenient (tolerant load / peer-sync) path WARNS instead of rejecting, so
// an already-persisted bad config still boots (#1960 fail-closed-on-load).
func TestBackupRouterMismatchLenientWarns(t *testing.T) {
	tree := buildTree(t, []string{
		"set system backup-router 2001:db8::1 destination 0.0.0.0/0",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient load of a mismatched backup-router must NOT fail (brick-on-restart), got: %v", err)
	}
	if !hasBackupRouterFamilyWarning(cfg) {
		t.Fatalf("lenient load must emit a family-mismatch warning, warnings=%v", cfg.Warnings)
	}
}

// The node-aware lenient path (HA peer-sync / display) also warns rather than
// failing.
func TestBackupRouterMismatchLenientForNodeWarns(t *testing.T) {
	tree := buildTree(t, []string{
		"set system backup-router 192.168.50.1 destination ::/0",
	})
	cfg, err := CompileConfigForNodeLenient(tree, 0)
	if err != nil {
		t.Fatalf("node-aware lenient load must NOT fail, got: %v", err)
	}
	if !hasBackupRouterFamilyWarning(cfg) {
		t.Fatalf("node-aware lenient load must emit a family-mismatch warning, warnings=%v", cfg.Warnings)
	}
}
