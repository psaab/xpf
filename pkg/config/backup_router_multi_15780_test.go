package config

import (
	"strings"
	"testing"
)

// #15780: `system backup-router <addr> destination` modelled a single
// scalar prefix. A bracketed list `[ 0.0.0.0/1 128.0.0.0/1 ]` kept only
// the first prefix, repeated `destination` leaves kept only the last,
// and every additional prefix bypassed validateBackupRouterDst. The
// daemon likewise installed exactly one table-999 route.
//
// FAIL-ON-REVERT: restoring the scalar compiler read / non-multi schema
// leaf makes the bracket and repeated-leaf cells below compile to a
// single destination (or reject the list), and restoring the scalar
// validator makes the invalid-second-prefix cells compile clean.

func equalStrs15780(a, b []string) bool {
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

// Bracketed two-prefix flat-set fixture compiles to BOTH destinations.
func TestBackupRouterBracketListRetainsAll15780(t *testing.T) {
	tree := buildTree(t, []string{
		"set system backup-router 192.0.2.1 destination [ 0.0.0.0/1 128.0.0.0/1 ]",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("bracketed multi-destination backup-router must compile, got: %v", err)
	}
	want := []string{"0.0.0.0/1", "128.0.0.0/1"}
	if !equalStrs15780(cfg.System.BackupRouterDsts, want) {
		t.Fatalf("BackupRouterDsts = %v, want %v (extra prefixes silently dropped)", cfg.System.BackupRouterDsts, want)
	}
	if cfg.System.BackupRouterDst != "0.0.0.0/1" {
		t.Fatalf("BackupRouterDst (scalar first) = %q, want 0.0.0.0/1", cfg.System.BackupRouterDst)
	}
}

// Bracketed list in hierarchical spelling compiles to both destinations.
func TestBackupRouterBracketListHierarchical15780(t *testing.T) {
	src := "system {\n backup-router 192.0.2.1 {\n destination [ 0.0.0.0/1 128.0.0.0/1 ];\n }\n}\n"
	tree, perrs := NewParser(src).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("hierarchical bracket list must compile, got: %v", err)
	}
	want := []string{"0.0.0.0/1", "128.0.0.0/1"}
	if !equalStrs15780(cfg.System.BackupRouterDsts, want) {
		t.Fatalf("BackupRouterDsts = %v, want %v", cfg.System.BackupRouterDsts, want)
	}
}

// Repeated `destination` leaves (flat and hierarchical) retain all.
func TestBackupRouterRepeatedLeavesRetainAll15780(t *testing.T) {
	tree := buildTree(t, []string{
		"set system backup-router 192.0.2.1 destination 0.0.0.0/1",
		"set system backup-router 192.0.2.1 destination 128.0.0.0/1",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("repeated destination leaves must compile, got: %v", err)
	}
	want := []string{"0.0.0.0/1", "128.0.0.0/1"}
	if !equalStrs15780(cfg.System.BackupRouterDsts, want) {
		t.Fatalf("flat repeated: BackupRouterDsts = %v, want %v (last-wins drop)", cfg.System.BackupRouterDsts, want)
	}

	src := "system {\n backup-router 192.0.2.1 {\n destination 0.0.0.0/1;\n destination 128.0.0.0/1;\n }\n}\n"
	htree, perrs := NewParser(src).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	hcfg, err := CompileConfig(htree)
	if err != nil {
		t.Fatalf("hierarchical repeated leaves must compile, got: %v", err)
	}
	if !equalStrs15780(hcfg.System.BackupRouterDsts, want) {
		t.Fatalf("hier repeated: BackupRouterDsts = %v, want %v", hcfg.System.BackupRouterDsts, want)
	}
}

// An invalid SECOND prefix is rejected at strict commit, not skipped.
func TestBackupRouterInvalidSecondPrefixRejected15780(t *testing.T) {
	cases := []struct {
		name string
		cmds []string
	}{
		{"bracket-malformed-second", []string{"set system backup-router 192.0.2.1 destination [ 0.0.0.0/1 10.0.0.0/99 ]"}},
		{"repeated-malformed-second", []string{
			"set system backup-router 192.0.2.1 destination 0.0.0.0/1",
			"set system backup-router 192.0.2.1 destination notacidr",
		}},
		{"bracket-family-mismatch-second", []string{"set system backup-router 192.0.2.1 destination [ 0.0.0.0/1 ::/1 ]"}},
		{"repeated-family-mismatch-second", []string{
			"set system backup-router 192.0.2.1 destination 0.0.0.0/1",
			"set system backup-router 192.0.2.1 destination ::/1",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTree(t, tc.cmds)
			if _, err := CompileConfig(tree); err == nil {
				t.Fatalf("invalid second destination must be rejected, compiled clean (%v)", tc.cmds)
			} else if !strings.Contains(err.Error(), "backup-router") {
				t.Fatalf("error should name backup-router, got: %v", err)
			}
		})
	}
}

// Lenient load warns for an invalid second prefix instead of rejecting,
// so an already-persisted config still boots (#1960).
func TestBackupRouterInvalidSecondPrefixLenientWarns15780(t *testing.T) {
	tree := buildTree(t, []string{
		"set system backup-router 192.0.2.1 destination [ 0.0.0.0/1 10.0.0.0/99 ]",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient load must NOT fail, got: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "10.0.0.0/99") {
			found = true
		}
	}
	if !found {
		t.Fatalf("lenient load must warn naming the invalid second prefix, warnings=%v", cfg.Warnings)
	}
	if !equalStrs15780(cfg.System.BackupRouterDsts, []string{"0.0.0.0/1", "10.0.0.0/99"}) {
		t.Fatalf("lenient BackupRouterDsts = %v, want both prefixes retained", cfg.System.BackupRouterDsts)
	}
}

// IPv6 multi-destination list compiles and validates per prefix.
func TestBackupRouterIPv6MultiDestination15780(t *testing.T) {
	tree := buildTree(t, []string{
		"set system backup-router 2001:db8::1 destination [ 2001:db8:1::/48 2001:db8:2::/48 ]",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("IPv6 multi-destination must compile, got: %v", err)
	}
	want := []string{"2001:db8:1::/48", "2001:db8:2::/48"}
	if !equalStrs15780(cfg.System.BackupRouterDsts, want) {
		t.Fatalf("BackupRouterDsts = %v, want %v", cfg.System.BackupRouterDsts, want)
	}
}

// Single and empty destinations keep their prior behaviour.
func TestBackupRouterSingleAndEmptyUnchanged15780(t *testing.T) {
	tree := buildTree(t, []string{
		"set system backup-router 192.0.2.1 destination 10.0.0.0/8",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("single destination: %v", err)
	}
	if !equalStrs15780(cfg.System.BackupRouterDsts, []string{"10.0.0.0/8"}) || cfg.System.BackupRouterDst != "10.0.0.0/8" {
		t.Fatalf("single: Dsts=%v Dst=%q", cfg.System.BackupRouterDsts, cfg.System.BackupRouterDst)
	}

	tree2 := buildTree(t, []string{"set system backup-router 2001:db8::1"})
	cfg2, err := CompileConfig(tree2)
	if err != nil {
		t.Fatalf("empty destination: %v", err)
	}
	if len(cfg2.System.BackupRouterDsts) != 0 || cfg2.System.BackupRouterDst != "" {
		t.Fatalf("empty must stay empty for the family-aware daemon default, Dsts=%v Dst=%q", cfg2.System.BackupRouterDsts, cfg2.System.BackupRouterDst)
	}
}
