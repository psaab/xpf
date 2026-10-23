package config

import (
	"strings"
	"testing"
)

// #15944 H21-01: `system backup-router` destinations must accumulate
// across backup-router nodes. Before the fix, each `backup-router`
// child truncated BackupRouterDsts to that one node's destinations, so
// a second node — a bare next-hop update, a sibling destination
// statement, or a second top-level `system` root — wiped the earlier
// prefixes, and the management-VRF builder silently fell back to the
// implicit family default route.
//
// FAIL-ON-REVERT: restoring `sys.BackupRouterDsts = sys.BackupRouterDsts[:0]`
// in the compiler makes the bare-update and sibling cells below lose
// the first node's destinations.

func TestBackupRouterPreservesDestinationsAcrossNodes15944(t *testing.T) {
	// Two nodes in one system block: destinations, then a bare
	// next-hop update. The destinations survive; the next-hop updates.
	cfg := compileHierStrict(t,
		"system { backup-router 192.0.2.1 { destination 10.0.0.0/8; destination 172.16.0.0/12; } backup-router 192.0.2.2; }\n")
	if cfg.System.BackupRouter != "192.0.2.2" {
		t.Fatalf("BackupRouter = %q, want 192.0.2.2 (last next-hop wins)", cfg.System.BackupRouter)
	}
	if !equalStrs15780(cfg.System.BackupRouterDsts, []string{"10.0.0.0/8", "172.16.0.0/12"}) {
		t.Fatalf("BackupRouterDsts = %v, want [10.0.0.0/8 172.16.0.0/12] preserved across the bare node", cfg.System.BackupRouterDsts)
	}
	if cfg.System.BackupRouterDst != "10.0.0.0/8" {
		t.Fatalf("BackupRouterDst = %q, want 10.0.0.0/8 (scalar stays in sync with [0])", cfg.System.BackupRouterDst)
	}

	// Sibling destination statements across two nodes accumulate,
	// deduplicated.
	cfg2 := compileHierStrict(t,
		"system { backup-router 192.0.2.1 destination 10.0.0.0/8; backup-router 192.0.2.2 destination 172.16.0.0/12; backup-router 192.0.2.2 destination 10.0.0.0/8; }\n")
	if !equalStrs15780(cfg2.System.BackupRouterDsts, []string{"10.0.0.0/8", "172.16.0.0/12"}) {
		t.Fatalf("sibling nodes: BackupRouterDsts = %v, want [10.0.0.0/8 172.16.0.0/12] deduped", cfg2.System.BackupRouterDsts)
	}
}

// The per-root dispatch arm: two top-level `system` roots each re-enter
// compileSystem; the second root's bare backup-router must not wipe the
// first root's destinations.
func TestBackupRouterPreservesAcrossSystemRoots15944(t *testing.T) {
	cfg := compileHierStrict(t,
		"system { backup-router 2001:db8::1 destination 2001:db8:1::/48; }\n"+
			"system { backup-router 2001:db8::2; }\n")
	if cfg.System.BackupRouter != "2001:db8::2" {
		t.Fatalf("BackupRouter = %q, want 2001:db8::2", cfg.System.BackupRouter)
	}
	if !equalStrs15780(cfg.System.BackupRouterDsts, []string{"2001:db8:1::/48"}) {
		t.Fatalf("across roots: BackupRouterDsts = %v, want [2001:db8:1::/48] preserved", cfg.System.BackupRouterDsts)
	}
}

// #15944 H21-03: repeated `netconf` siblings under one `services` node.
// The singular FindChild("netconf") consulted only the first (empty)
// sibling, so `netconf { } netconf { ssh; }` compiled NetconfSSH=false
// and lost both the show row and the not-served warning.
//
// FAIL-ON-REVERT: restoring the singular FindChild read makes the
// sibling cell compile NetconfSSH=false with no warning.
func TestNetconfSSHSiblingNodes15944(t *testing.T) {
	cfg := compileHierStrict(t, "system { services { netconf { } netconf { ssh; } } }\n")
	if cfg.System.Services == nil || !cfg.System.Services.NetconfSSH {
		t.Fatalf("NetconfSSH = %v, want true (second sibling carries ssh)", cfg.System.Services)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "netconf ssh") {
			found = true
		}
	}
	if !found {
		t.Fatalf("warnings = %v, want the netconf not-served warning", cfg.Warnings)
	}

	// Controls: single block, and the packed spelling, still compile.
	if cfg := compileHierStrict(t, "system { services { netconf { ssh; } } }\n"); !cfg.System.Services.NetconfSSH {
		t.Fatal("single netconf { ssh; } must set NetconfSSH")
	}
	if cfg := compileHierStrict(t, "system { services { netconf { } } }\n"); cfg.System.Services != nil && cfg.System.Services.NetconfSSH {
		t.Fatal("netconf without ssh must not set NetconfSSH")
	}
}
