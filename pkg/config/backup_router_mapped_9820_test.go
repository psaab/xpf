package config

import (
	"strings"
	"testing"
)

// #9820: an IPv4-mapped next-hop is refused as a backup-router (product
// restriction) at strict commit and warned on the tolerant path —
// regardless of the destination. Mapped destinations keep the gate's
// long-standing behavior (v6-NH/mapped-dst ACCEPTS under matching v6;
// v4-NH/mapped-dst REFUSES as a mismatch); the render belt is what moves
// (Codex-B3).
//
// FAIL-ON-REVERT: drop the FRRAddrIsMapped arm from
// validateBackupRouterDst and the mapped REFUSE cells compile clean.

func TestBackupRouterMappedNextHopRefused_9820(t *testing.T) {
	for _, tc := range []struct {
		name string
		sets []string
	}{
		{"empty-dst", []string{"set system backup-router ::ffff:192.0.2.1"}},
		{"v6-dst", []string{"set system backup-router ::ffff:192.0.2.1 destination ::/0"}},
		{"v4-dst", []string{"set system backup-router ::ffff:192.0.2.1 destination 0.0.0.0/0"}},
		{"hex", []string{"set system backup-router ::ffff:c000:201"}},
		{"expanded", []string{"set system backup-router 0:0:0:0:0:ffff:c000:0201"}},
		{"uppercase", []string{"set system backup-router ::FFFF:C000:201"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := flatTreeFromSets(t, tc.sets...)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("mapped backup-router compiled without error (%v)", tc.sets)
			}
			// The v4-dst row already failed before #9820 (family
			// mismatch) — the mapped-specific reason is what proves
			// the new arm.
			if !strings.Contains(err.Error(), "IPv4-mapped") {
				t.Fatalf("error should give the mapped-specific reason, got: %v", err)
			}
		})
	}
}

func TestBackupRouterMappedNextHopLenientWarns_9820(t *testing.T) {
	tree := flatTreeFromSets(t, "set system backup-router ::ffff:192.0.2.1")
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient load must NOT fail, got: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "IPv4-mapped") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("lenient load must warn the mapped reason, warnings=%v", cfg.Warnings)
	}
}

func TestBackupRouterMappedDestinationGateUnmoved_9820(t *testing.T) {
	// B3 row 1: v6 NH + mapped dst — the gate ACCEPTS (v6 == v6), as
	// before. The belt is what changes (it used to veto this row).
	tree := flatTreeFromSets(t,
		"set system backup-router 2001:db8::1 destination ::ffff:10.0.0.0/104")
	cfg := assertCommitAccepts(t, tree)
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "backup-router") {
			t.Fatalf("B3 row 1 must not warn, warnings=%v", cfg.Warnings)
		}
	}
	// B3 row 2: v4 NH + mapped dst — REFUSED as a family mismatch (the
	// NH is plain v4, so the mapped arm does not fire).
	tree2 := flatTreeFromSets(t,
		"set system backup-router 192.168.50.1 destination ::ffff:10.0.0.0/104")
	_, err := CompileConfig(tree2)
	if err == nil || !strings.Contains(err.Error(), "does not match next-hop family") {
		t.Fatalf("B3 row 2 must refuse as a mismatch, got: %v", err)
	}
}

func TestBackupRouterPlainControls_9820(t *testing.T) {
	for _, tc := range []struct {
		name string
		sets []string
	}{
		{"v4-empty", []string{"set system backup-router 192.168.50.1"}},
		{"v6-empty", []string{"set system backup-router 2001:db8::1"}},
		{"v4-matched", []string{"set system backup-router 192.168.50.1 destination 0.0.0.0/0"}},
		{"v6-matched", []string{"set system backup-router 2001:db8::1 destination ::/0"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := flatTreeFromSets(t, tc.sets...)
			cfg := assertCommitAccepts(t, tree)
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "backup-router") {
					t.Fatalf("plain control must not warn, warnings=%v", cfg.Warnings)
				}
			}
		})
	}
}

// GLM-F2: a zoned literal is refused as malformed (net.ParseIP rejects
// zones), so the belt must agree by omitting it — netip alone would
// accept it and the renderer would emit a line FRR refuses.
func TestBackupRouterZonedNextHopRefused_9820(t *testing.T) {
	tree := flatTreeFromSets(t, "set system backup-router fe80::1%eth0")
	_, err := CompileConfig(tree)
	if err == nil || !strings.Contains(err.Error(), "not a valid IP address") {
		t.Fatalf("zoned backup-router must be refused as malformed, got: %v", err)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient load must NOT fail, got: %v", err)
	}
	if cfg.System.BackupRouter != "fe80::1%eth0" {
		t.Fatalf("lenient compile must retain the zoned value for the belt: %q", cfg.System.BackupRouter)
	}
}
