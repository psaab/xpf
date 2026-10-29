package config

import (
	"fmt"
	"strings"
	"testing"
)

// Tests for #16699/#17779: each valid VPN claimant emits four queue keys,
// and the runtime capture plan quarantines all keys when multiple VPN names
// claim one if_id (OwnerContested), regardless of whether their selectors
// are disjoint. The same plan bounds a generation to 32 VPN claimants.
// Strict commit rejects / lenient load warns for both runtime refusal cases;
// a 32-VPN / 32-if_id control still compiles.
//
// Flat-set syntax MUST be built with ParseSetCommand/SetPath
// (buildBindIfaceTree), never NewParser.

func bindIfaceLimitCmds(tunnels int) []string {
	cmds := make([]string, 0, tunnels*3)
	for i := range tunnels {
		cmds = append(cmds,
			fmt.Sprintf("set security ipsec vpn V%02d bind-interface st%d.0", i, i),
			fmt.Sprintf("set security ipsec vpn V%02d gateway 203.0.113.%d", i, i+1),
			// Per-VPN PSK and peer IP keep the unrelated #14139 / #17772
			// identity gates silent; the control measures only #16699.
			fmt.Sprintf("set security ipsec vpn V%02d pre-shared-key ascii-text fixture-secret-%02d", i, i))
	}
	return cmds
}

// TestSecureTunnelCaptureLimitRejectedAtCommit16699 proves a 33-distinct-
// tunnel config is hard-rejected at strict commit with a message naming
// the limit, and the 32-tunnel control commits cleanly.
//
// FAIL-ON-REVERT: removing the #16699 arm in
// validateSecureTunnelBindInterfaceAST makes the 33-tunnel compile
// succeed -> this test goes RED.
func TestSecureTunnelCaptureLimitRejectedAtCommit16699(t *testing.T) {
	tree := buildBindIfaceTree(t, bindIfaceLimitCmds(33)...)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("CompileConfig accepted 33 distinct route-based VPN tunnels; want reject (#16699)")
	}
	for _, sub := range []string{"33", "32", "route-based", "#16699"} {
		if !strings.Contains(err.Error(), sub) {
			t.Errorf("error %q missing substring %q", err.Error(), sub)
		}
	}

	control := buildBindIfaceTree(t, bindIfaceLimitCmds(32)...)
	cfg, err := CompileConfig(control)
	if err != nil {
		t.Fatalf("CompileConfig rejected the 32-tunnel control: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#16699") {
			t.Fatalf("32-tunnel control produced a #16699 warning: %q", w)
		}
	}
}

// TestSecureTunnelCaptureLimitLenientWarns16699 proves the tolerant
// load/peer-sync path downgrades the over-limit condition to a warning
// and still compiles — a persisted or peer-synced over-limit config must
// still BOOT (#1960). The daemon QUEUE_OPEN stage error stays the
// fail-closed runtime backstop.
func TestSecureTunnelCaptureLimitLenientWarns16699(t *testing.T) {
	tree := buildBindIfaceTree(t, bindIfaceLimitCmds(33)...)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient rejected 33 tunnels (want warn): %v", err)
	}
	var found bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#16699") && strings.Contains(w, "32") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("lenient compile produced no #16699 limit warning; got %v", cfg.Warnings)
	}
}

// TestSecureTunnelCaptureLimitRejectsSharedBindClaimants17779 reproduces
// the missed runtime rule: 33 VPNs on 32 if_ids (with V00 and V32 sharing
// st0.0 but using disjoint selectors) pass the old distinct-if_id limit,
// then the runtime plan quarantines the whole generation OwnerContested.
// The strict compiler now rejects with that aligned reason; lenient load
// warns, and the 32-VPN / 32-if_id control commits.
//
// FAIL-ON-REVERT: restoring the old len(len(byID)) gate lets this strict
// fixture compile because it contains only 32 distinct if_ids.
func TestSecureTunnelCaptureLimitRejectsSharedBindClaimants17779(t *testing.T) {
	cmds := bindIfaceLimitCmds(32)
	// Keep #11380 quiet so this exercises the capture-plan claimant rule,
	// not selector overlap. Unique remote ranges make the shared bind valid
	// for the selector gate while the capture plan still contests the owner.
	cmds = append(cmds,
		"set security ipsec vpn V00 traffic-selector to-peer-a remote-ip 198.51.100.0/24",
		"set security ipsec vpn V32 bind-interface st0.0",
		"set security ipsec vpn V32 gateway 203.0.113.33",
		"set security ipsec vpn V32 pre-shared-key ascii-text fixture-secret-32",
		"set security ipsec vpn V32 traffic-selector to-peer-b remote-ip 198.51.101.0/24")
	tree := buildBindIfaceTree(t, cmds...)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("strict compile accepted 33 VPNs with two claimants on if_id 1; want runtime-aligned quarantine rejection")
	}
	for _, sub := range []string{
		"V00", "V32", "if_id 1", "at most one claimant per if_id",
		"OwnerContested", "#17779",
	} {
		if !strings.Contains(err.Error(), sub) {
			t.Errorf("strict error %q missing substring %q", err.Error(), sub)
		}
	}

	cfg, err := CompileConfigLenient(buildBindIfaceTree(t, cmds...))
	if err != nil {
		t.Fatalf("lenient compile rejected persisted shared-bind config: %v", err)
	}
	foundWarning := false
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "#17779") &&
			strings.Contains(warning, "OwnerContested") &&
			strings.Contains(warning, "at most one claimant per if_id") {
			foundWarning = true
			break
		}
	}
	if !foundWarning {
		t.Fatalf("lenient compile produced no runtime-aligned OwnerContested warning: %v", cfg.Warnings)
	}

	control, err := CompileConfig(buildBindIfaceTree(t, bindIfaceLimitCmds(32)...))
	if err != nil {
		t.Fatalf("CompileConfig rejected 32 VPNs on 32 distinct if_ids: %v", err)
	}
	for _, warning := range control.Warnings {
		if strings.Contains(warning, "#17779") {
			t.Fatalf("32/32 control produced a #17779 warning: %q", warning)
		}
	}
}
