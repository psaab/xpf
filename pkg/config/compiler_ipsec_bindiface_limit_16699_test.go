package config

import (
	"fmt"
	"strings"
	"testing"
)

// Tests for #16699: the IPsec capture generation is bounded to 32 distinct
// route-based VPN capture tunnels (MaxRouteBasedVPNCaptureTunnels), but no
// commit-time limit existed. A 33rd distinct bind-interface committed
// cleanly, stageIpsecCapture discarded the bound error and returned a
// QuarantineAll(QUEUE_OPEN) runtime with a nil error, and every apply
// installed a box-wide quarantine dropping all non-loopback,
// non-lifeline INPUT/FORWARD while the commit reported success.
//
// The fix mirrors #10638: strict commit / commit-check hard-rejects when
// the DISTINCT capture-tunnel count (distinct non-zero XFRM if_ids)
// exceeds the limit, naming the limit; the lenient load / peer-sync path
// warns and still boots (#1960). The daemon QUEUE_OPEN stage now also
// returns a non-nil error (see pkg/daemon 15068/16699 tests).
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

// TestSecureTunnelCaptureLimitCountsDistinctTunnels16699 proves the
// limit counts DISTINCT capture tunnels (distinct if_ids), not VPN
// stanzas: 33 VPNs sharing 32 distinct bind-interfaces stay within the
// capture bound (the shared-bind shape is governed by #11380, not this
// gate), so no #16699 rejection fires. The strict compile may still
// reject for other reasons; this
// test only asserts the #16699 limit is not the rejection reason.
func TestSecureTunnelCaptureLimitCountsDistinctTunnels16699(t *testing.T) {
	cmds := bindIfaceLimitCmds(32)
	// 33rd VPN shares V00's tunnel st0.0 but has its own peer IP and
	// PSK identity: still 32 distinct if_ids, without a #17772 collision.
	cmds = append(cmds,
		"set security ipsec vpn V32 bind-interface st0.0",
		"set security ipsec vpn V32 gateway 203.0.113.33",
		"set security ipsec vpn V32 pre-shared-key ascii-text fixture-secret-32")
	tree := buildBindIfaceTree(t, cmds...)
	_, err := CompileConfig(tree)
	if err != nil && strings.Contains(err.Error(), "#16699") {
		t.Fatalf("33 VPNs on 32 distinct tunnels rejected by the capture limit; want distinct-tunnel counting: %v", err)
	}
	cfg, lerr := CompileConfigLenient(tree)
	if lerr != nil {
		t.Fatalf("CompileConfigLenient: %v", lerr)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#16699") {
			t.Fatalf("33 VPNs on 32 distinct tunnels produced a #16699 warning: %q", w)
		}
	}
}
