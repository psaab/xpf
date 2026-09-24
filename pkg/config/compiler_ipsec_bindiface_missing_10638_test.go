package config

import (
	"strings"
	"testing"
)

// Tests for #10638: a `security ipsec vpn` with NO `bind-interface` committed
// cleanly on the strict path (the gate explicitly skipped empty bind-interface),
// but every apply then installed a box-wide quarantine guard dropping all
// non-loopback INPUT and FORWARD in inet and bridge at priority -200 —
// management plane, IKE, BGP and cluster heartbeat lost until the config
// changed. Chain: validateSecureTunnelBindInterfaceAST skipped empty
// (compiler_ipsec_bindiface.go); buildIpsecCaptureQueuePlan adds
// IFIDUnderivable on vpn.BindInterface == "" and stageIpsecCapture runs on
// every apply (pkg/daemon); the divert guard exempts only iifname lo
// (pkg/nftables/ipsec_divert.go, #10501).
//
// Route-based (st0/XFRM) IPsec is the ONLY IPsec model xpf supports
// (policy-based `then permit tunnel` is hard-rejected at commit, #3114), so
// every VPN requires a usable bind-interface. The fix REJECTS a
// bind-interface-less VPN at strict commit (CompileConfig) and WARNS on the
// tolerant load / peer-sync path (CompileConfigLenient), mirroring the #5297
// invalid-name arm and the #1960 fail-closed-on-strict / lenient-on-load
// doctrine.
//
// Flat-set syntax MUST be built with ParseSetCommand/SetPath
// (buildBindIfaceTree), never NewParser (CLAUDE.md "Testing flat set syntax").

// TestSecureTunnelBindIfaceMissingRejectedAtCommit proves a VPN with no
// bind-interface is hard-rejected at strict commit with an actionable message.
//
// FAIL-ON-REVERT: reverting the missing-bind arm in
// validateSecureTunnelBindInterfaceAST back to a bare `continue` makes these
// configs compile clean (no error) → this test expects an error and goes RED.
func TestSecureTunnelBindIfaceMissingRejectedAtCommit(t *testing.T) {
	cases := []struct {
		name string
		cmds []string
		want []string // substrings expected in the commit error
	}{
		{
			name: "vpn with gateway but no bind-interface",
			cmds: []string{
				"set security ipsec vpn V gateway 203.0.113.1",
			},
			want: []string{
				"security ipsec vpn V",
				"bind-interface",
				"st<N> or st<N>.<unit>",
				"#10638",
			},
		},
		{
			name: "packed one-liner without bind-interface",
			cmds: []string{
				"set security ipsec vpn W gateway G",
			},
			want: []string{
				"security ipsec vpn W",
				"bind-interface",
				"#10638",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildBindIfaceTree(t, tc.cmds...)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("CompileConfig accepted a bind-interface-less VPN; want reject (#10638)")
			}
			for _, sub := range tc.want {
				if !strings.Contains(err.Error(), sub) {
					t.Errorf("error %q missing substring %q", err.Error(), sub)
				}
			}
		})
	}
}

// TestSecureTunnelBindIfaceMissingLenientWarns proves the tolerant
// load/peer-sync path downgrades a missing bind-interface to a warning and
// still compiles — a config an older binary silently accepted must still BOOT
// (#1960), not fail closed. The runtime capture-plan quarantine stays the
// fail-closed backstop for such a config.
func TestSecureTunnelBindIfaceMissingLenientWarns(t *testing.T) {
	tree := buildBindIfaceTree(t,
		"set security ipsec vpn V gateway 203.0.113.1")
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient rejected missing bind-interface (want warn): %v", err)
	}
	var found bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "security ipsec vpn V") && strings.Contains(w, "#10638") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("lenient compile produced no missing bind-interface warning; got %v", cfg.Warnings)
	}
}

// TestSecureTunnelBindIfaceMissingValidStillCommits_10638NonRegression proves
// the #10638 missing-bind arm did NOT disturb valid configs: a VPN with a
// canonical bind-interface still commits cleanly with no new warning.
func TestSecureTunnelBindIfaceMissingValidStillCommits_10638NonRegression(t *testing.T) {
	tree := buildBindIfaceTree(t,
		"set security ipsec vpn V bind-interface st0.0",
		"set security ipsec vpn V gateway 203.0.113.1")
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig rejected a valid bind-interface: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#10638") {
			t.Fatalf("valid bind-interface produced a #10638 warning: %q", w)
		}
	}
}
