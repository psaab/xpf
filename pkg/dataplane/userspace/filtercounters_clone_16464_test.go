package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16464: helper counters published under a suppressed-member clone must
// fold into the authored source filter (same family/term) so readers that
// skip clones do not lose member-unit hits. Acceptance: 40 + 60 = 100.
//
// FAIL-ON-REVERT: reverting BuildFirewallFilterTermCounterIndexForConfig to
// the plain index leaves the clone key separate, so the source key reads 40.
func TestBuildFilterTermCounterIndexForConfigFoldsClone16464(t *testing.T) {
	realCfg := compileLenientSharedFBF16464(t)
	status := &ProcessStatus{FilterTermCounters: []FirewallFilterTermCounterStatus{
		{Family: "inet", FilterName: "shared-fbf", TermName: "steer", Packets: 40, Bytes: 4000},
		{Family: "inet", FilterName: cloneNameOf16464(t, realCfg), TermName: "steer", Packets: 60, Bytes: 6000},
		{Family: "inet", FilterName: "shared-fbf", TermName: "other", Packets: 7, Bytes: 70},
		{Family: "inet6", FilterName: cloneNameOf16464(t, realCfg), TermName: "steer", Packets: 999, Bytes: 9990},
	}}
	idx := BuildFirewallFilterTermCounterIndexForConfig(status, realCfg)
	got := idx[FirewallFilterTermCounterKey{Family: "inet", FilterName: "shared-fbf", TermName: "steer"}]
	if got.Packets != 100 || got.Bytes != 10000 {
		t.Fatalf("folded source steer = %d/%d, want 100/10000", got.Packets, got.Bytes)
	}
	if _, ok := idx[FirewallFilterTermCounterKey{Family: "inet", FilterName: cloneNameOf16464(t, realCfg), TermName: "steer"}]; ok {
		t.Fatalf("clone key must not remain after fold: %+v", idx)
	}
	// Control: distinct term untouched; wrong-family clone row NOT folded.
	if o := idx[FirewallFilterTermCounterKey{Family: "inet", FilterName: "shared-fbf", TermName: "other"}]; o.Packets != 7 {
		t.Fatalf("control term other = %d, want 7", o.Packets)
	}
	if w := idx[FirewallFilterTermCounterKey{Family: "inet6", FilterName: cloneNameOf16464(t, realCfg), TermName: "steer"}]; w.Packets != 999 {
		t.Fatalf("inet6 clone-named row must stay unfolded (clone is inet-only), got %d", w.Packets)
	}
	// Plain index (no config) must NOT fold — pins the opt-in.
	plain := BuildFirewallFilterTermCounterIndex(status)
	if p := plain[FirewallFilterTermCounterKey{Family: "inet", FilterName: "shared-fbf", TermName: "steer"}]; p.Packets != 40 {
		t.Fatalf("plain index source = %d, want 40 (no fold without cfg)", p.Packets)
	}
	// Nil cfg falls back to plain.
	if n := BuildFirewallFilterTermCounterIndexForConfig(status, nil); n[FirewallFilterTermCounterKey{Family: "inet", FilterName: "shared-fbf", TermName: "steer"}].Packets != 40 {
		t.Fatalf("nil-cfg index must not fold")
	}
}

func cloneNameOf16464(t *testing.T, cfg *config.Config) string {
	t.Helper()
	for name, f := range cfg.Firewall.FiltersInet {
		if src, _ := f.SuppressedMemberFBF11321(); src == "shared-fbf" {
			return name
		}
	}
	t.Fatalf("no clone of shared-fbf in %+v", cfg.Firewall.FiltersInet)
	return ""
}

func compileLenientSharedFBF16464(t *testing.T) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, cmd := range []string{
		"set routing-instances member-ri instance-type vrf",
		"set routing-instances member-ri interface ge-0/0/1.0",
		"set routing-instances steer-ri instance-type forwarding",
		"set firewall family inet filter shared-fbf term steer from source-address 192.0.2.0/24",
		"set firewall family inet filter shared-fbf term steer then count hits",
		"set firewall family inet filter shared-fbf term steer then routing-instance steer-ri",
		"set interfaces ge-0/0/1 unit 0 family inet filter input shared-fbf",
		"set interfaces ge-0/0/2 unit 0 family inet filter input shared-fbf",
	} {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	return cfg
}

// #16464: policer rows under a clone fold likewise.
func TestBuildThreeColorPolicerIndexForConfigFoldsClone16464(t *testing.T) {
	cfg := compileLenientSharedFBF16464(t)
	cloneName := cloneNameOf16464(t, cfg)
	status := &ProcessStatus{ThreeColorPolicerCounters: []ThreeColorPolicerStatus{
		{Name: "p1", Family: "inet", FilterName: "shared-fbf", TermName: "steer", GreenPackets: 10},
		{Name: "p1", Family: "inet", FilterName: cloneName, TermName: "steer", GreenPackets: 5},
	}}
	idx := BuildThreeColorPolicerStatusIndexForConfig(status, cfg)
	got, ok := idx[ThreeColorPolicerStatusKey{Family: "inet", FilterName: "shared-fbf", TermName: "steer", Policer: "p1"}]
	if !ok || got.GreenPackets != 15 {
		t.Fatalf("folded policer = %+v ok=%v, want green 15", got, ok)
	}
}
