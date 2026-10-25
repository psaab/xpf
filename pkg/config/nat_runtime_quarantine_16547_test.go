package config

import (
	"strings"
	"testing"
)

// #16547: the runtime interface-SNAT overlap quarantine token must expand
// to operator prose, and the WithRuntime compositions must fold the
// applied snapshot's verdict in without overriding a config verdict.

func TestSourceNATDisarmReasonTextIfaceOverlap16547(t *testing.T) {
	got := SourceNATDisarmReasonText("iface_snat_egress_overlap")
	if got == "" || got == "iface_snat_egress_overlap" {
		t.Fatalf("iface_snat_egress_overlap rendered as %q; want operator prose, not the raw token or empty", got)
	}
	if !strings.Contains(got, "interface") || !strings.Contains(got, "overlap") {
		t.Errorf("prose %q must name the interface-SNAT egress overlap", got)
	}
}

func runtimeCfg16547() (*Config, *NATRule) {
	pool := &NATPool{Name: "P", Addresses: []string{"203.0.113.7"}}
	cfg := &Config{}
	cfg.Security.NAT.SourcePools = map[string]*NATPool{"P": pool}
	rule := &NATRule{Name: "pool-snat"}
	rule.Then.PoolName = "P"
	return cfg, rule
}

func TestSourceNATRuleNotInstalledReasonWithRuntime16547(t *testing.T) {
	cfg, rule := runtimeCfg16547()
	// Control: config-only verdict is armed (usable pool).
	if got := SourceNATRuleNotInstalledReason(cfg, rule); got != "" {
		t.Fatalf("control: config verdict = %q, want armed", got)
	}
	// Runtime quarantine fills the gap.
	if got := SourceNATRuleNotInstalledReasonWithRuntime(cfg, rule, "iface_snat_egress_overlap"); got != "iface_snat_egress_overlap" {
		t.Fatalf("runtime verdict = %q, want iface_snat_egress_overlap", got)
	}
	// No runtime verdict: stays armed.
	if got := SourceNATRuleNotInstalledReasonWithRuntime(cfg, rule, ""); got != "" {
		t.Fatalf("no-runtime verdict = %q, want armed", got)
	}
	// Config verdict wins over runtime: an empty pool reports empty_pool.
	empty := &Config{}
	empty.Security.NAT.SourcePools = map[string]*NATPool{"P": {Name: "P"}}
	if got := SourceNATRuleNotInstalledReasonWithRuntime(empty, rule, "iface_snat_egress_overlap"); got != "empty_pool" {
		t.Fatalf("config precedence: got %q, want empty_pool", got)
	}
}

func TestSourceNATPoolNotInstalledReasonWithRuntime16547(t *testing.T) {
	cfg, _ := runtimeCfg16547()
	pool := cfg.Security.NAT.SourcePools["P"]
	if got := SourceNATPoolNotInstalledReasonWithRuntime(cfg, pool, "P", nil, "iface_snat_egress_overlap"); got != "iface_snat_egress_overlap" {
		t.Fatalf("pool runtime verdict = %q, want iface_snat_egress_overlap", got)
	}
	if got := SourceNATPoolNotInstalledReasonWithRuntime(cfg, pool, "P", nil, ""); got != "" {
		t.Fatalf("pool no-runtime verdict = %q, want armed", got)
	}
	empty := &NATPool{Name: "E"}
	if got := SourceNATPoolNotInstalledReasonWithRuntime(cfg, empty, "E", nil, "iface_snat_egress_overlap"); got != "empty_pool" {
		t.Fatalf("pool config precedence: got %q, want empty_pool", got)
	}
}
