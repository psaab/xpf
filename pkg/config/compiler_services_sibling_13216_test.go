package config

import (
	"strings"
	"testing"
)

// #13216 (D3-10): repeated sibling service containers under one parent are
// merged by Junos/flat-set semantics but were silently dropped by singular
// FindChild reads, and ip-monitoring validation depended on Go map order.

func parseHier13216(t *testing.T, src string) *ConfigTree {
	t.Helper()
	p := NewParser(src)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	return tree
}

func TestCompileServicesMultipleSiblingBlocks13216(t *testing.T) {
	src := `services {
  rpm { probe p1 { test t1 { probe-type icmp-ping; target address 192.0.2.1; } } }
  rpm { probe p2 { test t2 { probe-type icmp-ping; target address 192.0.2.2; } } }
  ip-monitoring { policy a-pol { match { rpm-probe p1; } then { preferred-route { route 0.0.0.0/0 { next-hop 192.0.2.1; } } } } }
  ip-monitoring { policy b-pol { match { rpm-probe p2; } then { preferred-route { route 0.0.0.0/0 { next-hop 192.0.2.2; } } } } }
  flow-monitoring { version9 { template v9a { flow-active-timeout 60; } } }
  flow-monitoring { version-ipfix { template ipfixa { flow-active-timeout 61; } } }
}`
	cfg, err := CompileConfigLenient(parseHier13216(t, src))
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	if cfg.Services.RPM == nil || cfg.Services.RPM.Probes["p1"] == nil || cfg.Services.RPM.Probes["p2"] == nil {
		t.Fatalf("sibling rpm blocks dropped: %+v", cfg.Services.RPM)
	}
	if cfg.Services.IPMonitoring == nil || cfg.Services.IPMonitoring.Policies["a-pol"] == nil || cfg.Services.IPMonitoring.Policies["b-pol"] == nil {
		t.Fatalf("sibling ip-monitoring blocks dropped: %+v", cfg.Services.IPMonitoring)
	}
	if cfg.Services.FlowMonitoring == nil || cfg.Services.FlowMonitoring.Version9 == nil || cfg.Services.FlowMonitoring.VersionIPFIX == nil {
		t.Fatalf("sibling flow-monitoring blocks dropped: %+v", cfg.Services.FlowMonitoring)
	}
	if cfg.Services.FlowMonitoring.Version9.Templates["v9a"] == nil || cfg.Services.FlowMonitoring.VersionIPFIX.Templates["ipfixa"] == nil {
		t.Fatalf("flow templates dropped: %+v", cfg.Services.FlowMonitoring)
	}
}

func TestCompileFlowMonitoringMultipleVersionBlocks13216(t *testing.T) {
	src := `services {
  flow-monitoring {
    version9 { template v9a { flow-active-timeout 60; } }
    version9 { template v9b { flow-active-timeout 62; } }
    version-ipfix { template ipfixa { flow-active-timeout 61; } }
    version-ipfix { template ipfixb { flow-active-timeout 63; } }
  }
}`
	cfg, err := CompileConfigLenient(parseHier13216(t, src))
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	fm := cfg.Services.FlowMonitoring
	if fm == nil || fm.Version9 == nil || fm.Version9.Templates["v9a"] == nil || fm.Version9.Templates["v9b"] == nil {
		t.Fatalf("sibling version9 blocks dropped: %+v", fm)
	}
	if fm.VersionIPFIX == nil || fm.VersionIPFIX.Templates["ipfixa"] == nil || fm.VersionIPFIX.Templates["ipfixb"] == nil {
		t.Fatalf("sibling version-ipfix blocks dropped: %+v", fm)
	}
}

func TestCompileDHCPLocalServerMultipleDynamicDNS13216(t *testing.T) {
	src := `system {
  services {
    dhcp-local-server {
      dynamic-dns { domain corp.example.com; }
      dynamic-dns { ttl 600; }
    }
  }
}`
	cfg, err := CompileConfigLenient(parseHier13216(t, src))
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	ddns := cfg.System.DHCPServer.DynamicDNS
	if ddns == nil || ddns.Domain != "corp.example.com" || ddns.TTLSeconds != 600 {
		t.Fatalf("sibling dynamic-dns blocks not merged: %+v", ddns)
	}
}

func TestValidateIPMonitoringDeterministicOrder13216(t *testing.T) {
	for i := 0; i < 30; i++ {
		cfg := &Config{}
		cfg.Services.RPM = &RPMConfig{Probes: map[string]*RPMProbe{"p": {Name: "p"}}}
		cfg.Services.IPMonitoring = &IPMonitoringConfig{Policies: map[string]*IPMonitoringPolicy{
			"b-pol": {Name: "b-pol", MatchRPMProbe: "p", PreferredRoutes: []*PreferredRoute{{Destination: "bad"}}},
			"a-pol": {Name: "a-pol", MatchRPMProbe: "p", PreferredRoutes: []*PreferredRoute{{Destination: "bad"}}},
		}}
		err := validateIPMonitoringStrict(cfg)
		if err == nil || !strings.Contains(err.Error(), `"a-pol"`) {
			t.Fatalf("iteration %d: want deterministic a-pol error, got %v", i, err)
		}
	}
}
