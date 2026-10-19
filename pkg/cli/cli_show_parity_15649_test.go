package cli

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// #15649 parity: CLI detail must show then-count + live Session statistics,
// standard view must show count, printAppDetail must resolve sets/terms,
// screen must reject unknown args, flow timeouts must use SSOT.

func parityConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Security.PolicyStatsEnabled = true
	cfg.Security.Zones = map[string]*config.ZoneConfig{"trust": {Name: "trust"}, "untrust": {Name: "untrust"}}
	cfg.Applications.Applications = map[string]*config.Application{
		"custom-term-web": {Name: "custom-term-web", Protocol: "tcp", DestinationPort: "8443", ALG: "ssl"},
		"custom-term-alt": {Name: "custom-term-alt", Protocol: "udp", DestinationPort: "8443"},
	}
	cfg.Applications.ApplicationSets = map[string]*config.ApplicationSet{
		"custom-set": {Name: "custom-set", Applications: []string{"custom-term-web", "custom-term-alt"}},
		"outer-set":  {Name: "outer-set", Applications: []string{"custom-set", "junos-ssh"}},
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "trust", ToZone: "untrust",
		Policies: []*config.Policy{{
			Name:  "p-count",
			Count: true,
			Match: config.PolicyMatch{SourceAddresses: []string{"any"}, DestinationAddresses: []string{"any"}, Applications: []string{"outer-set"}},
		}},
	}}
	return cfg
}

func TestCLIPolicyDetailCountAndStats15649(t *testing.T) {
	cfg := parityConfig()
	c := &CLI{dp: &policyCounterCLIDP{Manager: dataplane.New(), counters: map[uint32]dataplane.CounterValue{0: {Packets: 42, Bytes: 4200}}}}
	out := captureStdout(t, func() {
		if err := c.showPoliciesDetail(cfg, "", ""); err != nil {
			t.Fatalf("detail: %v", err)
		}
	})
	if !strings.Contains(out, "count") {
		t.Errorf("detail missing then count:\n%s", out)
	}
	if !strings.Contains(out, "42 packets, 4200 bytes") {
		t.Errorf("detail missing live session statistics:\n%s", out)
	}
	// expanded applications: outer-set leaves must detail
	if !strings.Contains(out, "8443") || !strings.Contains(out, "ssl") {
		t.Errorf("detail did not expand outer-set terms:\n%s", out)
	}
	if !strings.Contains(out, "22") {
		t.Errorf("detail did not resolve predefined junos-ssh in outer-set:\n%s", out)
	}
}

func TestCLIScreenUnknownArg15649(t *testing.T) {
	c := &CLI{}
	if err := c.handleShowScreen([]string{"bogus-target"}); err == nil {
		t.Fatalf("unknown screen arg must error")
	}
	if err := c.handleShowScreen([]string{"ids-option", "p", "bogus"}); err == nil {
		t.Fatalf("trailing screen arg must error")
	}
}

func TestCLIFlowTimeoutsSSOT15649(t *testing.T) {
	store := flowTimeoutStore(t, []string{"set security zones security-zone trust", "set security flow gre-performance-acceleration"})
	c := &CLI{store: store}
	out := captureStdout(t, func() {
		if err := c.showFlowTimeouts(); err != nil {
			t.Fatalf("showFlowTimeouts: %v", err)
		}
	})
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "ICMP") && strings.Contains(l, "30s") {
			t.Errorf("ICMP 30s regression: %q", l)
		}
	}
	if !strings.Contains(out, "60s (default)") {
		t.Errorf("missing 60s default:\n%s", out)
	}
	if strings.Contains(out, "#5804") {
		t.Errorf("stale GRE text:\n%s", out)
	}
}
