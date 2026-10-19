package cli

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// #15773 RED fixtures: >=2 rules per family; r-disarmed via empty source
// pool, r-notrans via port no-translation pool, dr-disarmed via addressless
// destination pool.

func natRuleNameCfg15773() *config.Config {
	cfg := &config.Config{}
	cfg.Security.NAT.SourcePools = map[string]*config.NATPool{
		"p-empty":   {Name: "p-empty"},
		"p-notrans": {Name: "p-notrans", Address: "192.0.2.20", PortNoTranslation: true},
		"p-normal":  {Name: "p-normal", Address: "192.0.2.10"},
	}
	cfg.Security.NAT.Source = []*config.NATRuleSet{{
		Name: "rs1", FromZone: "trust", ToZone: "untrust",
		Rules: []*config.NATRule{
			{Name: "r-disarmed", Match: config.NATMatch{SourceAddress: "10.0.0.0/8"}, Then: config.NATThen{PoolName: "p-empty"}},
			{Name: "r-notrans", Match: config.NATMatch{SourceAddress: "10.1.0.0/16"}, Then: config.NATThen{PoolName: "p-notrans"}},
			{Name: "r-normal", Match: config.NATMatch{SourceAddress: "10.2.0.0/16"}, Then: config.NATThen{PoolName: "p-normal"}},
		},
	}}
	cfg.Security.NAT.Destination = &config.DestinationNATConfig{
		Pools: map[string]*config.NATPool{
			"dp-empty":  {Name: "dp-empty"},
			"dp-normal": {Name: "dp-normal", Address: "192.0.2.50", Port: 8080},
			"dp-lonely": {Name: "dp-lonely", Address: "192.0.2.60"},
		},
		RuleSets: []*config.NATRuleSet{{
			Name: "drs1", FromZone: "untrust",
			Rules: []*config.NATRule{
				{Name: "dr-disarmed", Match: config.NATMatch{DestinationAddress: "203.0.113.1/32"}, Then: config.NATThen{PoolName: "dp-empty"}},
				{Name: "dr-normal", Match: config.NATMatch{DestinationAddress: "203.0.113.2/32"}, Then: config.NATThen{PoolName: "dp-normal"}},
			},
		}},
	}
	return cfg
}

func TestLocalNATRuleNameFilter15773(t *testing.T) {
	cfg := natRuleNameCfg15773()
	c := &CLI{dp: dataplane.New()}

	out := captureStdout(t, func() {
		if err := c.showNATSource(cfg, []string{"rule", "r-disarmed"}); err != nil {
			t.Fatalf("source rule r-disarmed: %v", err)
		}
	})
	if !strings.Contains(out, "r-disarmed") || strings.Contains(out, "r-normal") || strings.Contains(out, "r-notrans") {
		t.Errorf("source rule <name> must show only named rule:\n%s", out)
	}
	if !strings.Contains(out, "NOT INSTALLED") {
		t.Errorf("disarmed named source rule must carry NOT INSTALLED:\n%s", out)
	}
	if !strings.Contains(out, "Total source NAT rules: 1") {
		t.Errorf("filtered total must be 1:\n%s", out)
	}

	out = captureStdout(t, func() {
		if err := c.showNATSource(cfg, []string{"rule", "r-notrans"}); err != nil {
			t.Fatalf("source rule r-notrans: %v", err)
		}
	})
	if !strings.Contains(out, "r-notrans") || strings.Contains(out, "r-normal") {
		t.Errorf("source rule r-notrans filter:\n%s", out)
	}
	if !strings.Contains(out, "no-translation") {
		t.Errorf("port no-translation pool state must be visible for named rule:\n%s", out)
	}
	if strings.Contains(out, "NOT INSTALLED") {
		t.Errorf("armed no-translation rule must not be NOT INSTALLED:\n%s", out)
	}

	out = captureStdout(t, func() {
		if err := c.showNATDestination(cfg, []string{"rule", "dr-disarmed"}); err != nil {
			t.Fatalf("dest rule dr-disarmed: %v", err)
		}
	})
	if !strings.Contains(out, "dr-disarmed") || strings.Contains(out, "dr-normal") {
		t.Errorf("dest rule <name> must show only named rule:\n%s", out)
	}
	if !strings.Contains(out, "NOT INSTALLED") {
		t.Errorf("disarmed named dest rule must carry NOT INSTALLED:\n%s", out)
	}

	// Unknown names fail loudly (error, not silent all-rules / empty success).
	if err := c.showNATSource(cfg, []string{"rule", "nope"}); err == nil {
		t.Error("source rule unknown name: want error")
	}
	if err := c.showNATDestination(cfg, []string{"rule", "nope"}); err == nil {
		t.Error("destination rule unknown name: want error")
	}
	// Bare / all listings unchanged.
	for _, args := range [][]string{{"rule"}, {"rule", "all"}} {
		out = captureStdout(t, func() {
			if err := c.showNATSource(cfg, args); err != nil {
				t.Fatalf("source %v: %v", args, err)
			}
		})
		if !strings.Contains(out, "r-normal") || !strings.Contains(out, "r-disarmed") || !strings.Contains(out, "Total source NAT rules: 3") {
			t.Errorf("source %v must list all:\n%s", args, out)
		}
	}
	// Extra junk after name fails.
	if err := c.showNATSource(cfg, []string{"rule", "r-normal", "junk"}); err == nil {
		t.Error("source rule <name> junk: want error")
	}
	// Unreferenced destination pool stays visible in pool listing.
	out = captureStdout(t, func() {
		if err := c.showNATDestination(cfg, []string{"pool", "dp-lonely"}); err != nil {
			t.Fatalf("dest pool dp-lonely: %v", err)
		}
	})
	if !strings.Contains(out, "dp-lonely") {
		t.Errorf("unreferenced DNAT pool must be visible locally:\n%s", out)
	}
}
