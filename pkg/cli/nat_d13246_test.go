package cli

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func dnatCfg13246(rules ...*config.NATRule) *config.Config {
	cfg := &config.Config{}
	cfg.Security.NAT.Destination = &config.DestinationNATConfig{
		Pools: map[string]*config.NATPool{
			"dp1": {Name: "dp1", Address: "10.0.0.5", Port: 8080},
		},
		RuleSets: []*config.NATRuleSet{{
			Name: "drs", FromZone: "untrust", ToZone: "trust",
			Rules: rules,
		}},
	}
	return cfg
}

func TestD13246NATShowEvilTwins(t *testing.T) {
	// Twin 3 (#7173): no-translation pool must not render 1024-65535.
	srcCfg := &config.Config{}
	srcCfg.Security.NAT.SourcePools = map[string]*config.NATPool{
		"nt": {Name: "nt", Addresses: []string{"203.0.113.1"}, PortNoTranslation: true},
	}
	out := captureStdout(t, func() {
		if err := (&CLI{}).showNATSource(srcCfg, nil); err != nil {
			t.Fatalf("showNATSource: %v", err)
		}
	})
	if strings.Contains(out, "1024-65535") {
		t.Fatalf("no-translation pool rendered a port range:\n%s", out)
	}
	if !strings.Contains(out, "no-translation") {
		t.Fatalf("no-translation pool not labelled:\n%s", out)
	}
	// Control: normal pool still renders range.
	srcCfg.Security.NAT.SourcePools["nt"].PortNoTranslation = false
	out = captureStdout(t, func() {
		if err := (&CLI{}).showNATSource(srcCfg, nil); err != nil {
			t.Fatalf("showNATSource control: %v", err)
		}
	})
	if !strings.Contains(out, "Port range: 1024-65535") {
		t.Fatalf("normal pool lost port range:\n%s", out)
	}

	// Twin 2 (#7363) + implicit action in default destination view.
	actionless := &config.NATRule{Name: "actionless"}
	plural := &config.NATRule{
		Name: "plural",
		Match: config.NATMatch{
			DestinationAddresses:    []string{"203.0.113.10/32", "203.0.113.11/32"},
			DestinationAddressNames: []string{"web-net"},
		},
		Then: config.NATThen{PoolName: "dp1"},
	}
	offRule := &config.NATRule{
		Name:  "off",
		Match: config.NATMatch{DestinationAddress: "203.0.113.20/32"},
		Then:  config.NATThen{Off: true},
	}
	wildcard := &config.NATRule{
		Name:  "wildcard",
		Match: config.NATMatch{DestinationAddress: "0.0.0.0/0"},
	}
	cfg := dnatCfg13246(actionless, plural, offRule, wildcard)
	out = captureStdout(t, func() {
		if err := (&CLI{}).showNATDestination(cfg, nil); err != nil {
			t.Fatalf("showNATDestination: %v", err)
		}
	})
	for _, want := range []string{
		"Match destination-address: 203.0.113.10/32 203.0.113.11/32 web-net",
		"Match destination-address: 0.0.0.0/0",
		"Then pool: dp1",
		"Action: none",
		"Action: off",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("showNATDestination missing %q:\n%s", want, out)
		}
	}

	// Twins 1: rule-set and rule-all views.
	for _, view := range []struct {
		name string
		run  func() error
	}{
		{"rule-set", func() error { return (&CLI{}).showNATDestinationRuleSet(cfg, "drs") }},
		{"rule-all", func() error { return (&CLI{}).showNATDestinationRuleAll(cfg, "") }},
	} {
		out = captureStdout(t, func() {
			if err := view.run(); err != nil {
				t.Fatalf("%s: %v", view.name, err)
			}
		})
		if !strings.Contains(out, "Action: none") {
			t.Fatalf("%s: actionless rule not rendered none:\n%s", view.name, out)
		}
		if !strings.Contains(out, "Action: off") {
			t.Fatalf("%s: explicit off control lost:\n%s", view.name, out)
		}
		if !strings.Contains(out, "Action: pool dp1") {
			t.Fatalf("%s: pool control lost:\n%s", view.name, out)
		}
	}
}
