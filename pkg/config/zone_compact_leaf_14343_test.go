package config

import (
	"strings"
	"testing"
)

func TestSecurityZoneCompactLeafWithBracedBodyAndUnbracketedHeaderTokens(t *testing.T) {
	// Path A: body attached to leaf screen must not vanish; either compile
	// attaches to zone or strict rejects.
	t.Run("screen leaf with braced body", func(t *testing.T) {
		src := `security { screen { ids-option my-screen { icmp { ping-death; } } } zones { security-zone trust screen my-screen { interfaces { ge-0/0/0.0; } host-inbound-traffic { system-services { ssh; } } } } } interfaces { ge-0/0/0 { unit 0 { family inet { address 192.0.2.1/24; } } } }`
		tr, perrs := NewParser(src).Parse()
		if len(perrs) > 0 {
			t.Fatalf("parse %v", perrs)
		}
		cfg, err := compileConfigWithOpts(tr, compileOpts{})
		if err != nil {
			// Reject is acceptable fail-closed
			t.Logf("strict rejected (acceptable): %v", err)
			return
		}
		z := cfg.Security.Zones["trust"]
		if z == nil {
			t.Fatalf("no trust zone")
		}
		if z.ScreenProfile != "my-screen" {
			t.Errorf("Screen=%q want my-screen", z.ScreenProfile)
		}
		if len(z.Interfaces) == 0 {
			t.Errorf("Interfaces empty, body silently dropped: %+v", z)
		}
		if z.HostInboundTraffic == nil {
			t.Errorf("HIB nil, body dropped")
		}
		_ = strings.Contains
		_ = cfg
	})
	t.Run("description leaf with braced body", func(t *testing.T) {
		src := `security { zones { security-zone trust description hello { interfaces { ge-0/0/0.0; } } } } interfaces { ge-0/0/0 { unit 0 { family inet { address 192.0.2.1/24; } } } }`
		tr, perrs := NewParser(src).Parse()
		if len(perrs) > 0 {
			t.Fatalf("parse %v", perrs)
		}
		cfg, err := compileConfigWithOpts(tr, compileOpts{})
		if err != nil {
			t.Logf("strict rejected (acceptable): %v", err)
			return
		}
		z := cfg.Security.Zones["trust"]
		if z == nil || len(z.Interfaces) == 0 {
			t.Errorf("body dropped desc: %+v", z)
		}
	})
	t.Run("tcp-reset unbracketed", func(t *testing.T) {
		src := `security { zones { security-zone trust tcp-reset { interfaces { ge-0/0/0.0; } } } } interfaces { ge-0/0/0 { unit 0 { family inet { address 192.0.2.1/24; } } } }`
		tr, perrs := NewParser(src).Parse()
		if len(perrs) > 0 {
			t.Fatalf("parse %v", perrs)
		}
		cfg, err := compileConfigWithOpts(tr, compileOpts{})
		if err != nil {
			t.Logf("strict rejected (acceptable): %v", err)
			return
		}
		if _, ok := cfg.Security.Zones["tcp-reset"]; ok {
			t.Errorf("phantom zone tcp-reset minted")
		}
	})
	t.Run("bracketed control", func(t *testing.T) {
		src := screenDef8794 + `zones { security-zone [ trust untrust ] { screen edge; } } }`
		tr, perrs := NewParser(src).Parse()
		if len(perrs) > 0 {
			t.Fatalf("parse %v", perrs)
		}
		cfg, err := compileConfigWithOpts(tr, compileOpts{})
		if err != nil {
			t.Fatalf("bracketed control rejected: %v", err)
		}
		if cfg.Security.Zones["trust"] == nil || cfg.Security.Zones["untrust"] == nil {
			t.Errorf("bracketed broken")
		}
	})
	t.Run("bare group Format control", func(t *testing.T) {
		src := screenDef8794 + `zones { security-zone trust untrust { screen edge; } } }`
		tr, perrs := NewParser(src).Parse()
		if len(perrs) > 0 {
			t.Fatalf("parse %v", perrs)
		}
		cfg, err := compileConfigWithOpts(tr, compileOpts{})
		if err != nil {
			t.Fatalf("bare group rejected: %v", err)
		}
		if cfg.Security.Zones["trust"] == nil || cfg.Security.Zones["untrust"] == nil {
			t.Errorf("bare group (Format) broken: %v", cfg.Security.Zones)
		}
	})
}
