package config

import (
	"strings"
	"testing"
)

// #15652 V5-04: header-elided / value-in-child application leaves were
// silently dropped by applicationDirectLeaves: `destination-port { [ 80 443 ]; }`
// kept only 80 and `protocol { tcp destination-port 8080; }` kept tcp with
// no port (all-port). Canonical resolver must never silently widen.
// These tests fail on the divergent compiler: bracket form yields "80",
// protocol-child form yields "".

func TestHeaderElidedAppLeaves15652(t *testing.T) {
	t.Run("bracket destination-port list does not silently drop ports", func(t *testing.T) {
		src := "applications { application myapp { protocol tcp; destination-port { [ 80 443 ]; } } }"
		tree := hierTree(t, src)
		cfg, err := CompileConfig(tree)
		if err == nil {
			// Must not compile clean with only 80.
			app := cfg.Applications.Applications["myapp"]
			if app == nil {
				t.Fatalf("myapp missing")
			}
			if app.DestinationPort == "80" {
				t.Fatalf("bracket list silently dropped 443: dport=%q (fail-closed or preserve required)", app.DestinationPort)
			}
			t.Fatalf("bracket list compiled without error but dport=%q; want strict reject naming surplus", app.DestinationPort)
		}
		if !strings.Contains(err.Error(), "443") && !strings.Contains(err.Error(), "destination-port") {
			t.Fatalf("strict error must name dropped port/leaf, got %v", err)
		}
	})

	t.Run("protocol value-in-child preserves destination-port", func(t *testing.T) {
		src := "applications { application myapp { protocol { tcp destination-port 8080; } } }"
		cfg, err := CompileConfig(hierTree(t, src))
		if err != nil {
			t.Fatalf("strict compile must honor value-in-child, got %v", err)
		}
		app := cfg.Applications.Applications["myapp"]
		if app == nil {
			t.Fatalf("myapp missing")
		}
		if app.Protocol != "tcp" || app.DestinationPort != "8080" {
			t.Fatalf("myapp = proto %q dport %q, want tcp/8080", app.Protocol, app.DestinationPort)
		}
	})

	t.Run("destination-port block list does not silently drop ports", func(t *testing.T) {
		src := "applications { application myapp { protocol tcp; destination-port { 80; 443; } } }"
		_, err := CompileConfig(hierTree(t, src))
		if err == nil {
			t.Fatalf("block list with two ports must reject strict (single-valued leaf), got clean compile")
		}
	})

	t.Run("single destination-port block still compiles control", func(t *testing.T) {
		src := "applications { application myapp { protocol tcp; destination-port { 443; } } }"
		cfg, err := CompileConfig(hierTree(t, src))
		if err != nil {
			t.Fatalf("control must compile: %v", err)
		}
		app := cfg.Applications.Applications["myapp"]
		if app == nil || app.DestinationPort != "443" {
			t.Fatalf("control dport wrong: %+v", app)
		}
	})
}
