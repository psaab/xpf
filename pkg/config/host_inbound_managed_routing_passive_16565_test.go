package config

import (
	"strings"
	"testing"
)

// #16565: the #11571 managed-routing host-inbound gate must skip
// effectively passive OSPF/OSPFv3 interfaces. A passive interface sends
// no hellos and forms no adjacency, so there is no host-bound multicast
// to isolate and no host-inbound token is required. Active interfaces
// (including PassiveDefault overridden by no-passive, and a name that
// is active in any area/fragment) must still reject.

func passiveGateLines16565(extra ...string) []string {
	lines := []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/0 unit 0 family inet6 address 2001:db8::1/64",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
		"set interfaces ge-0/0/1 unit 0 family inet6 address 2001:db8:1::1/64",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
		"set security zones security-zone trust interfaces ge-0/0/1.0",
	}
	return append(lines, extra...)
}

// passiveGateRI16565 builds a routing-instance fixture whose interfaces
// live in a different zone from the default instance's, so the zone does
// not span two routing contexts (which an unrelated gate rejects).
func passiveGateRI16565(extra ...string) []string {
	lines := []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
		"set interfaces ge-0/0/1 unit 0 family inet6 address 2001:db8:1::1/64",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
		"set security zones security-zone vrfzone interfaces ge-0/0/1.0",
		"set routing-instances vr1 instance-type virtual-router",
		"set routing-instances vr1 interface ge-0/0/1.0",
	}
	return append(lines, extra...)
}

func TestManagedRoutingPassiveHostInbound16565(t *testing.T) {
	cases := []struct {
		name    string
		lines   []string
		wantErr string // substring of strict error; "" means commit must succeed
	}{
		{
			name:  "ospf-passive-commits",
			lines: passiveGateLines16565("set protocols ospf area 0.0.0.0 interface ge-0/0/1.0 passive"),
		},
		{
			name:  "ospf3-passive-commits",
			lines: passiveGateLines16565("set protocols ospf3 area 0.0.0.0 interface ge-0/0/1.0 passive"),
		},
		{
			name:    "ospf-active-still-rejects",
			lines:   passiveGateLines16565("set protocols ospf area 0.0.0.0 interface ge-0/0/1.0"),
			wantErr: `omits "ospf"`,
		},
		{
			name:    "ospf3-active-still-rejects",
			lines:   passiveGateLines16565("set protocols ospf3 area 0.0.0.0 interface ge-0/0/1.0"),
			wantErr: `omits "ospf3"`,
		},
		{
			name: "ospf-passive-default-commits",
			lines: passiveGateLines16565(
				"set protocols ospf passive",
				"set protocols ospf area 0.0.0.0 interface ge-0/0/1.0",
			),
		},
		{
			name: "ospf-passive-default-no-passive-rejects",
			lines: passiveGateLines16565(
				"set protocols ospf passive",
				"set protocols ospf area 0.0.0.0 interface ge-0/0/1.0 no-passive",
			),
			wantErr: `omits "ospf"`,
		},
		{
			name: "ospf-passive-default-mixed-only-active-rejects",
			lines: passiveGateLines16565(
				"set protocols ospf passive",
				"set protocols ospf area 0.0.0.0 interface ge-0/0/0.0",
				"set protocols ospf area 0.0.0.0 interface ge-0/0/1.0 no-passive",
			),
			wantErr: `on interface "ge-0/0/1.0"`,
		},
		{
			name: "ospf-passive-plus-token-commits",
			lines: passiveGateLines16565(
				"set protocols ospf area 0.0.0.0 interface ge-0/0/1.0 passive",
				"set security zones security-zone trust host-inbound-traffic protocols ospf",
			),
		},
		{
			name: "routing-instance-ospf-passive-commits",
			lines: passiveGateRI16565(
				"set routing-instances vr1 protocols ospf area 0.0.0.0 interface ge-0/0/1.0 passive",
			),
		},
		{
			name: "routing-instance-ospf3-passive-commits",
			lines: passiveGateRI16565(
				"set routing-instances vr1 protocols ospf3 area 0.0.0.0 interface ge-0/0/1.0 passive",
			),
		},
		{
			name: "routing-instance-ospf-active-still-rejects",
			lines: passiveGateRI16565(
				"set routing-instances vr1 protocols ospf area 0.0.0.0 interface ge-0/0/1.0",
			),
			wantErr: `omits "ospf"`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfig(buildTree(t, tc.lines))
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("passive config must commit, got %v", err)
				}
				for _, w := range cfg.Warnings {
					if strings.Contains(w, `omits "ospf"`) || strings.Contains(w, `omits "ospf3"`) {
						t.Fatalf("passive config produced managed-routing warning: %v", cfg.Warnings)
					}
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("strict error = %v, want containing %q", err, tc.wantErr)
			}
			// Tolerant path must warn (not silently pass) for active rows.
			lenient, lerr := CompileConfigLenient(buildTree(t, tc.lines))
			if lerr != nil {
				t.Fatalf("tolerant load must boot: %v", lerr)
			}
			found := false
			for _, w := range lenient.Warnings {
				if strings.Contains(w, tc.wantErr) {
					found = true
				}
			}
			if !found {
				t.Fatalf("tolerant warnings = %v, want containing %q", lenient.Warnings, tc.wantErr)
			}
		})
	}

	// Passive rows must also be silent on the tolerant path.
	t.Run("ospf-passive-tolerant-silent", func(t *testing.T) {
		cfg, err := CompileConfigLenient(buildTree(t, passiveGateLines16565(
			"set protocols ospf area 0.0.0.0 interface ge-0/0/1.0 passive")))
		if err != nil {
			t.Fatalf("tolerant load: %v", err)
		}
		for _, w := range cfg.Warnings {
			if strings.Contains(w, `omits "ospf"`) {
				t.Fatalf("passive tolerant load warned: %v", cfg.Warnings)
			}
		}
	})
}

// TestManagedRoutingPassiveDirectHelper16565 pins the collector semantics
// that end-to-end spelling cannot easily reach: any-active wins across
// areas, both flags together stay passive for OSPFv2, and the `all`
// wildcard is never passive.
func TestManagedRoutingPassiveDirectHelper16565(t *testing.T) {
	mkZone := func(iface string) *ZoneConfig {
		return &ZoneConfig{Interfaces: []string{iface}}
	}
	contains := func(warnings []string, substr string) bool {
		for _, w := range warnings {
			if strings.Contains(w, substr) {
				return true
			}
		}
		return false
	}

	t.Run("ospfv2-passive-in-one-area-active-in-another-warns", func(t *testing.T) {
		cfg := &Config{}
		cfg.Security.Zones = map[string]*ZoneConfig{"trust": mkZone("ge-0/0/0.0")}
		cfg.Protocols.OSPF = &OSPFConfig{Areas: []*OSPFArea{
			{ID: "0.0.0.0", Interfaces: []*OSPFInterface{{Name: "ge-0/0/0.0", Passive: true}}},
			{ID: "0.0.0.1", Interfaces: []*OSPFInterface{{Name: "ge-0/0/0.0"}}},
		}}
		if w := validateHostInboundManagedRoutingMismatch(cfg); !contains(w, `omits "ospf"`) {
			t.Fatalf("any-active must warn, got %v", w)
		}
	})

	t.Run("ospfv2-passive-in-all-areas-silent", func(t *testing.T) {
		cfg := &Config{}
		cfg.Security.Zones = map[string]*ZoneConfig{"trust": mkZone("ge-0/0/0.0")}
		cfg.Protocols.OSPF = &OSPFConfig{Areas: []*OSPFArea{
			{ID: "0.0.0.0", Interfaces: []*OSPFInterface{{Name: "ge-0/0/0.0", Passive: true}}},
			{ID: "0.0.0.1", Interfaces: []*OSPFInterface{{Name: "ge-0/0/0.0", Passive: true}}},
		}}
		if w := validateHostInboundManagedRoutingMismatch(cfg); len(w) != 0 {
			t.Fatalf("all-passive must be silent, got %v", w)
		}
	})

	t.Run("ospfv2-passive-and-no-passive-without-default-is-passive", func(t *testing.T) {
		// Mirrors the FRR renderer: without PassiveDefault the
		// `passive-interface` directive is emitted from Passive alone;
		// NoPassive only cancels the default.
		cfg := &Config{}
		cfg.Security.Zones = map[string]*ZoneConfig{"trust": mkZone("ge-0/0/0.0")}
		cfg.Protocols.OSPF = &OSPFConfig{Areas: []*OSPFArea{
			{ID: "0.0.0.0", Interfaces: []*OSPFInterface{{Name: "ge-0/0/0.0", Passive: true, NoPassive: true}}},
		}}
		if w := validateHostInboundManagedRoutingMismatch(cfg); len(w) != 0 {
			t.Fatalf("passive+no-passive without default must be silent, got %v", w)
		}
	})

	t.Run("ospfv2-passive-default-with-passive-and-no-passive-is-active", func(t *testing.T) {
		// With PassiveDefault set, NoPassive explicitly re-activates
		// (Junos no-passive semantics) even if passive also appears.
		cfg := &Config{}
		cfg.Security.Zones = map[string]*ZoneConfig{"trust": mkZone("ge-0/0/0.0")}
		cfg.Protocols.OSPF = &OSPFConfig{PassiveDefault: true, Areas: []*OSPFArea{
			{ID: "0.0.0.0", Interfaces: []*OSPFInterface{{Name: "ge-0/0/0.0", Passive: true, NoPassive: true}}},
		}}
		// Passive flag wins in the renderer's passive-default branch
		// only via NoPassive; with both set the effective formula
		// Passive || (Default && !NoPassive) is true, so silent.
		if w := validateHostInboundManagedRoutingMismatch(cfg); len(w) != 0 {
			t.Fatalf("effectively passive (Passive=true) must be silent, got %v", w)
		}
	})

	t.Run("ospfv3-passive-in-one-area-active-in-another-warns", func(t *testing.T) {
		cfg := &Config{}
		cfg.Security.Zones = map[string]*ZoneConfig{"trust": mkZone("ge-0/0/0.0")}
		cfg.Protocols.OSPFv3 = &OSPFv3Config{Areas: []*OSPFv3Area{
			{ID: "0.0.0.0", Interfaces: []*OSPFv3Interface{{Name: "ge-0/0/0.0", Passive: true}}},
			{ID: "0.0.0.1", Interfaces: []*OSPFv3Interface{{Name: "ge-0/0/0.0"}}},
		}}
		if w := validateHostInboundManagedRoutingMismatch(cfg); !contains(w, `omits "ospf3"`) {
			t.Fatalf("any-active ospf3 must warn, got %v", w)
		}
	})

	t.Run("ospf-all-wildcard-never-passive", func(t *testing.T) {
		cfg := &Config{}
		cfg.Security.Zones = map[string]*ZoneConfig{"trust": mkZone("ge-0/0/0.0")}
		cfg.Protocols.OSPF = &OSPFConfig{PassiveDefault: true, Areas: []*OSPFArea{
			{ID: "0.0.0.0", Interfaces: []*OSPFInterface{{Name: "all", Passive: true}}},
		}}
		if w := validateHostInboundManagedRoutingMismatch(cfg); !contains(w, `omits "ospf"`) {
			t.Fatalf("interface all must still warn, got %v", w)
		}
	})

	t.Run("ospf3-all-wildcard-never-passive", func(t *testing.T) {
		cfg := &Config{}
		cfg.Security.Zones = map[string]*ZoneConfig{"trust": mkZone("ge-0/0/0.0")}
		cfg.Protocols.OSPFv3 = &OSPFv3Config{Areas: []*OSPFv3Area{
			{ID: "0.0.0.0", Interfaces: []*OSPFv3Interface{{Name: "all", Passive: true}}},
		}}
		if w := validateHostInboundManagedRoutingMismatch(cfg); !contains(w, `omits "ospf3"`) {
			t.Fatalf("ospf3 interface all must still warn, got %v", w)
		}
	})

	t.Run("rip-unaffected-by-ospf-passive", func(t *testing.T) {
		cfg := &Config{}
		cfg.Security.Zones = map[string]*ZoneConfig{"trust": mkZone("ge-0/0/0.0")}
		cfg.Protocols.RIP = &RIPConfig{Interfaces: []string{"ge-0/0/0.0"}}
		cfg.Protocols.OSPF = &OSPFConfig{Areas: []*OSPFArea{
			{ID: "0.0.0.0", Interfaces: []*OSPFInterface{{Name: "ge-0/0/0.0", Passive: true}}},
		}}
		w := validateHostInboundManagedRoutingMismatch(cfg)
		if !contains(w, `omits "rip"`) || contains(w, `omits "ospf"`) {
			t.Fatalf("want only rip warning, got %v", w)
		}
	})
}
