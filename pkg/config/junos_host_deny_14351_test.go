package config

import (
	"slices"
	"testing"
)

// #14351: bind-only secure-tunnel units must be covered by junos-host deny
// scoping.

func boundStConfig14351(bareParent bool, zoneRef string) *Config {
	cfg := &Config{}
	if bareParent {
		cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
			"st0": {Name: "st0", Description: "vpn tunnel", Units: map[int]*InterfaceUnit{}},
		}
	} else {
		cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{}
	}
	cfg.Security.IPsec.VPNs = map[string]*IPsecVPN{
		"v": {Name: "v", BindInterface: "st0.0"},
	}
	cfg.Security.Zones = map[string]*ZoneConfig{
		"vpn": {Name: "vpn", Interfaces: []string{zoneRef},
			HostInboundTraffic: &HostInboundTraffic{SystemServices: []string{"ssh"}}},
	}
	cfg.Security.AddressBook = &AddressBook{Addresses: map[string]*Address{
		"bad-net": {Name: "bad-net", Value: "10.0.0.0/8"},
	}}
	cfg.Security.Policies = []*ZonePairPolicies{
		{FromZone: "vpn", ToZone: "junos-host", Policies: []*Policy{
			jhDeny("block", []string{"bad-net"}, []string{"any"}),
		}},
	}
	return cfg
}

func TestJunosHostDenyBoundSecureTunnelUnitCoverage(t *testing.T) {
	cases := []struct {
		name       string
		bareParent bool
		zoneRef    string
	}{
		{name: "bare st0 with parent stanza", bareParent: true, zoneRef: "st0"},
		{name: "explicit st0.0 without stanza", bareParent: false, zoneRef: "st0.0"},
		{name: "bare st0 without stanza", bareParent: false, zoneRef: "st0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := boundStConfig14351(tc.bareParent, tc.zoneRef)
			if got := InterfaceUnitRefKeys(cfg, "st0"); !slices.Contains(got, "st0.0") {
				t.Errorf("InterfaceUnitRefKeys(st0)=%v, want st0.0 included (bind-only fan-down)", got)
			}
			proj := BuildJunosHostDenyProjection(cfg)
			if len(proj.Programs) != 1 {
				t.Fatalf("want 1 program, got %+v", proj.Programs)
			}
			p := proj.Programs[0]
			t.Logf("program ingress=%v representable=%v rulesV4=%d rendered=%v", p.IngressNetdevs, p.Representable, len(p.RulesV4), proj.RenderedPolicyKeys)
			if !slices.Contains(p.IngressNetdevs, "st0.0") {
				t.Errorf("IngressNetdevs=%v, want st0.0 (real xfrmi device for bind st0.0)", p.IngressNetdevs)
			}
			if slices.Contains(p.IngressNetdevs, "st0") && !tc.bareParent {
			}
			key := JunosHostZonePairPolicyKey("vpn", "block")
			if !proj.RenderedPolicyKeys[key] {
				t.Errorf("RenderedPolicyKeys missing %q (warning not suppressed when protected)", key)
			}
			// coverage direct
			cov := junosHostZoneNetdevCoverageMap(cfg)["vpn"]
			t.Logf("coverage scoped=%v unscopable=%v", cov.Scoped, cov.Unscopable)
			nd := JunosHostZoneIngressNetdevs(cfg)["vpn"]
			if !slices.Contains(nd, "st0.0") {
				t.Errorf("JunosHostZoneIngressNetdevs[vpn]=%v, want st0.0", nd)
			}
		})
	}
	// Global/from-any suppression case: explicit st0.0, no stanza, policy from-zone any
	t.Run("from-any suppression explicit", func(t *testing.T) {
		cfg := boundStConfig14351(false, "st0.0")
		cfg.Security.Policies = []*ZonePairPolicies{
			{FromZone: "any", ToZone: "junos-host", Policies: []*Policy{
				jhDeny("block-any", []string{"bad-net"}, []string{"any"}),
			}},
		}
		proj := BuildJunosHostDenyProjection(cfg)
		key := JunosHostZonePairPolicyKey("any", "block-any")
		t.Logf("programs=%+v rendered=%v", proj.Programs, proj.RenderedPolicyKeys)
		if len(proj.Programs) != 1 || !slices.Contains(proj.Programs[0].IngressNetdevs, "st0.0") {
			t.Errorf("from-any program ingress wrong: %+v", proj.Programs)
		}
		if !proj.RenderedPolicyKeys[key] {
			t.Errorf("from-any Rendered missing %q", key)
		}
	})
}
