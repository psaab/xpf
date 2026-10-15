package config

import (
	"slices"
	"testing"
)

// junosHostVRFTrunkCfg13135: untagged unit 0 in vrf1/trust, tagged unit 100
// in inet.0/dmz, on the same physical port.
func junosHostVRFTrunkCfg13135(t *testing.T) *Config {
	t.Helper()
	cfg := &Config{}
	cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", VlanTagging: true, Units: map[int]*InterfaceUnit{
			0:   {Number: 0, Addresses: []string{"10.0.0.1/24"}},
			100: {Number: 100, VlanID: 100, Addresses: []string{"10.0.100.1/24"}},
		}},
	}
	cfg.RoutingInstances = []*RoutingInstanceConfig{
		{Name: "vrf1", InstanceType: "vrf", Interfaces: []string{"ge-0/0/0.0"}},
	}
	cfg.Security.Zones = map[string]*ZoneConfig{
		"dmz": {Name: "dmz", Interfaces: []string{"ge-0/0/0.100"},
			HostInboundTraffic: &HostInboundTraffic{SystemServices: []string{"ssh"}}},
		"trust": {Name: "trust", Interfaces: []string{"ge-0/0/0.0"},
			HostInboundTraffic: &HostInboundTraffic{SystemServices: []string{"ssh"}}},
	}
	cfg.Security.AddressBook = &AddressBook{Addresses: map[string]*Address{
		"bad-net": {Name: "bad-net", Value: "10.0.0.0/8"},
	}}
	cfg.Security.Policies = []*ZonePairPolicies{
		{FromZone: "trust", ToZone: "junos-host", Policies: []*Policy{
			jhDeny("deny-ssh", []string{"bad-net"}, []string{"junos-ssh"})}},
		{FromZone: "dmz", ToZone: "junos-host", Policies: []*Policy{
			jhDeny("deny-ssh-dmz", []string{"bad-net"}, []string{"junos-ssh"})}},
	}
	return cfg
}

// TestJunosHostTaggedUnitDoesNotStealVRFBase13135 (D2-03): a non-VRF tagged
// unit must not fan up to out[base] merely because its untagged unit-0
// sibling is VRF-enslaved. Pre-fix "dmz" (sorted first) claimed ge-0/0/0,
// making vrf-vrf1 contested and withdrawing trust's deny program.
func TestJunosHostTaggedUnitDoesNotStealVRFBase13135(t *testing.T) {
	cfg := junosHostVRFTrunkCfg13135(t)
	zones := junosHostZoneByInterface(cfg)
	if got := zones["ge-0/0/0"]; got != "trust" {
		t.Fatalf("base must belong to unit-0 owner trust, got %q in %v", got, zones)
	}
	cov := junosHostZoneNetdevCoverageMap(cfg)
	trust := cov["trust"]
	if len(trust.Unscopable) != 0 {
		t.Fatalf("trust must be scopable, got Unscopable %+v (cov %+v)", trust.Unscopable, trust)
	}
	foundScope := false
	for _, s := range trust.VRFScopes {
		if s.Master == "vrf-vrf1" && slices.Equal(s.Slaves, []string{"ge-0-0-0"}) {
			foundScope = true
		}
	}
	if !foundScope {
		t.Fatalf("trust must have VRF scope {vrf-vrf1 [ge-0-0-0]}, got %+v", trust)
	}
	dmz := cov["dmz"]
	if !slices.Equal(dmz.Scoped, []string{"ge-0-0-0.100"}) || len(dmz.Unscopable) != 0 {
		t.Fatalf("dmz must scope only its VLAN netdev, got %+v", dmz)
	}
	proj := BuildJunosHostDenyProjection(cfg)
	byZone := map[string]JunosHostDenyProgram{}
	for _, p := range proj.Programs {
		byZone[p.Zone] = p
	}
	if p, ok := byZone["trust"]; !ok || !p.Representable {
		t.Fatalf("trust deny must stay representable, got %+v", p)
	}
	if p, ok := byZone["dmz"]; !ok || !p.Representable {
		t.Fatalf("dmz deny must stay representable, got %+v", p)
	}
}

// TestJunosHostTunnelUnitDoesNotClaimBase13135 (D2-03 tunnel arm): a zoned
// non-zero tunnel unit whose own netdev differs from the base device must
// not claim the bare base (whose unit 0 is unzoned).
func TestJunosHostTunnelUnitDoesNotClaimBase13135(t *testing.T) {
	cfg := &Config{}
	cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"st0": {Name: "st0", Units: map[int]*InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.1.0.1/30"}},
			1: {Number: 1, Addresses: []string{"10.1.1.1/30"}},
		}},
	}
	// Plain (non-secure) tunnel units resolve via TunnelNameMap to st0u<N>.
	cfg.Interfaces.Interfaces["st0"].Units[0].Tunnel = &TunnelConfig{Source: "192.0.2.1", Destination: "192.0.2.2"}
	cfg.Interfaces.Interfaces["st0"].Units[1].Tunnel = &TunnelConfig{Source: "192.0.2.1", Destination: "192.0.2.3"}
	cfg.Security.Zones = map[string]*ZoneConfig{
		"vpn": {Name: "vpn", Interfaces: []string{"st0.1"},
			HostInboundTraffic: &HostInboundTraffic{SystemServices: []string{"ssh"}}},
	}
	zones := junosHostZoneByInterface(cfg)
	if got := zones["st0.1"]; got != "vpn" {
		t.Fatalf("st0.1 must stay vpn, got %q in %v", got, zones)
	}
	if got := zones["st0"]; got != "" {
		t.Fatalf("distinct tunnel unit st0.1 must not claim bare st0, got %q in %v", got, zones)
	}
}
