package config

import "testing"

// #13134 (D2-02): on a distinct VLAN/tunnel unit 0, the physical-ingress row
// evaluated the BARE interface name, so it inherited the zone-level
// ike/ident-reset/any-service set even when unit 0's replacement override
// narrowed it. A lifeline unit must not contribute exemption verdicts at all.
func TestJunosHostExempt13134DistinctUnit0UsesUnitOverride(t *testing.T) {
	// VLAN-tagged unit 0 narrowed to ssh; physical ingress must not exempt.
	cfg := jh12838Cfg(nil, &HostInboundTraffic{SystemServices: []string{"ssh"}})
	cfg.Security.Zones["untrust"].HostInboundTraffic.SystemServices = []string{"ike", "ident-reset"}
	cfg.Interfaces.Interfaces["ge-0/0/1"].Units[0].VlanID = 100
	nd := JunosHostZoneIngressNetdevs(cfg)
	ike, ident, _, _ := junosHostZoneExemptNetdevs(cfg, "untrust",
		cfg.Security.Zones["untrust"], nd["untrust"], nil)
	if has12838(ike, "ge-0-0-1") {
		t.Errorf("IKE exempt = %v, want none on physical ge-0-0-1: unit-0 override has ssh only", ike)
	}
	if has12838(ident, "ge-0-0-1") {
		t.Errorf("IdentReset = %v, want none on physical ge-0-0-1: unit-0 override has ssh only", ident)
	}
	// Preservation: distinct unit's own netdev also must not gain exemptions
	// from the zone set after replacement (unit row resolves unit0Name itself).
	if has12838(ike, "ge-0-0-1.100") || has12838(ident, "ge-0-0-1.100") {
		t.Errorf("distinct unit netdev must not exempt: ike=%v ident=%v", ike, ident)
	}
}

func TestJunosHostExempt13134DistinctUnit0GrantReachesPhysical(t *testing.T) {
	// Preservation under fix: when unit 0 itself grants ike/ident-reset, the
	// physical ingress carrier keeps them (correct unit0Name resolution).
	cfg := jh12838Cfg(nil, &HostInboundTraffic{SystemServices: []string{"ike", "ident-reset"}})
	cfg.Security.Zones["untrust"].HostInboundTraffic.SystemServices = []string{"ssh"}
	cfg.Interfaces.Interfaces["ge-0/0/1"].Units[0].VlanID = 100
	nd := JunosHostZoneIngressNetdevs(cfg)
	ike, ident, _, _ := junosHostZoneExemptNetdevs(cfg, "untrust",
		cfg.Security.Zones["untrust"], nd["untrust"], nil)
	if !has12838(ike, "ge-0-0-1") || !has12838(ident, "ge-0-0-1") {
		t.Errorf("physical carrier: ike=%v ident=%v, want both contain ge-0-0-1 from unit-0 grant", ike, ident)
	}
}

func TestJunosHostExempt13134LifelineUnitDoesNotContaminateParent(t *testing.T) {
	// Lifeline sibling on same trunk/zone: coverage map excludes fxp0.0,
	// so its netdev should not be in `netdevs`; use direct call with the
	// parent netdev included to prove exempt walk itself skips lifelines.
	// fxp0.0 shares physical netdev fxp0 with a VLAN sibling in untrust.
	cfg := &Config{}
	cfg.Chassis.Cluster = &ClusterConfig{ControlInterface: "fxp0.0"}
	cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"fxp0": {Name: "fxp0", Units: map[int]*InterfaceUnit{
			0:  {Number: 0, Addresses: []string{"10.0.0.1/24"}},
			50: {Number: 50, VlanID: 50, Addresses: []string{"10.0.50.1/24"}},
		}},
	}
	cfg.Security.Zones = map[string]*ZoneConfig{
		"untrust": {Name: "untrust", Interfaces: []string{"fxp0.0", "fxp0.50"},
			HostInboundTraffic: &HostInboundTraffic{SystemServices: []string{"ike", "ident-reset"}}},
	}
	cfg.Security.AddressBook = &AddressBook{Addresses: map[string]*Address{
		"bad-net": {Name: "bad-net", Value: "10.0.0.0/8"},
	}}
	cfg.Security.Policies = []*ZonePairPolicies{{FromZone: "untrust", ToZone: "junos-host",
		Policies: []*Policy{jhDeny("block", []string{"bad-net"}, []string{"any"})}}}
	// Direct: pretend ingress scope includes fxp0 (physical) and fxp0.50.
	// Lifeline fxp0.0's parent contribution (fxp0) must be skipped; only the
	// ordinary VLAN unit fxp0.50 may contribute. Its own netdev is fxp0.50
	// (not in netdevs) but its parent contribution is fxp0 — that is
	// legitimate. So instead assert with netdevs=[fxp0.50's? ] — simpler:
	// remove ordinary sibling: only lifeline unit present, parent must stay clean.
	cfg.Security.Zones["untrust"].Interfaces = []string{"fxp0.0"}
	ike, ident, _, _ := junosHostZoneExemptNetdevs(cfg, "untrust",
		cfg.Security.Zones["untrust"], []string{"fxp0"}, nil)
	if len(ike) != 0 || len(ident) != 0 {
		t.Errorf("lifeline unit must not exempt: ike=%v ident=%v, want none", ike, ident)
	}
}
