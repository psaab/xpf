package config

import "testing"

// #12951 (follow-up to #12838): pin the ZONE-OWNERSHIP arm of the unit-0
// collapse gate in junosHostZoneExemptNetdevs — the zoneByIface[unit0Name]
// comparison that decides whether the bare physical row survives when unit 0
// exists. The GLM probe from the PR #12943 review: when unit 0 is QUARANTINED
// (its key claimed by two zones, so junosHostZoneByInterface carries no row
// for it anywhere), a zone holding the bare physical ref keeps its ike /
// ident-reset exemptions ONLY through that arm. Every committed #12838
// fixture keeps unit 0 owned by the exercising zone, and that zone's unit row
// inherits the physical override through the #3720 base union, so deleting
// the arm left those tests green while silently failing closed here. A
// discriminating cell needs the conflicted unit row EXCLUDED, which is what
// these fixtures build: zone edge holds the bare ref `ge-0/0/2`, zone alpha
// additionally claims `ge-0/0/2.0`, and the conflicting claim quarantines the
// unit key out of every zone map.

// jh12951Cfg builds the probe config. vlanID 0 models the same-netdev unit-0
// collapse (#12838's own shape); vlanID > 0 models a distinct VLAN unit-0
// netdev. edge's bare stanza (ike + ident-reset on `ge-0/0/2`) is the only
// source of exemptions once the quarantined unit row is excluded; alpha's
// zone-level set admits ike/ident-reset too, so any leak of the physical row
// to the quarantined claimant is observable rather than masked by an empty
// effective set.
func jh12951Cfg(vlanID int) *Config {
	unit0 := &InterfaceUnit{Number: 0, Addresses: []string{"10.0.4.10/24"}}
	if vlanID > 0 {
		unit0.VlanID = vlanID
	}
	cfg := &Config{}
	cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"ge-0/0/2": {Name: "ge-0/0/2", Units: map[int]*InterfaceUnit{0: unit0}},
	}
	cfg.Security.Zones = map[string]*ZoneConfig{
		"edge": {Name: "edge", Interfaces: []string{"ge-0/0/2"},
			HostInboundTraffic: &HostInboundTraffic{SystemServices: []string{"ssh"}},
			InterfaceHostInbound: map[string]*HostInboundTraffic{
				"ge-0/0/2": {SystemServices: []string{"ike", "ident-reset"}},
			}},
		"alpha": {Name: "alpha", Interfaces: []string{"ge-0/0/2.0"},
			HostInboundTraffic: &HostInboundTraffic{SystemServices: []string{"ike", "ident-reset"}}},
	}
	cfg.Security.AddressBook = &AddressBook{Addresses: map[string]*Address{
		"bad-net": {Name: "bad-net", Value: "10.0.0.0/8"},
	}}
	cfg.Security.Policies = []*ZonePairPolicies{
		{FromZone: "edge", ToZone: "junos-host",
			Policies: []*Policy{jhDeny("block", []string{"bad-net"}, []string{"any"})}},
		{FromZone: "alpha", ToZone: "junos-host",
			Policies: []*Policy{jhDeny("block", []string{"bad-net"}, []string{"any"})}},
	}
	return cfg
}

// require12951Quarantine pins the cell's discriminating shape: the unit-0 key
// is conflicted and excluded from the zone map for EVERY zone, while the bare
// key stays owned by edge. If this precondition ever stops holding, the cell
// degrades into a naive #12838 fixture that passes with the arm deleted.
func require12951Quarantine(t *testing.T, cfg *Config) {
	t.Helper()
	if _, conflicted := QuarantinedZoneInterfaceKeys(cfg)["ge-0/0/2.0"]; !conflicted {
		t.Fatal("precondition: ge-0/0/2.0 must be a quarantined (two-zone) unit-0 claim")
	}
	zoneByIface := junosHostZoneByInterface(cfg)
	if zone, exists := zoneByIface["ge-0/0/2.0"]; exists {
		t.Fatalf("precondition: quarantined unit-0 must carry no zone row, got %q", zone)
	}
	if zone := zoneByIface["ge-0/0/2"]; zone != "edge" {
		t.Fatalf("precondition: bare ref ge-0/0/2 must stay owned by edge, got %q", zone)
	}
}

func jh12951Program(t *testing.T, cfg *Config, zone string) JunosHostDenyProgram {
	t.Helper()
	for _, p := range BuildJunosHostDenyProjection(cfg).Programs {
		if p.Zone == zone {
			return p
		}
	}
	t.Fatalf("no junos-host program projected for zone %q", zone)
	return JunosHostDenyProgram{}
}

// Same-netdev collapse (#12838's own shape): unit 0 exists and folds onto the
// physical netdev, but is quarantined, so the unit row notes nothing for any
// zone. The bare row — retained by the zone-ownership arm — is then the ONLY
// carrier of edge's base stanza, and deleting the arm (leaving the bare row
// gated on `unit0 == nil` alone) silently withdraws both exemptions.
func TestJunosHostZoneOwner12951QuarantinedCollapseKeepsBareRow(t *testing.T) {
	cfg := jh12951Cfg(0)
	require12951Quarantine(t, cfg)
	p := jh12951Program(t, cfg, "edge")
	if len(p.IKEExemptNetdevs) != 1 || !has12838(p.IKEExemptNetdevs, "ge-0-0-2") || !p.CoarseAdmitsIKE {
		t.Errorf("quarantined same-netdev unit-0: IKE exempt = %v (CoarseAdmitsIKE=%v), "+
			"want exactly [ge-0-0-2] kept via the zone-ownership arm",
			p.IKEExemptNetdevs, p.CoarseAdmitsIKE)
	}
	if len(p.IdentResetNetdevs) != 1 || !has12838(p.IdentResetNetdevs, "ge-0-0-2") || !p.CoarseIdentResets {
		t.Errorf("quarantined same-netdev unit-0: ident reset = %v (CoarseIdentResets=%v), "+
			"want exactly [ge-0-0-2] kept via the zone-ownership arm",
			p.IdentResetNetdevs, p.CoarseIdentResets)
	}
}

// Distinct VLAN unit-0 netdev: the physical row is still retained for the
// bare-ref zone through the same arm, and the quarantined unit's own netdev
// ge-0-0-2.<vlan> must stay excluded — the conflict fails closed rather than
// granting either claimant the unit device.
func TestJunosHostZoneOwner12951QuarantinedDistinctUnit0KeepsBareRowOnly(t *testing.T) {
	cfg := jh12951Cfg(100)
	require12951Quarantine(t, cfg)
	p := jh12951Program(t, cfg, "edge")
	if len(p.IKEExemptNetdevs) != 1 || !has12838(p.IKEExemptNetdevs, "ge-0-0-2") || !p.CoarseAdmitsIKE {
		t.Errorf("quarantined distinct unit-0: IKE exempt = %v (CoarseAdmitsIKE=%v), "+
			"want exactly [ge-0-0-2]; the VLAN device ge-0-0-2.100 must stay excluded",
			p.IKEExemptNetdevs, p.CoarseAdmitsIKE)
	}
	if len(p.IdentResetNetdevs) != 1 || !has12838(p.IdentResetNetdevs, "ge-0-0-2") || !p.CoarseIdentResets {
		t.Errorf("quarantined distinct unit-0: ident reset = %v (CoarseIdentResets=%v), "+
			"want exactly [ge-0-0-2]; the VLAN device ge-0-0-2.100 must stay excluded",
			p.IdentResetNetdevs, p.CoarseIdentResets)
	}
	if has12838(p.IngressNetdevs, "ge-0-0-2.100") {
		t.Errorf("quarantined unit-0 netdev leaked into edge ingress scope: %v", p.IngressNetdevs)
	}
}

// The quarantined claimant itself must fail closed: alpha's only ref is the
// conflicted unit key, so it resolves no ingress scope at all — even though
// its zone-level set admits ike/ident-reset, nothing reaches a netdev. This
// guards the opposite direction: erosion of the quarantine (for example a
// sorted-name winner) would hand alpha the physical row and its exemptions.
func TestJunosHostZoneOwner12951QuarantinedClaimantFailsClosed(t *testing.T) {
	cfg := jh12951Cfg(0)
	require12951Quarantine(t, cfg)
	nd := JunosHostZoneIngressNetdevs(cfg)
	if got := nd["alpha"]; len(got) != 0 {
		t.Fatalf("quarantined claimant alpha must resolve no ingress netdevs, got %v", got)
	}
	ike, ident, ikeVRF, identVRF := junosHostZoneExemptNetdevs(cfg, "alpha",
		cfg.Security.Zones["alpha"], nd["alpha"], nil)
	if len(ike) != 0 || len(ident) != 0 || len(ikeVRF) != 0 || len(identVRF) != 0 {
		t.Fatalf("quarantined claimant alpha must earn no exemptions, got ike=%v ident=%v ikeVRF=%v identVRF=%v",
			ike, ident, ikeVRF, identVRF)
	}
}
