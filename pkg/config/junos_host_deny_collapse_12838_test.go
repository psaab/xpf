package config

import "testing"

// #12838 (D3-01): on a same-netdev unit-0 collapse the BARE physical row must
// not contribute to junosHostZoneExemptNetdevs — unit 0 is the authoritative
// carrier (userspace #5699). The base row's InterfaceHostInboundEffective is
// base-only (or zone, when no base stanza), so a base stanza granting
// ike/ident-reset leaked onto the collapsed netdev even when unit 0's
// replacement override removed it, and a base any-service stanza suppressed
// ident-reset the unit still resets.

// jh12838Cfg builds a collapsing unit-0 config: zone-level ssh, optional
// physical-level and unit-0-level overrides.
func jh12838Cfg(phys, unit0 *HostInboundTraffic) *Config {
	cfg := &Config{}
	cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.0.2.10/24"}},
		}},
	}
	ov := map[string]*HostInboundTraffic{}
	if phys != nil {
		ov["ge-0/0/1"] = phys
	}
	if unit0 != nil {
		ov["ge-0/0/1.0"] = unit0
	}
	cfg.Security.Zones = map[string]*ZoneConfig{
		"untrust": {Name: "untrust", Interfaces: []string{"ge-0/0/1.0"},
			HostInboundTraffic:   &HostInboundTraffic{SystemServices: []string{"ssh"}},
			InterfaceHostInbound: ov},
	}
	cfg.Security.AddressBook = &AddressBook{Addresses: map[string]*Address{
		"bad-net": {Name: "bad-net", Value: "10.0.0.0/8"},
	}}
	cfg.Security.Policies = []*ZonePairPolicies{{FromZone: "untrust", ToZone: "junos-host",
		Policies: []*Policy{jhDeny("block", []string{"bad-net"}, []string{"any"})}}}
	return cfg
}

func jh12838Program(t *testing.T, cfg *Config) JunosHostDenyProgram {
	t.Helper()
	proj := BuildJunosHostDenyProjection(cfg)
	if len(proj.Programs) != 1 {
		t.Fatalf("want 1 program, got %+v", proj.Programs)
	}
	return proj.Programs[0]
}

func has12838(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// Bare base ref admits IKE+ident-reset through the zone; unit 0 replaces that
// zone set with ssh-only. The collapsed netdev must NOT inherit the base-row
// zone-level admissions.
func TestJunosHostCollapse12838BaseGrantDoesNotLeak(t *testing.T) {
	cfg := jh12838Cfg(nil, &HostInboundTraffic{SystemServices: []string{"ssh"}})
	cfg.Security.Zones["untrust"].HostInboundTraffic.SystemServices = []string{"ike", "ident-reset"}
	p := jh12838Program(t, cfg)
	if has12838(p.IKEExemptNetdevs, "ge-0-0-1") || p.CoarseAdmitsIKE {
		t.Errorf("IKE exempt = %v (CoarseAdmitsIKE=%v), want none: unit-0 override replaced the base-zone grant",
			p.IKEExemptNetdevs, p.CoarseAdmitsIKE)
	}
	if has12838(p.IdentResetNetdevs, "ge-0-0-1") || p.CoarseIdentResets {
		t.Errorf("IdentReset = %v (CoarseIdentResets=%v), want none: unit-0 override replaced the base-zone grant",
			p.IdentResetNetdevs, p.CoarseIdentResets)
	}
}

// Narrowing case from the issue: zone any-service (full admit) narrowed by a
// unit-0 override to {ssh, ident-reset}. The unit resets 113; the base row's
// full-admit (zone set, no base stanza) must not suppress it.
func TestJunosHostCollapse12838NarrowFromAnyServiceResetsIdent(t *testing.T) {
	cfg := jh12838Cfg(nil,
		&HostInboundTraffic{SystemServices: []string{"ssh", "ident-reset"}})
	cfg.Security.Zones["untrust"].HostInboundTraffic.SystemServices = []string{"any-service"}
	p := jh12838Program(t, cfg)
	if !has12838(p.IdentResetNetdevs, "ge-0-0-1") || !p.CoarseIdentResets {
		t.Errorf("IdentReset = %v (CoarseIdentResets=%v), want [ge-0-0-1]: unit-0 narrowing from any-service must reset 113",
			p.IdentResetNetdevs, p.CoarseIdentResets)
	}
}

// Reverse: base any-service full-admit from zone level must not suppress the
// unit's ident reset.
func TestJunosHostCollapse12838BaseFullAdmitDoesNotSuppress(t *testing.T) {
	cfg := jh12838Cfg(nil, &HostInboundTraffic{SystemServices: []string{"ssh", "ident-reset"}})
	cfg.Security.Zones["untrust"].HostInboundTraffic.SystemServices = []string{"any-service"}
	p := jh12838Program(t, cfg)
	if !has12838(p.IdentResetNetdevs, "ge-0-0-1") || !p.CoarseIdentResets {
		t.Errorf("IdentReset = %v (CoarseIdentResets=%v), want [ge-0-0-1]: base zone full-admit must not suppress unit-0 ident-reset",
			p.IdentResetNetdevs, p.CoarseIdentResets)
	}
}

// Countercase: the distinct VLAN unit-0 physical carrier remains in the zone's
// ingress scope, but its exemptions follow unit 0's effective override rather
// than leaking the broader zone-level set.
func TestJunosHostCollapse12838VlanUnit0BaseRowKept(t *testing.T) {
	cfg := jh12838Cfg(nil, &HostInboundTraffic{SystemServices: []string{"ssh"}})
	cfg.Security.Zones["untrust"].HostInboundTraffic.SystemServices = []string{"ike", "ident-reset"}
	cfg.Interfaces.Interfaces["ge-0/0/1"].Units[0].VlanID = 100
	nd := JunosHostZoneIngressNetdevs(cfg)
	if len(nd["untrust"]) != 2 || !has12838(nd["untrust"], "ge-0-0-1") ||
		!has12838(nd["untrust"], "ge-0-0-1.100") {
		t.Fatalf("VLAN unit-0 zone ingress = %v, want physical ge-0-0-1 plus distinct VLAN device ge-0-0-1.100", nd["untrust"])
	}
	ike, ident, _, _ := junosHostZoneExemptNetdevs(cfg, "untrust",
		cfg.Security.Zones["untrust"], nd["untrust"], nil)
	if has12838(ike, "ge-0-0-1") || has12838(ident, "ge-0-0-1") {
		t.Errorf("distinct VLAN physical carrier: ike=%v ident=%v, want neither: unit-0 override is ssh-only",
			ike, ident)
	}
}

// Control: unit 0 itself grants ike+ident-reset on the collapse — exempt.
func TestJunosHostCollapse12838UnitGrantExempts(t *testing.T) {
	p := jh12838Program(t, jh12838Cfg(
		&HostInboundTraffic{SystemServices: []string{"ssh"}},
		&HostInboundTraffic{SystemServices: []string{"ike", "ident-reset"}},
	))
	if !has12838(p.IKEExemptNetdevs, "ge-0-0-1") || !p.CoarseAdmitsIKE {
		t.Errorf("IKE exempt = %v, want [ge-0-0-1]", p.IKEExemptNetdevs)
	}
	if !has12838(p.IdentResetNetdevs, "ge-0-0-1") || !p.CoarseIdentResets {
		t.Errorf("IdentReset = %v, want [ge-0-0-1]", p.IdentResetNetdevs)
	}
}

// Control: no overrides at all — zone set governs the collapsed netdev.
func TestJunosHostCollapse12838ZoneOnlyGoverns(t *testing.T) {
	cfg := jh12838Cfg(nil, nil)
	cfg.Security.Zones["untrust"].HostInboundTraffic.SystemServices = []string{"ike", "ident-reset"}
	p := jh12838Program(t, cfg)
	if !p.CoarseAdmitsIKE || !p.CoarseIdentResets {
		t.Errorf("zone-only: CoarseAdmitsIKE=%v CoarseIdentResets=%v, want both true",
			p.CoarseAdmitsIKE, p.CoarseIdentResets)
	}
}
