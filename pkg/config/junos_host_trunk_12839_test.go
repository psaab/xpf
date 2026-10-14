package config

import (
	"slices"
	"strings"
	"testing"
)

// junosHostTrunkCfg12839 builds one physical trunk carrying two VLAN
// units in separate zones, plus an unzoned unit-0 ingress.
func junosHostTrunkCfg12839(t *testing.T) *Config {
	t.Helper()
	cfg := &Config{}
	cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"ge-0/0/2": {Name: "ge-0/0/2", Units: map[int]*InterfaceUnit{
			0:  {Number: 0, Addresses: []string{"10.0.9.1/24"}},
			50: {Number: 50, VlanID: 50, Addresses: []string{"10.0.50.1/24"}},
			80: {Number: 80, VlanID: 80, Addresses: []string{"10.0.80.1/24"}},
		}},
	}
	cfg.Security.Zones = map[string]*ZoneConfig{
		"vlan-a": {Name: "vlan-a", Interfaces: []string{"ge-0/0/2.50"},
			HostInboundTraffic: &HostInboundTraffic{SystemServices: []string{"ssh"}}},
		"vlan-b": {Name: "vlan-b", Interfaces: []string{"ge-0/0/2.80"},
			HostInboundTraffic: &HostInboundTraffic{SystemServices: []string{"ssh"}}},
	}
	cfg.Security.AddressBook = &AddressBook{Addresses: map[string]*Address{
		"bad-net": {Name: "bad-net", Value: "10.0.0.0/8"},
	}}
	cfg.Security.Policies = []*ZonePairPolicies{
		{FromZone: "vlan-a", ToZone: "junos-host", Policies: []*Policy{
			jhDeny("block-vlan-a", []string{"bad-net"}, []string{"any"})}},
		{FromZone: "vlan-b", ToZone: "junos-host", Policies: []*Policy{
			jhDeny("block-vlan-b", []string{"bad-net"}, []string{"any"})}},
	}
	return cfg
}

// TestJunosHostUnitRefDoesNotOwnBase12839 pins the boundary directly:
// tagged unit refs cannot claim the physical ingress, while an explicit
// bare ref still does. Cross-zone ambiguity remains pinned by the existing
// TestJunosHostCrossZoneAmbiguousTrunkKeepsWarning test.
func TestJunosHostUnitRefDoesNotOwnBase12839(t *testing.T) {
	cfg := junosHostTrunkCfg12839(t)
	zones := junosHostZoneByInterface(cfg)
	if got := zones["ge-0/0/2"]; got != "" {
		t.Fatalf("tagged unit refs must not claim bare parent, got zone %q in %v", got, zones)
	}
	cfg.Security.Zones["vlan-a"].Interfaces = append(cfg.Security.Zones["vlan-a"].Interfaces, "ge-0/0/2")
	zones = junosHostZoneByInterface(cfg)
	if got := zones["ge-0/0/2"]; got != "vlan-a" {
		t.Fatalf("explicit bare ref must claim base, got zone %q in %v", got, zones)
	}
}

// TestJunosHostMultiZoneTrunkNoFalseUnscopable12839: two tagged zones on
// one trunk must each scope exactly their own VLAN netdev, without a false
// parent gap or #4146 warning from the unzoned unit-0 row.
func TestJunosHostMultiZoneTrunkNoFalseUnscopable12839(t *testing.T) {
	cfg := junosHostTrunkCfg12839(t)
	cov := junosHostZoneNetdevCoverageMap(cfg)
	want := map[string][]string{
		"vlan-a": {"ge-0-0-2.50"},
		"vlan-b": {"ge-0-0-2.80"},
	}
	for zone, scoped := range want {
		c := cov[zone]
		if !slices.Equal(c.Scoped, scoped) || len(c.Unscopable) != 0 {
			t.Errorf("zone %s coverage = Scoped %v Unscopable %v, want Scoped %v and no gap",
				zone, c.Scoped, c.Unscopable, scoped)
		}
	}
	for _, w := range ValidateConfig(cfg) {
		if strings.Contains(w, "#4146") && strings.Contains(w, "junos-host") {
			t.Errorf("fully-scoped trunk denies must not retain #4146 warning: %s", w)
		}
	}
}

// TestJunosHostTaggedOnlyZoneParentCandidateNotOwn12839: a tagged-only
// zone plus an unzoned unit-0 keeps the conservative parent candidate but
// does not treat that parent as a zone-owned ingress or a coverage gap.
func TestJunosHostTaggedOnlyZoneParentCandidateNotOwn12839(t *testing.T) {
	cfg := junosHostTrunkCfg12839(t)
	delete(cfg.Security.Zones, "vlan-b")
	cfg.Security.Policies = cfg.Security.Policies[:1]
	c := junosHostZoneNetdevCoverageMap(cfg)["vlan-a"]
	if len(c.Unscopable) != 0 {
		t.Errorf("tagged-only coverage must have no own-ingress gap, got %+v", c)
	}
	if !slices.Equal(c.Scoped, []string{"ge-0-0-2", "ge-0-0-2.50"}) {
		t.Errorf("tagged-only coverage must retain VLAN and conservative parent candidates, got %v", c.Scoped)
	}
}
