package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #12854 (D4-08): a StableZoneID collision loser (z214) and a reserved zone
// name (junos-host) are quarantined from the scoped view, so they must not
// be reported as addressless-enforcing (which would latch
// HostInboundPendingIntentFromSnapshots=true forever, even when every real
// zone is statically addressed). Likewise an interface whose zone membership
// is contested (claimed by two zones, QuarantinedZoneInterfaceKeys) must not
// produce a per-interface DHCP-pending entry: InterfaceZoneMap omits it.
func quarantinedAddresslessCfg12854(t *testing.T) *config.Config {
	t.Helper()
	if config.StableZoneID("z174") != config.StableZoneID("z214") {
		t.Fatalf("premise: z174/z214 must collide")
	}
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		// survivor: statically addressed
		"ge-0-0-0": {Name: "ge-0-0-0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.0.1.10/24"}},
		}},
		// quarantined loser: DHCP, no lease — would be reported pre-fix
		"ge-0-0-1": {Name: "ge-0-0-1", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, DHCP: true, DHCPv6: true},
		}},
		// reserved zone iface: DHCP, no lease — would be reported pre-fix
		"ge-0-0-2": {Name: "ge-0-0-2", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, DHCP: true},
		}},
		// contested iface: claimed by two real zones, DHCP no lease
		"ge-0-0-3": {Name: "ge-0-0-3", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, DHCP: true, DHCPv6: true},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"z174":       {Name: "z174", Interfaces: []string{"ge-0-0-0.0"}},
		"z214":       {Name: "z214", Interfaces: []string{"ge-0-0-1.0"}},
		"junos-host": {Name: "junos-host", Interfaces: []string{"ge-0-0-2.0"}},
		"trust":      {Name: "trust", Interfaces: []string{"ge-0-0-3.0"}},
		"untrust":    {Name: "untrust", Interfaces: []string{"ge-0-0-3.0"}},
	}
	return cfg
}

func TestAddresslessQuarantinedZonesNotReported12854(t *testing.T) {
	cfg := quarantinedAddresslessCfg12854(t)
	got := addresslessEnforcingZonesFromSnapshots(cfg, buildInterfaceSnapshots(cfg))
	for _, z := range got {
		switch z.Zone {
		case "z214", "junos-host":
			t.Errorf("quarantined/reserved zone %q reported addressless: %+v", z.Zone, got)
		case "trust", "untrust":
			t.Errorf("zone with only a contested interface reported addressless: %+v", got)
		case "z174":
			t.Errorf("survivor z174 statically addressed must not be reported")
		}
	}
}

func TestAddresslessQuarantinedInterfacesNotReported12854(t *testing.T) {
	cfg := quarantinedAddresslessCfg12854(t)
	got := addresslessEnforcingInterfacesFromSnapshots(cfg, buildInterfaceSnapshots(cfg))
	for _, e := range got {
		if e.Zone == "z214" || e.Zone == "junos-host" {
			t.Errorf("quarantined/reserved zone interface reported: %+v", e)
		}
		if e.Interface == "ge-0-0-3.0" {
			t.Errorf("contested interface (quarantined key) reported: %+v (all=%+v)", e, got)
		}
	}
	if len(got) != 0 {
		t.Errorf("expected no per-interface windows, got %+v", got)
	}
}

func TestHostInboundPendingIntentQuarantined12854(t *testing.T) {
	cfg := quarantinedAddresslessCfg12854(t)
	if HostInboundPendingIntentFromSnapshots(cfg, buildInterfaceSnapshots(cfg)) {
		t.Errorf("pending intent latched true by quarantined/reserved/contested scopes only")
	}
}

// Positive control: a legitimate non-quarantined DHCP-pending zone still reports.
func TestAddresslessLegitPendingStillReported12854(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0-0-1": {Name: "ge-0-0-1", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, DHCP: true},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"wan": {Name: "wan", Interfaces: []string{"ge-0-0-1.0"}},
	}
	if got := addresslessEnforcingZonesFromSnapshots(cfg, buildInterfaceSnapshots(cfg)); len(got) != 1 || got[0].Zone != "wan" {
		t.Errorf("legit DHCP-pending zone must still report, got %+v", got)
	}
	if got := addresslessEnforcingInterfacesFromSnapshots(cfg, buildInterfaceSnapshots(cfg)); len(got) != 1 {
		t.Errorf("legit DHCP-pending iface must still report, got %+v", got)
	}
	if !HostInboundPendingIntentFromSnapshots(cfg, buildInterfaceSnapshots(cfg)) {
		t.Errorf("legit pending must latch barrier")
	}
}
