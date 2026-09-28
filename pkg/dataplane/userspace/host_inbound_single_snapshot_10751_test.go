// #10751 R4-2/R5-B: the install inputs, the handoff retention verdict, and
// the handoff change checks all derive from observed address snapshots
// instead of re-sampling the kernel piecemeal — a lease landing mid-apply
// must not skew the installed ruleset against the retention decision. The
// change checks compare RENDERED desired destinations (daemon-side, via the
// FromSnapshots builders plus the uncovered-drop helper), never raw rows:
// only an actually-denied destination counts.
package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

func newcomerRow10751(name, zone string, addrs ...InterfaceAddressSnapshot) InterfaceSnapshot {
	return InterfaceSnapshot{Name: name, Zone: zone, IsUnit: true, LinuxName: name, Addresses: addrs}
}

func newcomerAddr10751(fam, cidr string, scope int) InterfaceAddressSnapshot {
	return InterfaceAddressSnapshot{Family: fam, Address: cidr, Scope: scope}
}

// TestHostInboundPendingIntentFromSnapshots10751 drives the handoff retention
// verdict directly over synthetic snapshots: an fe80-only DHCPv6 unit is
// pending, a globally-addressed one is not, and an addressless DHCP unit is
// pending at zone granularity.
func TestHostInboundPendingIntentFromSnapshots10751(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0-0-1": {Name: "ge-0-0-1", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, DHCP: true, DHCPv6: true},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"wan": {Name: "wan", Interfaces: []string{"ge-0-0-1.0"}},
	}
	link := int(netlink.SCOPE_LINK)
	universe := int(netlink.SCOPE_UNIVERSE)
	for _, tc := range []struct {
		name  string
		snaps []InterfaceSnapshot
		want  bool
	}{
		{"link-local only is pending", []InterfaceSnapshot{newcomerRow10751("ge-0-0-1.0", "wan",
			newcomerAddr10751("inet6", "fe80::7/64", link))}, true},
		{"addressless is pending", []InterfaceSnapshot{newcomerRow10751("ge-0-0-1.0", "wan")}, true},
		{"no rows is pending", nil, true},
		{"global resolves", []InterfaceSnapshot{newcomerRow10751("ge-0-0-1.0", "wan",
			newcomerAddr10751("inet", "203.0.113.5/24", universe),
			newcomerAddr10751("inet6", "2001:db8::5/64", universe))}, false},
	} {
		if got := HostInboundPendingIntentFromSnapshots(cfg, tc.snaps); got != tc.want {
			t.Errorf("%s: HostInboundPendingIntentFromSnapshots = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestBuildUnzonedDHCPUnleasedNetdevs10751 pins the R7-B/F8-A backstop
// input: unzoned non-lifeline DHCP units with no resolved address in an
// intended family are listed by LOCAL_IN netdev name, SPLIT BY FAMILY (a
// leased family gets neither DROP nor DHCP admit — pure destination
// judgement). Zoned, lifeline, static, resolved, and VRF-enslaved units
// are excluded.
func TestBuildUnzonedDHCPUnleasedNetdevs10751(t *testing.T) {
	link := int(netlink.SCOPE_LINK)
	universe := int(netlink.SCOPE_UNIVERSE)
	mkcfg := func() *config.Config {
		cfg := &config.Config{}
		cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
			"ge-0-0-9": {Name: "ge-0-0-9", Units: map[int]*config.InterfaceUnit{
				0: {Number: 0, DHCP: true, DHCPv6: true},
			}},
		}
		return cfg
	}
	t.Run("unzoned unleased listed", func(t *testing.T) {
		v4, v6 := BuildUnzonedDHCPUnleasedNetdevs(mkcfg(), nil)
		if len(v4) != 1 || v4[0] != "ge-0-0-9" || len(v6) != 1 || v6[0] != "ge-0-0-9" {
			t.Fatalf("unleased v4/v6 = %v/%v, want [ge-0-0-9]/[ge-0-0-9]", v4, v6)
		}
	})
	t.Run("zoned excluded", func(t *testing.T) {
		cfg := mkcfg()
		cfg.Security.Zones = map[string]*config.ZoneConfig{
			"wan": {Name: "wan", Interfaces: []string{"ge-0-0-9.0"}},
		}
		if v4, v6 := BuildUnzonedDHCPUnleasedNetdevs(cfg, nil); len(v4) != 0 || len(v6) != 0 {
			t.Fatalf("unleased v4/v6 = %v/%v, want empty/empty (zoned units use pending retention)", v4, v6)
		}
	})
	t.Run("static excluded", func(t *testing.T) {
		cfg := mkcfg()
		cfg.Interfaces.Interfaces["ge-0-0-9"].Units[0] = &config.InterfaceUnit{Number: 0}
		if v4, v6 := BuildUnzonedDHCPUnleasedNetdevs(cfg, nil); len(v4) != 0 || len(v6) != 0 {
			t.Fatalf("unleased v4/v6 = %v/%v, want empty/empty (no DHCP intent)", v4, v6)
		}
	})
	t.Run("resolved excluded", func(t *testing.T) {
		cfg := mkcfg()
		cfg.Interfaces.Interfaces["ge-0-0-9"].Units[0] = &config.InterfaceUnit{Number: 0, DHCP: true}
		snaps := []InterfaceSnapshot{newcomerRow10751("ge-0-0-9.0", "",
			newcomerAddr10751("inet", "203.0.113.9/24", universe))}
		if v4, v6 := BuildUnzonedDHCPUnleasedNetdevs(cfg, snaps); len(v4) != 0 || len(v6) != 0 {
			t.Fatalf("unleased v4/v6 = %v/%v, want empty/empty (leased address resolves)", v4, v6)
		}
	})
	t.Run("link-local only still unleased", func(t *testing.T) {
		cfg := mkcfg()
		snaps := []InterfaceSnapshot{newcomerRow10751("ge-0-0-9.0", "",
			newcomerAddr10751("inet6", "fe80::9/64", link))}
		v4, v6 := BuildUnzonedDHCPUnleasedNetdevs(cfg, snaps)
		if len(v4) != 1 || len(v6) != 1 {
			t.Fatalf("unleased v4/v6 = %v/%v, want the netdev in both (automatic LL never resolves intent)", v4, v6)
		}
	})
	t.Run("partial family lists", func(t *testing.T) {
		cfg := mkcfg()
		cfg.Interfaces.Interfaces["ge-0-0-9"].Units[0] = &config.InterfaceUnit{
			Number: 0, Addresses: []string{"10.9.9.9/24"}, DHCPv6: true,
		}
		snaps := []InterfaceSnapshot{newcomerRow10751("ge-0-0-9.0", "",
			newcomerAddr10751("inet", "10.9.9.9/24", universe))}
		v4, v6 := BuildUnzonedDHCPUnleasedNetdevs(cfg, snaps)
		if len(v4) != 0 || len(v6) != 1 || v6[0] != "ge-0-0-9" {
			t.Fatalf("unleased v4/v6 = %v/%v, want empty/[ge-0-0-9] (leased v4 keeps pure destination judgement; v6 unleased)", v4, v6)
		}
	})
	t.Run("lifeline excluded", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
			"fxp0": {Name: "fxp0", Units: map[int]*config.InterfaceUnit{
				0: {Number: 0, DHCP: true},
			}},
		}
		if v4, v6 := BuildUnzonedDHCPUnleasedNetdevs(cfg, nil); len(v4) != 0 || len(v6) != 0 {
			t.Fatalf("unleased v4/v6 = %v/%v, want empty/empty (lifeline management must survive)", v4, v6)
		}
	})
	t.Run("vrf enslaved excluded", func(t *testing.T) {
		cfg := mkcfg()
		cfg.RoutingInstances = []*config.RoutingInstanceConfig{
			{Name: "vrf1", Interfaces: []string{"ge-0-0-9.0"}},
		}
		if v4, v6 := BuildUnzonedDHCPUnleasedNetdevs(cfg, nil); len(v4) != 0 || len(v6) != 0 {
			t.Fatalf("unleased v4/v6 = %v/%v, want empty/empty (LOCAL_IN identity is the shared master; iifname would shadow siblings)", v4, v6)
		}
	})
}
