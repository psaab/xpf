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

// TestBuildUnzonedDHCPUnleasedNetdevs10751 pins the R7-B backstop input:
// unzoned non-lifeline DHCP units with no resolved address in an intended
// family are listed by LOCAL_IN netdev name. Zoned, lifeline, static,
// resolved, and VRF-enslaved units are excluded; either-family unleased
// lists (LAST placement keeps the addressed family judging by
// destinations).
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
		got := BuildUnzonedDHCPUnleasedNetdevs(mkcfg(), nil)
		if len(got) != 1 || got[0] != "ge-0-0-9" {
			t.Fatalf("unleased = %v, want [ge-0-0-9]", got)
		}
	})
	t.Run("zoned excluded", func(t *testing.T) {
		cfg := mkcfg()
		cfg.Security.Zones = map[string]*config.ZoneConfig{
			"wan": {Name: "wan", Interfaces: []string{"ge-0-0-9.0"}},
		}
		if got := BuildUnzonedDHCPUnleasedNetdevs(cfg, nil); len(got) != 0 {
			t.Fatalf("unleased = %v, want empty (zoned units use pending retention)", got)
		}
	})
	t.Run("static excluded", func(t *testing.T) {
		cfg := mkcfg()
		cfg.Interfaces.Interfaces["ge-0-0-9"].Units[0] = &config.InterfaceUnit{Number: 0}
		if got := BuildUnzonedDHCPUnleasedNetdevs(cfg, nil); len(got) != 0 {
			t.Fatalf("unleased = %v, want empty (no DHCP intent)", got)
		}
	})
	t.Run("resolved excluded", func(t *testing.T) {
		cfg := mkcfg()
		cfg.Interfaces.Interfaces["ge-0-0-9"].Units[0] = &config.InterfaceUnit{Number: 0, DHCP: true}
		snaps := []InterfaceSnapshot{newcomerRow10751("ge-0-0-9.0", "",
			newcomerAddr10751("inet", "203.0.113.9/24", universe))}
		if got := BuildUnzonedDHCPUnleasedNetdevs(cfg, snaps); len(got) != 0 {
			t.Fatalf("unleased = %v, want empty (leased address resolves)", got)
		}
	})
	t.Run("link-local only still unleased", func(t *testing.T) {
		cfg := mkcfg()
		snaps := []InterfaceSnapshot{newcomerRow10751("ge-0-0-9.0", "",
			newcomerAddr10751("inet6", "fe80::9/64", link))}
		got := BuildUnzonedDHCPUnleasedNetdevs(cfg, snaps)
		if len(got) != 1 {
			t.Fatalf("unleased = %v, want the netdev (automatic LL never resolves intent)", got)
		}
	})
	t.Run("partial family lists", func(t *testing.T) {
		cfg := mkcfg()
		cfg.Interfaces.Interfaces["ge-0-0-9"].Units[0] = &config.InterfaceUnit{
			Number: 0, Addresses: []string{"10.9.9.9/24"}, DHCPv6: true,
		}
		snaps := []InterfaceSnapshot{newcomerRow10751("ge-0-0-9.0", "",
			newcomerAddr10751("inet", "10.9.9.9/24", universe))}
		got := BuildUnzonedDHCPUnleasedNetdevs(cfg, snaps)
		if len(got) != 1 {
			t.Fatalf("unleased = %v, want the netdev (v6 unleased; LAST placement preserves v4 destinations)", got)
		}
	})
	t.Run("lifeline excluded", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
			"fxp0": {Name: "fxp0", Units: map[int]*config.InterfaceUnit{
				0: {Number: 0, DHCP: true},
			}},
		}
		if got := BuildUnzonedDHCPUnleasedNetdevs(cfg, nil); len(got) != 0 {
			t.Fatalf("unleased = %v, want empty (lifeline management must survive)", got)
		}
	})
	t.Run("vrf enslaved excluded", func(t *testing.T) {
		cfg := mkcfg()
		cfg.RoutingInstances = []*config.RoutingInstanceConfig{
			{Name: "vrf1", Interfaces: []string{"ge-0-0-9.0"}},
		}
		if got := BuildUnzonedDHCPUnleasedNetdevs(cfg, nil); len(got) != 0 {
			t.Fatalf("unleased = %v, want empty (LOCAL_IN identity is the shared master; iifname would shadow siblings)", got)
		}
	})
}
