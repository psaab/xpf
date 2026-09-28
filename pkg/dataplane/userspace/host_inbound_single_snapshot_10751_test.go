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
