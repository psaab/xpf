// #10751 R4-2: the install inputs, the handoff retention verdict, and the
// handoff change check all derive from observed address snapshots instead of
// re-sampling the kernel piecemeal — a lease landing mid-apply must not skew
// the installed ruleset against the retention decision. SnapshotNewcomerAddrs
// is the change check: any address present in the handoff re-sample but
// absent from the install sample is uncovered by the installed ruleset,
// INCLUDING a new kernel link-local (installed views deny fe80 destinations,
// so a link that came up mid-apply is uncovered exactly like a new global).
package userspace

import (
	"reflect"
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

func TestSnapshotNewcomerAddrs10751(t *testing.T) {
	link := int(netlink.SCOPE_LINK)
	universe := int(netlink.SCOPE_UNIVERSE)
	v4 := newcomerAddr10751("inet", "10.0.0.1/24", universe)
	v6 := newcomerAddr10751("inet6", "2001:db8::99/64", universe)
	ll := newcomerAddr10751("inet6", "fe80::7/64", link)
	row := func(addrs ...InterfaceAddressSnapshot) []InterfaceSnapshot {
		return []InterfaceSnapshot{newcomerRow10751("ge-0/0/0.0", "trust", addrs...)}
	}
	for _, tc := range []struct {
		name  string
		base  []InterfaceSnapshot
		fresh []InterfaceSnapshot
		want  []string
	}{
		{"no change", row(v4), row(v4), nil},
		{"new global", row(v4), row(v4, v6), []string{"2001:db8::99"}},
		// A NEW link-local is uncovered by the install sample's ruleset
		// exactly like a new global (installed views deny fe80). RED on
		// revert: scope-filtering the comparison drops this newcomer and
		// the handoff would open link-local host input.
		{"new link-local", row(v4), row(v4, ll), []string{"fe80::7"}},
		{"standing link-local both sides", row(v4, ll), row(v4, ll), nil},
		{"removal is not a newcomer", row(v4, v6), row(v4), nil},
		{"link-local removal is not a newcomer", row(v4, ll), row(v4), nil},
		{"empty baseline", nil, row(v4, ll), []string{"10.0.0.1", "fe80::7"}},
		{"empty fresh", row(v4), nil, nil},
		{"unparseable rows skipped", row(v4), []InterfaceSnapshot{newcomerRow10751("ge-0/0/0.0", "trust",
			v4, newcomerAddr10751("inet6", "not-an-address", universe))}, nil},
	} {
		if got := SnapshotNewcomerAddrs(tc.base, tc.fresh); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: SnapshotNewcomerAddrs = %v, want %v", tc.name, got, tc.want)
		}
	}
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
