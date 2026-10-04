package daemon

import (
	"net"
	"testing"

	"github.com/vishvananda/netlink"
)

// The management-VRF netlink installer must keep higher-metric, equal-
// preference next-hops out of the primary's multipath set. Equal metrics stay
// multipath backups. RED-on-revert: grouping only by preference installs all
// three gateways together at distance 5.
func TestMgmtStaticQualifiedNextHopMetricOrdersEqualPreference_11792(t *testing.T) {
	store := testStoreWithSetConfig(t, []string{
		"set interfaces fxp0 unit 0 family inet address 192.0.2.10/24",
		"set routing-options static route 198.51.100.0/24 next-hop 192.0.2.1 interface fxp0",
		"set routing-options static route 198.51.100.0/24 qualified-next-hop 192.0.2.2 interface fxp0 metric 10",
		"set routing-options static route 198.51.100.0/24 qualified-next-hop 192.0.2.3 interface fxp0 metric 10",
	})
	fake := &mgmtStaticRouteFake11449{links: map[string]int{"fxp0": 2}}
	mgmtSet := map[string]bool{"fxp0": true}
	desired := mgmtStaticRoutesDesired(fake, store.ActiveConfig(), mgmtSet, [2][]netlink.Route{})

	var primary, backup *netlink.Route
	for _, target := range desired {
		route := target.route
		if route.Dst == nil || route.Dst.String() != "198.51.100.0/24" {
			continue
		}
		switch route.Priority {
		case 5:
			primary = &route
		case 6:
			backup = &route
		}
	}
	if primary == nil || primary.Gw == nil || !primary.Gw.Equal(net.ParseIP("192.0.2.1")) {
		t.Fatalf("primary route = %+v, want pref-5 gateway 192.0.2.1", primary)
	}
	if backup == nil || len(backup.MultiPath) != 2 {
		t.Fatalf("backup route = %+v, want pref-6 ECMP tier with two equal-metric gateways", backup)
	}
	got := map[string]bool{}
	for _, nextHop := range backup.MultiPath {
		got[nextHop.Gw.String()] = true
	}
	if !got["192.0.2.2"] || !got["192.0.2.3"] {
		t.Fatalf("backup multipath gateways = %v, want 192.0.2.2 and .3", got)
	}
}
