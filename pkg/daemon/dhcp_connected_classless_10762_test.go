package daemon

import (
	"net/netip"
	"testing"

	"github.com/psaab/xpf/pkg/dhcp"
)

// #10762: an option-121 route more specific than an existing connected
// network wins longest-prefix match and can send internal traffic to the DHCP
// server's gateway. Exercise the real lease collector, including connected
// prefixes from both configured interface addresses and another DHCP lease.
func TestCollectDHCPRoutesSuppressesClasslessRoutesInsideConnectedSubnets10762(t *testing.T) {
	t.Setenv(dhcpClasslessTrustOverrideEnv, "")
	store := testStoreWithSetConfig(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
		"set interfaces ge-0/0/1 unit 0 family inet dhcp",
		"set interfaces ge-0/0/2 unit 0 family inet address 10.10.0.1/24",
		"set routing-instances tenant instance-type virtual-router",
		"set routing-instances tenant interface ge-0/0/2.0",
	})
	mgr := dhcp.NewManagerForTesting(nil)
	mgr.SeedLeaseForTesting("ge-0-0-1", dhcp.AFInet, &dhcp.Lease{
		Interface: "ge-0-0-1",
		Family:    dhcp.AFInet,
		Address:   netip.MustParsePrefix("198.51.100.10/24"),
		Gateway:   netip.MustParseAddr("198.51.100.1"),
		ClasslessRoutes: []dhcp.LeaseRoute{
			{Destination: netip.MustParsePrefix("10.0.1.0/25"), Gateway: netip.MustParseAddr("198.51.100.1")},
			{Destination: netip.MustParsePrefix("10.0.1.128/25"), Gateway: netip.MustParseAddr("198.51.100.1")},
			{Destination: netip.MustParsePrefix("198.51.100.0/25"), Gateway: netip.MustParseAddr("198.51.100.1")},
			// A broader learned prefix and an unrelated prefix remain useful.
			{Destination: netip.MustParsePrefix("10.0.0.0/23"), Gateway: netip.MustParseAddr("198.51.100.1")},
			{Destination: netip.MustParsePrefix("192.0.2.0/24"), Gateway: netip.MustParseAddr("198.51.100.1")},
			// An overlap in another routing context must not suppress this route.
			{Destination: netip.MustParsePrefix("10.10.0.0/25"), Gateway: netip.MustParseAddr("198.51.100.1")},
		},
	})
	d := &Daemon{store: store, dhcp: mgr}

	routes := d.collectDHCPRoutes()
	got := make(map[string]int, len(routes))
	for _, route := range routes {
		got[route.Destination]++
	}
	for _, blocked := range []string{"10.0.1.0/25", "10.0.1.128/25", "198.51.100.0/25"} {
		if got[blocked] != 0 {
			t.Errorf("connected-overlap DHCP route %s survived: %+v", blocked, routes)
		}
	}
	for _, allowed := range []string{"", "10.0.0.0/23", "10.10.0.0/25", "192.0.2.0/24"} {
		if got[allowed] != 1 {
			t.Errorf("DHCP route %q count = %d, want 1; routes: %+v", allowed, got[allowed], routes)
		}
	}
	if len(routes) != 4 {
		t.Errorf("got %d DHCP routes, want default plus three allowed classless routes: %+v", len(routes), routes)
	}

	// The established, explicit classless trust override remains available.
	t.Setenv(dhcpClasslessTrustOverrideEnv, "1")
	for _, route := range d.collectDHCPRoutes() {
		if route.Destination == "10.0.1.0/25" {
			return
		}
	}
	t.Fatal("explicit classless trust override did not restore the connected-overlap route")
}
