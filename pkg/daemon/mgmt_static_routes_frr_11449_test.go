package daemon

import "testing"

func TestAssembleFRRConfigKeepsManagementStaticsOutOfDataTable11449(t *testing.T) {
	store := testStoreWithSetConfig(t, []string{
		"set interfaces fxp0 unit 0 family inet address 192.0.2.2/24",
		"set interfaces ge-0/0/0 unit 0 family inet address 203.0.113.2/24",
		"set interfaces fxp0 unit 0 family inet6 address 2001:db8:10::2/64",
		"set interfaces ge-0/0/0 unit 0 family inet6 address 2001:db8:20::2/64",
		"set routing-options static route 198.51.100.0/24 next-hop 192.0.2.1",
		"set routing-options static route 198.51.101.0/24 next-hop 192.0.2.1 interface fxp0",
		"set routing-options static route 203.0.114.0/24 next-hop 203.0.113.1",
		"set routing-options rib inet6.0 static route 2001:db8:100::/64 next-hop 2001:db8:10::1",
		"set routing-options rib inet6.0 static route 2001:db8:101::/64 next-hop 2001:db8:10::1 interface fxp0",
		"set routing-options rib inet6.0 static route 2001:db8:200::/64 next-hop 2001:db8:20::1",
	})
	fc := (&Daemon{}).assembleFRRConfig(store.ActiveConfig(), nil)
	if len(fc.StaticRoutes) != 1 || fc.StaticRoutes[0].Destination != "203.0.114.0/24" {
		t.Fatalf("FRR global static routes = %+v, want only the data-scoped route", fc.StaticRoutes)
	}
	if len(fc.Inet6StaticRoutes) != 1 || fc.Inet6StaticRoutes[0].Destination != "2001:db8:200::/64" {
		t.Fatalf("FRR global IPv6 static routes = %+v, want only the data-scoped route", fc.Inet6StaticRoutes)
	}
}
