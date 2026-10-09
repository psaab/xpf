package daemon

import (
	"reflect"
	"sort"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

func TestMgmtStaticRouteAliasDeduplicationInstallsInKernel12084(t *testing.T) {
	enterPrivateNetns9813(t)
	fxp0 := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "fxp0"}}
	if err := netlink.LinkAdd(fxp0); err != nil {
		t.Skipf("cannot create dummy fxp0 in private netns: %v", err)
	}
	if err := netlink.LinkSetUp(fxp0); err != nil {
		t.Fatalf("bring fxp0 up: %v", err)
	}
	addr := &netlink.Addr{IPNet: mustRoute11449(t, "2001:db8:ffff::2/64")}
	if err := netlink.AddrAdd(fxp0, addr); err != nil {
		t.Fatalf("add fxp0 IPv6 gateway subnet: %v", err)
	}
	nlh, err := netlink.NewHandle()
	if err != nil {
		t.Fatalf("netlink.NewHandle: %v", err)
	}
	t.Cleanup(nlh.Close)

	text := `routing-options {
		static {
			route 2001:db8:40::/48 { next-hop 2001:db8:ffff::1 { interface fxp0; } }
			route 2001:db8:50::/48 { next-hop 2001:db8:ffff::1 { interface fxp0; } preference 200; }
			route 2001:db8:50::1/48 { next-hop 2001:db8:ffff::1 { interface fxp0; } }
			route ::/0 { next-hop 2001:db8:ffff::1 { interface fxp0; } }
			route 2001:db8:70::/48 { next-hop 2001:db8:ffff::1 { interface fxp0; } }
			route 2001:db8:80::/48 {
				next-hop 2001:db8:ffff::1 { interface fxp0; }
				next-hop 2001:db8:ffff::1 { interface fxp0; }
			}
		}
		rib inet6.0 { static {
			route 2001:db8:40::/48 { qualified-next-hop 2001:db8:ffff::1 { interface fxp0; preference 5; } }
			route 2001:db8:50::/48 { next-hop 2001:db8:ffff::1 { interface fxp0; } preference 200; }
			route ::/0 { next-hop 2001:db8:ffff::1 { interface fxp0; } }
			route 2001:db8:70::/48 {
				next-hop 2001:db8:ffff::1 { interface fxp0; }
				next-hop 2001:db8:ffff::3 { interface fxp0; }
			}
		} }
	}`
	root, parseErrs := config.NewParser(text).Parse()
	if len(parseErrs) != 0 {
		t.Fatalf("parse route fold fixture: %v", parseErrs)
	}
	cfg, err := config.CompileConfig(&config.ConfigTree{Children: root.Children})
	if err != nil {
		t.Fatalf("compile route fold fixture: %v", err)
	}
	mgmtSet := map[string]bool{"fxp0": true}
	if link, err := nlh.LinkByName("fxp0"); err != nil || link == nil {
		t.Fatalf("lookup fxp0 in install namespace: link=%v err=%v", link, err)
	}
	desired := mgmtStaticRoutesDesired(nlh, cfg, mgmtSet, [2][]netlink.Route{})
	if len(desired) != 6 {
		t.Fatalf("production desired routes = %+v, want six H1/H2/R4 tiers", desired)
	}
	if err := (&Daemon{}).applyMgmtVRFStaticRoutesTo(nlh, cfg, mgmtSet); err != nil {
		t.Fatalf("applyMgmtVRFStaticRoutesTo: %v", err)
	}

	gotRoutes, err := nlh.RouteListFiltered(netlink.FAMILY_V6,
		&netlink.Route{Table: mgmtVRFTableID}, netlink.RT_FILTER_TABLE)
	if err != nil {
		t.Fatalf("list table 999: %v", err)
	}
	if len(gotRoutes) == 0 {
		t.Fatalf("kernel returned no table-999 routes after production apply (desired=%+v)", desired)
	}
	got := make(map[string]map[int][]string)
	for _, route := range gotRoutes {
		destination := "::/0"
		if route.Dst != nil {
			destination = route.Dst.String()
		}
		if got[destination] == nil {
			got[destination] = make(map[int][]string)
		}
		if route.Gw != nil {
			got[destination][route.Priority] = append(got[destination][route.Priority], route.Gw.String())
		}
		if len(route.MultiPath) == 0 {
			if route.LinkIndex <= 0 {
				t.Fatalf("route %s/%d lost fxp0 link scope: %+v", destination, route.Priority, route)
			}
		} else {
			for _, hop := range route.MultiPath {
				if hop.LinkIndex <= 0 {
					t.Fatalf("route %s/%d multipath member lost fxp0 scope: %+v", destination, route.Priority, hop)
				}
				got[destination][route.Priority] = append(got[destination][route.Priority], hop.Gw.String())
			}
		}
	}
	for _, tiers := range got {
		for _, gateways := range tiers {
			sort.Strings(gateways)
		}
	}
	expected := map[string]map[int][]string{
		"2001:db8:40::/48": {5: {"2001:db8:ffff::1"}},
		"2001:db8:50::/48": {
			5:   {"2001:db8:ffff::1"},
			200: {"2001:db8:ffff::1"},
		},
		"::/0":             {5: {"2001:db8:ffff::1"}},
		"2001:db8:70::/48": {5: {"2001:db8:ffff::1", "2001:db8:ffff::3"}},
		"2001:db8:80::/48": {5: {"2001:db8:ffff::1"}},
	}
	if !reflect.DeepEqual(got, expected) {
		t.Fatalf("installed mgmt-VRF static routes = %#v, want %#v", got, expected)
	}
}

func TestMgmtStaticRoutesDesiredDeduplicatesEffectiveHops12084(t *testing.T) {
	sets := []string{
		"set routing-options static route 2001:db8:40::/48 next-hop 2001:db8:ffff::1 interface fxp0",
		"set routing-options rib inet6.0 static route 2001:db8:40::/48 qualified-next-hop 2001:db8:ffff::1 interface fxp0",
		"set routing-options rib inet6.0 static route 2001:db8:40::/48 qualified-next-hop 2001:db8:ffff::1 preference 5",
		"set routing-options static route 2001:db8:50::/48 next-hop 2001:db8:ffff::1 interface fxp0",
		"set routing-options static route 2001:db8:50::/48 preference 200",
		"set routing-options static route 2001:db8:50::1/48 next-hop 2001:db8:ffff::1 interface fxp0",
		"set routing-options rib inet6.0 static route 2001:db8:50::/48 next-hop 2001:db8:ffff::1 interface fxp0",
		"set routing-options rib inet6.0 static route 2001:db8:50::/48 preference 200",
		"set routing-options static route ::/0 next-hop 2001:db8:ffff::1 interface fxp0",
		"set routing-options rib inet6.0 static route ::/0 next-hop 2001:db8:ffff::1 interface fxp0",
		"set routing-options static route 2001:db8:70::/48 next-hop 2001:db8:ffff::1 interface fxp0",
		"set routing-options rib inet6.0 static route 2001:db8:70::/48 next-hop 2001:db8:ffff::1 interface fxp0",
		"set routing-options rib inet6.0 static route 2001:db8:70::/48 next-hop 2001:db8:ffff::3 interface fxp0",
	}
	tree := &config.ConfigTree{}
	for _, set := range sets {
		path, err := config.ParseSetCommand(set)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", set, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", set, err)
		}
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	desired := mgmtStaticRoutesDesired(
		&mgmtStaticRouteFake11449{links: map[string]int{"fxp0": 7}},
		cfg, map[string]bool{"fxp0": true}, [2][]netlink.Route{})
	got := make(map[string]map[int][]string)
	for _, target := range desired {
		route := target.route
		destination := "::/0"
		if route.Dst != nil {
			destination = route.Dst.String()
		}
		if got[destination] == nil {
			got[destination] = make(map[int][]string)
		}
		if route.Gw != nil {
			got[destination][route.Priority] = append(got[destination][route.Priority], route.Gw.String())
		}
		for _, hop := range route.MultiPath {
			got[destination][route.Priority] = append(got[destination][route.Priority], hop.Gw.String())
		}
	}
	for _, tiers := range got {
		for _, gateways := range tiers {
			sort.Strings(gateways)
		}
	}
	expected := map[string]map[int][]string{
		"2001:db8:40::/48": {5: {"2001:db8:ffff::1"}},
		"2001:db8:50::/48": {
			5:   {"2001:db8:ffff::1"},
			200: {"2001:db8:ffff::1"},
		},
		"::/0":             {5: {"2001:db8:ffff::1"}},
		"2001:db8:70::/48": {5: {"2001:db8:ffff::1", "2001:db8:ffff::3"}},
	}
	if !reflect.DeepEqual(got, expected) {
		t.Fatalf("desired mgmt-VRF static routes = %#v, want %#v", got, expected)
	}
}
