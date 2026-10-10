package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

func TestMgmtStaticRouteResolvedGatewayAliasesInstallInKernel_12084(t *testing.T) {
	cases := []struct {
		name        string
		family      int
		gateway     string
		address     string
		destination string
		routes      string
		vrf         bool
	}{
		{
			name:   "v6-inferred-and-qualified",
			family: netlink.FAMILY_V6, gateway: "2001:db8:ffff::1", address: "2001:db8:ffff::2/64",
			destination: "2001:db8:60::/48",
			routes: `routing-options { static { route 2001:db8:60::/48 { next-hop 2001:db8:ffff::1; } }
				rib inet6.0 { static { route 2001:db8:60::/48 { qualified-next-hop 2001:db8:ffff::1 { interface fxp0; } } } } }`,
		},
		{
			name:   "v6-case-variant",
			family: netlink.FAMILY_V6, gateway: "2001:db8:ffff::1", address: "2001:db8:ffff::2/64",
			destination: "2001:db8:61::/48",
			routes: `routing-options { static { route 2001:db8:61::/48 { next-hop 2001:DB8:FFFF::1; } }
				rib inet6.0 { static { route 2001:db8:61::/48 { qualified-next-hop 2001:db8:ffff::1 { interface fxp0; } } } } }`,
		},
		{
			name:   "v6-noncanonical-variant",
			family: netlink.FAMILY_V6, gateway: "2001:db8:ffff::1", address: "2001:db8:ffff::2/64",
			destination: "2001:db8:62::/48",
			routes: `routing-options { static { route 2001:db8:62::/48 { next-hop 2001:db8:ffff:0:0::1; } }
				rib inet6.0 { static { route 2001:db8:62::/48 { qualified-next-hop 2001:db8:ffff::1 { interface fxp0; } } } } }`,
		},
		{
			name:   "v4-connected-vrf-alias",
			family: netlink.FAMILY_V4, gateway: "192.0.2.1", address: "192.0.2.2/24", vrf: true,
			destination: "10.71.0.0/16",
			routes: `routing-options { static {
				route 10.71.0.0/16 { next-hop 192.0.2.1; }
				route 10.71.0.1/16 { qualified-next-hop 192.0.2.1 { interface fxp0; } }
			} }`,
		},
		{
			name:   "same-block-h7-effective-alias",
			family: netlink.FAMILY_V6, gateway: "2001:db8:ffff::1", address: "2001:db8:ffff::2/64",
			destination: "2001:db8:70::/48",
			routes: `routing-options { static { route 2001:db8:70::/48 {
				next-hop 2001:db8:ffff::1;
				qualified-next-hop 2001:db8:ffff::1 { interface fxp0; preference 5; }
			} } }`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			enterPrivateNetns9813(t)
			if tc.vrf {
				vrf := &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: mgmtVRFDeviceName}, Table: mgmtVRFTableID}
				if err := netlink.LinkAdd(vrf); err != nil {
					t.Skipf("cannot create management VRF in private netns: %v", err)
				}
				if err := netlink.LinkSetUp(vrf); err != nil {
					t.Fatalf("bring management VRF up: %v", err)
				}
			}
			fxp0 := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "fxp0"}}
			if err := netlink.LinkAdd(fxp0); err != nil {
				t.Skipf("cannot create dummy fxp0 in private netns: %v", err)
			}
			if err := netlink.LinkSetUp(fxp0); err != nil {
				t.Fatalf("bring fxp0 up: %v", err)
			}
			if tc.vrf {
				vrf, err := netlink.LinkByName(mgmtVRFDeviceName)
				if err != nil {
					t.Fatalf("lookup management VRF: %v", err)
				}
				if err := netlink.LinkSetMaster(fxp0, vrf); err != nil {
					t.Fatalf("enslave fxp0 to management VRF: %v", err)
				}
			}
			if err := netlink.AddrAdd(fxp0, &netlink.Addr{IPNet: mustRoute11449(t, tc.address)}); err != nil {
				t.Fatalf("add fxp0 address: %v", err)
			}
			nlh, err := netlink.NewHandle()
			if err != nil {
				t.Fatalf("netlink.NewHandle: %v", err)
			}
			t.Cleanup(nlh.Close)

			ifaceFamily := "inet6"
			if tc.family == netlink.FAMILY_V4 {
				ifaceFamily = "inet"
			}
			text := `interfaces { fxp0 { unit 0 { family ` + ifaceFamily + ` { address ` + tc.address + `; } } } }
				` + tc.routes
			root, parseErrs := config.NewParser(text).Parse()
			if len(parseErrs) != 0 {
				t.Fatalf("parse route alias fixture: %v", parseErrs)
			}
			cfg, err := config.CompileConfig(&config.ConfigTree{Children: root.Children})
			if err != nil {
				t.Fatalf("compile route alias fixture: %v", err)
			}
			mgmtSet := map[string]bool{"fxp0": true}
			if err := (&Daemon{}).applyMgmtVRFStaticRoutesTo(nlh, cfg, mgmtSet); err != nil {
				t.Fatalf("applyMgmtVRFStaticRoutesTo: %v", err)
			}
			got, err := nlh.RouteListFiltered(tc.family,
				&netlink.Route{Table: mgmtVRFTableID}, netlink.RT_FILTER_TABLE)
			if err != nil {
				t.Fatalf("list table 999: %v", err)
			}
			installed := make([]netlink.Route, 0, 1)
			for _, route := range got {
				if route.Dst != nil && route.Dst.String() == tc.destination {
					installed = append(installed, route)
				}
			}
			if len(installed) != 1 {
				t.Fatalf("installed routes for %s = %+v, all table routes = %+v, want one static route", tc.destination, installed, got)
			}
			var gateway string
			if installed[0].Gw != nil {
				gateway = installed[0].Gw.String()
			}
			if len(installed[0].MultiPath) > 0 {
				t.Fatalf("installed route has duplicate multipath legs: %+v", installed[0].MultiPath)
			}
			if gateway != tc.gateway {
				t.Fatalf("installed gateway = %q, want %q", gateway, tc.gateway)
			}
		})
	}
}

func TestMgmtStaticRouteTolerantNoInstallActionInstallsGateway_12084(t *testing.T) {
	enterPrivateNetns9813(t)
	fxp0 := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "fxp0"}}
	if err := netlink.LinkAdd(fxp0); err != nil {
		t.Skipf("cannot create dummy fxp0 in private netns: %v", err)
	}
	if err := netlink.LinkSetUp(fxp0); err != nil {
		t.Fatalf("bring fxp0 up: %v", err)
	}
	if err := netlink.AddrAdd(fxp0, &netlink.Addr{IPNet: mustRoute11449(t, "192.0.2.2/24")}); err != nil {
		t.Fatalf("add fxp0 address: %v", err)
	}
	nlh, err := netlink.NewHandle()
	if err != nil {
		t.Fatalf("netlink.NewHandle: %v", err)
	}
	t.Cleanup(nlh.Close)

	text := `interfaces { fxp0 { unit 0 { family inet { address 192.0.2.2/24; } } } }
		routing-options { static {
			route 10.72.0.0/16 { qualified-next-hop 192.0.2.1 { interface fxp0; } }
			route 10.72.0.1/16 { discard; no-install; }
		} }`
	root, parseErrs := config.NewParser(text).Parse()
	if len(parseErrs) != 0 {
		t.Fatalf("parse route fixture: %v", parseErrs)
	}
	cfg, err := config.CompileConfigLenient(&config.ConfigTree{Children: root.Children})
	if err != nil {
		t.Fatalf("compile route fixture: %v", err)
	}
	mgmtSet := map[string]bool{"fxp0": true}
	if err := (&Daemon{}).applyMgmtVRFStaticRoutesTo(nlh, cfg, mgmtSet); err != nil {
		t.Fatalf("applyMgmtVRFStaticRoutesTo: %v", err)
	}
	got, err := nlh.RouteListFiltered(netlink.FAMILY_V4,
		&netlink.Route{Table: mgmtVRFTableID}, netlink.RT_FILTER_TABLE)
	if err != nil {
		t.Fatalf("list table 999: %v", err)
	}
	var gateway string
	for _, route := range got {
		if route.Dst != nil && route.Dst.String() == "10.72.0.0/16" && route.Gw != nil {
			gateway = route.Gw.String()
		}
	}
	if gateway != "192.0.2.1" {
		t.Fatalf("installed gateway for 10.72.0.0/16 = %q (table routes = %+v), want 192.0.2.1", gateway, got)
	}
}
