package daemon

import (
	"net"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// #12721: the kernel lists IPv6 connected routes with RT_SCOPE_UNIVERSE,
// not SCOPE_LINK. The live connected-route checks gated on SCOPE_LINK, so
// an IPv6 gateway resolved by a live table-999 connected route never
// matched: FRR kept management IPv6 statics it should have excluded, and
// the DHCP classless connected-prefix fence missed IPv6 connected
// prefixes. IPv4 connected routes are listed with link scope, so only
// IPv6 was affected.

func connectedRoute12721(t *testing.T, prefix string, linkIndex int, scope netlink.Scope) netlink.Route {
	t.Helper()
	_, dst, err := net.ParseCIDR(prefix)
	if err != nil {
		t.Fatalf("parse %s: %v", prefix, err)
	}
	family := netlink.FAMILY_V6
	if ones, bits := dst.Mask.Size(); bits == 32 && ones >= 0 {
		family = netlink.FAMILY_V4
	}
	return netlink.Route{
		Family:    family,
		Dst:       dst,
		LinkIndex: linkIndex,
		Table:     mgmtVRFTableID,
		Type:      unix.RTN_UNICAST,
		Protocol:  unix.RTPROT_KERNEL,
		Scope:     scope,
	}
}

func TestMgmtStaticConnectedLinkIndexIPv6Universe12721(t *testing.T) {
	gateway := net.ParseIP("2001:db8:10::1")
	cases := []struct {
		name  string
		route netlink.Route
		want  int
		found bool
	}{
		{"v6 universe connected", connectedRoute12721(t, "2001:db8:10::/64", 7, netlink.SCOPE_UNIVERSE), 7, true},
		{"v6 link connected", connectedRoute12721(t, "2001:db8:10::/64", 7, netlink.SCOPE_LINK), 7, true},
		{"v4 link connected", connectedRoute12721(t, "192.0.2.0/24", 7, netlink.SCOPE_LINK), 7, true},
		{"v4 universe is not connected", connectedRoute12721(t, "192.0.2.0/24", 7, netlink.SCOPE_UNIVERSE), 0, false},
		{"v6 universe is non-covering", connectedRoute12721(t, "2001:db8:20::/64", 7, netlink.SCOPE_UNIVERSE), 0, false},
		// A universe gateway route (Gw set) is not a connected route.
		{"v6 universe with gateway", func() netlink.Route {
			r := connectedRoute12721(t, "2001:db8:10::/64", 7, netlink.SCOPE_UNIVERSE)
			r.Gw = net.ParseIP("2001:db8::fe")
			return r
		}(), 0, false},
		// A non-kernel universe route is not a connected route.
		{"v6 universe static", func() netlink.Route {
			r := connectedRoute12721(t, "2001:db8:10::/64", 7, netlink.SCOPE_UNIVERSE)
			r.Protocol = unix.RTPROT_STATIC
			return r
		}(), 0, false},
		// A host-scope row is not a connected route.
		{"v6 host scope", connectedRoute12721(t, "2001:db8:10::/64", 7, netlink.SCOPE_HOST), 0, false},
		// A universe kernel route whose prefix does not contain the gateway.
		{"v6 universe non-covering", connectedRoute12721(t, "2001:db8:20::/64", 7, netlink.SCOPE_UNIVERSE), 0, false},
	}
	for _, tc := range cases {
		gw := gateway
		if tc.route.Dst != nil && tc.route.Dst.IP.To4() != nil {
			gw = net.ParseIP("192.0.2.1")
		}
		got, found := mgmtStaticConnectedLinkIndex(gw, []netlink.Route{tc.route})
		if found != tc.found || got != tc.want {
			t.Errorf("%s: mgmtStaticConnectedLinkIndex = (%d, %v), want (%d, %v)",
				tc.name, got, found, tc.want, tc.found)
		}
	}
}

// Ambiguity: two different links both claim the gateway via universe-scope
// connected routes — the lookup must refuse, not guess.
func TestMgmtStaticConnectedLinkIndexIPv6UniverseAmbiguous12721(t *testing.T) {
	routes := []netlink.Route{
		connectedRoute12721(t, "2001:db8:10::/64", 7, netlink.SCOPE_UNIVERSE),
		connectedRoute12721(t, "2001:db8:10::/64", 9, netlink.SCOPE_UNIVERSE),
	}
	if idx, ok := mgmtStaticConnectedLinkIndex(net.ParseIP("2001:db8:10::1"), routes); ok {
		t.Fatalf("ambiguous universe connected routes resolved to link %d, want refusal", idx)
	}
}

// The mgmtVRFRouteInventory connected-prefix fence must include IPv6
// universe-scope connected routes (control/fabric fence + ordinary
// connected prefixes), while IPv4 behavior stays link-scope.
func TestMgmtVRFRouteInventoryIPv6UniverseConnected12721(t *testing.T) {
	fake := &mgmtStaticRouteFake11449{
		links: map[string]int{"fxp0": 7},
		routes: []netlink.Route{
			connectedRoute12721(t, "2001:db8:10::/64", 7, netlink.SCOPE_UNIVERSE),
			connectedRoute12721(t, "2001:db8:20::/64", 9, netlink.SCOPE_LINK),
		},
	}
	_, _, control, prefixes, err := mgmtVRFRouteInventory(fake, netlink.FAMILY_V6, map[int]string{7: "fxp0"})
	if err != nil {
		t.Fatalf("inventory: %v", err)
	}
	var got []string
	for _, p := range prefixes {
		got = append(got, p.String())
	}
	if len(got) != 2 {
		t.Fatalf("connected prefixes = %v, want both v6 connected prefixes", got)
	}
	if len(control) != 1 || control[0].LinkIndex != 7 {
		t.Fatalf("control connected = %+v, want the universe-scope fxp0 route", control)
	}
}

func TestFRRExcludesStaticResolvedByIPv6UniverseConnectedRoute12721(t *testing.T) {
	store := testStoreWithSetConfig(t, []string{
		"set interfaces fxp0 unit 0 family inet6 address 2001:db8:10::2/64",
		"set interfaces ge-0/0/0 unit 0 family inet6 address 2001:db8:20::2/64",
		"set routing-options rib inet6.0 static route 2001:db8:100::/64 next-hop 2001:db8:10::1",
		"set routing-options rib inet6.0 static route 2001:db8:200::/64 next-hop 2001:db8:20::1",
	})
	current := [2][]netlink.Route{}
	current[1] = []netlink.Route{
		connectedRoute12721(t, "2001:db8:10::/64", 7, netlink.SCOPE_UNIVERSE),
	}
	_, got := mgmtStaticRoutesForFRR(
		store.ActiveConfig(), map[string]bool{"fxp0": true}, nil, current)
	if len(got) != 1 || got[0].Destination != "2001:db8:200::/64" {
		t.Fatalf("IPv6 FRR statics = %+v, want only data-connected static", got)
	}
}
