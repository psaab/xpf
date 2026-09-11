package frr

import (
	"net/netip"
	"strings"
	"testing"
)

func renderDHCP9501(routes ...DHCPRoute) string {
	var b strings.Builder
	renderDHCPDefaults(&b, &FullConfig{DHCPRoutes: routes})
	return b.String()
}

// #9501: the DHCP-learned route line interpolated dr.Interface with no token
// belt, while the static-route renderer one function away belts exactly that
// operand class. A token-unsafe interface arriving via a tolerant load, peer
// sync or rollback could split the line or inject another stanza into the
// managed frr.conf.
func TestDHCPRouteInterfaceOperandIsBelted_9501(t *testing.T) {
	gw4 := netip.MustParseAddr("10.0.2.1").String()
	ll6 := netip.MustParseAddr("fe80::1").String()

	// CONTROLS: a well-formed interface still binds the route, in both families.
	if got := renderDHCP9501(DHCPRoute{Gateway: gw4, Interface: "fxp0"}); !strings.Contains(got, "ip route 0.0.0.0/0 10.0.2.1 fxp0 200") {
		t.Fatalf("control: a valid interface must still qualify the v4 DHCP route:\n%s", got)
	}
	if got := renderDHCP9501(DHCPRoute{Gateway: ll6, Interface: "ge-0-0-1", IsIPv6: true}); !strings.Contains(got, "ipv6 route ::/0 fe80::1 ge-0-0-1 200") {
		t.Fatalf("control: a valid interface must still qualify the v6 link-local DHCP route:\n%s", got)
	}

	for _, bad := range []string{"fxp0 x", "fxp0\tx", "fxp0\nip route 0.0.0.0/0 6.6.6.6"} {
		got := renderDHCP9501(DHCPRoute{Gateway: gw4, Interface: bad})
		if strings.Contains(got, "6.6.6.6") || strings.Contains(got, " x ") || strings.Contains(got, "\tx") {
			t.Fatalf("#9501: a token-unsafe interface %q reached the rendered DHCP route:\n%s", bad, got)
		}
		// A routable gateway keeps its route, without the qualifier.
		if !strings.Contains(got, "ip route 0.0.0.0/0 10.0.2.1 200") {
			t.Fatalf("#9501: the v4 DHCP default must still render without the unsafe interface %q:\n%s", bad, got)
		}
	}

	// A link-local gateway cannot resolve without an interface: the route is dropped.
	got := renderDHCP9501(DHCPRoute{Gateway: ll6, Interface: "ge0 x", IsIPv6: true})
	if strings.Contains(got, "fe80::1") {
		t.Fatalf("#9501: a link-local DHCP route with an unsafe interface must be dropped, not rendered:\n%s", got)
	}
}
