package frr

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// injectedPrefix6795 is the shape the defect permits: a first operand FRR
// accepts, a newline, then a statement the operator never wrote.
const injectedPrefix6795 = "10.0.0.0/8\nip route 0.0.0.0/0 Null0"

func staticRoute6795(dest string, nh config.NextHopEntry) *config.StaticRoute {
	return &config.StaticRoute{Destination: dest, NextHops: []config.NextHopEntry{nh}}
}

// TestMalformedStaticRouteOperandsNeverReachFRRConf6795 is the render-side belt
// on the three raw operands of `ip route`: destination, gateway, interface.
//
// A malformed value fails the WHOLE frr-reload — one vtysh add-batch exits
// non-zero on any CMD_WARNING_CONFIG_FAILED — so a single bad route takes every
// other route on the box with it. A value carrying whitespace additionally
// splits into extra operands or an extra statement.
//
// Each case asserts what the render BECAME, and each is paired with a
// legitimate route in the same call that must still render — an absence check
// alone passes against a renderer that emits nothing.
func TestMalformedStaticRouteOperandsNeverReachFRRConf6795(t *testing.T) {
	m := &Manager{}
	good := config.NextHopEntry{Address: "10.0.0.1"}

	cases := []struct {
		name  string
		route *config.StaticRoute
		// absent is a substring that must NOT appear in the render.
		absent string
	}{
		{
			name:   "destination-with-injected-statement",
			route:  staticRoute6795(injectedPrefix6795, good),
			absent: "0.0.0.0/0 Null0",
		},
		{
			name:   "destination-unparseable",
			route:  staticRoute6795("not-a-prefix", good),
			absent: "not-a-prefix",
		},
		{
			name: "gateway-with-injected-statement",
			route: staticRoute6795("10.1.0.0/16", config.NextHopEntry{
				Address: "10.0.0.1\nip route 0.0.0.0/0 Null0",
			}),
			absent: "0.0.0.0/0 Null0",
		},
		{
			name: "gateway-unparseable",
			route: staticRoute6795("10.1.0.0/16", config.NextHopEntry{
				Address: "not-an-address",
			}),
			absent: "not-an-address",
		},
		{
			name: "interface-with-embedded-space",
			route: staticRoute6795("10.1.0.0/16", config.NextHopEntry{
				Interface: "eth0 Null0",
			}),
			absent: "eth0 Null0",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := m.generateStaticRouteInTable(tc.route, "", 0, nil, nil)
			if strings.Contains(out, tc.absent) {
				t.Fatalf("a malformed route operand reached frr.conf (%q):\n%s",
					tc.absent, out)
			}

			// Control on the SAME renderer: a legitimate route must still
			// render fully, so the assertion above is not passing because the
			// renderer emits nothing at all.
			ok := m.generateStaticRouteInTable(
				staticRoute6795("10.2.0.0/16", good), "", 0, nil, nil)
			if !strings.Contains(ok, "ip route 10.2.0.0/16 10.0.0.1") {
				t.Fatalf("the VALID route did not render, so this cell cannot "+
					"distinguish a working belt from a broken renderer:\n%s", ok)
			}
		})
	}
}

// TestEcmpDropsOnlyTheBadNextHop6795 pins the GRANULARITY, which is the part a
// coarser fix gets wrong.
//
// A `next-hop [ a b ]` ECMP list with one malformed member must still install
// the good ones. Dropping the whole route would turn a typo in one gateway into
// a blackhole for the prefix — and the no-next-hop path already renders NOTHING
// rather than a Null0 (#3872), so a whole-route drop is silently fail-wide.
func TestEcmpDropsOnlyTheBadNextHop6795(t *testing.T) {
	m := &Manager{}
	route := &config.StaticRoute{
		Destination: "10.1.0.0/16",
		NextHops: []config.NextHopEntry{
			{Address: "10.0.0.1"},
			{Address: "10.0.0.2\nip route 0.0.0.0/0 Null0"},
			{Address: "10.0.0.3"},
		},
	}
	out := m.generateStaticRouteInTable(route, "", 0, nil, nil)

	for _, want := range []string{"10.0.0.1", "10.0.0.3"} {
		if !strings.Contains(out, "ip route 10.1.0.0/16 "+want) {
			t.Fatalf("a VALID ECMP next-hop (%s) was dropped along with the bad "+
				"one — one malformed gateway must not blackhole the prefix:\n%s",
				want, out)
		}
	}
	if strings.Contains(out, "0.0.0.0/0 Null0") {
		t.Fatalf("the malformed ECMP next-hop injected a statement:\n%s", out)
	}
}

// TestGenerateRouteOperandBelt6795 covers the blackhole renderer. A
// generate-route emits `ip route <p> blackhole`, so a mangled operand is the one
// shape that could silently WIDEN what is dropped.
func TestGenerateRouteOperandBelt6795(t *testing.T) {
	var b strings.Builder
	renderGenerateRoutes(&b, &FullConfig{
		GenerateRoutes: []*config.GenerateRoute{
			{Prefix: "192.168.0.0/16"},
			{Prefix: injectedPrefix6795},
			{Prefix: "garbage"},
		},
	})
	out := b.String()

	if !strings.Contains(out, "ip route 192.168.0.0/16 blackhole") {
		t.Fatalf("the VALID generate-route did not render:\n%s", out)
	}
	if strings.Contains(out, "0.0.0.0/0 Null0") {
		t.Fatalf("a malformed generate-route prefix injected a statement:\n%s", out)
	}
	if strings.Contains(out, "garbage") {
		t.Fatalf("an unparseable generate-route prefix reached frr.conf:\n%s", out)
	}
}

// TestRouteOperandBeltAcceptsWhatCommitsToday6795 is the OVER-REJECTION control,
// and it is the assertion I trust least without it.
//
// Dropping a route is an outage, and a belt is most likely to be wrong in the
// too-strict direction — that is exactly how the first draft of #6796 failed,
// caught by a pre-existing test. These are the forms this tree renders today.
func TestRouteOperandBeltAcceptsWhatCommitsToday6795(t *testing.T) {
	for _, p := range []string{
		"0.0.0.0/0", "::/0", "10.0.0.0/8", "2001:db8::/32",
		"10.0.0.1", // a maskless host route
		"2001:db8::1",
	} {
		if !validFRRRoutePrefix(p) {
			t.Errorf("validFRRRoutePrefix(%q) = false — dropping a route form "+
				"that renders today is an outage", p)
		}
	}
	for _, g := range []string{"10.0.0.1", "fe80::1", "2001:db8::1"} {
		if !validFRRNextHopAddress(g) {
			t.Errorf("validFRRNextHopAddress(%q) = false", g)
		}
	}
	for _, i := range []string{"eth0", "ge-0-0-1", "ge-0-0-1.50", "reth0.80"} {
		if !validFRRInterfaceOperand(i) {
			t.Errorf("validFRRInterfaceOperand(%q) = false", i)
		}
	}

	// And the negatives, so the accepting rows above are not vacuous.
	for _, p := range []string{"", "10.0.0.0/8 extra", "not-a-prefix", "10.0.0.0/8\nx"} {
		if validFRRRoutePrefix(p) {
			t.Errorf("validFRRRoutePrefix(%q) = true", p)
		}
	}
	for _, g := range []string{"", "10.0.0.0/8", "10.0.0.1 extra", "10.0.0.1\nx"} {
		if validFRRNextHopAddress(g) {
			t.Errorf("validFRRNextHopAddress(%q) = true — a prefix or a "+
				"multi-token value in the gateway slot is a grammar error that "+
				"fails the frr-reload", g)
		}
	}
	for _, i := range []string{"", "eth0 x", "eth0\nx", "eth0\tx"} {
		if validFRRInterfaceOperand(i) {
			t.Errorf("validFRRInterfaceOperand(%q) = true", i)
		}
	}
}

// TestDHCPRouteOperandsAreStructurallySafe6795 covers ALL THREE operands of the
// DHCP-learned `ip route` line (#9501 corrected this record).
//
//   - gateway and destination: safe by construction. They come from netip.Addr
//     and netip.Prefix String(), which cannot contain whitespace. The fixture
//     below builds the gateway from a real netip.Addr so it exercises that shape.
//     The field is `string` at the FRR boundary, so no compile error would flag a
//     widening; this cell only checks the rendered shape.
//   - interface: NOT safe by construction. It is a plain string from
//     config.DHCPLeaseIfName, so it IS belted (dhcpRouteInterface, #9501);
//     TestDHCPRouteInterfaceOperandIsBelted_9501 holds the rows that can fail.
func TestDHCPRouteOperandsAreStructurallySafe6795(t *testing.T) {
	var b strings.Builder
	renderDHCPDefaults(&b, &FullConfig{
		DHCPRoutes: []DHCPRoute{{Gateway: netip.MustParseAddr("10.0.2.1").String(), Interface: "fxp0"}},
	})
	if !strings.Contains(b.String(), "ip route 0.0.0.0/0 10.0.2.1 fxp0 200") {
		t.Fatalf("the DHCP default route did not render as expected:\n%s", b.String())
	}
}
