package dhcp

import (
	"net"
	"net/netip"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
)

// classlessACK builds a DHCPv4 ACK carrying yourIP 192.0.2.50/24 plus the
// supplied options (option 3 Router, option 121 Classless Static Route, or a
// raw legacy option 249). It reuses the leaseFromACKv4 acquire path.
func classlessACK(t *testing.T, opts ...dhcpv4.Option) *dhcpv4.DHCPv4 {
	t.Helper()
	mods := []dhcpv4.Modifier{
		dhcpv4.WithMessageType(dhcpv4.MessageTypeAck),
		dhcpv4.WithYourIP(net.ParseIP("192.0.2.50")),
		dhcpv4.WithNetmask(net.IPMask{255, 255, 255, 0}),
	}
	for _, o := range opts {
		mods = append(mods, dhcpv4.WithOption(o))
	}
	ack, err := dhcpv4.New(mods...)
	if err != nil {
		t.Fatalf("build DHCPv4 ACK: %v", err)
	}
	return ack
}

func mustCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("parse CIDR %q: %v", s, err)
	}
	return n
}

// TestLeaseFromACKv4ClasslessRoutesSupersedeOption3 locks in the #4118 fix:
// when a DHCPv4 ACK carries RFC 3442 option 121 (Classless Static Route), the
// client MUST install those routes and IGNORE the option-3 Router default. The
// 0.0.0.0/0 entry in option 121 supplies the default gateway; more-specific
// routes land on lease.ClasslessRoutes.
//
// RED-on-revert: without option-121 parsing the lease keeps the option-3
// gateway (198.51.100.99) and lease.ClasslessRoutes is empty — both assertions
// below fail.
func TestLeaseFromACKv4ClasslessRoutesSupersedeOption3(t *testing.T) {
	classless := dhcpv4.OptClasslessStaticRoute(
		// Default route via 192.0.2.1 (option-121 way to express option 3).
		&dhcpv4.Route{Dest: mustCIDR(t, "0.0.0.0/0"), Router: net.ParseIP("192.0.2.1")},
		// More-specific classless route: 10.20.0.0/16 via 192.0.2.9.
		&dhcpv4.Route{Dest: mustCIDR(t, "10.20.0.0/16"), Router: net.ParseIP("192.0.2.9")},
	)
	// A DIFFERENT option-3 gateway — must be ignored per RFC 3442.
	router := dhcpv4.OptRouter(net.ParseIP("198.51.100.99"))

	ack := classlessACK(t, router, classless)
	lease, err := leaseFromACKv4WithProtected("wan0", ack, nil)
	if err != nil {
		t.Fatalf("leaseFromACKv4: %v", err)
	}

	// Option 121 supersedes option 3: gateway is the 0.0.0.0/0 entry.
	wantGW := netip.MustParseAddr("192.0.2.1")
	if lease.Gateway != wantGW {
		t.Errorf("lease.Gateway = %v, want %v (option-121 default, NOT the option-3 gateway 198.51.100.99)",
			lease.Gateway, wantGW)
	}
	if lease.Gateway == netip.MustParseAddr("198.51.100.99") {
		t.Errorf("lease.Gateway is the option-3 gateway; option 3 must be ignored when option 121 present")
	}

	// The more-specific route is installed (not the 0.0.0.0/0 entry, which
	// became the gateway).
	want := []LeaseRoute{
		{Destination: netip.MustParsePrefix("10.20.0.0/16"), Gateway: netip.MustParseAddr("192.0.2.9")},
	}
	if len(lease.ClasslessRoutes) != len(want) {
		t.Fatalf("lease.ClasslessRoutes = %v, want %v", lease.ClasslessRoutes, want)
	}
	if lease.ClasslessRoutes[0] != want[0] {
		t.Errorf("classless route = %+v, want %+v", lease.ClasslessRoutes[0], want[0])
	}
}

// TestLeaseFromACKv4ClasslessOnlySpecificNoDefault verifies that option 121
// with only a more-specific route (no 0.0.0.0/0 entry) still suppresses option
// 3 per RFC 3442: the server chose not to provide a default, so no default is
// installed even though option 3 is present.
func TestLeaseFromACKv4ClasslessOnlySpecificNoDefault(t *testing.T) {
	classless := dhcpv4.OptClasslessStaticRoute(
		&dhcpv4.Route{Dest: mustCIDR(t, "172.16.0.0/12"), Router: net.ParseIP("192.0.2.7")},
	)
	router := dhcpv4.OptRouter(net.ParseIP("198.51.100.99"))

	ack := classlessACK(t, router, classless)
	lease, err := leaseFromACKv4WithProtected("wan0", ack, nil)
	if err != nil {
		t.Fatalf("leaseFromACKv4: %v", err)
	}
	if lease.Gateway.IsValid() {
		t.Errorf("lease.Gateway = %v, want invalid (option 3 ignored, no option-121 default entry)", lease.Gateway)
	}
	want := LeaseRoute{Destination: netip.MustParsePrefix("172.16.0.0/12"), Gateway: netip.MustParseAddr("192.0.2.7")}
	if len(lease.ClasslessRoutes) != 1 || lease.ClasslessRoutes[0] != want {
		t.Errorf("lease.ClasslessRoutes = %v, want [%+v]", lease.ClasslessRoutes, want)
	}
}

// TestLeaseFromACKv4Option3OnlyUnchanged verifies the fallback path is
// unchanged: with no option 121/249, the option-3 Router default is honored
// and no classless routes are recorded.
func TestLeaseFromACKv4Option3OnlyUnchanged(t *testing.T) {
	router := dhcpv4.OptRouter(net.ParseIP("192.0.2.1"))
	ack := classlessACK(t, router)
	lease, err := leaseFromACKv4WithProtected("wan0", ack, nil)
	if err != nil {
		t.Fatalf("leaseFromACKv4: %v", err)
	}
	if lease.Gateway != netip.MustParseAddr("192.0.2.1") {
		t.Errorf("lease.Gateway = %v, want 192.0.2.1 (option 3)", lease.Gateway)
	}
	if len(lease.ClasslessRoutes) != 0 {
		t.Errorf("lease.ClasslessRoutes = %v, want empty (no option 121/249)", lease.ClasslessRoutes)
	}
}

// TestLeaseFromACKv4LegacyOption249 verifies the legacy Microsoft option 249
// is decoded with the identical RFC 3442 encoding when option 121 is absent.
func TestLeaseFromACKv4LegacyOption249(t *testing.T) {
	// Encode the same routes into the raw option-249 value using the shared
	// RFC 3442 encoder.
	raw := dhcpv4.Routes{
		{Dest: mustCIDR(t, "0.0.0.0/0"), Router: net.ParseIP("192.0.2.1")},
		{Dest: mustCIDR(t, "10.0.0.0/8"), Router: net.ParseIP("192.0.2.5")},
	}.ToBytes()
	opt249 := dhcpv4.OptGeneric(dhcpv4.GenericOptionCode(249), raw)
	router := dhcpv4.OptRouter(net.ParseIP("198.51.100.99"))

	ack := classlessACK(t, router, opt249)
	lease, err := leaseFromACKv4WithProtected("wan0", ack, nil)
	if err != nil {
		t.Fatalf("leaseFromACKv4: %v", err)
	}
	if lease.Gateway != netip.MustParseAddr("192.0.2.1") {
		t.Errorf("lease.Gateway = %v, want 192.0.2.1 (option-249 default, option 3 ignored)", lease.Gateway)
	}
	want := LeaseRoute{Destination: netip.MustParsePrefix("10.0.0.0/8"), Gateway: netip.MustParseAddr("192.0.2.5")}
	if len(lease.ClasslessRoutes) != 1 || lease.ClasslessRoutes[0] != want {
		t.Errorf("lease.ClasslessRoutes = %v, want [%+v]", lease.ClasslessRoutes, want)
	}
}

// TestClasslessStaticRoutesEncoding pins the RFC 3442
// {mask-length, significant-prefix-octets, gateway} decode for a /24, /0, and
// /32 — the mask determines how many prefix octets are on the wire (3, 0, 4).
func TestClasslessStaticRoutesEncoding(t *testing.T) {
	classless := dhcpv4.OptClasslessStaticRoute(
		&dhcpv4.Route{Dest: mustCIDR(t, "10.20.30.0/24"), Router: net.ParseIP("192.0.2.2")},  // 3 prefix octets
		&dhcpv4.Route{Dest: mustCIDR(t, "0.0.0.0/0"), Router: net.ParseIP("192.0.2.1")},      // 0 prefix octets (default)
		&dhcpv4.Route{Dest: mustCIDR(t, "203.0.113.7/32"), Router: net.ParseIP("192.0.2.3")}, // 4 prefix octets (host)
	)
	ack := classlessACK(t, classless)

	routes, defGW, present := classlessStaticRoutes(ack)
	if !present {
		t.Fatal("classlessStaticRoutes reported not present")
	}
	if defGW != netip.MustParseAddr("192.0.2.1") {
		t.Errorf("default gateway = %v, want 192.0.2.1", defGW)
	}
	want := map[netip.Prefix]netip.Addr{
		netip.MustParsePrefix("10.20.30.0/24"):  netip.MustParseAddr("192.0.2.2"),
		netip.MustParsePrefix("203.0.113.7/32"): netip.MustParseAddr("192.0.2.3"),
	}
	if len(routes) != len(want) {
		t.Fatalf("routes = %v, want %d entries", routes, len(want))
	}
	for _, r := range routes {
		gw, ok := want[r.Destination]
		if !ok {
			t.Errorf("unexpected route destination %v", r.Destination)
			continue
		}
		if r.Gateway != gw {
			t.Errorf("route %v gateway = %v, want %v", r.Destination, r.Gateway, gw)
		}
	}
}
