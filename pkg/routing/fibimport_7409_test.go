package routing

import (
	"errors"
	"net"
	"reflect"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// #7409 — kernel-learned route importer.
//
// The importer exists because the userspace dataplane FIB is built from
// config-derived sources only, so an FRR-installed (BGP/OSPF/IS-IS/RIP) or
// DHCP-learned route is invisible to the helper while the kernel routes it —
// and a transit packet toward such a destination either takes NoRoute and is
// reinjected to the kernel with no policy/session/NAT/screen, or is forwarded
// to a static default's next-hop instead of the learned one.
//
// These tests pin the import's SAFETY PROPERTIES, not just its happy path.
// Every rejection below is load-bearing: the whole reason this fix is safe to
// ship for a black-hole-class bug is that the importer can only ever add a
// forwarding path, never remove or redirect one.

func mustCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return n
}

// withRouteLister swaps the netlink seam for the duration of a test and
// restores it, so a failing case cannot leak a fake into its neighbours.
func withRouteLister(t *testing.T, fn func(int, *netlink.Route, uint64) ([]netlink.Route, error)) {
	t.Helper()
	prev := learnedRouteListFn
	learnedRouteListFn = fn
	t.Cleanup(func() { learnedRouteListFn = prev })
}

// staticLister serves a fixed route set for (family, table) and empty
// otherwise, so a test states exactly the kernel it is describing.
func staticLister(byKey map[[2]int][]netlink.Route) func(int, *netlink.Route, uint64) ([]netlink.Route, error) {
	return func(family int, filter *netlink.Route, _ uint64) ([]netlink.Route, error) {
		table := 0
		if filter != nil {
			table = filter.Table
		}
		return byKey[[2]int{family, table}], nil
	}
}

func v4Main(routes ...netlink.Route) map[[2]int][]netlink.Route {
	return map[[2]int][]netlink.Route{{netlink.FAMILY_V4, mainTableID}: routes}
}

// unicast builds a plain gateway-bearing unicast route, the shape every
// genuine learned route has.
func unicast(dst *net.IPNet, gw string, proto int) netlink.Route {
	return netlink.Route{
		Dst:      dst,
		Gw:       net.ParseIP(gw),
		Type:     unix.RTN_UNICAST,
		Protocol: netlink.RouteProtocol(proto),
	}
}

// A BGP-learned prefix with a next-hop is the canonical thing the helper FIB
// is missing today. RED on revert: drop RTPROT_BGP from learnedRouteProtocols
// and this route stops being imported.
func TestImportAdoptsBGPLearnedRoute(t *testing.T) {
	withRouteLister(t, staticLister(v4Main(
		unicast(mustCIDR(t, "10.20.30.0/24"), "192.0.2.1", unix.RTPROT_BGP),
	)))

	got, err := ImportLearnedRoutes([]int{mainTableID})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 imported route, got %d: %+v", len(got), got)
	}
	if got[0].Destination != "10.20.30.0/24" {
		t.Errorf("destination = %q, want 10.20.30.0/24", got[0].Destination)
	}
	if !reflect.DeepEqual(got[0].NextHops, []string{"192.0.2.1"}) {
		t.Errorf("next-hops = %v, want [192.0.2.1]", got[0].NextHops)
	}
	if !reflect.DeepEqual(got[0].NextHopWeights, []uint32{1}) {
		t.Errorf("next-hop weights = %v, want [1] for a single path", got[0].NextHopWeights)
	}
	if got[0].Protocol != "bgp" {
		t.Errorf("protocol = %q, want bgp", got[0].Protocol)
	}
}

func TestImportCarriesKernelMetrics11388(t *testing.T) {
	lower := unicast(mustCIDR(t, "198.51.100.0/24"), "192.0.2.2", unix.RTPROT_DHCP)
	lower.Priority = 100
	higher := unicast(mustCIDR(t, "198.51.100.0/24"), "192.0.2.10", unix.RTPROT_DHCP)
	higher.Priority = 200
	withRouteLister(t, staticLister(v4Main(lower, higher)))

	got, err := ImportLearnedRoutes([]int{mainTableID})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	metrics := make(map[string]int, len(got))
	for _, route := range got {
		metrics[route.NextHops[0]] = route.Metric
	}
	if len(metrics) != 2 || metrics["192.0.2.2"] != 100 || metrics["192.0.2.10"] != 200 {
		t.Fatalf("imported route metrics = %v, want .2:100 and .10:200", metrics)
	}
}

// THE DEFAULT-ROUTE NORMALISATION. The kernel may report 0.0.0.0/0 and ::/0
// as a route with NO RTA_DST, i.e. Dst == nil — pkg/routing routeToEntry
// already carries that same normalisation for the display path. A DHCP-learned
// default is the single most important route this import exists to capture and
// the one most likely to arrive in that shape, so a nil Dst must become the
// family's default prefix, never a skip.
//
// RED on revert: make learnedRouteDestination return ok=false for a nil Dst
// and both sub-cases below vanish from the import.
func TestImportNormalisesNilDstDefaultRoute(t *testing.T) {
	withRouteLister(t, staticLister(map[[2]int][]netlink.Route{
		{netlink.FAMILY_V4, mainTableID}: {{
			Dst: nil, Gw: net.ParseIP("192.0.2.254"),
			Type: unix.RTN_UNICAST, Protocol: netlink.RouteProtocol(rtprotZStatic),
		}},
		{netlink.FAMILY_V6, mainTableID}: {{
			Dst: nil, Gw: net.ParseIP("2001:db8::1"),
			Type: unix.RTN_UNICAST, Protocol: netlink.RouteProtocol(rtprotZStatic),
		}},
	}))

	got, err := ImportLearnedRoutes([]int{mainTableID})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 imported routes, got %d: %+v", len(got), got)
	}
	byFamily := map[int]string{}
	for _, lr := range got {
		byFamily[lr.Family] = lr.Destination
	}
	if byFamily[netlink.FAMILY_V4] != "0.0.0.0/0" {
		t.Errorf("v4 default = %q, want 0.0.0.0/0", byFamily[netlink.FAMILY_V4])
	}
	if byFamily[netlink.FAMILY_V6] != "::/0" {
		t.Errorf("v6 default = %q, want ::/0", byFamily[netlink.FAMILY_V6])
	}
}

// The no-dynamic-protocol-needed half of the exposure: FRR staticd (196)
// carries the DHCP-learned AD-200 default AND its RFC 3442 classless routes.
// A box with no BGP/OSPF stanza at all is still exposed through this path,
// which is why a "refuse to arm when a routing protocol is configured" gate
// would have closed nothing.
func TestImportAdoptsFRRStaticdDHCPRoutes(t *testing.T) {
	withRouteLister(t, staticLister(v4Main(
		unicast(mustCIDR(t, "0.0.0.0/0"), "198.51.100.1", rtprotZStatic),
		unicast(mustCIDR(t, "203.0.113.0/24"), "198.51.100.1", rtprotZStatic),
	)))

	got, err := ImportLearnedRoutes([]int{mainTableID})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 imported routes, got %d: %+v", len(got), got)
	}
	for _, lr := range got {
		if lr.Protocol != "static" {
			t.Errorf("%s protocol = %q, want static", lr.Destination, lr.Protocol)
		}
	}
}

// SAFETY PROPERTY: the importer can only ever ADD A FORWARDING PATH.
//
// Non-unicast route types are never adopted, so no kernel discard/blackhole/
// unreachable route can be published into the helper FIB — the importer can
// therefore never convert a working forwarding path into a drop. That is what
// makes this fix safe to ship for a bug whose bad outcome is a black-hole.
//
// ONE VARIABLE. Each route below is byte-identical to the BGP route that
// TestImportAdoptsBGPLearnedRoute proves IS imported — same gateway, same
// protocol, same prefix shape — and differs ONLY in Type. So a rejection here
// can only be attributable to the unicast gate.
//
// (An earlier version of this test used realistic gateway-LESS blackhole
// routes and passed for the wrong reason: they were already rejected by the
// gateway-less rule, so removing the unicast gate entirely left the test
// GREEN. Measured, not assumed.)
//
// RED on revert: delete importableRoute's `r.Type != unix.RTN_UNICAST` gate.
func TestImportRejectsNonUnicastEvenWhenOtherwiseImportable(t *testing.T) {
	for _, tc := range []struct {
		name     string
		routeTyp int
	}{
		{"blackhole", unix.RTN_BLACKHOLE},
		{"unreachable", unix.RTN_UNREACHABLE},
		{"prohibit", unix.RTN_PROHIBIT},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := unicast(mustCIDR(t, "10.20.30.0/24"), "192.0.2.1", unix.RTPROT_BGP)
			r.Type = tc.routeTyp // the ONLY difference from the imported case
			withRouteLister(t, staticLister(v4Main(r)))

			got, err := ImportLearnedRoutes([]int{mainTableID})
			if err != nil {
				t.Fatalf("import: %v", err)
			}
			if len(got) != 0 {
				t.Fatalf("a %s route must never be imported, got %+v", tc.name, got)
			}
		})
	}
}

// The HA inactive-RG blackhole route, in its REAL shape.
//
// pkg/daemon installs these as RTN_BLACKHOLE with the 4242 priority sentinel
// and no gateway, so BOTH the unicast gate and the gateway-less rule exclude
// it — deliberately belt-and-braces, since adopting it would double-enforce an
// HA ownership decision the helper already makes for itself via its
// HAInactive disposition. This test pins the realistic input; the unicast
// PREDICATE is bound by the one-variable test above.
func TestImportRejectsHABlackholeSentinelRoute(t *testing.T) {
	withRouteLister(t, staticLister(v4Main(netlink.Route{
		Dst:      mustCIDR(t, "10.0.61.0/24"),
		Type:     unix.RTN_BLACKHOLE,
		Priority: 4242,
		Protocol: netlink.RouteProtocol(unix.RTPROT_BOOT),
	})))

	got, err := ImportLearnedRoutes([]int{mainTableID})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("the HA blackhole sentinel must never be imported, got %+v", got)
	}
}

// An ICMP-redirect-installed route is not a routing decision this firewall
// should adopt into its fast path.
func TestImportRejectsRedirectProtocol(t *testing.T) {
	withRouteLister(t, staticLister(v4Main(
		unicast(mustCIDR(t, "10.9.0.0/16"), "192.0.2.9", unix.RTPROT_REDIRECT),
	)))

	got, err := ImportLearnedRoutes([]int{mainTableID})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("RTPROT_REDIRECT must not be imported, got %+v", got)
	}
}

// A gateway-less route is directly connected, and connected prefixes already
// reach the helper FIB from the interface snapshot. Rejecting them keeps the
// importer clear of the Rust side's bare-gateway ifindex inference, where a
// wrongly-shaped connected route would resolve to the wrong egress.
//
// This is also what keeps the host's own `proto kernel scope link` routes out
// of a snapshot when the import runs on a real box.
func TestImportRejectsGatewaylessRoute(t *testing.T) {
	withRouteLister(t, staticLister(v4Main(
		netlink.Route{
			Dst: mustCIDR(t, "10.0.100.0/24"), Gw: nil,
			Type: unix.RTN_UNICAST, Protocol: netlink.RouteProtocol(unix.RTPROT_KERNEL),
		},
	)))

	got, err := ImportLearnedRoutes([]int{mainTableID})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("a gateway-less route must not be imported, got %+v", got)
	}
}

// ECMP is imported WHOLE. Every leg lands, in kernel order.
func TestImportAdoptsEveryECMPLeg(t *testing.T) {
	withRouteLister(t, staticLister(v4Main(
		netlink.Route{
			Dst:      mustCIDR(t, "10.50.0.0/16"),
			Type:     unix.RTN_UNICAST,
			Protocol: netlink.RouteProtocol(unix.RTPROT_OSPF),
			MultiPath: []*netlink.NexthopInfo{
				{Gw: net.ParseIP("192.0.2.1"), Hops: 0},
				{Gw: net.ParseIP("192.0.2.2"), Hops: 3},
			},
		},
	)))

	got, err := ImportLearnedRoutes([]int{mainTableID})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 route, got %d: %+v", len(got), got)
	}
	want := []string{"192.0.2.1", "192.0.2.2"}
	if !reflect.DeepEqual(got[0].NextHops, want) {
		t.Errorf("next-hops = %v, want %v", got[0].NextHops, want)
	}
	if !reflect.DeepEqual(got[0].NextHopWeights, []uint32{1, 4}) {
		t.Errorf("next-hop weights = %v, want [1 4] in kernel leg order", got[0].NextHopWeights)
	}
}

// ...OR NOT AT ALL. Publishing a SUBSET of an ECMP set is the same defect
// class as the #1827 half-override the ip-monitoring overlay is built to make
// impossible: traffic would be pinned to the legs that happened to parse.
//
// RED on revert: make learnedRouteNextHops skip a gateway-less leg instead of
// returning ok=false, and this route is imported with one leg.
func TestImportRejectsPartialECMPRatherThanHalfImporting(t *testing.T) {
	withRouteLister(t, staticLister(v4Main(
		netlink.Route{
			Dst:      mustCIDR(t, "10.60.0.0/16"),
			Type:     unix.RTN_UNICAST,
			Protocol: netlink.RouteProtocol(unix.RTPROT_OSPF),
			MultiPath: []*netlink.NexthopInfo{
				{Gw: net.ParseIP("192.0.2.1")},
				{Gw: nil}, // an interface-only leg
			},
		},
	)))

	got, err := ImportLearnedRoutes([]int{mainTableID})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("a partial ECMP set must be rejected whole, got %+v", got)
	}
}

// The management VRF is not reinject-reachable: a packet reinjected on
// xpf-usp0 resolves in main and can never reach table 999. Importing its
// DHCP routes would hand the transit fast path a route to the management
// gateway that the kernel path would never have used.
func TestImportExcludesManagementVRFTable(t *testing.T) {
	dumped := map[int]bool{}
	withRouteLister(t, func(family int, filter *netlink.Route, _ uint64) ([]netlink.Route, error) {
		if filter != nil {
			dumped[filter.Table] = true
		}
		return []netlink.Route{
			unicast(mustCIDR(t, "0.0.0.0/0"), "10.99.0.1", unix.RTPROT_DHCP),
		}, nil
	})

	got, err := ImportLearnedRoutes([]int{mainTableID, mgmtVRFTableID})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if dumped[mgmtVRFTableID] {
		t.Error("table 999 must never be dumped at all")
	}
	for _, lr := range got {
		if lr.TableID == mgmtVRFTableID {
			t.Errorf("table 999 route leaked into the import: %+v", lr)
		}
	}
}

// FAIL CLOSED. A netlink failure aborts the whole import with no partial
// result — the snapshot builder cannot distinguish "this prefix has no
// learned route" from "this family's dump failed", and would otherwise
// publish a FIB silently missing a subset of destinations while the kernel
// keeps routing them. Mirrors the #3772 M9 contract on the ip-rule side.
//
// Note this is the OPPOSITE of the display path's #5125 partial-result
// contract in routes.go: `show route` renders what it can because a missing
// row misleads a human, whereas a missing FIB entry misdirects a packet.
func TestImportFailsClosedOnNetlinkError(t *testing.T) {
	sentinel := errors.New("netlink boom")
	withRouteLister(t, func(family int, filter *netlink.Route, _ uint64) ([]netlink.Route, error) {
		if family == netlink.FAMILY_V6 {
			return nil, sentinel
		}
		return []netlink.Route{
			unicast(mustCIDR(t, "10.20.30.0/24"), "192.0.2.1", unix.RTPROT_BGP),
		}, nil
	})

	got, err := ImportLearnedRoutes([]int{mainTableID})
	if !errors.Is(err, sentinel) {
		t.Fatalf("error = %v, want it to wrap %v", err, sentinel)
	}
	if got != nil {
		t.Fatalf("a failed import must return NO partial result, got %+v", got)
	}
}

// The dumped table set is bounded by what the config names, so a table xpf
// does not own can never reach the fast path.
func TestLearnedRouteTableIDsIsBoundedAndDeduped(t *testing.T) {
	got := LearnedRouteTableIDs([]int{100, 100, mgmtVRFTableID, 0, -1, mainTableID, 200})
	want := []int{mainTableID, 100, 200}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("table ids = %v, want %v", got, want)
	}
}
