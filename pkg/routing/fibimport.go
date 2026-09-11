package routing

import (
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"sync"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/psaab/xpf/pkg/config"
)

// #7409 — the kernel-learned route importer.
//
// THE DEFECT. The userspace dataplane FIB is built by
// pkg/dataplane/userspace buildRouteSnapshots from four CONFIG-DERIVED
// sources only: config statics, connected prefixes, the ip-rule leak
// mirror, and the ip-monitoring overlay. Nothing reads the kernel FIB. But
// FRR installs BGP/OSPF/IS-IS/RIP routes, and DHCP-learned defaults plus
// RFC 3442 classless routes on NON-management interfaces, straight into the
// kernel's main table where the helper never sees them. The result is a
// divergence with two distinct failure modes, both reachable by a sender
// who picks the destination:
//
//   - No less-specific route covers the destination in the helper FIB
//     (typically: no config default) -> the lookup resolves NoRoute, the
//     frame is slow-path eligible (userspace-dp is_slow_path_eligible), and
//     it is REINJECTED to xpf-usp0. #7480 now adjudicates that reinject
//     against the computable zone pair, so a frame the operator's policy
//     denies is refused instead of delegated; what follows describes the
//     pre-#7480 behaviour and still describes a POLICY-PERMITTED frame,
//     which is delegated by design. The kernel then forwards it via the
//     learned route with no zone policy, no session, no NAT and no screen —
//     and nothing downstream catches it (there is no nftables `hook
//     forward` chain at all, ip_forward is force-enabled while armed, and
//     rp_filter is deliberately 0 on the TUN). That is the #7409 policy
//     bypass.
//   - A config default DOES cover it -> the helper forwards to the STATIC
//     default's next-hop instead of the learned one. Policy is evaluated,
//     so this is not a bypass, but the traffic silently takes the wrong
//     path. This second mode is the more common production symptom and the
//     one the shipped HA configs actually sit in.
//
// THE FIX. Import the kernel's learned routes so the helper FIB agrees with
// the FIB the reinject would have consulted. The importer is deliberately
// NARROW; every restriction below exists so that adding routes can never
// turn a working forwarding path into a drop or a hijack.
//
// WHAT THIS DOES NOT DO. It does not close the hole, it BOUNDS it — and
// #7437 has since narrowed that bound rather than removing it.
//
// Before #7437 the snapshot was pushed on operator commit and on
// ip-monitoring actuation only, with no kernel route-event subscription
// anywhere in the repo, so the window was "time to the next commit" —
// unbounded in practice on a quiet box with a flapping peer. #7437 adds
// the rtnetlink route listener (pkg/daemon/daemon_route_listener.go,
// modelled on the RTM_NEWNEIGH listener as this comment used to
// recommend), so a kernel route change now drives a republish on its own.
//
// THE WINDOW IS NARROWER, NOT GONE, and the distinction is load-bearing.
// The listener MARKS; the republish is coalesced (pkg/coalesce, debounce
// 1 s / throttle 3 s) because a per-event full snapshot replace under BGP
// churn would starve session installs on the shared control socket. So a
// route learned at t still reaches the helper FIB some seconds later, and
// on a fresh boot the first push still bounds it.
//
// Because a window survives, the NoRoute disposition MUST STILL stay
// slow-path eligible: dropping it instead — which #6664 proposes — would
// black-hole every learned destination for the width of that window, and
// on a fresh boot for the width of the first push. #7437 shrinks the
// exposure; it does not make #6664 safe by itself.

// LearnedRouteImportPreference is the Junos route preference stamped on
// every imported route.
//
// Under the gap-fill rule (ImportedRoutesForSnapshot never emits a route for
// a (table, family, prefix) the config-derived snapshot already carries) an
// imported route can never contend with a config route, so this value is
// never consulted in normal operation. It is set anyway, and set to a value
// WORSE than every config-derived preference (direct 0, static default 5),
// as defence in depth: if a future caller ever bypasses the gap-fill rule,
// the Rust FIB's #2390 tie-break — descending prefix length, then ASCENDING
// preference — still selects the operator's route over the imported one
// rather than letting insertion order decide. 200 mirrors the admin
// distance pkg/frr already renders DHCP-learned defaults at, so the number
// carries the same meaning it does everywhere else in the tree.
const LearnedRouteImportPreference = 200

// mgmtVRFTableID is the kernel routing table backing the management VRF
// (config.ManagementVRFTableID, #9622), named here to hard-exclude the table
// from the import.
//
// Management-interface (fxp*/fab*/em*) DHCP leases are NOT owned by FRR —
// pkg/daemon collectDHCPRoutes skips them and programs them directly via
// netlink into this table, stamped RTPROT_DHCP. A packet reinjected on
// xpf-usp0 resolves in main and can never reach table 999, so those routes
// are not part of the #7409 exposure. Importing them would be actively
// harmful: it would hand the transit fast path a route to the management
// gateway that the kernel path would never have used.
const mgmtVRFTableID = config.ManagementVRFTableID

// learnedRouteListFn is the netlink route enumerator, indirected so tests
// can drive the importer against synthetic kernel tables and assert a
// transient failure is surfaced rather than swallowed. Mirrors the
// ruleListFn seam in pkg/dataplane/userspace routes.go.
var learnedRouteListFn = netlink.RouteListFiltered

// LearnedRoute is one kernel-FIB unicast route that the userspace dataplane
// FIB does not derive from configuration.
//
// It is deliberately a flat value with no netlink types in it: the consumer
// (pkg/dataplane/userspace buildRouteSnapshots) turns it into a
// RouteSnapshot, and keeping netlink out of the boundary means the snapshot
// builder's tests do not need a kernel.
type LearnedRoute struct {
	// TableID is the kernel table the route was read from.
	TableID int
	// Family is netlink.FAMILY_V4 or netlink.FAMILY_V6.
	Family int
	// Destination is the route prefix in CIDR form. A kernel default route
	// carries a nil Dst; it is normalised here to "0.0.0.0/0" or "::/0" so
	// the consumer never has to special-case it. Getting this wrong would
	// drop exactly the DHCP-learned default that motivates the import.
	Destination string
	// NextHops holds every gateway leg, in kernel order. Always non-empty:
	// a route with no gateway is not imported (see importableRoute).
	NextHops []string
	// Protocol is the rtnetlink protocol name (rtProtoName) that admitted
	// the route — "bgp", "ospf", "isis", "rip", "static", "dhcp",
	// "connected". Diagnostic only; it does not reach the helper.
	Protocol string
}

// learnedRouteProtocols is the set of rtnetlink protocol values whose routes
// the importer will adopt.
//
// FRR's zebra stamps each FIB route with the originating daemon's RTPROT_*
// value via zebra2proto(); rtProtoName in routes.go is the SSOT for that
// mapping and this set is keyed on the same constants. RTPROT_ZSTATIC (196,
// FRR staticd) is the value that carries DHCP-learned defaults, RFC 3442
// classless routes, generate-routes and backup-router — i.e. the whole
// no-dynamic-protocol-needed half of the #7409 exposure.
//
// RTPROT_REDIRECT (1) is deliberately ABSENT: an ICMP-redirect-installed
// route is not a routing decision this firewall should adopt into its fast
// path.
var learnedRouteProtocols = map[int]bool{
	unix.RTPROT_KERNEL: true, // 2   — connected/local/kernel (also FRR)
	unix.RTPROT_BOOT:   true, // 3   — boot-time / legacy dhcp
	unix.RTPROT_STATIC: true, // 4   — manual `ip route`
	unix.RTPROT_DHCP:   true, // 16
	unix.RTPROT_BGP:    true, // 186
	unix.RTPROT_ISIS:   true, // 187
	unix.RTPROT_OSPF:   true, // 188
	unix.RTPROT_RIP:    true, // 189
	rtprotZStatic:      true, // 196 — FRR staticd
}

// ImportLearnedRoutes reads the given kernel routing tables and returns the
// unicast routes that are candidates for the userspace dataplane FIB.
//
// tableIDs is the caller's bounded table set — main plus each configured
// routing instance's table. The dump is scoped per table rather than
// enumerating every table on the box so an unrelated table (a foreign
// daemon's, or the local/broadcast tables) can never leak into the fast
// path.
//
// FAIL CLOSED. A netlink failure for ANY (table, family) pair aborts the
// whole import with an error and no partial result. This mirrors the #3772
// M9 contract the ip-rule enumeration already follows in
// pkg/dataplane/userspace routes.go: a PARTIAL learned-route set is worse
// than none, because the snapshot builder cannot tell "this prefix has no
// learned route" from "this family's dump failed", and would publish a FIB
// that silently omits a subset of destinations while the kernel keeps
// routing them. Note this differs from the DISPLAY path's #5125
// partial-result contract in routes.go: `show route` renders what it can
// because a missing row misleads a human, whereas a missing FIB entry
// misdirects a packet.
func ImportLearnedRoutes(tableIDs []int) ([]LearnedRoute, error) {
	var out []LearnedRoute
	names := newLinkNameCache()
	for _, tableID := range tableIDs {
		if tableID <= 0 || tableID == mgmtVRFTableID {
			continue
		}
		for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
			filter := &netlink.Route{Table: tableID}
			routes, err := learnedRouteListFn(family, filter, netlink.RT_FILTER_TABLE)
			if err != nil {
				return nil, fmt.Errorf(
					"learned-route import: %s route dump failed (table %d): %w",
					familyName(family), tableID, err)
			}
			for _, r := range routes {
				lr, ok := importableRouteScoped(r, family, tableID, names.lookup)
				if !ok {
					continue
				}
				out = append(out, lr)
			}
		}
	}
	return out, nil
}

// importableRoute decides whether one kernel route is adoptable and, if so,
// converts it.
//
// Every rejection below is a deliberate safety property, not a
// simplification:
//
//   - NON-UNICAST IS NEVER IMPORTED. Only RTN_UNICAST is adopted, so the
//     importer can only ever ADD A FORWARDING PATH — it can never install a
//     discard/blackhole/unreachable route into the helper FIB and so can
//     never convert a forwarding path into a drop. That is the property
//     that makes this fix safe to ship for a bug whose bad outcome is a
//     black-hole. It also excludes, by construction, the HA inactive-RG
//     blackhole routes pkg/daemon installs as RTN_BLACKHOLE with the 4242
//     priority sentinel — those encode an HA ownership decision the helper
//     already makes for itself via its own HAInactive disposition, and
//     adopting them would double-enforce it in the wrong layer. Dropping
//     kernel discard routes costs nothing: a packet that would have matched
//     one either matches a config route in the helper or takes NoRoute and
//     is reinjected, and the kernel then applies the discard itself.
//   - A GATEWAY-LESS ROUTE IS NEVER IMPORTED. A route with no next-hop
//     gateway is directly connected, and connected prefixes already reach
//     the helper FIB from the interface snapshot. Requiring a gateway loses
//     no real learned route (BGP/OSPF/IS-IS/RIP routes and DHCP defaults
//     all carry one) and keeps the importer clear of the Rust side's
//     bare-gateway ifindex inference, where a wrongly-shaped connected
//     route would resolve to the wrong egress.
//   - AN ECMP ROUTE IS IMPORTED WHOLE OR NOT AT ALL. Kernel multipath legs
//     live in RTA_MULTIPATH with route.Gw nil. Every leg with a gateway is
//     collected; if a leg is present but carries no gateway the route is
//     REJECTED rather than half-imported, because publishing a subset of an
//     ECMP set is the same defect class as the #1827 half-override the
//     overlay path is built to make impossible.
func importableRoute(r netlink.Route, family, tableID int) (LearnedRoute, bool) {
	return importableRouteScoped(r, family, tableID, newLinkNameCache().lookup)
}

// importableRouteScoped is importableRoute with the link-name resolver the
// #9512 scoping uses. ImportLearnedRoutes passes one cache for the whole dump,
// so a table of routes sharing a handful of links costs a handful of lookups.
func importableRouteScoped(r netlink.Route, family, tableID int, linkName func(int) (string, bool)) (LearnedRoute, bool) {
	if r.Type != unix.RTN_UNICAST {
		return LearnedRoute{}, false
	}
	if !learnedRouteProtocols[int(r.Protocol)] {
		return LearnedRoute{}, false
	}
	dst, ok := learnedRouteDestination(r, family)
	if !ok {
		return LearnedRoute{}, false
	}
	nextHops, ok, unscoped := learnedRouteNextHops(r, linkName)
	if unscoped != nil {
		warnUnscopedLinkLocalOnce(tableID, dst, unscoped, r)
		return LearnedRoute{}, false
	}
	if !ok || len(nextHops) == 0 {
		return LearnedRoute{}, false
	}
	return LearnedRoute{
		TableID:     tableID,
		Family:      family,
		Destination: dst,
		NextHops:    nextHops,
		Protocol:    rtProtoName(r.Protocol),
	}, true
}

// learnedRouteDestination renders the route prefix, normalising the kernel's
// nil-Dst representation of a default route.
//
// The kernel reports 0.0.0.0/0 and ::/0 as a route with no RTA_DST, so Dst
// is nil. That is precisely the DHCP-learned default this import exists to
// capture, so treating a nil Dst as "skip" would silently drop the single
// most important route in the set. Mirrors the same normalisation
// routeToEntry already does for the display path.
func learnedRouteDestination(r netlink.Route, family int) (string, bool) {
	if r.Dst != nil {
		return r.Dst.String(), true
	}
	if family == netlink.FAMILY_V6 {
		return "::/0", true
	}
	return "0.0.0.0/0", true
}

// learnedRouteNextHops collects every gateway leg of a route.
//
// Returns ok=false when the route is an ECMP set with at least one leg that
// carries no gateway — see the all-or-nothing rule on importableRoute.
//
// #9512: an IPv6 LINK-LOCAL gateway is meaningless without its link, and the
// wire form has a place for the link: `gateway@interface`, the form the
// configured-route path already emits and the helper already parses. Before
// #9512 the leg's LinkIndex was dropped. The helper then inferred the link by
// scanning connected prefixes, and every addressed interface contributes an
// fe80::/64, so the scan bound whichever interface came FIRST in the snapshot,
// an order-dependent wrong egress for every OSPFv3-learned route (RFC 5340
// makes the link-local address the next hop there).
//
// So each link-local leg is published as `gateway@<netdev>`, using the kernel
// name the helper resolves through its linux-name map. A link-local leg whose
// link cannot be named makes the whole route unimportable (unscoped is set):
// a scope-less link-local next hop has no correct binding to fall back to.
// This is deliberately NOT extended to GLOBAL (or IPv4) gateways. A scope-less
// global gateway is legitimate and correctly inferred from the connected
// prefix today, and refusing or rescoping it would change working routes.
func learnedRouteNextHops(r netlink.Route, linkName func(int) (string, bool)) (nhs []string, ok bool, unscoped net.IP) {
	if len(r.MultiPath) > 0 {
		nhs = make([]string, 0, len(r.MultiPath))
		for _, nh := range r.MultiPath {
			if nh == nil || nh.Gw == nil {
				return nil, false, nil
			}
			leg, scoped := scopeLearnedGateway(nh.Gw, nh.LinkIndex, linkName)
			if !scoped {
				return nil, false, nh.Gw
			}
			nhs = append(nhs, leg)
		}
		return nhs, true, nil
	}
	if r.Gw == nil {
		return nil, true, nil
	}
	leg, scoped := scopeLearnedGateway(r.Gw, r.LinkIndex, linkName)
	if !scoped {
		return nil, false, r.Gw
	}
	return []string{leg}, true, nil
}

// scopeLearnedGateway renders one gateway leg. Only an IPv6 link-local
// gateway is scoped; scoped=false means it is link-local and its link has no
// resolvable name.
func scopeLearnedGateway(gw net.IP, linkIndex int, linkName func(int) (string, bool)) (string, bool) {
	if gw.To4() != nil || !gw.IsLinkLocalUnicast() {
		return gw.String(), true
	}
	if linkIndex <= 0 || linkName == nil {
		return "", false
	}
	name, ok := linkName(linkIndex)
	if !ok || name == "" {
		return "", false
	}
	return gw.String() + "@" + name, true
}

// learnedRouteLinkNameFn resolves a kernel ifindex to its netdev name.
// Indirected so the importer cells can run without real links.
var learnedRouteLinkNameFn = func(index int) (string, error) {
	link, err := netlink.LinkByIndex(index)
	if err != nil {
		return "", err
	}
	return link.Attrs().Name, nil
}

// linkNameCache memoises learnedRouteLinkNameFn for one import, failures
// included, so a dump costs one lookup per distinct link.
type linkNameCache map[int]string

func newLinkNameCache() linkNameCache { return linkNameCache{} }

func (c linkNameCache) lookup(index int) (string, bool) {
	if name, seen := c[index]; seen {
		return name, name != ""
	}
	name, err := learnedRouteLinkNameFn(index)
	if err != nil {
		name = ""
	}
	c[index] = name
	return name, name != ""
}

// unscopedLinkLocalWarned dedups the refusal diagnostic. The importer runs on
// every route-snapshot build, so an unlogged refusal would be silent and a
// logged-every-time one would repeat at build rate. Keyed on the route and its
// leg, so a different failure warns again. It grows only with distinct refused
// routes.
var unscopedLinkLocalWarned sync.Map

func warnUnscopedLinkLocalOnce(tableID int, dst string, gw net.IP, r netlink.Route) {
	key := strconv.Itoa(tableID) + "|" + dst + "|" + gw.String()
	if _, loaded := unscopedLinkLocalWarned.LoadOrStore(key, true); loaded {
		return
	}
	slog.Warn("refusing a kernel-learned route: its IPv6 link-local next hop has no resolvable "+
		"interface, and a link-local next hop without one cannot be bound correctly (#9512)",
		"destination", dst, "table", tableID, "gateway", gw.String(),
		"protocol", rtProtoName(r.Protocol))
}

// LearnedRouteTableIDs returns the bounded kernel table set the importer
// should dump: the main table plus every configured routing-instance table.
//
// Passing an explicit set rather than enumerating the kernel's tables keeps
// a table xpf does not own out of the fast path.
func LearnedRouteTableIDs(instanceTableIDs []int) []int {
	out := make([]int, 0, len(instanceTableIDs)+1)
	out = append(out, mainTableID)
	seen := map[int]bool{mainTableID: true}
	for _, id := range instanceTableIDs {
		if id <= 0 || id == mgmtVRFTableID || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

// Compile-time assertion that the vendored netlink route enumerator keeps
// the signature the learnedRouteListFn indirection assumes. A drift in the
// library would otherwise surface only as a build break inside the snapshot
// path, or — if the seam were ever reassigned in a test — not at all.
var _ func(int, *netlink.Route, uint64) ([]netlink.Route, error) = learnedRouteListFn
