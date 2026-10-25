package dataplane

import "github.com/vishvananda/netlink"

// #16582: the zone loop is a second writer of a GRE tunnel's admin
// state. The tunnel manager (ApplyTunnels, earlier in the same apply)
// already honours a keepalive-held-down tunnel via skipUp, but
// mapZoneInterface unconditionally LinkSetUp'd every zoned netdev, so
// any commit during a peer outage re-upped the dead tunnel and the
// runner (whose down edge was gated on state.Up) never took it down
// again.
//
// Two defences, mirroring the issue's two acceptance options:
//
//  1. This resolver: the daemon registers the routing manager's
//     TunnelHeldDown predicate at startup (the same injection shape
//     as SetProtectedInterfaceResolver — pkg/dataplane must not import
//     pkg/routing). mapZoneInterface consults it by LINUX netdev name
//     (the keepalive map is keyed by TunnelConfig.Name, which is the
//     Linux name, e.g. gr-0-0-0) before LinkSetUp. Nil (unit tests,
//     non-daemon embedders) preserves the pre-#16582 behaviour, and
//     the runner defence below still re-downs within one probe
//     interval.
//  2. The runner itself (pkg/routing): a dead tick at/past threshold
//     re-downs a link observed admin UP, so any writer this resolver
//     does not cover (a missed registration, an operator `ip link
//     set up`) is corrected on the next tick.
var tunnelHeldDownResolver func(linuxName string) bool

// SetTunnelHeldDownResolver registers the daemon's #16582 held-down
// provider. Called once at daemon startup. Passing nil restores the
// pre-#16582 behaviour.
func SetTunnelHeldDownResolver(fn func(linuxName string) bool) {
	tunnelHeldDownResolver = fn
}

// tunnelHeldDown reports whether keepalive currently holds the named
// LINUX netdev down, per the registered resolver. No resolver means
// not held (pre-#16582 behaviour for embedders without routing).
func tunnelHeldDown(linuxName string) bool {
	if tunnelHeldDownResolver == nil || linuxName == "" {
		return false
	}
	return tunnelHeldDownResolver(linuxName)
}

// zoneLinkSetUpSeam / zoneLinkSetDownSeam are the zone loop's admin
// state writes, behind seams so a test can drive the real
// programZoneMaps over a simulated host and assert whether the held-
// down tunnel was re-upped — without a privileged netdev (the
// #8122 lesson: an unseamed production write is unbindable).
var (
	zoneLinkSetUpSeam   = netlink.LinkSetUp
	zoneLinkSetDownSeam = netlink.LinkSetDown
)
