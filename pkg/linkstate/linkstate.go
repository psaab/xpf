// Package linkstate is the single source for the carrier-state read:
// whether a kernel link's operational state counts as "up" (#17132).
//
// Before #17132 the predicate lived in three byte-identical copies —
// pkg/cluster.LinkAttrsUp, pkg/routing's linkAttrsUp, and pkg/vrrp's
// linkAttrsUp — and #2070 already had to fix it in lockstep in more than
// one producer. It lives in this leaf (zero xpf imports) so cluster,
// routing, vrrp, daemon, cli, and grpcapi all read the same verdict.
package linkstate

import (
	"net"

	"github.com/vishvananda/netlink"
)

// Up reports whether a link is operationally up.
//
// Carrier health must NOT be decided from the administrative IFF_UP flag
// (net.FlagUp): xpfd admin-ups ALL managed interfaces, so IFF_UP stays set
// whenever the interface is admin-up — including when the cable is pulled.
// A carrier-down link keeps IFF_UP set while OperState transitions to
// OperDown/OperLowerLayerDown. Decide from the operational state
// (IFLA_OPERSTATE):
//   - OperUp                 -> up.
//   - OperUnknown            -> fall back to the admin flag (common on
//     virtual devices and 802.1Q VLAN sub-interfaces that report no
//     independent carrier state).
//   - OperDown / lower-layer-down / anything else -> down.
func Up(attrs *netlink.LinkAttrs) bool {
	switch attrs.OperState {
	case netlink.OperUp:
		return true
	case netlink.OperUnknown:
		return attrs.Flags&net.FlagUp != 0
	default:
		return false
	}
}
