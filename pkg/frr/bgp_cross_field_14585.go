package frr

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// #14585 render belt: the strict gate (pkg/config
// validateBGPCrossFieldStrict) rejects these combinations at commit, but a
// leniently-loaded or peer-synced config (#1960) can still carry them. Omit
// each line FRR would refuse — with a warning — rather than failing the
// whole frr-reload.
//
// #15016 extends the same belt to OSPF virtual links: a VL whose effective
// transit is the backbone or a stub/NSSA area is omitted, and valid VLs
// render in a trailing `router ospf` stanza after interface activation.

func bgpNeighborIBGP14585(routerAS uint32, n *config.BGPNeighbor) bool {
	return config.BGPNeighborIsIBGP14585(routerAS, n)
}

func renderBGPRouteReflectorClient14585(b *strings.Builder, routerAS uint32, n *config.BGPNeighbor) {
	if !n.RouteReflectorClient {
		return
	}
	if n.PeerAS != 0 && !bgpNeighborIBGP14585(routerAS, n) {
		slog.Warn("frr: omitting route-reflector-client for an eBGP neighbor (#14585)",
			"neighbor", sanitizeFRRValue(n.Address), "peer_as", n.PeerAS, "router_as", routerAS,
			"local_as", config.BGPNeighborEffectiveLocalAS15663(routerAS, n))
		return
	}
	fmt.Fprintf(b, "  neighbor %s route-reflector-client\n", n.Address)
}

// #15202: Junos `remove-private` strips the private-AS run at the head
// (most-recently-prepended end) of the advertised AS path even when a
// public AS follows it. The bare FRR `remove-private-AS` strips only an
// all-private path, leaking the private ASNs of a mixed
// private-then-public path upstream; `remove-private-AS all` is the
// Junos-equivalent spelling. Residual difference: FRR `all` also
// strips a private run that is not at the head of the path, and Junos
// withholds stripping when the path contains the eBGP peer's own AS —
// neither is expressible in FRR's CLI.
func renderBGPRemovePrivate14585(b *strings.Builder, routerAS uint32, n *config.BGPNeighbor) {
	if !n.RemovePrivateAS {
		return
	}
	if bgpNeighborIBGP14585(routerAS, n) {
		slog.Warn("frr: omitting remove-private-AS for an iBGP neighbor (#14585)",
			"neighbor", sanitizeFRRValue(n.Address), "peer_as", n.PeerAS, "router_as", routerAS,
			"local_as", config.BGPNeighborEffectiveLocalAS15663(routerAS, n))
		return
	}
	fmt.Fprintf(b, "  neighbor %s remove-private-AS all\n", n.Address)
}

// isBackboneArea14585 reports whether id spells area 0 in any form
// ValidateOSPFArea accepts ("0", "0.0.0.0", ...).
func isBackboneArea14585(id string) bool {
	return ospfAreaIdentity11400(id) == "0"
}
