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

func bgpNeighborIBGP14585(routerAS uint32, n *config.BGPNeighbor) bool {
	return config.BGPNeighborIsIBGP14585(routerAS, n)
}

func renderBGPRouteReflectorClient14585(b *strings.Builder, routerAS uint32, n *config.BGPNeighbor) {
	if !n.RouteReflectorClient {
		return
	}
	if n.PeerAS != 0 && !bgpNeighborIBGP14585(routerAS, n) {
		slog.Warn("frr: omitting route-reflector-client for an eBGP neighbor (#14585)",
			"neighbor", sanitizeFRRValue(n.Address), "peer_as", n.PeerAS, "router_as", routerAS)
		return
	}
	fmt.Fprintf(b, "  neighbor %s route-reflector-client\n", n.Address)
}

func renderBGPRemovePrivate14585(b *strings.Builder, routerAS uint32, n *config.BGPNeighbor) {
	if !n.RemovePrivateAS {
		return
	}
	if bgpNeighborIBGP14585(routerAS, n) {
		slog.Warn("frr: omitting remove-private-AS for an iBGP neighbor (#14585)",
			"neighbor", sanitizeFRRValue(n.Address), "peer_as", n.PeerAS, "router_as", routerAS)
		return
	}
	fmt.Fprintf(b, "  neighbor %s remove-private-AS\n", n.Address)
}

// isBackboneArea14585 reports whether id spells area 0 in any form
// ValidateOSPFArea accepts ("0", "0.0.0.0", ...).
func isBackboneArea14585(id string) bool {
	return ospfAreaIdentity11400(id) == "0"
}
