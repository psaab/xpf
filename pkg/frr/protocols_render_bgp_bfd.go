// protocols_render_bgp_bfd.go holds the deferred BGP BFD-peer
// accumulation of generateProtocolsCluster15158 (#16125 verbatim
// extraction).
//
// The body below is the contiguous deferred accumulation block moved
// verbatim out of generateProtocolsCluster15158. It stays a separate
// step after every protocol stanza (not folded into the BGP stanza)
// so BFD peers are accumulated in the historical order into the
// shared accumulator owned by the caller.

package frr

import (
	"github.com/psaab/xpf/pkg/config"
)

// accumulateBGPBFDPeers16125 accumulates BFD peers for the
// renderable BGP neighbors into the shared bfd accumulator. Moved
// verbatim from generateProtocolsCluster15158 (#16125).
func accumulateBGPBFDPeers16125(bgp *config.BGPConfig, validNeighbors []*config.BGPNeighbor, vrfName string, bfd *bfdSection) {
	// Accumulate BFD peer entries for BGP neighbors with BFD enabled. The
	// in-scope vrfName is recorded with each peer so the single global
	// block carries the matching `vrf <name>` suffix (#2489). Emission is
	// deferred to bfdSection.render() — either here (local fallback) or by
	// the manager for the consolidated global block (#2550).
	if bgp != nil && bgp.LocalAS > 0 {
		// Accumulate BFD peers only for renderable (declared) neighbors
		// (#5518). A remote-as-0 neighbor skipped by the declaration loop must
		// not emit a `bfd` peer either — validNeighbors is the shared
		// exclusion set.
		for _, n := range validNeighbors {
			if n.BFD {
				// #14587: key multihop neighbors as multihop (with the
				// update-source as local-address) so the static peer is
				// the session bgpd uses, not an orphan single-hop peer.
				mh := bgpNeighborBFDMultihop14587(n, bgp.LocalAS)
				localAddr := ""
				if mh {
					localAddr = n.LocalAddress
				}
				bfd.addPeer(bfdPeer{
					address:      n.Address,
					vrfName:      vrfName,
					interval:     n.BFDInterval,
					multiplier:   n.BFDMultiplier,
					multihop:     mh,
					localAddress: localAddr,
				})
			}
		}
	}
}
