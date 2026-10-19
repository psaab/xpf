package config

import (
	"fmt"
	"sort"
)

// bgpDampeningEffective14585 resolves the renderer's dampening defaults
// (pkg/frr protocols_render.go): unset fields fall back to 15/750/2000/60.
func bgpDampeningEffective14585(bgp *BGPConfig) (halfLife, reuse, suppress, maxSuppress int) {
	halfLife = bgp.DampeningHalfLife
	if halfLife == 0 {
		halfLife = 15
	}
	reuse = bgp.DampeningReuse
	if reuse == 0 {
		reuse = 750
	}
	suppress = bgp.DampeningSuppress
	if suppress == 0 {
		suppress = 2000
	}
	maxSuppress = bgp.DampeningMaxSuppress
	if maxSuppress == 0 {
		maxSuppress = 60
	}
	return halfLife, reuse, suppress, maxSuppress
}

// BGPNeighborIsIBGP14585 reports whether the neighbor is internal: its
// effective peer-as equals the router AS. PeerAS 0 is the missing-peer-as
// case owned by validateBGPNeighborPeerASStrict, not an iBGP peer.
func BGPNeighborIsIBGP14585(routerAS uint32, n *BGPNeighbor) bool {
	return n != nil && routerAS != 0 && n.PeerAS == routerAS
}

// validateBGPCrossFieldStrict rejects BGP/OSPF knob combinations that FRR
// refuses at reload time (#14585, residual of #9012 which typed only the
// per-value numerics). Verified against real bgpd via frr-reload:
//
//   - `neighbor X local-as <own AS>` -> "% Cannot have local-as same as BGP AS number"
//   - `neighbor X route-reflector-client` on an eBGP peer -> "% Invalid command. Not an internal neighbor"
//   - `neighbor X remove-private-AS` on an iBGP peer -> "% remove-private-AS cannot be configured for IBGP peers"
//   - `bgp dampening` with suppress <= reuse -> line silently not installed
//   - OSPF/OSPFv3 backbone (area 0) `area-type stub|nssa` -> Junos and FRR
//     both require the backbone to remain a normal area.
//
// Each bad line fails (or silently drops from) every later frr-reload, so a
// commit-check-clean config was not FRR-loadable. Strict on commit /
// commit-check; lenient on load / peer-sync (opts.lenientBGPCrossField14585,
// #1960) where the render path omits each refused line.
// VirtualLinkTransitInvalid15016 reports why a virtual link's effective
// transit area is FRR-refused (#15016 A12-04), or "" if it is valid.
// The backbone itself cannot be a transit area, and a stub/NSSA area
// cannot carry a virtual link. Area identity is spelling-normalized so
// "0", "0.0.0.0" etc. compare equal. An unknown transit area (no area
// stanza) has no known type and is not refused here — only backbone
// identity, which needs no lookup, is refused in that case.
func VirtualLinkTransitInvalid15016(ospf *OSPFConfig, vl *OSPFVirtualLink) string {
	if ospf == nil || vl == nil {
		return ""
	}
	if ospfAreaIdentity11400(vl.TransitArea) == "0" {
		return "backbone"
	}
	for _, a := range ospf.Areas {
		if a == nil {
			continue
		}
		if ospfAreaIdentity11400(a.ID) == ospfAreaIdentity11400(vl.TransitArea) &&
			(a.AreaType == "stub" || a.AreaType == "nssa") {
			return a.AreaType
		}
	}
	return ""
}

func validateBGPCrossFieldStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}

	checkBGP := func(scope string, bgp *BGPConfig) error {
		if bgp == nil {
			return nil
		}
		if bgp.Dampening {
			_, reuse, suppress, _ := bgpDampeningEffective14585(bgp)
			if suppress <= reuse {
				return fmt.Errorf("%sprotocols bgp damping: suppress threshold %d must be "+
					"greater than reuse threshold %d — FRR bgpd does not install a dampening "+
					"line with suppress <= reuse, so route damping would silently not run; "+
					"raise suppress or lower reuse", scope, suppress, reuse)
			}
		}
		neighbors := append([]*BGPNeighbor(nil), bgp.Neighbors...)
		sort.SliceStable(neighbors, func(i, j int) bool {
			if neighbors[i] == nil {
				return neighbors[j] != nil
			}
			if neighbors[j] == nil {
				return false
			}
			return neighbors[i].Address < neighbors[j].Address
		})
		for _, n := range neighbors {
			if n == nil {
				continue
			}
			detail := fmt.Sprintf("%sprotocols bgp neighbor %s", scope, n.Address)
			if n.GroupName != "" {
				detail = fmt.Sprintf("%sprotocols bgp group %s neighbor %s", scope, n.GroupName, n.Address)
			}
			if bgp.LocalAS != 0 && n.LocalAS != 0 && n.LocalAS == bgp.LocalAS {
				return fmt.Errorf("%s: local-as %d equals the router AS %d — FRR bgpd "+
					"rejects `neighbor %s local-as %d` (\"Cannot have local-as same as BGP AS "+
					"number\"), failing the frr-reload; remove local-as or set a different AS",
					detail, n.LocalAS, bgp.LocalAS, n.Address, n.LocalAS)
			}
			ibgp := BGPNeighborIsIBGP14585(bgp.LocalAS, n)
			if n.RouteReflectorClient && n.PeerAS != 0 && !ibgp {
				return fmt.Errorf("%s: route-reflector-client is only valid for iBGP peers "+
					"(peer-as %d != local-as %d) — FRR bgpd rejects it for external neighbors "+
					"(\"Not an internal neighbor\"), failing the frr-reload; remove "+
					"route-reflector-client or fix peer-as", detail, n.PeerAS, bgp.LocalAS)
			}
			if n.RemovePrivateAS && ibgp {
				return fmt.Errorf("%s: remove-private is only valid for eBGP peers "+
					"(peer-as %d == local-as %d, iBGP) — FRR bgpd rejects remove-private-AS "+
					"for IBGP peers, failing the frr-reload; remove remove-private (Junos "+
					"treats it as a no-op for iBGP)", detail, n.PeerAS, bgp.LocalAS)
			}
		}
		return nil
	}

	checkBackbone := func(scope, proto string, id, areaType string) error {
		if areaType == "" || ospfAreaIdentity11400(id) != "0" {
			return nil
		}
		return fmt.Errorf("%sprotocols %s area %s: area-type %s is not allowed for the "+
			"backbone area (area 0) — the backbone must remain a normal area and FRR "+
			"refuses a stub/nssa backbone, failing the frr-reload; remove area-type or "+
			"move it to a non-backbone area", scope, proto, id, areaType)
	}

	checkScope := func(scope string, ospf *OSPFConfig, ospfv3 *OSPFv3Config, bgp *BGPConfig) error {
		if err := checkBGP(scope, bgp); err != nil {
			return err
		}
		if ospf != nil {
			for _, area := range ospf.Areas {
				if area == nil {
					continue
				}
				if err := checkBackbone(scope, "ospf", area.ID, area.AreaType); err != nil {
					return err
				}
				for _, vl := range area.VirtualLinks {
					if vl == nil {
						continue
					}
					switch reason := VirtualLinkTransitInvalid15016(ospf, vl); reason {
					case "":
					case "backbone":
						return fmt.Errorf("%sprotocols ospf area %s virtual-link %s: transit area %s is the backbone — a virtual link must transit a non-backbone normal area to reach the backbone and FRR refuses a backbone transit area, failing the frr-reload; move the virtual-link under a normal transit area or set transit-area to one", scope, area.ID, vl.NeighborID, vl.TransitArea)
					default:
						return fmt.Errorf("%sprotocols ospf area %s virtual-link %s: transit area %s is a %s area — a virtual link cannot transit a stub or NSSA area and FRR refuses it, failing the frr-reload; use a normal transit area", scope, area.ID, vl.NeighborID, vl.TransitArea, reason)
					}
				}
			}
		}
		if ospfv3 != nil {
			for _, area := range ospfv3.Areas {
				if area == nil {
					continue
				}
				if err := checkBackbone(scope, "ospf3", area.ID, area.AreaType); err != nil {
					return err
				}
			}
		}
		return nil
	}

	if err := checkScope("", cfg.Protocols.OSPF, cfg.Protocols.OSPFv3, cfg.Protocols.BGP); err != nil {
		return err
	}
	for _, ri := range cfg.RoutingInstances {
		if ri == nil {
			continue
		}
		scope := fmt.Sprintf("routing-instance %s ", ri.Name)
		if err := checkScope(scope, ri.OSPF, ri.OSPFv3, ri.BGP); err != nil {
			return err
		}
	}
	return nil
}
