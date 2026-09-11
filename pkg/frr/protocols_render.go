// protocols_render.go renders the FRR routing-protocol stanzas
// (OSPF, OSPFv3, BGP, RIP, IS-IS) for the default instance and each VRF.
//
// Split out of policy_render.go (#6424) as a pure code-motion refactor;
// the emitted frr.conf is byte-identical.
//
// Symbols:
//   - generateProtocols (OSPF/OSPFv3/BGP/RIP/ISIS)
package frr

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// generateProtocols generates FRR CLI config for OSPF, BGP, RIP, and IS-IS.
// If vrfName is non-empty, generates VRF-scoped commands.
// ecmpMaxPaths > 1 enables ECMP with the given maximum equal-cost paths.
// policyOptions is used to resolve export policy names to route-map references.
//
// BFD emission (#2550): when the optional `shared` accumulator is provided
// (the manager passes one section across the default instance AND every
// VRF), this function ONLY accumulates BFD profiles/peers into it and emits
// NO `bfd` block — the manager renders a single global block once. When no
// shared section is passed (direct callers / unit tests), it falls back to
// a function-local section emitted at the end, preserving the historical
// single-instance behavior byte-for-byte.
func (m *Manager) generateProtocols(ospf *config.OSPFConfig, ospfv3 *config.OSPFv3Config, bgp *config.BGPConfig, rip *config.RIPConfig, isis *config.ISISConfig, vrfName string, ecmpMaxPaths int, policyOptions *config.PolicyOptionsConfig, bgpAcceptDefault map[string]bool, shared ...*bfdSection) string {
	var b strings.Builder
	var bfd *bfdSection
	emitLocal := false
	if len(shared) > 0 && shared[0] != nil {
		bfd = shared[0]
	} else {
		bfd = newBFDSection()
		emitLocal = true
	}

	vrfSuffix := ""
	if vrfName != "" {
		// Render belt (#5557): sanitize the routing-instance name for the
		// `router <proto> ... vrf <name>` clauses this suffix feeds
		// (OSPF/OSPFv3/BGP/RIP/IS-IS). The name is validated at commit, but
		// the tolerant load / HA config-sync paths only warn (#1960 no-brick),
		// so a control character could otherwise inject a second vtysh line
		// into the managed frr.conf. Mirrors the static-route vrf clause
		// (config_render.go) and the BFD peer vrf clause below.
		vrfSuffix = " vrf " + sanitizeFRRValue(vrfName)
	}

	if ospf != nil {
		fmt.Fprintf(&b, "router ospf%s\n", vrfSuffix)
		if validRouterID(ospf.RouterID) {
			fmt.Fprintf(&b, " ospf router-id %s\n", ospf.RouterID)
		}
		// #9408: ReferenceBandwidthMbps is ALREADY in FRR's unit (Mbps) and
		// already range-checked against `auto-cost reference-bandwidth
		// (1-4294967)` — the bits/s -> Mbps conversion and the range gate both
		// live in pkg/config (ospfReferenceBandwidthMbps). Render verbatim; do
		// not re-scale here, and do not accept a raw operator token at this
		// layer.
		if ospf.ReferenceBandwidthMbps > 0 {
			fmt.Fprintf(&b, " auto-cost reference-bandwidth %d\n", ospf.ReferenceBandwidthMbps)
		}
		if ospf.PassiveDefault {
			b.WriteString(" passive-interface default\n")
		}
		for _, area := range ospf.Areas {
			for _, iface := range area.Interfaces {
				// OSPFv2 area membership is activated per-interface in the
				// "interface <name>" block below via "ip ospf area <id>", NOT
				// with a "network <prefix> area" statement here. A global
				// "network 0.0.0.0/0 area" matches EVERY IPv4 interface in
				// the VRF (over-activation; render order silently decides the
				// area when multiple areas exist), and FRR ospfd does not
				// support mixing "network" and "ip ospf" activation on one
				// instance (#1712). passive-interface directives are
				// independent of activation and remain under "router ospf".
				if ospf.PassiveDefault {
					if iface.NoPassive {
						fmt.Fprintf(&b, " no passive-interface %s\n", iface.Name)
					}
				} else if iface.Passive {
					fmt.Fprintf(&b, " passive-interface %s\n", iface.Name)
				}
			}
			if area.AreaType != "" {
				if area.NoSummary {
					fmt.Fprintf(&b, " area %s %s no-summary\n", area.ID, area.AreaType)
				} else {
					fmt.Fprintf(&b, " area %s %s\n", area.ID, area.AreaType)
				}
			}
			for _, vl := range area.VirtualLinks {
				fmt.Fprintf(&b, " area %s virtual-link %s\n", vl.TransitArea, vl.NeighborID)
			}
		}
		if ecmpMaxPaths > 1 {
			fmt.Fprintf(&b, " maximum-paths %d\n", ecmpMaxPaths)
		}
		for _, export := range ospf.Export {
			b.WriteString(m.resolveRedistribute(export, policyOptions, "ospf", bgpAcceptDefault))
		}
		b.WriteString("exit\n!\n")
		// OSPF interface settings + per-interface area activation. The
		// "interface <name>" block is emitted UNCONDITIONALLY for every
		// configured OSPF interface because "ip ospf area <id>" is now the
		// sole activation mechanism (the global "network 0.0.0.0/0 area"
		// line was removed above, #1712). Cost / network-type / auth / BFD
		// lines remain optional within the block.
		for _, area := range ospf.Areas {
			for _, iface := range area.Interfaces {
				fmt.Fprintf(&b, "interface %s\n", iface.Name)
				if iface.Cost > 0 {
					fmt.Fprintf(&b, " ip ospf cost %d\n", iface.Cost)
				}
				// Adjacency timers + DR priority (#4285). hello/dead MUST
				// match the neighbor or the adjacency never forms; FRR keeps
				// its defaults (hello 10s, dead 40s, priority 1) when unset.
				if iface.HelloInterval > 0 {
					fmt.Fprintf(&b, " ip ospf hello-interval %d\n", iface.HelloInterval)
				}
				if iface.DeadInterval > 0 {
					fmt.Fprintf(&b, " ip ospf dead-interval %d\n", iface.DeadInterval)
				}
				if iface.RetransmitInt > 0 {
					fmt.Fprintf(&b, " ip ospf retransmit-interval %d\n", iface.RetransmitInt)
				}
				// HasPriority gates the line; 0 is a valid value ("never DR").
				if iface.HasPriority {
					fmt.Fprintf(&b, " ip ospf priority %d\n", iface.Priority)
				}
				if iface.NetworkType != "" {
					fmt.Fprintf(&b, " ip ospf network %s\n", iface.NetworkType)
				}
				// #8443: an EMPTY key must render nothing. Without this guard
				// `authentication { md5 1; }` — a clean commit — emitted
				// `ip ospf message-digest-key 1 md5` with no argument, and
				// `authentication { simple-password; }` emitted
				// `ip ospf authentication-key` with none. vtysh rejects a
				// keyword missing its argument, and ONE rejected line fails the
				// entire managed-section reload (#1880/#2223) — taking down all
				// dynamic routing, not just OSPF. RIP and IS-IS already guard
				// this; OSPF was the only path that did not.
				if iface.AuthKey != "" && iface.AuthType == "md5" {
					b.WriteString(" ip ospf authentication message-digest\n")
					keyID := iface.AuthKeyID
					if keyID == 0 {
						keyID = 1
					}
					if tok, ok := authTokenOrOmit("ospf-md5", iface.AuthKey.Reveal()); ok {
						fmt.Fprintf(&b, " ip ospf message-digest-key %d md5 %s\n", keyID, tok)
					}
				} else if iface.AuthKey != "" && iface.AuthType == "simple" {
					b.WriteString(" ip ospf authentication\n")
					if tok, ok := authTokenOrOmit("ospf-simple", iface.AuthKey.Reveal()); ok {
						fmt.Fprintf(&b, " ip ospf authentication-key %s\n", tok)
					}
				}
				if iface.BFD {
					if iface.BFDInterval > 0 || iface.BFDMultiplier > 0 {
						profile := bfdProfileName(iface.BFDInterval, iface.BFDMultiplier)
						bfd.addProfile(profile, bfdProfile{iface.BFDInterval, iface.BFDMultiplier})
						fmt.Fprintf(&b, " ip ospf bfd profile %s\n", profile)
					} else {
						b.WriteString(" ip ospf bfd\n")
					}
				}
				fmt.Fprintf(&b, " ip ospf area %s\n", area.ID)
				b.WriteString("exit\n!\n")
			}
		}
	}

	if ospfv3 != nil {
		fmt.Fprintf(&b, "router ospf6%s\n", vrfSuffix)
		if validRouterID(ospfv3.RouterID) {
			fmt.Fprintf(&b, " ospf6 router-id %s\n", ospfv3.RouterID)
		}
		for _, area := range ospfv3.Areas {
			for _, iface := range area.Interfaces {
				fmt.Fprintf(&b, " interface %s area %s\n", iface.Name, area.ID)
			}
		}
		// IPv6 OSPF ECMP mirrors the OSPFv4 block: FRR ospf6d requires an
		// explicit "maximum-paths <N>" under "router ospf6" to install
		// equal-cost multipath. OSPFv3 reuses the same global forwarding-table
		// ECMP knob (ecmpMaxPaths) as OSPFv4 — there is no separate OSPFv3
		// maximum-paths config leaf (#2997).
		if ecmpMaxPaths > 1 {
			fmt.Fprintf(&b, " maximum-paths %d\n", ecmpMaxPaths)
		}
		for _, export := range ospfv3.Export {
			b.WriteString(m.resolveRedistribute(export, policyOptions, "ospf6", bgpAcceptDefault))
		}
		b.WriteString("exit\n!\n")
		for _, area := range ospfv3.Areas {
			for _, iface := range area.Interfaces {
				if iface.Cost > 0 || iface.Passive || iface.BFD ||
					iface.HelloInterval > 0 || iface.DeadInterval > 0 ||
					iface.RetransmitInt > 0 || iface.HasPriority {
					fmt.Fprintf(&b, "interface %s\n", iface.Name)
					if iface.Passive {
						b.WriteString(" ipv6 ospf6 passive\n")
					}
					if iface.Cost > 0 {
						fmt.Fprintf(&b, " ipv6 ospf6 cost %d\n", iface.Cost)
					}
					// Adjacency timers + DR priority (#4285): hello/dead must
					// match the neighbor. HasPriority gates the priority line;
					// priority 0 ("never DR") emits, unset omits.
					if iface.HelloInterval > 0 {
						fmt.Fprintf(&b, " ipv6 ospf6 hello-interval %d\n", iface.HelloInterval)
					}
					if iface.DeadInterval > 0 {
						fmt.Fprintf(&b, " ipv6 ospf6 dead-interval %d\n", iface.DeadInterval)
					}
					if iface.RetransmitInt > 0 {
						fmt.Fprintf(&b, " ipv6 ospf6 retransmit-interval %d\n", iface.RetransmitInt)
					}
					if iface.HasPriority {
						fmt.Fprintf(&b, " ipv6 ospf6 priority %d\n", iface.Priority)
					}
					if iface.BFD {
						if iface.BFDInterval > 0 || iface.BFDMultiplier > 0 {
							profile := bfdProfileName(iface.BFDInterval, iface.BFDMultiplier)
							bfd.addProfile(profile, bfdProfile{iface.BFDInterval, iface.BFDMultiplier})
							fmt.Fprintf(&b, " ipv6 ospf6 bfd profile %s\n", profile)
						} else {
							b.WriteString(" ipv6 ospf6 bfd\n")
						}
					}
					b.WriteString("exit\n!\n")
				}
			}
		}
	}

	// #5518: compute the renderable BGP neighbor set ONCE and drive every
	// neighbor-referencing render loop from it. A neighbor authored/loaded
	// without a peer-as keeps a zero PeerAS; AS 0 is reserved (RFC 7607) and
	// FRR/vtysh rejects `remote-as 0`, so the declaration loop below must skip
	// it (the #2963 fail-closed guard). Commit-time validation
	// (validateBGPNeighborPeerASStrict, pkg/config) rejects remote-as-0 on
	// commit/commit-check, but the tolerant load / peer-sync path downgrades it
	// to a warning, so a leniently-loaded remote-as-0 neighbor can reach the
	// renderer. The declaration guard alone is not enough: the address-family
	// activation loop and the BFD accumulator ALSO iterate the neighbors, and
	// emitting `neighbor <ip> activate` / a route-map / `neighbor <ip> bfd` /
	// a `bfd` peer for a neighbor that was never declared makes vtysh reject
	// the WHOLE managed section — a single remote-as-0 neighbor would brick the
	// frr-reload for every valid peer on the box. Building the set once here
	// guarantees the three loops can never diverge on which neighbors render.
	var validNeighbors []*config.BGPNeighbor
	if bgp != nil {
		validNeighbors = make([]*config.BGPNeighbor, 0, len(bgp.Neighbors))
		for _, n := range bgp.Neighbors {
			if n.PeerAS == 0 {
				continue
			}
			// #6796: the address is rendered RAW at every site below, so a
			// value carrying whitespace SPANS MULTIPLE FRR TOKENS and injects
			// attacker-chosen configuration (`1.1.1.1 remote-as 65000\n
			// neighbor 2.2.2.2` becomes a valid first line plus a second
			// statement). Excluding it HERE rather than guarding each render
			// site is deliberate: this set is already the single exclusion
			// point the declaration loop, the address-family activation loop
			// and the BFD accumulator all share, so a per-site guard would
			// have to be repeated 24 times and could diverge — and a neighbor
			// declared-but-not-activated, or activated-but-not-declared, makes
			// vtysh reject the WHOLE managed section.
			if !validBGPNeighborAddress(n.Address) {
				continue
			}
			validNeighbors = append(validNeighbors, n)
		}
	}

	if bgp != nil && bgp.LocalAS > 0 {
		fmt.Fprintf(&b, "router bgp %d%s\n", bgp.LocalAS, vrfSuffix)
		if validRouterID(bgp.RouterID) {
			fmt.Fprintf(&b, " bgp router-id %s\n", bgp.RouterID)
		}
		if bgp.ClusterID != "" && validClusterID(bgp.ClusterID) {
			// #4919: skip a malformed cluster-id (leniently-loaded / peer-synced
			// bad value) and sanitize the accepted value, so no invalid token or
			// injected newline reaches the frr-reload.
			fmt.Fprintf(&b, " bgp cluster-id %s\n", sanitizeFRRValue(bgp.ClusterID))
		}
		if bgp.GracefulRestart {
			b.WriteString(" bgp graceful-restart\n")
		}
		if bgp.LogNeighborChanges {
			b.WriteString(" bgp log-neighbor-changes\n")
		}
		if bgp.MultipathMultipleAS {
			b.WriteString(" bgp bestpath as-path multipath-relax\n")
		}
		if bgp.Dampening {
			hl := bgp.DampeningHalfLife
			if hl == 0 {
				hl = 15
			}
			reuse := bgp.DampeningReuse
			if reuse == 0 {
				reuse = 750
			}
			suppress := bgp.DampeningSuppress
			if suppress == 0 {
				suppress = 2000
			}
			maxSup := bgp.DampeningMaxSuppress
			if maxSup == 0 {
				maxSup = 60
			}
			fmt.Fprintf(&b, " bgp dampening %d %d %d %d\n", hl, reuse, suppress, maxSup)
		}
		// validNeighbors excludes remote-as-0 neighbors (#2963/#5518). Every
		// neighbor-referencing loop below (AF activation, BFD accumulator)
		// iterates the SAME slice so an undeclared neighbor is never activated
		// or attached to BFD — see the validNeighbors construction above.
		for _, n := range validNeighbors {
			fmt.Fprintf(&b, " neighbor %s remote-as %d\n", n.Address, n.PeerAS)
			// Per-peering local-as (#4286): present a different AS than the
			// router's own to this peer.
			if n.LocalAS > 0 {
				fmt.Fprintf(&b, " neighbor %s local-as %d\n", n.Address, n.LocalAS)
			}
			// update-source (#4286): iBGP peers over loopbacks need the TCP
			// session sourced from the loopback the peer has a `neighbor`
			// statement for, not the egress interface IP — otherwise the peer
			// rejects the connection and the session never establishes.
			if n.LocalAddress != "" {
				fmt.Fprintf(&b, " neighbor %s update-source %s\n", n.Address, sanitizeFRRValue(n.LocalAddress))
			}
			// passive (#4286): do not initiate — wait for the peer to connect.
			if n.Passive {
				fmt.Fprintf(&b, " neighbor %s passive\n", n.Address)
			}
			// hold-time (#4286): FRR `timers <keepalive> <holdtime>`; keepalive
			// defaults to hold/3 per the BGP convention (Junos derives the same
			// way). A mismatched hold-time shortens or breaks the session.
			if n.HoldTime > 0 {
				keepalive := n.HoldTime / 3
				if keepalive < 1 {
					keepalive = 1
				}
				fmt.Fprintf(&b, " neighbor %s timers %d %d\n", n.Address, keepalive, n.HoldTime)
			}
			if n.Description != "" {
				fmt.Fprintf(&b, " neighbor %s description %s\n", n.Address, sanitizeFRRValue(n.Description))
			}
			if n.MultihopTTL > 0 {
				fmt.Fprintf(&b, " neighbor %s ebgp-multihop %d\n", n.Address, n.MultihopTTL)
			}
			if n.AuthPassword != "" {
				if tok, ok := authTokenOrOmit("bgp", n.AuthPassword.Reveal()); ok {
					fmt.Fprintf(&b, " neighbor %s password %s\n", n.Address, tok)
				}
			}
			if n.BFD {
				fmt.Fprintf(&b, " neighbor %s bfd\n", n.Address)
			}
			if n.RouteReflectorClient {
				fmt.Fprintf(&b, " neighbor %s route-reflector-client\n", n.Address)
			}
			if n.AllowASIn > 0 {
				fmt.Fprintf(&b, " neighbor %s allowas-in %d\n", n.Address, n.AllowASIn)
			}
			if n.RemovePrivateAS {
				fmt.Fprintf(&b, " neighbor %s remove-private-AS\n", n.Address)
			}
		}
		// A global `protocols bgp export <token>` has TWO legitimate
		// shapes that render differently (#2473):
		//
		//   - A DEFINED policy-statement name → a Junos default export
		//     policy applied to every BGP peer, i.e. a peer-level
		//     `route-map <name> out` per neighbor/address-family. It MUST
		//     NOT be routed through resolveRedistribute: doing so emitted
		//     `redistribute ospf route-map ...` under `router bgp`, which
		//     actively ANNOUNCES all OSPF/connected routes into BGP (route
		//     leak, #2473 failure mode 1), and for a prefix/community-only
		//     policy with no `from protocol` it returned "" and SILENTLY
		//     DROPPED the operator's advertise filter (#2473 failure mode
		//     2). The route-map is already emitted by generatePolicyOptions,
		//     so `route-map out` filters advertisements without leaking the
		//     internal RIB.
		//
		//   - A BARE PROTOCOL TOKEN (connected/direct/static/kernel/ospf/
		//     bgp/rip/isis — i.e. NOT a defined policy-statement) → this
		//     firewall's redistribution shorthand, a genuine `redistribute
		//     <proto>`. It has NO route-map to reference, so it must keep
		//     going through resolveRedistribute. Rendering it as
		//     `neighbor X route-map connected out` would point at a
		//     non-existent route-map. So we classify each token by the SAME
		//     policy-statement-exists predicate the commit-time validator uses
		//     (checkRedist/checkPolicyRef in pkg/config) and split the two
		//     render paths.
		//
		//     #6807 CORRECTION: this comment used to say an undefined
		//     route-map "resolves to PERMIT-ALL — advertising the entire
		//     table". FRR does the OPPOSITE (RMAP_DENY on a failed
		//     route_map_lookup_by_name, stable/10.6). The split is still
		//     right — a bare protocol token is a redistribute verb, not a
		//     policy — but its consequence is a withdrawal, not a leak.
		//
		// Coexistence (Junos most-specific-wins) applies ONLY among the
		// policy-statement-name route-map-out exports: a per-neighbor
		// export overrides the global default for that neighbor. FRR
		// accepts a single `route-map out` per neighbor/AF, so exactly one
		// is emitted — the neighbor's own export chain when present, else
		// the global export chain (bgpNeighborExportChain resolves the
		// override; a resolved chain of >= 2 is composed into one
		// `-xpf-chain` route-map via composedChainName/bgpRouteMapRef,
		// #5277). A bare-token redistribute is a GLOBAL redistribute verb,
		// not per-neighbor, and is emitted once under `router bgp`.
		// globalExportChain is the ORDERED list of DEFINED policy-statements
		// in `protocols bgp export` — the global export CHAIN applied as a
		// peer-level default to neighbors with no own export. Every entry is
		// preserved and composed in order (#5277); the pre-#5277 code kept only
		// the LAST defined entry, silently dropping a leading reject/attribute
		// policy so prohibited routes were advertised. Bare protocol tokens are
		// still split out to the redistribute path below (unchanged).
		globalExportChain := make([]string, 0, len(bgp.Export))
		for _, e := range bgp.Export {
			if e == "" {
				continue
			}
			if isDefinedPolicyStatement(e, policyOptions) {
				globalExportChain = append(globalExportChain, e)
			} else {
				// Bare protocol token (or a name that slipped the
				// validator on a lenient load/HA-sync path) → genuine
				// redistribute. resolveRedistribute normalizes direct→
				// connected and refuses to emit an invalid bare-name
				// line (#2223), and drops a self-redistribute (#2943).
				b.WriteString(m.resolveRedistribute(e, policyOptions, "bgp", bgpAcceptDefault))
			}
		}

		// Global `protocols bgp import <policy>` default (#2490). Unlike
		// export there is NO redistribute equivalent for inbound filtering
		// (FRR has no "redistribute in") — import is route-map-only. An
		// import ref MUST therefore name a DEFINED policy-statement so the
		// route-map below references a route-map that generatePolicyOptions
		// actually emits. A bare/undefined ref is REJECTED at commit
		// (validateRoutingExportReferencesStrict, strict) and SKIPPED here
		// on the lenient load/HA-sync path.
		//
		// #6807 CORRECTION: the skip's stated reason — that `route-map <token>
		// in` for a non-existent route-map "would resolve to PERMIT-ALL in FRR
		// and silently accept every inbound advertisement" — is backwards. FRR
		// stable/10.6 bgp_input_modifier returns RMAP_DENY for an unresolvable
		// name; it is the ABSENT attachment this skip produces that accepts
		// everything. Behaviour unchanged here (that decision is #7625); the
		// claim is corrected so nobody
		// reasons from it. Every DEFINED entry is
		// preserved as an ordered CHAIN and composed in order (#5277); the
		// pre-#5277 code kept only the last, silently dropping a leading inbound
		// filter so prohibited routes were accepted.
		globalImportChain := make([]string, 0, len(bgp.Import))
		for _, e := range bgp.Import {
			if e == "" {
				continue
			}
			if isDefinedPolicyStatement(e, policyOptions) {
				globalImportChain = append(globalImportChain, e)
			}
		}

		// Address-family blocks for neighbors with family declarations.
		// When a global default export exists it must reach EVERY peer,
		// including neighbors with no explicit `family` (FRR default-
		// activates those under ipv4 unicast), so route them into the
		// ipv4 set in that case.
		var inet4Neighbors, inet6Neighbors []*config.BGPNeighbor
		// Classify only renderable (declared) neighbors (#5518). A remote-as-0
		// neighbor excluded from the declaration loop above must NOT be
		// activated here — vtysh rejects `neighbor <ip> activate` for a
		// neighbor with no `remote-as`, failing the whole managed section.
		for _, n := range validNeighbors {
			// A neighbor lands in the ipv4 (default) AF when it explicitly
			// declares family inet, OR when a peer-level policy must reach it
			// and it has not been pinned to inet6: a global export/import
			// default, or its own per-neighbor export/import (FRR default-
			// activates a family-less neighbor under ipv4 unicast). Per-
			// neighbor import/export inclusion is #2490 (symmetric to the
			// global-default inclusion #2473 added).
			hasOwnPolicy := hasNonEmptyPolicy(n.Export) || hasNonEmptyPolicy(n.Import)
			// The "default-activate a family-less policied neighbor under
			// ipv4 unicast" fall-through (#2473/#2490) is correct ONLY for
			// an IPv4 peer address. An IPv6 peer (e.g. 2001:db8::1) with a
			// policy but no explicit `family inet6` also satisfies
			// !n.FamilyInet6, so the pre-#2941 code activated it under
			// `address-family ipv4 unicast` — the WRONG family. FRR cannot
			// resolve an IPv4 next-hop over an IPv6 peer (no RFC 8950
			// extended-next-hop) so the session drops prefixes / fails, and
			// the neighbor never participates in ipv6 unicast. Gate the
			// ipv4 fall-through on the peer address family, and route an
			// IPv6-address family-less-but-policied neighbor into the ipv6
			// set instead so it activates under ipv6 unicast (#2941).
			isIPv6Peer := strings.Contains(n.Address, ":")
			policyDefault := len(globalExportChain) > 0 || len(globalImportChain) > 0 || hasOwnPolicy
			if (n.FamilyInet || (policyDefault && !n.FamilyInet6)) && !isIPv6Peer {
				inet4Neighbors = append(inet4Neighbors, n)
			}
			if n.FamilyInet6 || (policyDefault && !n.FamilyInet && isIPv6Peer) {
				inet6Neighbors = append(inet6Neighbors, n)
			}
		}
		// BGP maximum-paths is driven ONLY by the explicit `protocols bgp
		// multipath` knob (bgp.Multipath), never seeded from the global
		// forwarding-table ECMP setting (ecmpMaxPaths). ECMP is a zebra/
		// kernel forwarding concept; rendering it into the BGP address-
		// families would silently turn on BGP multipath path-selection the
		// operator never asked for (#2791). The global ECMP knob still
		// reaches the IGP `maximum-paths` lines (OSPF/zebra) above via
		// ecmpMaxPaths.
		bgpMaxPaths := bgp.Multipath
		if len(inet4Neighbors) > 0 || bgpMaxPaths > 1 {
			b.WriteString(" !\n address-family ipv4 unicast\n")
			if bgpMaxPaths > 1 {
				fmt.Fprintf(&b, "  maximum-paths %d\n", bgpMaxPaths)
				// FRR `maximum-paths N` enables eBGP multipath only; iBGP
				// multipath requires the separate `maximum-paths ibgp N`
				// command, gated on the explicit `protocols bgp multipath
				// ibgp` knob (#2978).
				if bgp.MultipathIBGP {
					fmt.Fprintf(&b, "  maximum-paths ibgp %d\n", bgpMaxPaths)
				}
			}
			for _, n := range inet4Neighbors {
				fmt.Fprintf(&b, "  neighbor %s activate\n", n.Address)
				if n.DefaultOriginate {
					fmt.Fprintf(&b, "  neighbor %s default-originate\n", n.Address)
				}
				if n.PrefixLimitInet > 0 {
					fmt.Fprintf(&b, "  neighbor %s maximum-prefix %d\n", n.Address, n.PrefixLimitInet)
				}
				// Outbound filter. The effective export CHAIN (neighbor's own
				// list, else the global default) is pre-filtered to DEFINED
				// policy-statements (filterDefinedPolicies), so bare/undefined
				// refs never render a dangling `route-map out` (#2473/#2539) —
				// bare tokens stay on the redistribute path. (#6807: a dangling
				// out-ref would DENY, not permit as this said; the definition
				// side is what #6807 fixes.) A single-policy chain references the standalone
				// route-map (byte-identical to pre-#5277); a chain of >= 2
				// references the composed route-map that preserves the ordered
				// Junos policy chain (#5277) instead of dropping all but the
				// last.
				if rm := bgpNeighborExportRef(n, bgp, globalExportChain, policyOptions); rm != "" {
					fmt.Fprintf(&b, "  neighbor %s route-map %s out\n", n.Address, rm)
				}
				// Junos `then next-hop self` is lowered per-term INSIDE the
				// export route-map as `set ip/ipv6 next-hop peer-address`
				// (which resolves to self in the outbound direction), NOT the
				// neighbor-wide `neighbor <peer> next-hop-self` knob. The knob
				// ran after route selection and rewrote EVERY route advertised
				// to the peer, widening a term-scoped action to all of the
				// neighbor's routes (#5115). The route-map lowering still
				// overrides iBGP / route-reflector-reflected next-hops (the
				// #2977 fix), now scoped to the term. See the `term.NextHop ==
				// "self"` branch in the route-map renderer.
				//
				// Inbound filter (#2490/#5277). Same chain composition as the
				// outbound path: the effective import chain is defined-filtered
				// (no dangling in-line), single-policy references the standalone
				// route-map, and a chain of >= 2 references the composed
				// route-map preserving the ordered inbound policy chain.
				if rm := bgpNeighborImportRef(n, bgp, globalImportChain, policyOptions); rm != "" {
					fmt.Fprintf(&b, "  neighbor %s route-map %s in\n", n.Address, rm)
				}
			}
			b.WriteString(" exit-address-family\n")
		}
		if len(inet6Neighbors) > 0 || bgpMaxPaths > 1 {
			b.WriteString(" !\n address-family ipv6 unicast\n")
			if bgpMaxPaths > 1 {
				fmt.Fprintf(&b, "  maximum-paths %d\n", bgpMaxPaths)
				// iBGP multipath (#2978) — see the ipv4 block above.
				if bgp.MultipathIBGP {
					fmt.Fprintf(&b, "  maximum-paths ibgp %d\n", bgpMaxPaths)
				}
			}
			for _, n := range inet6Neighbors {
				fmt.Fprintf(&b, "  neighbor %s activate\n", n.Address)
				if n.DefaultOriginate {
					fmt.Fprintf(&b, "  neighbor %s default-originate\n", n.Address)
				}
				if n.PrefixLimitInet6 > 0 {
					fmt.Fprintf(&b, "  neighbor %s maximum-prefix %d\n", n.Address, n.PrefixLimitInet6)
				}
				// Outbound filter (#2539/#5277) — see the ipv4 block above.
				if rm := bgpNeighborExportRef(n, bgp, globalExportChain, policyOptions); rm != "" {
					fmt.Fprintf(&b, "  neighbor %s route-map %s out\n", n.Address, rm)
				}
				// `then next-hop self` is lowered per-term in the export
				// route-map as `set ip/ipv6 next-hop peer-address`, NOT a
				// neighbor-wide `next-hop-self` knob (#5115) — see the ipv4
				// block above.
				// Inbound filter (#2490/#5277) — see the ipv4 block above.
				if rm := bgpNeighborImportRef(n, bgp, globalImportChain, policyOptions); rm != "" {
					fmt.Fprintf(&b, "  neighbor %s route-map %s in\n", n.Address, rm)
				}
			}
			b.WriteString(" exit-address-family\n")
		}

		b.WriteString("exit\n!\n")
	}

	if rip != nil {
		fmt.Fprintf(&b, "router rip%s\n", vrfSuffix)
		for _, iface := range rip.Interfaces {
			fmt.Fprintf(&b, " network %s\n", iface)
		}
		for _, iface := range rip.Passive {
			fmt.Fprintf(&b, " passive-interface %s\n", iface)
		}
		for _, r := range rip.Redistribute {
			b.WriteString(m.resolveRedistribute(r, policyOptions, "rip", bgpAcceptDefault))
		}
		b.WriteString("exit\n!\n")
		// RIP per-interface authentication
		if rip.AuthKey != "" {
			for _, iface := range rip.Interfaces {
				fmt.Fprintf(&b, "interface %s\n", iface)
				// #8443: a value the strict gate would now reject can still arrive
				// on the TOLERANT load path (#1960 — a persisted config must still
				// boot). Render what we always rendered, but say so: silently
				// downgrading md5 to plaintext is the defect, and the operator has
				// no other signal because `show configuration` echoes their value.
				// #9105: an ABSENT type is not `unrecognized`, so this warning could not
				// fire for it -- and it renders the key in CLEARTEXT exactly as a
				// chosen `simple` does. Warn on both: the commit gate stops every NEW
				// instance, this tells the operator about an existing one arriving
				// through the tolerant load path.
				if config.AuthTypeAbsent(rip.AuthType) {
					slog.Warn("frr: rip authentication-key is set with NO authentication-type; "+
						"rendering PLAINTEXT -- the key travels in clear in every PDU. Set "+
						"authentication-type md5 to authenticate with a digest (#9105)",
						"accepted", config.AuthTypeSpellings())
				}
				if config.AuthTypeUnrecognized(rip.AuthType) {
					slog.Warn("frr: unrecognized rip authentication-type; rendering PLAINTEXT authentication",
						"interface", iface, "authentication_type", rip.AuthType,
						"accepted", config.AuthTypeSpellings())
				}
				if config.AuthTypeIsMD5(rip.AuthType) {
					b.WriteString(" ip rip authentication mode md5\n")
				} else {
					b.WriteString(" ip rip authentication mode text\n")
				}
				if tok, ok := authTokenOrOmit("rip", rip.AuthKey.Reveal()); ok {
					fmt.Fprintf(&b, " ip rip authentication string %s\n", tok)
				}
				b.WriteString("exit\n!\n")
			}
		}
	}

	if isis != nil {
		fmt.Fprintf(&b, "router isis xpf%s\n", vrfSuffix)
		if isis.NET != "" {
			fmt.Fprintf(&b, " net %s\n", isis.NET)
		}
		// #8446: canonicalize through the SHARED predicate the commit gate
		// uses (config.CanonicalISISLevel) rather than switching on the raw
		// stored string. This switch previously had no `default` arm, so a
		// value outside the three it named emitted NO is-type line and FRR
		// silently fell back to its own default, level-1-2 — WIDENING the
		// router's adjacency scope. `level-2-only` (the spelling emitted
		// three lines below) hit that path, so feeding our own output back
		// in turned a Level-2-only router into a Level-1-2 one.
		//
		// The strict commit gate rejects a non-canonical value, but the
		// tolerant Load / peer-sync paths only warn (#1960 no-brick), so the
		// renderer keeps its own belt: an unrecognized value renders the
		// SAFE default rather than nothing. Narrower than authored is a
		// recoverable misconfiguration; wider than authored is a silent
		// security regression. Same shape as the #6686 as-path belt.
		level, ok := config.CanonicalISISLevel(isis.Level)
		if !ok {
			level = config.DefaultISISLevel
		}
		switch level {
		case "level-1":
			b.WriteString(" is-type level-1\n")
		case "level-1-2":
			b.WriteString(" is-type level-1-2\n")
		default:
			// level-2 and every unrecognized value: the narrow default.
			b.WriteString(" is-type level-2-only\n")
		}
		for _, export := range isis.Export {
			b.WriteString(m.resolveRedistribute(export, policyOptions, "isis", bgpAcceptDefault))
		}
		if isis.WideMetricsOnly {
			b.WriteString(" metric-style wide\n")
		}
		if isis.Overload {
			b.WriteString(" set-overload-bit\n")
		}
		if isis.AuthKey != "" {
			// #9105: an ABSENT type is not `unrecognized`, so this warning could not
			// fire for it -- and it renders the key in CLEARTEXT exactly as a
			// chosen `simple` does. Warn on both: the commit gate stops every NEW
			// instance, this tells the operator about an existing one arriving
			// through the tolerant load path.
			if config.AuthTypeAbsent(isis.AuthType) {
				slog.Warn("frr: isis authentication-key is set with NO authentication-type; "+
					"rendering PLAINTEXT -- the key travels in clear in every PDU. Set "+
					"authentication-type md5 to authenticate with a digest (#9105)",
					"accepted", config.AuthTypeSpellings())
			}
			if config.AuthTypeUnrecognized(isis.AuthType) {
				slog.Warn("frr: unrecognized isis authentication-type; rendering PLAINTEXT area/domain password",
					"authentication_type", isis.AuthType,
					"accepted", config.AuthTypeSpellings())
			}
			if config.AuthTypeIsMD5(isis.AuthType) {
				if tok, ok := authTokenOrOmit("isis-area-md5", isis.AuthKey.Reveal()); ok {
					fmt.Fprintf(&b, " area-password md5 %s\n", tok)
				}
				if tok, ok := authTokenOrOmit("isis-domain-md5", isis.AuthKey.Reveal()); ok {
					fmt.Fprintf(&b, " domain-password md5 %s\n", tok)
				}
			} else {
				if tok, ok := authTokenOrOmit("isis-area-clear", isis.AuthKey.Reveal()); ok {
					fmt.Fprintf(&b, " area-password clear %s\n", tok)
				}
				if tok, ok := authTokenOrOmit("isis-domain-clear", isis.AuthKey.Reveal()); ok {
					fmt.Fprintf(&b, " domain-password clear %s\n", tok)
				}
			}
		}
		b.WriteString("exit\n!\n")
		for _, iface := range isis.Interfaces {
			fmt.Fprintf(&b, "interface %s\n", iface.Name)
			fmt.Fprintf(&b, " ip router isis xpf\n")
			// #8450: enable the IPv6 topology too. Only `ip router isis` was
			// emitted, so isisd ran IPv4-only on every interface and IS-IS
			// learned and advertised NO IPv6 routes — on a dual-stack product,
			// with the compiler happily accepting IS-IS on dual-stack
			// interfaces and knownRedistProtocols extended for IPv6 IGPs
			// (#2943). FRR itself enables both address families for a
			// configured `router isis`, so emitting both matches its defaults;
			// on an interface with no IPv6 address there is nothing to
			// advertise and the line is inert.
			fmt.Fprintf(&b, " ipv6 router isis xpf\n")
			// #8450: the per-interface circuit type. ISISInterface.Level was
			// compiled and stored and then never rendered, so an interface an
			// operator restricted to one level kept forming adjacencies at the
			// ROUTER-WIDE is-type — dead config that fails OPEN. An empty value
			// renders no line, which is the correct "inherit the router-wide
			// is-type" behaviour in both FRR and Junos. An unrecognised value
			// also renders no line rather than a broken one: the strict commit
			// gate rejects it, and on the tolerant Load / peer-sync path
			// (#1960) an omitted circuit-type is the pre-#8450 behaviour, which
			// is recoverable, where an invalid `isis circuit-type <junk>` line
			// would fail the WHOLE frr-reload (#1880/#2223).
			if ct, ok := config.CanonicalISISCircuitType(iface.Level); ok && ct != "" {
				fmt.Fprintf(&b, " isis circuit-type %s\n", ct)
			}
			if iface.Passive {
				b.WriteString(" isis passive\n")
			}
			if iface.Metric > 0 {
				fmt.Fprintf(&b, " isis metric %d\n", iface.Metric)
			}
			if iface.AuthKey != "" {
				// #9105: an ABSENT type is not `unrecognized`, so this warning could not
				// fire for it -- and it renders the key in CLEARTEXT exactly as a
				// chosen `simple` does. Warn on both: the commit gate stops every NEW
				// instance, this tells the operator about an existing one arriving
				// through the tolerant load path.
				if config.AuthTypeAbsent(iface.AuthType) {
					slog.Warn("frr: isis interface authentication-key is set with NO authentication-type; "+
						"rendering PLAINTEXT -- the key travels in clear in every PDU. Set "+
						"authentication-type md5 to authenticate with a digest (#9105)",
						"accepted", config.AuthTypeSpellings())
				}
				if config.AuthTypeUnrecognized(iface.AuthType) {
					slog.Warn("frr: unrecognized isis interface authentication-type; rendering PLAINTEXT password",
						"interface", iface.Name, "authentication_type", iface.AuthType,
						"accepted", config.AuthTypeSpellings())
				}
				// #9496: the per-interface pair goes through the same #9050 belt as
				// every other routing-auth site. sanitizeFRRValue maps a TAB into a
				// splitter and passes a space through, so a whitespace secret arriving
				// via a tolerant load, peer sync or rollback rendered a splittable line.
				if config.AuthTypeIsMD5(iface.AuthType) {
					if tok, ok := authTokenOrOmit("isis-interface-md5", iface.AuthKey.Reveal()); ok {
						fmt.Fprintf(&b, " isis password md5 %s\n", tok)
					}
				} else {
					if tok, ok := authTokenOrOmit("isis-interface-clear", iface.AuthKey.Reveal()); ok {
						fmt.Fprintf(&b, " isis password clear %s\n", tok)
					}
				}
			}
			// `isis bfd` / `isis bfd profile <name>` are interface-scoped
			// commands and MUST be emitted INSIDE the interface block,
			// before `exit`. Emitting them after `exit` lands them at
			// global config scope, which vtysh rejects — and one rejected
			// line fails the WHOLE managed-section reload (#1880/#2223),
			// breaking every IS-IS interface with BFD enabled. This mirrors
			// the OSPFv3 per-interface BFD ordering above (#2942).
			if iface.BFD {
				if iface.BFDInterval > 0 || iface.BFDMultiplier > 0 {
					profile := bfdProfileName(iface.BFDInterval, iface.BFDMultiplier)
					bfd.addProfile(profile, bfdProfile{iface.BFDInterval, iface.BFDMultiplier})
					fmt.Fprintf(&b, " isis bfd profile %s\n", profile)
				} else {
					b.WriteString(" isis bfd\n")
				}
			}
			b.WriteString("exit\n!\n")
		}
	}

	// Accumulate BFD peer entries for BGP neighbors with BFD enabled. The
	// in-scope vrfName is recorded with each peer so the single global
	// block carries the matching `vrf <name>` suffix (#2489). Emission is
	// deferred to bfdSection.render() — either here (local fallback) or by
	// the manager for the consolidated global block (#2550).
	if bgp != nil {
		// Accumulate BFD peers only for renderable (declared) neighbors
		// (#5518). A remote-as-0 neighbor skipped by the declaration loop must
		// not emit a `bfd` peer either — validNeighbors is the shared
		// exclusion set.
		for _, n := range validNeighbors {
			if n.BFD {
				bfd.addPeer(bfdPeer{
					address:    n.Address,
					vrfName:    vrfName,
					interval:   n.BFDInterval,
					multiplier: n.BFDMultiplier,
				})
			}
		}
	}

	// In local-fallback mode (no shared accumulator from the manager) emit
	// the single `bfd` block here, preserving historical single-instance
	// output. In shared mode the manager renders one global block instead.
	if emitLocal {
		b.WriteString(bfd.render())
	}

	return b.String()
}
