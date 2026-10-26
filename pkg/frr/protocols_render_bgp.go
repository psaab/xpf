// protocols_render_bgp.go renders the BGP stanza of
// generateProtocolsCluster15158 (#16125 verbatim extraction).
//
// The body below is the contiguous `if bgp != nil && bgp.LocalAS > 0`
// subtree moved verbatim out of generateProtocolsCluster15158; the
// valid-neighbor pre-pass stays in the caller because the deferred
// BGP BFD-peer accumulation shares it. Output ordering, the shared
// BFD accumulator and every render belt are unchanged.

package frr

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// renderBGP16125 renders the `router bgp` stanza into b. Moved
// verbatim from generateProtocolsCluster15158 (#16125);
// validNeighbors is the single renderable-neighbor set computed by
// the caller pre-pass, and bfd is the shared BFD accumulator.
func (m *Manager) renderBGP16125(b *strings.Builder, bgp *config.BGPConfig, validNeighbors []*config.BGPNeighbor, vrfName, vrfSuffix string, ecmpMaxPaths int, policyOptions *config.PolicyOptionsConfig, bgpAcceptDefault map[string]bool, qnhMetrics *qnhMetricScope11447, clusterMode bool, bfd *bfdSection) {
	// #16572: `protocols bgp disable` renders no `router bgp` at all.
	if bgp != nil && bgp.Disable {
		return
	}
	if bgp != nil && bgp.LocalAS > 0 {
		fmt.Fprintf(b, "router bgp %d%s\n", bgp.LocalAS, vrfSuffix)
		// #14584: FRR bgpd defaults to `bgp ebgp-requires-policy`
		// (RFC 8212): an eBGP neighbor with no inbound route-map has
		// every inbound update discarded (inboundEbgpRequiresPolicy),
		// and a policy-less eBGP neighbor is discarded outbound too.
		// Junos default import accepts all received routes and default
		// export advertises active BGP routes, and this renderer
		// already relies on an ABSENT route-map attachment meaning
		// that default (#6807/#7625). Opt every stanza (default and
		// each VRF) out of requires-policy so the absent-attachment
		// shapes — export-only and policy-less eBGP — exchange routes
		// as Junos does. Neighbors WITH policies are unaffected: their
		// route-maps still filter exactly as before.
		b.WriteString(" no bgp ebgp-requires-policy\n")
		// #16620: pin BGP (external, internal, local) to the single
		// Junos BGP preference 170 so a verbatim Junos static
		// preference arbitrates as on Junos; see
		// protocol_distance_16620.go.
		b.WriteString(junosBGPDistanceLine)
		if validRouterID(bgp.RouterID) {
			fmt.Fprintf(b, " bgp router-id %s\n", bgp.RouterID)
		}
		if bgp.ClusterID != "" && validClusterID(bgp.ClusterID) {
			// #4919: skip a malformed cluster-id (leniently-loaded / peer-synced
			// bad value) and sanitize the accepted value, so no invalid token or
			// injected newline reaches the frr-reload.
			fmt.Fprintf(b, " bgp cluster-id %s\n", sanitizeFRRValue(bgp.ClusterID))
		} else if bgp.ClusterID != "" {
			// #14377: never silently omit a configured cluster-id (incl.
			// padded spellings the strict gate now rejects): warn so the
			// RR loop-prevention loss is operator-visible.
			logOmittedBGPClusterID(bgp.ClusterID)
		}
		// #16800: FRR bgpd evaluates an outbound route-map for a
		// REFLECTED (IBGP->IBGP) advertisement on a dummy attribute
		// copy unless `bgp route-reflector allow-outbound-policy` is
		// set, so every export-policy `set` clause — the #5115
		// `then next-hop self` lowering (`set ip/ipv6 next-hop
		// peer-address`), `set local-preference`, `set community`,
		// ... — is silently discarded on exactly the routes the
		// #2977 fix claims to rewrite, and RR clients receive the
		// original next-hop/attributes (blackhole when they have no
		// IGP path to that next-hop). The knob is a router-global
		// toggle with no per-neighbor/AF form, so render it once,
		// after cluster-id, in every stanza (default AND each VRF)
		// that actually renders a route-reflector-client neighbor.
		// Gating on a rendered client — not on which policies are
		// attached — keeps the line present for accept/reject-only
		// and later-attached policies, while a stanza with no client
		// (including one whose only clients the #14585 belt omits as
		// eBGP) renders byte-identically to before.
		if bgpRRAllowsOutboundPolicy16800(bgp.LocalAS, validNeighbors) {
			b.WriteString(" bgp route-reflector allow-outbound-policy\n")
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
		// #15185: `bgp dampening` is an address-family command in bgpd.
		// Rendered at router level, bgpd files it under
		// `address-family ipv4 unicast` only, so IPv6 unicast route-flap
		// damping was silently never enabled. Compute the line once here
		// (defaults + the #14585 suppress<=reuse belt preserved) and emit
		// it inside each rendered unicast AF block below — never at
		// router level.
		var dampeningLine string
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
			if suppress <= reuse {
				slog.Warn("frr: omitting bgp dampening with suppress <= reuse (#14585)",
					"reuse", reuse, "suppress", suppress)
			} else {
				dampeningLine = fmt.Sprintf("  bgp dampening %d %d %d %d\n", hl, reuse, suppress, maxSup)
			}
		}
		// validNeighbors excludes remote-as-0 neighbors (#2963/#5518). Every
		// neighbor-referencing loop below (AF activation, BFD accumulator)
		// iterates the SAME slice so an undeclared neighbor is never activated
		// or attached to BFD — see the validNeighbors construction above.
		for _, n := range validNeighbors {
			fmt.Fprintf(b, " neighbor %s remote-as %d\n", n.Address, n.PeerAS)
			// Per-peering local-as (#4286): present a different AS than the
			// router's own to this peer. #14585: bgpd refuses local-as equal
			// to the router AS; omit it on the tolerant path.
			if n.LocalAS > 0 && n.LocalAS == bgp.LocalAS {
				slog.Warn("frr: omitting neighbor local-as equal to the router AS (#14585)",
					"neighbor", sanitizeFRRValue(n.Address), "local_as", n.LocalAS)
			} else if n.LocalAS > 0 {
				fmt.Fprintf(b, " neighbor %s local-as %d\n", n.Address, n.LocalAS)
			}
			// update-source (#4286): iBGP peers over loopbacks need the TCP
			// session sourced from the loopback the peer has a `neighbor`
			// statement for, not the egress interface IP — otherwise the peer
			// rejects the connection and the session never establishes.
			// #9493: a spaced value survived sanitizeFRRValue and split the line.
			if n.LocalAddress != "" && frrOperandOrOmit("bgp update-source", n.LocalAddress) {
				fmt.Fprintf(b, " neighbor %s update-source %s\n", n.Address, sanitizeFRRValue(n.LocalAddress))
			}
			// passive (#4286): do not initiate — wait for the peer to connect.
			if n.Passive {
				fmt.Fprintf(b, " neighbor %s passive\n", n.Address)
			}
			// hold-time (#4286): FRR `timers <keepalive> <holdtime>`; keepalive
			// defaults to hold/3 per the BGP convention (Junos derives the same
			// way). A mismatched hold-time shortens or breaks the session.
			// #16749/#14585 belt: a hold-time of 1 or 2 (or above the 16-bit
			// wire max) renders a timers line bgpd refuses, failing the whole
			// frr-reload. The strict gate rejects it (ValidateBGPHoldTime),
			// but a leniently loaded / peer-synced value must not poison
			// every later reload — omit the line and warn, like the other
			// #14585 render belts. HoldTime 0 keeps its unset meaning.
			if n.HoldTime == 1 || n.HoldTime == 2 || n.HoldTime > 65535 {
				slog.Warn("frr: omitting neighbor timers with hold-time FRR rejects (#16749)",
					"neighbor", sanitizeFRRValue(n.Address), "hold_time", n.HoldTime)
			} else if n.HoldTime > 0 {
				keepalive := n.HoldTime / 3
				if keepalive < 1 {
					keepalive = 1
				}
				fmt.Fprintf(b, " neighbor %s timers %d %d\n", n.Address, keepalive, n.HoldTime)
			}
			if n.Description != "" {
				// #16776/#17839: the pipe gate must judge the
				// string that will actually be rendered, not the
				// raw stored description: sanitizeFRRValue turns
				// control bytes into spaces, so a raw-safe value
				// such as "uplink |\tprimary" renders as
				// "uplink | primary", which FRR's vty pipe hook
				// refuses while the reload reports success.
				// Omit it on the tolerant path (the strict gate
				// rejects it at commit).
				renderedDescription := sanitizeFRRValue(n.Description)
				if !config.FRRDescriptionPipeSafe16776(renderedDescription) {
					slog.Warn("frr: omitting neighbor description containing \"| \"; it would be refused by the vty pipe hook (#16776)",
						"neighbor", sanitizeFRRValue(n.Address))
				} else {
					fmt.Fprintf(b, " neighbor %s description %s\n", n.Address, renderedDescription)
				}
			}
			if n.MultihopTTL > 0 {
				fmt.Fprintf(b, " neighbor %s ebgp-multihop %d\n", n.Address, frrClampInt("bgp ebgp-multihop", n.MultihopTTL, 255))
			}
			if n.AuthPassword.Reveal() != "" {
				if tok, ok := authTokenOrOmit("bgp", &n.AuthPassword); ok {
					fmt.Fprintf(b, " neighbor %s password %s\n", n.Address, tok)
				}
			}
			if n.BFD {
				// #14587: for a multihop neighbor, plain `neighbor X bfd`
				// leaves bgpd's dynamic bfdd session at FRR defaults
				// (300ms x3) — the static single-hop peer stanza at the
				// configured timers is an orphan bgpd never uses. Bind
				// the profile encoding the configured timers so bgpd
				// applies them to the session it actually creates. The
				// profile definition is registered with the section;
				// the static peer is keyed multihop in the accumulator
				// below so bfdd shows exactly one session.
				if bgpNeighborBFDMultihop14587(n, bgp.LocalAS) {
					profile := bfdProfileName(n.BFDInterval, n.BFDMultiplier)
					bfd.addProfile(profile, bfdProfile{n.BFDInterval, n.BFDMultiplier})
					fmt.Fprintf(b, " neighbor %s bfd profile %s\n", n.Address, profile)
				} else {
					fmt.Fprintf(b, " neighbor %s bfd\n", n.Address)
				}
			}
		}
		// A global `protocols bgp export <token>` has TWO legitimate
		// shapes that render differently (#2473):
		//
		//   - A DEFINED policy-statement name → a Junos default export
		//     policy applied to every BGP peer, i.e. a peer-level
		//     `route-map <name> out` per neighbor/address-family. It MUST
		//     NOT be routed through the BARE-token redistribute path:
		//     doing so emitted an UNFILTERED `redistribute ospf` under
		//     `router bgp`, which actively ANNOUNCES all OSPF/connected
		//     routes into BGP (route leak, #2473 failure mode 1), and for
		//     a prefix/community-only policy with no `from protocol` it
		//     returned "" and SILENTLY DROPPED the operator's advertise
		//     filter (#2473 failure mode 2). The route-map is already
		//     emitted by generatePolicyOptions, so `route-map out`
		//     filters advertisements without leaking the internal RIB.
		//
		//     #14586 completes this shape: in Junos the BGP export
		//     policy is ALSO what originates the routes its `from
		//     protocol` terms select — there is no separate
		//     redistribution step. The route-map-out alone could only
		//     filter routes already in BGP, so `from protocol
		//     static|direct` advertised nothing (PfxSnt 0). For each
		//     defined policy in the effective export chains (global +
		//     per-neighbor union, bgpExportPolicies14586) the renderer
		//     now ALSO emits `redistribute <proto> route-map
		//     <policy>-<proto>-xpf-redist` per family — the filtered
		//     per-source map (#12065), never an unfiltered
		//     redistribute — keeping `route-map out` as the per-peer
		//     filter. A policy whose terms select no source at a node
		//     (e.g. prefix/community-only) originates nothing there.
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
		// Origination (#14586) follows the UNION of effective chains:
		// redistribution is router-global in FRR (like the Junos BGP
		// RIB), so a policy any neighbor effectively exports originates
		// its selected routes once; the per-peer route-map out remains
		// the per-peer gate.
		// globalExportChain is the ORDERED list of DEFINED policy-statements
		// in `protocols bgp export` — the global export CHAIN applied as a
		// peer-level default to neighbors with no own export. Every entry is
		// preserved and composed in order (#5277); the pre-#5277 code kept only
		// the LAST defined entry, silently dropping a leading reject/attribute
		// policy so prohibited routes were advertised. Bare protocol tokens are
		// still split out to the redistribute path below (unchanged).
		globalExportChain := make([]string, 0, len(bgp.Export))
		// #9667: a bare token's IPv6 routes go into `address-family ipv6
		// unicast`, the only BGP node whose redistribute grammar lists IPv6
		// sources. Collected here, written when that block is opened below.
		// #14586 defined-policy IPv6 origination joins the same block.
		var bgpIPv6Redist strings.Builder
		// #14586: defined-policy origination entries are already
		// de-duplicated by (proto, routeMap) in
		// bgpChainRedistEntriesCluster16868; a bare token (routeMap "") can
		// never collide with a filtered policy entry.
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
				//
				// #9667: route each family to the node that carries it, so a
				// dual-family source renders in both and a single-family one in
				// its own, with no drop warning for the family it lacks. A token
				// that is not a protocol keyword keeps today's single call and its
				// warning; self (`export bgp`) is dropped once, by that call.
				kw, isProto := config.FRRRoutingProtocolKeyword(e)
				fam, _ := config.RedistributionSourceFamilies(kw)
				if !isProto || fam&config.FamilyIPv4 != 0 || kw == "bgp" {
					// Bare-token path: resolveRedistribute (self "bgp")
					// keeps the historical skip-and-warn wording; a bare
					// token has no route-map, so no entry can collide
					// with the filtered policy entries below.
					b.WriteString(m.resolveRedistributeCluster15158(e, policyOptions, "bgp", bgpAcceptDefault, clusterMode))
				}
				if isProto && kw != "bgp" && fam&config.FamilyIPv6 != 0 {
					bgpIPv6Redist.WriteString(m.resolveBGPIPv6RedistributeCluster15158(e, policyOptions, bgpAcceptDefault, clusterMode))
				}
			}
		}
		// #14586: originate the routes selected by every defined policy
		// in the effective export chains, through the filtered
		// per-source maps. Router-level (IPv4 grammar) lines are written
		// now, de-duplicated against the bare-token lines above; IPv6
		// lines join bgpIPv6Redist for the address-family block below,
		// de-duplicated against bare-token IPv6 lines already collected.
		b.WriteString(formatRedistEntries(m.bgpChainRedistEntriesCluster16868(bgp, policyOptions, clusterMode)))
		{
			seen6 := make(map[redistEntry]bool)
			for _, ln := range strings.Split(bgpIPv6Redist.String(), "\n") {
				ln = strings.TrimSpace(ln)
				if ln == "" {
					continue
				}
				// Reconstruct the entry from "redistribute <proto>[ route-map <name>]".
				fields := strings.Fields(ln)
				if len(fields) >= 2 && fields[0] == "redistribute" {
					ent := redistEntry{proto: fields[1]}
					if len(fields) >= 4 && fields[2] == "route-map" {
						ent.routeMap = fields[3]
					}
					seen6[ent] = true
				}
			}
			var extra6 strings.Builder
			for _, ent := range m.bgpChainIPv6RedistEntriesCluster16868(bgp, policyOptions, clusterMode) {
				if seen6[ent] {
					continue
				}
				seen6[ent] = true
				extra6.WriteString(formatRedistEntries([]redistEntry{ent}))
			}
			bgpIPv6Redist.WriteString(indentFRRLines(extra6.String(), " "))
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
		// everything. That absent-attachment accept holds only because every
		// `router bgp` stanza now emits `no bgp ebgp-requires-policy`
		// (#14584): bgpd's RFC 8212 default otherwise discards every inbound
		// update from an eBGP peer with no inbound route-map (and outbound
		// too when it has no outbound route-map), even though the route-map
		// attachment is absent. Behaviour unchanged here (that decision is #7625); the
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

		// Address-family blocks are rendered for declared families and peers
		// whose address determines their family. A global default export still
		// reaches family-less IPv4 peers, which FRR default-activates under
		// ipv4 unicast unless the renderer places them there explicitly.
		var inet4Neighbors, inet4DisabledNeighbors, inet6Neighbors []*config.BGPNeighbor
		// FRR auto-activates neighbors under IPv4 unicast by default. A peer
		// intended only for IPv6 (explicit inet6 or a family-less IPv6 address)
		// must be explicitly disabled here, or FRR claims the IPv4 AF too.
		// Classify only renderable (declared) neighbors (#5518). A remote-as-0
		// neighbor excluded from the declaration loop above must NOT be
		// activated here — vtysh rejects `neighbor <ip> activate` for an
		// undeclared neighbor, failing the whole managed section.
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
			// set instead so it activates under ipv6 unicast (#2941). The
			// same address-family classification applies with NO policy at
			// all (#11564): a family-less IPv6 peer with neither a global
			// default nor its own export/import otherwise lands in NEITHER
			// set. Because FRR default-activates IPv4 peers, keep a family-
			// less IPv6 peer explicitly disabled in IPv4 and activate it
			// only under IPv6.
			isIPv6Peer := strings.Contains(n.Address, ":")
			policyDefault := len(globalExportChain) > 0 || len(globalImportChain) > 0 || hasOwnPolicy
			hasAFNeighborAttributes := n.RouteReflectorClient || n.AllowASIn > 0 || n.RemovePrivateAS || n.DefaultOriginate
			// Router-level emission of these controls configures IPv4 unicast
			// by default in FRR. Keep family-less IPv4 neighbors in an explicit
			// AF block so their existing IPv4 behavior is preserved when the
			// controls are rendered in their actual address family below.
			// DefaultOriginate belongs here too (#14381): without it a
			// family-less IPv4 peer whose only AF attribute was
			// default-originate landed in no set and the default route was
			// never advertised.
			// A cross-family per-neighbor inet declaration is equally
			// unrenderable: fail closed instead of allowing FRR's default AF.
			hasUnrenderableFamily := n.UnsupportedInetSAFI || n.UnsupportedInet6SAFI || n.CrossFamilyInet
			// SAFIs xpf cannot render must not fall through to FRR's default
			// IPv4-unicast activation (the original labeled-unicast miscompile,
			// #11815). Explicitly supported unicast remains independently valid.
			// #16870: a neighbour that will attach the #15157 default-export
			// map must also be classified into the AF that renders that
			// attachment. A family-less, policy-less IPv4 peer otherwise
			// lands in no set while FRR default-activates it in IPv4
			// unicast with no out-map, leaking another peer's originated
			// routes. Definition (bgpUsesDefaultExport15157) and attachment
			// now share this one predicate.
			needsDefaultExport := bgpNeighborNeedsDefaultExport15157(n, bgp, globalExportChain, policyOptions)
			if (n.FamilyInet || ((policyDefault || hasAFNeighborAttributes || needsDefaultExport) && !n.FamilyInet6 && !hasUnrenderableFamily)) && !isIPv6Peer {
				inet4Neighbors = append(inet4Neighbors, n)
			}
			if !n.FamilyInet && (n.FamilyInet6 || isIPv6Peer || hasUnrenderableFamily) {
				inet4DisabledNeighbors = append(inet4DisabledNeighbors, n)
			}
			if n.FamilyInet6 || (!n.FamilyInet && isIPv6Peer && !hasUnrenderableFamily) {
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
		if len(inet4Neighbors) > 0 || len(inet4DisabledNeighbors) > 0 || bgpMaxPaths > 1 || dampeningLine != "" {
			b.WriteString(" !\n address-family ipv4 unicast\n")
			b.WriteString(dampeningLine)
			if bgpMaxPaths > 1 {
				fmt.Fprintf(b, "  maximum-paths %d\n", bgpMaxPaths)
				// FRR `maximum-paths N` enables eBGP multipath only; iBGP
				// multipath requires the separate `maximum-paths ibgp N`
				// command, gated on the explicit `protocols bgp multipath
				// ibgp` knob (#2978).
				if bgp.MultipathIBGP {
					fmt.Fprintf(b, "  maximum-paths ibgp %d\n", bgpMaxPaths)
				}
			}
			for _, n := range inet4DisabledNeighbors {
				fmt.Fprintf(b, "  no neighbor %s activate\n", n.Address)
			}
			for _, n := range inet4Neighbors {
				fmt.Fprintf(b, "  neighbor %s activate\n", n.Address)
				renderBGPRouteReflectorClient14585(b, bgp.LocalAS, n)
				renderBGPAllowASIn(b, n)
				renderBGPRemovePrivate14585(b, bgp.LocalAS, n)

				if n.DefaultOriginate {
					fmt.Fprintf(b, "  neighbor %s default-originate\n", n.Address)
				}
				writeBGPMaximumPrefix15010(b, n.Address, "inet", bgpPrefixLimitInet15010(n))
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
				rm := bgpNeighborExportRef15157(n, bgp, globalExportChain, policyOptions)
				if alias := m.narrowedAliasRef10129(n, bgp, globalExportChain, policyOptions, true); alias != "" {
					rm = alias
				}
				if rm != "" {
					fmt.Fprintf(b, "  neighbor %s route-map %s out\n", n.Address, frrName(rm))
				}
				// Junos `then next-hop self` is lowered per-term INSIDE the
				// export route-map as `set ip/ipv6 next-hop peer-address`
				// (which resolves to self in the outbound direction), NOT the
				// neighbor-wide `neighbor <peer> next-hop-self` knob. The knob
				// ran after route selection and rewrote EVERY route advertised
				// to the peer, widening a term-scoped action to all of the
				// neighbor's routes (#5115). The route-map lowering still
				// overrides iBGP next-hops (the #2977 fix), now scoped to
				// the term, and route-reflector-reflected next-hops when
				// the stanza renders `bgp route-reflector
				// allow-outbound-policy` (#16800). See the `term.NextHop ==
				//
				// Inbound filter (#2490/#5277). Same chain composition as the
				rm = bgpNeighborImportRef(n, bgp, globalImportChain, policyOptions)
				if alias := m.narrowedAliasRef10129(n, bgp, globalImportChain, policyOptions, false); alias != "" {
					rm = alias
				}
				if rm != "" {
					fmt.Fprintf(b, "  neighbor %s route-map %s in\n", n.Address, frrName(rm))
				}
			}
			b.WriteString(" exit-address-family\n")
		}
		// #9667: also opened for bare-token IPv6 redistribution alone. FRR
		// accepts the block with no IPv6 neighbor, and a later IPv6 peer then
		// sees the routes.
		if len(inet6Neighbors) > 0 || bgpMaxPaths > 1 || bgpIPv6Redist.Len() > 0 || dampeningLine != "" {
			b.WriteString(" !\n address-family ipv6 unicast\n")
			b.WriteString(dampeningLine)
			if bgpMaxPaths > 1 {
				fmt.Fprintf(b, "  maximum-paths %d\n", bgpMaxPaths)
				// iBGP multipath (#2978) — see the ipv4 block above.
				if bgp.MultipathIBGP {
					fmt.Fprintf(b, "  maximum-paths ibgp %d\n", bgpMaxPaths)
				}
			}
			b.WriteString(bgpIPv6Redist.String())
			for _, n := range inet6Neighbors {
				fmt.Fprintf(b, "  neighbor %s activate\n", n.Address)
				renderBGPRouteReflectorClient14585(b, bgp.LocalAS, n)
				renderBGPAllowASIn(b, n)
				renderBGPRemovePrivate14585(b, bgp.LocalAS, n)
				if n.DefaultOriginate {
					fmt.Fprintf(b, "  neighbor %s default-originate\n", n.Address)
				}
				writeBGPMaximumPrefix15010(b, n.Address, "inet6", bgpPrefixLimitInet6_15010(n))
				rm := bgpNeighborExportRef15157(n, bgp, globalExportChain, policyOptions)
				if alias := m.narrowedAliasRef10129(n, bgp, globalExportChain, policyOptions, true); alias != "" {
					rm = alias
				}
				if rm != "" {
					fmt.Fprintf(b, "  neighbor %s route-map %s out\n", n.Address, frrName(rm))
				}
				// `then next-hop self` is lowered per-term in the export
				// route-map as `set ip/ipv6 next-hop peer-address`, NOT a
				// neighbor-wide `next-hop-self` knob (#5115) — see the ipv4
				// block above.
				// Inbound filter (#2490/#5277) — see the ipv4 block above.
				rm = bgpNeighborImportRef(n, bgp, globalImportChain, policyOptions)
				if alias := m.narrowedAliasRef10129(n, bgp, globalImportChain, policyOptions, false); alias != "" {
					rm = alias
				}
				if rm != "" {
					fmt.Fprintf(b, "  neighbor %s route-map %s in\n", n.Address, frrName(rm))
				}
			}
			b.WriteString(" exit-address-family\n")
		}

		b.WriteString("exit\n!\n")
	}
}
