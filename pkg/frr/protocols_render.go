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
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// bgpNeighborBFDMultihop14587 reports whether bgpd will key neighbor n's
// BFD session as multihop in bfdd (#14587). Mirrors FRR's
// PEER_IS_MULTIHOP (bgpd/bgp_bfd.h): an iBGP peer that is not on a shared
// network, or an eBGP peer with ebgp-multihop configured. xpf cannot know
// shared_network at render time (it is learned when the session's nexthop
// resolves), and Junos bfd-liveness-detection on a BGP neighbor is
// overwhelmingly the loopback/iBGP design, so an iBGP neighbor is treated
// as multihop-conservative: keying multihop for a directly-connected iBGP
// peer still matches bgpd's session because bfdd matches on
// (peer, local-address, multihop, vrf) and bgpd installs its session with
// the update-source as local address. The alternative (plain peer) is the
// proven orphan: bgpd's dynamic multihop session runs FRR defaults and
// the configured timers never apply.
func bgpNeighborBFDMultihop14587(n *config.BGPNeighbor, routerAS uint32) bool {
	effectiveLocalAS := n.LocalAS
	if effectiveLocalAS == 0 {
		effectiveLocalAS = routerAS
	}
	if n.PeerAS != 0 && effectiveLocalAS == n.PeerAS {
		return true // iBGP
	}
	return n.MultihopTTL > 0 // ebgp-multihop
}

// bgpPrefixLimitRender15010 carries the full Junos prefix-limit model
// (#15010) into the FRR renderer.
type bgpPrefixLimitRender15010 struct {
	limit    int
	teardown bool
	pct      int
	idle     int
	forever  bool
}

func bgpPrefixLimitInet15010(n *config.BGPNeighbor) bgpPrefixLimitRender15010 {
	return bgpPrefixLimitRender15010{limit: n.PrefixLimitInet, teardown: n.PrefixLimitTeardownInet, pct: n.PrefixLimitTeardownPctInet, idle: n.PrefixLimitIdleTimeoutInet, forever: n.PrefixLimitIdleForeverInet}
}

func bgpPrefixLimitInet6_15010(n *config.BGPNeighbor) bgpPrefixLimitRender15010 {
	return bgpPrefixLimitRender15010{limit: n.PrefixLimitInet6, teardown: n.PrefixLimitTeardownInet6, pct: n.PrefixLimitTeardownPctInet6, idle: n.PrefixLimitIdleTimeoutInet6, forever: n.PrefixLimitIdleForeverInet6}
}

// writeBGPMaximumPrefix15010 renders Junos prefix-limit semantics in FRR
// 10.6 grammar (neighbour maximum-prefix in bgp_vty.c):
//   - no teardown (Junos default): `maximum-prefix N warning-only`
//     (log-only; bgpd returns without CEASE in warning mode)
//   - teardown, no idle-timeout: `maximum-prefix N [pct]` (CEASE, no
//     pmax_restart timer; peer stays suppressed until `clear bgp
//     neighbor` — Junos re-establishes "in a short time", but FRR has
//     no sub-minute restart value, so this maps to manual-clear; see
//     docs/log/15010.md)
//   - teardown + idle-timeout minutes: `... [pct] restart M`
//   - teardown + idle-timeout forever: `maximum-prefix N [pct]` (same
//     FRR shape as no-idle; both are no-restart/manual-clear in FRR)
//
// Out-of-range typed operands from tolerant construction are clamped
// by omission of that operand (warn), never passed verbatim to vtysh:
// a rejected line fails the whole managed-section reload.
func writeBGPMaximumPrefix15010(b *strings.Builder, address, family string, p bgpPrefixLimitRender15010) {
	if p.limit <= 0 {
		return
	}
	if uint64(p.limit) > uint64(^uint32(0)) {
		slog.Warn("frr: omitting invalid BGP maximum-prefix value (#11793)",
			"neighbor", sanitizeFRRValue(address), "family", family, "maximum", p.limit)
		return
	}
	if !p.teardown {
		fmt.Fprintf(b, "  neighbor %s maximum-prefix %d warning-only\n", address, p.limit)
		return
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "  neighbor %s maximum-prefix %d", address, p.limit)
	if p.pct != 0 {
		if p.pct < 1 || p.pct > 100 {
			slog.Warn("frr: omitting out-of-range BGP maximum-prefix threshold (#15010)",
				"neighbor", sanitizeFRRValue(address), "family", family, "threshold", p.pct)
		} else {
			fmt.Fprintf(&sb, " %d", p.pct)
		}
	}
	if !p.forever && p.idle != 0 {
		if p.idle < 1 || p.idle > 65535 {
			slog.Warn("frr: omitting out-of-range BGP maximum-prefix restart (#15010)",
				"neighbor", sanitizeFRRValue(address), "family", family, "restart", p.idle)
		} else {
			fmt.Fprintf(&sb, " restart %d", p.idle)
		}
	}
	sb.WriteString("\n")
	b.WriteString(sb.String())
}

// ospfAreaIdentity11400 compares FRR's two valid spellings of a 32-bit area
// ID as the same area. Invalid tolerant-path values stay keyed by raw spelling.
func ospfAreaIdentity11400(id string) string {
	if config.ValidateOSPFArea(id) == nil {
		if ip := net.ParseIP(id); ip != nil && ip.To4() != nil {
			return strconv.FormatUint(uint64(binary.BigEndian.Uint32(ip.To4())), 10)
		}
		if value, err := strconv.ParseUint(id, 10, 32); err == nil {
			return strconv.FormatUint(value, 10)
		}
	}
	return "raw:" + id
}

type ospfRenderArea11400 struct {
	key string
	id  string
}

func warnOSPFInterfaceConflict12186(protocol, name string, fields []string) {
	if len(fields) == 0 {
		return
	}
	slog.Warn("frr: conflicting OSPF interface settings; retaining first present values (#12186)",
		"protocol", protocol,
		"interface", sanitizeFRRValue(name),
		"fields", strings.Join(fields, ", "))
}

// validFRROSPFArea reports whether id is renderable as an FRR area operand
// (#9820): exactly what the commit gate accepts (ValidateOSPFArea,
// incl. its mapped + padding arms) AND a single FRR token. The token
// check is defense-in-depth against validating-normalized/emitting-raw
// drift (the #9493 virtual-link belt carries the same pair).
func validFRROSPFArea(id string) bool {
	return config.ValidateOSPFArea(id) == nil && config.FRRSingleToken(id)
}

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
	return m.generateProtocolsWithQNH11447(ospf, ospfv3, bgp, rip, isis, vrfName, ecmpMaxPaths, policyOptions, bgpAcceptDefault, nil, shared...)
}

func (m *Manager) generateProtocolsWithQNH11447(ospf *config.OSPFConfig, ospfv3 *config.OSPFv3Config, bgp *config.BGPConfig, rip *config.RIPConfig, isis *config.ISISConfig, vrfName string, ecmpMaxPaths int, policyOptions *config.PolicyOptionsConfig, bgpAcceptDefault map[string]bool, qnhMetrics *qnhMetricScope11447, shared ...*bfdSection) string {
	return m.generateProtocolsCluster15158(ospf, ospfv3, bgp, rip, isis, vrfName, ecmpMaxPaths, policyOptions, bgpAcceptDefault, qnhMetrics, false, shared...)
}

// generateProtocolsCluster15158 is generateProtocolsWithQNH11447 with the
// #15158 cluster flag: bare `redistribute static` attachments are rewritten
// to the deny-tag guard map. Only buildManagedSection passes clusterMode,
// from fc.ClusterMode; every direct caller keeps the historical render.
func (m *Manager) generateProtocolsCluster15158(ospf *config.OSPFConfig, ospfv3 *config.OSPFv3Config, bgp *config.BGPConfig, rip *config.RIPConfig, isis *config.ISISConfig, vrfName string, ecmpMaxPaths int, policyOptions *config.PolicyOptionsConfig, bgpAcceptDefault map[string]bool, qnhMetrics *qnhMetricScope11447, clusterMode bool, shared ...*bfdSection) string {
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

	m.renderOSPF16125(&b, ospf, vrfSuffix, ecmpMaxPaths, policyOptions, bgpAcceptDefault, qnhMetrics, clusterMode, bfd)

	m.renderOSPFv316125(&b, ospfv3, vrfSuffix, ecmpMaxPaths, policyOptions, clusterMode, qnhMetrics, bfd)

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
	// ApplyFull rejects cross-group duplicate addresses. Do not collapse entries
	// here: same-group duplicates can be separate policy-bearing AST fragments.
	var validNeighbors []*config.BGPNeighbor
	if bgp != nil {
		validNeighbors = make([]*config.BGPNeighbor, 0, len(bgp.Neighbors))
		for _, n := range bgp.Neighbors {
			// #16572: a disabled neighbor (own `disable` or inherited
			// group disable, or whole-protocol disable) never renders.
			if bgp.Disable || n.Disable {
				continue
			}
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
			// #14977 (D33-05): a configured TCP-MD5 password that is not
			// a single vtysh token must fail closed HERE, at the same
			// single exclusion point, not at the declaration site.
			// #9050 omitted only the `password` line and kept the
			// neighbor, reasoning that the adjacency then "fails to
			// authenticate" — true only when the PEER requires MD5. A
			// peer that does not (the common misconfiguration, and the
			// exact tolerant-load scenario) establishes an
			// UNAUTHENTICATED session and exchanges routes. Excluding
			// the neighbor confines the damage exactly as #9050
			// intended — that one adjacency does not come up — without
			// the unauthenticated-session window, and every loop below
			// inherits the exclusion so none can activate it.
			if n.AuthPassword.Reveal() != "" {
				if _, ok := authTokenOrOmit("bgp", &n.AuthPassword); !ok {
					slog.Warn("frr: omitting BGP neighbor with an unrenderable authentication password; refusing to establish it unauthenticated (#14977)",
						"neighbor", sanitizeFRRValue(n.Address))
					continue
				}
			}
			validNeighbors = append(validNeighbors, n)
		}
	}

	m.renderBGP16125(&b, bgp, validNeighbors, vrfName, vrfSuffix, ecmpMaxPaths, policyOptions, bgpAcceptDefault, qnhMetrics, clusterMode, bfd)
	// #17735: zebra fixes IS-IS at 115 while the managed RIP stanza is
	// pinned to 100. Junos prefers IS-IS (15/18) over RIP (100), so a
	// tolerant-loaded same-table pair would install the wrong protocol.
	// Strict commit rejects this pair; withhold RIP on the no-brick path
	// and retain IS-IS, the Junos-preferred protocol.
	if config.RIPISISDistanceConflict(rip, isis) {
		slog.Warn("frr: withholding RIP because its distance 100 would beat fixed-distance IS-IS 115, reversing Junos IS-IS 15/18 < RIP 100 (#17735)")
		rip = nil
	}

	m.renderRIP16125(&b, rip, vrfSuffix, policyOptions, clusterMode, qnhMetrics)

	m.renderISIS16125(&b, isis, vrfSuffix, policyOptions, clusterMode, qnhMetrics, bfd)

	accumulateBGPBFDPeers16125(bgp, validNeighbors, vrfName, bfd)

	// In local-fallback mode (no shared accumulator from the manager) emit
	// the single `bfd` block here, preserving historical single-instance
	// output. In shared mode the manager renders one global block instead.
	if emitLocal {
		b.WriteString(bfd.render())
	}

	return b.String()
}
