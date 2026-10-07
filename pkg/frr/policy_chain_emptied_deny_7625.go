package frr

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// policy_chain_emptied_deny_7625.go — #7625, the EMPTIED half.
//
// filterDefinedPolicies discards any chain member naming a policy-statement
// that is not defined. When EVERY member is discarded the chain empties, and an
// empty chain resolved to "" — so the renderer emitted no `route-map ... in|out`
// line at all.
//
// Per the FRR semantics established in #6807 (stable/10.6 bgpd/bgp_route.c):
//
//	bgp_input_modifier:   rmap = route_map_lookup_by_name(rmap_name);
//	                      if (!rmap) return RMAP_DENY;
//	bgp_output_modifier:  if (!rmap_name) return RMAP_PERMIT;
//	                      rmap = route_map_lookup_by_name(rmap_name);
//	                      if (rmap == NULL) return RMAP_DENY;
//
// an ABSENT attachment is the one shape that PERMITS. So the direction whose
// filter failed hardest — every single member unresolvable — was the direction
// that ended up unfiltered. That is a hole, not a degradation: the config asking
// for the most filtering got the least.
//
// The fix attaches a bounded explicit deny under a reserved name, exactly as
// #6807 does for the adjacent oversized-expansion case. The reference and its
// definition are emitted together, so the #6807 property (every referenced
// route-map name is defined in the same managed section) holds BY CONSTRUCTION
// rather than by the reference being dropped.
//
// SCOPE. Only the EMPTIED shape is changed here. A NARROWED chain (some members
// survive) still renders the surviving subset, unchanged — whether that should
// change depends on a measurement of FRR chain evaluation that #7625 tracks
// separately.
//
// These configs reach the renderer precisely BECAUSE they are legacy or
// peer-synced: the strict commit path rejects an undefined policy reference, so
// the lenient load / peer-sync / rollback path (#1960) is where this fires.

// emptiedChainDenyName is the reserved route-map name carrying the bounded deny
// that an emptied policy chain attaches. It ends in ReservedChainSuffix, the
// namespace the strict commit path forbids operator POLICY-STATEMENTS from
// using (compiler_validate_strict_routing.go).
//
// That namespace is NOT sufficient on its own, and an earlier version of this
// comment wrongly said it was. Strict rejects a policy-statement whose name ENDS
// in the suffix; it does not stop several legally named policies from JOINING
// into this name. composedChainName(["xpf","emptied","chain"]) is byte-identical
// to it. FRR keys route-maps by name in one global namespace and MERGES
// same-named definitions, so such a chain would fuse its permits into this deny
// — reopening the unfiltered-direction hole — and have its own filter corrupted
// by the deny's sequence in the same merge. bgpComposedChainCollision fails the
// apply CLOSED on that derivation; emptiedChainDenyCollision covers the direct
// operator-policy-statement spelling. Both are required: neither sees the other's
// case.
const emptiedChainDenyName = "xpf-emptied-chain" + ReservedChainSuffix

// chainEmptiedByUndefinedPolicies reports whether authored is a non-empty policy
// chain whose every member is a GENUINE GHOST — a name that resolves to nothing
// at all.
//
// protocolTokensAreRedistribute selects the DIRECTION's semantics, and the
// asymmetry is real rather than defensive:
//
//   - EXPORT (true). A BGP `export` list may name bare protocols (`static`,
//     `direct`). They are excluded from the policy chain on purpose because they
//     render as `redistribute <proto>` on a separate path (#2473/#2490). Such a
//     list also filters to empty, but it is not an emptied FILTER: the operator
//     asked to advertise those routes. Attaching a deny there would withdraw
//     every route to the peer — a worse outage than the bug. Keying on "the
//     filtered chain is empty" would do exactly that.
//
//   - IMPORT (false). Inbound has NO redistribute equivalent, so a bare protocol
//     token is not a protocol reference at all — it renders as a route-map name
//     and resolves to nothing. The strict commit path rejects it for exactly
//     that reason (config.TestBGPNeighborImportProtocolTokenRejected), so it can
//     only arrive here leniently — and when it does it is a ghost like any
//     other, and the direction must deny rather than fall open.
func chainEmptiedByUndefinedPolicies(authored []string, po *config.PolicyOptionsConfig, protocolTokensAreRedistribute bool) bool {
	sawGhost := false
	for _, n := range authored {
		if n == "" {
			continue
		}
		if isDefinedPolicyStatement(n, po) {
			// Not emptied — this member survives and renders normally.
			return false
		}
		if protocolTokensAreRedistribute &&
			(knownRedistProtocol(n) || knownRedistProtocol(junosProtocolToFRR7625(n))) {
			// Redistribute meaning, not a failed filter.
			return false
		}
		sawGhost = true
	}
	return sawGhost
}

// junosProtocolToFRR7625 maps the Junos spelling of directly-connected routes
// onto the FRR keyword, mirroring resolveRedistribute's normalization so
// `export direct` is recognized as a protocol token here too (#2144).
func junosProtocolToFRR7625(name string) string {
	if name == "direct" {
		return "connected"
	}
	return name
}

// bgpChainRefOrEmptiedDeny resolves an attachment to the route-map name it must
// reference. It returns the normal chain reference when the chain resolves, the
// reserved emptied-chain deny when every authored member is a ghost, and "" when
// there was no filter to begin with (no attachment — the correct permit).
func bgpChainRefOrEmptiedDeny(authored, resolved []string, po *config.PolicyOptionsConfig, protocolTokensAreRedistribute bool) string {
	if rm := bgpRouteMapRef(resolved); rm != "" {
		return rm
	}
	if !chainEmptiedByUndefinedPolicies(authored, po, protocolTokensAreRedistribute) {
		return ""
	}
	return emptiedChainDenyName
}

// bgpNeighborAuthoredExport / bgpNeighborAuthoredImport return the chain the
// OPERATOR wrote for this neighbor, before any defined-filtering. They mirror
// bgpNeighborExportChain/bgpNeighborImportChain's most-specific-wins resolution
// exactly: a neighbor with ANY own entry suppresses the global default, so the
// authored chain is its own list; otherwise it inherits the global one.
func bgpNeighborAuthoredExport(n *config.BGPNeighbor, bgp *config.BGPConfig) []string {
	if hasNonEmptyPolicy(n.Export) {
		return n.Export
	}
	if bgp == nil {
		return nil
	}
	return bgp.Export
}

func bgpNeighborAuthoredImport(n *config.BGPNeighbor, bgp *config.BGPConfig) []string {
	if hasNonEmptyPolicy(n.Import) {
		return n.Import
	}
	if bgp == nil {
		return nil
	}
	return bgp.Import
}

// bgpNeighborExportRef / bgpNeighborImportRef are what the four neighbor render
// sites call: the effective route-map name for the attachment, "" for none.
func bgpNeighborExportRef(n *config.BGPNeighbor, bgp *config.BGPConfig, globalExportChain []string, po *config.PolicyOptionsConfig) string {
	return bgpChainRefOrEmptiedDeny(
		bgpNeighborAuthoredExport(n, bgp),
		bgpNeighborExportChain(n, globalExportChain, po), po, true)
}

func bgpNeighborImportRef(n *config.BGPNeighbor, bgp *config.BGPConfig, globalImportChain []string, po *config.PolicyOptionsConfig) string {
	return bgpChainRefOrEmptiedDeny(
		bgpNeighborAuthoredImport(n, bgp),
		bgpNeighborImportChain(n, globalImportChain, po), po, false)
}

// bgpUsesEmptiedChainDeny reports whether any neighbor in bgp resolves to the
// emptied-chain deny, in either direction.
func bgpUsesEmptiedChainDeny(bgp *config.BGPConfig, po *config.PolicyOptionsConfig) bool {
	if bgp == nil {
		return false
	}
	globalExportChain := bgpGlobalExportChain(bgp, po)
	globalImportChain := bgpGlobalImportChain(bgp, po)
	for _, n := range bgp.Neighbors {
		if n == nil {
			continue
		}
		if bgpNeighborExportRef(n, bgp, globalExportChain, po) == emptiedChainDenyName {
			return true
		}
		if bgpNeighborImportRef(n, bgp, globalImportChain, po) == emptiedChainDenyName {
			return true
		}
	}
	return false
}

// renderEmptiedChainDeny emits the DEFINITION of the emptied-chain deny when any
// attachment in fc references it (default instance or any VRF), and "" when none
// does — so a config with no emptied chain renders byte-identically to before.
//
// It is emitted OUTSIDE the `fc.PolicyOptions != nil` guard that wraps the other
// route-map renderers on purpose: a nil PolicyOptions makes EVERY authored name
// a ghost, which is exactly when the deny is most needed and when skipping the
// definition would leave the reference dangling.
func (m *Manager) renderEmptiedChainDeny(fc *FullConfig) string {
	if fc == nil {
		return ""
	}
	used := bgpUsesEmptiedChainDeny(fc.BGP, fc.PolicyOptions)
	if !used {
		for _, inst := range fc.Instances {
			if bgpUsesEmptiedChainDeny(inst.BGP, fc.PolicyOptions) {
				used = true
				break
			}
		}
	}
	if !used {
		return ""
	}
	slog.Warn("BGP policy chain resolved to nothing: every policy-statement it named is "+
		"undefined, so the direction the operator filtered would otherwise be left "+
		"UNFILTERED (an absent route-map attachment permits in FRR). Attaching an "+
		"explicit deny instead — routes in that direction are withdrawn until the "+
		"missing policy-statements are restored",
		"route-map", emptiedChainDenyName)
	m.noteQuarantined(emptiedChainDenyName)
	var b strings.Builder
	b.WriteString(renderQuarantineDenyRouteMap(emptiedChainDenyName))
	b.WriteString("!\n")
	return b.String()
}

// emptiedChainDenyCollision is the render-side fail-closed guard for the
// reserved deny name, mirroring bgpComposedChainCollision (#5277) and
// redistProtocolMapCollision. FRR MERGES two same-named route-map
// definitions, so an operator policy-statement of this exact name would fuse its
// (possibly permit) sequences into this deny and reopen the very hole the deny
// closes. The strict commit path already forbids the ReservedChainSuffix
// namespace; this covers the lenient load / peer-sync path that reaches the
// renderer without that gate.
func emptiedChainDenyCollision(fc *FullConfig) error {
	if fc == nil || fc.PolicyOptions == nil {
		return nil
	}
	if _, ok := fc.PolicyOptions.PolicyStatements[emptiedChainDenyName]; !ok {
		return nil
	}
	if !bgpUsesEmptiedChainDeny(fc.BGP, fc.PolicyOptions) {
		used := false
		for _, inst := range fc.Instances {
			if bgpUsesEmptiedChainDeny(inst.BGP, fc.PolicyOptions) {
				used = true
				break
			}
		}
		if !used {
			return nil
		}
	}
	return fmt.Errorf(
		"the reserved emptied-chain deny route-map %q collides with an operator "+
			"policy-statement of that exact name; FRR merges same-named route-maps, so "+
			"the operator policy's sequences would fuse into the deny and could reopen "+
			"the unfiltered-direction hole it closes — refusing to render (rename the "+
			"policy-statement, #7625)", emptiedChainDenyName)
}
