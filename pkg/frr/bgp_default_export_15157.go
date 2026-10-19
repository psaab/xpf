package frr

// bgp_default_export_15157.go — #15157 (B08-02).
//
// #14586 originates the routes a neighbour's export policy selects by
// emitting router-global `redistribute <proto> route-map
// <policy>-<proto>-xpf-redist`. Redistribution is router-global in FRR,
// so those routes enter the SHARED BGP RIB of the instance — every
// neighbour of the instance can then advertise them, not just the peer
// whose export originated them.
//
// Junos does not leak this way. A neighbour with NO export policy (or
// whose export chain falls off its end) advertises under the Junos
// default export policy, which permits only active routes in the BGP
// RIB itself — i.e. routes whose source-protocol is bgp — and denies
// everything else, including routes redistributed (originated) into
// the RIB by ANOTHER neighbour's export. This file restores that
// boundary without touching the per-peer gates that already exist:
//
//  1. When any #14586 origination exists in an instance, every
//     neighbour/AF whose effective export is EMPTY (no attachment
//     today) gets the generated `xpf-default-export-xpf-chain`
//     route-map: permit `match source-protocol bgp`, then deny. The
//     name ends in ReservedChainSuffix like the other generated chain
//     maps; it is not derivable by composedChainName (a single member
//     never composes), and the collision belt below refuses the apply
//     if an operator policy forges the exact name.
//  2. The #2998 plain `permit` tail of EXPORT maps (single via
//     renderRouteMapForPolicyExport15157, composed via
//     renderComposedRouteMapExport15157) becomes, in an instance with
//     origination, the same carved pair — permit BGP-sourced, deny
//     the rest — so a redistributed route an export term did not
//     select cannot ride the tail out of a neighbour that DOES have
//     an export whose chain ends without a final reject. Import maps
//     keep the plain permit; explicit accept/reject defaults are
//     untouched; instances with no origination render byte-identically.

import (
	"fmt"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// bgpDefaultExportName15157 is the reserved generated route-map that
// carries the Junos default export (permit BGP-sourced, deny rest) for
// neighbours with an empty effective export in an instance that has
// #14586 origination. It ends in ReservedChainSuffix, the namespace the
// strict commit path forbids operator policy-statements from using;
// the render-side collision belt below covers the lenient path exactly
// as emptiedChainDenyCollision does for the #7625 deny.
const bgpDefaultExportName15157 = "xpf-default-export" + ReservedChainSuffix

// bgpInstanceHasOrigination15157 reports whether this BGP instance
// originates any route via #14586: the union of effective export
// chains selects at least one non-self, node-fitting source at either
// family node. A policy whose only source is bgp itself originates
// nothing (self-drop), so it does not trigger the carve.
func bgpInstanceHasOrigination15157(bgp *config.BGPConfig, po *config.PolicyOptionsConfig) bool {
	if bgp == nil || po == nil {
		return false
	}
	policies := bgpExportPolicies14586(bgp, po)
	if len(policies) == 0 {
		return false
	}
	m := &Manager{}
	return len(m.bgpPolicyRedistEntries14586(policies, po)) > 0 ||
		len(m.bgpPolicyIPv6RedistEntries14586(policies, po)) > 0
}

// bgpExportBGPOnlyDefault15157 is the per-instance trigger shared by
// every #15157 carve: origination exists in this instance.
func bgpExportBGPOnlyDefault15157(bgp *config.BGPConfig, po *config.PolicyOptionsConfig) bool {
	return bgpInstanceHasOrigination15157(bgp, po)
}

// bgpNeighborNeedsDefaultExport15157 reports whether neighbour n (in
// bgp) must attach the generated default-export map: origination
// exists in the instance AND the neighbour's effective export resolves
// to no attachment at all (empty authored chain, or an authored chain
// of bare protocol tokens only — those render as redistribute verbs,
// never as a route-map out, so the Junos default export still applies
// to what the peer advertises from the shared RIB; the bare-token
// redistribution itself is operator-authored and unchanged).
//
// A chain emptied by ghost policies resolves to the #7625 deny, which
// already denies everything — strictly stronger than the default
// export — so it does NOT need (and must not be overridden by) the
// default-export map.
func bgpNeighborNeedsDefaultExport15157(n *config.BGPNeighbor, bgp *config.BGPConfig, globalExportChain []string, po *config.PolicyOptionsConfig) bool {
	if n == nil || bgp == nil {
		return false
	}
	if !bgpExportBGPOnlyDefault15157(bgp, po) {
		return false
	}
	ref := bgpNeighborExportRef(n, bgp, globalExportChain, po)
	return ref == ""
}

// bgpNeighborExportRef15157 is the export attachment the render sites
// use: the normal chain reference (or the #7625 emptied deny), else the
// generated default-export map when #15157 requires it, else "".
func bgpNeighborExportRef15157(n *config.BGPNeighbor, bgp *config.BGPConfig, globalExportChain []string, po *config.PolicyOptionsConfig) string {
	if ref := bgpNeighborExportRef(n, bgp, globalExportChain, po); ref != "" {
		return ref
	}
	if bgpNeighborNeedsDefaultExport15157(n, bgp, globalExportChain, po) {
		return bgpDefaultExportName15157
	}
	return ""
}

// bgpUsesDefaultExport15157 reports whether any neighbour in bgp
// attaches the generated default-export map.
func bgpUsesDefaultExport15157(bgp *config.BGPConfig, po *config.PolicyOptionsConfig) bool {
	if bgp == nil {
		return false
	}
	globalExportChain := bgpGlobalExportChain(bgp, po)
	for _, n := range bgp.Neighbors {
		if bgpNeighborNeedsDefaultExport15157(n, bgp, globalExportChain, po) {
			return true
		}
	}
	return false
}

// renderBGPDefaultExport15157 emits the DEFINITION of the generated
// default-export map when any attachment in fc references it (default
// instance or any VRF), and "" when none does — so a config with no
// #14586 origination, or where every neighbour carries its own export,
// renders byte-identically to before. The definition is the Junos
// default export policy: permit routes sourced from BGP itself, deny
// everything else (redistributed/originated non-BGP routes included).
func (m *Manager) renderBGPDefaultExport15157(fc *FullConfig) string {
	if fc == nil {
		return ""
	}
	used := bgpUsesDefaultExport15157(fc.BGP, fc.PolicyOptions)
	if !used {
		for _, inst := range fc.Instances {
			if bgpUsesDefaultExport15157(inst.BGP, fc.PolicyOptions) {
				used = true
				break
			}
		}
	}
	if !used {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "route-map %s permit 10\n", frrName(bgpDefaultExportName15157))
	b.WriteString(" match source-protocol bgp\n")
	b.WriteString("exit\n")
	fmt.Fprintf(&b, "route-map %s deny 20\n", frrName(bgpDefaultExportName15157))
	b.WriteString("exit\n")
	b.WriteString("!\n")
	return b.String()
}

// bgpDefaultExportCollision15157 is the render-side fail-closed guard
// for the generated default-export name, mirroring
// emptiedChainDenyCollision (#7625). FRR merges same-named route-map
// definitions, so an operator policy-statement of this exact name
// would fuse its (possibly permit) sequences into the default export
// and reopen the cross-neighbour leak. The strict commit path already
// forbids the ReservedChainSuffix namespace; this covers the lenient
// load / peer-sync path that reaches the renderer without that gate.
// It fires only when the map is actually referenced, exactly like the
// #7625 belt.
func bgpDefaultExportCollision15157(fc *FullConfig) error {
	if fc == nil || fc.PolicyOptions == nil {
		return nil
	}
	if _, ok := fc.PolicyOptions.PolicyStatements[bgpDefaultExportName15157]; !ok {
		return nil
	}
	used := bgpUsesDefaultExport15157(fc.BGP, fc.PolicyOptions)
	if !used {
		for _, inst := range fc.Instances {
			if bgpUsesDefaultExport15157(inst.BGP, fc.PolicyOptions) {
				used = true
				break
			}
		}
	}
	if !used {
		return nil
	}
	return fmt.Errorf(
		"the reserved default-export route-map %q collides with an operator "+
			"policy-statement of that exact name; FRR merges same-named route-maps, so "+
			"the operator policy's sequences would fuse into the Junos default export "+
			"and could reopen the cross-neighbour route leak it closes — refusing to "+
			"render (rename the policy-statement, #15157)", bgpDefaultExportName15157)
}

// bgpExportOriginationInstances15157 returns the set of BGP instances
// (by pointer identity of their *config.BGPConfig) in fc that have
// #14586 origination. generatePolicyOptions renders ALL policies once
// for the whole section, but the #15157 carved tail is a per-instance
// property: a policy used as an export in an originating instance and
// only as an import (or in a non-originating instance) elsewhere must
// carve only where origination exists. The collectors below therefore
// key the carve by policy name over originating instances only.
func bgpAnyInstanceHasOrigination15157(fc *FullConfig) bool {
	if fc == nil {
		return false
	}
	if bgpInstanceHasOrigination15157(fc.BGP, fc.PolicyOptions) {
		return true
	}
	for _, inst := range fc.Instances {
		if bgpInstanceHasOrigination15157(inst.BGP, fc.PolicyOptions) {
			return true
		}
	}
	return false
}
