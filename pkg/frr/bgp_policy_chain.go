// bgp_policy_chain.go resolves ordered BGP import/export policy CHAINS
// into FRR route-map references and derives the composed route-maps a
// multi-policy chain needs (#5277), including the fail-closed collision
// guard against operator route-map names.
//
// Split out of policy_render.go (#6424) as a pure code-motion refactor;
// the emitted frr.conf is byte-identical.
//
// Symbols:
//   - ReservedChainSuffix
//   - hasNonEmptyPolicy, filterDefinedPolicies
//   - bgpGlobalExportChain, bgpGlobalImportChain
//   - bgpNeighborExportChain, bgpNeighborImportChain
//   - composedChainName, bgpRouteMapRef
//   - collectBGPRouteMapPolicies, bgpEffectiveChains
//   - collectBGPComposedChains, bgpComposedChainCollision
//   - renderComposedBGPChains, equalStringSlice
package frr

import (
	"fmt"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// ReservedChainSuffix is the route-map name suffix xpf RESERVES for the
// composed BGP policy-chain route-maps the renderer derives for an ordered
// import/export policy list of length >= 2 (composedChainName below). FRR keys
// route-maps by NAME in a single GLOBAL namespace, so a composed name that
// collided with an operator policy-statement would fuse the two objects and
// could silently change the operator's filtering — the render-side guard
// bgpComposedChainCollision fails the whole apply CLOSED on any collision
// (#5277). The canonical constant lives in pkg/config (config.ReservedChainSuffix),
// which the commit-time strict validator validatePolicyReservedChainNameStrict
// reserves (#5442); this re-export sources the same literal so the composed-name
// derivation here and the config gate cannot drift (mirrors the redist pattern,
// where frr references config.ReservedRedistSuffix directly).
const ReservedChainSuffix = config.ReservedChainSuffix

// hasNonEmptyPolicy reports whether names holds at least one non-empty entry.
// It replaces the old lastNonEmpty("") != "" idiom for "does this neighbor set
// its own import/export?", independent of whether the entries resolve to
// defined policy-statements (a bare/undefined own ref still suppresses the
// global default, matching the pre-#5277 override precedence).
func hasNonEmptyPolicy(names []string) bool {
	for _, n := range names {
		if n != "" {
			return true
		}
	}
	return false
}

// filterDefinedPolicies returns, in order, the non-empty entries of names that
// resolve to a DEFINED policy-statement. Bare protocol tokens and undefined
// refs are dropped: a bare export token takes the redistribute path (#2473),
// and an undefined ref must never render a dangling `route-map <name> in|out`
// (#2473/#2490/#2539). The surviving slice is the ordered Junos policy CHAIN
// the renderer composes (#5277).
//
// #6807 CORRECTION — read this before reasoning about the drop. The #2473/#2490
// comments said a dangling route-map resolves to PERMIT-ALL. It does not. FRR
// stable/10.6 bgpd/bgp_route.c returns RMAP_DENY when route_map_lookup_by_name
// fails (bgp_input_modifier, bgp_output_modifier); only an ABSENT attachment
// permits. So the direction of this drop is the opposite of what those comments
// claim: dropping the reference is what yields permit-all, and emitting it
// would deny.
//
// #7625 RESOLVED THE EMPTIED HALF. This function still returns only the
// surviving subset, but the renderer no longer treats an EMPTY result as "no
// attachment": when every authored member is a ghost, the attachment sites
// reference a bounded explicit deny instead (bgpNeighborImportRef /
// bgpNeighborExportRef, policy_chain_emptied_deny_7625.go). A NARROWED chain --
// some members survive -- is still rendered as the surviving subset here,
// pending a measurement of FRR chain evaluation that #7625 tracks separately.
// Do not read the drop below as "the reference is safely discarded".
//
// #6807 fixes the sibling case where the policy IS authored and the RENDERER
// omitted it (an over-ceiling expansion): there the name is defined by a
// bounded explicit deny rather than left to dangle.
func filterDefinedPolicies(names []string, po *config.PolicyOptionsConfig) []string {
	out := make([]string, 0, len(names))
	for _, n := range names {
		if n != "" && isDefinedPolicyStatement(n, po) {
			out = append(out, n)
		}
	}
	return out
}

// bgpGlobalExportChain / bgpGlobalImportChain return the ordered chain of
// DEFINED policy-statements set as a global `protocols bgp export`/`import`
// default. Bare export protocol tokens are excluded here (they render as a
// `redistribute <proto>` verb on their own path, unchanged); import has no
// redistribute equivalent so only defined policy-statements survive (#2490).
func bgpGlobalExportChain(bgp *config.BGPConfig, po *config.PolicyOptionsConfig) []string {
	if bgp == nil {
		return nil
	}
	return filterDefinedPolicies(bgp.Export, po)
}

func bgpGlobalImportChain(bgp *config.BGPConfig, po *config.PolicyOptionsConfig) []string {
	if bgp == nil {
		return nil
	}
	return filterDefinedPolicies(bgp.Import, po)
}

// bgpNeighborExportChain resolves a BGP neighbor's effective ORDERED export
// policy chain, applying Junos most-specific-wins: the neighbor's OWN export
// list (the compiler resolves group-vs-neighbor level precedence into n.Export,
// #5277) overrides the global default. A neighbor that sets ANY own export
// entry — even a bare/undefined one — suppresses the global default for that
// peer (pre-#5277 override precedence); its chain is then the defined subset of
// its own list. An empty own list falls back to the global chain.
func bgpNeighborExportChain(n *config.BGPNeighbor, globalExportChain []string, po *config.PolicyOptionsConfig) []string {
	if hasNonEmptyPolicy(n.Export) {
		return filterDefinedPolicies(n.Export, po)
	}
	return globalExportChain
}

// bgpNeighborImportChain is the inbound symmetric of bgpNeighborExportChain
// (#2490/#5277). Import has no redistribute shorthand, so the own-list subset is
// simply its defined policy-statements.
func bgpNeighborImportChain(n *config.BGPNeighbor, globalImportChain []string, po *config.PolicyOptionsConfig) []string {
	if hasNonEmptyPolicy(n.Import) {
		return filterDefinedPolicies(n.Import, po)
	}
	return globalImportChain
}

// composedChainName derives the FRR route-map name for an ordered BGP policy
// chain of length >= 2. The member policy names (a chain never contains an
// empty entry) are joined and suffixed with the reserved ReservedChainSuffix so
// the composed object lives in a namespace distinct from operator route-maps;
// bgpComposedChainCollision fails the apply closed on the rare residual
// collision (#5277).
func composedChainName(chain []string) string {
	return strings.Join(chain, "-") + ReservedChainSuffix
}

// bgpRouteMapRef resolves an ordered policy chain to the FRR route-map name a
// neighbor/address-family line references. A single-policy chain references the
// standalone per-policy route-map generatePolicyOptions already emits
// (byte-identical to the pre-#5277 render); a chain of >= 2 references the
// composed route-map (composedChainName) that renderComposedRouteMap emits. An
// empty chain yields "" (no `route-map` line). The chain is pre-filtered to
// DEFINED policy-statements, so the returned name never dangles.
//
// CALLERS: the neighbor attachment sites do NOT call this directly -- they go
// through bgpNeighborImportRef / bgpNeighborExportRef, which map the "" case for
// a chain that EMPTIED (every authored member undefined) onto the #7625 bounded
// deny. Calling this directly reintroduces the permit-all hole for that case.
func bgpRouteMapRef(chain []string) string {
	switch len(chain) {
	case 0:
		return ""
	case 1:
		return chain[0]
	default:
		return composedChainName(chain)
	}
}

// collectBGPRouteMapPolicies records, into dst, every DEFINED
// policy-statement name that is rendered as a BGP `route-map in`/`out`
// for any neighbor in bgp. These are exactly the policies whose Junos
// fall-off-the-end default action is ACCEPT: a BGP import OR export policy
// that reaches its end without a terminating term falls through to the BGP
// default policy, which permits the route (vSRX advertises/accepts the
// unmatched route unmodified). This is unlike a redistribute /
// forwarding-table export policy, whose protocol default is REJECT
// (#2998).
//
// The set records only a SINGLE-policy chain's standalone route-map: a chain of
// one references the per-policy route-map generatePolicyOptions emits, whose
// trailing default must be the BGP-accept permit. A MULTI-policy chain (#5277)
// references a COMPOSED route-map (renderComposedRouteMap) that carries the
// BGP-accept fall-off default INTERNALLY, so the composed members' standalone
// route-maps are not the referenced objects and must not be forced to permit
// here (a member also used single-policy / as a redistribute elsewhere is
// recorded by THAT reference). globalExport/globalImport chains are resolved the
// same way the BGP renderer resolves them.
func collectBGPRouteMapPolicies(bgp *config.BGPConfig, po *config.PolicyOptionsConfig, dst map[string]bool) {
	if bgp == nil || po == nil {
		return
	}
	globalExportChain := bgpGlobalExportChain(bgp, po)
	globalImportChain := bgpGlobalImportChain(bgp, po)
	// A single-policy chain references the standalone route-map by name; only
	// those need the #2998 trailing-permit default recorded.
	addSingle := func(chain []string) {
		if len(chain) == 1 {
			dst[chain[0]] = true
		}
	}
	for _, n := range bgp.Neighbors {
		addSingle(bgpNeighborExportChain(n, globalExportChain, po))
		addSingle(bgpNeighborImportChain(n, globalImportChain, po))
	}
}

// bgpEffectiveChains yields every neighbor's effective export and import chain
// for bgp (each already Junos most-specific-resolved and defined-filtered). The
// visit callback receives each chain; callers filter by length. Shared by the
// composed-route-map collector and the collision guard so the two never compute
// the referenced chains differently (#5277).
func bgpEffectiveChains(bgp *config.BGPConfig, po *config.PolicyOptionsConfig, visit func(chain []string)) {
	if bgp == nil || po == nil {
		return
	}
	globalExportChain := bgpGlobalExportChain(bgp, po)
	globalImportChain := bgpGlobalImportChain(bgp, po)
	for _, n := range bgp.Neighbors {
		visit(bgpNeighborExportChain(n, globalExportChain, po))
		visit(bgpNeighborImportChain(n, globalImportChain, po))
	}
}

// collectBGPComposedChains records composedName -> chain for every REFERENCED
// BGP export/import policy chain of length >= 2 in bgp. On a name conflict
// (two DISTINCT chains deriving the same composedName) it keeps the FIRST
// deterministically; bgpComposedChainCollision is the fail-closed guard that
// rejects such a config before it renders (#5277).
func collectBGPComposedChains(bgp *config.BGPConfig, po *config.PolicyOptionsConfig, dst map[string][]string) {
	bgpEffectiveChains(bgp, po, func(chain []string) {
		if len(chain) < 2 {
			return
		}
		name := composedChainName(chain)
		if _, ok := dst[name]; ok {
			return
		}
		dst[name] = append([]string(nil), chain...)
	})
}

// bgpComposedChainCollision is the render-side fail-closed guard for the
// composed BGP policy-chain route-maps (#5277), mirroring
// redistProtocolMapCollision. FRR keys route-maps by name globally and merges
// same-named `route-map` definitions, so a composed name that collides with an
// operator policy-statement — or two DISTINCT chains that derive the same
// composed name — would fuse objects and could silently change the operator's
// BGP filtering (a security-relevant leak). The reserved ReservedChainSuffix
// makes both collisions astronomically unlikely, but on ANY collision this
// returns an error so ApplyFull fails the whole managed-section apply CLOSED
// (FRR keeps its last-good config) instead of emitting a fused route-map.
// Returns nil for the common non-colliding case.
func bgpComposedChainCollision(fc *FullConfig) error {
	if fc == nil || fc.PolicyOptions == nil {
		return nil
	}
	seen := map[string][]string{}
	var firstErr error
	check := func(bgp *config.BGPConfig) {
		bgpEffectiveChains(bgp, fc.PolicyOptions, func(chain []string) {
			if firstErr != nil || len(chain) < 2 {
				return
			}
			name := composedChainName(chain)
			// #8362 follow-up: a composed name can also collide with the
			// RESERVED emptied-chain deny (emptiedChainDenyName). The reserved
			// ReservedChainSuffix does NOT make that name unforgeable, which the
			// #7625 comment wrongly claimed: strict rejects a policy-statement
			// whose name ENDS in the suffix, but nothing stops several legally
			// named policies from JOINING into it —
			// composedChainName(["xpf","emptied","chain"]) is byte-identical to
			// "xpf-emptied-chain" + ReservedChainSuffix. FRR merges same-named
			// route-maps, so the composed chain's permits would fuse into the
			// deny and reopen the unfiltered-direction hole #7625 closed, while
			// the composed chain's own filter is corrupted by the deny's
			// sequence. Fail the apply CLOSED, same posture as the two
			// collisions below.
			if name == emptiedChainDenyName {
				firstErr = fmt.Errorf(
					"composed BGP policy-chain route-map %q (from chain %v) collides "+
						"with the reserved emptied-chain deny route-map of that exact "+
						"name; FRR merges same-named route-maps, so this would fuse "+
						"operator permits into the deny that closes an unfiltered "+
						"direction — refusing to render (rename a chain member, #7625)",
					name, chain)
				return
			}
			if _, ok := fc.PolicyOptions.PolicyStatements[name]; ok {
				firstErr = fmt.Errorf(
					"composed BGP policy-chain route-map %q (from chain %v) "+
						"collides with an operator policy-statement of that exact "+
						"name; FRR merges same-named route-maps, so the collision "+
						"could silently alter BGP filtering — refusing to render "+
						"(rename the operator policy-statement or a chain member, "+
						"#5277)", name, chain)
				return
			}
			if prev, ok := seen[name]; ok && !equalStringSlice(prev, chain) {
				firstErr = fmt.Errorf(
					"BGP policy-chains %v and %v derive the same composed "+
						"route-map name %q; FRR would merge them — rename a "+
						"policy-statement to disambiguate (#5277)", prev, chain, name)
				return
			}
			seen[name] = chain
		})
	}
	check(fc.BGP)
	for _, inst := range fc.Instances {
		check(inst.BGP)
	}
	return firstErr
}

// renderComposedBGPChains emits the DEFINITIONS of every composed BGP
// policy-chain route-map referenced anywhere in fc (default instance + every
// VRF), deduplicated and sorted by name for deterministic output. It is emitted
// alongside generatePolicyOptions in the managed section; FRR resolves a
// `neighbor X route-map <name> out` reference to a route-map defined anywhere in
// the file, so definition order does not matter. Returns "" when no chain of
// length >= 2 is referenced (byte-identical to the pre-#5277 render). Any
// distinct-chain name conflict is already rejected by bgpComposedChainCollision
// in ApplyFull; here a residual conflict keeps the first chain deterministically.
func (m *Manager) renderComposedBGPChains(fc *FullConfig) string {
	if fc == nil || fc.PolicyOptions == nil {
		return ""
	}
	chains := map[string][]string{}
	collectBGPComposedChains(fc.BGP, fc.PolicyOptions, chains)
	for _, inst := range fc.Instances {
		collectBGPComposedChains(inst.BGP, fc.PolicyOptions, chains)
	}
	if len(chains) == 0 {
		return ""
	}
	names := make([]string, 0, len(chains))
	for name := range chains {
		names = append(names, name)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, name := range names {
		b.WriteString(m.renderComposedRouteMap(fc.PolicyOptions, name, chains[name]))
		b.WriteString("!\n")
	}
	return b.String()
}

// equalStringSlice reports whether two string slices are element-wise equal.
func equalStringSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
