package frr

import (
	"fmt"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// narrowedAliasSuffix10129 is deliberately inside the existing reserved chain
// namespace. The strict policy-name gate already rejects operator names ending
// in ReservedChainSuffix; the render-side collision belt below additionally
// covers tolerant Load / peer-sync / rollback paths and collisions with
// generated composed and emptied-chain names.
const narrowedAliasSuffix10129 = "-xpf-narrowed" + ReservedChainSuffix

// narrowedAliasName10129 derives the per-surviving-chain route-map alias. It
// is injective only over policy names without the separator, so the collision
// belt must reject distinct chains that derive the same FRR name.
func narrowedAliasName10129(kept []string) string {
	return strings.Join(kept, "-") + narrowedAliasSuffix10129
}

// narrowedSurvivorShape10129 classifies the surviving member chain for
// measurement and rollout. The shape is intentionally separate from
// GhostsAreSuffix: member position decides whether synthesis deletes later
// survivors, while the survivor body decides whether a trailing deny is
// reachable.
// policyTermHasAuthoredMatch10129 mirrors every PolicyTerm field that can
// produce a rendered match clause. A term with any one of these fields is not
// treated as match-all by the rollout classifier, even if a lenient render
// later omits an invalid reference; that conservative result cannot authorize
// a behavior flip.
func policyTermHasAuthoredMatch10129(term *config.PolicyTerm) bool {
	return term != nil &&
		(len(term.FromProtocols) > 0 ||
			len(term.PrefixList) > 0 ||
			len(term.FromCommunity) > 0 ||
			len(term.FromASPath) > 0 ||
			len(term.RouteFilters) > 0)
}

// narrowedSurvivorShape10129 classifies the surviving member chain for
// measurement and rollout. The shape is intentionally separate from
// GhostsAreSuffix: member position decides whether synthesis deletes later
// survivors, while the survivor body decides whether a trailing deny is
// reachable.
func narrowedSurvivorShape10129(kept []string, po *config.PolicyOptionsConfig) string {
	if len(kept) == 0 {
		return "empty"
	}
	if po == nil || po.PolicyStatements == nil {
		return "empty"
	}
	// The renderer's #5701/#5732 quarantine uses these exact predicates and
	// emits a bounded deny; classify it separately so census and alias
	// eligibility never count an already-denied attachment as fall-through.
	if len(kept) == 1 {
		if ps := po.PolicyStatements[kept[0]]; ps != nil &&
			config.RouteMapSequenceCount(po, ps) > config.MaxRouteMapSequences {
			return "quarantined"
		}
	} else if config.ComposedChainSequenceCount(po, po.PolicyStatements, kept) > config.MaxRouteMapSequences {
		return "quarantined"
	}
	sawEmpty := false
	for _, name := range kept {
		ps := po.PolicyStatements[name]
		if ps == nil {
			continue
		}
		if ps.DefaultAction == "accept" || ps.DefaultAction == "reject" {
			return "terminating-default"
		}
		if len(ps.Terms) == 0 {
			sawEmpty = true
			continue
		}
		for _, term := range ps.Terms {
			// Any unconditional terminating term stops FRR/Junos
			// evaluation, even when later terms are present.
			if term != nil && !policyTermHasAuthoredMatch10129(term) &&
				(term.Action == "accept" || term.Action == "reject") {
				return "match-all"
			}
		}
	}
	if sawEmpty {
		allEmpty := true
		for _, name := range kept {
			ps := po.PolicyStatements[name]
			if ps != nil && (len(ps.Terms) != 0 || ps.DefaultAction != "") {
				allEmpty = false
				break
			}
		}
		if allEmpty {
			return "empty"
		}
	}
	return "fall-through"
}

// narrowedAliasEligible10129 is the future behavior gate. Non-suffix chains
// are never eligible because a synthesized terminating member there deletes
// later survivors. Terminating-default and match-all-final-term survivors are
// safe to leave on the existing map: their suffix deny is unreachable. The
// only shapes that need a deny alias are fall-through and empty survivors.
func narrowedAliasEligible10129(site narrowedChainSite, po *config.PolicyOptionsConfig) bool {
	if len(site.Kept) == 0 || !site.GhostsAreSuffix {
		return false
	}
	shape := narrowedSurvivorShape10129(site.Kept, po)
	return shape == "fall-through" || shape == "empty"
}

// renderNarrowedChainAlias10129 renders a deny-terminated attached-map alias
// without mutating the shared standalone or composed map. It is intentionally
// not wired into neighbor attachment sites until fleet measurement authorizes
// the behavior flip. Explicit member defaults remain authoritative; only a
// no-default fall-through reaches the alias's explicit deny.
func (m *Manager) renderNarrowedChainAlias10129(po *config.PolicyOptionsConfig, kept []string) (string, string) {
	name := narrowedAliasName10129(kept)
	if po == nil || po.PolicyStatements == nil {
		return name, renderQuarantineDenyRouteMap(name)
	}
	if len(kept) == 1 {
		ps := po.PolicyStatements[kept[0]]
		if ps == nil {
			return name, renderQuarantineDenyRouteMap(name)
		}
		// Standalone aliases use the fail-closed non-BGP default for a
		// no-default policy while preserving explicit accept/reject.
		return name, m.renderRouteMapForPolicy(po, name, ps, policyTrailingAction(kept[0], ps, nil))
	}
	return name, m.renderComposedRouteMapWithDefault(po, name, kept, "deny")
}

// narrowedAliasCollision10129 is the render-side collision belt for the
// future alias attachment. It checks all four same-name merge hazards:
// operator policy, composed chain, the #7625 emptied deny, and two distinct
// narrowed survivors. It is kept separate from ApplyFull until the measured
// behavior flip wires aliases into the managed section.
func narrowedAliasCollision10129(fc *FullConfig) error {
	if fc == nil || fc.PolicyOptions == nil {
		return nil
	}
	var sites []narrowedChainSite
	add := func(bgp *config.BGPConfig) {
		sites = append(sites, narrowedChainSites(bgp, fc.PolicyOptions)...)
	}
	add(fc.BGP)
	for _, inst := range fc.Instances {
		add(inst.BGP)
	}
	aliases := make(map[string][]string)
	for _, site := range sites {
		if !narrowedAliasEligible10129(site, fc.PolicyOptions) {
			continue
		}
		alias := narrowedAliasName10129(site.Kept)
		if _, ok := fc.PolicyOptions.PolicyStatements[alias]; ok {
			return fmt.Errorf("narrowed BGP policy-chain alias %q collides with operator policy-statement", alias)
		}
		if alias == emptiedChainDenyName {
			return fmt.Errorf("narrowed BGP policy-chain alias %q collides with emptied-chain deny", alias)
		}
		if prev, ok := aliases[alias]; ok && !equalStringSlice(prev, site.Kept) {
			return fmt.Errorf("narrowed BGP policy-chain alias %q collides for distinct surviving chains %q and %q", alias, strings.Join(prev, ","), strings.Join(site.Kept, ","))
		}
		aliases[alias] = append([]string(nil), site.Kept...)
	}
	composed := make(map[string][]string)
	collectBGPComposedChains(fc.BGP, fc.PolicyOptions, composed)
	for _, inst := range fc.Instances {
		collectBGPComposedChains(inst.BGP, fc.PolicyOptions, composed)
	}
	for alias, chain := range aliases {
		if other, ok := composed[alias]; ok && !equalStringSlice(other, chain) {
			return fmt.Errorf("narrowed BGP policy-chain alias %q collides with composed chain %q", alias, strings.Join(other, ","))
		}
	}
	return nil
}

// narrowedAliasNames10129 returns eligible aliases in deterministic order for
// future managed-section emission and makes dedupe observable in tests.
func narrowedAliasNames10129(fc *FullConfig) []string {
	if fc == nil || fc.PolicyOptions == nil {
		return nil
	}
	seen := make(map[string]struct{})
	var out []string
	add := func(bgp *config.BGPConfig) {
		for _, site := range narrowedChainSites(bgp, fc.PolicyOptions) {
			if !narrowedAliasEligible10129(site, fc.PolicyOptions) {
				continue
			}
			name := narrowedAliasName10129(site.Kept)
			if _, ok := seen[name]; !ok {
				seen[name] = struct{}{}
				out = append(out, name)
			}
		}
	}
	add(fc.BGP)
	for _, inst := range fc.Instances {
		add(inst.BGP)
	}
	sort.Strings(out)
	return out
}

// narrowedAliasChains10129 returns one kept chain per eligible alias. The
// collision belt must run before this is used; duplicate derivations are not
// silently resolved.
func narrowedAliasChains10129(fc *FullConfig) map[string][]string {
	out := make(map[string][]string)
	if fc == nil || fc.PolicyOptions == nil {
		return out
	}
	add := func(bgp *config.BGPConfig) {
		for _, site := range narrowedChainSites(bgp, fc.PolicyOptions) {
			if narrowedAliasEligible10129(site, fc.PolicyOptions) {
				out[narrowedAliasName10129(site.Kept)] = append([]string(nil), site.Kept...)
			}
		}
	}
	add(fc.BGP)
	for _, inst := range fc.Instances {
		add(inst.BGP)
	}
	return out
}

// narrowedAliasRef10129 swaps one attachment to its prepared alias only when
// the explicit test-only mechanism switch is enabled. All ordinary callers
// retain the existing reference and therefore the current warn-only behavior.
func (m *Manager) narrowedAliasRef10129(n *config.BGPNeighbor, bgp *config.BGPConfig, global []string, po *config.PolicyOptionsConfig, export bool) string {
	if !m.narrowedAliasesEnabled10129 || n == nil || bgp == nil || po == nil {
		return ""
	}
	var authored, kept []string
	whereSuffix := " import"
	if export {
		authored = bgpNeighborAuthoredExport(n, bgp)
		whereSuffix = " export"
	} else {
		authored = bgpNeighborAuthoredImport(n, bgp)
	}
	if export {
		kept = bgpNeighborExportChain(n, global, po)
	} else {
		kept = bgpNeighborImportChain(n, global, po)
	}
	suffix := "neighbor " + n.Address + whereSuffix
	for _, site := range narrowedChainSites(bgp, po) {
		if site.Where == suffix && equalStringSlice(site.Authored, authored) &&
			equalStringSlice(site.Kept, kept) && narrowedAliasEligible10129(site, po) {
			return narrowedAliasName10129(site.Kept)
		}
	}
	return ""
}

// renderNarrowedAliases10129 emits every prepared alias definition beside the
// ordinary policy maps. The test-only attachment switch and this definition
// emitter share narrowedAliasChains10129, so references and definitions are
// emitted together by construction.
func (m *Manager) renderNarrowedAliases10129(fc *FullConfig) string {
	chains := narrowedAliasChains10129(fc)
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
		_, rendered := m.renderNarrowedChainAlias10129(fc.PolicyOptions, chains[name])
		b.WriteString(rendered)
	}
	return b.String()
}
