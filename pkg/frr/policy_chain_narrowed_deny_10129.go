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

// narrowedAliasEligible10129 identifies the suffix-safe subset whose missing
// authored members can be closed without changing the surviving chain
// semantics. Terminating-default and match-all-final-term survivors remain on
// the shared map because their explicit termination makes a trailing deny
// unreachable. Fall-through and empty survivors receive a private deny alias.
func narrowedAliasEligible10129(site narrowedChainSite, po *config.PolicyOptionsConfig) bool {
	if len(site.Kept) == 0 || !site.GhostsAreSuffix {
		return false
	}
	shape := narrowedSurvivorShape10129(site.Kept, po)
	return shape == "fall-through" || shape == "empty"
}

// narrowedAliasEligible10821 extends #10129's suffix-safe alias to non-suffix
// fall-through and empty survivors. The private alias appends a trailing deny
// after the retained chain, preserving all survivors in their original order;
// it does not insert a terminating chain member at the ghost position.
func narrowedAliasEligible10821(site narrowedChainSite, po *config.PolicyOptionsConfig) bool {
	if narrowedAliasEligible10129(site, po) {
		return true
	}
	if len(site.Kept) == 0 {
		return false
	}
	shape := narrowedSurvivorShape10129(site.Kept, po)
	return shape == "fall-through" || shape == "empty"
}

// narrowedGhostsAfterTerminator10821 reports whether every ghost is after a
// kept prefix that provably terminates for every route. In that case the ghost
// is unreachable and the existing shared map is safe. A missing/unknown
// direction or any reachable ghost is not proof and must fail closed.
func narrowedGhostsAfterTerminator10821(site narrowedChainSite, po *config.PolicyOptionsConfig) bool {
	if po == nil {
		return false
	}
	export := strings.HasSuffix(site.Where, " export")
	if !export && !strings.HasSuffix(site.Where, " import") {
		return false
	}
	var prefix []string
	sawGhost := false
	for _, name := range site.Authored {
		if name == "" {
			continue
		}
		if isDefinedPolicyStatement(name, po) {
			prefix = append(prefix, name)
			continue
		}
		if export && (knownRedistProtocol(name) ||
			knownRedistProtocol(junosProtocolToFRR7625(name))) {
			continue
		}
		sawGhost = true
		shape := narrowedSurvivorShape10129(prefix, po)
		if shape != "terminating-default" && shape != "match-all" {
			return false
		}
	}
	return sawGhost
}

// renderNarrowedChainAlias10129 renders a deny-terminated attached-map alias
// without mutating the shared standalone or composed map. Explicit member
// defaults remain authoritative; only a no-default fall-through reaches the
// alias's explicit deny.
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
// production narrowed alias attachment. It checks all four same-name merge
// hazards: operator policy, composed chain, the #7625 emptied deny, and two
// distinct narrowed survivors.
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

	type aliasIdentity struct {
		raw  string
		kept []string
	}
	aliases := make(map[string]aliasIdentity)
	operatorNames := make([]string, 0, len(fc.PolicyOptions.PolicyStatements))
	for name := range fc.PolicyOptions.PolicyStatements {
		operatorNames = append(operatorNames, name)
	}
	sort.Strings(operatorNames)
	for _, site := range sites {
		if !narrowedAliasEligible10821(site, fc.PolicyOptions) {
			if !site.GhostsAreSuffix &&
				!narrowedGhostsAfterTerminator10821(site, fc.PolicyOptions) {
				return fmt.Errorf("non-suffix narrowed BGP chain at %q has a reachable ghost with no safe trailing-deny rendering; refusing the fail-open surviving attachment", site.Where)
			}
			continue
		}
		alias := narrowedAliasName10129(site.Kept)
		final := frrName(alias)
		// Policy names are rendered through frrName too. Compare final FRR
		// names, not only raw map keys, so a tolerant invalid alias cannot
		// sanitize into an operator-owned route-map.
		for _, operatorName := range operatorNames {
			if frrName(operatorName) == final {
				return fmt.Errorf("narrowed BGP policy-chain alias %q (rendered %q) collides with operator policy-statement %q", alias, final, operatorName)
			}
		}
		if final == frrName(emptiedChainDenyName) {
			return fmt.Errorf("narrowed BGP policy-chain alias %q (rendered %q) collides with emptied-chain deny", alias, final)
		}
		if prev, ok := aliases[final]; ok && !equalStringSlice(prev.kept, site.Kept) {
			return fmt.Errorf("narrowed BGP policy-chain alias %q (rendered %q) collides for distinct surviving chains %q and %q", alias, final, strings.Join(prev.kept, ","), strings.Join(site.Kept, ","))
		}
		aliases[final] = aliasIdentity{raw: alias, kept: append([]string(nil), site.Kept...)}
	}

	composed := make(map[string][]string)
	collectBGPComposedChains(fc.BGP, fc.PolicyOptions, composed)
	for _, inst := range fc.Instances {
		collectBGPComposedChains(inst.BGP, fc.PolicyOptions, composed)
	}
	for composedName, chain := range composed {
		final := frrName(composedName)
		if alias, ok := aliases[final]; ok {
			return fmt.Errorf("narrowed BGP policy-chain alias %q (rendered %q) collides with composed chain %q", alias.raw, final, strings.Join(chain, ","))
		}
	}
	return nil
}

// narrowedAliasNames10129 returns eligible aliases in deterministic order for
// managed-section emission and makes dedupe observable in tests.
func narrowedAliasNames10129(fc *FullConfig) []string {
	if fc == nil || fc.PolicyOptions == nil {
		return nil
	}
	seen := make(map[string]struct{})
	var out []string
	add := func(bgp *config.BGPConfig) {
		for _, site := range narrowedChainSites(bgp, fc.PolicyOptions) {
			if !narrowedAliasEligible10821(site, fc.PolicyOptions) {
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
			if narrowedAliasEligible10821(site, fc.PolicyOptions) {
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

// narrowedAliasRef10129 swaps one eligible attachment to its prepared alias.
// The #10821 extension attaches non-suffix fall-through/empty chains using a
// trailing deny, preserving the surviving order. A non-suffix chain that
// cannot reach that deny safely is rejected by the collision/apply guard
// unless every ghost follows a terminating survivor.
func (m *Manager) narrowedAliasRef10129(n *config.BGPNeighbor, bgp *config.BGPConfig, global []string, po *config.PolicyOptionsConfig, export bool) string {
	if n == nil || bgp == nil || po == nil {
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
			equalStringSlice(site.Kept, kept) && narrowedAliasEligible10821(site, po) {
			return narrowedAliasName10129(site.Kept)
		}
	}
	return ""
}

// renderNarrowedAliases10129 emits every production narrowed alias definition
// beside the ordinary policy maps. The attachment and definition paths share
// narrowedAliasChains10129, so references and definitions are emitted
// together by construction.
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
