package config

import (
	"math"
	"strings"
)

// CarvedSingleExtraSequences16869 reports standalone carved-tail sequences
// beyond the fallback already reserved by RouteMapSequenceCount.
func CarvedSingleExtraSequences16869(carved bool, ps *PolicyStatement) uint64 {
	if !carved || ps == nil || ps.DefaultAction != "" {
		return 0
	}
	if policyStatementHasNextPolicy(ps) {
		return 2
	}
	return 1
}

// CarvedComposedExtraSequences16869 reports the extra carved fall-off sequence
// beyond the fallback already reserved by ComposedChainSequenceCount.
func CarvedComposedExtraSequences16869(po *PolicyOptionsConfig, chain []string, carved bool, fallbackAction string) uint64 {
	if po == nil {
		return 0
	}
	return CarvedComposedExtraSequencesForStatements16869(po.PolicyStatements, chain, carved, fallbackAction)
}

// CarvedComposedExtraSequencesForStatements16869 is
// CarvedComposedExtraSequences16869 over an explicit statement map instead of
// po.PolicyStatements: callers that render filtered statements reserve
// against the members they actually render. This is the single termination
// walk both variants share, so the strict gate and the render belt cannot
// diverge on whether a chain reaches the carved fall-off pair.
func CarvedComposedExtraSequencesForStatements16869(pss map[string]*PolicyStatement, chain []string, carved bool, fallbackAction string) uint64 {
	if !carved || fallbackAction != "permit" {
		return 0
	}
	for _, name := range chain {
		ps := pss[name]
		if ps == nil {
			continue
		}
		if (ps.DefaultAction == "accept" || ps.DefaultAction == "reject") &&
			!policyStatementHasNextPolicy(ps) {
			return 0
		}
	}
	return 1
}

// AddCarvedSequenceReserve16869 adds a carved reserve without wrapping a
// saturated sequence count back into the in-bound range.
func AddCarvedSequenceReserve16869(count, reserve uint64) uint64 {
	if count > math.MaxUint64-reserve {
		return math.MaxUint64
	}
	return count + reserve
}

// carvedBGPExportShapes16890 returns single-policy and composed export maps
// whose tails are carved by #15157. The renderer marks these only for
// originating BGP instances and only when a neighbor references the export.
func carvedBGPExportShapes16890(cfg *Config) (map[string]bool, map[string][]string) {
	singles := make(map[string]bool)
	composed := make(map[string][]string)
	if cfg == nil {
		return singles, composed
	}
	pss := cfg.PolicyOptions.PolicyStatements
	mark := func(bgp *BGPConfig) {
		if bgp == nil || len(bgp.Neighbors) == 0 || !bgpHasOrigination16890(bgp, pss) {
			return
		}
		for _, chain := range bgpExportChains16890(bgp, pss) {
			if len(chain) == 1 {
				singles[chain[0]] = true
				continue
			}
			if len(chain) < 2 {
				continue
			}
			name := strings.Join(chain, "-") + ReservedChainSuffix
			if _, exists := composed[name]; !exists {
				composed[name] = chain
			}
		}
	}
	mark(cfg.Protocols.BGP)
	for _, ri := range cfg.RoutingInstances {
		if ri != nil {
			mark(ri.BGP)
		}
	}
	return singles, composed
}

// bgpExportChains16890 resolves the effective, defined export chains for a BGP
// instance. With no neighbors, the global chain still determines origination,
// but it does not produce an attached route-map and is ignored by the carve
// collector above.
func bgpExportChains16890(bgp *BGPConfig, pss map[string]*PolicyStatement) [][]string {
	if bgp == nil {
		return nil
	}
	global := policyChainDefined(bgp.Export, pss)
	var chains [][]string
	if len(bgp.Neighbors) == 0 {
		if len(global) > 0 {
			return [][]string{global}
		}
		return nil
	}
	seen := make(map[string]bool)
	for _, neighbor := range bgp.Neighbors {
		if neighbor == nil {
			continue
		}
		chain := global
		if policyListHasNonEmpty(neighbor.Export) {
			chain = policyChainDefined(neighbor.Export, pss)
		}
		if len(chain) == 0 {
			continue
		}
		key := strings.Join(chain, "\x00")
		if seen[key] {
			continue
		}
		seen[key] = true
		chains = append(chains, chain)
	}
	return chains
}

// BGPHasOriginationForCarvedExport16890 reports whether an instance's
// effective export chains originate at least one non-BGP source route.
// pkg/config and pkg/frr share this predicate so strict bounds match the
// renderer's #15157 carve trigger.
func BGPHasOriginationForCarvedExport16890(bgp *BGPConfig, po *PolicyOptionsConfig) bool {
	if po == nil {
		return false
	}
	return bgpHasOrigination16890(bgp, po.PolicyStatements)
}

func bgpHasOrigination16890(bgp *BGPConfig, pss map[string]*PolicyStatement) bool {
	for _, chain := range bgpExportChains16890(bgp, pss) {
		for _, name := range chain {
			if policyCanOriginateBGP16890(pss[name]) {
				return true
			}
		}
	}
	return false
}

// policyCanOriginateBGP16890 mirrors the BGP redistribute enrollment predicate
// used by the renderer: an accept-capable term that selects a source other than
// BGP itself can originate at least one IPv4 or IPv6 source route.
func policyCanOriginateBGP16890(ps *PolicyStatement) bool {
	if ps == nil {
		return false
	}
	for _, term := range ps.Terms {
		if term == nil || term.NextPolicy && term.Action != "" ||
			term.NextTerm && term.Action != "" || term.NextTerm && term.NextPolicy ||
			term.Action == "reject" && !term.NextPolicy {
			continue
		}
		if len(term.FromProtocols) == 0 {
			for _, source := range RedistributionSourceKeywords() {
				if source != "bgp" {
					return true
				}
			}
			continue
		}
		for _, raw := range term.FromProtocols {
			source, ok := FRRRoutingProtocolKeyword(raw)
			if !ok || source == "bgp" {
				continue
			}
			if families, ok := RedistributionSourceFamilies(source); ok && families != 0 {
				return true
			}
		}
	}
	return false
}
