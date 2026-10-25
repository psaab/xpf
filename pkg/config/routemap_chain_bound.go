package config

import (
	"fmt"
	"sort"
	"strings"
)

// The #5701 route-map sequence bound (validatePolicyRouteMapSequenceBoundStrict)
// bounds each POLICY-STATEMENT to <= MaxRouteMapSequences term sequences. That
// closes the single-policy overflow, but a composed BGP policy CHAIN
// (`import`/`export [ A B ... ]` of length >= 2, #5277) is rendered by
// pkg/frr.renderComposedRouteMap into ONE route-map with a RUNNING sequence
// number accumulated across ALL rendered members. A chain whose members are
// each individually <= the ceiling but whose SUM exceeds it re-introduces the
// exact #5701 overflow — a `route-map` line past FRR seq 65535 that poisons the
// whole frr-reload — trivially bypassing the per-policy gate by splitting one
// oversized policy in two (#5732).
//
// The functions below MIRROR pkg/frr's chain resolution
// (bgpGlobalExportChain / bgpNeighborExportChain / filterDefinedPolicies /
// hasNonEmptyPolicy / collectBGPComposedChains) so the commit gate resolves the
// SAME chains the renderer composes. They live here (not pkg/frr) because the
// commit gate runs in pkg/config, which cannot import pkg/frr. The composed
// COUNT itself is the shared SSOT ComposedChainSequenceCount, which pkg/frr also
// consults in its render-side belt — so the gate and the renderer can never
// disagree on what overflows.

// policyChainDefined returns, in order, the non-empty entries of names that
// resolve to a defined policy-statement — the ordered chain the renderer
// composes. Mirrors pkg/frr.filterDefinedPolicies.
func policyChainDefined(names []string, pss map[string]*PolicyStatement) []string {
	out := make([]string, 0, len(names))
	for _, n := range names {
		if n == "" {
			continue
		}
		if _, ok := pss[n]; ok {
			out = append(out, n)
		}
	}
	return out
}

// policyListHasNonEmpty reports whether names has any non-empty entry. Mirrors
// pkg/frr.hasNonEmptyPolicy — a neighbor that sets ANY own import/export (even a
// bare/undefined one) suppresses the inherited group default for that peer.
func policyListHasNonEmpty(names []string) bool {
	for _, n := range names {
		if n != "" {
			return true
		}
	}
	return false
}

// bgpComposedChains collects every REFERENCED composed BGP policy chain
// (length >= 2) across bgp's neighbors, deduped by the composed route-map name
// (strings.Join(chain,"-")+ReservedChainSuffix), into dst. It mirrors the
// resolution pkg/frr.collectBGPComposedChains performs: per neighbor, the
// effective export/import chain is the neighbor's own defined list when it sets
// one, else the global default — exactly what renderComposedRouteMap is handed.
func bgpComposedChains(bgp *BGPConfig, pss map[string]*PolicyStatement, dst map[string][]string) {
	if bgp == nil {
		return
	}
	globalExport := policyChainDefined(bgp.Export, pss)
	globalImport := policyChainDefined(bgp.Import, pss)
	record := func(chain []string) {
		if len(chain) < 2 {
			return
		}
		name := strings.Join(chain, "-") + ReservedChainSuffix
		if _, seen := dst[name]; !seen {
			dst[name] = chain
		}
	}
	for _, n := range bgp.Neighbors {
		if n == nil {
			continue
		}
		exportChain := globalExport
		if policyListHasNonEmpty(n.Export) {
			exportChain = policyChainDefined(n.Export, pss)
		}
		importChain := globalImport
		if policyListHasNonEmpty(n.Import) {
			importChain = policyChainDefined(n.Import, pss)
		}
		record(exportChain)
		record(importChain)
	}
}

// validateBGPComposedChainSequenceBoundStrict rejects a composed BGP policy
// chain whose summed rendered sequence count, including any #15157 carved
// export tail, exceeds the FRR ceiling. renderComposedRouteMap concatenates
// the chain's members into ONE route-map with a running sequence number, so a
// chain of individually-in-bounds policies can still emit a `route-map` line
// past seq 65535 — the exact #5701 frr-reload-poisoning overflow, re-introduced
// at the chain level (#5732). This is the CHAIN companion to the per-policy
// validatePolicyRouteMapSequenceBoundStrict (kept for defense in depth); both
// share the base-count SSOT plus the #16869 carved reserve and the same
// MaxRouteMapSequences ceiling.
// Strict on commit / commit-check (hard reject naming the chain); downgraded to
// a warning on the tolerant load / peer-sync paths (opts.lenientPolicyRouteMapSeq,
// #1960) — renderComposedRouteMap independently SKIPS an over-ceiling chain
// (renders nothing) so a leniently-loaded config cannot poison the reload.
// Chains are checked in sorted composed-name order for a deterministic first
// error. The default instance and every routing-instance BGP are covered.
func validateBGPComposedChainSequenceBoundStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	pss := cfg.PolicyOptions.PolicyStatements
	if len(pss) == 0 {
		return nil
	}
	chains := make(map[string][]string)
	bgpComposedChains(cfg.Protocols.BGP, pss, chains)
	for _, ri := range cfg.RoutingInstances {
		if ri != nil {
			bgpComposedChains(ri.BGP, pss, chains)
		}
	}
	if len(chains) == 0 {
		return nil
	}
	_, carvedComposed := carvedBGPExportShapes16890(cfg)
	names := make([]string, 0, len(chains))
	for name := range chains {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		chain := chains[name]
		base := ComposedChainSequenceCount(&cfg.PolicyOptions, pss, chain)
		reserve := CarvedComposedExtraSequences16869(&cfg.PolicyOptions, chain, len(carvedComposed[name]) > 0, "permit")
		n := AddCarvedSequenceReserve16869(base, reserve)
		if n > MaxRouteMapSequences {
			carved := ""
			if reserve > 0 {
				carved = " including its carved BGP export tail"
			}
			return fmt.Errorf(
				"BGP composed policy chain [ %s ] expands to %d route-map sequences%s, "+
					"over the FRR ceiling of %d — renderComposedRouteMap concatenates "+
					"the chain's members into ONE route-map %q with a running sequence "+
					"number, so it would emit a `route-map` line past sequence %d, which "+
					"FRR rejects and which poisons the ENTIRE frr-reload; shorten the "+
					"chain or reduce the members' `from prefix-list` / `from community` / "+
					"`from as-path` values (each member's Cartesian product drives its "+
					"count)",
				strings.Join(chain, " "), n, carved, MaxRouteMapSequences, name, frrMaxRouteMapSeq)
		}
	}
	return nil
}
