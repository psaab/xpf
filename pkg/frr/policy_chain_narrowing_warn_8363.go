package frr

import (
	"log/slog"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// policy_chain_narrowing_warn_8363.go — #8363 visibility and #10129 closure.
//
// A NARROWED policy chain — some authored members resolve, some do not — is a
// real deviation from authored intent: the operator wrote a filter and the
// renderer must not silently discard its missing members. The current
// production split is deliberately narrow:
// suffix-narrowed fall-through and empty survivors attach a private
// deny-terminated alias (#10129), while ghost-first/middle chains retain the
// surviving members and deny-inert survivors retain their authored terminal
// shared map. The warning and shape gauges remain for every narrowed site.
//
// The position rule is load-bearing. A synthesized terminating member at a
// non-final ghost position deletes every later survivor
// (#8363/#10129), so non-suffix sites remain on the shared map rather than
// receiving a deny that changes their chain semantics. Terminating-default and
// match-all-final-term survivors already terminate evaluation, so a trailing
// alias deny is not emitted for them.
//
// Historical #8369 rationale (superseded for the eligible suffix shapes):
// narrowed chains originally carried traffic with their fall-through PERMITTED
// (#2998), and a deny would convert that to denied on a tolerant load, peer
// sync, or rollback. The fleet census/migration gate remains owed only for any
// future non-suffix expansion; the suffix-only control is the #10129 rollout
// boundary. The empty-survivor shape remains in the affected denominator:
// [EMPTY,SYNTH-DENY] renders lone deny-10, reachable by every route
// (TestEmptySurvivorSynthesizedDenyIsReachable9947), so it flips permit-all to
// deny-all rather than being an over-count.
// narrowedChainSite is one attachment whose resolved chain is a strict, non-empty
// subset of what the operator authored.
type narrowedChainSite struct {
	Where    string
	Authored []string
	Kept     []string
	Dropped  []string
	// SurvivorShape records the body shape of the kept chain for the
	// #10129 measurement gauge. It is independent of GhostsAreSuffix:
	// position decides whether a synthesized member deletes survivors,
	// while body shape decides whether a trailing deny is reachable.
	SurvivorShape string
	// GhostsAreSuffix selects the position-safe production alias path:
	// every undefined member sits AFTER every surviving one. A deny at a
	// non-final ghost position would delete later survivors, so those sites
	// retain the shared map instead.
	GhostsAreSuffix bool
}

// narrowedChainSites reports every BGP attachment in bgp whose authored chain
// lost members but kept at least one.
//
// Sites whose chain EMPTIED are excluded: those now attach the #7625 bounded
// deny and renderEmptiedChainDeny already warns about them, so reporting them
// here would double-count one config error under two different descriptions.
//
// Neighbour sites mirror the resolvers' most-specific-wins rule via
// bgpNeighborAuthoredExport/Import, and the export side excludes bare protocol
// tokens for the same reason the emptied path does: they are redistribute verbs,
// not failed policy references, so a chain that "lost" one lost nothing.
func narrowedChainSites(bgp *config.BGPConfig, po *config.PolicyOptionsConfig) []narrowedChainSite {
	if bgp == nil {
		return nil
	}
	var out []narrowedChainSite
	globalExportChain := bgpGlobalExportChain(bgp, po)
	globalImportChain := bgpGlobalImportChain(bgp, po)

	add := func(where string, authored, kept []string, protocolTokensAreRedistribute bool) {
		if len(authored) == 0 || len(kept) == 0 {
			return
		}
		var dropped []string
		suffix := true
		sawGhost := false
		for _, n := range authored {
			if n == "" {
				continue
			}
			ghost := !isDefinedPolicyStatement(n, po) &&
				!(protocolTokensAreRedistribute &&
					(knownRedistProtocol(n) || knownRedistProtocol(junosProtocolToFRR7625(n))))
			if ghost {
				dropped = append(dropped, n)
				sawGhost = true
				continue
			}
			// A member that SURVIVES and appears after a ghost breaks the suffix
			// property: a deny synthesized at that ghost's position would delete
			// this member entirely (#8363).
			if sawGhost {
				suffix = false
			}
		}
		if len(dropped) == 0 {
			return
		}
		out = append(out, narrowedChainSite{
			Where:           where,
			Authored:        authored,
			Kept:            kept,
			Dropped:         dropped,
			SurvivorShape:   narrowedSurvivorShape10129(kept, po),
			GhostsAreSuffix: suffix,
		})
	}

	for _, n := range bgp.Neighbors {
		if n == nil {
			continue
		}
		add("neighbor "+n.Address+" export",
			bgpNeighborAuthoredExport(n, bgp),
			bgpNeighborExportChain(n, globalExportChain, po), true)
		add("neighbor "+n.Address+" import",
			bgpNeighborAuthoredImport(n, bgp),
			bgpNeighborImportChain(n, globalImportChain, po), false)
	}
	return out
}

// warnNarrowedChains emits one warning per narrowed attachment across fc and
// rebuilds the operator-visible narrowed/shape gauges. Eligible suffix
// fall-through and empty sites are closed by the alias renderer in the same
// managed-section build; non-eligible sites retain their shared map.
func (m *Manager) warnNarrowedChains(fc *FullConfig) {
	m.resetNarrowed()
	if fc == nil {
		return
	}
	sites := narrowedChainSites(fc.BGP, fc.PolicyOptions)
	for _, inst := range fc.Instances {
		sites = append(sites, narrowedChainSites(inst.BGP, fc.PolicyOptions)...)
	}
	m.recordNarrowed(sites)
	for _, s := range sites {
		slog.Warn("BGP policy chain is NARROWER than configured: part of the authored chain "+
			"names policy-statements that are not defined, so the direction is still filtered "+
			"but by less than was written — define the missing policy-statements or remove "+
			"them from the chain",
			"where", s.Where,
			"authored", strings.Join(s.Authored, ","),
			"applied", strings.Join(s.Kept, ","),
			"discarded", strings.Join(s.Dropped, ","),
			"ghosts-are-suffix", s.GhostsAreSuffix)
	}
}
