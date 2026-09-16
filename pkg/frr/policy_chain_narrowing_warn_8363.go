package frr

import (
	"log/slog"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// policy_chain_narrowing_warn_8363.go — #8363 visibility.
//
// A NARROWED policy chain — some authored members resolve, some do not — is a
// real deviation from authored intent: the operator wrote a filter and is
// getting a weaker one. Unlike the EMPTIED case (#7625/#8362) it is not a hole,
// so the behaviour is deliberately unchanged; but before this it was also
// completely SILENT. The rendered section is internally consistent, the session
// works, `show route-map` displays a real well-formed policy, and nothing
// anywhere says a member of the authored chain was discarded.
//
// Why the behaviour is not "fixed" here as well: see the #8363 measurement in
// policy_chain_narrowed_eval_8363_test.go. Synthesizing a deny for the missing
// member is safe ONLY when the undefined members form a suffix of the authored
// chain — renderComposedRouteMap breaks on the first member with a terminating
// default action, so a deny at a non-final ghost position DELETES every later
// member and renders deny-all. Making the narrowing visible is correct under
// either outcome of that decision, which is why it lands separately from it.
//
// #8369 — THE DENY IS DEFERRED, NOT PENDING IMPLEMENTATION. Three reasons, and
// the third is new evidence rather than a restatement of the issue.
//
//  1. THE DIRECTION IS A ROUTING CHANGE AT LOAD TIME. A narrowed chain is
//     carrying traffic right now with its fall-through PERMITTED (#2998, the
//     Junos BGP default-accept). A deny converts that to denied. Strict commit
//     rejects an undefined policy reference in both directions, so the ENTIRE
//     affected population arrives via the lenient path (Store.Load / SyncApply)
//     — a reboot, a peer sync or a rollback. The operator gets a routing change
//     triggered by an unrelated event, on a config they did not just edit, with
//     no commit to warn them at, and a route-map deny is silent: the first
//     symptom is a prefix simply absent from the neighbour's adj-rib.
//     TestNarrowedChainStillPermitsFallThroughToday8369 asserts the direction
//     so it cannot change silently.
//
//  2. THE POPULATION IS UNMEASURED, and #8369 makes measuring it a
//     precondition ("Do not decide this from argument"). No fleet split has
//     been collected.
//
//  3. THE EMPTY-SURVIVOR SHAPE IS THE HIGHEST-IMPACT MEMBER, NOT AN
//     OVER-COUNT. (Corrects the earlier "gauge over-counts" version of
//     this reason — #9947.) A surviving policy statement that is DEFINED
//     but carries no terms renders today as one match-all sequence,
//     `route-map C permit 10`. The earlier inference was that a trailing
//     deny would sit unreachable behind it. Measured against the actual
//     synthesis shape — a chain MEMBER with a terminating default —
//     EMPTY contributes zero sequences, so [EMPTY,SYNTH-DENY] renders
//     lone deny-10, reachable by every route: the shape flips permit-all
//     to deny-all (TestEmptySurvivorSynthesizedDenyIsReachable9947).
//     xpf_frr_policy_chains_narrowed_deny_safe counts it correctly;
//     excluding it would hide an outage case, not correct an over-count.
//
// What a future implementation still owes, beyond the issue's own list: the
// migration decision must weigh that the empty-survivor population flips
// from permit-all to deny-all (not inert), and reachability must be
// re-derived per survivor shape (terminating-default and match-all-final-
// term survivors are code-read, not yet pinned — see the F-008 tracker).

// narrowedChainSite is one attachment whose resolved chain is a strict, non-empty
// subset of what the operator authored.
type narrowedChainSite struct {
	Where    string
	Authored []string
	Kept     []string
	Dropped  []string
	// GhostsAreSuffix reports whether every undefined member sits AFTER every
	// surviving one. That is the #8363 safety condition for ever synthesizing a
	// deny here: renderComposedRouteMap breaks on the first member with a
	// terminating default action, so a deny at a non-final ghost position does
	// not shadow the rest of the chain, it DELETES it. Recorded now, while
	// behaviour is unchanged, so the decision on whether to synthesize is sized
	// on how often the safe shape actually occurs rather than on argument.
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
			Where: where, Authored: authored, Kept: kept, Dropped: dropped,
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

// warnNarrowedChains emits one warning per narrowed attachment across fc. It
// changes no rendered output — it is the operator-visible signal that a filter
// is weaker than authored.
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
