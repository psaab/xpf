package config

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

// FRR route-map sequence numbers occupy the command range
// `route-map WORD <permit|deny> (1-65535)`. The pkg/frr renderer numbers
// sequences in steps of routeMapSeqStep. The pre-fallback count includes all
// rendered term variants and an explicit policy default when `next policy`
// can jump over it; one final fallback follows that count. A map with N
// pre-fallback sequences therefore has highest sequence number
// routeMapSeqStep*(N+1). Once that exceeds frrMaxRouteMapSeq FRR rejects the
// `route-map` line with CMD_WARNING_CONFIG_FAILED, and a single failed line
// makes the whole vtysh-batched frr-reload exit non-zero — poisoning the ENTIRE
// managed-section reload, not just this policy (#5701).
const (
	frrMaxRouteMapSeq = 65535
	routeMapSeqStep   = 10
	// MaxRouteMapSequences is the largest number of pre-fallback route-map
	// sequences a policy-statement may expand to before the final fallback's
	// highest FRR sequence number (routeMapSeqStep*(N+1)) would exceed
	// frrMaxRouteMapSeq. 65535/10 - 1 = 6552.
	MaxRouteMapSequences = frrMaxRouteMapSeq/routeMapSeqStep - 1
)

// policyStatementHasNextPolicy reports whether any term jumps to the next policy.
func policyStatementHasNextPolicy(ps *PolicyStatement) bool {
	if ps == nil {
		return false
	}
	for _, term := range ps.Terms {
		if term != nil && term.NextPolicy && term.Action == "" {
			return true
		}
	}
	return false
}

// CanonicalSourceProtocol maps Junos `from protocol` aliases to the spelling
// used by FRR route-map source-protocol matches.
func CanonicalSourceProtocol(proto string) string {
	if proto == "direct" {
		return "connected"
	}
	return proto
}

// uniqueCanonicalProtocolCount counts the distinct source-protocol matches
// after alias normalization, matching pkg/frr's sequence expansion.
func uniqueCanonicalProtocolCount(protos []string) int {
	if len(protos) == 0 {
		return 0
	}
	seen := make(map[string]struct{}, len(protos))
	for _, proto := range protos {
		seen[CanonicalSourceProtocol(proto)] = struct{}{}
	}
	return len(seen)
}

// RouteMapSequenceCount returns the FRR route-map sequences before the final
// fallback for ps: all rendered term variants, plus an explicit policy-default
// sequence when `then next policy` can jump over it. It mirrors the renderer's
// Cartesian expansion exactly: per term, (2 when the term's route-filters mix
// IPv4 and IPv6 families, else 1) x max(1,|from prefix-list|) x
// max(1,|from community|) x max(1,|from as-path|) x
// max(1,|unique canonical from protocol|), summed over terms. `direct` and
// `connected` are the same FRR source-protocol match and count only once.
// Term count depends on each term's OR-set lengths, route-filter family mix,
// referenced prefix-list families (not prefix entries), and source-protocol
// values. emitVariants emits one sequence per unique canonical protocol.
// Every multiply and the running sum are overflow-checked (checkedMulU64 /
// saturating add): a pathological crafted policy saturates to math.MaxUint64
// rather than wrapping back down into the in-bound range.
// #7526: po carries the prefix-list table, because the count depends on WHAT
// the referenced lists hold, not just how many are named. The renderer expands
// one prefix-list NAME into one match line per family it holds
// (fromPrefixListRefs), so a mixed v4+v6 list is TWO sequences. Counting names
// under-counted every such reference by exactly a factor of two, and a policy
// admitted just under MaxRouteMapSequences then rendered past FRR's ceiling.
//
// The parameter is REQUIRED rather than optional so the compiler enumerates
// every call site: an optional table would be nil at the sites that most need
// it, and the count would silently fall back to the old family-blind answer.
func RouteMapSequenceCount(po *PolicyOptionsConfig, ps *PolicyStatement) uint64 {
	if ps == nil {
		return 0
	}
	var total uint64
	for _, term := range ps.Terms {
		if term == nil {
			continue
		}
		fam := uint64(1)
		if termRouteFiltersMixFamily(term) {
			fam = 2
		}
		v := checkedMulU64(fam, TermPrefixListRefCount(po, term.PrefixList))
		v = checkedMulU64(v, orOneU64(len(term.FromCommunity)))
		v = checkedMulU64(v, orOneU64(len(term.FromASPath)))
		v = checkedMulU64(v, orOneU64(uniqueCanonicalProtocolCount(term.FromProtocols)))
		if total > math.MaxUint64-v {
			return math.MaxUint64
		}
		total += v
	}
	if policyStatementHasNextPolicy(ps) &&
		(ps.DefaultAction == "accept" || ps.DefaultAction == "reject") {
		if total == math.MaxUint64 {
			return total
		}
		total++
	}
	return total
}

// ComposedChainSequenceCount returns the FRR route-map sequences before the
// final fallback for an ordered BGP policy chain (`import`/`export [ A B ... ]`,
// #5277): the sum of RouteMapSequenceCount over members, truncated after the
// first explicit policy default with no `next policy` term. That default
// terminates ordinary fall-through and no route can reach later members.
//
// Like the single-policy RouteMapSequenceCount this EXCLUDES the final fallback
// sequence, so the SAME MaxRouteMapSequences ceiling applies — the composed
// map's highest FRR sequence number is routeMapSeqStep*(count+1).
// nil / undefined members are skipped, matching renderComposedRouteMap's
// `if ps == nil { continue }` (the chain is pre-filtered to defined statements).
// The running sum is saturating so a pathological chain never wraps back into
// the in-bound range. This is the SSOT the #5732 commit gate
// (validateBGPComposedChainSequenceBoundStrict) and the renderComposedRouteMap
// render-side belt BOTH consult, so they can never disagree on what overflows.
// #7526: po is required for the same reason as on RouteMapSequenceCount — the
// per-member count depends on what the referenced prefix-lists hold.
func ComposedChainSequenceCount(po *PolicyOptionsConfig, pss map[string]*PolicyStatement, chain []string) uint64 {
	var total uint64
	for _, name := range chain {
		ps := pss[name]
		if ps == nil {
			continue
		}
		n := RouteMapSequenceCount(po, ps)
		if total > math.MaxUint64-n {
			total = math.MaxUint64
		} else {
			total += n
		}
		// An explicit policy default normally terminates the chain. A matched
		// `next policy` term jumps around it, making the following member reachable.
		if (ps.DefaultAction == "accept" || ps.DefaultAction == "reject") &&
			!policyStatementHasNextPolicy(ps) {
			break
		}
	}
	return total
}

// orOneU64 clamps a slice length to a minimum of 1: a missing `from` OR-set
// still contributes one route-map sequence (the emitVariants "" sentinel).
func orOneU64(n int) uint64 {
	if n <= 0 {
		return 1
	}
	return uint64(n)
}

// termRouteFiltersMixFamily reports whether a term's route-filters carry BOTH
// an IPv4 and an IPv6 prefix — the condition under which the renderer SPLITS
// the term into a v4 sequence and a v6 sequence (#2607), doubling its
// per-term sequence count. Family is classified by the same `:` heuristic
// partitionRouteFiltersByFamily uses.
func termRouteFiltersMixFamily(term *PolicyTerm) bool {
	var v4, v6 bool
	for _, rf := range term.RouteFilters {
		if rf == nil {
			continue
		}
		if strings.Contains(rf.Prefix, ":") {
			v6 = true
		} else {
			v4 = true
		}
		if v4 && v6 {
			return true
		}
	}
	return false
}

// validatePolicyRouteMapSequenceBoundStrict rejects a policy-statement whose
// route-map term expansion would exceed the FRR route-map sequence-number
// ceiling. Rendering such a policy emits a `route-map <name> <action> <seq>`
// line with seq > 65535, which FRR rejects (CMD_WARNING_CONFIG_FAILED); a
// single failed line makes the vtysh add-batch of the frr-reload exit non-zero
// and POISONS the whole managed-section reload (#5701) — every route/policy in
// the section fails to apply, not just this one policy. Rejecting at commit
// keeps the overflow from ever reaching the renderer.
//
// Strict on commit / commit-check (hard reject so the operator sees which
// policy is oversized); downgraded to a warning on the tolerant load /
// peer-sync paths (opts.lenientPolicyRouteMapSeq, #1960 no-brick) — the
// renderer independently SKIPS an over-ceiling policy (generatePolicyOptions),
// so a leniently-loaded oversized policy renders nothing rather than poisoning
// the reload. Policy names are validated in sorted order for a deterministic
// first error. Mirrors validateNextTableTargetReferencesStrict.
func validatePolicyRouteMapSequenceBoundStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	pss := cfg.PolicyOptions.PolicyStatements
	if len(pss) == 0 {
		return nil
	}
	names := make([]string, 0, len(pss))
	for name := range pss {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		ps := pss[name]
		if ps == nil {
			continue
		}
		if n := RouteMapSequenceCount(&cfg.PolicyOptions, ps); n > MaxRouteMapSequences {
			return fmt.Errorf(
				"policy-statement %q expands to %d route-map sequences, over the "+
					"FRR ceiling of %d (route-map sequence numbers are 1..%d in steps "+
					"of %d, one reserved for the trailing default) — rendering it would "+
					"emit a `route-map` line past sequence %d, which FRR rejects and "+
					"which poisons the ENTIRE frr-reload; reduce the number of `from "+
					"protocol` / `from prefix-list` / `from community` / `from as-path` "+
					"values (their Cartesian product per term drives the count) or split "+
					"the policy across multiple policy-statements",
				name, n, MaxRouteMapSequences, frrMaxRouteMapSeq, routeMapSeqStep, frrMaxRouteMapSeq)
		}
	}
	return nil
}
