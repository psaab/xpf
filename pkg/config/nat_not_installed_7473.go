package config

// Fail-closed "not installed" verdicts for NAT rules, in the composition every
// operator surface needs (#7473).
//
// The PREDICATES already lived here — `SourceNATPoolUnusableReason` and
// `DestinationNATRuleExcludedReason`. What did not was the two lines around
// them: which pool map to look the rule's pool up in, and what to answer when
// it is absent. `pkg/cli` had that composition privately; `pkg/api` and
// `pkg/grpcapi` were about to grow their own copies for the structured
// surfaces, and three copies of "which map, and what if it is missing" is three
// chances to answer it differently for the same rule.
//
// So the composition is exported once and all three surfaces call it. The text
// renderers and the JSON/protobuf objects then cannot disagree about which
// rules are armed, which is the whole point of the #6534 family: a surface that
// disagrees with the builder is the defect, and two surfaces that disagree with
// each other is the same defect twice.

// SourceNATRuleNotInstalledReason reports why the snapshot builder will not
// install this source-NAT rule, or "" when it is armed.
//
// Only pool-mode rules can be disarmed this way: interface-mode source NAT has
// no pool to be unusable, which is why the empty-pool-name arm returns "" and
// not a reason. That mirrors the builder, which gates on a non-empty pool name
// for exactly the same reason.
func SourceNATRuleNotInstalledReason(cfg *Config, rule *NATRule) string {
	if cfg == nil || rule == nil {
		return ""
	}
	// #9877: a match-content verdict disarms any non-exemption rule — pool,
	// interface or actionless — so it is asked BEFORE the pool-mode gate
	// below. It returns operator PROSE (a skipped rule ships nothing, so no
	// wire token exists); SourceNATDisarmReasonText echoes unknown tokens
	// verbatim, so the text renderers print it as-is and the structured
	// surfaces carry it in not_installed_reason unchanged.
	if reason := SourceNATRuleExcludedReason(rule); reason != "" {
		return reason
	}
	if rule.Then.PoolName == "" {
		return ""
	}
	// #8329: NO early return for a missing pool. This used to be
	//
	//	pool, ok := cfg.Security.NAT.SourcePools[rule.Then.PoolName]
	//	if !ok || pool == nil {
	//		return ""      // <- "armed"
	//	}
	//
	// which reported a rule naming an UNDEFINED pool as installed. The builder
	// does the opposite: it marks the rule unusable with the reason token
	// "missing_pool" (nat_source.go:98-102). So the surface said armed about a
	// rule the dataplane had disarmed -- the #6534 defect this very file exists
	// to prevent, in the composition written to prevent it.
	//
	// The fix is a DELETION, because the answer was already here:
	// SourceNATPoolUnusableReason returns "missing_pool" for a nil pool, and a
	// map miss yields exactly that nil. The short-circuit discarded a correct
	// verdict the predicate was about to give, and it discarded it in favour of
	// the one value that means "nothing is wrong".
	//
	// REACHABILITY, which is why this is a live defect and not dead code:
	// CompileConfig (strict) REFUSES an undefined pool reference, so the branch
	// is unreachable there. CompileConfigLenient ACCEPTS it -- and lenient is
	// the stored-config load and HA peer-sync path, i.e. a node that booted
	// from disk or took a config from its peer. That is precisely where a
	// config arrives without strict re-validation, and precisely where an
	// operator has no other signal.
	//
	// The empty-pool-name arm above is NOT this bug and must stay: an
	// interface-mode rule legitimately has no pool and IS armed. The two share
	// an exit and mean opposite things.
	return SourceNATPoolUnusableReason(cfg.Security.NAT.SourcePools[rule.Then.PoolName])
}

// DestinationNATRuleNotInstalledReason reports why the snapshot builder will
// not install this destination-NAT rule, or "" when it is armed.
//
// The destination predicate already returns operator prose, where the source
// one returns a token that `SourceNATDisarmReasonText` expands. Callers that
// render the reason must respect that difference; callers that only need the
// boolean can treat both alike.
func DestinationNATRuleNotInstalledReason(cfg *Config, rule *NATRule) string {
	if cfg == nil || rule == nil || cfg.Security.NAT.Destination == nil {
		return ""
	}
	return DestinationNATRuleExcludedReason(cfg.Security.NAT.Destination, rule)
}
