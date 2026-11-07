package config

// NPTv6ScopeUnsupported reports whether an NPTv6 (RFC 6296) static-NAT rule
// carries a match-scope dimension the NPTv6 dataplane does not honor and is
// therefore EXCLUDED from the userspace snapshot (#5818 fail-closed).
//
// NPTv6Rules calls this once per NPTv6 rule and carries the result in its
// canonical reference. The snapshot builder and compileNPTv6 both consume that
// reference: a dropped rule never reaches the Rust helper and keeps
// warn-and-skip for a per-rule prefix fault; an emitted rule is subject to the
// #4960 validate-before-mutate check because Rust rejects the whole snapshot on
// an unparseable, mismatched, or host-bits-set prefix.
//
// Keeping the membership decision in one helper avoids two bad directions:
// disagreeing on DROP rejects a working config, while disagreeing on EMIT lets
// the half-applied #4960 shape back in. The overlap and external-prefix gates
// use the same Installed verdict from NPTv6Rules.
//
// `validateNPTv6ScopeStrict` also consumes NPTv6Rules, but uses its
// ScopeUnsupported detail to report WHICH dimension offends in
// operator-facing text. TestNPTv6ScopeUnsupportedMatchesTheStrictGate_4960
// pins the shared decision.
//
// A nil rule-set or rule reports true (excluded); NPTv6Rules skips nil entries
// before calling this predicate, so nil cannot reach a downstream consumer.
func NPTv6ScopeUnsupported(rs *StaticNATRuleSet, rule *StaticNATRule) bool {
	if rs == nil || rule == nil {
		return true
	}
	// Rule-set scope: the wire carries only `from zone`, so an interface- or
	// routing-instance-scoped rule would install as a broader zone/global
	// rewrite. #16604: an explicit master (`routing-instance default`)
	// scope is likewise a constraint the wire would drop.
	if rs.FromInterface != "" || rs.FromRoutingInstance != "" || rs.FromRoutingInstanceDefault {
		return true
	}
	// Per-rule scope: a `match source-address` or `match destination-port` is
	// likewise dropped by the wire, so the rule would translate every source /
	// every port.
	return len(rule.SourceAddresses) > 0 || rule.SourceAddress != "" ||
		rule.MatchDestinationPort != 0
}
