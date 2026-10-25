package config

// NPTv6ScopeUnsupported reports whether an NPTv6 (RFC 6296) static-NAT rule
// carries a match-scope dimension the NPTv6 dataplane does not honor and is
// therefore EXCLUDED from the userspace snapshot (#5818 fail-closed).
//
// It is the single source of truth for two callers that must agree exactly on
// "does this rule reach the Rust helper":
//
//   - `pkg/dataplane/userspace.buildNptv6Snapshots` DROPS the rule, so it never
//     reaches `Nptv6State::try_from_snapshots`.
//   - `pkg/dataplane.compileNPTv6` reads it to choose the DISPOSITION of a
//     per-rule prefix fault. A rule that WILL be emitted must be a hard error:
//     the helper rejects the WHOLE snapshot on an unparseable / mismatched /
//     host-bits-set prefix, and that rejection lands at publish, AFTER
//     compileZones has created VLANs and reconciled addresses (#4960). A rule
//     that will be DROPPED must stay a warn-and-skip, because today's apply
//     SUCCEEDS without it and erroring would fail a config that works.
//
// The two directions fail differently and both are bad, which is why this is
// one function rather than two copies of a five-field predicate: disagreeing in
// the DROP direction rejects a working config, disagreeing in the EMIT
// direction lets the half-applied #4960 shape back in.
//
// `validateNPTv6ScopeStrict` deliberately stays separate rather than calling
// this: it must report WHICH dimension offends, per rule-set and per rule, in
// operator-facing text. This answers only the yes/no the two compile-path
// callers need. TestNPTv6ScopeUnsupportedMatchesTheStrictGate_4960 pins the two
// to the same answer.
//
// A nil rule-set or rule reports true (excluded). Neither caller can pass one —
// both skip nils first — and "excluded" is the direction that cannot turn a
// working config into a failed apply.
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
