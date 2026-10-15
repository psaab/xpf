package natshow

import "github.com/psaab/xpf/pkg/config"

// rule_action_8580.go — #8580.
//
// THE DRIFT. Five surfaces render a source-NAT rule's action, and each computed
// it from its own copy of the same switch. Measured before this file existed,
// counting reads of `Then.Off` per file:
//
//	pkg/natshow/source.go        1
//	pkg/cli/cli_show_nat.go      0   (3 bare `action := "interface"`)
//	pkg/api/nat.go               0   (1)
//	pkg/grpcapi/server_nat.go    0   (1)
//
// So #7640 — "render the action the rule ACTUALLY carries", which stopped an
// ACTIONLESS rule from claiming an action it does not have and will not
// perform — landed in ONE copy and left the other four wrong. Every other
// surface still reported `then source-nat off` (a no-NAT exemption, #3844) as
// `interface`, i.e. as the exact opposite of what the rule does: exempt from
// NAT, rendered as NAT'ing via the egress interface.
//
// #7363 has the identical shape one field over: `natMatchAddresses` is read 3
// times in `pkg/natshow` and 0 times anywhere else, so a rule scoped by an
// address-book NAME renders as `0.0.0.0/0` — matching everything — on every
// surface but one.
//
// WHY THIS IS SINGLE-SOURCED RATHER THAN CROSS-CHECKED. An agreement test
// between five copies asserts they say the same thing; it does not stop a sixth
// copy being written, and it must pick a spelling to compare against, which
// encodes which copy is trusted. Routing every surface through one function
// removes the class: there is nothing left to disagree.
//
// The strings are deliberately identical across CLI, REST and gRPC. They were
// already meant to be — each copy was a transcription of the same four cases —
// and an operator who greps a REST response for the action their CLI showed
// should find it.

// SourceRuleAction renders a source-NAT rule's action exactly as
// `show security nat source rule detail` does.
//
// The `none` case is load-bearing and is NOT a placeholder for "interface":
// a rule with no `then` at all is rejected by the strict commit gate but is
// admitted by a tolerant load (#1960), and it performs no translation. Naming
// it `interface` tells the operator the one rule shape they most need to find
// is doing something it is not (#7640).
func SourceRuleAction(rule *config.NATRule) string {
	switch {
	case rule == nil:
		return "none"
	case rule.Then.PoolName != "":
		return "pool " + rule.Then.PoolName
	case rule.Then.Off:
		return "off"
	case rule.Then.Interface:
		return "interface"
	default:
		return "none"
	}
}

// DestRuleAction renders the action of a destination-NAT rule consistently
// across text and structured output. An actionless rule is not explicitly off.
func DestRuleAction(rule *config.NATRule) string {
	switch {
	case rule == nil:
		return "none"
	case rule.Then.PoolName != "":
		return "pool " + rule.Then.PoolName
	case rule.Then.Off:
		return "off"
	default:
		return "none"
	}
}

// RuleMatchSource renders a rule's complete source-address match, or the
// caller-visible "any" spelling when it has none. See match_addresses_7363.go
// for why the plural supersedes the singular rather than joining it.
//
// Named for the SIDE, not the rule kind: source-NAT and destination-NAT rules
// carry the same `Match` field set, so the destination-NAT renderers use these
// too. That matters because the singular-only copy had spread to BOTH kinds —
// the census in this package's test found three destination-side copies after
// the source side was routed through here.
func RuleMatchSource(rule *config.NATRule) string {
	if rule == nil {
		return "0.0.0.0/0"
	}
	if m := natMatchAddresses(
		rule.Match.SourceAddress, rule.Match.SourceAddresses,
		rule.Match.SourceAddressName, rule.Match.SourceAddressNames,
	); m != "" {
		return m
	}
	return "0.0.0.0/0"
}

// RuleMatchDestination is RuleMatchSource for the destination side.
func RuleMatchDestination(rule *config.NATRule) string {
	if rule == nil {
		return "0.0.0.0/0"
	}
	if m := natMatchAddresses(
		rule.Match.DestinationAddress, rule.Match.DestinationAddresses,
		rule.Match.DestinationAddressName, rule.Match.DestinationAddressNames,
	); m != "" {
		return m
	}
	return "0.0.0.0/0"
}
