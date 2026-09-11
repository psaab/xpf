package config

import (
	"fmt"
	"sort"
	"strings"
)

// validateDHCPRelayChildTokensAST refuses a keyword directly under
// `forwarding-options dhcp-relay` that the schema does not declare (#9552).
//
// `dhcp-relay` was OPEN-WORLD at every config channel. The schema declares
// exactly `server-group` and `group`, the walk SKIPS an undeclared child, and
// compileDHCPRelay reads only those two, so
//
//	forwarding-options { dhcp-relay { xpfbogus { foo 1; } } }
//
// was accepted by SchemaValidate, CompileConfig, CompileConfigLenient and
// CheckText, and compiled to 0 server-groups and 0 groups. A typo, or a real
// Junos relay statement xpf does not implement, was indistinguishable from
// authoring nothing. #9411 refused only the `dhcpv6` token, by position, and
// left this wider question open pending a census.
//
// THE CENSUS: every tracked config-like file authors only `group` and
// `server-group` under dhcp-relay. Every other child in the Go test literals is
// #9411's `dhcpv6` fixtures, or `inactive: dhcpv6`, which is pruned before
// pre-walk gates run. So the gate refuses nothing the tree authors today.
//
// WHY NOT closedWorld ON dhcp-relay: it INHERITS, into `group` and `overrides`
// (the #9323 lesson). This gate is scoped to the dhcp-relay level and inherits
// nothing. THE PERMITTED SET IS READ FROM THE SCHEMA (#9017's rule), so a
// child declared later is permitted automatically.
//
// `dhcpv6` is skipped here: #9411's gate owns it, and its message says the
// relay AGENT does not exist, which is more useful than "unknown keyword".
// Meta statements (`apply-groups`, `apply-groups-except`, `apply-macro`) are
// skipped, as #9323 skips them.
//
// Strict on commit / commit-check; downgraded to a warning on the tolerant
// load / peer-sync paths (opts.lenientDHCPRelayChildTokens), so a persisted
// config still BOOTS (#1960). The stanza is inert either way, because
// compileDHCPRelay reads nothing but the two declared children.
func validateDHCPRelayChildTokensAST(nodes []*Node, lenient bool) ([]string, error) {
	declared := dhcpRelayChildTokens9552()
	if len(declared) == 0 {
		// The schema could not be read. Refusing every relay would turn a lookup
		// failure into an outage, so decline to judge.
		return nil, nil
	}
	permitted := make(map[string]bool, len(declared))
	for _, tok := range declared {
		permitted[tok] = true
	}
	var warnings []string
	seen := map[string]bool{}
	check := func(tok string) error {
		if tok == "" || tok == "dhcpv6" || permitted[tok] || routingInstanceApplyMetaKeyword9323(tok) {
			return nil
		}
		msg := fmt.Sprintf("forwarding-options dhcp-relay: %q is not a dhcp-relay statement "+
			"xpf implements (known: %s) — it compiles to NOTHING: it commits clean, renders "+
			"in `show configuration`, and relays nothing (#9552)", tok, strings.Join(declared, ", "))
		if !lenient {
			return fmt.Errorf("%s", msg)
		}
		// The flat-set spelling yields one node per set line, so one keyword
		// written on three lines must read as one statement, not three.
		if !seen[msg] {
			seen[msg] = true
			warnings = append(warnings, msg)
		}
		return nil
	}
	for _, fo := range nodes {
		if fo == nil || fo.Name() != "forwarding-options" {
			continue
		}
		// `forwarding-options dhcp-relay <tok> …;`, the fully elided spelling.
		if len(fo.Keys) >= 3 && fo.Keys[1] == "dhcp-relay" {
			if err := check(fo.Keys[2]); err != nil {
				return warnings, err
			}
		}
		for _, relay := range fo.FindChildren("dhcp-relay") {
			if relay == nil {
				continue
			}
			for _, tok := range dhcpRelayChildTokensOf9552(relay) {
				if err := check(tok); err != nil {
					return warnings, err
				}
			}
		}
	}
	return warnings, nil
}

// dhcpRelayChildTokens9552 returns the keywords the `forwarding-options
// dhcp-relay` schema node declares, sorted, for the gate and its message.
func dhcpRelayChildTokens9552() []string {
	fo := setSchema.children["forwarding-options"]
	if fo == nil {
		return nil
	}
	relay := fo.children["dhcp-relay"]
	if relay == nil {
		return nil
	}
	out := make([]string, 0, len(relay.children))
	for k := range relay.children {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// dhcpRelayChildTokensOf9552 returns the statement keywords one `dhcp-relay`
// node carries. The two sources are EXCLUSIVE, as #9323 measured for routing
// instances. A brace-elided `dhcp-relay group g1 { … }` packs its keyword on
// Keys[1], and its Children are that keyword's BODY. Only a bare `[dhcp-relay]`
// node, braced or flat-set, has Children that are relay statements.
func dhcpRelayChildTokensOf9552(relay *Node) []string {
	if len(relay.Keys) >= 2 {
		return []string{relay.Keys[1]}
	}
	var out []string
	for _, ch := range relay.Children {
		if ch != nil && ch.Name() != "" {
			out = append(out, ch.Name())
		}
	}
	return out
}
