package config

import "fmt"

// validateDHCPRelayDHCPv6AST refuses `forwarding-options dhcp-relay dhcpv6`
// (#9411).
//
// xpf has NO DHCPv6 relay agent: pkg/dhcprelay relays DHCPv4 only, and its
// README says so under "IPv6 / DHCPv6 parity". That absence is documented and
// is not the defect. The defect is what AUTHORING the Junos DHCPv6 relay stanza
// did. Measured on all four config channels, with controls in the same run:
//
//	braced dhcpv6 relay       SchemaValidate/CompileConfig/Lenient/CheckText ACCEPT   relay 0 server-groups, 0 groups
//	CONTROL braced v4 relay   ACCEPT on all four                                      relay 1 server-group, 1 group
//	CONTROL bogus child       ACCEPT on all four                                      relay 0, 0
//	dhcpv6 BESIDE a v4 relay  ACCEPT on all four                                      only the v4 group survives
//	flat-set dhcpv6 relay     SchemaValidate/CompileConfig/Lenient ACCEPT            relay 0, 0
//
// So a stanza asking for a relay that does not exist was indistinguishable from
// garbage and from having authored nothing: it committed clean, rendered back
// in `show configuration`, and relayed nothing. Mechanism: the `dhcp-relay`
// schema node declares exactly `server-group` and `group`, the walk SKIPS an
// undeclared child rather than refusing it, and compileDHCPRelay reads only
// those two keywords.
//
// WHY ON THE AST. The stanza compiles to NOTHING, so by the time
// cfg.ForwardingOptions.DHCPRelay exists there is no trace of it left to
// validate — the reason #9017's family-token gate and #9323's routing-instance
// child gate run here too. It also avoids a config field whose only job would
// be to remember an absence.
//
// WHY NOT closedWorld ON dhcp-relay. closedWorld INHERITS, and it would refuse
// every OTHER undeclared child as well. The bogus-child control above is
// equally silent, but refusing arbitrary children needs its own census of
// shipped configs first, so that wider question is not folded in here.
//
// FIVE AST SHAPES, measured, and a gate checking one would miss the rest:
//
//	dhcp-relay { dhcpv6 { … } }              child node,  Keys=["dhcpv6"]
//	dhcp-relay { dhcpv6; }                   child leaf,  Keys=["dhcpv6"]
//	set … dhcp-relay dhcpv6 group …          child leaf,  Keys=["dhcpv6","group",…]
//	dhcp-relay dhcpv6 { … }                  the relay node's OWN Keys[1]
//	forwarding-options dhcp-relay dhcpv6 …;  forwarding-options' OWN Keys[1:3]
//
// THE PARSER PRODUCES FIVE; THE GATE SEES FOUR, measured by mutation rather than
// assumed. The brace-elision normalizer folds the fully elided spelling into the
// relay-node-Keys[1] shape BEFORE runPreWalkGates runs, so on every compile
// channel the forwarding-options-Keys clause below is never the one that fires:
// removing it SURVIVES every end-to-end #9411 cell, while removing the relay
// Keys[1] check reds the fully-elided row. It is KEPT rather than trimmed,
// because the normalizer is under active change (#8690, #8876) and a change that
// stopped folding this spelling would otherwise silently re-open it — and it is
// kept EXERCISABLE rather than excused:
// TestDHCPRelayDHCPv6GateSeesTheRawElidedShape9411 drives the gate on the RAW
// parser tree, where this clause is the only one that can fire.
//
// POSITION, NOT MEMBERSHIP, is what keeps this from over-rejecting. A DHCPv4
// relay GROUP or SERVER-GROUP may legitimately be NAMED `dhcpv6`
// (`dhcp-relay group dhcpv6 { … }`). That token sits after `group`, never
// immediately after `dhcp-relay` and never as a child's Name(), so a gate that
// searched for the token anywhere would refuse a working DHCPv4 relay.
//
// Strict on commit / commit-check; downgraded to a warning on the tolerant load
// / peer-sync paths (opts.lenientDHCPRelayDHCPv6) so a persisted or peer-synced
// config carrying the stanza still BOOTS (#1960).
//
// THE DOWNGRADE WAS NOT SAFE UNTIL THE COMPILER WAS FIXED TOO, and the first draft
// of this comment claimed it already was. "The stanza compiles to nothing" held
// for four of the five shapes. For `dhcp-relay dhcpv6 { group g6 { … } }` it was
// false, measured at the pristine base on all four channels:
//
//	dhcp-relay dhcpv6 { group g6 … }                    ACCEPT  v4-groups=[g6]
//	dhcp-relay dhcpv6 { g6 } THEN dhcp-relay { g1 v4 }   see compileForwardingOptions
//
// The elided spelling puts `dhcpv6` on the relay node's own Keys, so `group g6`
// is a direct child of a node named `dhcp-relay`, and compileForwardingOptions'
// FindChild("dhcp-relay") returned that node: a DHCPv6 relay group was installed
// as a DHCPv4 relay on the interface the operator named for DHCPv6. A warning in
// front of that would have been a warning in front of a mis-compile, not in front
// of an inert stanza. dhcpRelayV4Node9411 is what makes the downgrade inert.

func validateDHCPRelayDHCPv6AST(nodes []*Node, lenient bool) ([]string, error) {
	var warnings []string
	report := func(spelling string) error {
		msg := fmt.Sprintf("forwarding-options dhcp-relay dhcpv6 (%s): xpf has no DHCPv6 "+
			"relay agent — pkg/dhcprelay relays DHCPv4 only — so this stanza compiles to "+
			"NOTHING: it commits clean, renders in `show configuration`, and relays no "+
			"DHCPv6 at all. Remove it; a DHCPv4 relay under `forwarding-options dhcp-relay` "+
			"is unaffected (#9411)", spelling)
		if lenient {
			warnings = append(warnings, msg)
			return nil
		}
		return fmt.Errorf("%s", msg)
	}
	for _, fo := range nodes {
		if fo == nil || fo.Name() != "forwarding-options" {
			continue
		}
		// forwarding-options dhcp-relay dhcpv6 …;  — the fully elided spelling.
		if len(fo.Keys) >= 3 && fo.Keys[1] == "dhcp-relay" && fo.Keys[2] == "dhcpv6" {
			if err := report("elided spelling"); err != nil {
				return warnings, err
			}
		}
		for _, relay := range fo.FindChildren("dhcp-relay") {
			if relay == nil {
				continue
			}
			found := len(relay.Keys) >= 2 && relay.Keys[1] == "dhcpv6"
			for _, ch := range relay.Children {
				if ch != nil && ch.Name() == "dhcpv6" {
					found = true
				}
			}
			if found {
				// Once per relay node: the flat-set spelling yields one child PER
				// set line, and three identical warnings would read as three stanzas.
				if err := report("dhcp-relay dhcpv6"); err != nil {
					return warnings, err
				}
			}
		}
	}
	return warnings, nil
}

// dhcpRelayV4Node9411 returns the `dhcp-relay` node compileDHCPRelay should read:
// the FIRST one that is not the `dhcp-relay dhcpv6 { … }` spelling.
//
// It keeps FindChild's "first node wins" semantics for every DHCPv4 spelling, so
// this changes nothing for a config without the dhcpv6 token. It only stops the
// dhcpv6-elided node — whose `group` children are DHCPv6 groups — from being
// taken for the DHCPv4 relay, which both mis-compiled those groups as DHCPv4
// relays and, when that node came first, hid the real DHCPv4 relay block after it.
func dhcpRelayV4Node9411(fo *Node) *Node {
	if fo == nil {
		return nil
	}
	for _, n := range fo.FindChildren("dhcp-relay") {
		if n == nil {
			continue
		}
		if len(n.Keys) >= 2 && n.Keys[1] == "dhcpv6" {
			continue
		}
		return n
	}
	return nil
}
