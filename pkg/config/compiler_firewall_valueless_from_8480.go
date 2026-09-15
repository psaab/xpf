package config

import (
	"fmt"
	"strings"
)

// #8480: the unshipped half of #8430.
//
// `set firewall family inet filter F term T from protocol` — with the value
// omitted — parses to `Keys=["protocol"]` with no tail and no children.
// firewallMatchValues skips "" and returns an empty slice, so term.Protocols is
// empty, and the term treats an empty match set as match-ANY rather than as an
// error. A stateless filter term silently widens to every protocol.
//
// This is the same defect security policies have rejected since #6526
// (policyValuelessMatchDimensions) and NAT since #8430
// (validateNATRuleMatchConstrainedStrict). #8430's title covers "NAT `match`
// AND firewall `from`", and only the NAT half shipped — every file touching
// that fix is NAT-side. So this is a consistency gap in an area already
// hardened twice, not a newly discovered class.
//
// SCOPE, and it is the whole risk of this gate. Not every `from` leaf is
// value-bearing: `is-fragment` is a presence-only FLAG (compileFirewall sets
// term.IsFragment = true and reads no values), and `flexible-match-range`
// carries its operands in CHILDREN with their own match-start/byte-offset
// grammar. Rejecting either would refuse a correct configuration. The list
// below is therefore the leaves compileFirewall actually reads through
// firewallMatchValues or firewallPrefixListRefs into a set the matcher
// interprets as match-ANY when empty — the same readers, so the gate and the
// compiler can never disagree about which leaves carry semantics in their
// operands.
var valueBearingFirewallFromLeaves = []string{
	"dscp",
	"traffic-class",
	"protocol",
	"next-header",
	"source-address",
	"destination-address",
	"source-prefix-list",
	"destination-prefix-list",
	"source-port",
	"destination-port",
	"source-port-except",
	"destination-port-except",
	"icmp-type",
	"icmp-code",
	"tcp-flags",
}

// firewallValueBearingFromLeaf is the membership test, built once from the
// declaration order above.
var firewallValueBearingFromLeaf = func() map[string]bool {
	m := make(map[string]bool, len(valueBearingFirewallFromLeaves))
	for _, l := range valueBearingFirewallFromLeaves {
		m[l] = true
	}
	return m
}()

// firewallTermValuelessFromLeaves returns the value-bearing `from` leaves a
// term WRITES but leaves EMPTY, in declaration order.
//
// It reads through the same helpers compileFirewall uses — firewallMatchValues
// for most leaves, firewallPrefixListRefs for the two prefix-list leaves, which
// have their own dual-shape reader (#3843) and would be misjudged by the
// general one. A gate that re-implemented the read would drift from the
// compiler, which is the defect one layer up.
//
// A leaf written more than once is valueless only if EVERY occurrence is: Junos
// merges duplicate blocks, so `from { protocol; }` beside `from { protocol tcp; }`
// is a constrained term and flagging it would refuse a correct config. That
// mirrors policyValuelessMatchDimensions' seen/valued split for the same reason.
func firewallTermValuelessFromLeaves(termNode *Node) []string {
	seen := map[string]bool{}
	valued := map[string]bool{}
	for _, from := range termNode.Children {
		if from.Name() != "from" {
			continue
		}
		for _, child := range from.Children {
			name := child.Name()
			if !firewallValueBearingFromLeaf[name] {
				continue
			}
			seen[name] = true
			// firewallMatchValues for EVERY leaf, including the two
			// prefix-list ones. The first version special-cased those through
			// firewallPrefixListRefs — their own dual-shape reader (#3843) —
			// on the theory that the general helper would misjudge them. A
			// mutation replacing the special case ESCAPED, and measuring it
			// showed why: across every prefix-list spelling the two readers
			// disagree only on CONTENT (`except` scoping), never on
			// EMPTINESS, which is the only question this gate asks.
			//
			//   source-prefix-list;                 matchValues=0 refs=0
			//   source-prefix-list pl1;             matchValues=1 refs=1
			//   source-prefix-list { pl1; }         matchValues=1 refs=1
			//   source-prefix-list { pl1 except; }  matchValues=2 refs=1
			//   source-prefix-list { }              matchValues=0 refs=0
			//
			// The special case was therefore unfalsifiable — a branch nothing
			// could distinguish, reading as a guard while binding nothing. It
			// is removed rather than kept as belt-and-braces.
			if len(firewallMatchValues(child)) > 0 {
				valued[name] = true
			}
		}
	}
	var out []string
	for _, leaf := range valueBearingFirewallFromLeaves {
		if seen[leaf] && !valued[leaf] {
			out = append(out, leaf)
		}
	}
	return out
}

// validateFirewallFilterValuelessFromStrict walks the group-expanded `firewall`
// subtree and rejects a term whose `from` writes a value-bearing leaf with no
// operand (#8480).
//
// Strict (commit / commit-check): the FIRST offending term is a hard error
// naming the family, filter, term and every valueless leaf, so the operator is
// told exactly which line to fix rather than which file.
//
// Lenient (load / peer-sync): every offending term is returned as a warning and
// compilation continues, so an already-persisted or peer-synced config an older
// binary silently accepted still BOOTS (#1960 no-brick). The term keeps its
// pre-existing match-any compilation, now flagged — same doctrine as
// validatePolicyRequiredMatchStrict and validateNATRuleMatchConstrainedStrict.
//
// It walks the AST rather than the compiled *Config because the defect is the
// ABSENCE of values: by the time compileFirewall has run, a valueless leaf and
// an omitted one are byte-identical empty slices, and nothing downstream can
// tell them apart. That is the same reason #6526 and #7525 run pre-walk.
func validateFirewallFilterValuelessFromStrict(children []*Node, lenient bool) ([]string, error) {
	var warnings []string
	// checkFilters gates every term under the given filter nodes, attributing
	// rejects to family ("" for the family-less spelling). Filter and term
	// names resolve through namedInstances, the same dual-shape reader
	// compileFirewall uses, so `filter { F { ... } }` and `term { T { ... } }`
	// block names are gated too.
	checkFilters := func(family string, filterNodes []*Node) error {
		for _, filterInst := range namedInstances(filterNodes) {
			for _, termInst := range namedInstances(filterInst.node.FindChildren("term")) {
				bad := firewallTermValuelessFromLeaves(termInst.node)
				if len(bad) == 0 {
					continue
				}
				where := fmt.Sprintf("firewall filter %q term %q", filterInst.name, termInst.name)
				if family != "" {
					where = fmt.Sprintf("firewall family %s filter %q term %q",
						family, filterInst.name, termInst.name)
				}
				msg := fmt.Sprintf("%s: `from %s` carries no value, and an "+
					"empty match set is read as match-ANY — the term matches "+
					"EVERY packet on that criterion rather than none, so a "+
					"`then discard` widens and a `then accept` opens. Give "+
					"the leaf a value; for an intentional wildcard, omit the "+
					"leaf entirely (#8480)",
					where, strings.Join(bad, ", "))
				if !lenient {
					return fmt.Errorf("%s", msg)
				}
				warnings = append(warnings, msg)
			}
		}
		return nil
	}
	for _, fw := range children {
		if fw.Name() != "firewall" {
			continue
		}
		// `firewall filter F` (no family) and `firewall family ...` are both
		// real spellings; the filter level is found by NAME rather than by
		// depth, in document order (which offending term strict reports first
		// when several offend is therefore unchanged from #8480).
		for _, fam := range fw.Children {
			switch fam.Name() {
			case "family":
				// BOTH shapes compileFirewall compiles, via the shared
				// firewallAFNodes walker (#9876): hierarchical
				// `family inet { filter ... }` and nested
				// `family { inet { filter ... } }`.
				for _, afArm := range firewallAFNodes(fam) {
					if err := checkFilters(afArm.af, afArm.node.FindChildren("filter")); err != nil {
						return nil, err
					}
				}
			case "filter":
				if err := checkFilters("", []*Node{fam}); err != nil {
					return nil, err
				}
			}
		}
	}
	return warnings, nil
}
