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
// Each `from` node is read through packedBody with the SAME from-schema
// compileFilterFrom is lowered with (compiler_firewall.go), and the term itself
// is first lowered through its term schema. A from-packed leaf (`from
// protocol;`) lives on the from node's Keys, not its Children, while a
// term-packed leaf (`term T from protocol;`) lives on the term Keys. Reading
// both packed levels keeps the #8480 gate and #9875 marker aligned with the
// compiler rather than relying on whichever compact-normalizer pair happens
// to admit a spelling.
//
// A leaf written more than once is valueless only if EVERY occurrence is: Junos
// merges duplicate blocks, so `from { protocol; }` beside `from { protocol tcp; }`
// is a constrained term and flagging it would refuse a correct config. That
// mirrors policyValuelessMatchDimensions' seen/valued split for the same reason.
func firewallTermValuelessFromLeaves(termNode *Node, fromSchema *schemaNode) []string {
	// Spark-F2: a nil schema (unresolvable address family) would make
	// packedBody return raw Children, blinding this read to packed tails
	// exactly where the structural fix matters. The from-leaf set is
	// family-independent, so fall back to the inet from-schema and keep
	// packed sight regardless of family spelling.
	if fromSchema == nil {
		fromSchema = schemaForPath("firewall", "family", "inet", "filter", "term", "from")
	}
	if termNode == nil || fromSchema == nil {
		return nil
	}
	seen := map[string]bool{}
	valued := map[string]bool{}
	termSchema := schemaForPath("firewall", "family", "inet", "filter", "term")
	termBody := packedBody(termNode, termSchema)
	fromNodes := append([]*Node(nil), termBody.Children...)
	ambiguousFrom := map[*Node]bool{}
	// #10073: preserve a raw packed `from` node when the operand has the
	// same spelling as its prefix-list leaf. The schema now declares one
	// argument, so packedBody would otherwise reinterpret that operand as a
	// child statement; the normalizer deliberately preserves this ambiguous
	// raw spelling for the gate to resolve conservatively.
	if packedFroms := firewallPackedTermFromNodes(termNode, termSchema); len(packedFroms) > 0 {
		ambiguous := false
		for _, packedFrom := range packedFroms {
			for i := 1; i < len(packedFrom.Keys); i++ {
				leaf := packedFrom.Keys[i]
				if (leaf == "source-prefix-list" || leaf == "destination-prefix-list") &&
					i+1 < len(packedFrom.Keys) &&
					!packedFrom.KeyQuoted(i+1) &&
					packedFrom.Keys[i+1] == leaf {
					ambiguous = true
					break
				}
			}
			if ambiguous {
				break
			}
		}
		if ambiguous {
			fromNodes = nil
		}
		for _, packedFrom := range packedFroms {
			ambiguousFrom[packedFrom] = ambiguous
			fromNodes = append(fromNodes, packedFrom)
		}
	}
	for _, from := range fromNodes {
		if from.Name() != "from" {
			continue
		}
		ambiguousSelf := ambiguousFrom[from]
		// Read the operand distinction from the RAW tail: the token
		// following a leaf keyword is its operand unless it opens another
		// unquoted schema-known statement. Quoted keyword-shaped names and
		// non-keyword tokens are operands.
		for i := 1; i < len(from.Keys); i++ {
			leaf := from.Keys[i]
			if leaf != "source-prefix-list" && leaf != "destination-prefix-list" {
				continue
			}
			seen[leaf] = true
			if i+1 < len(from.Keys) && !from.KeyQuoted(i+1) && from.Keys[i+1] == leaf {
				ambiguousSelf = true
				continue
			}
			if i+1 < len(from.Keys) && (from.KeyQuoted(i+1) || resolveSchemaChild(fromSchema, from.Keys[i+1]) == nil) {
				valued[leaf] = true
			}
		}
		ambiguousFrom[from] = ambiguousSelf
		for _, child := range packedBody(from, fromSchema).Children {
			name := child.Name()
			if !firewallValueBearingFromLeaf[name] {
				continue
			}
			seen[name] = true
			if ambiguousSelf &&
				(name == "source-prefix-list" || name == "destination-prefix-list") &&
				len(child.Keys) > 1 && !child.KeyQuoted(1) && child.Keys[1] == name {
				continue
			}
			// #9875: the two prefix-list leaves are read through their own
			// dual-shape reader (firewallPrefixListRefs, #3843) — the SAME
			// reader compileFilterFrom uses — not the general
			// firewallMatchValues. The first version did exactly this, then
			// removed it as "unfalsifiable": across every prefix-list spelling
			// the two readers disagreed only on CONTENT (`except` scoping),
			// never on EMPTINESS, the only question this gate asks. That
			// measurement missed the self-named reference:
			// firewallMatchValues SKIPS a tail token equal to the leaf's own
			// keyword (the #8883 experiment) while firewallPrefixListRefs
			// keeps it as the reference name — so
			// `source-prefix-list "source-prefix-list";` (a defined list
			// legitimately named like the leaf; quoted keyword-shaped names
			// are legitimate per #9029) reads EMPTY here but compiles a REAL
			// resolving ref there. The falsifying row:
			//
			//   source-prefix-list "source-prefix-list";  matchValues=0 refs=1
			//
			// The gate then false-rejects a constrained term, and the #9875
			// marker — which shares this helper — would refuse that term's
			// snapshot on the tolerant path, amplifying a strict-gate false
			// positive into a boot/sync brick. Every other spelling agrees
			// (bare `source-prefix-list;` → 0/0, `pl1` → 1/1,
			// `{ pl1 except; }` → 2/1, `{ }` → 0/0), so this changes behavior
			// ONLY for self-named references: resolving ones now commit (the
			// false positive is gone) while dangling ones are still rejected
			// by the prefix-list reference gate. Same for
			// destination-prefix-list.
			isValued := len(firewallMatchValues(child)) > 0
			if name == "source-prefix-list" || name == "destination-prefix-list" {
				isValued = len(firewallPrefixListRefs(child)) > 0
			}
			if isValued {
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
	firewallPermitted := firewallFamilyPermitted9017()
	// checkFilters gates every term under the given filter nodes, attributing
	// rejects to displayFamily ("" for the family-less spelling). Filter and
	// term names resolve through namedInstances, the same dual-shape reader
	// compileFirewall uses, so `filter { F { ... } }` and `term { T { ... } }`
	// block names are gated too. The `from` schema each term is read under
	// resolves from af, the address family the filters compile under ("" for
	// the family-less and unknown-container spellings, where schemaForPath
	// yields nil and the helper falls back to the inet from-schema, #9875).
	checkFilters := func(af, displayFamily string, filterNodes []*Node) error {
		fromSchema := schemaForPath("firewall", "family", af, "filter", "term", "from")
		for _, filterInst := range namedInstances(filterNodes) {
			for _, termInst := range namedInstances(filterInst.node.FindChildren("term")) {
				bad := firewallTermValuelessFromLeaves(termInst.node, fromSchema)
				if len(bad) == 0 {
					continue
				}
				where := fmt.Sprintf("firewall filter %q term %q", filterInst.name, termInst.name)
				if displayFamily != "" {
					where = fmt.Sprintf("firewall family %s filter %q term %q",
						displayFamily, filterInst.name, termInst.name)
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
				// firewallFamilyMembers9883 extractor (#9876 over #9883):
				// hierarchical `family inet { filter ... }` and nested
				// `family { inet { filter ... } }`. Quarantined members
				// compile to NOTHING, so there are no compiled terms to
				// check — skipped exactly like the compiler skips them.
				for _, m := range firewallFamilyMembers9883(fam) {
					if firewallFamilyQuarantined9883(m, firewallPermitted) {
						continue
					}
					if err := checkFilters(m.Af, m.Af, m.AfNode.FindChildren("filter")); err != nil {
						return nil, err
					}
				}
			case "filter":
				if err := checkFilters("", "", []*Node{fam}); err != nil {
					return nil, err
				}
			default:
				// Unknown container directly under firewall: af stays ""
				// (schemaForPath yields nil, the helper falls back to the
				// inet from-schema). The compiler ignores these shapes; the
				// gate still polices nested filters in the safe
				// (reject-only) direction.
				if err := checkFilters("", fam.Name(), fam.FindChildren("filter")); err != nil {
					return nil, err
				}
			}
		}
	}
	return warnings, nil
}
