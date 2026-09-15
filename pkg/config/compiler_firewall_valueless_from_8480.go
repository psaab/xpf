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
// compileFilterFrom is lowered with (compiler_firewall.go) — not raw
// Children. A from-packed leaf (`from protocol;`) lives on the from node's
// Keys, not its Children, and a children-only read is blind to it while
// compilation still lowers it (to an empty match set). The pre-fix helper
// was exactly that blind: from-packed `protocol` was caught only because
// the compact normalizer happens to admit (from,protocol) and expands it
// before gates run — scope-accident, not structure. For a pair the
// normalizer declines the leaf compiled-but-unmarked with the strict gate
// missing it too. Reading packedBody makes gate and marker see packed
// tails BY CONSTRUCTION, aligned with compilation regardless of
// normalizer scope. Braced shapes are unaffected (packedBody returns the
// original node when there is nothing to expand), and term-level packing
// still escapes (there is no `from` child at all on a term-packed node —
// the pinned #10072 escape, which the strict gate misses identically).
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
	seen := map[string]bool{}
	valued := map[string]bool{}
	for _, from := range termNode.Children {
		if from.Name() != "from" {
			continue
		}
		// GPT-F2/#10081: packedBody reinterprets a keyword-shaped OPERAND
		// as another statement (the prefix-list leaf schema declares zero
		// args), so `from source-prefix-list "source-prefix-list";`
		// synthesizes valueless children for a valued ref — where an AAA
		// operand bails the expansion entirely. Read the operand
		// distinction from the RAW tail: the token following the leaf
		// keyword is its operand UNLESS it opens a new statement, i.e. an
		// unquoted schema-known head (packedBody's own rule, plus the
		// quoting it ignores). Quoted keyword-shaped names are legitimate
		// operands (#9029); a non-keyword token is always an operand.
		// Only a tail-END leaf, or one followed by a new statement head,
		// is valueless here. (Unquoted keyword operand, `from
		// source-prefix-list source-prefix-list;`, therefore reads as two
		// valueless statements and rejects — while the braced reader
		// quote-blindly keeps it as a ref. The grammar genuinely cannot
		// tell them apart; #9029 legitimizes the quoted spelling, and an
		// unquoted keyword-named list is dangling-gated on the braced
		// side too. Statement splitting inside packed tails otherwise
		// stays #10081's to own.)
		for i := 1; i < len(from.Keys); i++ {
			leaf := from.Keys[i]
			if leaf != "source-prefix-list" && leaf != "destination-prefix-list" {
				continue
			}
			seen[leaf] = true
			if i+1 < len(from.Keys) && (from.KeyQuoted(i+1) || resolveSchemaChild(fromSchema, from.Keys[i+1]) == nil) {
				valued[leaf] = true
			}
		}
		for _, child := range packedBody(from, fromSchema).Children {
			name := child.Name()
			if !firewallValueBearingFromLeaf[name] {
				continue
			}
			seen[name] = true
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
	for _, fw := range children {
		if fw.Name() != "firewall" {
			continue
		}
		for _, fam := range fw.Children {
			// `firewall filter F` (no family) and `firewall family inet
			// filter F` are both real spellings; the first has `filter` where
			// the second has a family, so the filter level is found by NAME
			// rather than by depth. The set-command shape `family { inet {
			// ... } }` is a third: the compiler descends into the
			// family-name children (compileFirewall), so the gate must too —
			// skipping them lets a valueless leaf COMMIT while compilation
			// records the marker, and the marker then refuses the snapshot
			// of a committed config (boot brick). Each group carries the
			// address family its from-schema resolves under, plus the
			// family name the diagnostic prints (the resolved af — NOT
			// the container keyword, which would print "family family").
			type famFilters struct {
				af      string
				famName string
				filters []*Node
			}
			var groups []famFilters
			switch {
			case fam.Name() == "filter":
				groups = append(groups, famFilters{"", "", []*Node{fam}})
			case fam.Name() == "family" && len(fam.Keys) < 2:
				for _, afNode := range fam.Children {
					af := afNode.Name()
					if len(afNode.Keys) >= 2 {
						af = afNode.Keys[1]
					}
					groups = append(groups, famFilters{af, af, afNode.Children})
				}
			case fam.Name() == "family":
				af := ""
				if len(fam.Keys) >= 2 {
					af = fam.Keys[1]
				}
				groups = append(groups, famFilters{af, af, fam.Children})
			default:
				// Unknown container directly under firewall: af stays ""
				// (schemaForPath yields nil, the helper falls back to the
				// inet from-schema). The compiler ignores these shapes; the
				// gate still polices nested filters in the safe
				// (reject-only) direction.
				groups = append(groups, famFilters{"", fam.Name(), fam.Children})
			}
			for _, g := range groups {
				fromSchema := schemaForPath("firewall", "family", g.af, "filter", "term", "from")
				for _, filt := range g.filters {
					if filt.Name() != "filter" {
						continue
					}
					// GPT-F1: resolve filter and term INSTANCES exactly as
					// the compiler does (namedInstances at both levels). A
					// nested filter-name node (`filter { F { ... } }`) has
					// no `term` children itself, and a nested term-name node
					// (`term { T { ... } }`) holds no `from` — inspecting
					// the wrappers instead of the resolved instances lets a
					// valueless leaf commit while compilation records the
					// marker on the actual term.
					for _, fi := range namedInstances([]*Node{filt}) {
						for _, termNode := range fi.node.FindChildren("term") {
							for _, ti := range namedInstances([]*Node{termNode}) {
								bad := firewallTermValuelessFromLeaves(ti.node, fromSchema)
								if len(bad) == 0 {
									continue
								}
								where := fmt.Sprintf("firewall filter %q term %q", fi.name, ti.name)
								if g.famName != "" {
									where = fmt.Sprintf("firewall family %s filter %q term %q",
										g.famName, fi.name, ti.name)
								}
								msg := fmt.Sprintf("%s: `from %s` carries no value, and an "+
									"empty match set is read as match-ANY — the term matches "+
									"EVERY packet on that criterion rather than none, so a "+
									"`then discard` widens and a `then accept` opens. Give "+
									"the leaf a value; for an intentional wildcard, omit the "+
									"leaf entirely (#8480)",
									where, strings.Join(bad, ", "))
								if !lenient {
									return nil, fmt.Errorf("%s", msg)
								}
								warnings = append(warnings, msg)
							}
						}
					}
				}
			}
		}
	}
	return warnings, nil
}
