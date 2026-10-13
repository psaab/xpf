package config

import "fmt"

// #12528: two firewall `from` leaves read less than an operator can write
// under them, and a term action written there is dropped without a word.
//
// `is-fragment` is a bare flag: compileFilterFrom sets term.IsFragment and
// reads nothing else from the node. `flexible-match-range` is read only
// through its named `range` instances, each through its six range fields. A
// missing `;` or a misplaced brace parks the term's action under one of them,
//
//	set ... term T from is-fragment then discard          (flat set, load set)
//	term T { from { is-fragment then discard; } }         (hierarchical)
//	range R { byte-offset 9; then discard; }              (flexible-match-range)
//
// and the term compiles with an EMPTY Action. The userspace filter engine
// reads that as a fall-through, so an intended discard or reject accepts,
// while `show configuration` still prints the action the operator wrote.
//
// The gate reads POSITIONS, never spellings. Its first version matched the
// two words anywhere under `firewall` and refused configs that compile
// correctly: a term, filter or prefix-list reference named `is-fragment`
// (quoted or not), a range named `then`, `from is-fragment protocol udp;`.
// Keyword-shaped names are legitimate (#9029), and a plain "a bare flag takes
// no trailing tokens" check was measured wrong once already (#8437,
// docs/config-schema.md). So filters and terms are found with namedInstances,
// `from` statements with firewallTermFromNodes and leaves with packedBody under
// the from-schema -- the readers compileFirewall itself uses, as the #8480 gate
// does -- and only a token those readers walk past is reported.

// fusedThen12528 is the first statement under one term's is-fragment or
// flexible-match-range leaf that the firewall compiler never reads.
type fusedThen12528 struct {
	leaf  string // "is-fragment" or "flexible-match-range"
	token string // the first unread token
	// packedTerm marks the term-level packed spelling (packedTermFromThen12528):
	// it compiles with its action, but its set form does not.
	packedTerm bool
}

// firewallTermFusedThen12528 returns the first unread statement under one term
// instance. termNode is the namedInstances node compileFirewall compiles, and
// termSchema/fromSchema are the schemas it lowers that node with.
func firewallTermFusedThen12528(termNode *Node, termSchema, fromSchema *schemaNode) (fusedThen12528, bool) {
	flexSchema := resolveSchemaChild(fromSchema, "flexible-match-range")
	fromNodes, _ := firewallTermFromNodes(termNode, termSchema)
	for _, from := range fromNodes {
		for _, leaf := range packedBody(from, fromSchema).Children {
			switch leaf.Name() {
			case "is-fragment":
				if token, ok := isFragmentUnread12528(leaf); ok {
					return fusedThen12528{leaf: "is-fragment", token: token}, true
				}
			case "flexible-match-range":
				if flexibleMatchRangeThen12528(leaf, flexSchema) {
					return fusedThen12528{leaf: "flexible-match-range", token: "then"}, true
				}
			}
		}
	}
	if leaf, ok := packedTermFromThen12528(termNode, termSchema, fromSchema); ok {
		return fusedThen12528{leaf: leaf, token: "then", packedTerm: true}, true
	}
	return fusedThen12528{}, false
}

// isFragmentUnread12528 returns the first token written after a bare
// `is-fragment` flag. Both shapes occur: a braced `is-fragment then discard;`
// keeps the tail on the leaf's Keys, while SetPath (flat set, interactive set,
// the LoadMerge replay) nests it as a statement beneath the leaf.
func isFragmentUnread12528(leaf *Node) (string, bool) {
	if len(leaf.Keys) > 1 {
		return leaf.Keys[1], true
	}
	if len(leaf.Children) > 0 {
		return leaf.Children[0].Name(), true
	}
	return "", false
}

// flexibleMatchRangeThen12528 reports a `then` statement anywhere the
// flexible-match-range reader in compileFilterFrom walks past: beside the
// ranges, inside a range body, beneath or after a range field's value, or in a
// packed run packedBody declines to expand. A range NAMED `then` is an
// identity -- consumeNodeKeys spends it as the range's argument, and
// namedInstances resolves the block-named spelling -- so it never matches.
// Other unread statements there are outside this gate (docs/log/12528.md).
func flexibleMatchRangeThen12528(flex *Node, flexSchema *schemaNode) bool {
	if flexSchema == nil {
		return false
	}
	body := packedBody(flex, flexSchema)
	if packedRunThen12528(body, flexSchema) || thenStatement12528(body.Children) {
		return true
	}
	rangeSchema := resolveSchemaChild(flexSchema, "range")
	if rangeSchema == nil {
		return false
	}
	for _, inst := range namedInstances(body.FindChildren("range")) {
		rangeBody := packedBody(inst.node, rangeSchema)
		if packedRunThen12528(rangeBody, rangeSchema) || thenStatement12528(rangeBody.Children) {
			return true
		}
		for _, field := range rangeBody.Children {
			fieldSchema := resolveSchemaChild(rangeSchema, field.Name())
			if fieldSchema == nil {
				continue
			}
			// A field spends one value; statements after it in the same run
			// belong to the range (expandResolvingRuns9792 splits them there).
			consumed, cur := consumeNodeKeys(field.Keys, fieldSchema)
			if runThen12528(field, consumed, []*schemaNode{rangeSchema, cur}) ||
				thenStatement12528(field.Children) {
				return true
			}
		}
	}
	return false
}

// thenStatement12528 reports an unquoted `then` statement among nodes.
func thenStatement12528(nodes []*Node) bool {
	for _, n := range nodes {
		if n != nil && n.Name() == "then" && !n.KeyQuoted(0) {
			return true
		}
	}
	return false
}

// packedRunThen12528 reports whether node's packed key run reaches an unquoted
// `then` no open level declares -- the token packedBody gives up on, leaving
// the whole run unread.
func packedRunThen12528(node *Node, schema *schemaNode) bool {
	if node == nil || schema == nil || len(node.Keys) == 0 {
		return false
	}
	consumed, cur := consumeNodeKeys(node.Keys, schema)
	return runThen12528(node, consumed, []*schemaNode{cur})
}

// runThen12528 walks node.Keys[i:] the way packedBodyChildren does -- each
// statement resolves at the deepest open level and spends its declared
// arguments -- and reports an unquoted `then` at a statement position. A
// token no level declares has no knowable arity, so the walk steps past it
// one token at a time; `then` is never declared under from,
// flexible-match-range or range, so a statement-position `then` there is
// always the term action, never an operand.
func runThen12528(node *Node, i int, levels []*schemaNode) bool {
	for i < len(node.Keys) {
		bare := !node.KeyQuoted(i) && !node.KeyBracketed(i)
		at := -1
		var child *schemaNode
		for level := len(levels) - 1; bare && level >= 0; level-- {
			if candidate := resolveSchemaChild(levels[level], node.Keys[i]); candidate != nil {
				at, child = level, candidate
				break
			}
		}
		if child == nil {
			if bare && node.Keys[i] == "then" {
				return true
			}
			i++
			continue
		}
		n, refined := consumeNodeKeys(node.Keys[i:], child)
		if n <= 0 {
			n = 1
		}
		levels = append(levels[:at+1], refined)
		i += n
	}
	return false
}

// packedTermFromThen12528 reports the term-level packed spelling whose `from`
// statement ends at is-fragment, or inside flexible-match-range, and is
// followed by the term's `then`:
//
//	term T from is-fragment then discard;
//	term T from is-fragment { then discard; }
//	term T from flexible-match-range range R match-value 0x11 then discard;
//
// packedBody splits these at the term level, so they compile WITH their
// action. Their set form does not: `show configuration | display set` and the
// LoadMerge replay print `set ... term T from is-fragment then discard`, and
// SetPath nests that `then` under the leaf, where the action is dropped. The
// replayed shape is refused by the checks above, so the packed spelling is
// refused at its own commit too: one spelling, one verdict on every load path.
func packedTermFromThen12528(termNode *Node, termSchema, fromSchema *schemaNode) (string, bool) {
	froms, next := firewallPackedTermFromStatements(termNode, termSchema, true)
	for i, from := range froms {
		switch next[i] {
		case "then":
		case "":
			// A trailing block is written beneath the run's last statement, so
			// `term T from is-fragment { then discard; }` renders as one path.
			if termNode.FindChild("then") == nil {
				continue
			}
		default:
			continue
		}
		roots := packedBody(from, fromSchema).Children
		if len(roots) == 0 {
			continue
		}
		switch leaf := roots[len(roots)-1].Name(); leaf {
		case "is-fragment", "flexible-match-range":
			return leaf, true
		}
	}
	return "", false
}

// message renders one finding. Names come from the instance walk, so packed,
// block-named and flat-set terms are all named exactly as authored, and the
// remedy is one that commits: an action moves to the term's own `then`
// block, never to a `then` inside `from` (which `from then` refuses).
func (f fusedThen12528) message(family, filter, term string) string {
	where := fmt.Sprintf("firewall filter %q term %q", filter, term)
	if family != "" {
		where = fmt.Sprintf("firewall family %s filter %q term %q", family, filter, term)
	}
	switch {
	case f.packedTerm:
		return fmt.Sprintf("%s: the packed spelling `from %s ... then ...` compiles, but its "+
			"set form (`show configuration | display set`, the `load merge` replay) nests "+
			"`then` under `%s`, where the firewall compiler never reads the action. Write "+
			"`from` and `then` as separate statements: `term <name> { from ...; then ...; }` "+
			"(#12528)", where, f.leaf, f.leaf)
	case f.leaf == "is-fragment" && f.token == "then":
		return fmt.Sprintf("%s: `then` follows `from is-fragment`, a bare flag that takes no "+
			"value or statements, so the firewall compiler never reads the action while "+
			"`show configuration` still displays it. The term is left with no action and "+
			"falls through to later terms. Move the action to the term's own block: "+
			"`from { is-fragment; } then { ...; }` (#12528)", where)
	case f.leaf == "is-fragment":
		return fmt.Sprintf("%s: token %q follows `from is-fragment`, a bare flag that takes "+
			"no value or statements, so the firewall compiler never reads it while "+
			"`show configuration` still displays it. Give `is-fragment` a statement of its "+
			"own: `from { is-fragment; ...; }`, or one `set ... from` command per match "+
			"(#12528)", where, f.token)
	default:
		return fmt.Sprintf("%s: `then` is written inside `from flexible-match-range`, which "+
			"reads only its named ranges and their match-start, byte-offset, bit-length, "+
			"match-value, match-mask and range fields, so the firewall compiler never reads "+
			"the action while `show configuration` still displays it. The term is left with "+
			"no action and falls through to later terms. Move the action to the term's own "+
			"block: `from { flexible-match-range { ... } } then { ...; }` (#12528)", where)
	}
}

// validateFirewallFusedThenStrict12528 walks the group-expanded `firewall`
// subtree and reports every term whose is-fragment or flexible-match-range
// leaf carries a statement the firewall compiler never reads (#12528).
//
// Strict (commit / commit-check): the FIRST offending term, in document order,
// is a hard error naming the family, filter, term and unread token. Lenient
// (Store.Load / Store.SyncApply): EVERY offending term is a warning and
// compilation continues, so a config an older binary persisted or a peer
// synced still boots (#1960). The term keeps its historical compilation, now
// flagged; for the fused shapes that is still a fall-through.
//
// It runs in the compiler pre-walk beside #8480 and NOT in the schema walk.
// The commit path runs SchemaValidate first, so the typed-leaf (#1319) and
// fused-sibling (#8437) diagnostics keep their precedence, and Store.Load
// still records its [typed-leaf-tolerated] warning. Nameless terms are left to
// the #10294 gate, which rejects them with its more specific diagnostic.
// Quarantined families compile to nothing (#9883) and are skipped, as the
// compiler skips them.
func validateFirewallFusedThenStrict12528(children []*Node, lenient bool) ([]string, error) {
	var warnings []string
	permitted := firewallFamilyPermitted9017()
	checkFilters := func(af, displayFamily string, filterNodes []*Node) error {
		termSchema := schemaForPath("firewall", "family", af, "filter", "term")
		fromSchema := schemaForPath("firewall", "family", af, "filter", "term", "from")
		if termSchema == nil || fromSchema == nil {
			// Family-less spelling: the same inet fallback compileFilterFrom
			// and the #8480 gate use.
			termSchema = schemaForPath("firewall", "family", "inet", "filter", "term")
			fromSchema = schemaForPath("firewall", "family", "inet", "filter", "term", "from")
		}
		for _, filterInst := range namedInstances(filterNodes) {
			termNodes := filterInst.node.FindChildren("term")
			nameless := firewallNamelessTermNodes(termNodes)
			for _, termInst := range namedInstances(termNodes) {
				if _, skip := nameless[termInst.node]; skip {
					continue
				}
				finding, ok := firewallTermFusedThen12528(termInst.node, termSchema, fromSchema)
				if !ok {
					continue
				}
				msg := finding.message(displayFamily, filterInst.name, termInst.name)
				if !lenient {
					return fmt.Errorf("%s", msg)
				}
				warnings = append(warnings, msg)
			}
		}
		return nil
	}
	for _, fw := range children {
		if fw == nil || fw.Name() != "firewall" {
			continue
		}
		for _, child := range fw.Children {
			if child == nil {
				continue
			}
			switch child.Name() {
			case "family":
				for _, m := range firewallFamilyMembers9883(child) {
					if firewallFamilyQuarantined9883(m, permitted) {
						continue
					}
					if err := checkFilters(m.Af, m.Af, m.AfNode.FindChildren("filter")); err != nil {
						return nil, err
					}
				}
			case "filter":
				if err := checkFilters("", "", []*Node{child}); err != nil {
					return nil, err
				}
			}
		}
	}
	return warnings, nil
}
