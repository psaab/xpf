package config

// Routing-policy terms whose packed body the generic expander declines
// (#12537).
//
// A group's packed `term T from ... then ...;` merges into its inline peer
// through the body packedBodyChildren synthesizes (#7648/#9855). That expander
// is all-or-nothing: one token outside the modelled grammar — the `reject` in
// `from route-filter 10.0.0.0/8 orlonger reject`, an `upto /bogus` trailer,
// the second value of `from protocol static bgp`, the value of `then community
// add C1` — and it synthesizes nothing. The merge then kept the inline term
// and silently dropped the group's: its route-filter vanished, the term
// compiled match-all accept, and strict validation never saw the tail that
// the direct spelling rejects. An inline term the expander declines had the
// mirror image: promotion bailed and the group's term was dropped the same
// way, route-filter and all.
//
// policyTermBody12537 rebuilds such a tail as the braced body the compiler
// reads, with the compiler's own readers rather than a third one:
//
//   - every `from` clause becomes one `from` container holding
//     splitPolicyTermFromRun11779's split of its run — the reader
//     parsePolicyTermChildren applies to a packed `from` line — so each match
//     merges as one statement and an unknown word stays an opaque leaf that
//     the #11779 gate rejects, as it does in the direct spelling;
//   - every `then` clause is cut into one statement per action, the shape the
//     expander gives each run it can model and the shape expandFlatRun reads:
//     an action keeps the operands its schema declares, a multi-value action
//     (community, as-path-prepend) keeps its values, and any other token stays
//     on the action it follows, where the #12517 tail gate names it. The
//     actions therefore merge with the other side's `then` exactly as an
//     expanded body's do, so a malformed group action is rejected instead of
//     being dropped.
//
// A `then` clause that opens with an unknown action word has no action to
// carry it. A group's becomes an unknown statement of its `then` block, which
// warns (#10707) as the braced spelling does instead of vanishing; an inline
// peer's makes the rebuild decline, so the peer keeps its packed line, where
// the direct reader rejects the word as the operator wrote it.
//
// Only routing-policy terms take this path: splitPolicyTermFromRun11779 and
// the #12517 `then` gate belong to the routing-policy compiler, and a firewall
// filter term compiles through its own readers. The first version of this fix
// re-read every merged `term` with the routing-policy `from` schema and split
// valid firewall matches into valueless leaves (#12696 review B1).

// policyTermBody12537 returns the braced body for a packed routing-policy term
// leaf, or nil when leafSchema is not the policy-options term schema, the node
// carries children, its tail does not open with a `from` or `then` clause, or
// inline is set and a `then` clause opens with an unknown action word.
func policyTermBody12537(leafSchema *schemaNode, term *Node, inline bool) []*Node {
	if term == nil || len(term.Children) > 0 || leafSchema == nil ||
		leafSchema != schemaForPath("policy-options", "policy-statement", "term") {
		return nil
	}
	fromSchema := resolveSchemaChild(leafSchema, "from")
	thenSchema := resolveSchemaChild(leafSchema, "then")
	keys := term.Keys
	i, _ := consumeNodeKeys(keys, leafSchema)
	if fromSchema == nil || thenSchema == nil || i >= len(keys) ||
		!policyTermClauseKeyword11779(keys[i]) {
		return nil
	}
	// A clause word inside a `[ ... ]` list is a value, never a clause.
	clauseAt := func(k int) bool {
		return !term.KeyBracketed(k) && policyTermClauseKeyword11779(keys[k])
	}
	actionAt := func(k int) bool {
		return !term.KeyBracketed(k) && resolveSchemaChild(thenSchema, keys[k]) != nil
	}
	var body []*Node
	var from, then *Node
	for i < len(keys) {
		end := i + 1
		if keys[i] == "from" {
			var parts []*Node
			if end < len(keys) {
				parts = splitPolicyTermFromRun11779(nil, keySpan12537(term, end, len(keys)), fromSchema, true)
			}
			for _, part := range parts {
				cut := policyTermClauseCut12537(part, fromSchema)
				if cut == 0 {
					break
				}
				if cut > 0 {
					part = keySpan12537(part, 0, cut)
				}
				if from == nil {
					from = &Node{Keys: []string{"from"}, InheritedFrom: term.InheritedFrom}
					body = append(body, from)
				}
				from.Children = append(from.Children, part)
				end += len(part.Keys)
				if cut > 0 {
					break
				}
			}
			i = end
			continue
		}
		if inline && end < len(keys) && !clauseAt(end) && !actionAt(end) {
			return nil
		}
		for end < len(keys) && !clauseAt(end) {
			action := end
			end++
			if head := resolveSchemaChild(thenSchema, keys[action]); head != nil {
				// Declared operand slots are values even when they spell a
				// keyword, as in expandFlatRun (#9124).
				end = min(end+head.args, len(keys))
			}
			for end < len(keys) && !clauseAt(end) && !actionAt(end) {
				end++
			}
			if then == nil {
				then = &Node{Keys: []string{"then"}}
				body = append(body, then)
			}
			then.Children = append(then.Children, keySpan12537(term, action, end))
		}
		i = end
	}
	return body
}

// policyTermClauseCut12537 reports where the term's next clause begins in one
// part of a split `from` run: 0 for a part that opens with `from` or `then`,
// the index of the first unbracketed clause word inside an opaque part (an
// unknown or quoted head keeps the rest of the run, while the direct reader
// resumes at that word, skipUnknownPolicyTermFromTail11779), and -1 for a
// match statement, whose span ends before any clause word.
func policyTermClauseCut12537(part *Node, fromSchema *schemaNode) int {
	if !part.KeyQuoted(0) && resolveSchemaChild(fromSchema, part.Keys[0]) != nil {
		return -1
	}
	for k, key := range part.Keys {
		if !part.KeyBracketed(k) && policyTermClauseKeyword11779(key) {
			return k
		}
	}
	return -1
}

// keySpan12537 returns a fresh leaf holding n.Keys[from:to] with their quote
// and bracket provenance, plus the list-closed bit for a bracketed span, as
// packedBodyChildren and expandFlatRun carry them onto synthesized nodes.
func keySpan12537(n *Node, from, to int) *Node {
	span := &Node{
		Keys:          append([]string(nil), n.Keys[from:to]...),
		IsLeaf:        true,
		InheritedFrom: n.InheritedFrom,
	}
	if len(n.KeysQuoted) == len(n.Keys) {
		span.setKeysQuoted(n.KeysQuoted[from:to])
	}
	if len(n.KeysBracketed) == len(n.Keys) {
		span.setKeysBracketed(n.KeysBracketed[from:to], n.BracketedClosed)
	}
	return span
}
