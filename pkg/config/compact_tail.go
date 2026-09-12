package config

// Compact ("packed") stanza bodies — #6683 / #6684 / #6685.
//
// Junos accepts a stanza body written either NESTED or PACKED onto one line,
// and the two are the same configuration:
//
//	security { screen { ids-option s1 { icmp { ping-death; } } } }   nested
//	security { screen { ids-option s1 icmp ping-death; } }           packed
//
// The parser does not normalise them. A packed body arrives as extra tokens on
// the node's OWN Keys, with no Children at all:
//
//	nested   [ids-option s1] -> [icmp] -> [ping-death]
//	packed   [ids-option s1 icmp ping-death]
//
// A compiler that descends only `node.Children` therefore sees an instance with
// an EMPTY body. The instance NAME survives, which is what makes this class so
// hard to notice: the profile/host/term exists, `show configuration` displays
// what the operator wrote, it binds to a zone or an interface normally — and it
// enforces nothing.
//
// The three known instances all fail in the security-relevant direction: a
// screen check compiles DISABLED (#6683), a syslog host compiles with ZERO
// facilities so nothing is shipped (#6684), and a firewall filter term compiles
// with an EMPTY action so a `discard` does not discard (#6685).
//
// # Why this needs the schema rather than a split on whitespace
//
// The packed tail does NOT expand uniformly, which is why there was no shared
// helper before and why fixing one site by hand does not generalise:
//
//	ids-option s1 icmp ping-death   ->  [icmp] -> [ping-death]     a CHAIN
//	host 10.0.0.1 any any           ->  [any any]                  ONE 2-key leaf
//	term t1 then discard            ->  [then] -> [discard]        a CHAIN
//
// How many tokens each level swallows is a property of the GRAMMAR, and the
// grammar already has a single source of truth: `setSchema`, whose
// `schemaNode.args` is defined as "extra tokens consumed as part of this node's
// key". `consumeNodeKeys` is the same primitive `SchemaValidate` uses to answer
// exactly this question, so expansion here cannot drift from validation there.
//
// The expansion is deliberately NOT done in the parser. `show configuration`
// renders from the AST, so normalising at parse time would rewrite the
// operator's packed one-liner into nested form on display — a round-trip
// fidelity change well beyond the scope of these three fail-opens.

// schemaForPath resolves the schema node addressed by an absolute keyword path
// (e.g. []string{"security", "screen", "ids-option"}), or nil when the path is
// not modelled. Instance-name slots resolve through the wildcard child, so the
// path names KEYWORDS only — no instance names.
func schemaForPath(path ...string) *schemaNode {
	cur := setSchema
	for i := 0; i < len(path); i++ {
		if cur == nil {
			return nil
		}
		cur = resolveSchemaChild(cur, path[i])
		if cur == nil {
			return nil
		}
		// Compound key (`family inet`): the following token is part of THIS
		// node's key and selects a sub-child, so the caller spells it as a
		// path element and it is consumed here rather than resolved as a
		// child of the compound node — which is where it does not exist.
		if cur.compoundKey && i+1 < len(path) {
			if sub, ok := cur.children[path[i+1]]; ok {
				cur = sub
				i++
			}
		}
	}
	return cur
}

// packedBodyChildren returns the body a compiler should descend for node.
//
// When the body was written nested it is `node.Children`, returned unchanged —
// this is the overwhelmingly common path and costs one length check.
//
// When the body was PACKED onto the node's Keys it is a synthesized chain that
// is shape-identical to what the parser would have produced for the nested
// spelling, so the caller's existing nested-shape reader handles it with no
// second code path to keep in step.
//
// schema is the node's OWN schema (the one addressing e.g. `ids-option`), used
// to learn how many leading Keys are the node's identity and how the remaining
// tokens divide. A nil schema, or a tail that leaves the modelled grammar,
// returns the children unchanged rather than guessing: this helper exists to
// stop configuration being silently dropped, and inventing a shape the schema
// does not describe would be a different way of doing the same thing.
//
// Synthesized nodes are FRESH allocations; the input node is never mutated, so
// a caller that also renders or re-walks the original AST sees exactly what the
// operator wrote.
func packedBodyChildren(node *Node, schema *schemaNode) []*Node {
	if node == nil || schema == nil {
		return nodeChildren(node)
	}
	consumed, cur := consumeNodeKeys(node.Keys, schema)
	tail := node.Keys[consumed:]
	if len(tail) == 0 {
		return node.Children
	}

	// #9620 H9: the open schema levels, not a single `cur`.
	//
	// This used to refine `cur` one level deeper per statement and build a
	// strictly NESTED chain, which is right only while every statement is a
	// child of the one before it. `term t1 then count C1 discard;` is not that
	// shape: `count` is a child of `then`, and so is `discard` — a SIBLING.
	// After consuming `count C1` the old loop had refined `cur` to `count`,
	// `resolveSchemaChild(count, "discard")` came back nil, and the whole body
	// was discarded under "do not guess".
	//
	// The term then compiled with an EMPTY Action — and that is not a formatting
	// matter. Measured through the real filter engine: a modifier-only term is a
	// fall-through (`NextTerm`), nothing later terminates, and
	// `FilterResult::default()` returns `FilterAction::Accept`. So a term written
	// `then count C1 discard;` ACCEPTED the packet it was written to discard,
	// on a commit strict reports clean, with `show` printing `then accept`. A
	// DENY that PERMITS.
	//
	// So the walk keeps the levels it has opened and attaches each statement to
	// the DEEPEST open level that declares it, popping the levels below. A
	// single-parent chain (`filter input f1`) is unchanged, because there the
	// deepest declaring level is always the one just pushed.
	type openLevel struct {
		schema *schemaNode
		node   *Node // nil for the synthetic root the first statement attaches to
	}
	levels := []openLevel{{schema: cur}}
	// The run's ROOT-level statements, in order. A list rather than a single
	// head: once the walk can pop back to the container, a run produces SIBLINGS
	// there -- `term t1 from protocol tcp then discard;` is a `from` and a `then`
	// side by side, not one nested in the other. Chaining them under the first
	// statement put `then` inside `from`, and the commit gate then refused the
	// config as "`from then` is not enforced by the dataplane" -- caught by
	// dumping this function's own output rather than by the verdict, which was
	// merely "refused" and looked like a deliberate gate.
	var roots []*Node
	var last *Node
	for len(tail) > 0 {
		// Deepest first: a token a nested level declares belongs to that level,
		// which is what makes the ordinary chain keep its shape.
		//
		// TWO JUSTIFIED SURVIVORS, with the fact that would kill them. Neither
		// the deepest-FIRST order here nor the `levels[:at+1]` truncation below
		// is falsifiable by the current corpus: mutating either to its wrong
		// form leaves the whole pkg/config suite green (measured, not assumed).
		// That is a statement about COVERAGE, not about the clauses -- both
		// decide which level owns a token, and they can only differ where ONE
		// packed run has two OPEN levels that declare the SAME child name.
		//
		// 72 (ancestor, descendant) pairs in the schema share a child name --
		// `authentication-key` under both `protocols bgp group` and `... group
		// neighbor`, `class` under both `system login` and `system login user`,
		// `address` under both `security address-book global` and its
		// `address-set`. None is reached by a packed run any fixture writes: the
		// bgp one was tried and does not discriminate, because packedBody is
		// called on the NEIGHBOR node so `group` is never an open level.
		//
		// THE EXPIRY CONDITION: the first packed run that opens two levels
		// declaring one name is where these two get their cell. Until then they
		// are the conservative choice (the deeper level is the more specific
		// owner, and a truncated stack cannot attach under a statement the run
		// has already left) and they are NOT claimed as proven.
		at := -1
		var childSchema *schemaNode
		for i := len(levels) - 1; i >= 0; i-- {
			if cs := resolveSchemaChild(levels[i].schema, tail[0]); cs != nil {
				at, childSchema = i, cs
				break
			}
		}
		if childSchema == nil {
			// Outside the modelled grammar at every open level. Do not guess.
			return node.Children
		}
		n, refined := consumeNodeKeys(tail, childSchema)
		if n <= 0 {
			return node.Children
		}
		next := &Node{Keys: append([]string(nil), tail[:n]...)}
		if levels[at].node == nil {
			// The run's first statement, or one that popped all the way back to
			// the container: a SIBLING at the body's top level.
			roots = append(roots, next)
		} else {
			levels[at].node.Children = append(levels[at].node.Children, next)
		}
		levels = append(levels[:at+1], openLevel{schema: refined, node: next})
		last = next
		tail = tail[n:]
	}

	if len(node.Children) == 0 {
		return roots
	}
	// The parser DOES produce both, contrary to what this comment used to
	// claim. `authentication md5 7 { key "secret"; }` parses as
	// Keys=["authentication","md5","7"] with Children=[Keys=["key","secret"]] --
	// a packed tail AND a nested block on one node.
	//
	// Returning them as SIBLINGS is wrong, and wrong in the silent direction.
	// The two halves spell ONE path: `authentication { md5 7 { key "secret" } }`.
	// Side by side, the caller sees an md5 node with no key and a stray `key`
	// node at the wrong level -- OSPF compiled AuthType=md5 with an EMPTY key,
	// and `transport protocol tcp { protocol tls; }` let the synthesized `tcp`
	// overwrite the real `tls` child, silently downgrading an audit stream from
	// TLS to plaintext.
	//
	// The nested block belongs UNDER the deepest packed node -- but only if the
	// grammar says that node can HOLD one.
	//
	// `cur` is the schema the last consumeNodeKeys refined to, i.e. the terminal
	// node's own schema. If it declares neither children nor a wildcard, it is a
	// leaf, and `stanza leaf value { body }` is not a shape the grammar
	// describes. Attaching there would invent a nesting the schema does not
	// have; returning the real children unexpanded is the same "outside the
	// modelled grammar, do not guess" answer this function already gives when
	// resolveSchemaChild comes back nil.
	//
	// Verified rather than assumed: the three-level
	// `from flexible-match-range range r { byte-offset 9; }` chain DOES permit a
	// body at its terminal, and compiles identically to the fully nested
	// spelling. Chain length was never the question; whether the terminal takes
	// a body is.
	// #9620 H9: the deepest OPEN level's schema, which is what `cur` used to
	// hold when the chain could only nest.
	cur = levels[len(levels)-1].schema
	if cur == nil || (len(cur.children) == 0 && cur.wildcard == nil) {
		return node.Children
	}
	last.Children = append(last.Children, node.Children...)
	return roots
}

// nodeChildren is node.Children with a nil-node guard.
func nodeChildren(node *Node) []*Node {
	if node == nil {
		return nil
	}
	return node.Children
}

// packedBody returns node with its packed tail expanded into Children, so a
// caller can keep using the ordinary *Node helpers (FindChild / FindChildren /
// range over Children) with no second code path for the packed spelling.
//
// The returned node is the ORIGINAL when there is nothing to expand — the
// common case, and the one where identity matters to callers that compare
// nodes. Otherwise it is a shallow copy carrying the synthesized body; the
// original is never mutated.
func packedBody(node *Node, schema *schemaNode) *Node {
	if node == nil {
		return nil
	}
	children := packedBodyChildren(node, schema)
	if len(children) == len(node.Children) {
		// Same backing slice means nothing was synthesized.
		if len(children) == 0 || &children[0] == &node.Children[0] {
			return node
		}
	}
	clone := *node
	clone.Children = children
	return &clone
}
