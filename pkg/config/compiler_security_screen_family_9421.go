package config

// Screen FAMILY-node packed-tail normalization — #9421.
//
// #6683 taught compileScreen to read the ids-option node's PACKED body:
//
//	ids-option s1 { icmp { ping-death; } }   nested   -> [ids-option s1]>[icmp]>[ping-death]
//	ids-option s1 icmp ping-death;           packed   -> [ids-option s1 icmp ping-death]
//
// It normalises the tail at ONE depth — `screenPackedBody(inst.node, idsSchema)` —
// and the depth one level in was never swept. A FAMILY node (`icmp`, `ip`,
// `tcp`, `udp`, `limit-session`) that carries its own body packed onto its
// Keys arrives with ZERO children:
//
//	ids-option s1 { icmp ping-death; }              -> [icmp ping-death]
//	ids-option s1 { icmp [ ping-death fragment ]; } -> [icmp ping-death fragment]
//	ids-option s1 { tcp bogus-check; }              -> [tcp bogus-check]
//
// compileScreen iterates `icmpNode.Children`, so the loop body never runs: no
// flag is set, nothing reaches `ScreenProfile.UnknownLeaves`, and the #3318
// gate (validateScreenUnknownStrict) — which is armed ONLY from UnknownLeaves —
// never fires. The check compiles DISABLED on a commit that reported success.
//
// # The part that makes this hard to notice: three observables, two shapes
//
// The FLAT spelling of the identical statement does not lose it, because
// SetPath builds a CHAIN instead of packing onto one node
// (`[icmp]>[ping-death]>[fragment]`). Measured on master for
// `icmp [ ping-death fragment ]`:
//
//	shape          strict CompileConfig   ICMP.PingDeath   UnknownLeaves
//	hierarchical   ACCEPT                 false            []
//	flat set       REJECT (#1960 msg)     true (lenient)   [icmp ping-death fragment]
//
// One statement, two spellings, and they disagree on the verdict, on the
// compiled boolean AND on whether the gate is armed. A gate that fires in one
// AST shape only is a reachability defect independent of the lost flag.
//
// # Why this expands PAST the modelled grammar where packedBodyChildren stops
//
// `packedBodyChildren` (compact_tail.go) refuses to guess: the first tail token
// that is not a schema child of the previous one abandons the whole expansion
// and returns the node's real children. That is right for its callers, which
// have no backstop — inventing a shape the schema does not model would drop
// configuration a different way.
//
// Here there IS a backstop, and it is the point of the fix. Every token this
// walk cannot resolve lands as a node the family's `default:` arm (or
// recordKeyExtras / recordChildExtras) records on `UnknownLeaves`, so the
// commit is REJECTED with the same message the flat path already produces
// rather than silently accepted. Continuing the chain is therefore not a guess
// about meaning; it is what makes the unmodelled token VISIBLE. The shape built
// is exactly the one SetPath builds for the same tokens, which is why the two
// AST shapes come out byte-identical afterwards.
//
// This is a site-local normalization in compileScreen, deliberately NOT an
// admission into the `compact_normalize_scope.go` table: that table's stated
// safety precondition is that a site first appear in the measured
// `testdata/compact_block_divergences_2419.txt` inventory, and #9056 is the
// open issue that the inventory census cannot enumerate a valueless boolean
// flag at all. #9056 owns that general class (83 sites across the tree, of
// which the screen families are a handful) and stays open; this fixes the
// screen family depth at the reader.

// screenPackedBody uses the shared schema-directed expansion when it can
// resolve the full packed tail. If that walk bails on an unmodelled token,
// expand the remainder as single-token nodes instead: compileScreen records
// those nodes as UnknownLeaves, allowing the strict screen gate to reject
// malformed configuration rather than silently dropping the entire body.
func screenPackedBody(node *Node, schema *schemaNode) *Node {
	// #16148: the modelled branch is the default BodyView (packedBodyChildren's
	// shared expansion). Only the declined branch — a tail the shared walk
	// will not guess at — falls through to screenFamilyBody, whose
	// unknown-token backstop keeps every token visible so compileScreen
	// records it on UnknownLeaves and the #3318 gate rejects it.
	expanded := bodyViewOf(node, schema).Node()
	if expanded != node || node == nil || schema == nil {
		return expanded
	}
	consumed, _ := consumeNodeKeys(node.Keys, schema)
	if consumed >= len(node.Keys) || node.KeyBracketed(consumed) {
		// Bracketed keys can be a list of ids-option instance names rather
		// than a compact screen body (for example, ids-option [s1 s2]).
		// Keep that schema-declined shape untouched; only unbracketed tails
		// are interpreted as packed statements here.
		return expanded
	}
	return screenFamilyBody(node, schema)
}

// screenBodyExpansion is the screen family's BodyView expansion (#16148):
// screenFamilyBody's sibling-preserving walk. screenFamilyBody returns a
// clone with Keys truncated to the family identity, so this adapter
// rebuilds that identity node from its children; callers that need the
// identity node itself keep using screenPackedBody.
func screenBodyExpansion(node *Node, schema *schemaNode) []*Node {
	return screenFamilyBody(node, schema).Children
}

// screenBodyView returns the BodyView for a screen node under schema: the
// screen expansion (shared walk via screenPackedBody's first branch is
// the caller's concern; here the family's own order is explicit).
func screenBodyView(node *Node, schema *schemaNode) bodyView {
	return bodyViewOf(node, schema).withExpansion(screenBodyExpansion)
}

// screenNormalizeFamilies returns body with every FAMILY child's packed tail
// expanded. The returned node is the ORIGINAL when nothing needed expanding
// (the overwhelmingly common nested spelling); otherwise it is a shallow copy,
// so the operator's AST is never mutated and `show configuration` still renders
// exactly what was typed.
func screenNormalizeFamilies(body *Node, idsSchema *schemaNode) *Node {
	if body == nil || idsSchema == nil || len(body.Children) == 0 {
		return body
	}
	var out []*Node
	changed := false
	for _, fam := range body.Children {
		norm := fam
		if fam != nil && len(fam.Keys) > 0 {
			norm = screenBodyNode(fam, resolveSchemaChild(idsSchema, fam.Keys[0]))
		}
		if norm != fam {
			changed = true
		}
		out = append(out, norm)
	}
	if !changed {
		return body
	}
	clone := *body
	clone.Children = out
	return &clone
}

// screenBodyNode returns the family node with its packed tail expanded:
// the authored node on the plain branch, otherwise a clone with Keys
// truncated to the family identity and the expanded children. It is
// screenFamilyBody reached through the screen BodyView (#16148); the
// identity truncation is why this returns a node rather than using
// view.Node() directly (the view only replaces Children).
func screenBodyNode(node *Node, schema *schemaNode) *Node {
	if node == nil || schema == nil || len(node.Keys) == 0 {
		return node
	}
	consumed, _ := consumeNodeKeys(node.Keys, schema)
	if consumed >= len(node.Keys) {
		return node
	}
	children := screenBodyView(node, schema).Children()
	clone := *node
	clone.Keys = append([]string(nil), node.Keys[:consumed]...)
	clone.Children = children
	clone.IsLeaf = false
	return &clone
}

// screenFamilyBody expands one family node's packed tail into the shape
// the nested spelling produces: sibling statements stay SIBLINGS.
//
// schema is the FAMILY's own schema node (`icmp`), used to learn how many
// leading Keys are the family's identity and how many tokens each tail
// statement consumes. A family the schema does not model (nil schema) is
// returned untouched — compileScreen's top-level switch already records it as
// an unknown family, so there is nothing to normalise for.
//
// #15944 H13-03: the walk keeps the open levels it has entered (the
// packedBodyChildren discipline), attaching each token to the deepest
// open level that declares it and popping back to that level. The
// previous single-cursor chain refined `cur` into each new node and
// never popped, so after a value-bearing leaf (`alarm-threshold 100`)
// the next sibling (`attack-threshold 500`) resolved against the
// leaf's (childless) schema, failed, and chained UNDER the leaf —
// compileScreen's named-child reads then lost every option after the
// first in a depth-1 packed run such as
// `tcp syn-flood alarm-threshold 100 attack-threshold 500;`, and the
// mis-nested token surfaced as a spurious strict rejection.
//
// A token no open level declares is kept visible in the chain shape
// the flat-set parser builds for the identical tokens, so
// compileScreen's recorders name it exactly as the flat path does and
// the strict gate rejects it rather than silently dropping it — the
// #9421 backstop this normalizer exists to provide.
//
// Synthesized nodes are FRESH allocations and the input node is never mutated.
func screenFamilyBody(node *Node, schema *schemaNode) *Node {
	if node == nil || schema == nil || len(node.Keys) == 0 {
		return node
	}
	consumed, cur := consumeNodeKeys(node.Keys, schema)
	if consumed >= len(node.Keys) {
		// Nothing packed onto this node's Keys: the nested spelling.
		return node
	}
	tail := node.Keys[consumed:]
	// #9421: a BRACKETED tail (`icmp [ ping-death fragment ]`) is a list
	// spelling the screen grammar does not model (`icmp` declares
	// children, not multi:). It must keep the flat-set CHAIN shape so
	// the unknown-leaf gate records `icmp ping-death fragment` and
	// strict compile rejects it; expanding it as siblings would accept
	// a shape the flat path refuses. The chain walk is inlined below
	// (#16148 deleted the separate screenFamilyBodyChain expander: it
	// was this same single-cursor chain, kept as a second function).
	bracketed := consumed < len(node.Keys) && node.KeyBracketed(consumed)
	if bracketed {
		var head, last *Node
		curB := cur
		tailB := tail
		for len(tailB) > 0 {
			n := 1
			var refined *schemaNode
			if curB != nil {
				if childSchema := resolveSchemaChild(curB, tailB[0]); childSchema != nil {
					if c, r := consumeNodeKeys(tailB, childSchema); c > 0 && c <= len(tailB) {
						n, refined = c, r
					}
				}
			}
			next := &Node{Keys: append([]string(nil), tailB[:n]...), IsLeaf: true}
			if last == nil {
				head = next
			} else {
				last.Children = []*Node{next}
				last.IsLeaf = false
			}
			last = next
			tailB = tailB[n:]
			curB = refined
		}
		if len(node.Children) > 0 && last != nil {
			last.Children = append(last.Children, node.Children...)
			last.IsLeaf = false
		}
		clone := *node
		clone.Keys = append([]string(nil), node.Keys[:consumed]...)
		clone.Children = []*Node{head}
		clone.IsLeaf = false
		return &clone
	}

	type openLevel struct {
		schema *schemaNode
		node   *Node // nil for the family's synthetic root level
	}
	levels := []openLevel{{schema: cur}}
	// path holds the synthesized ancestors of the current position, so
	// an unresolvable token can be re-emitted in the CHAIN shape the
	// flat-set parser builds for the identical tokens
	// (`[tcp]>[land]>[bogus-tail]`): compileScreen's recordKeyExtras /
	// recordChildExtras then name it exactly as the flat path does
	// (`tcp land bogus-tail`) instead of inventing a new spelling.
	var roots []*Node
	var last *Node
	var path []*Node
	chainUnder := func(keys []string) *Node {
		next := &Node{Keys: keys, IsLeaf: true}
		if len(path) == 0 {
			roots = append(roots, next)
		} else {
			parent := path[len(path)-1]
			parent.Children = append(parent.Children, next)
			parent.IsLeaf = false
		}
		path = append(path, next)
		last = next
		return next
	}
	for len(tail) > 0 {
		at := -1
		var childSchema *schemaNode
		for i := len(levels) - 1; i >= 0; i-- {
			if cs := resolveSchemaChild(levels[i].schema, tail[0]); cs != nil {
				at, childSchema = i, cs
				break
			}
		}
		if childSchema == nil {
			// No open level declares this token. Keep it visible in
			// the flat chain shape under the deepest synthesized
			// node (or at the family root when nothing is open), so
			// the unknown-leaf gate records the same path the flat
			// spelling produces. The level stack is rebuilt to mirror
			// the chain: each chain node is unresolvable (nil schema),
			// so a later token only resolves again at the family root.
			chainUnder(append([]string(nil), tail[0]))
			levels = []openLevel{{schema: cur}}
			for _, p := range path {
				levels = append(levels, openLevel{schema: nil, node: p})
			}
			tail = tail[1:]
			continue
		}
		n := 1
		var refined *schemaNode
		if c, r := consumeNodeKeys(tail, childSchema); c > 0 && c <= len(tail) {
			n, refined = c, r
		}
		next := &Node{Keys: append([]string(nil), tail[:n]...), IsLeaf: true}
		if levels[at].node == nil && at == 0 {
			roots = append(roots, next)
			path = []*Node{next}
		} else if levels[at].node != nil {
			levels[at].node.Children = append(levels[at].node.Children, next)
			levels[at].node.IsLeaf = false
			path = append(append([]*Node(nil), path[:at]...), next)
		} else {
			// `at` indexes a chain level built by the unknown-token
			// arm (node marker nil but not the root): attach under
			// the chain node at that depth.
			parent := path[at-1]
			parent.Children = append(parent.Children, next)
			parent.IsLeaf = false
			path = append(append([]*Node(nil), path[:at]...), next)
		}
		levels = append(levels[:at+1], openLevel{schema: refined, node: next})
		last = next
		tail = tail[n:]
	}

	// A node may carry a packed tail AND a braced body at once
	// (`icmp flood { threshold 500; }` elides to [icmp flood] + children).
	// The two halves spell ONE path, so the body belongs UNDER the deepest
	// packed node, never beside it — the #6821 / #8850 rule.
	if len(node.Children) > 0 && last != nil {
		last.Children = append(last.Children, node.Children...)
		last.IsLeaf = false
	}

	clone := *node
	clone.Keys = append([]string(nil), node.Keys[:consumed]...)
	clone.Children = roots
	clone.IsLeaf = false
	return &clone
}
