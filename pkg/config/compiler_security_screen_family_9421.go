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
	expanded := packedBody(node, schema)
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
			norm = screenFamilyBody(fam, resolveSchemaChild(idsSchema, fam.Keys[0]))
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

// screenFamilyBody expands one family node's packed tail into the CHAIN shape
// the flat-set parser produces for the identical statement.
//
// schema is the FAMILY's own schema node (`icmp`), used to learn how many
// leading Keys are the family's identity and how many tokens each tail
// statement consumes. A family the schema does not model (nil schema) is
// returned untouched — compileScreen's top-level switch already records it as
// an unknown family, so there is nothing to normalise for.
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

	var head, last *Node
	for len(tail) > 0 {
		// Default to one token per node — what SetPath does once the grammar
		// runs out. When the schema DOES model the token, consume its declared
		// args with it so a `threshold 500` value stays on its own leaf.
		n := 1
		var refined *schemaNode
		if cur != nil {
			if childSchema := resolveSchemaChild(cur, tail[0]); childSchema != nil {
				if c, r := consumeNodeKeys(tail, childSchema); c > 0 && c <= len(tail) {
					n, refined = c, r
				}
			}
		}
		next := &Node{Keys: append([]string(nil), tail[:n]...), IsLeaf: true}
		if last == nil {
			head = next
		} else {
			last.Children = []*Node{next}
			last.IsLeaf = false
		}
		last = next
		tail = tail[n:]
		cur = refined
	}

	// A node may carry a packed tail AND a braced body at once
	// (`icmp flood { threshold 500; }` elides to [icmp flood] + children).
	// The two halves spell ONE path, so the body belongs UNDER the deepest
	// packed node, never beside it — the #6821 / #8850 rule.
	if len(node.Children) > 0 {
		last.Children = append(last.Children, node.Children...)
		last.IsLeaf = false
	}

	clone := *node
	clone.Keys = append([]string(nil), node.Keys[:consumed]...)
	clone.Children = []*Node{head}
	clone.IsLeaf = false
	return &clone
}
