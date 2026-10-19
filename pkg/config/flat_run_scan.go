package config

// expandFlatRun returns a container's child statements with a flat-set chain
// expanded into one node per leaf, or the original slice when nothing moves.
//
// THE SHAPE, and it is not what it looks like at two leaves. A flat `set`
// command naming several leaves of one container is ONE command, and SetPath
// models only the FIRST link:
//
//	set security ike gateway gw1 address A external-interface E local-address L
//
//	[gateway gw1]
//	  [address A]
//	    [external-interface E local-address L]     <- ONE node, a FLAT RUN
//
// At TWO leaves the remainder is a single keyword/value pair, so the chain is
// indistinguishable from ordinary nesting and a recursive descent appears to
// work. At THREE it packs onto one node's Keys, and a descent reads
// `external-interface` and silently drops `local-address`. So the expansion
// must be a KEYWORD-DELIMITED SCAN of each node's Keys, not a walk of Children
// — the same scan parseApplicationTerms performs, and the reason #6524's fix
// took that form.
//
// A leaf that is not a node's own first token is re-emitted as a synthesized
// `keyword value` node, so every caller sees the uniform shape it already
// iterates.
//
// GATED ON THE SCHEMA, IN BOTH DIRECTIONS. A token is only treated as a new
// leaf when the container declares it; anything else stays with the leaf it
// follows, so a multi-token value is not chopped into keywords that happen to
// collide. A leaf that DECLARES CHILDREN keeps its subtree — its body belongs
// to it, and hoisting that would turn a nested block into sibling statements of
// the container.
//
// AND A NESTED NODE IS HOISTED ONLY IF IT NAMES A SIBLING. The first version
// hoisted every child of a terminating leaf, on the reasoning that a leaf
// declaring no children can have no body — so anything under it must be the
// next link of the chain. THAT IS FALSE FOR A `multi` LEAF, and #2419 already
// said so: in the BLOCK spelling `permissions { view; configure; }` the
// children are VALUES, not statements, and hoisting them turned a read leaf
// into an unread one. The shipped spelling-differential gate caught it —
// `system login class <*> permissions` went `inert` in one spelling and
// `drop` in another — where the loser fixture could not, because an
// already-walking container leaving the loser list looks like nothing
// happened. Hoisting only a child that RESOLVES as another leaf of the
// container keeps every chain link (they all begin with a keyword) and leaves
// every value list attached to the leaf that owns it.
//
// A `multi` leaf's own Keys are never cut either: by the #2419 absorb rule a
// sibling token is never absorbed onto them in the first place, so a cut there
// could only ever chop a VALUE that happens to share a sibling's spelling.
//
// THE TWO GUARDS ARE NOT REDUNDANT, THOUGH THE MEASURED DEFECT NEEDED ONLY
// ONE. Mutation matrix against TestSchemaSpellingDifferentialGate, which is
// what caught the regression:
//
//	multi guard  sibling-gated hoist   verdict
//	present      REMOVED               ok
//	REMOVED      present               ok
//	REMOVED      REMOVED               FAIL, A=keep B=inert … F=drop
//
// Either alone clears `permissions`, because that leaf is both multi AND
// block-spelled. They guard DIFFERENT operations and diverge elsewhere: the
// hoist gate also covers a NON-multi `blockValue` leaf, whose children are
// likewise values (#6774's `default-policy { deny-all; }`), and the multi
// guard also covers CUTTING a value list at a token that happens to spell a
// sibling — a case with no instance in today's schema, so it encodes #2419's
// contract rather than a reproduced defect. Recorded rather than trimmed to
// the minimum, because "either one suffices" is a property of the ONE example
// that exists, not of the rule.
//
// WHY EXPAND RATHER THAN REJECT. The chain is a SUPPORTED spelling —
// `set applications application a1 protocol tcp destination-port 80` is tested
// behaviour — and #6524 recorded why teaching the schema to refuse it is wrong:
// a schema-only reject leaves the LENIENT path (boot load, HA SyncApply)
// untouched, which is exactly where already-stored configs are.
func expandFlatRun(children []*Node, container *schemaNode) []*Node {
	if container == nil || len(children) == 0 {
		return children
	}
	var out []*Node
	changed := false

	var visit func(n *Node)
	visit = func(n *Node) {
		if n == nil || len(n.Keys) == 0 {
			return
		}
		leaf := resolveSchemaChild(container, n.Keys[0])
		// Not a leaf of this container, or one that owns a body: leave it and
		// its subtree exactly as authored.
		// #15270 exception: `host` declares only the `port` modifier child —
		// a value-plus-modifier leaf, not a body-owning container. It must
		// still split (`host <addr> transport ...` chains) like other leaves.
		hostPortOnly15270 := n.Keys[0] == "host" && leaf != nil && len(leaf.children) == 1 && leaf.children["port"] != nil
		if leaf == nil || ((len(leaf.children) > 0 || leaf.wildcard != nil) && !hostPortOnly15270) {
			out = append(out, n)
			return
		}
		// A multi-value leaf owns everything under and after it (#2419).
		if leaf.multi {
			out = append(out, n)
			return
		}
		// Split this node's Keys at every token the container declares as
		// another leaf. The first keyword keeps the node; each later one
		// becomes a synthesized sibling.
		// #9124: A LEAF'S DECLARED VALUE SLOTS ARE NOT CUT CANDIDATES.
		//
		// The scan used to test every index from 1, so index 1 of an `args: 1`
		// leaf -- its VALUE -- was a cut point whenever the value happened to
		// spell another leaf of the same container:
		//
		//	security ike gateway gw1 { ike-policy address; address 198.51.100.1; }
		//
		// with a policy legitimately NAMED `address` cut `ike-policy address`
		// into `ike-policy` + `address`, so the gateway compiled with
		// IKEPolicy="" and committed CLEAN at CheckText with zero warnings.
		// The trigger is a naming coincidence rather than an ordinary spelling,
		// which is why it survived: the operator's own object name has to equal
		// a sibling keyword.
		//
		// Skipping `args` tokens after each cut point is the whole fix, and it
		// is the same information the schema already carries for the SetPath
		// walk -- the scan simply never asked for it.
		cut := []int{0}
		i := 1 + effectiveArgs15752(leaf, n.Keys, container)
		for ; i < len(n.Keys); i++ {
			sib := resolveSchemaChild(container, n.Keys[i])
			if sib == nil {
				continue
			}
			cut = append(cut, i)
			// The sibling's own value slots belong to it, not to the next cut.
			i += effectiveArgs15752(sib, n.Keys[i:], container)
		}
		if len(cut) > 1 {
			changed = true
		}
		for c, start := range cut {
			end := len(n.Keys)
			if c+1 < len(cut) {
				end = cut[c+1]
			}
			seg := &Node{
				Keys:       append([]string(nil), n.Keys[start:end]...),
				IsLeaf:     true,
				Annotation: n.Annotation,
				Inactive:   n.Inactive,
				Line:       n.Line,
				Column:     n.Column,
			}
			if n.KeysQuoted != nil && end <= len(n.KeysQuoted) {
				seg.KeysQuoted = append([]bool(nil), n.KeysQuoted[start:end]...)
			}
			// #12517: bracket provenance is a per-key mask too (#8921), so it
			// moves with its keys. Without it a `[ ... ]` list cut out of a
			// chained run (`accept community add [ a b ]`) reads exactly like
			// unbracketed values, and the list's extent is lost.
			if len(n.KeysBracketed) == len(n.Keys) {
				seg.setKeysBracketed(n.KeysBracketed[start:end], n.BracketedClosed)
			}
			out = append(out, seg)
		}
		// A nested node is the next link of the chain only if it NAMES another
		// leaf of this container. Anything else is a value the authored
		// spelling put there, and it stays with the segment it was written
		// under.
		var keep []*Node
		var hoist []*Node
		for _, c := range n.Children {
			if len(c.Keys) > 0 && resolveSchemaChild(container, c.Keys[0]) != nil {
				hoist = append(hoist, c)
				continue
			}
			keep = append(keep, c)
		}
		if len(keep) > 0 && len(out) > 0 {
			last := out[len(out)-1]
			if last != n {
				last.Children = append(append([]*Node(nil), last.Children...), keep...)
				last.IsLeaf = false
			}
		}
		for _, c := range hoist {
			changed = true
			visit(c)
		}
	}
	for _, c := range children {
		visit(c)
	}
	if !changed {
		return children
	}
	return out
}
