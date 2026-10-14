package config

// hoistAndSplitRun8939 flattens a packed flat-set run under container: it lifts
// a statement nested INSIDE another statement back to sibling position, and
// splits a node whose Keys carry several statements.
//
// #8939 needs BOTH operations, and which one a site needs depends on the shape
// SetPath happened to build:
//
//	set … test T target address 10.0.0.1 probe-type icmp-ping
//	  [test T] > [target] > [address 10.0.0.1] > [probe-type icmp-ping]
//	                                              ^ NESTED, not a sibling
//
//	set … then count c1 log discard
//	  [then] > [count c1] > [log discard]
//	                         ^ nested AND packed: two statements on one node
//
// expandFlatRun alone splits the second case and cannot see the first, because
// the trailing statement is not on the container's own children at all — it is
// several levels down, hanging off whichever leaf the run started at.
// flattenThenChain8939 solved this once for the filter `then` clause; this is
// the same operation with the container passed in, so the next site does not
// need a third copy.
//
// THE BOUND IS THE SAME ONE flattenThenChain8939 STATES. A node is only hoisted
// when its own head RESOLVES as a leaf of the container — that is what
// distinguishes "a second statement got nested here" from "these are this
// leaf's VALUES", and reading it wrong turns a value list into a statement
// (#2419). A leaf that owns a body, a wildcard, or a multi leaf is left exactly
// as authored.
func hoistAndSplitRun8939(children []*Node, container *schemaNode) []*Node {
	if container == nil || len(children) == 0 {
		return children
	}
	var out []*Node
	changed := false

	var visit func(n *Node)
	visit = func(n *Node) {
		if n == nil || len(n.Keys) == 0 {
			out = append(out, n)
			return
		}
		leaf := resolveSchemaChild(container, n.Keys[0])
		if leaf == nil || leaf.multi {
			// Not a leaf of THIS container, or a multi leaf that owns
			// everything after it (#2419): leave it exactly as authored.
			out = append(out, n)
			return
		}
		if len(leaf.children) > 0 || leaf.wildcard != nil {
			// A leaf that legitimately owns a BODY -- `target { address X; }`.
			// Its own children are its business, but a run can still be nested
			// UNDER it, several levels down:
			//
			//	[test T] > [target] > [address 10.0.0.1] > [probe-type icmp-ping]
			//	                                            ^ a leaf of TEST,
			//	                                              not of TARGET
			//
			// So descend and lift out only descendants whose head resolves as a
			// leaf of the ORIGINAL container. That predicate is what keeps this
			// safe: `address` resolves under TARGET and stays put, while
			// `probe-type` resolves under TEST and is hoisted to where the
			// compiler looks for it.
			kept, lifted := splitNestedForeignRun8939(n, container)
			out = append(out, kept)
			if len(lifted) > 0 {
				changed = true
				for _, l := range lifted {
					visit(l)
				}
			}
			return
		}
		if len(n.Children) == 0 {
			out = append(out, n)
			return
		}
		// A leaf of this container carrying children: the children are a run
		// that got nested under it. Keep the head, hoist the rest.
		changed = true
		head := &Node{
			Keys:       append([]string(nil), n.Keys...),
			IsLeaf:     true,
			Annotation: n.Annotation,
			Inactive:   n.Inactive,
			Line:       n.Line,
			Column:     n.Column,
		}
		if n.KeysQuoted != nil {
			head.KeysQuoted = append([]bool(nil), n.KeysQuoted...)
		}
		out = append(out, head)
		for _, c := range n.Children {
			visit(c)
		}
	}
	for _, c := range children {
		visit(c)
	}
	if !changed {
		// Still split: one node can carry a packed run with nothing nested.
		return expandFlatRun(children, container)
	}
	return expandFlatRun(out, container)
}

// splitNestedForeignRun8939 removes, from n's subtree, every node whose head
// resolves as a leaf of `container` rather than of n's own body, and returns
// the pruned node plus the lifted ones.
//
// #8939: this is the half hoistAndSplitRun8939's bound cannot do on its own. A
// leaf that owns a body is left alone by that bound -- correctly, its children
// are its own -- but SetPath will still nest a LATER statement underneath it,
// and that statement belongs to the enclosing container.
//
// AMBIGUITY IS NOT HOISTABLE, and this is the precondition the caller cannot
// check for itself. "resolves under the enclosing container" only identifies a
// FOREIGN statement when the name is not ALSO legal where it currently sits.
// `forwarding-options sampling instance I family inet output` declares
// source-address, and so does its own `flow-server` child:
//
//	output { flow-server 10.0.0.9 { source-address 10.1.1.1; } }
//	                                ^ resolves under BOTH
//
// That source-address is the per-collector export source, authored exactly
// where it means what it says. Lifting it makes it the instance-wide source and
// silently rewrites which address every OTHER collector sees the device as --
// and a collector keys device identity on it. So when a head resolves in both
// places the authored nesting wins and nothing is lifted. Only an
// UNAMBIGUOUSLY foreign head -- legal in the container, illegal here -- can be
// a statement that SetPath misplaced.
//
// #12942: "HERE" IS THE WHOLE BODY WHEN THE BODY DECLARES ITS OWN RUN
// SPELLING. A head may be illegal under the leaf it is nested in yet still be
// a leaf of the body-owning node this walk started from:
//
//	schedulers { scheduler S { tuesday { start-time 09:00:00 {
//		stop-time 17:00:00; } } } }
//	                                  ^ illegal under start-time, LEGAL
//	                                    under tuesday -- and also legal
//	                                    under scheduler
//
// stop-time is a declared leaf of the day schema, and the nested shape is the
// braced twin of the #8939 flat run `tuesday start-time 09:00:00
// stop-time 17:00:00`, which SetPath nests identically. The old bound read it
// as unambiguously foreign because it compared against the immediate parent
// only, hoisted it to the scheduler level, and the compiler read the phantom
// as the scheduler's own stop-time: the scalar window filled with StopTime and
// no StartTime (every non-Tuesday tick warned and failed closed in the
// scheduler), a daily window beside it was corrupted to the weekday's stop on
// the tolerant path, and the legitimate daily+weekday pair strict-rejected as
// an #11358 daily repeat nobody authored.
//
// THE GATE IS packedFlatRun, AND THE TUNNEL IS WHY IT MUST BE. `tunnel
// routing-instance destination VR1 destination 10.0.0.2` nests the tunnel's
// destination IP under the routing-instance's `destination <name>` leaf, and
// `destination` resolves under BOTH bodies -- yet there the nested statement
// is a tunnel leaf SetPath misplaced, and hoisting it is the whole #9156 fix.
// The difference is DECLARED, not structural: schemaSchedulerDay sets
// packedFlatRun, so the schema walk and the day reader expand a nested run as
// the day's own body spelling (schema_walk.go), while the routing-instance
// body declares no run spelling and its reader reads authored children only.
// So the body-root ambiguity rule fires only for a body that opted in, and
// there it keeps the authored nesting exactly as the both-places rule above
// keeps it for the immediate parent.
func splitNestedForeignRun8939(n *Node, container *schemaNode) (*Node, []*Node) {
	if n == nil {
		return n, nil
	}
	var lifted []*Node
	// local is the schema position of `node` itself, or nil once the walk
	// leaves the declared schema. A nil local cannot vouch for a name, so it
	// disables lifting rather than permitting it -- an undeclared body is
	// exactly where an unrecognised name is most likely to be someone's value.
	//
	// root is the schema of the body this walk must not empty (n's own
	// position). When the body declares its own flat-run spelling
	// (packedFlatRun), a head resolving under root is the body's statement,
	// and the both-places ambiguity rule applies against it too (#12942).
	root := localSchemaFor8939(n, container)
	var prune func(node *Node, local *schemaNode, depth int) *Node
	prune = func(node *Node, local *schemaNode, depth int) *Node {
		if node == nil || depth > 8 {
			return node
		}
		var kept []*Node
		for _, c := range node.Children {
			if c == nil || len(c.Keys) == 0 {
				continue
			}
			sub := localSchemaChild8939(local, c.Keys[0])
			ownsBodyRun12942 := root != nil && root.packedFlatRun &&
				localSchemaChild8939(root, c.Keys[0]) != nil
			if local != nil && sub == nil && !ownsBodyRun12942 &&
				resolveSchemaChild(container, c.Keys[0]) != nil {
				// Legal in the ENCLOSING container, illegal under its parent,
				// and not the declared run spelling of the body it sits in:
				// the only reading is a statement SetPath nested by accident.
				lifted = append(lifted, c)
				continue
			}
			kept = append(kept, prune(c, sub, depth+1))
		}
		if len(kept) == len(node.Children) {
			return node
		}
		clone := *node
		clone.Children = kept
		return &clone
	}
	pruned := prune(n, root, 0)
	return pruned, lifted
}

// localSchemaFor8939 resolves n's own schema position under container, so the
// prune walk can ask whether a nested head is legal WHERE IT SITS.
func localSchemaFor8939(n *Node, container *schemaNode) *schemaNode {
	if n == nil || len(n.Keys) == 0 {
		return nil
	}
	return resolveSchemaChild(container, n.Keys[0])
}

// localSchemaChild8939 descends one level, tolerating a wildcard slot (an
// instance name such as the flow-server's address) which declares the body the
// next key must be read against.
func localSchemaChild8939(local *schemaNode, key string) *schemaNode {
	if local == nil {
		return nil
	}
	if c := resolveSchemaChild(local, key); c != nil {
		return c
	}
	if local.wildcard != nil {
		return resolveSchemaChild(local.wildcard, key)
	}
	return nil
}
