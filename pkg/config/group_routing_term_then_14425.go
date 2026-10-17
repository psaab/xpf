package config

// #14425: a group-supplied routing policy-term `then accept` merged into
// an inline term carrying `then reject` (or vice versa) resolved by the
// generic inline-wins override: the group leaf was silently dropped and
// only one action survived to the compiler, so no conflict gate could
// see it. mergeNodes therefore adopts a group routing-term terminal
// beside its peer (instead of dropping it); the compiler accumulates
// both actions on TerminalActions and
// validateRoutingTermTerminalConflictStrict rejects distinct actions
// (identical repeats stay legal).

// isRoutingTermThenAction14425 reports whether n, at ancestorPath
// (the path of its parent), is a routing policy-term terminal-action
// node: a `then accept` / `then reject` leaf, a `then { accept; }`
// single-key container, an `accept`/`reject` statement inside a `then`
// container, or a packed `term T ... then accept ...` leaf.
func isRoutingTermThenAction14425(ancestorPath [][]string, n *Node) bool {
	if n == nil || len(n.Keys) == 0 || len(ancestorPath) == 0 {
		return false
	}
	parent := schemaAtAncestorPath(ancestorPath)
	if parent == nil {
		return false
	}
	termThen := routingTermThenSchema14425()
	if termThen == nil {
		return false
	}
	key := n.Keys[0]
	switch {
	case key == "then" && parent == routingTermSchema14425():
		// `then accept;` leaf or `then { accept; }` container directly
		// under a term: qualifies iff it carries a terminal action.
		return routingThenNodeAction14425(n) != ""
	case (key == "accept" || key == "reject") && parent == termThen:
		return true
	case key == "term" && parent == routingPolicyStatementSchema14425():
		// Packed term leaf: qualifies iff its tail carries a terminal.
		return routingPackedTermThenAction14425(n) != ""
	}
	return false
}

func routingPolicyStatementSchema14425() *schemaNode {
	return resolveSchemaChild(schemaPolicyOptions, "policy-statement")
}

func routingTermSchema14425() *schemaNode {
	if ps := routingPolicyStatementSchema14425(); ps != nil {
		return resolveSchemaChild(ps, "term")
	}
	return nil
}

func routingTermThenSchema14425() *schemaNode {
	if term := routingTermSchema14425(); term != nil {
		return resolveSchemaChild(term, "then")
	}
	return nil
}

// routingThenNodeAction14425 returns the terminal action carried by a
// `then` node in leaf (`then accept`) or container (`then { accept; }`)
// spelling, or "" if it carries none.
func routingThenNodeAction14425(n *Node) string {
	if n == nil || len(n.Keys) == 0 || n.Keys[0] != "then" {
		return ""
	}
	if len(n.Keys) >= 2 {
		if n.Keys[1] == "accept" || n.Keys[1] == "reject" {
			return n.Keys[1]
		}
		return ""
	}
	for _, c := range n.Children {
		if c != nil && len(c.Keys) > 0 && (c.Keys[0] == "accept" || c.Keys[0] == "reject") {
			return c.Keys[0]
		}
	}
	return ""
}

// routingPackedTermThenAction14425 returns the terminal action in a
// packed `term T then accept ...` leaf tail, or "". Only a term whose
// tail OPENS with `then` qualifies: a from-first packed term
// (`term T from route-filter ... then accept`) is a match-carrying
// leaf whose merge is owned by #12537/#12529, not a bare terminal.
func routingPackedTermThenAction14425(n *Node) string {
	if n == nil || len(n.Keys) < 4 || n.Keys[2] != "then" {
		return ""
	}
	if a := n.Keys[3]; a == "accept" || a == "reject" {
		return a
	}
	return ""
}
