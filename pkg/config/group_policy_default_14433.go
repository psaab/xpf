package config

// #14433: statement-level `then` is a single-choice container
// (accept | reject). mergeNodes' container branch recurses into a
// same-keyed inline `then` and drops the group's arm as a scalar
// override, so a group accept beside an inline reject never reaches
// the compiler as a pair. Adopt a group arm beside an inline peer
// instead, mirroring the #12923 default-policy group-group handling:
// both arms then compile onto DefaultActionsSeen and the #14433 gate
// rejects the contradiction (tolerant loads fail closed to reject).
// An authored inline arm still suppresses nothing here — the pair is
// the evidence the gate needs; identical arms record once.

// isPolicyStatementThen14433 matches a statement-level `then` node:
// its parent (ancestorPath tail) is a policy-statement instance.
func isPolicyStatementThen14433(ancestorPath [][]string, n *Node) bool {
	if n == nil || len(n.Keys) == 0 || n.Keys[0] != "then" || len(ancestorPath) == 0 {
		return false
	}
	parentKeys := ancestorPath[len(ancestorPath)-1]
	if len(parentKeys) < 2 || parentKeys[0] != "policy-statement" {
		return false
	}
	parent := schemaAtAncestorPath(ancestorPath)
	if parent == nil {
		return false
	}
	stmt := resolveSchemaChild(schemaPolicyOptions, "policy-statement")
	if stmt == nil {
		return false
	}
	return resolveSchemaChild(parent, "then") == stmt.children["then"]
}

// policyStatementThenPeer14433 returns the same-keyed `then` peer in
// dst (leaf or container spelling) when src is statement-level.
func policyStatementThenPeer14433(ancestorPath [][]string, dst []*Node, src *Node) *Node {
	if !isPolicyStatementThen14433(ancestorPath, src) {
		return nil
	}
	for _, d := range dst {
		if d != nil && len(d.Keys) > 0 && d.Keys[0] == "then" {
			return d
		}
	}
	return nil
}

// thenDefaultArms14433 extracts accept/reject arms from a `then` node
// in braced-child, packed-key, or flat-leaf spelling.
func thenDefaultArms14433(n *Node) []string {
	var arms []string
	add := func(a string) {
		if a != "accept" && a != "reject" {
			return
		}
		for _, x := range arms {
			if x == a {
				return
			}
		}
		arms = append(arms, a)
	}
	if n == nil {
		return nil
	}
	if len(n.Keys) >= 2 {
		add(n.Keys[1])
	}
	for _, c := range n.Children {
		if c != nil {
			add(c.Name())
			if len(c.Keys) >= 1 {
				// Flat-run child may carry the arm as its only key.
				if len(c.Keys) == 1 {
					add(c.Keys[0])
				}
			}
		}
	}
	return arms
}

// adoptPolicyStatementThenArm14433 appends src's arms beside the peer's
// arms so the compiler records both. The peer becomes a container whose
// children are leaf arms (`accept;` / `reject;`), the shape the braced
// compiler loop reads; a packed peer key is folded in as a child first.
// Returns false when src carries no default arm.
func adoptPolicyStatementThenArm14433(peer, src *Node) bool {
	srcArms := thenDefaultArms14433(src)
	if len(srcArms) == 0 {
		return false
	}
	peerArms := thenDefaultArms14433(peer)
	// Normalize peer to container-with-leaf-arms.
	peer.IsLeaf = false
	peer.Keys = []string{"then"}
	peer.Children = nil
	for _, a := range append(peerArms, srcArms...) {
		exists := false
		for _, existing := range peer.Children {
			if existing != nil && existing.Name() == a {
				exists = true
				break
			}
		}
		if !exists {
			peer.Children = append(peer.Children, &Node{Keys: []string{a}, IsLeaf: true})
		}
	}
	return true
}
