package config

// reachableGroupNamesAST returns the names of the `groups` blocks whose `stanza`
// subtree group expansion can merge into the candidate (#9657), without
// expanding anything. The pre-expansion collision views use it so they do not
// count a name declared in a group that never lands under `stanza`.
//
// Group expansion applies a group at the context where its apply-groups
// statement sits and walks the group's body only down to that context
// (walkGroupToContext). A group's `stanza` children therefore reach the tree
// only when the group is applied at the top level or directly under a `stanza`
// node. Applying it under another stanza, or inside one of stanza's named
// entries, never adds a name under `stanza`.
//
//   - Seeds are apply-groups statements at the top level and directly under a
//     top-level `stanza` node.
//   - A `${node}` reference reaches BOTH node0 and node1, so both nodes compute
//     the same set from the same candidate.
//   - A reached group's own body is searched the same way, so a group applied
//     from inside another reached group is reached too. Each group is searched
//     once, so a cycle terminates here; group expansion reports it.
//
// The set errs toward COUNTING, which can only refuse a config, never admit a
// collision:
//   - a group reached only at the `stanza` context has its whole body searched,
//     though expansion walks only its `stanza` subtree;
//   - apply-groups-except is ignored. It is enforced per destination during the
//     merge (#9422), and deciding it here could drop a group that still lands
//     in another destination.
//
// A reference to an undefined group is reached and has no body; group expansion
// reports that on its own.
func reachableGroupNamesAST(tree *ConfigTree, stanza string) map[string]struct{} {
	bodies := make(map[string][]*Node)
	var outside []*Node
	for _, child := range tree.Children {
		if child.Name() != "groups" {
			outside = append(outside, child)
			continue
		}
		// Node{Keys:["groups","node0"]} merges the group name into Keys[1] and
		// its children are the body; otherwise each child is one group, named
		// the way expandGroups names it.
		if len(child.Keys) >= 2 {
			bodies[child.Keys[1]] = append(bodies[child.Keys[1]], child.Children...)
			continue
		}
		for _, g := range child.Children {
			if len(g.Keys) == 0 {
				continue
			}
			name := g.Keys[0]
			if len(g.Keys) > 1 {
				name = g.Keys[1]
			}
			bodies[name] = append(bodies[name], g.Children...)
		}
	}
	reached := make(map[string]struct{})
	var pending []string
	reach := func(apply *Node) {
		for _, key := range apply.Keys[1:] {
			for _, node := range []string{"node0", "node1"} {
				name := resolveVars(key, map[string]string{"node": node})
				if _, seen := reached[name]; !seen {
					reached[name] = struct{}{}
					pending = append(pending, name)
				}
			}
		}
	}
	// scanLevel finds the applications in one body laid out from the top level:
	// its own apply-groups, and those directly under a `stanza` node.
	scanLevel := func(nodes []*Node) {
		for _, n := range nodes {
			switch n.Name() {
			case "apply-groups":
				reach(n)
			case stanza:
				for _, c := range n.Children {
					if c.Name() == "apply-groups" {
						reach(c)
					}
				}
			}
		}
	}
	scanLevel(outside)
	for len(pending) > 0 {
		name := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		scanLevel(bodies[name])
	}
	return reached
}
