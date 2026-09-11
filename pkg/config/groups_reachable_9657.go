package config

// reachableGroupNamesAST returns the names of the `groups` blocks that some
// apply-groups statement can reach (#9657), without expanding anything. It
// answers "could this group's contents compile on either cluster node" for the
// pre-expansion collision views, which must not count a group that group
// expansion drops.
//
//   - Seeds are every apply-groups statement outside the groups stanza, at any
//     depth: a nested apply-groups applies its group at that stanza.
//   - A `${node}` reference reaches BOTH node0 and node1, so both nodes compute
//     the same set from the same candidate.
//   - A reached group's own body is searched the same way, so a group applied
//     only from inside another reached group is reached too. Each group is
//     searched once, so a cycle terminates here; group expansion reports it.
//
// apply-groups-except is ignored: it narrows where a reached group applies,
// never whether it is reached, so ignoring it keeps the set a superset. A
// reference to an undefined group is reached and has no body; group expansion
// reports that on its own.
func reachableGroupNamesAST(tree *ConfigTree) map[string]struct{} {
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
	var scan func(nodes []*Node)
	scan = func(nodes []*Node) {
		for _, n := range nodes {
			if n.Name() == "apply-groups" {
				for _, key := range n.Keys[1:] {
					for _, node := range []string{"node0", "node1"} {
						name := resolveVars(key, map[string]string{"node": node})
						if _, seen := reached[name]; !seen {
							reached[name] = struct{}{}
							pending = append(pending, name)
						}
					}
				}
				continue
			}
			scan(n.Children)
		}
	}
	scan(outside)
	for len(pending) > 0 {
		name := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		scan(bodies[name])
	}
	return reached
}
