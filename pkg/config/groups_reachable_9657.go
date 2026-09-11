package config

import "strings"

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
//   - A reference is counted unresolved AND resolved for node0 and node1. A
//     compile without node variables expands it unresolved (a group literally
//     named `${node}` lands as is), and each cluster node expands its own
//     resolution, so both nodes compute the same set from the same candidate.
//   - A reached group's own body is searched the same way, so a group applied
//     from inside another reached group is reached too. Each group is searched
//     once, so a cycle terminates here; group expansion reports it.
//
// An `apply-groups-except` that group expansion honours (#9422, enforced per
// destination in mergeNodes) removes a group from the returned set:
//   - a top-level application is excluded by an exclusion at the top level, or
//     at ANY top-level `stanza` root (siblingsExcludeGroup);
//   - an application directly under a `stanza` root is excluded only by that
//     root, so the group is dropped only when EVERY root excludes it.
//
// Wherever the exclusion cannot be decided without expanding, the group is still
// counted, which can only refuse a config, never admit a collision:
//   - a group also reached from another group's body (that content merges under
//     the other group's name, so excluding this one does not stop it);
//   - a `${node}` name on either side;
//   - the flat `set` spelling, whose group name group expansion does not read
//     (#9685);
//   - a group reached only at the `stanza` context has its whole body searched,
//     though expansion walks only its `stanza` subtree.
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
	// How each group was reached decides whether an exclusion can drop it.
	type reachSites struct{ top, stanza, body, variable bool }
	sites := make(map[string]*reachSites)
	reached := make(map[string]struct{})
	var pending []string
	reach := func(apply *Node, site string) {
		for _, key := range apply.Keys[1:] {
			variable := strings.Contains(key, "${")
			for _, name := range []string{
				key,
				resolveVars(key, map[string]string{"node": "node0"}),
				resolveVars(key, map[string]string{"node": "node1"}),
			} {
				rs := sites[name]
				if rs == nil {
					rs = &reachSites{}
					sites[name] = rs
				}
				switch site {
				case "top":
					rs.top = true
				case "stanza":
					rs.stanza = true
				default:
					rs.body = true
				}
				if variable {
					rs.variable = true
				}
				if _, seen := reached[name]; !seen {
					reached[name] = struct{}{}
					pending = append(pending, name)
				}
			}
		}
	}
	// scanLevel finds the applications in one body laid out from the top level:
	// its own apply-groups, and those directly under a `stanza` node.
	scanLevel := func(nodes []*Node, inGroupBody bool) {
		for _, n := range nodes {
			switch n.Name() {
			case "apply-groups":
				if inGroupBody {
					reach(n, "body")
				} else {
					reach(n, "top")
				}
			case stanza:
				for _, c := range n.Children {
					if c.Name() == "apply-groups" {
						if inGroupBody {
							reach(c, "body")
						} else {
							reach(c, "stanza")
						}
					}
				}
			}
		}
	}
	scanLevel(outside, false)
	for len(pending) > 0 {
		name := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		scanLevel(bodies[name], true)
	}

	// #9422 exclusions, read the way nodesExcludeGroup reads them: from the
	// statement's own keys only, literal names only.
	excludes := func(nodes []*Node, group string) bool {
		for _, n := range nodes {
			if n == nil || n.Name() != "apply-groups-except" {
				continue
			}
			for _, key := range n.Keys[1:] {
				if !strings.Contains(key, "${") && key == group {
					return true
				}
			}
		}
		return false
	}
	var stanzaRoots []*Node
	for _, n := range outside {
		if n.Name() == stanza && !n.IsLeaf {
			stanzaRoots = append(stanzaRoots, n)
		}
	}
	for name := range reached {
		rs := sites[name]
		if rs == nil || rs.body || rs.variable || len(stanzaRoots) == 0 && !rs.top {
			continue
		}
		anyRoot, everyRoot := false, len(stanzaRoots) > 0
		for _, root := range stanzaRoots {
			if excludes(root.Children, name) {
				anyRoot = true
			} else {
				everyRoot = false
			}
		}
		topExcluded := !rs.top || excludes(outside, name) || anyRoot
		stanzaExcluded := !rs.stanza || everyRoot
		if topExcluded && stanzaExcluded {
			delete(reached, name)
		}
	}
	return reached
}
