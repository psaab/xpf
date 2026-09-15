package config

// normalizeImplicitInetFilters9899 gives Junos' [edit firewall filter] spelling
// the same compiler view as [edit firewall family inet filter]. Run on clones
// after compact normalization, before expansion and validation, and never on the
// candidate or display tree. A packed `firewall family inet` root must first
// fold, or its filter children would be mistaken for implicit-inet definitions.
// Every implicit filter in one firewall scope shares a SINGLE navigable
// `family inet` scope: one synthetic wrapper when no explicit one exists, or
// the first explicit wrapper when one does (implicit definitions keep their
// document order around its children). Per-filter wrappers broke nested group
// inheritance — walkGroupToContext returns the FIRST matching scope only, so
// every later filter's inherited template silently vanished. Duplicate and
// family-any collision gates still see every definition: nothing is merged
// away, only re-homed under one scope.
func normalizeImplicitInetFilters9899(tree *ConfigTree) int {
	if tree == nil {
		return 0
	}
	return normalizeImplicitInetScope9899(tree.Children)
}

func normalizeImplicitInetScope9899(nodes []*Node) int {
	changed := 0
	for _, root := range nodes {
		if root == nil {
			continue
		}
		switch root.Name() {
		case "firewall":
			if len(root.Keys) != 1 {
				continue
			}
			var implicitIdx []int
			explicitIdx := -1
			for i, child := range root.Children {
				if child == nil {
					continue
				}
				if child.Name() == "filter" {
					implicitIdx = append(implicitIdx, i)
					continue
				}
				if explicitIdx < 0 && len(child.Keys) == 2 && child.Keys[0] == "family" && child.Keys[1] == "inet" && !child.IsLeaf {
					explicitIdx = i
				}
			}
			if len(implicitIdx) == 0 {
				continue
			}
			changed += len(implicitIdx)
			implicit := make([]*Node, 0, len(implicitIdx))
			for _, i := range implicitIdx {
				implicit = append(implicit, root.Children[i])
			}
			keep := func(i int) bool {
				for _, j := range implicitIdx {
					if i == j {
						return false
					}
				}
				return true
			}
			if explicitIdx >= 0 {
				// Re-home into the existing scope, preserving document order:
				// implicit definitions before the explicit node go first.
				var before, after []*Node
				for k, i := range implicitIdx {
					if i < explicitIdx {
						before = append(before, implicit[k])
					} else {
						after = append(after, implicit[k])
					}
				}
				explicit := root.Children[explicitIdx]
				explicit.Children = append(append(before, explicit.Children...), after...)
				next := make([]*Node, 0, len(root.Children)-len(implicitIdx))
				for i, child := range root.Children {
					if keep(i) {
						next = append(next, child)
					}
				}
				root.Children = next
				continue
			}
			wrapper := &Node{Keys: []string{"family", "inet"}, Children: implicit}
			next := make([]*Node, 0, len(root.Children)-len(implicitIdx)+1)
			placed := false
			for i, child := range root.Children {
				if !keep(i) {
					if !placed {
						next = append(next, wrapper)
						placed = true
					}
					continue
				}
				next = append(next, child)
			}
			root.Children = next
		case "groups":
			// Only configuration roots and group bodies are root scopes. An
			// arbitrary instance named "firewall" must not be rewritten.
			if len(root.Keys) >= 2 {
				changed += normalizeImplicitInetScope9899(root.Children)
			} else {
				for _, group := range root.Children {
					if group != nil {
						changed += normalizeImplicitInetScope9899(group.Children)
					}
				}
			}
		}
	}
	return changed
}
