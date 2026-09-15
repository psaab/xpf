package config

// normalizeImplicitInetFilters9899 gives Junos' [edit firewall filter] spelling
// the same compiler view as [edit firewall family inet filter]. Run on clones
// after compact normalization, before expansion and validation, and never on the
// candidate or display tree. A packed `firewall family inet` root must first
// fold, or its filter children would be mistaken for implicit-inet definitions.
// Keep each definition in place so duplicate and family-any collision gates
// retain their evidence; this pass must not merge definitions away.
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
			for i, child := range root.Children {
				if child != nil && child.Name() == "filter" {
					root.Children[i] = &Node{
						Keys:     []string{"family", "inet"},
						Children: []*Node{child},
					}
					changed++
				}
			}
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
