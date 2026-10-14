package config

// isDefaultPolicyGroupBlock12823 identifies the Junos choice-container
// spelling at the security policies level. Group-adopted nodes are marked in
// mergeNodes so later group merges can distinguish them from inline values.
func isDefaultPolicyGroupBlock12823(ancestorPath [][]string, n *Node) bool {
	if n == nil || n.IsLeaf || len(n.Keys) != 1 || n.Keys[0] != "default-policy" ||
		len(ancestorPath) == 0 {
		return false
	}
	parent := schemaAtAncestorPath(ancestorPath)
	return parent != nil && resolveSchemaChild(parent, "default-policy") == schemaSecurity.children["policies"].children["default-policy"]
}

// markDefaultPolicyGroupBlocks12823 records group block nodes throughout an
// expanded clone, including blocks merged during nested-group expansion.
// The expansion-local pointer set is deliberately independent of #9862's
// apply-groups-except contributor metadata.
func markDefaultPolicyGroupBlocks12823(budget *groupExpandBudget, ancestorPath [][]string, nodes []*Node) {
	markDefaultPolicyGroupBlocksAtPath12823(budget, ancestorPath, nodes)
}

func markDefaultPolicyGroupBlocksAtPath12823(budget *groupExpandBudget, path [][]string, nodes []*Node) {
	for _, n := range nodes {
		if n == nil {
			continue
		}
		if isDefaultPolicyGroupBlock12823(path, n) {
			if budget.groupDefaultPolicyBlocks12823 == nil {
				budget.groupDefaultPolicyBlocks12823 = make(map[*Node]bool)
			}
			budget.groupDefaultPolicyBlocks12823[n] = true
		}
		if !n.IsLeaf && len(n.Children) > 0 {
			markDefaultPolicyGroupBlocksAtPath12823(budget, append(path, n.Keys), n.Children)
		}
	}
}

// defaultPolicyGroupBlockOverride12823 suppresses a group choice block only
// when the destination is an authored inline choice. A destination that came
// from another group remains mergeable, preserving #11367's rejection of
// conflicting group defaults when there is no explicit inline override.
func defaultPolicyGroupBlockOverride12823(budget *groupExpandBudget, ancestorPath [][]string, dst []*Node, src *Node) bool {
	if !isDefaultPolicyGroupBlock12823(ancestorPath, src) {
		return false
	}
	for _, n := range dst {
		if n == nil || n.IsLeaf || !keysEqual(n.Keys, src.Keys) {
			continue
		}
		if budget.groupDefaultPolicyBlocks12823[n] {
			continue
		}
		return true
	}
	return false
}
