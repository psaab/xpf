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

// isDefaultPolicyGroupStanza12923 matches BOTH spellings of a group's
// default-policy choice at the security policies level: the flat valued leaf
// (`default-policy permit-all;`) and the braced block #12823 tracks. Only the
// block carried provenance before, so a flat leaf met the inline-wins override
// and the #4325 no-duplicate guard even when the winning destination stanza
// came from another apply-group — two groups with different actions resolved
// by order, permit-first, with no stanza pair for #11821/#12821 to see.
func isDefaultPolicyGroupStanza12923(ancestorPath [][]string, n *Node) bool {
	if n == nil || (!n.IsLeaf && len(n.Keys) != 1) || len(n.Keys) == 0 ||
		n.Keys[0] != "default-policy" || len(ancestorPath) == 0 {
		return false
	}
	parent := schemaAtAncestorPath(ancestorPath)
	return parent != nil && resolveSchemaChild(parent, "default-policy") == schemaSecurity.children["policies"].children["default-policy"]
}

// markGroupDefaultPolicyStanza12923 records one default-policy stanza as
// adopted from a group, so a later group's stanza beside it is treated as a
// group-group pair rather than an inline override.
func markGroupDefaultPolicyStanza12923(budget *groupExpandBudget, ancestorPath [][]string, n *Node) {
	if budget == nil || !isDefaultPolicyGroupStanza12923(ancestorPath, n) {
		return
	}
	if budget.groupDefaultPolicyBlocks12823 == nil {
		budget.groupDefaultPolicyBlocks12823 = make(map[*Node]bool)
	}
	budget.groupDefaultPolicyBlocks12823[n] = true
}

// groupDefaultPolicyStanzaAdopted12923 reports whether dst holds a default-
// policy stanza already adopted from a group.
func groupDefaultPolicyStanzaAdopted12923(budget *groupExpandBudget, dst []*Node) bool {
	for _, n := range dst {
		if n != nil && budget.groupDefaultPolicyBlocks12823[n] {
			return true
		}
	}
	return false
}

// markDefaultPolicyGroupBlocks12823 records group default-policy stanzas —
// block and flat-leaf spellings — throughout an expanded clone, including
// stanzas merged during nested-group expansion. The expansion-local pointer
// set is deliberately independent of #9862's apply-groups-except contributor
// metadata.
func markDefaultPolicyGroupBlocks12823(budget *groupExpandBudget, ancestorPath [][]string, nodes []*Node) {
	markDefaultPolicyGroupBlocksAtPath12823(budget, ancestorPath, nodes)
}

func markDefaultPolicyGroupBlocksAtPath12823(budget *groupExpandBudget, path [][]string, nodes []*Node) {
	for _, n := range nodes {
		if n == nil {
			continue
		}
		if isDefaultPolicyGroupStanza12923(path, n) {
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
