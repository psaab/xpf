package config

// `apply-groups-except` — #9422.
//
// Junos: "Don't inherit configuration data from these groups"
// (docs/junos-config-display-reference.md:76). A stanza carrying
// `apply-groups-except <g>` does not inherit from group <g> at that point in
// the hierarchy, even though an ancestor applied it.
//
// Before this, the token was ACCEPTED by every config channel and consulted by
// NONE. `ConfigTree.expandGroups` collected only `apply-groups`; there was no
// `apply-groups-except` branch anywhere in expansion, `mergeNodes`,
// `walkGroupToContext` or `stripApplyGroups`. The five production references to
// the keyword were all of the form "skip this token so it is not misread as a
// sibling member" (#7029) — none of them an exclusion. Measured on the base
// revision, removing the `-except` line changed NOTHING:
//
//	groups { G { system { host-name FROM-GROUP; } } }
//	apply-groups G;
//	system { apply-groups-except G; domain-name example.com; }
//	  -> System.HostName = "FROM-GROUP", Warnings = []      (identical without it)
//
// The exclusion is enforced in `mergeNodes` rather than by pre-pruning the
// group body, because mergeNodes is the only place that already knows the
// DESTINATION each part of a group body lands in. That matters for a `<*>`
// group key, which fans one source subtree out into every matching destination
// container: two of those containers may disagree about whether they exclude
// the group, and a decision taken once against the group body cannot express
// that. Checking at each merge level gets it per-destination for free, and the
// level-scoped check inherits down the subtree exactly as the Junos statement
// reads — everything at and below the excluding stanza stops inheriting.
//
// The `apply-groups-except` node is deliberately LEFT in the tree, unlike
// `apply-groups` which expansion strips. It has no compiled meaning, so the
// #7029 skip lists that keep it from being read as a zone/interface member are
// still what stops that, and their fixtures stay non-vacuous.
//
// A name that matches no defined group is a no-op rather than an error: unlike
// `apply-groups`, which fails to ADD configuration and therefore has to say so,
// an exclusion that matches nothing removes nothing. Rejecting it would also
// break a shared cluster config that excludes a `${node}` group defined only in
// the peer's view.

// treeHasApplyGroupsExcept9862 reports whether the tree carries any
// `apply-groups-except` statement anywhere, including inside group definitions
// (an exclusion authored in a group's own body filters that group's nested
// merges). It gates ALL #9862 machinery: when false, expansion tags nothing,
// accumulates nothing, and filters nothing — bit-identical to #9422.
//
// The scan matches the keyword in ANY key position, not just the node's own:
// a packed group leaf (`routing-instances ri9 apply-groups-except H;`) carries
// the exclusion on its Keys tail with Name()=="routing-instances", and #7648
// synthesis materializes the real exclusion node into the destination DURING
// the merge — after this scan ran. Missing it would leave the gate off while
// a live exclusion sits in the tree, regressing the #9422 vetoes (which
// consulted the tree unconditionally) for subsequently applied groups. A
// keyword-valued leaf (`description apply-groups-except;`) trips the gate
// spuriously, but that only enables tagging walks: collection still reads
// statement nodes, so no exclusion is invented. Vars need no handling: the
// splitter takes no vars, so a `${var}` tail can never synthesize an
// exclusion the literal scan misses.
func treeHasApplyGroupsExcept9862(nodes []*Node) bool {
	for _, n := range nodes {
		if n == nil {
			continue
		}
		for _, k := range n.Keys {
			if k == "apply-groups-except" {
				return true
			}
		}
		if treeHasApplyGroupsExcept9862(n.Children) {
			return true
		}
	}
	return false
}

// cloneExceptSet9862 copies an accumulated exclusion set for descent. mergeNodes
// recursion must never share the map with its caller: each level adds its own
// names, and a shared map would leak one destination's exclusions into its
// siblings. Sets hold a handful of names, so the copy is negligible.
func cloneExceptSet9862(set map[string]bool) map[string]bool {
	if len(set) == 0 {
		return nil
	}
	out := make(map[string]bool, len(set))
	for name := range set {
		out[name] = true
	}
	return out
}

// collectExceptNames9862 union-adds the vars-resolved group names this
// hierarchy level excludes into into, allocating it on first use. Bracket lists
// (`apply-groups-except [ g1 g2 ]`) collapse onto one node's Keys, so every key
// past the keyword is a group name; `${var}` names resolve the same way
// `apply-groups` names do.
func collectExceptNames9862(nodes []*Node, vars map[string]string, into map[string]bool) map[string]bool {
	for _, n := range nodes {
		if n == nil || n.Name() != "apply-groups-except" {
			continue
		}
		for _, key := range n.Keys[1:] {
			if into == nil {
				into = make(map[string]bool)
			}
			into[resolveVars(key, vars)] = true
		}
	}
	return into
}

// collectSiblingExceptNames9862 union-adds the exclusions carried by EVERY
// same-keyed destination container into into. It is used at the CONTAINER
// descent only. The wildcard branch does not need it: that branch already
// recurses into each matching destination separately, so the per-destination
// decision is taken by the entry accumulation of the recursive call — and a
// same-keyed duplicate under a wildcard-matched container is folded away by
// mergeDuplicateBlocks9023 before expansion runs. A copy of this check was
// written there first and MUTATION-TESTED AS DEAD (severing it killed nothing),
// which is what identified it as redundant rather than as an untested branch.
//
// The union exists because one logical hierarchy level can be spread across
// several AST nodes — `system { host-name p; } … system { apply-groups-except
// G; }` is two top-level `system` nodes, and the compiler reads both — while
// mergeNodes merges a group's contribution into selected containers only.
// Asking only the receiving container reads the exclusion out of a config that
// plainly carries it, which was measured: the same fixture honoured the
// statement with one `system` block and ignored it with two. The scan is over
// `keysEqual` siblings, the same identity mergeNodes itself uses to decide
// what "the same container" means, so the two cannot drift. #9862 keeps the
// union for nested contributors too: same-keyed twins are ONE level, so an
// `apply-groups-except H` in either twin excludes H from the level.
func collectSiblingExceptNames9862(dst []*Node, keys []string, vars map[string]string, into map[string]bool) map[string]bool {
	for _, d := range dst {
		if d == nil || d.IsLeaf || !keysEqual(d.Keys, keys) {
			continue
		}
		into = collectExceptNames9862(d.Children, vars, into)
	}
	return into
}

// unionNodeContrib9862 union-adds each name in contrib to n's own provenance
// only (non-recursive). Shared by the subtree walk below and the leaf-list
// duplicate-ownership merge, which must not credit the duplicate's owners to
// unrelated grandchildren.
func unionNodeContrib9862(n *Node, contrib []string) {
	for _, c := range contrib {
		found := false
		for _, have := range n.fromGroups {
			if have == c {
				found = true
				break
			}
		}
		if !found {
			n.fromGroups = append(n.fromGroups, c)
		}
	}
}

// leafListMemberGroups9862 records one leaf-list member and the groups whose
// bodies contributed it. The slice is aligned with leafListMembers9627 on the
// owning node; a nil groups slice means authored-inline or uncertain
// ownership, which is intentionally kept by exclusion filtering.
type leafListMemberGroups9862 struct {
	value  string
	quoted bool
	groups []string
}

func cloneLeafMemberGroups9862(in []leafListMemberGroups9862) []leafListMemberGroups9862 {
	if in == nil {
		return nil
	}
	out := make([]leafListMemberGroups9862, len(in))
	for i, m := range in {
		out[i] = leafListMemberGroups9862{
			value:  m.value,
			quoted: m.quoted,
			groups: append([]string(nil), m.groups...),
		}
	}
	return out
}

// leafListMemberGroupsForNode9862 returns a member-aligned ownership view.
// Older/ordinary nodes have no parallel metadata, so their node-level
// fromGroups tag is used for every member. A union node keeps the richer
// parallel view.
func leafListMemberGroupsForNode9862(n *Node) []leafListMemberGroups9862 {
	if n == nil {
		return nil
	}
	members := leafListMembers9627(n)
	if len(members) == 0 {
		return nil
	}
	if len(n.leafMemberGroups9862) == len(members) {
		out := make([]leafListMemberGroups9862, len(n.leafMemberGroups9862))
		for i, m := range n.leafMemberGroups9862 {
			out[i] = leafListMemberGroups9862{
				value:  m.value,
				quoted: m.quoted,
				groups: append([]string(nil), m.groups...),
			}
		}
		return out
	}
	out := make([]leafListMemberGroups9862, len(members))
	for i, m := range members {
		out[i] = leafListMemberGroups9862{
			value:  m.value,
			quoted: m.quoted,
			groups: append([]string(nil), n.fromGroups...),
		}
	}
	return out
}

func unionMemberGroups9862(dst *[]string, src []string) {
	for _, want := range src {
		found := false
		for _, have := range *dst {
			if have == want {
				found = true
				break
			}
		}
		if !found {
			*dst = append(*dst, want)
		}
	}
}

// leafListMemberSurvives9862 applies the #9862 contributor rule to one
// member: an uncertain/authored member survives, and a tagged member survives
// when at least one of its contributors is not excluded.
func leafListMemberSurvives9862(m leafListMemberGroups9862, excluded map[string]bool) bool {
	if len(m.groups) == 0 {
		return true
	}
	for _, group := range m.groups {
		if !excluded[group] {
			return true
		}
	}
	return false
}

// filterLeafListMembers9862 removes only members whose every contributor is
// excluded. It runs on a cloned group source immediately before adoption or
// union, so collapsed (Keys) and block (child leaves) spellings share exactly
// the same per-member policy.
func filterLeafListMembers9862(n *Node, excluded map[string]bool) bool {
	if n == nil || len(excluded) == 0 {
		return true
	}
	members := leafListMemberGroupsForNode9862(n)
	if len(members) == 0 {
		return true
	}
	keep := make([]leafListMemberGroups9862, 0, len(members))
	keptIndexes := make([]int, 0, len(members))
	for i, m := range members {
		if leafListMemberSurvives9862(m, excluded) {
			keep = append(keep, m)
			keptIndexes = append(keptIndexes, i)
		}
	}
	if len(keep) == len(members) {
		// Preserve the synthesized metadata even when no member was removed;
		// a later outer merge may carry this node through another level.
		n.leafMemberGroups9862 = keep
		return true
	}
	if n.IsLeaf {
		keys := append([]string{n.Keys[0]}, make([]string, 0, len(keep))...)
		var quoted, bracketed []bool
		if len(n.KeysQuoted) == len(n.Keys) {
			quoted = append([]bool{n.KeysQuoted[0]}, make([]bool, 0, len(keep))...)
		}
		if len(n.KeysBracketed) == len(n.Keys) {
			bracketed = append([]bool{n.KeysBracketed[0]}, make([]bool, 0, len(keep))...)
		}
		for _, index := range keptIndexes {
			keys = append(keys, n.Keys[index+1])
			if quoted != nil {
				quoted = append(quoted, n.KeysQuoted[index+1])
			}
			if bracketed != nil {
				bracketed = append(bracketed, n.KeysBracketed[index+1])
			}
		}
		n.Keys = keys
		n.setKeysQuoted(quoted)
		n.setKeysBracketed(bracketed)
	} else {
		// A leaf-list block has one value-bearing child per member in the
		// ordinary AST. Keep the general multi-key walk for synthesized trees.
		memberIndex := 0
		children := make([]*Node, 0, len(n.Children))
		for _, child := range n.Children {
			if child == nil {
				continue
			}
			keys := make([]string, 0, len(child.Keys))
			var quoted, bracketed []bool
			if len(child.KeysQuoted) == len(child.Keys) {
				quoted = make([]bool, 0, len(child.Keys))
			}
			if len(child.KeysBracketed) == len(child.Keys) {
				bracketed = make([]bool, 0, len(child.Keys))
			}
			for i, key := range child.Keys {
				if memberIndex >= len(members) {
					break
				}
				if leafListMemberSurvives9862(members[memberIndex], excluded) {
					keys = append(keys, key)
					if quoted != nil {
						quoted = append(quoted, child.KeysQuoted[i])
					}
					if bracketed != nil {
						bracketed = append(bracketed, child.KeysBracketed[i])
					}
				}
				memberIndex++
			}
			if len(keys) == 0 {
				continue
			}
			child.Keys = keys
			child.setKeysQuoted(quoted)
			child.setKeysBracketed(bracketed)
			children = append(children, child)
		}
		n.Children = children
	}
	n.leafMemberGroups9862 = keep
	return len(keep) > 0
}

// addNodeContrib9862 union-adds each name in contrib to every node's subtree
// provenance. It tags a group's context-walked clone (with the resolved group
// name, before nested references expand) and inherits a packed-leaf source's
// contrib onto its synthesized body. Tags are chain-independent and flow
// through the #4474 memo verbatim via cloneNodes. Fresh synthesized nodes
// take the contrib as their whole set, while an (impossible-for-leaves,
// defensive) aliased child keeps its own tags too.
func addNodeContrib9862(nodes []*Node, contrib []string) {
	if len(contrib) == 0 {
		return
	}
	for _, n := range nodes {
		if n == nil {
			continue
		}
		unionNodeContrib9862(n, contrib)
		addNodeContrib9862(n.Children, contrib)
	}
}

// mergeLeafListDupOwnership9862 records src's ownership on dst's block-form
// children carrying value — the member the union just skipped as a duplicate.
// Without this, the first contributor's tag wins and excluding it drops a
// member a surviving group also owns (over-exclusion). Collapsed (Keys)
// members have no node to tag; the cleared parent covers them by falling back
// to keep. Ownership merges ONLY when both sides are known-tagged; a nil side
// means uncertain provenance (union-cleared or fresh-appended), which
// propagates nil so the fallback keeps the member rather than asserting a
// sole ownership the union cannot prove.
func mergeLeafListDupOwnership9862(dst, src *Node, value string) {
	if dst.IsLeaf || value == "" {
		return
	}
	for _, vn := range dst.Children {
		if vn == nil {
			continue
		}
		match := false
		for _, k := range vn.Keys {
			if k == value {
				match = true
				break
			}
		}
		if !match {
			continue
		}
		if len(vn.fromGroups) == 0 || len(src.fromGroups) == 0 {
			vn.fromGroups = nil
			continue
		}
		unionNodeContrib9862(vn, src.fromGroups)
	}
}

// contribExcluded9862 reports whether every contributor of the node is
// excluded: a node survives iff ANY contributor survives (never
// over-excludes). Single-contributor nodes — the overwhelmingly common case —
// behave exactly as an intersection check; the distinction matters only for
// multi-owner leaf-list members, whose duplicate-merged ownership must keep
// the member while any owner survives. Untagged (nil) nodes are cross-group
// leaf-list unions whose per-member provenance mergeLeafListInto cleared as
// uncertain, or fresh union-appended member leaves; they fall back to the
// merge's outer group, which keeps them unless the outer application is
// itself vetoed. (Every src clone is tagged when filtering is active, so the
// fallback covers uncertain-overwritten nodes, not missing tags.)
func contribExcluded9862(n *Node, group string, excluded map[string]bool) bool {
	if len(excluded) == 0 {
		return false
	}
	if len(n.fromGroups) == 0 {
		return group != "" && excluded[group]
	}
	for _, c := range n.fromGroups {
		if !excluded[c] {
			return false
		}
	}
	return true
}

// subtreeSurvives9862 reports whether filtering keeps anything of n: the node
// itself when its own provenance is clean, else any surviving descendant (the
// node then routes or adopts as a shell for its surviving children). Leaf-list
// blocks need no special case: pure blocks carry one contributor so survival is
// atomic by construction, and cross-group unions are tag-cleared so the
// fallback keeps them (documented under-exclusion, never over-exclusion).
func subtreeSurvives9862(n *Node, group string, excluded map[string]bool) bool {
	if n == nil {
		return false
	}
	if !contribExcluded9862(n, group, excluded) {
		return true
	}
	for _, c := range n.Children {
		if subtreeSurvives9862(c, group, excluded) {
			return true
		}
	}
	return false
}

// pruneExcluded9862 drops excluded-contrib nodes from a wholesale-adopted
// subtree, recursing so a kept container's excluded children do not ride along.
// A container is dropped only when it is itself excluded AND nothing of it
// survives: an independently authored container (clean own provenance) is
// preserved even when its only children were excluded inheritances — an empty
// zone is a real object, and the exclusion names H's statements, not G's.
// Runs after pruneWildcardInstances9802; the two commute (both drop, and the
// adopter's emptiness check below covers either).
func pruneExcluded9862(nodes []*Node, group string, excluded map[string]bool) []*Node {
	if len(excluded) == 0 {
		return nodes
	}
	out := nodes[:0]
	for _, n := range nodes {
		if n == nil {
			continue
		}
		kept := pruneExcluded9862(n.Children, group, excluded)
		if len(kept) == 0 && contribExcluded9862(n, group, excluded) {
			continue
		}
		n.Children = kept
		out = append(out, n)
	}
	return out
}
