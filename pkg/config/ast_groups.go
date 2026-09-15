package config

import (
	"fmt"
	"strings"
)

const (
	// maxGroupExpandDepth bounds the TRANSITIVE nested-group recursion —
	// apply-groups inside a group body inside a group body, a chain
	// g1->g2->...->gN (#5194 A3-b2-F1). The `seen` cycle guard only rejects a
	// group that references ITSELF (directly or via a cycle); the #4474 memo
	// only collapses a converging DAG. Neither bounds a shallow-syntax ACYCLIC
	// chain of distinct groups, which recurses one stack frame per link and can
	// exhaust the goroutine stack on commit / HA config-sync. A legitimate Junos
	// config nests apply-groups templates only a handful deep, so this cap sits
	// far above real use yet rejects a generated/pathological chain cleanly with
	// an error instead of crashing.
	maxGroupExpandDepth = 64
	// maxGroupExpandWork bounds the TOTAL number of group expansions performed
	// across one ExpandGroups call (every context, every nesting level). It
	// catches a wide shallow fan-out that stays under the depth cap but still
	// performs unbounded work, and is a backstop for the depth cap itself.
	maxGroupExpandWork = 100000
)

// groupExpandBudget carries the total-work counter shared across the whole
// expansion recursion (depth is passed by value per nested-group level).
type groupExpandBudget struct {
	work int // group expansions performed so far
	// promoted9855 records the dst nodes promoteLeafPeerForPackedGroup9855
	// promoted during this expansion (#9855). A promotion turns a leaf peer
	// into a two-key container, which leafListPeer can no longer select —
	// so a successive same-keyword group leaf must resolve against the
	// promoted node (raw match) or be suppressed (master suppressed it via
	// the pre-promotion leaf), never adopted beside it as a twin. The
	// budget struct is already the per-expansion shared state, so the set
	// rides here rather than as a tenth mergeNodes parameter; checks are
	// siblings-only, so entries from other levels never interfere.
	promoted9855 map[*Node]bool
}

// charge accounts n units of expansion work and reports when the budget is
// exhausted (#6767).
//
// Before this, work was charged ONCE per `apply-groups <name>` reference
// resolved, and mergeNodes — which does the actual cloning and merging — took
// no budget at all. A wildcard group container is merged into EVERY matching
// destination container, so the real cost is the (wildcard node x matching
// container) product, and a config with a handful of apply-groups references
// could build a quadratic AST while charging a handful of units.
func (b *groupExpandBudget) charge(n int) error {
	b.work += n
	if b.work > maxGroupExpandWork {
		return fmt.Errorf("apply-groups expansion exceeds maximum work budget of %d (possible generated or pathological config)", maxGroupExpandWork)
	}
	return nil
}

// countNodes is the size of a subtree forest, used to charge the budget for a
// clone BEFORE performing it — so a pathological fan-out is refused rather than
// materialised and then noticed.
func countNodes(nodes []*Node) int {
	n := 0
	for _, x := range nodes {
		if x == nil {
			continue
		}
		n += 1 + countNodes(x.Children)
	}
	return n
}

// ExpandGroups resolves all "apply-groups" references in the tree.
// It collects group definitions from the "groups" stanza, then for each
// "apply-groups <name>" node, clones the referenced group's children and
// merges them into the parent. After expansion, both "groups" and
// "apply-groups" nodes are removed from the tree.
func (t *ConfigTree) ExpandGroups() error {
	return t.expandGroups(false, nil)
}

// ExpandGroupsTagged is like ExpandGroups but tags each inherited node
// with InheritedFrom set to the group name, for "| display inheritance".
func (t *ConfigTree) ExpandGroupsTagged() error {
	return t.expandGroups(true, nil)
}

// ExpandGroupsWithVars is like ExpandGroups but resolves ${var} references
// in apply-groups names before lookup. This supports Junos-style per-node
// group selection, e.g. apply-groups "${node}" with vars {"node": "node0"}.
func (t *ConfigTree) ExpandGroupsWithVars(vars map[string]string) error {
	return t.expandGroups(false, vars)
}

// ExpandGroupsWithVarsTagged is ExpandGroupsWithVars with the
// ExpandGroupsTagged provenance marking: each inherited node carries
// InheritedFrom. The node-aware compile entry needs both the ${node}
// resolution and the #9854 coalescing provenance.
func (t *ConfigTree) ExpandGroupsWithVarsTagged(vars map[string]string) error {
	return t.expandGroups(true, vars)
}

// resolveVars replaces ${key} placeholders in s with values from vars.
func resolveVars(s string, vars map[string]string) string {
	if vars == nil {
		return s
	}
	for k, v := range vars {
		s = strings.ReplaceAll(s, "${"+k+"}", v)
	}
	return s
}

func (t *ConfigTree) expandGroups(tagInherited bool, vars map[string]string) error {
	// Collect group definitions: groups { <name> { ... } }
	groups := make(map[string]*Node)
	for _, child := range t.Children {
		if child.Name() == "groups" {
			for _, g := range child.Children {
				if len(g.Keys) < 1 {
					continue
				}
				name := g.Keys[0]
				if len(g.Keys) > 1 {
					name = g.Keys[1]
				}
				groups[name] = g
			}
		}
	}

	// If no groups defined, just strip any stale apply-groups references.
	if len(groups) == 0 {
		return t.stripApplyGroups(vars)
	}

	// Recursively resolve apply-groups at all levels.
	// The nil ancestorPath means we're at the top level. The memo map is
	// created once here and threaded through the whole recursion so a group
	// reachable via many paths (a converging DAG) is expanded ONCE (#4474).
	// haveExcept gates ALL #9862 machinery (provenance tagging, exclusion
	// accumulation, nested filtering): without a single `apply-groups-except`
	// in the tree, expansion is bit-identical to #9422.
	haveExcept := treeHasApplyGroupsExcept9862(t.Children)
	if err := expandGroupsRecursive(&t.Children, groups, nil, nil, make(map[string][]*Node), tagInherited, vars, 0, &groupExpandBudget{}, haveExcept); err != nil {
		return err
	}

	// Remove the "groups" stanza itself.
	filtered := make([]*Node, 0, len(t.Children))
	for _, child := range t.Children {
		if child.Name() != "groups" {
			filtered = append(filtered, child)
		}
	}
	t.Children = filtered

	return nil
}

// ancestorPathKey serializes an ancestor context path ([][]string) into a
// stable string for the group-expansion memo (#4474). Control-char separators
// (\x1e between path elements, \x1f between the keys of one element) keep it
// collision-free — config tokens never contain those bytes.
func ancestorPathKey(ancestorPath [][]string) string {
	if len(ancestorPath) == 0 {
		return ""
	}
	var b strings.Builder
	for i, keys := range ancestorPath {
		if i > 0 {
			b.WriteByte('\x1e')
		}
		for j, k := range keys {
			if j > 0 {
				b.WriteByte('\x1f')
			}
			b.WriteString(k)
		}
	}
	return b.String()
}

// tagNodesInherited recursively sets InheritedFrom on all nodes.
func tagNodesInherited(nodes []*Node, groupName string) {
	for _, n := range nodes {
		n.InheritedFrom = groupName
		tagNodesInherited(n.Children, groupName)
	}
}

// stripApplyGroups walks the tree after group expansion and returns an error
// if any apply-groups node still references an undefined group. vars is used
// to resolve ${var} placeholders in group names for error messages.
func (t *ConfigTree) stripApplyGroups(vars map[string]string) error {
	return stripApplyGroupsInNodes(t.Children, vars)
}

func stripApplyGroupsInNodes(nodes []*Node, vars map[string]string) error {
	for _, child := range nodes {
		if child.Name() == "apply-groups" {
			name := ""
			if len(child.Keys) > 1 {
				name = resolveVars(child.Keys[1], vars)
			}
			return fmt.Errorf("apply-groups references undefined group %q", name)
		}
		if !child.IsLeaf {
			if err := stripApplyGroupsInNodes(child.Children, vars); err != nil {
				return err
			}
		}
	}
	return nil
}

// walkGroupToContext walks a group definition's tree to match the ancestor
// context path. Each element of ancestorPath is the Keys slice of a parent
// node from root to the current level. Returns the children of the deepest
// matching node, or nil if the group has no matching subtree.
// Supports <*> wildcard matching in group keys.
func walkGroupToContext(groupChildren []*Node, ancestorPath [][]string) []*Node {
	current := groupChildren
	for _, pathKeys := range ancestorPath {
		var next []*Node
		for _, child := range current {
			if child.IsLeaf {
				continue
			}
			// Exact match or wildcard match (group keys may contain <*>).
			if keysEqual(child.Keys, pathKeys) || keysMatchWildcard(pathKeys, child.Keys) {
				next = child.Children
				break
			}
		}
		if next == nil {
			return nil // group doesn't have matching subtree at this context
		}
		current = next
	}
	return current
}

// expandGroupsRecursive processes apply-groups nodes within a node list,
// then recurses into all children to handle nested apply-groups.
// ancestorPath tracks the key path from root to the current level, enabling
// groups to be walked down to the matching context for nested apply-groups.
// seen tracks group names being expanded to detect circular references.
// memo caches the fully-expanded body of a group keyed by (name, ancestor
// context) so a converging DAG expands each group once (#4474 fan-out fix).
// If tagInherited is true, merged nodes get InheritedFrom set to the group name.
// vars provides ${var} replacements for group names (may be nil).
// haveExcept gates the #9862 provenance tagging: with no `apply-groups-except`
// in the tree, clones stay untagged and every filter below keeps all.
func expandGroupsRecursive(nodes *[]*Node, groups map[string]*Node, ancestorPath [][]string, seen map[string]bool, memo map[string][]*Node, tagInherited bool, vars map[string]string, depth int, budget *groupExpandBudget, haveExcept bool) error {
	// #5194 A3-b2-F1: bound the nested-group recursion depth before it can
	// exhaust the goroutine stack on a deep acyclic chain g1->g2->...->gN.
	if depth > maxGroupExpandDepth {
		return fmt.Errorf("apply-groups nesting exceeds maximum depth of %d (possible generated or pathological config)", maxGroupExpandDepth)
	}
	// First, collect apply-groups references at this level.
	// Support bracket-list syntax: apply-groups [ name1 name2 ] produces
	// Keys = ["apply-groups", "name1", "name2"].
	var applyNames []string
	for _, n := range *nodes {
		if n.Name() == "apply-groups" {
			for _, key := range n.Keys[1:] {
				applyNames = append(applyNames, resolveVars(key, vars))
			}
		}
	}

	// Expand each referenced group.
	for _, name := range applyNames {
		g, ok := groups[name]
		if !ok {
			return fmt.Errorf("apply-groups references undefined group %q", name)
		}

		// #5194 A3-b2-F1: bound the TOTAL expansion work so a wide shallow
		// fan-out (many groups, each referenced from many contexts) that stays
		// under the depth cap still cannot spin unbounded on commit / HA sync.
		budget.work++
		if budget.work > maxGroupExpandWork {
			return fmt.Errorf("apply-groups expansion exceeds maximum work budget of %d (possible generated or pathological config)", maxGroupExpandWork)
		}

		// Memoization (#4474 fan-out fix): the fully-expanded body of a group
		// is a function ONLY of (group name, ancestor context) within one
		// ExpandGroups call — walkGroupToContext AND the nested-expansion
		// context both depend on ancestorPath, while tagInherited/vars are
		// constant for the call. A completed memo entry is a fully-resolved,
		// cycle-free body (a cyclic expansion errors out before it is cached),
		// so reusing it is always correct. Without this, a converging DAG
		// re-expands a shared group once PER PATH — delete(seen,name) runs per
		// branch, so the `seen` cycle guard does NOT bound the fan-out — and a
		// machine-generated deep nested-group DAG goes exponential (~2x/level).
		// mergeNodes MUTATES its src argument, so store and hand out fresh
		// clones and keep the cached copy pristine.
		memoKey := name + "\x00" + ancestorPathKey(ancestorPath)
		if cached, hit := memo[memoKey]; hit {
			if cached != nil {
				// #6767: a memo HIT still clones and merges the whole cached
				// subtree, so it costs the same as a miss and must be charged.
				if err := budget.charge(countNodes(cached)); err != nil {
					return err
				}
				if err := mergeNodes(nodes, cloneNodes(cached), ancestorPath, budget, name, vars, nil, haveExcept); err != nil {
					return err
				}
			}
			continue
		}

		if seen == nil {
			seen = make(map[string]bool)
		}
		if seen[name] {
			return fmt.Errorf("apply-groups circular reference: group %q", name)
		}
		seen[name] = true

		// Walk the group tree to match the current context path.
		var srcChildren []*Node
		if len(ancestorPath) == 0 {
			// Top-level: merge group's direct children.
			srcChildren = g.Children
		} else {
			srcChildren = walkGroupToContext(g.Children, ancestorPath)
		}

		var expanded []*Node
		if srcChildren != nil {
			cloned := cloneNodes(srcChildren)
			if tagInherited {
				tagNodesInherited(cloned, name)
			}
			// #9862: leaf provenance for `apply-groups-except` through nested
			// groups. Tags the outer group's own body BEFORE the nested
			// expansion below merges nested content in, so nested nodes keep
			// the nested name. Gated: untagged clones filter identically to
			// #9422 when the tree carries no exclusion.
			if haveExcept {
				addNodeContrib9862(cloned, []string{name})
			}
			// Transitive apply-groups (#4474): a group body may itself say
			// `apply-groups G2` (a nested-group template, a standard Junos
			// idiom). Expand the group's OWN references to a fixed point BEFORE
			// merging its body, so G2's content is inherited rather than
			// silently dropped when the outer strip-and-recurse removes the
			// merged-in `apply-groups G2` node. The `seen` guard — `name` is
			// already marked above — breaks cycles (grpA->grpB->grpA returns a
			// circular-reference error, same as a direct self-cycle). Nodes
			// inherited FROM the nested group are tagged with THAT group's name:
			// tagNodesInherited above ran before this call, so it tags only the
			// outer group's own body and does not clobber the nested tags.
			if err := expandGroupsRecursive(&cloned, groups, ancestorPath, seen, memo, tagInherited, vars, depth+1, budget, haveExcept); err != nil {
				return err
			}
			expanded = cloned
		}

		// Cache a pristine copy of the completed expansion (even an empty one,
		// so a group with no matching context subtree is not re-walked), then
		// merge a SEPARATE clone into the parent so the cache is never mutated.
		memo[memoKey] = cloneNodes(expanded)
		if expanded != nil {
			if err := mergeNodes(nodes, expanded, ancestorPath, budget, name, vars, nil, haveExcept); err != nil {
				return err
			}
		}

		delete(seen, name)
	}

	// Remove apply-groups nodes.
	filtered := make([]*Node, 0, len(*nodes))
	for _, n := range *nodes {
		if n.Name() != "apply-groups" {
			filtered = append(filtered, n)
		}
	}
	*nodes = filtered

	// Recurse into children to handle nested apply-groups.
	for _, n := range *nodes {
		if !n.IsLeaf && len(n.Children) > 0 {
			childPath := make([][]string, len(ancestorPath)+1)
			copy(childPath, ancestorPath)
			childPath[len(ancestorPath)] = n.Keys
			// Descending the config TREE (not the nested-group chain), so depth
			// is unchanged — tree depth is already bounded by the parser
			// brace-depth cap (#4148). The shared work budget still applies.
			if err := expandGroupsRecursive(&n.Children, groups, childPath, seen, memo, tagInherited, vars, depth, budget, haveExcept); err != nil {
				return err
			}
		}
	}

	return nil
}

// mergeNodes merges src (apply-group) nodes into dst (inline stanza) at the
// schema level named by ancestorPath (the Keys path from root to this level,
// same convention expandGroupsRecursive threads for group context walking).
// For container nodes with matching keys, children are merged recursively.
//
// apply-groups inheritance is TYPED per Junos, not shape-based (#4070):
//   - LEAF-LIST statement (schema `multi:true && children==nil`, e.g.
//     name-server, policy `match application` / `source-address`, firewall
//     `from protocol`, routing export/import chains): the group's members are
//     inherited IN ADDITION to the inline members — UNION. Inline members keep
//     precedence and order; group members not already present are appended,
//     deduplicated. This holds across BOTH AST shapes (collapsed leaf and block
//     container) on either side, and yields exactly ONE node for the key.
//   - SCALAR leaf (host-name, ...): inline OVERRIDES the group value (the
//     explicit stanza wins via first-match ordering — unchanged).
//   - Unmodeled leaf (not resolvable in setSchema): OVERRIDE, the safe
//     non-regressing fallback (matches the incremental schema-coverage posture).
//
// Before #4070 the merge keyed on AST SHAPE — collapsed+collapsed OVERRODE,
// block+block UNIONED — so an inline `match application junos-http` that
// inherited a group's `match application junos-https` silently DROPPED
// junos-https (fable-164 L-8), narrowing a `then deny` to junos-http only.
// excluded accumulates the vars-resolved `apply-groups-except` names from this
// level and every ancestor level of THIS merge's descent (#9862): the
// exclusion reads "here and below", so an ancestor's exclusion filters the
// kept containers' children. Each call descends on its own copy
// (cloneExceptSet9862); sibling destinations never share the map. A fresh
// application from expandGroupsRecursive starts from nil — accumulation never
// crosses application boundaries, so an explicitly re-applied group below an
// exclusion still applies, exactly as #9422.
func mergeNodes(dst *[]*Node, src []*Node, ancestorPath [][]string, budget *groupExpandBudget, group string, vars map[string]string, excluded map[string]bool, haveExcept bool) error {
	// #9422: `apply-groups-except <group>` at THIS hierarchy level stops the
	// named group's inheritance here and below. Checking at every merge level
	// (rather than pre-pruning the group body once) is what makes it correct
	// for a `<*>` group key, whose one source subtree fans out into every
	// matching destination container — those containers may disagree about
	// whether they exclude the group, and the wildcard branch below recurses
	// into each with its OWN children as dst.
	//
	// #9862: the outer (merged) group keeps its veto EXACTLY. A veto at any
	// level prunes the descent, so membership in the accumulated set is
	// equivalent to the old per-level check — and nested contributors filter
	// per node below only when the outer application proceeds.
	level := excluded
	if haveExcept {
		level = collectExceptNames9862(*dst, vars, cloneExceptSet9862(excluded))
	}
	if level[group] {
		return nil
	}
	for _, s := range src {
		// #6767: one unit per source node MERGED, so a deep group subtree is
		// bounded by its own size rather than by the single reference that
		// pulled it in. Charged BEFORE the #9862 filter below: skipped nodes
		// cost their visit; only vetoed (unvisited) subtrees stay uncharged,
		// exactly as the #9422 vetoes. No charge line in this function moved.
		if err := budget.charge(1); err != nil {
			return err
		}
		// #9862: leaf filter for nested contributors. The outer group passed
		// its veto above, so this drops only nodes a nested exclusion names.
		// Leaves are atomic; containers route or adopt as shells when a
		// descendant survives. With no exclusions on the path this is one
		// length check per node.
		if contribExcluded9862(s, group, level) && (s.IsLeaf || !subtreeSurvives9862(s, group, level)) {
			continue
		}
		if s.IsLeaf {
			key := ""
			if len(s.Keys) > 0 {
				key = s.Keys[0]
			}
			// #9831: a group zone statement names ONE zone, so its inline peer is the
			// statement naming that zone, not any statement sharing the keyword.
			peer := leafListPeer(*dst, key)
			if groupZoneLeaf9831(ancestorPath, s) {
				peer = zoneGroupLeafPeer9831(ancestorPath, *dst, s)
			}
			if peer != nil {
				// #7648: a COMPACT group leaf whose key names a schema
				// CONTAINER, matched against a container peer, is the block
				// spelling wearing a leaf's shape. Expand it and merge, so the
				// two spellings of one group produce one outcome. The override
				// decision then happens one level down against the expanded
				// child, so an inline value still wins.
				if !peer.IsLeaf {
					if body := groupPackedLeafBody(ancestorPath, s); body != nil {
						// #9862: the synthesized body carries s's provenance, so a
						// nested group's packed leaf filters as nested below. The
						// fallback covers only the impossible untagged case.
						if haveExcept {
							contrib := s.fromGroups
							if len(contrib) == 0 {
								contrib = []string{group}
							}
							addNodeContrib9862(body, contrib)
						}
						if err := budget.charge(countNodes(body)); err != nil {
							return err
						}
						if err := mergeNodes(&peer.Children, body,
							appendPath(ancestorPath, peer.Keys), budget, group, vars, level, haveExcept); err != nil {
							return err
						}
						continue
					}
				}
				// A same-key node already exists inline. UNION when the
				// statement is a pure value-list leaf-list; otherwise OVERRIDE
				// (skip the group value — inline wins). Scalars, args>=2
				// multi-token leaves, groupReplace token-packed leaves, and
				// range-bearing leaves all take the override path.
				if leafListUnionEligible(ancestorPath, key, peer, s) {
					mergeLeafListInto(peer, s)
				} else if body, ok := promoteLeafPeerForPackedGroup9855(ancestorPath, peer, s); ok {
					// #9855: a PACKED group leaf naming the same instance as an
					// inline LEAF peer. Promoting the peer to its braced shape
					// and merging the expanded tail makes the two spellings of
					// one group produce one outcome; the override decision
					// happens one level down, so an inline value still wins.
					budget.notePromoted9855(peer)
					if err := budget.charge(countNodes(body)); err != nil {
						return err
					}
					if err := mergeNodes(&peer.Children, body,
						appendPath(ancestorPath, peer.Keys), budget, group, vars, level, haveExcept); err != nil {
						return err
					}
				} else if cpeer, cbody, ok := sameInstanceContainerPeer9855(ancestorPath, *dst, s); ok {
					// #9855: the leaf peer names another instance, but a
					// same-instance container (promoted earlier in this merge
					// or authored braced) is also present — merge there instead
					// of dropping the tail.
					if err := budget.charge(countNodes(cbody)); err != nil {
						return err
					}
					if err := mergeNodes(&cpeer.Children, cbody,
						appendPath(ancestorPath, cpeer.Keys), budget, group, vars, level, haveExcept); err != nil {
						return err
					}
				}
				continue
			}
			// #9855: no leaf peer, but a packed group leaf still merges into a
			// same-instance container — a peer this merge already promoted, or
			// an inline braced stanza. Without this a second packed leaf for
			// the instance adopts beside the first and twins the node. Zones,
			// value lists, and different instances keep the adopt below,
			// except that a successive leaf after a promotion is suppressed
			// as the base suppressed it (suppressSuccessiveLeaf9855).
			if cpeer, cbody, ok := sameInstanceContainerPeer9855(ancestorPath, *dst, s); ok {
				if err := budget.charge(countNodes(cbody)); err != nil {
					return err
				}
				if err := mergeNodes(&cpeer.Children, cbody,
					appendPath(ancestorPath, cpeer.Keys), budget, group, vars, level, haveExcept); err != nil {
					return err
				}
				continue
			}
			if suppressSuccessiveLeaf9855(budget, ancestorPath, *dst, s) {
				continue
			}
			// No inline value for this key: adopt the group leaf.
			*dst = append(*dst, s)
			continue
		}

		// Check if source keys contain wildcards (<*>).
		if keysContainWildcard(s.Keys) {
			// Wildcard merge: apply to all matching containers in dst.
			for _, d := range *dst {
				if keysMatchWildcard(d.Keys, s.Keys) && (!d.IsLeaf || zoneLeafTakesWildcard9801(ancestorPath, d)) {
					// #9801: a zone written as a leaf becomes the empty container its
					// braced spelling is, and takes the group the same way.
					// #9862: when filtering is active the flip waits for an
					// adoption (growth-detect): an all-filtered merge must not
					// reshape the leaf it adds nothing to. mergeNodes only
					// appends, so growth is exactly adoption. Unconditional
					// when filtering is off, exactly as before.
					leafKids := -1
					if haveExcept {
						leafKids = len(d.Children)
					} else {
						d.IsLeaf = false
					}
					// #6767: THIS is the fan-out. One wildcard source is cloned
					// into every matching destination container, so the cost is
					// the product, not the reference count. Charge the clone's
					// size BEFORE materialising it.
					if err := budget.charge(countNodes(s.Children)); err != nil {
						return err
					}
					cloned := cloneNodes(s.Children)
					if err := mergeNodes(&d.Children, cloned, appendPath(ancestorPath, d.Keys), budget, group, vars, level, haveExcept); err != nil {
						return err
					}
					if haveExcept && len(d.Children) > leafKids {
						d.IsLeaf = false
					}
				}
			}
			continue
		}

		// A single-key group container that the schema classifies as a
		// leaf-list is the BLOCK shape of a leaf-list ("name-server { 1; 2; }").
		// UNION its members into an existing inline leaf-list (either shape),
		// rather than recursing as a real hierarchical container. Multi-key
		// containers (["family","inet"]) are never leaf-lists.
		if len(s.Keys) == 1 && isLeafListSchema(ancestorPath, s.Keys[0]) {
			if peer := leafListPeer(*dst, s.Keys[0]); peer != nil {
				if leafListUnionEligible(ancestorPath, s.Keys[0], peer, s) {
					mergeLeafListInto(peer, s)
				}
				// else OVERRIDE: a range-bearing inline peer wins, group block
				// dropped (a groupReplace leaf never reaches here — its
				// isLeafListSchema is false, so it takes the container path).
			} else {
				*dst = append(*dst, s)
			}
			continue
		}

		// #9422: a same-keyed destination container excludes the group. Checked
		// across ALL same-keyed siblings, not only the one this merge would
		// descend into, because a level spread over two blocks
		// (`system {...} system { apply-groups-except G; ... }`) is one
		// hierarchy level to the operator and to the compiler.
		//
		// #9862: the sibling scan becomes a union scope for the descent below.
		// Veto-if-outer is exactly the old check (the entry veto already passed,
		// so the outer name can only come from the union); nested contributors
		// then filter against the level's whole union, since same-keyed twins
		// are ONE level. Only plain containers consult siblings — leaves,
		// wildcards, and leaf-list blocks keep their entry-level check alone,
		// exactly as before.
		scope := level
		if haveExcept {
			scope = collectSiblingExceptNames9862(*dst, s.Keys, vars, cloneExceptSet9862(level))
		}
		if scope[group] {
			continue
		}
		if contribExcluded9862(s, group, scope) && !subtreeSurvives9862(s, group, scope) {
			continue
		}

		// Container node: find matching containers in dst.
		//
		// #9802: a level spread over two blocks is ONE level. Merging into the
		// first same-keyed container and stopping sent a group body to a
		// stanza that could not receive it, and left the stanza that could
		// without the group. The wildcard-keyed children go to every
		// same-keyed container, because each may hold different instances;
		// the rest go to the one that can receive them.
		found := false
		if targets := sameKeyedContainers9802(*dst, s.Keys); len(targets) > 0 {
			wild, rest := splitWildcardChildren9802(s.Children)
			// #9802 follow-up: route EACH concrete child to the stanza that can
			// receive it. Bundling them sent a body carrying `screen` and
			// `zones` to whichever stanza matched first, and the other stanza
			// never saw the group: measured, `trust.ScreenProfile` went from
			// `edge` to empty.
			for _, c := range rest {
				d := receivingContainer9802(targets, c)
				if err := mergeNodes(&d.Children, []*Node{c}, appendPath(ancestorPath, d.Keys), budget, group, vars, scope, haveExcept); err != nil {
					return err
				}
			}
			for _, d := range targets {
				if len(wild) == 0 {
					break
				}
				// #6767: one clone per destination, charged before it is made,
				// exactly as the wildcard branch charges its fan-out.
				if err := budget.charge(countNodes(wild)); err != nil {
					return err
				}
				cloned := cloneNodes(wild)
				if err := mergeNodes(&d.Children, cloned, appendPath(ancestorPath, d.Keys), budget, group, vars, scope, haveExcept); err != nil {
					return err
				}
			}
			found = true
		}
		if !found {
			// Cross-shape guard (#4325): a single-key group container whose
			// leaf-list counterpart exists inline as a collapsed leaf sharing
			// Keys[0]. Leaf-list keys are handled by the union path above, so
			// this now only fires for a single-key container NOT modeled as a
			// leaf-list — keep the no-duplicate invariant (skip rather than
			// append a second node for the same key).
			if len(s.Keys) == 1 && hasMatchingLeaf(*dst, s.Keys) {
				continue
			}
			// #9802: the adopted subtree is never recursed into, so a
			// wildcard-keyed INSTANCE inside it would land in the tree as a
			// literal name — the #9423 phantom, reached by the route that
			// issue's fixtures cannot take. It matched nothing by
			// construction, so drop it; a member-slot wildcard is left alone
			// and stays refused. Pruned BEFORE the charge below, so the budget
			// counts what is actually added.
			hadChildren := len(s.Children) > 0
			s.Children = pruneWildcardInstances9802(appendPath(ancestorPath, s.Keys), s.Children)
			// #9862: the adopted subtree is never recursed into either, so
			// excluded nested contributors inside it would ride along. Pruned
			// recursively AFTER the wildcard prune (the two commute) and
			// BEFORE the charge below, so the budget counts what lands.
			// No-op when the scope is empty.
			wildLeft := len(s.Children)
			s.Children = pruneExcluded9862(s.Children, group, scope)
			if wildcardInstanceNode9802(ancestorPath, s) {
				continue
			}
			// A container whose whole body was wildcard-keyed adds nothing:
			// adopting it would leave an empty stanza the operator never wrote.
			// A body emptied by the exclusion filter is different: the shell
			// is independently authored (clean own provenance), so it is
			// preserved — only an excluded shell with nothing surviving drops.
			if hadChildren && len(s.Children) == 0 && (wildLeft == 0 || contribExcluded9862(s, group, scope)) {
				continue
			}
			// #6767: adopting a container WHOLESALE adds its entire subtree to
			// the AST without recursing into it, so the per-node charge above
			// never sees those nodes — a group carrying a million-node subtree
			// merged into a non-matching parent cost ONE unit. Charge the
			// subtree it actually adds. (The node itself was charged on entry,
			// hence -1.)
			if err := budget.charge(countNodes([]*Node{s}) - 1); err != nil {
				return err
			}
			*dst = append(*dst, s)
		}
	}
	return nil
}

// appendPath returns a fresh copy of base with keys appended, so recursive
// mergeNodes calls never alias or clobber a shared ancestorPath backing array.
func appendPath(base [][]string, keys []string) [][]string {
	out := make([][]string, len(base)+1)
	copy(out, base)
	out[len(base)] = keys
	return out
}

// schemaAtAncestorPath resolves the schema node addressed by an ancestor path,
// or nil when the path is not modelled. Extracted from isLeafListSchema so the
// #7648 packed-leaf expansion can reach the same context without duplicating
// the compoundKey descent.
func schemaAtAncestorPath(ancestorPath [][]string) *schemaNode {
	schema := setSchema
	for _, pk := range ancestorPath {
		if schema == nil || len(pk) == 0 {
			return nil
		}
		child := resolveSchemaChild(schema, pk[0])
		if child == nil {
			return nil
		}
		// consumeNodeKeys descends a compoundKey sub-token (family inet6) so
		// the leaf lookup lands at the correct level; args/midKeyword tokens
		// are identity values that do not change the schema level.
		_, child = consumeNodeKeys(pk, child)
		schema = child
	}
	return schema
}

// groupPackedLeafBody expands a group's COMPACT leaf into the children its
// BLOCK spelling would have produced, or nil when it carries no expandable
// tail (#7648).
//
// A group node carrying its body on `Keys` --
// `authentication-sha256 authentication-password "groupsecret"` -- is
// classified IsLeaf, so it took the leaf path and was OVERRIDDEN whenever a
// same-name node already existed inline. The BLOCK spelling of the same group
// is a container and merged correctly. Two spellings of one intent, opposite
// outcomes.
//
// Expanding lets the SAME override logic run one level down, which is what
// makes this correct rather than merely different:
//
//   - local `authentication-sha256 { }` (empty) -- no peer for the expanded
//     child, so the group's value is adopted. That is the case that was
//     silently dropped.
//   - local `authentication-sha256 { authentication-password "local"; }` --
//     the expanded child finds a peer and the ordinary apply-groups OVERRIDE
//     applies, so INLINE STILL WINS. The fix does not weaken that.
//
// Returns nil unless the tail actually expands under the schema, so an
// unmodelled or genuinely scalar leaf keeps its existing override behaviour.
func groupPackedLeafBody(ancestorPath [][]string, s *Node) []*Node {
	if s == nil || len(s.Keys) < 2 {
		return nil
	}
	parent := schemaAtAncestorPath(ancestorPath)
	if parent == nil {
		return nil
	}
	leafSchema := resolveSchemaChild(parent, s.Keys[0])
	if leafSchema == nil || leafSchema.children == nil {
		// Not a container in the schema: a real scalar leaf, whose override
		// semantics are correct as they stand.
		return nil
	}
	expanded := packedBodyChildren(s, leafSchema)
	// packedBodyChildren returns s.Children unchanged when there is no tail to
	// expand; that is the not-applicable case.
	if len(expanded) == 0 || (len(expanded) == 1 && expanded[0] == s) {
		return nil
	}
	return expanded
}

// leafListPeer returns the first dst node that expresses the leaf-list keyed
// by key — either a COLLAPSED leaf ("name-server 9.9.9.9") or a single-key
// BLOCK container ("name-server { 9.9.9.9; }"). It mirrors hasMatchingLeaf's
// match rule so union and override agree on what counts as "the same key".
func leafListPeer(dst []*Node, key string) *Node {
	if key == "" {
		return nil
	}
	for _, n := range dst {
		if len(n.Keys) == 0 || n.Keys[0] != key {
			continue
		}
		if n.IsLeaf || len(n.Keys) == 1 {
			return n
		}
	}
	return nil
}

// mergeLeafListInto unions the members of a group leaf-list node src into an
// existing inline leaf-list node dst. Members are read across both AST shapes
// (Keys[1:] AND child leaves), with their quote provenance. Inline members keep
// their position; group members not already present are appended in group
// order, deduplicated. The dst node's shape is preserved -- a collapsed leaf
// grows on Keys, a block container gains one child leaf per added member -- so
// the result is exactly ONE node for the key regardless of the two inputs'
// shapes.
//
// #9627: an UNQUOTED repeat of the leaf's own keyword in src is the ambiguous
// #9027 shape, and it is carried onto dst's Keys whatever dst's shape, never
// deduplicated. The #9027 gate runs on this merged tree and scans Keys, so it
// refuses the run (strict) or warns (lenient) exactly as it does for the same
// run authored inline, or inherited with no inline leaf. The union used to read
// src through firewallMatchValues, which DROPS that token, so a group's
// ambiguous run was silently resolved -- and hidden from the gate -- whenever an
// inline leaf of the same name existed. A QUOTED repeat is an ordinary member.
func mergeLeafListInto(dst, src *Node) {
	// #9862: a tagged dst is a group body being merged into (inner merge) or
	// a previously merged node (outer merge), so this union can mix members
	// across groups and the node's provenance is uncertain afterwards.
	// Cleared: filters then fall back to the merge's outer group, which keeps
	// the node unless the outer application is itself vetoed. Keeping either
	// side's tag would over-exclude the other side's members; member-level
	// provenance is a follow-up. The clearing is load-bearing only for inner
	// merges (whose product becomes outer src); on outer dst it is harmless
	// because dst-side tags are never consulted. Deliberately unconditional
	// (no haveExcept here): untagged trees clear nothing.
	if dst.fromGroups != nil {
		dst.fromGroups = nil
	}
	self := dst.Keys[0]
	seen := make(map[string]bool)
	for _, m := range leafListMembers9627(dst) {
		if m.value != self || m.quoted {
			seen[m.value] = true
		}
	}
	for _, m := range leafListMembers9627(src) {
		if m.value == self && !m.quoted {
			dst.Keys = append(dst.Keys, m.value)
			appendKeyQuoted9627(dst, false)
			continue
		}
		if seen[m.value] {
			// #9862: the duplicate is owned by BOTH sides. Record src's
			// ownership on the surviving member so excluding one owner
			// keeps the member for the other (never over-excludes).
			mergeLeafListDupOwnership9862(dst, src, m.value)
			continue
		}
		seen[m.value] = true
		if dst.IsLeaf {
			dst.Keys = append(dst.Keys, m.value)
			appendKeyQuoted9627(dst, m.quoted)
		} else {
			child := &Node{
				Keys:          []string{m.value},
				IsLeaf:        true,
				InheritedFrom: src.InheritedFrom,
			}
			if m.quoted {
				child.KeysQuoted = []bool{true}
			}
			dst.Children = append(dst.Children, child)
		}
	}
}

// leafListMember9627 is one member of a leaf-list node, with the quote its own
// authoring gave it.
type leafListMember9627 struct {
	value  string
	quoted bool
}

// leafListMembers9627 reads a leaf-list node's members across both AST shapes.
// Unlike firewallMatchValues it KEEPS a repeat of the leaf's own keyword: the
// union must not decide the #9027 ambiguity on the gate's behalf (#9627).
func leafListMembers9627(n *Node) []leafListMember9627 {
	var out []leafListMember9627
	for i := 1; i < len(n.Keys); i++ {
		if n.Keys[i] != "" {
			out = append(out, leafListMember9627{value: n.Keys[i], quoted: n.KeyQuoted(i)})
		}
	}
	for _, vn := range n.Children {
		for i, k := range vn.Keys {
			if k != "" {
				out = append(out, leafListMember9627{value: k, quoted: vn.KeyQuoted(i)})
			}
		}
	}
	return out
}

// appendKeyQuoted9627 records the quote of the member just appended to n.Keys,
// keeping the mask invariant (nil, or one bit per key). A group member keeps the
// quote its own authoring gave it: that is its provenance, and #6673's rule is
// only that the union never MINTS a quote a value did not have.
func appendKeyQuoted9627(n *Node, quoted bool) {
	switch {
	case len(n.KeysQuoted) == len(n.Keys)-1:
		n.KeysQuoted = append(n.KeysQuoted, quoted)
	case quoted && len(n.KeysQuoted) == 0:
		n.KeysQuoted = make([]bool, len(n.Keys))
		n.KeysQuoted[len(n.Keys)-1] = true
	}
}

// isLeafListSchema reports whether the leaf keyword key, resolved under the
// schema context ancestorPath, is a PURE single-token Junos leaf-list whose
// group + inline members UNION under apply-groups inheritance (#4070): a
// multi-value leaf that models no sub-structure, carries exactly one value
// token per member, and is not opted out. A scalar leaf, an args>=2 multi leaf
// (multi-token members), or a groupReplace leaf overrides instead. Returns
// false when the path or keyword is not modeled in setSchema, so an unmodeled
// leaf safely keeps the legacy override behavior.
//
// The gate is `multi:true && children==nil && args<=1 && !groupReplace`:
//   - multi + children==nil: the leaf-list discriminator (children==nil
//     excludes multi nodes carrying modifier sub-structure — CoS named
//     containers, static `next-hop [ a b ] { interface x; }`).
//   - args<=1: each member is a SINGLE token (application, source-address,
//     protocol, name-server, from community/as-path, export chains). An
//     args>=2 multi leaf packs multiple tokens per member (route-filter
//     `<prefix> <match-type>`, address-book `address <name> <prefix>`,
//     as-path `<name> <regex>`, CoS `queue <n> <class>`); token-level union
//     would mash the member tokens together, so it OVERRIDEs instead.
//   - !groupReplace: a token-packed args<=1 leaf that packs a SEPARATOR or
//     OPERATION keyword (port range `3000 to 4000`, `then community
//     add|set|delete|none`, `then as-path-prepend`) is explicitly opted out
//     (see the schemaNode.groupReplace doc) — union/dedup would corrupt it.
func isLeafListSchema(ancestorPath [][]string, key string) bool {
	schema := setSchema
	for _, pk := range ancestorPath {
		if schema == nil || len(pk) == 0 {
			return false
		}
		child := resolveSchemaChild(schema, pk[0])
		if child == nil {
			return false
		}
		// consumeNodeKeys descends a compoundKey sub-token (family inet6) so
		// the leaf lookup lands at the correct level; args/midKeyword tokens
		// are identity values that do not change the schema level.
		_, child = consumeNodeKeys(pk, child)
		schema = child
	}
	if schema == nil {
		return false
	}
	leaf := resolveSchemaChild(schema, key)
	return leaf != nil && leaf.multi && leaf.children == nil &&
		leaf.args <= 1 && !leaf.groupReplace
}

// leafListUnionEligible reports whether a group leaf-list node src should UNION
// into an existing inline node dst (both share Keys[0]==key at schema context
// ancestorPath), versus fall back to apply-groups OVERRIDE. Union requires the
// schema to classify key as a pure single-token value-list (isLeafListSchema)
// AND neither side to carry a range separator. A range like `3000 to 4000`
// packs the `to` separator onto the value list, so token-level union/dedup
// would corrupt it (a discard/reject port term would fail OPEN). The range
// check is a defensive net for any range-bearing leaf not explicitly marked
// groupReplace; the known port leaves already set the flag.
func leafListUnionEligible(ancestorPath [][]string, key string, dst, src *Node) bool {
	if !isLeafListSchema(ancestorPath, key) {
		return false
	}
	return !leafListCarriesRange(dst) && !leafListCarriesRange(src)
}

// leafListCarriesRange reports whether a leaf-list node packs a Junos range
// separator ("to", as in a port range `3000 to 4000`) onto its value list.
// Such a leaf is a range, not a set — union/dedup would corrupt it.
func leafListCarriesRange(n *Node) bool {
	for _, v := range firewallMatchValues(n) {
		if v == "to" {
			return true
		}
	}
	return false
}

// keysContainWildcard returns true if any key is the Junos wildcard "<*>".
func keysContainWildcard(keys []string) bool {
	for _, k := range keys {
		// #9423: ANY `<...>`-shaped key, not only the bare `<*>`. Recognising
		// only `<*>` sent `<ge-*>` down the ordinary container path, where a
		// key with no destination is ADOPTED — the compiled config gained an
		// interface literally named `<ge-*>`. Taking the wildcard branch is
		// what makes a non-matching pattern apply nothing instead.
		if _, ok := groupKeyPattern(k); ok {
			return true
		}
	}
	return false
}

// keysMatchWildcard checks if dst keys match src keys, where a `<...>` src key
// is a glob PATTERN matched against the dst key (#9423; `<*>` is the universal
// case of it). Both slices must have the same length.
func keysMatchWildcard(dst, src []string) bool {
	if len(dst) != len(src) {
		return false
	}
	for i := range src {
		if pat, ok := groupKeyPattern(src[i]); ok {
			if !globMatch(pat, dst[i]) {
				return false
			}
			continue
		}
		if src[i] != dst[i] {
			return false
		}
	}
	return true
}

// hasMatchingLeaf returns true if nodes contains a leaf whose first key
// matches. This prevents group values from overriding explicit config
// (e.g., if "host-name explicit" already exists, "host-name group" is skipped).
//
// It ALSO matches a single-key CONTAINER whose Keys[0] equals keys[0]
// (#4070). A leaf-list can be expressed either as a collapsed leaf
// ("name-server 1.1.1.1 2.2.2.2", Keys[0]=="name-server") or as a block
// container ("name-server { 1.1.1.1; 2.2.2.2; }", Keys==["name-server"]).
// Recognizing the block container here lets a collapsed group leaf and an
// existing block stanza (or vice versa) be treated as the SAME leaf-list
// instead of emitting both a leaf AND a container for one key. Only
// single-key containers cross-match: multi-key containers (e.g.
// ["family","inet"]) are real hierarchical nodes, never leaf-lists, and a
// leaf sharing only Keys[0] must not be confused with them.
func hasMatchingLeaf(nodes []*Node, keys []string) bool {
	if len(keys) == 0 {
		return false
	}
	for _, n := range nodes {
		if len(n.Keys) == 0 || n.Keys[0] != keys[0] {
			continue
		}
		if n.IsLeaf {
			return true
		}
		if len(n.Keys) == 1 {
			return true
		}
	}
	return false
}
