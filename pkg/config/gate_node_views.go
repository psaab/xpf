package config

import "fmt"

// gateNodeViewOpts selects how effectiveNodeViews expands a candidate tree
// for the pre-walk gates (#17222).
//
// Tagged selects the ExpandGroups*Tagged expansion (provenance marking for
// "| display inheritance"-sensitive gates: scheduler window pairs, reth
// LAG). The default is the plain expansion every other gate used.
//
// ExpandRanges additionally runs expandInterfaceRanges on each expanded
// view, so interface-range / wildcard members are seen exactly as the real
// compile path sees them. Gates that must NOT see range-expanded members
// (the login gates read system/login, where ranges are meaningless) leave
// it off.
//
// Fallback: when Fallback is set and NEITHER per-node expansion succeeds,
// effectiveNodeViews appends the tree ExpandGroupsNodeFallback15031 would
// compile for the generic (standalone) commit — the plain/${node}->node0
// expansion, or, when a group is literally named "${node}", the raw tree
// the plain expansion compiles as-is. That is the tree the standalone
// store's CompileConfigWithCurrentClusterPrimary compiles, so a gate
// inspecting it sees exactly the offending stanza the compiler compiles
// instead of contributing nothing (#13146, #17222). When either node view
// expands, no fallback view is added: the generic compile of such a tree
// lands the node0 (or literal) expansion, already covered by a node view.
//
// Gates that keep their own View-1 pre-expansion union (zone, tunnel,
// routing-instance, unit-alias, dup-name, bridge-domain, reth-LAG) leave
// Fallback unset: their View 1 already covers a name inside an
// un-expandable group, and adding the generic view would only duplicate it.
type gateNodeViewOpts struct {
	Tagged       bool
	ExpandRanges bool
	Fallback     bool
}

// effectiveNodeViews returns the effective views of tree a pre-walk gate
// must inspect (#17222): the candidate expanded for chassis-cluster node0
// and for node1, plus — when opts.Fallback is set and neither expands —
// the generic-compile fallback tree described on gateNodeViewOpts.
//
// It is the single source of truth for the per-cluster-node gate prologue
// previously hand-copied into ten gate files, of which only two received
// the #13146 raw-tree fallback: a literal `groups "${node}"` defeated the
// other copies' per-node expansions, so gates such as QinQ (#5879),
// packed-login (#6662) and login-class-shadow (#6701) silently inspected
// nothing on a strict standalone commit while the compiler compiled the
// raw tree. Every gate now goes through here, so the next expansion-shape
// fix lands in one place.
//
// Recursion-free by construction: it clones, expands groups, optionally
// expands interface ranges, and hands back trees for the caller to read —
// it never calls CompileConfig* (which would re-enter the calling gate).
// A per-node expansion error contributes no view for that node (a config
// defining only `groups node1` + `${node}` cannot expand for node0, and
// the real per-node compile already rejects that on the affected node);
// the OTHER node's view still applies. Both views are computed on both
// nodes regardless of which node commits, so a gate's verdict stays a
// pure function of the candidate (HA symmetry).
func effectiveNodeViews(tree *ConfigTree, opts gateNodeViewOpts) []*ConfigTree {
	if tree == nil {
		return nil
	}
	views := make([]*ConfigTree, 0, 3)
	for _, nodeID := range []int{0, 1} {
		if view := gateExpandedForNode(tree, nodeID, opts.Tagged); view != nil {
			if opts.ExpandRanges {
				// expandInterfaceRanges mutates the clone in place; its
				// warnings are emitted on the real path and discarded here.
				// #8438: the clone paths only need the budget SKIP (the
				// expansion is capped inside); the rejection is surfaced
				// once, by the prewalk caller.
				_, _ = expandInterfaceRanges(view)
			}
			views = append(views, view)
		}
	}
	if opts.Fallback && len(views) == 0 {
		if view := gateGenericView(tree, opts.Tagged); view != nil {
			views = append(views, view)
		}
	}
	return views
}

// gateNodeView returns the candidate expanded for one chassis-cluster node
// (nodeID may be any integer, e.g. a compiledNode other than 0/1 whose own
// `node%d` groups a node compile lands), or nil when that node's expansion
// fails. It never falls back: the generic fallback is a property of the
// node0+node1 pair, decided once by effectiveNodeViews /
// effectiveNodeViewsForNodes.
func gateNodeView(tree *ConfigTree, nodeID int, tagged bool) *ConfigTree {
	if tree == nil {
		return nil
	}
	return gateExpandedForNode(tree, nodeID, tagged)
}

// effectiveNodeViewsForNodes is effectiveNodeViews for callers that also
// fold in the view of a compile for an arbitrary node id (compiledNode,
// e.g. routing-instance and bridge-domain name unions): the generic view
// first when fallback is set and it expands, then node0, node1, and the
// compiled node's own view when it is not 0/1.
//
// The generic slot is the caller's own pre-existing view (an atomic
// ExpandGroupsNodeFallback15031 expansion), NOT the only-when-neither-
// expands fallback: those unions always inspected it, and folding it into
// the shared helper keeps exactly one expansion prologue. Callers pass
// fallback=false when they have no generic view.
func effectiveNodeViewsForNodes(tree *ConfigTree, compiledNode *int, tagged, fallback bool) []*ConfigTree {
	if tree == nil {
		return nil
	}
	var views []*ConfigTree
	if fallback {
		if view := gateGenericView(tree, tagged); view != nil {
			views = append(views, view)
		}
	}
	views = append(views, effectiveNodeViews(tree, gateNodeViewOpts{Tagged: tagged})...)
	if compiledNode != nil && *compiledNode != 0 && *compiledNode != 1 {
		if view := gateNodeView(tree, *compiledNode, tagged); view != nil {
			views = append(views, view)
		}
	}
	return views
}

// gateExpandedForNode clones tree and expands its groups under the
// `${node}` -> node<nodeID> binding, tagged when asked. Nil on error.
func gateExpandedForNode(tree *ConfigTree, nodeID int, tagged bool) *ConfigTree {
	clone := tree.Clone()
	vars := map[string]string{"node": fmt.Sprintf("node%d", nodeID)}
	var err error
	if tagged {
		err = clone.ExpandGroupsWithVarsTagged(vars)
	} else {
		err = clone.ExpandGroupsWithVars(vars)
	}
	if err != nil {
		return nil
	}
	return clone
}

// gateGenericView clones tree and expands it exactly as the generic
// compile does (ExpandGroupsNodeFallback15031: one atomic pass, plain or
// ${node}->node0, never a retry on a partially merged clone). Nil on error.
func gateGenericView(tree *ConfigTree, tagged bool) *ConfigTree {
	clone := tree.Clone()
	if _, err := clone.ExpandGroupsNodeFallback15031(tagged); err != nil {
		return nil
	}
	return clone
}

// interfaceUnitsOf returns an interface node's units the way
// compileInterfaces enumerates them: a packed instance tail on the
// interface line (`ge-0/0/0 bandwidth 1g unit 0 ...`) is expanded via
// packedBody first, then both the hierarchical (`unit { 0 { ... } }`) and
// flat spellings are enumerated via namedInstances (#14436, #14683,
// #17222). All three VLAN collectors (QinQ, vlan-map, vlan-id/tagging)
// use this so a packed-tail fix cannot reach only some of them again.
func interfaceUnitsOf(iface *Node) []struct {
	name string
	node *Node
} {
	if iface == nil {
		return nil
	}
	body := packedBody(iface, interfaceSchema9792())
	if body == nil {
		body = iface
	}
	return namedInstances(body.FindChildren("unit"))
}
