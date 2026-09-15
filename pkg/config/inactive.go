package config

// Junos `inactive:` statement support (#2008 H1).
//
// An operator deactivates a configuration node without deleting it by
// prefixing the statement with `inactive:`. The node stays in the
// configuration database — it displays in `show configuration`, survives
// commit and reboot, syncs to the HA peer, and can be re-enabled — but it
// is EXCLUDED from compilation/application: the firewall behaves as if the
// statement were absent.
//
// The parser lifts the `inactive:` marker into Node.Inactive (parser.go)
// so the node's identity (Keys) is unchanged and every key match, schema
// walk, and group merge keeps working on the real keys. This file provides
// the single centralized strip that prunes inactive subtrees before the
// compiler and the typed-leaf schema gate run, so neither of those layers
// ever observes an inactive node and none of the ~15 compiler files change.
//
// Strip runs on a CLONE before group expansion (see the compile entry
// points in compiler.go and schemaValidateExpandedTreeForNode in
// configstore/store.go — both strip BEFORE ExpandGroups, which collects
// apply-groups nodes by name without checking Inactive), so an
// `inactive: apply-groups foo` correctly suppresses the inherited config and
// an inactive node inside a `groups {}` body is pruned consistently.
//
// Strip only REMOVES nodes from the compiled set, but that does NOT
// guarantee a previously-compiling config stays compilable: deactivating a
// REFERENCED definition (e.g. an address-book entry a policy still matches,
// or a group an active apply-groups still applies) can leave that active
// reference dangling and surface a dangling-reference commit error. That is
// correct and expected — deactivating an object an active statement depends
// on is operator intent — and the schema gate enforces it for schema
// cross-references and policy address references (the active reference is
// validated against the inactive-stripped definitions source).

// HasInactiveNodes reports whether the tree contains any node (at any
// depth) marked inactive. Used to skip the strip clone on the common
// all-active path.
func (t *ConfigTree) HasInactiveNodes() bool {
	if t == nil {
		return false
	}
	return nodesHaveInactive(t.Children)
}

func nodesHaveInactive(nodes []*Node) bool {
	for _, n := range nodes {
		if n == nil {
			continue
		}
		if n.Inactive {
			return true
		}
		if nodesHaveInactive(n.Children) {
			return true
		}
	}
	return false
}

// WithoutInactive returns a deep copy of the tree with every inactive
// subtree pruned. When the tree contains no inactive nodes it returns the
// receiver unchanged (no clone) so the common path allocates nothing extra.
// The result is safe to mutate (it is a fresh clone whenever a prune
// happened); callers that further mutate the tree (group expansion) must
// not rely on aliasing with the receiver — they already Clone() first on
// the all-active path.
func (t *ConfigTree) WithoutInactive() *ConfigTree {
	if t == nil {
		return nil
	}
	if !t.HasInactiveNodes() {
		return t
	}
	return &ConfigTree{Children: stripInactiveNodes(t.Children)}
}

// cloneForExpansion returns a deep, freely-mutable copy of t with inactive
// subtrees pruned, doing exactly ONE deep copy. WithoutInactive already returns
// a fresh clone when it prunes (reused here), so only the all-active path —
// where WithoutInactive returns the receiver — needs an explicit Clone. The
// result NEVER aliases t, so a caller that expands groups in place on it cannot
// mutate the caller's tree (which must retain groups/apply-groups nodes for
// `show configuration`). This avoids the double deep-copy of
// t.WithoutInactive().Clone() on the has-inactive path.
func (t *ConfigTree) cloneForExpansion() *ConfigTree {
	if t == nil {
		return nil
	}
	if stripped := t.WithoutInactive(); stripped != t {
		return stripped // already a fresh prune-clone, safe to mutate in place
	}
	return t.Clone()
}

// stripInactiveNodes returns a deep copy of nodes with inactive subtrees
// removed. Active container nodes are cloned and recursively pruned.
func stripInactiveNodes(nodes []*Node) []*Node {
	if nodes == nil {
		return nil
	}
	result := make([]*Node, 0, len(nodes))
	for _, n := range nodes {
		if n == nil || n.Inactive {
			continue
		}
		clone := &Node{
			Keys: append([]string(nil), n.Keys...),
			// #6673: WithoutInactive runs on the cloned tree BEFORE compile, so
			// this is the copy the compiler reads. Dropping the per-key quote
			// provenance here would blind every reader downstream of it.
			KeysQuoted: append([]bool(nil), n.KeysQuoted...),
			// #6668: same reasoning for the bracket provenance — this clone is
			// what SchemaValidate walks and what a re-render of the stripped
			// tree would flatten, so dropping it here loses the one bit that
			// says where a container's key group ends.
			KeysBracketed: append([]bool(nil), n.KeysBracketed...),
			Children:      stripInactiveNodes(n.Children),
			IsLeaf:        n.IsLeaf,
			Annotation:    n.Annotation,
			InheritedFrom: n.InheritedFrom,
			// #9862: the strip runs before expansion today, so this is latent — but
			// dropping it here would repeat the #6673 provenance-drop class the
			// moment any flow expands first and strips second.
			fromGroups: append([]string(nil), n.fromGroups...),
			Inactive:   false,
			Line:       n.Line,
			Column:     n.Column,
		}
		result = append(result, clone)
	}
	return result
}
