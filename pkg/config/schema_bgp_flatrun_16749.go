package config

import (
	"strings"
)

// #16749: a valueless BGP flag (`passive`, `remove-private`,
// `log-updown`, and their peers) is a childless untyped leaf, so neither
// the typed-leaf branch nor the scalar branch of walkSchemaNode ever
// looks at its children. SetPath nests a flat-set run under it
// (`set protocols bgp group G passive hold-time 1` ->
// passive{hold-time 1}), the hierarchical parser does the same for
// `passive { hold-time 1; }`, and the BGP compilers then hoist the
// chained child back to the parent container via
// expandFlatRun/flattenChainedChildren (compiler_protocols.go bgp top
// and group, compiler_bgp_neighbor_merge_9192.go neighbor) and APPLY
// it. A chained `hold-time 1` therefore reached the renderer as
// HoldTime=1 -> `timers 1 1`, which bgpd refuses; frr-reload.py exited
// 1 and every later reload reported ErrFRRReloadDegraded (#14585).
// Chained unknown keywords were likewise invisible to the #10707
// advisory walker, which `continue`s at a childless leaf.
//
// Fix: when such a flag has children inside a container whose compiler
// expands flat runs (BGP top, group, neighbor — in the default
// instance and, by shared pointer, routing instances), validate the
// children at the PARENT schema exactly as the expanded compiler view
// would see them. A chained child that resolves at the parent is
// re-validated there, so its own typed validator (ValidateBGPHoldTime,
// the refused authentication-key-chain/algorithm stubs, ...) fires
// with the separate-line message; a chained child that does not
// resolve is an unknown keyword, which the strict walker leaves to
// the #10707 advisory (warnUnknownRoutingLeaves10707 also descends
// into these flags now) rather than hard-rejecting, matching the
// open-world contract of the BGP subtree.

// bgpFlatRunContainers16749 maps each BGP container schema whose
// compiler expands flat runs to nothing — membership is the test. The
// schemas are shared by pointer between the default instance and
// routing instances (schemaRoutingInstanceProtocols), so pointer
// identity covers both.
func bgpFlatRunContainers16749() map[*schemaNode]bool {
	return map[*schemaNode]bool{
		bgpLeafSchema8939():      true,
		bgpGroupSchema9181():     true,
		bgpNeighborSchema9792():  true,
	}
}

var bgpFlatRunContainerSet16749 = bgpFlatRunContainers16749()

// isBGPFlatRunContainer16749 reports whether parent is a BGP container
// whose compiler hoists chained children of a valueless flag back into
// the container (expandFlatRun / flattenChainedChildren).
func isBGPFlatRunContainer16749(parent *schemaNode) bool {
	return parent != nil && bgpFlatRunContainerSet16749[parent]
}

// isValuelessFlag16749 reports whether n is a childless, valueless
// leaf: no children, no wildcard, no value arity, not multi, and no
// validator of any kind — the admission-head shape of #9156. Such a
// leaf can legitimately carry nothing beneath it; anything nested
// under it arrived via a flat-set chain or a braced block and belongs
// to the parent container.
func isValuelessFlag16749(n *schemaNode) bool {
	return n != nil &&
		len(n.children) == 0 && n.wildcard == nil &&
		n.args == 0 && !n.multi &&
		!n.isTypedLeaf() && !n.isScalarValueLeaf() &&
		n.validator == nil && n.treeValidator == nil &&
		n.nodeValidator == nil && n.tailValidator == nil
}

// validateChainedUnderFlag16749 validates node.Children of a valueless
// flag at the PARENT container schema — the same expansion the BGP
// compilers apply. Children resolving at the parent are walked there
// (recursively, so a chained flag carrying a further chain is also
// expanded); unresolvable children are skipped here and reported by
// the #10707 advisory walker instead.
func validateChainedUnderFlag16749(node *Node, parent *schemaNode, path []string, vc *walkContext, closed bool) error {
	for _, c := range node.Children {
		if c == nil || len(c.Keys) == 0 {
			continue
		}
		if resolveSchemaChild(parent, c.Keys[0]) == nil {
			continue
		}
		if err := walkSchemaNode(c, parent, path, vc, node.Children, closed); err != nil {
			if vc.recordTypedLeaf(err) {
				continue
			}
			return err
		}
	}
	return nil
}

// chainedFlagError16749 rewrites an error raised against a chained
// child (validated at the parent schema) so it names the flag head and
// tells the operator to author the chained statement on its own line.
// The underlying validator verdict is preserved verbatim after the
// prefix. Path tokens are rendered through redactSecretPath via
// schemaErrorf's scrubbing choke point, so a chained secret-bearing
// leaf (authentication-key) never leaks its value.
func chainedFlagError16749(flagPath []string, flag string, err error) error {
	return schemaErrorf(flagPath, "%s: statement(s) chained under the valueless flag `%s` are validated as if written at the enclosing BGP level; author each statement on its own line (separate `set` commands, or separate statements in the block) — chained validation failed: %v (#16749)",
		strings.Join(redactSecretPath(flagPath), " "), flag, err)
}
