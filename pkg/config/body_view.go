package config

// BodyView is a zero-copy view over a node's body (#16148, W2.3 R4-narrowed).
//
// A compiler family that reads a stanza body needs the same two questions
// answered for the nested, packed, flat and bracketed spellings: what are
// the body's children, and where is the child named X? Before BodyView each
// family answered them with a bespoke expander (packedBodyChildren /
// packedBody, screenPackedBody / screenFamilyBody, expandFlatRun,
// hoistAndSplitRun8939, flattenChainedChildren, expandResolvingRuns9792, ...)
// whose ordering and bail rules could diverge per family, so the same
// statement could compile differently depending on how it was spelled.
//
// BodyView introduces no new expansion order. Children delegates to the
// per-family expansion the caller selects — by default packedBodyChildren,
// the schema-directed expander that already defines the shared order
// (deepest open level wins, siblings stay siblings, a token outside the
// modelled grammar declines the whole expansion rather than guessing).
// Find / FindAll are the Node.FindChild / FindChildren scans over Children.
// Adopting BodyView therefore cannot change what a family compiles on its
// own; it only deletes the family's private re-implementation of the
// expansion+lookup. Families whose bespoke expander carries extra semantics
// the shared walk does not (the screen family's unknown-token backstop, the
// flat-run hoist/split ambiguity bounds) keep that logic — it is not a
// Children/Find expander and deleting it would change behaviour, which is
// the stop-rule's falsifier, not its target.
//
// Per-family adoption (each step independently falsifiable):
//
//   - screen (#9421): bodyViewOf(...).withExpansion(screenFamilyBody) —
//     screenPackedBody's fallback and screenNormalizeFamilies both read
//     through the view; screenFamilyBodyChain is deleted, its bracketed
//     chain being the sibling-preserving walk's output.
//
// ALLOCATION GATE (the per-family acceptance check). The default view is
// zero-copy on the plain branch — a nested body with no packed tail:
// packedBodyChildren returns node.Children unchanged after one length
// check, so
//
//	bodyViewOf(node, schema).Children() == node.Children   (same slice)
//	bodyViewOf(node, schema).Node()      == node            (same pointer)
//
// and the view allocates nothing there. A view that copied on that branch
// would be a compile-path regression; the gate is pinned by
// TestBodyViewPlainBranchZeroAlloc16148. Views with a custom expansion
// (withExpansion) inherit that expander's allocation contract.
//
// The view is a value, not a wrapper node: it holds the authored node, its
// own schema and the selected expansion, and never mutates any of them.
// Node returns the authored node when the expansion synthesized nothing,
// otherwise a shallow copy carrying the expanded children, so callers that
// compare node identity or render the tree keep seeing exactly what was
// typed.

// bodyExpansion expands a node's packed/flat tail into the children a
// compiler should descend. It returns the authored children unchanged on
// the plain branch.
type bodyExpansion func(node *Node, schema *schemaNode) []*Node

type bodyView struct {
	node   *Node
	schema *schemaNode
	expand bodyExpansion // nil = packedBodyChildren
}

// bodyViewOf returns the BodyView for node's body under its own schema,
// using the shared packedBodyChildren expansion. schema may be nil, in
// which case the view is the authored body unchanged.
func bodyViewOf(node *Node, schema *schemaNode) bodyView {
	return bodyView{node: node, schema: schema}
}

// withExpansion returns a copy of the view using expand instead of
// packedBodyChildren for Children/Node/Find. This is how a family whose
// expansion order legitimately differs (the screen family's
// unknown-token-visible walk) adopts the view without pretending the
// shared order covers it: the family's order is named at the adoption
// site, and the lookup/identity plumbing is shared.
func (v bodyView) withExpansion(expand bodyExpansion) bodyView {
	v.expand = expand
	return v
}

func (v bodyView) expansion() bodyExpansion {
	if v.expand != nil {
		return v.expand
	}
	return packedBodyChildren
}

// Children returns the expanded body children: the authored slice
// unchanged on the plain branch, the synthesized shape-identical body on
// the packed branch.
func (v bodyView) Children() []*Node {
	return v.expansion()(v.node, v.schema)
}

// Node returns the authored node when nothing was synthesized, otherwise
// a shallow copy carrying Children. Identity is preserved whenever the
// expansion returns the authored slice (the plain branch, and every
// decline-to-authored answer), which callers that compare nodes rely on.
func (v bodyView) Node() *Node {
	if v.node == nil {
		return nil
	}
	children := v.Children()
	if len(children) == len(v.node.Children) {
		if len(children) == 0 || &children[0] == &v.node.Children[0] {
			return v.node
		}
	}
	clone := *v.node
	clone.Children = children
	return &clone
}

// Find returns the first expanded child whose first key is name, or nil.
// It is Node.FindChild over Children.
func (v bodyView) Find(name string) *Node {
	for _, child := range v.Children() {
		if len(child.Keys) > 0 && child.Keys[0] == name {
			return child
		}
	}
	return nil
}

// FindAll returns every expanded child whose first key is name, in body
// order. It is Node.FindChildren over Children and, like it, returns nil
// when nothing matches.
func (v bodyView) FindAll(name string) []*Node {
	var result []*Node
	for _, child := range v.Children() {
		if len(child.Keys) > 0 && child.Keys[0] == name {
			result = append(result, child)
		}
	}
	return result
}
