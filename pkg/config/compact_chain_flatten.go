package config

// flattenChainedChildren returns children with statements that SetPath NESTED
// beneath a terminating leaf hoisted into siblings, or the original slice when
// nothing moves.
//
// THE SHAPE. A flat-set command naming several leaves of one container is ONE
// command, and SetPath nests them rather than making them siblings:
//
//	set … classifiers dscp c1 ieee-802.1 c2
//	  [classifiers]
//	    [dscp c1]
//	      [ieee-802.1 c2]
//
// so a reader using FindChild on the container sees `dscp` and nothing else.
// The braced and packed-tail spellings are handled elsewhere -- by the parser
// and by packedStatements respectively -- and this is the third shape.
//
// GATED ON THE SCHEMA, never applied blanket. A nested body is legitimate under
// a leaf that DECLARES children, and hoisting it would turn that body into
// sibling statements of the container: `then reject <message-type>` is the
// worked example, where `reject` declares fourteen message types. Multi-value
// leaves also own their children, which are values rather than statements.
// Only a non-multi leaf the schema says holds NOTHING can have something nested
// under it by the chain, and that is the discriminator.
//
// WHY A READER RATHER THAN A REJECT. The chain is a SUPPORTED spelling --
// `set applications application a1 protocol tcp destination-port 80` is tested
// behaviour -- and #6524 recorded why teaching the schema to refuse it is the
// wrong move: a schema-only reject leaves the LENIENT path (boot load, HA
// SyncApply) untouched, which is exactly where already-stored configs are.
//
// `flattenThenChain8939` in compiler_firewall.go is the firewall-specific
// predecessor of this helper and does the same thing for filter-term `then`
// actions; they should converge when a third caller appears.
func flattenChainedChildren(children []*Node, container *schemaNode) []*Node {
	if container == nil || len(children) == 0 {
		return children
	}
	var out []*Node
	changed := false
	var visit func(n *Node)
	visit = func(n *Node) {
		if n == nil {
			return
		}
		leaf := resolveSchemaChild(container, n.Name())
		if leaf == nil || leaf.multi || len(leaf.children) > 0 || leaf.wildcard != nil || len(n.Children) == 0 {
			out = append(out, n)
			return
		}
		changed = true
		head := &Node{
			Keys:       append([]string(nil), n.Keys...),
			IsLeaf:     true,
			Annotation: n.Annotation,
			Inactive:   n.Inactive,
			Line:       n.Line,
			Column:     n.Column,
		}
		if n.KeysQuoted != nil {
			head.KeysQuoted = append([]bool(nil), n.KeysQuoted...)
		}
		out = append(out, head)
		for _, c := range n.Children {
			visit(c)
		}
	}
	for _, c := range children {
		visit(c)
	}
	if !changed {
		return children
	}
	return out
}

// flattenChainedNode returns node with flattenChainedChildren applied, or node
// itself when nothing moves -- so the SAME pointer is preserved on the
// overwhelmingly common path and Inactive/Annotation/provenance are untouched.
func flattenChainedNode(node *Node, container *schemaNode) *Node {
	if node == nil {
		return nil
	}
	flat := flattenChainedChildren(node.Children, container)
	if len(flat) == len(node.Children) {
		same := true
		for i := range flat {
			if flat[i] != node.Children[i] {
				same = false
				break
			}
		}
		if same {
			return node
		}
	}
	out := *node
	out.Children = flat
	return &out
}
