package config

import (
	"strconv"
)

// walkContext carries the per-walk validation inputs: the tree-derived
// cross-reference sets for treeValidator leaves (#16162: the former
// always-nil cfg ferry is retired; LeafValidator takes only the token).
type walkContext struct {
	refs *schemaRefs
	// #16012 collect mode: when non-nil, typed-leaf errors are appended
	// (bounded) and the walk continues; nil preserves first-error strict.
	collectErrs *[]error
	collectMax  int
}

func (vc *walkContext) collecting() bool { return vc != nil && vc.collectErrs != nil }

// recordTypedLeaf appends err in collect mode and reports whether the
// caller should continue (true) instead of returning err (false).
func (vc *walkContext) recordTypedLeaf(err error) bool {
	if !vc.collecting() || !IsTypedLeafSchemaError(err) {
		return false
	}
	if len(*vc.collectErrs) < vc.collectMax {
		*vc.collectErrs = append(*vc.collectErrs, err)
	}
	return true
}

// collectedRefs is a nil-receiver-safe accessor: the white-box walker
// tests drive walkSchemaNode with a nil context.
func (vc *walkContext) collectedRefs() *schemaRefs {
	if vc == nil {
		return nil
	}
	return vc.refs
}

// treeLeafValidator is the TREE-based counterpart of LeafValidator for
// cross-reference leaves: it receives the definitions collected from
// the candidate tree by collectSchemaRefs, so a definition and its
// reference added in the same commit validate atomically.
type treeLeafValidator func(raw string, refs *schemaRefs) error

// leafNodeValidator validates a complete leaf node, retaining AST provenance
// such as bracketed-list masks and hierarchical block children. The resolved
// parent schema is supplied so validators can reuse schema-aware ownership
// predicates without referring to globals during schema initialization.
type leafNodeValidator func(node *Node, parent *schemaNode) error

// leafTailValidator validates the whole value/modifier tail of a leaf as a
// unit (#4228 Gap 2). tokens are the flattened tail of the leaf node;
// siblingTails are the flattened tails of the same-keyword sibling nodes at
// the same level (so a modifier-only split-set line can look across to a
// sibling that supplies the value). See schemaNode.tailValidator.
type leafTailValidator func(tokens []string, siblingTails [][]string) error

// checkToken validates one token against a typed leaf directly: the
// scalar LeafValidator when set, else the tree-based cross-reference
// validator bound to the walk's collected refs. A typed leaf sets
// exactly one of the two (walkSchemaNode gates on either).
func (n *schemaNode) checkToken(vc *walkContext, tok string) error {
	if n.validator != nil {
		return n.validator(tok)
	}
	if n.treeValidator != nil {
		return n.treeValidator(tok, vc.collectedRefs())
	}
	return nil
}

// schemaRefs holds the referenceable definitions collected from the
// candidate tree before the walk (#1319 PR 3). Extend with new sets as
// more cross-reference validators land.
type schemaRefs struct {
	// forwardingClasses are the names defined via `class-of-service
	// forwarding-classes queue <n> <name>` anywhere in the tree —
	// including group bodies, applied or not. Collecting from group
	// definitions errs permissive: after apply-groups expansion the
	// applied bodies are inlined at top level anyway, and a reference
	// satisfied only by an UN-applied group must not be rejected (the
	// compiler ignores both the definition and any reference inside
	// that group, and node0/node1-variable configs legitimately keep
	// peer-node definitions un-applied locally).
	forwardingClasses map[string]struct{}
	// loginClasses are the custom names defined via `system login class
	// <name>` anywhere in the tree (including group bodies, applied or
	// not — same permissive rationale as forwardingClasses). The
	// `system login user <n> class <c>` leaf validates against the
	// built-in classes UNION this set (#4304 S-2).
	loginClasses map[string]struct{}
}

// collectSchemaRefs walks the tree for cross-referenceable definitions.
// The forwarding-class collection mirrors compileClassOfService exactly
// (compiler_class_of_service.go:82-89): `queue` leaves under a
// `forwarding-classes` node, Keys = ["queue", <int>, <name>]; entries
// whose queue number does not parse are skipped, as the compiler skips
// them.
func collectSchemaRefs(tree *ConfigTree) *schemaRefs {
	refs := &schemaRefs{
		forwardingClasses: map[string]struct{}{},
		loginClasses:      map[string]struct{}{},
	}
	if tree == nil {
		return refs
	}
	// collectCoS records forwarding-class names under EVERY sibling
	// `class-of-service` block of node (#15717: singular FindChild missed
	// classes defined in a second sibling block).
	var collectCoS func(node *Node)
	collectCoS = func(node *Node) {
		for _, cosNode := range node.FindChildren("class-of-service") {
			for _, fcNode := range cosNode.FindChildren("forwarding-classes") {
				for _, queueNode := range fcNode.FindChildren("queue") {
					if len(queueNode.Keys) < 3 {
						continue
					}
					if _, err := strconv.Atoi(queueNode.Keys[1]); err != nil {
						continue
					}
					refs.forwardingClasses[queueNode.Keys[2]] = struct{}{}
				}
			}
		}
	}
	// collectLoginClasses records custom `login class <name>` names under
	// EVERY sibling `system` block of parent (#4304 S-2; #15717: singular
	// FindChild("system") missed classes in a second sibling `system`
	// block). Mirrors the compiler's namedInstances over every sibling
	// `system login` block: each class name is the leading Keys arg.
	collectLoginClasses := func(parent *Node) {
		for _, sysNode := range parent.FindChildren("system") {
			for _, loginNode := range sysNode.FindChildren("login") {
				for _, classNode := range loginNode.FindChildren("class") {
					if len(classNode.Keys) >= 2 && classNode.Keys[1] != "" {
						refs.loginClasses[classNode.Keys[1]] = struct{}{}
						continue
					}
					// Hierarchical shape: `class { noc-admin { ... } }` — the name
					// is a child of the bare `class` node.
					for _, c := range classNode.Children {
						if len(c.Keys) > 0 && c.Keys[0] != "" {
							refs.loginClasses[c.Keys[0]] = struct{}{}
						}
					}
				}
			}
		}
	}
	// A synthetic parent lets the top level share the sibling-aware
	// collectors: tree.Children are the siblings of a virtual root.
	root := &Node{Children: tree.Children}
	collectCoS(root)
	collectLoginClasses(root)
	for _, top := range tree.Children {
		if top == nil || len(top.Keys) == 0 || top.Name() != "groups" {
			continue
		}
		for _, group := range top.Children {
			if group == nil {
				continue
			}
			collectCoS(group)
			collectLoginClasses(group)
		}
	}
	return refs
}
