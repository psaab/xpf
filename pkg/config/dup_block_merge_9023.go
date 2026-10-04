package config

// Issue 9023: a repeated named BLOCK silently discarded the earlier one.
//
//	snmp { trap-group tg1 { targets 10.0.0.1; }
//	       trap-group tg1 { version v1; } }
//	  -> targets LOST   (measured: 1 -> 0)
//
//	forwarding-options { sampling {
//	    instance i1 { input { rate 100; } }
//	    instance i1 { family inet { output { flow-server ...; } } } } }
//	  -> input rate LOST (measured: 100 -> 0)
//
// Junos merges repeated stanzas; the compiler's `m[name] = x` assignment made
// the last block win instead.
//
// WHY THIS MERGES ON BOTH PATHS, WHERE #8752 MERGES ONLY ON THE TOLERANT ONE.
// That fold is deliberately tolerant-only because the #3473 gate hard-rejects a
// duplicate policy name at commit, and merging first would destroy a diagnostic
// worth keeping. THERE IS NO SUCH GATE HERE -- `sampling instance` accepts a
// duplicate silently on the strict path, so there is no diagnostic to preserve,
// and the tolerant-only scoping that was right for policies would leave the
// operator-typed case unfixed.
//
// `snmp trap-group` looked like it had a gate and does not. It is rejected
// strictly, but for an unrelated reason: the zero-target check (#2990) runs
// per BLOCK, so the `version v1` block trips it on its own. The operator who
// wrote `targets 10.0.0.1` is told "no targets configured" -- a true statement
// about a block they did not intend to exist, describing a symptom of the
// duplication rather than the duplication. Merging first makes that gate see
// the group the operator actually described, so it stops firing on a config
// that is not missing its targets.
//
// The merge is announced, never silent: a config whose meaning changes deserves
// to say so even when the new meaning is the intended one.

// dupBlockMergeSites9023 is the (parent-container, repeated-keyword) list.
// Explicit rather than a predicate, so a container joins by a reviewed decision
// -- the same discipline compactNormalizeInScope settled on.
//
// The `*` keyword is for containers whose immediate child key is a dynamic
// operator-defined name, currently routing-instances and rib-groups.
var dupBlockMergeSites9023 = []struct{ parent, keyword string }{
	{"snmp", "trap-group"},
	{"sampling", "instance"},
	{"routing-instances", "*"},
	// #11791: the named groups' import-rib lists accumulate across blocks.
	{"rib-groups", "*"},

	// Issue 9209. These four became visible when #9024 taught the #8436 census
	// to build a NESTED fixture: each has only container children, so no
	// two-leaf fixture could be built, each left the population before any
	// verdict was formed, and the census reported "SILENT: 0" over a set that
	// excluded them. They are the same defect as the two above, at containers
	// that pass did not reach.
	//
	// EACH WAS CHECKED FOR AN EXISTING GATE BEFORE BEING ADDED, because
	// merging first destroys a diagnostic where one exists -- the reason #8752
	// folds only on the tolerant path:
	//
	//	firewall policer                        ACCEPTS the duplicate, silent
	//	protocols ospf area                     ACCEPTS the duplicate, silent
	//	system services dhcp-local-server group ACCEPTS the duplicate, silent
	//	security ipsec policy                   REJECTS -- but see below
	//
	// `security ipsec policy` is the `snmp trap-group` shape again, and it is
	// the reason this list is checked per site rather than in aggregate. The
	// gate that fires says `ipsec policy "p1" has no resolvable ipsec
	// proposals` -- a true statement about the SECOND block, which the operator
	// never intended to exist on its own, describing a symptom of the
	// duplication rather than the duplication. Merging first makes that gate
	// see the policy the operator actually described, so it stops firing on a
	// config that is not missing its proposals. No diagnostic is lost; a
	// misdirecting one is.
	{"firewall", "policer"},
	{"ospf", "area"},
	{"ipsec", "policy"},
	{"dhcp-local-server", "group"},
}

// dupUnnamedRoutingMergeSites12043 lists the three unnamed-container sites
// addressed by #12043. It is not a complete census of unnamed routing shapes;
// remaining cases are tracked in #12120.
var dupUnnamedRoutingMergeSites12043 = []struct {
	scope, parent, keyword string
}{
	{"global", "routing-options", "static"},
	{"instance", "routing-instances", "routing-options"},
	{"instance", "routing-instances", "protocols"},
}

// mergeDuplicateBlocks9023 folds the explicitly enumerated repeated named
// and unnamed containers and returns a description of each merge performed.
func mergeDuplicateBlocks9023(tree *ConfigTree) []string {
	if tree == nil {
		return nil
	}
	var merged []string
	var rootsMerged bool
	tree.Children, rootsMerged = mergeDuplicateRoutingInstanceContainers9023(tree.Children)
	if rootsMerged {
		merged = append(merged, "routing-instances")
	}
	var walk func(n *Node, depth int)
	walk = func(n *Node, depth int) {
		if n == nil || depth > 6 {
			return
		}
		var containersMerged bool
		n.Children, containersMerged = mergeDuplicateRoutingInstanceContainers9023(n.Children)
		if containersMerged {
			merged = append(merged, "routing-instances")
		}
		for _, site := range dupBlockMergeSites9023 {
			if n.Name() != site.parent {
				continue
			}
			if site.keyword == "*" {
				for _, name := range mergeDuplicateNamedChildren9023(n) {
					merged = append(merged, site.parent+" "+name)
				}
				continue
			}
			names, _, _ := mergeInstancesUnder(n, site.keyword, askNone9571)
			for _, name := range names {
				merged = append(merged, site.parent+" "+site.keyword+" "+name)
			}
		}
		if n.Name() == "routing-instances" {
			for _, instance := range n.Children {
				if instance == nil || instance.IsLeaf || len(instance.Keys) == 0 {
					continue
				}
				for _, site := range dupUnnamedRoutingMergeSites12043 {
					if site.scope != "instance" || site.parent != n.Name() {
						continue
					}
					if mergeDuplicateUnnamedRoutingChildren12043(instance, site.keyword) {
						merged = append(merged, "routing-instances "+instance.Name()+" "+site.keyword)
					}
				}
			}
		}

		for _, ch := range n.Children {
			walk(ch, depth+1)
		}
	}
	for _, root := range tree.Children {
		for _, site := range dupUnnamedRoutingMergeSites12043 {
			if site.scope != "global" || root.Name() != site.parent {
				continue
			}
			if mergeDuplicateUnnamedRoutingChildren12043(root, site.keyword) {
				merged = append(merged, site.parent+" "+site.keyword)
			}
		}
		walk(root, 0)
	}

	return merged
}

// mergeDuplicateRoutingInstanceContainers9023 folds sibling
// `routing-instances` containers into the first container. Hierarchical input
// preserves repeated top-level blocks as separate roots, while compileSections
// dispatches each root independently; joining them here makes identical names
// visible to the dynamic-instance fold below.
func mergeDuplicateRoutingInstanceContainers9023(children []*Node) ([]*Node, bool) {
	var first *Node
	kept := make([]*Node, 0, len(children))
	merged := false
	for _, child := range children {
		if child == nil || child.Name() != "routing-instances" || child.IsLeaf {
			kept = append(kept, child)
			continue
		}
		if first == nil {
			first = child
			kept = append(kept, child)
			continue
		}
		first.Children = append(first.Children, child.Children...)
		first.IsLeaf = false
		merged = true
	}
	if !merged {
		return children, false
	}
	return kept, true
}

// mergeDuplicateNamedChildren9023 folds repeated dynamic-name children into
// the first occurrence, preserving packed leaf tails and braced bodies.
func mergeDuplicateNamedChildren9023(parent *Node) []string {
	if parent == nil {
		return nil
	}
	first := make(map[string]*Node)
	kept := make([]*Node, 0, len(parent.Children))
	var merged []string
	for _, child := range parent.Children {
		if child == nil || len(child.Keys) == 0 || isApplyStatementNode(child) ||
			(child.IsLeaf && len(child.Keys) < 2) {
			kept = append(kept, child)
			continue
		}
		name := child.Keys[0]
		prev, seen := first[name]
		if !seen {
			first[name] = child
			kept = append(kept, child)
			continue
		}
		if tail := child.Keys[1:]; len(tail) > 0 {
			prev.Children = append(prev.Children, &Node{
				Keys:   append([]string(nil), tail...),
				IsLeaf: true,
			})
		}
		prev.Children = append(prev.Children, child.Children...)
		prev.IsLeaf = false
		mergeSiblingContainers9209(prev, 0)
		merged = append(merged, name)
	}
	if len(merged) > 0 {
		parent.Children = kept
	}
	return merged
}

// mergeDuplicateUnnamedRoutingChildren12043 folds repeated unnamed routing
// containers into the first sibling, preserving source order and recursively
// merging identical child containers just as the existing named-block path
// does. The sites are explicitly enumerated above; this is not a global AST
// normalization.
func mergeDuplicateUnnamedRoutingChildren12043(parent *Node, keyword string) bool {
	if parent == nil {
		return false
	}
	var first *Node
	kept := make([]*Node, 0, len(parent.Children))
	merged := false
	for _, child := range parent.Children {
		if child == nil || child.Name() != keyword || child.IsLeaf {
			kept = append(kept, child)
			continue
		}
		if first == nil {
			first = child
			kept = append(kept, child)
			continue
		}
		if tail := child.Keys[1:]; len(tail) > 0 {
			first.Children = append(first.Children, &Node{
				Keys:   append([]string(nil), tail...),
				IsLeaf: true,
			})
		}
		first.Children = append(first.Children, child.Children...)
		first.IsLeaf = false
		mergeSiblingContainers9209(first, 0)
		merged = true
	}
	if merged {
		parent.Children = kept
	}
	return merged
}
