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

// dupUnnamedRoutingMergeSites12043 lists the two unnamed-container sites
// addressed by #12043 that are not subsumed by the broader #12120 registry.
// Global and instance routing-options static now share the single "any"
// registration below; the #12043 global registration is removed to prevent a
// double fold and duplicate diagnostic.
var dupUnnamedRoutingMergeSites12043 = []struct {
	scope, parent, keyword string
}{
	{"instance", "routing-instances", "routing-options"},
	{"instance", "routing-instances", "protocols"},
}

// dupUnnamedRoutingMergeSites12120 lists the additional repeated unnamed
// routing containers found by #12120. "any" means every matching parent node;
// "root" is the top-level protocols container, whose separate roots otherwise
// dispatch independently and overwrite the same typed protocol.
//
// EACH SITE WAS CHECKED FOR AN EXISTING GATE BEFORE BEING ADDED, the
// dup_block_merge_9023.go:57-74 discipline. At afb932ee1 strict and tolerant
// compilation both accepted and silently dropped the second block for every
// newly registered shape:
//
//	routing-options static (instance)   ACCEPTS, silent; global twin already #12043
//	protocols ospf3 (global/instance)   ACCEPTS, silent
//	protocols rip                       ACCEPTS, silent
//	protocols isis                      ACCEPTS, silent
//	protocols lldp                      ACCEPTS, silent
//	protocols router-advertisement      ACCEPTS, silent
//
// The isis/rip gate check also verified the authType="" keyless result when
// md5 key/type were in the dropped second block. Merging restores the pair
// before #9105 reads it; strict and tolerant inputs then match their hand-merged
// controls. The global `interface-routes` gate/rejection is an existing
// registered site and its strict merged selectors are asserted below.
var dupUnnamedRoutingMergeSites12120 = []struct {
	scope, parent, keyword string
}{
	{"any", "routing-options", "generate"},
	{"any", "routing-options", "interface-routes"},
	{"any", "routing-options", "static"},
	{"any", "rib", "static"},
	{"any", "protocols", "ospf"},
	{"any", "protocols", "ospf3"},
	{"any", "protocols", "bgp"},
	{"any", "protocols", "rip"},
	{"any", "protocols", "isis"},
	{"any", "protocols", "lldp"},
	{"any", "protocols", "router-advertisement"},
	{"root", "root", "protocols"},
}

type duplicateBlockMergeKind9023 uint8

const (
	duplicateBlockMergeContainer9023 duplicateBlockMergeKind9023 = iota
	duplicateBlockMergeNamed9023
	duplicateBlockMergeUnnamed9023
)

// duplicateBlockMerge9023 carries structured fold context through to the
// diagnostic formatter. scope identifies a routing-instance or group body;
// parent, keyword, and name retain the same #12123 context used to avoid
// reparsing warning strings.
type duplicateBlockMerge9023 struct {
	kind            duplicateBlockMergeKind9023
	parent, keyword string
	name            string
	scope           string
	group           string
}

// mergeDuplicateBlocks9023 folds the explicitly enumerated repeated named
// and unnamed containers and returns structured context for each merge.
func mergeDuplicateBlocks9023(tree *ConfigTree, vars ...map[string]string) []duplicateBlockMerge9023 {
	if tree == nil {
		return nil
	}
	var groupVars map[string]string
	if len(vars) > 0 {
		groupVars = vars[0]
	}
	appliedGroups := appliedGroupNames12120(tree, groupVars)
	var merged []duplicateBlockMerge9023
	var rootsMerged bool
	tree.Children, rootsMerged = mergeDuplicateRoutingInstanceContainers9023(tree.Children)
	if rootsMerged {
		merged = append(merged, duplicateBlockMerge9023{
			kind: duplicateBlockMergeContainer9023, parent: "routing-instances",
		})
	}

	var walk func(n *Node, depth int, scope, group string)
	walk = func(n *Node, depth int, scope, group string) {
		if n == nil || depth > 6 {
			return
		}
		if n.Name() == "groups" {
			for _, groupNode := range n.Children {
				if groupNode == nil || groupNode.IsLeaf || len(groupNode.Keys) == 0 {
					continue
				}
				groupName := groupNode.Name()
				walk(groupNode, depth+1, "", groupName)
			}
			return
		}
		var containersMerged bool
		n.Children, containersMerged = mergeDuplicateRoutingInstanceContainers9023(n.Children)
		if containersMerged {
			merged = append(merged, duplicateBlockMerge9023{
				kind: duplicateBlockMergeContainer9023, parent: "routing-instances",
				scope: scope, group: group,
			})
		}
		for _, site := range dupBlockMergeSites9023 {
			if n.Name() != site.parent {
				continue
			}
			if site.keyword == "*" {
				for _, name := range mergeDuplicateNamedChildren9023(n) {
					merged = append(merged, duplicateBlockMerge9023{
						kind: duplicateBlockMergeNamed9023, parent: site.parent,
						name: name, scope: scope, group: group,
					})
				}
				continue
			}
			names, _, _ := mergeInstancesUnder(n, site.keyword, askNone9571)
			for _, name := range names {
				merged = append(merged, duplicateBlockMerge9023{
					kind: duplicateBlockMergeNamed9023, parent: site.parent,
					keyword: site.keyword, name: name, scope: scope, group: group,
				})
			}
		}
		if n.Name() == "routing-instances" {
			for _, instance := range n.Children {
				if instance == nil || instance.IsLeaf || len(instance.Keys) == 0 {
					continue
				}
				instanceScope := "routing-instances " + diagnosticMergeName9023(instance.Name())
				for _, site := range dupUnnamedRoutingMergeSites12043 {
					if site.parent != n.Name() {
						continue
					}
					children, didMerge := mergeDuplicateUnnamedRoutingChildren(instance.Children, site.keyword)
					instance.Children = children
					if didMerge {
						merged = append(merged, duplicateBlockMerge9023{
							kind: duplicateBlockMergeUnnamed9023, parent: site.parent,
							keyword: site.keyword, name: instance.Name(), scope: instanceScope,
							group: group,
						})
					}
				}
				walk(instance, depth+1, instanceScope, group)
			}
			return
		}

		for _, site := range dupUnnamedRoutingMergeSites12120 {
			if site.scope != "any" || n.Name() != site.parent {
				continue
			}
			children, didMerge := mergeDuplicateUnnamedRoutingChildren(n.Children, site.keyword)
			n.Children = children
			if didMerge {
				merged = append(merged, duplicateBlockMerge9023{
					kind: duplicateBlockMergeUnnamed9023, parent: site.parent,
					keyword: site.keyword, scope: scope, group: group,
				})
			}
		}
		for _, ch := range n.Children {
			walk(ch, depth+1, scope, group)
		}
	}

	// Fold only the top-level `protocols` siblings here. Do not recursively
	// merge their children yet: the per-keyword registrations below must see
	// and report any repeated protocol containers regardless of unrelated roots.
	for _, site := range dupUnnamedRoutingMergeSites12120 {
		if site.scope == "root" {
			var didMerge bool
			tree.Children, didMerge = mergeDuplicateUnnamedRoutingChildrenRecursion9023(
				tree.Children, site.keyword, false)
			if didMerge {
				merged = append(merged, duplicateBlockMerge9023{
					kind: duplicateBlockMergeUnnamed9023, keyword: site.keyword,
				})
			}
		}
	}
	for _, root := range tree.Children {
		walk(root, 0, "", "")
	}

	// The fold is required before expansion so applied group bodies conserve
	// their contents. Their diagnostics are retained only when that group is
	// reachable from an active apply-groups statement (including transitively).
	active := merged[:0]
	for _, merge := range merged {
		if merge.group != "" && !appliedGroups[merge.group] {
			continue
		}
		active = append(active, merge)
	}
	return active
}

func appliedGroupNames12120(tree *ConfigTree, vars map[string]string) map[string]bool {
	groups := make(map[string]*Node)
	for _, root := range tree.Children {
		if root == nil || root.Name() != "groups" {
			continue
		}
		for _, group := range root.Children {
			if group != nil && !group.IsLeaf && len(group.Keys) > 0 {
				groups[group.Name()] = group
			}
		}
	}
	applied := make(map[string]bool)
	var collect func(nodes []*Node, includeGroups bool)
	collect = func(nodes []*Node, includeGroups bool) {
		for _, n := range nodes {
			if n == nil {
				continue
			}
			if n.Name() == "groups" && !includeGroups {
				continue
			}
			if n.Name() == "apply-groups" {
				for _, name := range appendApplyGroupNames(nil, n, vars) {
					if applied[name] {
						continue
					}
					applied[name] = true
					if group := groups[name]; group != nil {
						collect(group.Children, true)
					}
				}
			}
			collect(n.Children, includeGroups)
		}
	}
	collect(tree.Children, false)
	return applied
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
		if parent.Name() == "routing-instances" {
			mergeSiblingContainers9209WithParent(prev, 0, "routing-instances")
		} else {
			mergeSiblingContainers9209(prev, 0)
		}
		merged = append(merged, name)
	}
	if len(merged) > 0 {
		parent.Children = kept
	}
	return merged
}

// mergeDuplicateUnnamedRoutingChildren folds a repeated unnamed routing
// container at one explicitly registered site into its first sibling,
// preserving source order and recursively merging identical child containers.
func mergeDuplicateUnnamedRoutingChildren(children []*Node, keyword string) ([]*Node, bool) {
	return mergeDuplicateUnnamedRoutingChildrenRecursion9023(children, keyword, true)
}

// mergeDuplicateUnnamedRoutingChildrenRecursion9023 lets the top-level
// protocols fold defer nested merges until their registered protocol site is
// visited, so those folds are deterministic and individually diagnosed.
func mergeDuplicateUnnamedRoutingChildrenRecursion9023(children []*Node, keyword string, recurse bool) ([]*Node, bool) {
	if len(children) == 0 {
		return children, false
	}
	var first *Node
	var kept []*Node
	merged := false
	for i, child := range children {
		if child == nil || child.Name() != keyword || child.IsLeaf {
			if merged {
				kept = append(kept, child)
			}
			continue
		}
		if first == nil {
			first = child
			if merged {
				kept = append(kept, child)
			}
			continue
		}
		if !merged {
			kept = make([]*Node, 0, len(children)-1)
			kept = append(kept, children[:i]...)
		}
		if tail := child.Keys[1:]; len(tail) > 0 {
			first.Children = append(first.Children, &Node{
				Keys:   append([]string(nil), tail...),
				IsLeaf: true,
			})
		}
		first.Children = append(first.Children, child.Children...)
		first.IsLeaf = false
		if recurse {
			mergeSiblingContainers9209(first, 0)
		}
		merged = true
	}
	if merged {
		return kept, true
	}
	return children, false
}
func isRegisteredUnnamedRoutingMergeSite9023(parent, keyword string) bool {
	for _, site := range dupUnnamedRoutingMergeSites12043 {
		if site.scope == "instance" && site.parent == parent && site.keyword == keyword {
			return true
		}
	}
	for _, site := range dupUnnamedRoutingMergeSites12120 {
		if site.scope == "any" && site.parent == parent && site.keyword == keyword {
			return true
		}
	}
	return false
}
