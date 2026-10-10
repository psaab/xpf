package config

import (
	"strconv"
	"strings"
)

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
// routing containers found by #12120. "any" rows are restricted to routing
// contexts: the root, a routing-instance, or those same paths in a group body.
// "root" is the top-level protocols container, whose separate roots otherwise
// dispatch independently and overwrite the same typed protocol.
//
// The #12120 protocol/static rows were checked for existing gates before being
// added, following the dup_block_merge_9023.go:57-74 discipline. At afb932ee1
// strict and tolerant compilation accepted and silently dropped the second
// block for these shapes:
//
//	routing-options static (instance)   ACCEPTS, silent; global twin already #12043
//	protocols ospf3 (global/instance)    ACCEPTS, silent
//	protocols rip                        ACCEPTS, silent
//	protocols isis                       ACCEPTS, silent
//	protocols lldp                       ACCEPTS, silent
//	protocols router-advertisement       ACCEPTS, silent
//
// The isis/rip gate check also verified the authType="" keyless result when
// md5 key/type were in the dropped second block. Merging restores the pair
// before #9105 reads it; strict and tolerant inputs then match their hand-merged
// controls. The nested `interface-routes rib-group` row was separately
// confirmed against X1/X3 and global selector fixtures: it preserves inet and
// inet6 together, while the global unsupported gate sees both selectors after
// the fold. The global `interface-routes` site itself remains registered with
// its strict merged-selector assertion.
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
	{"any", "interface-routes", "rib-group"},
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
	marker          string
}

// mergeDuplicateBlocks9023 folds the explicitly enumerated repeated named
// and unnamed containers and returns structured context for each merge.
func mergeDuplicateBlocks9023(tree *ConfigTree) []duplicateBlockMerge9023 {
	if tree == nil {
		return nil
	}
	var merged []duplicateBlockMerge9023
	appendMerge := func(merge duplicateBlockMerge9023, target *Node) {
		if merge.group != "" && target != nil {
			merge.marker = strconv.Itoa(len(merged))
			markDuplicateBlockMergeLeaves9023(target, merge.marker)
		}
		merged = append(merged, merge)
	}
	var rootsMerged bool
	tree.Children, rootsMerged = mergeDuplicateRoutingInstanceContainers9023(tree.Children)
	if rootsMerged {
		merged = append(merged, duplicateBlockMerge9023{
			kind: duplicateBlockMergeContainer9023, parent: "routing-instances",
		})
	}

	var walk func(n *Node, depth int, scope, group string, path []string)
	walk = func(n *Node, depth int, scope, group string, path []string) {
		if n == nil || depth > 6 {
			return
		}
		if n.Name() == "groups" {
			groupPath := appendDuplicateMergeNodePath9023(path, n)
			for _, groupNode := range n.Children {
				if groupNode == nil || groupNode.IsLeaf || len(groupNode.Keys) == 0 {
					continue
				}
				groupName := groupNode.Name()
				walk(groupNode, depth+1, "", groupName, groupPath)
			}
			return
		}
		var containersMerged bool
		n.Children, containersMerged = mergeDuplicateRoutingInstanceContainers9023(n.Children)
		if containersMerged {
			appendMerge(duplicateBlockMerge9023{
				kind: duplicateBlockMergeContainer9023, parent: "routing-instances",
				scope: scope, group: group,
			}, namedChild9023(n, "routing-instances"))
		}
		for _, site := range dupBlockMergeSites9023 {
			if n.Name() != site.parent {
				continue
			}
			if site.keyword == "*" {
				for _, name := range mergeDuplicateNamedChildren9023(n, path) {
					appendMerge(duplicateBlockMerge9023{
						kind: duplicateBlockMergeNamed9023, parent: site.parent,
						name: name, scope: scope, group: group,
					}, namedChild9023(n, name))
				}
				continue
			}
			names, _, _ := mergeInstancesUnder(n, site.keyword, askNone9571)
			for _, name := range names {
				appendMerge(duplicateBlockMerge9023{
					kind: duplicateBlockMergeNamed9023, parent: site.parent,
					keyword: site.keyword, name: name, scope: scope, group: group,
				}, namedSiteChild9023(n, site.keyword, name))
			}
		}
		if n.Name() == "routing-instances" {
			routingInstancesPath := appendDuplicateMergeNodePath9023(path, n)
			for _, instance := range n.Children {
				if instance == nil || instance.IsLeaf || len(instance.Keys) == 0 {
					continue
				}
				instanceScope := "routing-instances " + diagnosticMergeName9023(instance.Name())
				instancePath := appendDuplicateMergeNodePath9023(routingInstancesPath, instance)
				for _, site := range dupUnnamedRoutingMergeSites12043 {
					if site.parent != n.Name() {
						continue
					}
					children, didMerge := mergeDuplicateUnnamedRoutingChildrenAtPath9023(
						instance.Children, site.keyword, instancePath)
					instance.Children = children
					if didMerge {
						appendMerge(duplicateBlockMerge9023{
							kind: duplicateBlockMergeUnnamed9023, parent: site.parent,
							keyword: site.keyword, name: instance.Name(), scope: instanceScope,
							group: group,
						}, namedChild9023(instance, site.keyword))
					}
				}
				walk(instance, depth+1, instanceScope, group, routingInstancesPath)
			}
			return
		}

		nodePath := appendDuplicateMergeNodePath9023(path, n)
		for _, site := range dupUnnamedRoutingMergeSites12120 {
			if site.scope != "any" || n.Name() != site.parent ||
				!isAnyRoutingMergeParentPath9023(path, site.parent) {
				continue
			}
			children, didMerge := mergeDuplicateUnnamedRoutingChildrenAtPath9023(
				n.Children, site.keyword, nodePath)
			n.Children = children
			if didMerge {
				appendMerge(duplicateBlockMerge9023{
					kind: duplicateBlockMergeUnnamed9023, parent: site.parent,
					keyword: site.keyword, scope: scope, group: group,
				}, namedChild9023(n, site.keyword))
			}
		}
		for _, ch := range n.Children {
			walk(ch, depth+1, scope, group, nodePath)
		}
	}

	// Fold only the top-level `protocols` siblings here. Do not recursively
	// merge their children yet: the per-keyword registrations below must see
	// and report any repeated protocol containers regardless of unrelated roots.
	for _, site := range dupUnnamedRoutingMergeSites12120 {
		if site.scope == "root" {
			var didMerge bool
			tree.Children, didMerge = mergeDuplicateUnnamedRoutingChildrenRecursion9023(
				tree.Children, site.keyword, false, nil)
			if didMerge {
				merged = append(merged, duplicateBlockMerge9023{
					kind: duplicateBlockMergeUnnamed9023, keyword: site.keyword,
				})
			}
		}
	}
	path := make([]string, 0, 24)
	for _, root := range tree.Children {
		walk(root, 0, "", "", path[:0])
	}

	return merged
}

func appendDuplicateMergeNodePath9023(path []string, node *Node) []string {
	if node == nil {
		return path
	}
	return append(path, node.Keys...)
}

func routingMergePath9023(path []string) []string {
	if len(path) >= 2 && path[0] == "groups" {
		return path[2:]
	}
	return path
}

func isRootOrRoutingInstancePath9023(path []string) bool {
	path = routingMergePath9023(path)
	return len(path) == 0 ||
		(len(path) == 2 && path[0] == "routing-instances")
}

func isAnyRoutingMergeParentPath9023(path []string, parent string) bool {
	path = routingMergePath9023(path)
	switch parent {
	case "protocols", "routing-options":
		return isRootOrRoutingInstancePath9023(path)
	case "rib", "interface-routes":
		return (len(path) == 1 && path[0] == "routing-options") ||
			(len(path) == 3 && path[0] == "routing-instances" && path[2] == "routing-options")
	default:
		return false
	}
}

func namedChild9023(parent *Node, name string) *Node {
	if parent == nil {
		return nil
	}
	for _, child := range parent.Children {
		if child != nil && !child.IsLeaf && child.Name() == name {
			return child
		}
	}
	return nil
}

func namedSiteChild9023(parent *Node, keyword, mergeName string) *Node {
	name := strings.TrimPrefix(mergeName, keyword+" ")
	if parent == nil {
		return nil
	}
	for _, child := range parent.Children {
		if child != nil && len(child.Keys) > 1 &&
			child.Keys[0] == keyword && child.Keys[1] == name {
			return child
		}
	}
	return nil
}

func markDuplicateBlockMergeLeaves9023(node *Node, marker string) {
	if node == nil {
		return
	}
	if node.IsLeaf || len(node.Children) == 0 {
		appendDuplicateBlockMergeMarker9023(node, marker)
		return
	}
	for _, child := range node.Children {
		markDuplicateBlockMergeLeaves9023(child, marker)
	}
}

func appendDuplicateBlockMergeMarker9023(node *Node, marker string) {
	if node == nil {
		return
	}
	for _, existing := range node.duplicateBlockMergeMarkers9023 {
		if existing == marker {
			return
		}
	}
	node.duplicateBlockMergeMarkers9023 = append(node.duplicateBlockMergeMarkers9023, marker)
}

func duplicateBlockMergeMarkersAtNode9023(node *Node) []string {
	if node == nil {
		return nil
	}
	return node.duplicateBlockMergeMarkers9023
}

func duplicateBlockMergeMarkers9023(node *Node) []string {
	var seen map[string]struct{}
	var markers []string
	var walk func(*Node)
	walk = func(n *Node) {
		if n == nil {
			return
		}
		for _, marker := range n.duplicateBlockMergeMarkers9023 {
			if _, ok := seen[marker]; !ok {
				if seen == nil {
					seen = make(map[string]struct{})
				}
				seen[marker] = struct{}{}
				markers = append(markers, marker)
			}
		}
		for _, child := range n.Children {
			walk(child)
		}
	}
	walk(node)
	return markers
}

func appendDuplicateBlockMergeMarkers9023(node *Node, markers []string) {
	for _, marker := range markers {
		appendDuplicateBlockMergeMarker9023(node, marker)
	}
}

func appendDuplicateBlockMergeMarkersToLeaves9023(nodes []*Node, markers []string) {
	if len(markers) == 0 {
		return
	}
	var walk func(*Node)
	walk = func(n *Node) {
		if n == nil {
			return
		}
		if n.IsLeaf || len(n.Children) == 0 {
			for _, marker := range markers {
				appendDuplicateBlockMergeMarker9023(n, marker)
			}
			return
		}
		for _, child := range n.Children {
			walk(child)
		}
	}
	for _, node := range nodes {
		walk(node)
	}
}

func stripDuplicateBlockMergeMarkers9023(tree *ConfigTree) {
	if tree == nil {
		return
	}
	var walk func(*Node)
	walk = func(n *Node) {
		if n == nil {
			return
		}
		n.duplicateBlockMergeMarkers9023 = nil
		for _, child := range n.Children {
			walk(child)
		}
	}
	for _, child := range tree.Children {
		walk(child)
	}
}

func hasGroupScopedDuplicateBlockMerge9023(merges []duplicateBlockMerge9023) bool {
	for _, merge := range merges {
		if merge.group != "" {
			return true
		}
	}
	return false
}

func resolveDuplicateBlockMergeWarnings9023(tree *ConfigTree, merges []duplicateBlockMerge9023, existing []string) []string {
	var applied map[string]bool
	if hasGroupScopedDuplicateBlockMerge9023(merges) {
		if tree != nil {
			for _, root := range tree.Children {
				for _, marker := range duplicateBlockMergeMarkers9023(root) {
					if applied == nil {
						applied = make(map[string]bool)
					}
					applied[marker] = true
				}
			}
		}
		stripDuplicateBlockMergeMarkers9023(tree)
	}
	warnings := make([]string, 0, len(merges)+len(existing))
	for _, merge := range merges {
		if merge.group != "" && !applied[merge.marker] {
			continue
		}
		warnings = append(warnings, duplicateBlockMergeWarning9023(merge))
	}
	return append(warnings, existing...)
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
func mergeDuplicateNamedChildren9023(parent *Node, path []string) []string {
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
		parentPath := appendDuplicateMergeNodePath9023(path, parent)
		if parent.Name() == "routing-instances" {
			mergeSiblingContainers9209WithParentAndPath(prev, 0, "routing-instances", parentPath)
		} else {
			mergeSiblingContainers9209WithParentAndPath(prev, 0, "", parentPath)
		}
		merged = append(merged, name)
	}
	if len(merged) > 0 {
		parent.Children = kept
	}
	return merged
}

// mergeDuplicateUnnamedRoutingChildrenAtPath9023 folds a repeated unnamed
// routing container at one registered site and carries its ancestor path into
// recursive sibling handling.
func mergeDuplicateUnnamedRoutingChildrenAtPath9023(children []*Node, keyword string, parentPath []string) ([]*Node, bool) {
	return mergeDuplicateUnnamedRoutingChildrenRecursion9023(children, keyword, true, parentPath)
}

// mergeDuplicateUnnamedRoutingChildrenRecursion9023 lets the top-level
// protocols fold defer nested merges until their registered protocol site is
// visited, so those folds are deterministic and individually diagnosed.
func mergeDuplicateUnnamedRoutingChildrenRecursion9023(children []*Node, keyword string, recurse bool, parentPath []string) ([]*Node, bool) {
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
			mergeSiblingContainers9209WithParentAndPath(first, 0, "", parentPath)
		}
		merged = true
	}
	if merged {
		return kept, true
	}
	return children, false
}
func isRegisteredUnnamedRoutingMergeSite9023(parent, keyword string, path []string) bool {
	normalizedPath := routingMergePath9023(path)
	for _, site := range dupUnnamedRoutingMergeSites12043 {
		if site.scope == "instance" && site.parent == parent && site.keyword == keyword {
			return len(normalizedPath) == 1 && normalizedPath[0] == "routing-instances"
		}
	}
	for _, site := range dupUnnamedRoutingMergeSites12120 {
		if site.scope == "any" && site.parent == parent && site.keyword == keyword {
			return isAnyRoutingMergeParentPath9023(path, parent)
		}
	}
	return false
}
