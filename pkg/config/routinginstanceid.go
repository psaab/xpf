package config

import (
	"fmt"
	"hash/fnv"
	"sort"
	"strings"
)

// RoutingInstanceTableIDBase and RoutingInstanceTableIDSpan define the reserved
// kernel routing-table band for STABLE, name-hashed routing-instance table IDs
// (#3855). Every configured routing-instance's kernel table lands in
// [RoutingInstanceTableIDBase, RoutingInstanceTableIDBase+RoutingInstanceTableIDSpan-1]
// = [100000, 999999].
//
// The band sits ABOVE every other reserved kernel-table constant this project
// uses — the kernel-reserved local/main/default tables (253/254/255), the mgmt
// VRF table (999, ManagementVRFTableID), and the RPM probe-pin band (ProbeTableBase
// 7000..7049) — so a stable routing-instance table can never collide with any
// of them. It also stays >= 100 (the historical routing-instance table floor
// several callers and tests still assume) by construction.
const (
	RoutingInstanceTableIDBase = 100000
	RoutingInstanceTableIDSpan = 900000 // [100000, 999999]
)

// StableRoutingInstanceTableID maps a routing-instance name to a STABLE kernel
// routing table id: FNV-1a/64 xor-folded and mapped into the reserved band
// [RoutingInstanceTableIDBase, RoutingInstanceTableIDBase+RoutingInstanceTableIDSpan-1].
//
// The id is a pure function of the instance NAME alone — never of the rest of
// the routing-instance set, the compile order, or allocation history. This is
// the #3075 StableZoneID / #1873 StableTunnelEndpointID pattern applied to
// routing-instance kernel tables:
//
//	Positional assignment (the pre-#3855 defect) gave instances 100, 101, 102…
//	by config order, so DELETING or REORDERING one instance RENUMBERED every
//	survivor that followed it. pkg/routing/vrf.go then saw the survivor's kernel
//	VRF device carry a now-stale table id, DELETED it and recreated it with the
//	new number — a link down/up + route reprogram, i.e. a forwarding OUTAGE on a
//	VRF the operator never touched, on BOTH HA nodes.
//
// Deriving the table id from the NAME makes it invariant under add/remove/
// reorder of siblings: an untouched instance keeps its table id, so vrf.go's
// recreate-on-table-mismatch never fires spuriously. A genuine reconfig (rename
// → different name → different id) still recreates correctly. Both HA nodes and
// a cold-booting node compute identical ids from identical config with zero
// synced/persisted state.
func StableRoutingInstanceTableID(name string) int {
	h := fnv.New64a()
	_, _ = h.Write([]byte(name))
	s := h.Sum64()
	// xor-fold the high half down so the modulo samples the whole hash, then
	// map into the reserved band. Pure function of the name.
	folded := s ^ (s >> 32)
	return RoutingInstanceTableIDBase + int(folded%uint64(RoutingInstanceTableIDSpan))
}

// isApplyStatementNode reports whether a child of a routing-instances stanza is
// an apply statement rather than an instance: `apply-groups`,
// `apply-groups-except` or `apply-macro` (#9657). Group expansion strips only
// apply-groups; the other two stay in the tree, and compileRoutingInstances used
// to build a routing instance, and its VRF, named after the keyword. That
// phantom could also quarantine a real instance whose stable table id collided
// with it. The compiler and the collision scan share this predicate so they
// count the same instances.
//
// It goes by name, quoted or not. Group expansion strips apply-groups by name,
// the #9323 child validator skips all three by name, and a quote does not
// survive rendering, which an HA peer reparses: a quote-sensitive predicate
// would make the two nodes compile different instances.
func isApplyStatementNode(n *Node) bool {
	if len(n.Keys) == 0 {
		return false
	}
	switch n.Keys[0] {
	case "apply-groups", "apply-groups-except", "apply-macro":
		return true
	}
	return false
}

// collectRoutingInstanceNamesAST appends the routing-instance names declared
// under a "routing-instances" node into out. Mirrors compileRoutingInstances
// (compiler_routing.go): Keys[0] is the instance name in both the hierarchical
// and flat-set AST shapes, and that includes the brace-elided spelling
// `routing-instances { ri1 instance-type forwarding; }`, a LEAF whose Keys tail
// carries the body (#8787). The compiler builds an instance from that leaf, so
// this scan must see it: before #9622 it skipped every leaf, and neither the
// table-id gate nor the reserved-name gate saw a packed instance (two packed
// instances folding to one table passed the strict gate, and the runtime then
// quarantined one with a warning). A bare `routing-instances { ri1; }` carries no properties,
// compiles to nothing, and is still skipped.
type routingInstanceASTTypeFlags struct {
	hasForwarding bool
	hasVRF        bool
}

func collectRoutingInstanceNamesAST(riNode *Node, out map[string]struct{}) {
	collectRoutingInstanceAST(riNode, out, nil)
}

func collectRoutingInstanceAST(riNode *Node, names map[string]struct{}, types map[string]routingInstanceASTTypeFlags) {
	if riNode == nil {
		return
	}
	for _, child := range riNode.Children {
		if len(child.Keys) == 0 || (child.IsLeaf && len(child.Keys) < 2) || isApplyStatementNode(child) {
			continue
		}
		name := child.Keys[0]
		if name == "" {
			continue
		}
		if names != nil {
			names[name] = struct{}{}
		}
		if types == nil {
			continue
		}
		instanceType := ""
		for _, prop := range expandResolvingRuns9792(child.Children, routingInstanceSchema9792()) {
			if prop.Name() == "instance-type" {
				instanceType = nodeVal(prop)
			}
		}
		flags := types[name]
		if instanceType == "forwarding" {
			flags.hasForwarding = true
		} else {
			flags.hasVRF = true
		}
		types[name] = flags
	}
}

func routingInstanceTypeFlagsAST(tree *ConfigTree, compiledNode *int) map[string]routingInstanceASTTypeFlags {
	types := make(map[string]routingInstanceASTTypeFlags)
	emitGenericExpandedRoutingInstancesAST(tree, nil, types)
	emitNodeExpandedRoutingInstancesAST(tree, 0, nil, types)
	emitNodeExpandedRoutingInstancesAST(tree, 1, nil, types)
	// compileConfigForNodeWithOpts accepts any integer node ID, negative ones
	// included, and expands that node's own groups (`node%d`). A generic compile
	// passes nil.
	if compiledNode != nil && *compiledNode != 0 && *compiledNode != 1 {
		emitNodeExpandedRoutingInstancesAST(tree, *compiledNode, nil, types)
	}
	return types
}

func routingInstanceTypeFlagsASTByView(tree *ConfigTree, compiledNode *int) []map[string]routingInstanceASTTypeFlags {
	views := make([]map[string]routingInstanceASTTypeFlags, 0, 4)
	generic := make(map[string]routingInstanceASTTypeFlags)
	emitGenericExpandedRoutingInstancesAST(tree, nil, generic)
	views = append(views, generic)
	for _, nodeID := range []int{0, 1} {
		types := make(map[string]routingInstanceASTTypeFlags)
		emitNodeExpandedRoutingInstancesAST(tree, nodeID, nil, types)
		views = append(views, types)
	}
	// compileConfigForNodeWithOpts accepts any integer node ID, negative ones
	// included, and expands that node's own groups (`node%d`).
	if compiledNode != nil && *compiledNode != 0 && *compiledNode != 1 {
		types := make(map[string]routingInstanceASTTypeFlags)
		emitNodeExpandedRoutingInstancesAST(tree, *compiledNode, nil, types)
		views = append(views, types)
	}
	return views
}

// emitNodeExpandedRoutingInstancesAST collects routing-instance names and types
// after expanding the candidate tree for chassis-cluster node nodeID. This is
// the post-${node}/apply-groups view: an interpolated or wildcard instance name
// is only concrete after expansion.
//
// Like emitNodeExpandedZoneNames (zoneid.go), this is recursion-free (clone +
// expand + read AST, never calling CompileConfig*) and per-node expansion errors
// are non-fatal: a failed view contributes nothing because that node's compile
// path refuses the config (#9657).
func emitNodeExpandedRoutingInstancesAST(tree *ConfigTree, nodeID int, names map[string]struct{}, types map[string]routingInstanceASTTypeFlags) {
	clone := tree.Clone()
	vars := map[string]string{"node": fmt.Sprintf("node%d", nodeID)}
	if err := clone.ExpandGroupsWithVars(vars); err != nil {
		return
	}
	// #5691: union across every top-level `routing-instances` root — a split
	// config can declare instances in a second stanza that compileSections still
	// compiles.
	for _, ri := range clone.FindChildren("routing-instances") {
		collectRoutingInstanceAST(ri, names, types)
	}
}

// validateRoutingInstanceTableIDCollisionAST checks the UNION of routing-instance
// names across three views of the candidate config for StableRoutingInstanceTableID
// collisions (#3855), mirroring validateZoneIDCollisionAST (#3075) and
// validateTunnelEndpointIDCollisionAST (#1873). For ordinary names, a collision
// in any view pair is rejected as before. An invalid VRF name is a table claimant
// only when it is forwarding-effective in a view where the other name also exists;
// this avoids treating node-divergent, never-coexisting instances as colliding.
//
// Strict (commit / commit-check) returns an error so an operator can never
// commit a config whose two routing-instance names fold to the same kernel
// table and share route state.
// Lenient (load / peer-sync of an already-active config) returns a warning so an
// upgraded node still boots (#1960 no-brick); compileRoutingInstances then
// QUARANTINES the later-sorting colliding instance (see QuarantinedRoutingInstanceNames)
// so the two never actually share a kernel table.
func routingInstanceTableIDNamesCollideInView(nameA, nameB string, invalidA, invalidB bool, views []map[string]routingInstanceASTTypeFlags) bool {
	if !invalidA && !invalidB {
		// Preserve the union collision gate for ordinary names, including pairs
		// declared on different cluster nodes (#9657).
		return true
	}
	for _, view := range views {
		flagsA, presentA := view[nameA]
		flagsB, presentB := view[nameB]
		if !presentA || !presentB {
			continue
		}
		if (invalidA && !flagsA.hasForwarding) || (invalidB && !flagsB.hasForwarding) {
			continue
		}
		return true
	}
	return false
}

func validateRoutingInstanceTableIDCollisionAST(tree *ConfigTree, compiledNode *int, lenient bool) ([]string, error) {
	names := routingInstanceNameUnionAST(tree, compiledNode)
	var instanceTypeViews []map[string]routingInstanceASTTypeFlags
	var invalidVRFNames map[string]bool
	sorted := make([]string, 0, len(names))
	for name := range names {
		// #9622: a reserved name never gets a table. compileRoutingInstances
		// quarantines it BEFORE its own collision pass, so judging it here would
		// report a collision the runtime never has, name the wrong instance as
		// quarantined, and on the strict path reject with a table-id error
		// instead of the reserved-name one.
		if IsReservedRoutingInstanceName(name) {
			continue
		}
		// #11391: an invalid VRF device name is quarantined before the runtime
		// table-id pass and cannot claim a table. Forwarding instances do not get
		// that device-name quarantine, so they still participate in table checks.
		if _, reason := routingInstanceVRFDeviceNameIssue(name); reason != "" {
			if instanceTypeViews == nil {
				instanceTypeViews = routingInstanceTypeFlagsASTByView(tree, compiledNode)
			}
			if invalidVRFNames == nil {
				invalidVRFNames = make(map[string]bool)
			}
			invalidVRFNames[name] = true
			hasForwarding := false
			for _, view := range instanceTypeViews {
				if view[name].hasForwarding {
					hasForwarding = true
					break
				}
			}
			if !hasForwarding {
				continue
			}
		}
		sorted = append(sorted, name)
	}
	if len(sorted) < 2 {
		return nil, nil
	}
	sort.Strings(sorted)
	byID := make(map[int]string, len(sorted))
	var additionalOwners map[int][]string
	var warnings []string
	for _, name := range sorted {
		id := StableRoutingInstanceTableID(name)
		first, taken := byID[id]
		if !taken {
			byID[id] = name
			continue
		}
		owners := additionalOwners[id]
		if len(owners) == 0 {
			owners = []string{first}
		}
		owner := ""
		for _, candidate := range owners {
			if routingInstanceTableIDNamesCollideInView(
				candidate, name, invalidVRFNames[candidate], invalidVRFNames[name], instanceTypeViews) {
				owner = candidate
				break
			}
		}
		if owner == "" {
			if additionalOwners == nil {
				additionalOwners = make(map[int][]string)
			}
			additionalOwners[id] = append(owners, name)
			continue
		}
		msg := fmt.Sprintf(
			"routing-instance table-id collision between %q and %q (both fold to kernel table %d) — rename one instance (#3855)",
			owner, name, id)
		if !lenient {
			return nil, fmt.Errorf("routing-instances: %s", msg)
		}
		if additionalOwners == nil {
			additionalOwners = make(map[int][]string)
		}
		additionalOwners[id] = append(owners, name)
		// Lenient: keep booting. The union can include peer-only names, so it
		// cannot say which instance THIS node drops. The runtime pass in
		// compileRoutingInstances (QuarantinedRoutingInstanceNames) quarantines
		// on the tree this node compiles and warns naming the instance it drops,
		// with its VRF, routes and inter-VRF leaks; this warning names the
		// collision and leaves that claim to it (#9657).
		warnings = append(warnings, fmt.Sprintf("%s; a node where both instances are in effect quarantines one"+
			" of them and warns which", msg))
	}
	return warnings, nil
}

// QuarantinedRoutingInstanceNames returns the set of routing-instance names that
// MUST NOT be programmed into the kernel/dataplane because their
// StableRoutingInstanceTableID collides with an earlier (alphabetically-sorted)
// instance's table id. For each kernel table claimed by more than one name, the
// sorted-FIRST name keeps the table and every later name that folds to the same
// table is quarantined.
//
// This is the RUNTIME enforcement of the promise the lenient collision warning
// (validateRoutingInstanceTableIDCollisionAST) makes — the later-sorting
// instance is dropped — so two routing-instances never share a kernel table.
// Programming both would merge their routing-table state, including routes,
// next-table leaks and PBR. VRF instances bind `vrf-<name>` devices to these
// tables; forwarding instances also claim a table without creating a VRF.
// The STRICT commit path REJECTS a collision outright. The LENIENT path
// (tolerant load / peer-sync / a config a pre-#3855 binary persisted with
// positional ids and no stable-hash collision check) keeps booting but
// quarantines the colliding instance here, preserving the #1960 no-brick intent.
//
// The decision is a pure function of the instance-name SET
// (StableRoutingInstanceTableID is a pure function of the name and the sorted
// tie-break is deterministic), so both HA nodes and a cold-booting node compute
// the IDENTICAL quarantine set from the identical config. Returns nil when no
// table collides (the common case).
func QuarantinedRoutingInstanceNames(names []string) map[string]struct{} {
	if len(names) < 2 {
		return nil
	}
	sorted := make([]string, len(names))
	copy(sorted, names)
	sort.Strings(sorted)
	owner := make(map[int]string, len(sorted))
	var quarantined map[string]struct{}
	for _, name := range sorted {
		id := StableRoutingInstanceTableID(name)
		if existing, taken := owner[id]; taken {
			if existing == name {
				// Defensive: a duplicated name in the input slice is the same
				// instance, not a collision.
				continue
			}
			if quarantined == nil {
				quarantined = make(map[string]struct{})
			}
			quarantined[name] = struct{}{}
			continue
		}
		owner[id] = name
	}
	return quarantined
}

// routingInstanceNameUnionAST is the union of routing-instance names the
// name-based gates judge (#3855, #9622): every name some compile path can land.
//
//   - Every top-level "routing-instances" root, across all roots (#5691).
//   - The names after the generic compile's own group expansion
//     (compileConfigWithOpts: no node variables, and on an undefined "${node}"
//     group a retry with node0 on the same, already-expanded tree).
//   - The names after each cluster node's expansion (node0, node1), as
//     compileConfigForNodeWithOpts expands them, plus the requested node's own
//     expansion when a node compile passes any other ID, negative ones
//     included (compiledNode is nil for the generic compile).
//
// Every view is computed on both nodes from the same candidate, so both nodes
// decide identically. An expansion that fails contributes nothing: the compile
// path that performs it refuses the whole config, so nothing from it can land.
//
// #9657: an earlier pre-expansion view also counted instances declared in
// `groups` blocks. It had to approximate group expansion without running it, and
// every approximation disagreed with expansion somewhere: groups nothing
// applies, groups applied under another stanza, honoured and ignored
// exclusions, literal "${node}" groups. The expansion views are exact by
// construction.
func routingInstanceNameUnionAST(tree *ConfigTree, compiledNode *int) map[string]struct{} {
	names := make(map[string]struct{})
	for _, ri := range tree.FindChildren("routing-instances") {
		collectRoutingInstanceNamesAST(ri, names)
	}
	emitGenericExpandedRoutingInstancesAST(tree, names, nil)
	emitNodeExpandedRoutingInstancesAST(tree, 0, names, nil)
	emitNodeExpandedRoutingInstancesAST(tree, 1, names, nil)
	// compileConfigForNodeWithOpts accepts any integer node ID, negative ones
	// included, and expands that node's own groups (`node%d`), so a node compile
	// for any other ID counts its own view too. A generic compile passes nil.
	if compiledNode != nil && *compiledNode != 0 && *compiledNode != 1 {
		emitNodeExpandedRoutingInstancesAST(tree, *compiledNode, names, nil)
	}
	return names
}

// emitGenericExpandedRoutingInstancesAST collects the routing instances the
// generic compile lands, expanding a clone exactly as compileConfigWithOpts
// does: ExpandGroups, and on an undefined "${node}" group a retry with node0 on
// the same clone. Any other failure contributes nothing (#9657).
func emitGenericExpandedRoutingInstancesAST(tree *ConfigTree, names map[string]struct{}, types map[string]routingInstanceASTTypeFlags) {
	clone := tree.Clone()
	if err := clone.ExpandGroups(); err != nil {
		if !strings.Contains(err.Error(), `undefined group "${node}"`) {
			return
		}
		if err := clone.ExpandGroupsWithVars(map[string]string{"node": "node0"}); err != nil {
			return
		}
	}
	for _, ri := range clone.FindChildren("routing-instances") {
		collectRoutingInstanceAST(ri, names, types)
	}
}
