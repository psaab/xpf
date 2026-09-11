package config

import (
	"fmt"
	"hash/fnv"
	"sort"
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
// an apply statement rather than an instance: an UNQUOTED `apply-groups`,
// `apply-groups-except` or `apply-macro` (#9657). Group expansion strips only
// apply-groups; the other two stay in the tree, and compileRoutingInstances used
// to build a routing instance, and its VRF, named after the keyword. That
// phantom could also quarantine a real instance whose stable table id collided
// with it. A quoted name ("apply-macro") is an operator's instance name and is
// kept. The compiler and the collision scan share this predicate so they count
// the same instances.
func isApplyStatementNode(n *Node) bool {
	if len(n.Keys) == 0 || (len(n.KeysQuoted) > 0 && n.KeysQuoted[0]) {
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
func collectRoutingInstanceNamesAST(riNode *Node, out map[string]struct{}) {
	if riNode == nil {
		return
	}
	for _, child := range riNode.Children {
		if len(child.Keys) == 0 || (child.IsLeaf && len(child.Keys) < 2) {
			continue
		}
		// An apply statement is not an instance. compileRoutingInstances skips
		// it through the same predicate, so this scan counts exactly what the
		// compiler builds (#9657).
		if isApplyStatementNode(child) {
			continue
		}
		if name := child.Keys[0]; name != "" {
			out[name] = struct{}{}
		}
	}
}

// emitNodeExpandedRoutingInstanceNames returns the routing-instance names that
// survive expanding the candidate tree for chassis-cluster node nodeID (View 2
// for node0, View 3 for node1), used by validateRoutingInstanceTableIDCollisionAST.
// It is the post-`${node}`/apply-groups view: a `${node}`-interpolated or
// wildcard apply-group instance name is only concrete after expansion.
//
// It mirrors emitNodeExpandedZoneNames (zoneid.go): RECURSION-FREE by
// construction (clone + expand + read the names straight off the AST, never
// calling CompileConfig*), and per-node expansion errors are NON-FATAL (the
// view contributes the EMPTY set), so a config that defines only `groups node0`
// and references `${node}` does not turn a legitimate node1-expansion miss into
// a spurious commit failure. View 1's pre-expansion union still covers any
// collision inside the un-expandable group.
func emitNodeExpandedRoutingInstanceNames(tree *ConfigTree, nodeID int, out map[string]struct{}) {
	clone := tree.Clone()
	vars := map[string]string{"node": fmt.Sprintf("node%d", nodeID)}
	if err := clone.ExpandGroupsWithVars(vars); err != nil {
		return
	}
	// #5691: union across every top-level `routing-instances` root — a split
	// config can declare instances in a second stanza that compileSections still
	// compiles.
	for _, ri := range clone.FindChildren("routing-instances") {
		collectRoutingInstanceNamesAST(ri, out)
	}
}

// validateRoutingInstanceTableIDCollisionAST checks the UNION of routing-instance
// names across three views of the candidate config for StableRoutingInstanceTableID
// collisions (#3855), mirroring validateZoneIDCollisionAST (#3075) and
// validateTunnelEndpointIDCollisionAST (#1873):
//
//	View 1 — the PRE-expansion presence union across the main "routing-instances"
//	  hierarchy AND every "groups" block an apply-groups statement reaches
//	  (#9657; a group nothing applies never compiles). It runs on the pre-expansion tree so
//	  the check covers the union of instance names across all groups, keeping the
//	  accept/reject decision identical on both chassis-cluster nodes.
//	View 2 — the instance names that survive expanding the candidate for node0.
//	View 3 — the same for node1.
//
// All three views are pure functions of the SAME candidate config, so the union
// stays a pure function of config (HA symmetry preserved) and is monotone over
// View 1 (Views 2/3 only ADD rejects).
//
// Strict (commit / commit-check) returns an error so an operator can never
// commit a config whose two routing-instance names fold to the same kernel
// table — two VRFs sharing a table would MERGE their routes (a cross-VRF leak).
// Lenient (load / peer-sync of an already-active config) returns a warning so an
// upgraded node still boots (#1960 no-brick); compileRoutingInstances then
// QUARANTINES the later-sorting colliding instance (see QuarantinedRoutingInstanceNames)
// so the two never actually share a kernel table.
func validateRoutingInstanceTableIDCollisionAST(tree *ConfigTree, lenient bool) ([]string, error) {
	names := routingInstanceNameUnionAST(tree)
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
		sorted = append(sorted, name)
	}
	if len(sorted) < 2 {
		return nil, nil
	}
	sort.Strings(sorted)
	byID := make(map[int]string, len(sorted))
	var warnings []string
	for _, name := range sorted {
		id := StableRoutingInstanceTableID(name)
		owner, taken := byID[id]
		if !taken {
			byID[id] = name
			continue
		}
		msg := fmt.Sprintf(
			"routing-instance table-id collision between %q and %q (both fold to kernel table %d) — rename one instance (#3855)",
			owner, name, id)
		if !lenient {
			return nil, fmt.Errorf("routing-instances: %s", msg)
		}
		// Lenient: keep booting. This union spans both nodes' views, so it
		// cannot say which instance THIS node drops, or whether it drops one at
		// all: an instance may be in effect only on the peer. The runtime pass in
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
// Programming both would MERGE two VRFs: one instance's routes, next-table
// leaks and PBR would stand in for the other (pkg/routing/vrf.go binds a
// vrf-<name> device to the kernel table by number; two devices on one table is
// a cross-VRF route leak). The STRICT commit path REJECTS a collision outright;
// the LENIENT path (tolerant load / peer-sync / a config a pre-#3855 binary
// persisted with positional ids and no stable-hash collision check) keeps
// booting but quarantines the colliding instance here, preserving the #1960
// no-brick intent.
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

// routingInstanceNameUnionAST is the three-view union of routing-instance names
// the name gates judge (#3855, #9622): View 1 — the PRE-expansion presence union
// across every top-level "routing-instances" root AND every "groups" block an
// apply-groups statement reaches (#9657);
// Views 2/3 — the names that survive expanding the candidate for node0 and
// node1. It is a pure function of the candidate config, so a verdict built on
// it is identical on both chassis-cluster nodes. One definition for every gate
// that asks "which routing-instance names can this config create".
func routingInstanceNameUnionAST(tree *ConfigTree) map[string]struct{} {
	names := make(map[string]struct{})
	// View 1 — pre-expansion presence union (main + every groups block that an
	// apply-groups statement reaches, #9657). Union
	// across EVERY top-level `routing-instances` root (#5691): a split config can
	// declare instances in a second stanza, and compileSections compiles them
	// all, so a first-root-only scan would miss a collision spanning the roots.
	for _, ri := range tree.FindChildren("routing-instances") {
		collectRoutingInstanceNamesAST(ri, names)
	}
	// #9657: group expansion drops a group nothing applies, so an instance
	// declared only there never compiles on either node. Counting it refused
	// configs whose effective instances do not collide.
	reachable := reachableGroupNamesAST(tree)
	for _, child := range tree.Children {
		if child.Name() != "groups" {
			continue
		}
		for _, group := range child.Children {
			// Node{Keys:["groups","node0"]} merges the group name into
			// Keys[1]; the children are then the group body. The other shape
			// nests the group name as a child node.
			if len(child.Keys) >= 2 {
				if _, ok := reachable[child.Keys[1]]; ok {
					for _, ri := range child.FindChildren("routing-instances") {
						collectRoutingInstanceNamesAST(ri, names)
					}
				}
				break
			}
			if len(group.Keys) == 0 {
				continue
			}
			name := group.Keys[0]
			if len(group.Keys) > 1 {
				name = group.Keys[1]
			}
			if _, ok := reachable[name]; !ok {
				continue
			}
			for _, ri := range group.FindChildren("routing-instances") {
				collectRoutingInstanceNamesAST(ri, names)
			}
		}
	}
	// Views 2/3 — post-expansion instance names for node0 and node1. Both
	// computed on both nodes from the shared candidate, so the union stays
	// HA-symmetric; per-node expansion errors contribute the empty set.
	emitNodeExpandedRoutingInstanceNames(tree, 0, names)
	emitNodeExpandedRoutingInstanceNames(tree, 1, names)
	return names
}
