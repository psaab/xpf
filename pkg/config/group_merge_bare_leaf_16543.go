package config

// Bare named-instance leaves in wildcard group merge (#16543).
//
// #9801 generalized: a `<*>` group's destination may be a BARE leaf
// that names a typed instance the compiler builds from the leaf itself
// (OSPF/OSPFv3/IS-IS interface, BGP neighbor, RA interface, LLDP
// interface, policy, zone, and every other named-instance slot whose
// schema node carries a body). Writing the instance bare
// (`interface ge-0/0/0.0;`, `neighbor 192.0.2.2;`) is the usual spelling
// for an instance that inherits everything from its group, but the
// wildcard arm in mergeNodes visited only non-leaf destinations (zones
// excepted by #9801), so the group silently never bound: a wildcard
// OSPF-MD5 or neighbor BGP-MD5 template left the adjacency/session
// unauthenticated on a clean commit.
//
// The promotion is schema-driven, not a hard-coded list: a bare leaf
// qualifies iff its destination identity is fully consumed by the
// schema slot it sits in (keyword + declared args, or a wildcard name)
// AND that slot is a container (children != nil or wildcard != nil).
// That is exactly the set of slots namedInstances /
// bracketedGroupInstances8794 / FindChildren compile an instance from,
// regardless of hierarchy or leaf-ness. A scalar/multi leaf (its schema
// has no body) cannot receive group children, so it stays a leaf. A
// leaf carrying extra tokens past its identity is a packed statement
// owned by the packed-tail paths (#15032/#7648), not a bare instance,
// and stays untouched. The #9838 exclusion is literal: a top-level
// `interfaces <name>;` or `routing-instances <name>;` bare leaf
// compiles no instance at all, so a wildcard group must NOT turn it
// into one — those keep the #9838 refusal (mirrors the scoping
// TestWildcardLeafMergeIsScopedToZones9801 pinned for zones/interfaces).

// bareInstanceLeaf16543 reports whether d, sitting directly under the
// level addressed by ancestorPath, is a bare named-instance leaf whose
// schema slot is a container that compiles from a leaf. When it is, the
// wildcard arm may promote it to the empty container its braced
// spelling is before merging, exactly as #9801 does for zones.
func bareInstanceLeaf16543(ancestorPath [][]string, d *Node) bool {
	if d == nil || !d.IsLeaf || len(d.Children) > 0 || len(d.Keys) == 0 {
		return false
	}
	if isApplyStatementNode(d) {
		return false
	}
	// #9838: a bare top-level interface / routing-instance leaf compiles
	// NO instance, so promoting it would mint an instance only when a
	// group applies. The schema would otherwise admit both (wildcard
	// slots with bodies), so the exclusion is explicit and checked by
	// ancestor path before any schema resolution.
	if isBareLeaf9838Slot(ancestorPath) {
		return false
	}
	parent := schemaAtAncestorPath(ancestorPath)
	if parent == nil {
		return false
	}
	slot := resolveSchemaChild(parent, d.Keys[0])
	if slot == nil {
		return false
	}
	// The slot must be a container the compiler builds an instance from.
	// A plain/multi leaf slot (children == nil && wildcard == nil) has
	// no body to receive group children.
	if slot.children == nil && slot.wildcard == nil {
		return false
	}
	// Bare means the keys are EXACTLY the instance identity: keyword +
	// declared args (compound keys consume their sub-token too, e.g.
	// `family inet`). Anything past that is a packed tail owned by the
	// packed paths, and a bracketed value list is a multi-value leaf
	// spelling, never a bare instance.
	consumed, _ := consumeNodeKeys(d.Keys, slot)
	if consumed != len(d.Keys) {
		return false
	}
	for i := range d.Keys {
		if d.KeyBracketed(i) {
			return false
		}
	}
	return true
}

// isBareLeaf9838Slot reports whether ancestorPath is exactly the
// top-level `interfaces` or `routing-instances` container, the two
// #9838 slots whose bare leaves compile no instance.
func isBareLeaf9838Slot(ancestorPath [][]string) bool {
	if len(ancestorPath) != 1 || len(ancestorPath[0]) != 1 {
		return false
	}
	switch ancestorPath[0][0] {
	case "interfaces", "routing-instances":
		return true
	}
	return false
}

// promoteBareInstanceLeaf16543 turns a bare named-instance leaf into
// the empty container its braced spelling is, so the wildcard merge can
// fill it. Keys/identity are unchanged. Caller must have checked
// bareInstanceLeaf16543 (zone macro tails are handled by
// promoteZoneMacroLeaf13112 before this is consulted).
func promoteBareInstanceLeaf16543(d *Node) {
	if d == nil {
		return
	}
	d.IsLeaf = false
}
