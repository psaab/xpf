package config

// Brace-elided interface instances in group merge (#15032, A03-03).
//
// `ge-0/0/0 unit 0 family inet address A;` parses as ONE leaf whose Keys
// run is [ge-0/0/0 unit 0 family inet address A]. Its braced spelling is
// a container chain ge-0/0/0 -> unit 0 -> family inet -> address A, and
// the compiler (#14436/#14442) already reads the packed leaf as that
// chain. Group merge was blind to it:
//   - a `<*>` group never bound: keysMatchWildcard needs equal key
//     lengths, and the wildcard arm visited only non-leaf destinations
//     (zone leaves excepted by #9801);
//   - an exact-name group container found no same-keyed container, was
//     adopted beside the leaf, and compileInterfaces' last-wins map
//     assignment kept only the group twin, losing the inline address.
//
// The fix promotes the packed interface-instance leaf to its braced
// shape before those two decisions, exactly as its braced spelling
// would have presented. Promotion is scoped to `interfaces` direct
// children whose tail expands under the interface schema (unit/family/
// description/...); a bare `ge-0/0/0;` has no tail and stays a leaf for
// the #9838 gate, and an unexpandable tail stays untouched so downstream
// gates judge it as authored. Routing instances keep #9620/#9838
// behaviour: their elided form is already normalized before expansion
// on the compile path, and raw ExpandGroups callers keep the old shape.

// interfacePackedLeaf15032 reports whether d is a brace-elided interface
// instance directly under `interfaces` whose packed tail expands.
func interfacePackedLeaf15032(ancestorPath [][]string, d *Node) bool {
	if d == nil || !d.IsLeaf || len(d.Keys) < 2 || len(d.Children) > 0 {
		return false
	}
	if len(ancestorPath) != 1 || len(ancestorPath[0]) != 1 || ancestorPath[0][0] != "interfaces" {
		return false
	}
	if nonInterfaceIfKeyword[d.Keys[0]] || isApplyStatementNode(d) {
		return false
	}
	body := packedBodyChildren(d, schemaInterfaces.wildcard)
	return len(body) > 0 && !sameNodes9855(body, d.Children)
}

// promoteInterfacePackedLeaf15032 rewrites d in place to its braced
// shape: Keys truncated to the interface name, expanded body as
// children. Caller must have checked interfacePackedLeaf15032.
func promoteInterfacePackedLeaf15032(d *Node) bool {
	if d == nil {
		return false
	}
	body := packedBodyChildren(d, schemaInterfaces.wildcard)
	if len(body) == 0 || sameNodes9855(body, d.Children) {
		return false
	}
	name := d.Keys[0]
	quoted := d.KeysQuoted
	bracketed := d.KeysBracketed
	d.Keys = []string{name}
	if len(quoted) > 0 {
		d.setKeysQuoted(quoted[:1])
	}
	if len(bracketed) > 0 {
		d.setKeysBracketed(bracketed[:1], d.BracketedClosed)
	}
	d.Children = body
	d.IsLeaf = false
	return true
}

// promoteInterfacePackedLeaves15032 promotes every packed interface
// leaf in dst (used before a container merge so sameKeyedContainers
// can find the inline instance).
func promoteInterfacePackedLeaves15032(ancestorPath [][]string, dst []*Node, budget *groupExpandBudget) {
	for _, d := range dst {
		if interfacePackedLeaf15032(ancestorPath, d) {
			if promoteInterfacePackedLeaf15032(d) && budget != nil {
				budget.notePromoted9855(d)
			}
		}
	}
}
