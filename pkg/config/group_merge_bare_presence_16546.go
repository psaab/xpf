package config

// Bare presence leaf beside a group container (#16546).
//
// A body-less presence statement (`ssh;`, `syslog;`, `rip;`) is the same
// statement as its empty braced spelling (`ssh { }`): it states that the
// container exists and carries no values of its own. The braced spelling
// merges a group's container children recursively, so the bare spelling
// must too.
//
// Before this fix the #4325 cross-shape guard in mergeNodes saw only that
// a leaf shared Keys[0] with the group's single-key container and dropped
// the whole container. A bare `set system services ssh` beside a hardening
// group therefore silently voided the group's root-login deny, ciphers
// and connection-limit; the same shape dropped group syslog hosts, SNMP
// and LLDP settings.
//
// The fix promotes a bare leaf to an empty container (the #9801-style
// promotion) and merges the group's children into it with ordinary inline
// precedence, but only when every gate below holds:
//
//   - the group source is a single-key container with children, and the
//     inline peer is a bare leaf: exactly one key, no children, and no
//     bracketed value list (`ssh [ ... ];` carries values, so it is not a
//     presence statement);
//   - the schema node for the key is a plain container (children present,
//     not a value-list, not multi, no instance args): a leaf-list key is
//     owned by the #4070/#4325 union path, a groupReplace port by its own
//     path, and a named instance (`host 10.0.0.1;`, span >= 2) keeps its
//     existing identity handling — promotion here is for the bare keyword
//     alone;
//   - none of the specialised shapes that already own this peerage apply:
//     wildcards, zone leaves, the default-policy choice pair, and routing
//     term then-actions all keep their existing arms.
//
// A leaf that carries values (a packed tail such as
// `authentication md5 1;`, a bracketed list, or a collapsed leaf-list such
// as `name-server 9.9.9.9;`) is NOT a presence statement: the #4325 guard
// keeps firing for it exactly as before, so a valued inline statement
// still suppresses (or, for leaf-lists, unions into) the group container
// and no duplicate node is emitted.

// barePresenceContainerSchema16546 reports whether the single-key group
// container s may merge into a bare presence peer at this schema level:
// the key resolves to a plain args==0 container and no specialised shape
// owns the peerage.
func barePresenceContainerSchema16546(ancestorPath [][]string, s *Node) bool {
	if s == nil || s.IsLeaf || len(s.Keys) != 1 || len(s.Children) == 0 {
		return false
	}
	if keysContainWildcard(s.Keys) || groupZoneLeaf9831(ancestorPath, s) ||
		isDefaultPolicyGroupStanza12923(ancestorPath, s) ||
		isDefaultPolicyGroupBlock12823(ancestorPath, s) ||
		isRoutingTermThenAction14425(ancestorPath, s) ||
		isRoutingTermThenNextPolicy15259(ancestorPath, s) {
		return false
	}
	if isLeafListSchema(ancestorPath, s.Keys[0]) ||
		isGroupReplacePortSchema(ancestorPath, s.Keys[0]) {
		return false
	}
	parent := schemaAtAncestorPath(ancestorPath)
	if parent == nil {
		return false
	}
	leafSchema := resolveSchemaChild(parent, s.Keys[0])
	return leafSchema != nil && leafSchema.children != nil &&
		!leafSchema.valueList && !leafSchema.multi && leafSchema.args == 0
}

// barePresenceLeaf16546 reports whether n is a bare presence leaf: one
// key, no children, and no bracketed value list packed onto the key.
func barePresenceLeaf16546(n *Node) bool {
	if n == nil || !n.IsLeaf || len(n.Keys) != 1 || len(n.Children) != 0 {
		return false
	}
	if n.BracketedClosed {
		return false
	}
	for i := range n.Keys {
		if n.KeyBracketed(i) {
			return false
		}
	}
	return true
}

// barePresenceContainerPeer16546 finds the inline bare presence leaf peer
// for group container s and, if admissible, promotes it in place to the
// empty container its braced spelling is. It returns the promoted peer,
// or nil when the existing guard/adopt behaviour must stand.
func barePresenceContainerPeer16546(ancestorPath [][]string, dst []*Node, s *Node) *Node {
	if !barePresenceContainerSchema16546(ancestorPath, s) {
		return nil
	}
	for _, d := range dst {
		if barePresenceLeaf16546(d) && d.Keys[0] == s.Keys[0] {
			d.IsLeaf = false
			d.Children = nil
			return d
		}
	}
	return nil
}

// barePresenceGuardExempts16546 reports whether the #4325 guard must not
// drop the single-key group container s beside a bare presence leaf in
// dst. It is the guard-side twin of barePresenceContainerPeer16546: the
// promotion arm above handles the merge whenever it can, and this
// exemption keeps the guard from discarding the container on any path
// where promotion did not run. A valued leaf never exempts.
func barePresenceGuardExempts16546(ancestorPath [][]string, dst []*Node, s *Node) bool {
	if !barePresenceContainerSchema16546(ancestorPath, s) {
		return false
	}
	for _, d := range dst {
		if barePresenceLeaf16546(d) && d.Keys[0] == s.Keys[0] {
			return true
		}
	}
	return false
}
