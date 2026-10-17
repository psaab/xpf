package config

// #14419 (DR15-H4): same-name `as-path` definitions across shapes.
//
// `policy-options as-path` is schema `args:2, multi:true, children:nil`,
// so namedLeafPeer9859 (children==nil) declines it and leafListPeer /
// isLeafListSchema (args<=1) decline it. A group definition therefore
// adopts beside an inline same-name definition whenever shapes differ
// (packed leaf vs braced container, either direction) and even for
// container/container when the regex child tokens differ. The compiler
// (compiler_routing.go) stores definitions in a name-keyed map with
// last-wins assignment in merged-tree order (inline first, group
// second), so the GROUP regex silently replaces the inline one.
//
// Junos apply-groups precedence is inline-wins for a scalar definition
// like an as-path regex, exactly as the both-packed pair already behaves
// (group leaf dropped via keyword-peer override). Treat a same-name
// as-path definition as ONE statement across shapes: a group definition
// whose name matches an existing inline (dst) definition contributes
// nothing. Different-name definitions are different statements and must
// still adopt in both directions.

// isASPathDefinition14419 reports whether node n at ancestorPath is a
// policy-options `as-path <name> ...` definition (either shape).
func isASPathDefinition14419(ancestorPath [][]string, n *Node) bool {
	if n == nil || len(n.Keys) < 2 || n.Keys[0] != "as-path" {
		return false
	}
	// Only the policy-options level: ancestorPath is the path to the
	// parent level, whose last element is ["policy-options", ...].
	if len(ancestorPath) == 0 {
		return false
	}
	last := ancestorPath[len(ancestorPath)-1]
	return len(last) > 0 && last[0] == "policy-options"
}

// asPathIsDefinition14419 reports whether s itself is an as-path definition.
func asPathIsDefinition14419(ancestorPath [][]string, s *Node) bool {
	return isASPathDefinition14419(ancestorPath, s)
}

// asPathSameNameInlinePeer14419 returns a dst node that is a same-name
// as-path definition as group source s, or nil. Name is Keys[1].
func asPathSameNameInlinePeer14419(ancestorPath [][]string, dst []*Node, s *Node) *Node {
	if !isASPathDefinition14419(ancestorPath, s) {
		return nil
	}
	for _, d := range dst {
		if d == nil || len(d.Keys) < 2 || d.Keys[0] != "as-path" {
			continue
		}
		if d.Keys[1] == s.Keys[1] {
			return d
		}
	}
	return nil
}
