package config

// zonesSchema9801 is the `security zones` schema node.
var zonesSchema9801 = schemaSecurity.children["zones"]

// groupNamedInstanceSchema9831 returns the schema of the statement that a group
// leaf with keyword key names under the container at ancestorPath, when that
// statement is a named instance. A named instance is a container whose identity
// includes instance args, such as `security-zone <name>` or
// `system syslog host <host>`. For anything else it returns nil, which leaves
// the leaf-list and scalar override paths unchanged.
func groupNamedInstanceSchema9831(ancestorPath [][]string, key string) *schemaNode {
	if key == "" {
		return nil
	}
	parent := schemaAtAncestorPath(ancestorPath)
	if parent == nil {
		return nil
	}
	cs := resolveSchemaChild(parent, key)
	if cs == nil || cs.args < 1 || (cs.children == nil && cs.wildcard == nil) {
		return nil
	}
	return cs
}

// sameInstancePeer9831 returns the inline node that the named-instance group
// leaf s merges into or is overridden by, or nil when s is adopted. The peer is
// the first node naming the same instance, meaning the same keyword and
// instance keys.
//
// #9831: leafListPeer matched on the keyword alone. So an inline
// `security-zone trust;` took the inline-wins override against a group's
// `security-zone zga;`, and zone zga was dropped. Measured at ed313e4c9: the
// group leaf compiled only when neither side was a leaf.
//
// A group leaf that carries keys past the instance it names is not made
// redundant by that instance's inline node, because the override would drop
// those keys:
//   - Against a braced peer, #7648 expands a packed statement into it.
//     Otherwise s is adopted, as it was before #9831, when no braced instance
//     matched. With an override there, `security-zone [ zga zgb ];` beside
//     `security-zone zga { tcp-rst; }` committed without zgb (0195e18b4);
//     master refused it.
//   - Against a leaf zone, s is adopted too. Duplicate zone statements compile
//     as one zone, and #9656 judges the extra keys exactly as it judges the
//     same text written inline (measured at ad2ba883a).
//   - Against any other leaf instance, the override stands. Adopting beside it
//     would compile a second instance: `host 10.0.0.1; host 10.0.0.1 any any;`
//     compiles two syslog destinations (measured at ad2ba883a).
func sameInstancePeer9831(ancestorPath [][]string, dst []*Node, s *Node, args int) *Node {
	n := 1 + args
	if len(s.Keys) < n {
		return nil
	}
	for _, d := range dst {
		if d == nil || len(d.Keys) < n || !keysEqual(d.Keys[:n], s.Keys[:n]) {
			continue
		}
		switch {
		case len(s.Keys) == n:
			return d
		case !d.IsLeaf && groupPackedLeafBody(ancestorPath, s) != nil:
			return d
		case !d.IsLeaf:
			return nil
		case s.Keys[0] == "security-zone" && underZones9801(ancestorPath):
			return nil
		default:
			return d
		}
	}
	return nil
}

// zoneLeafTakesWildcard9801 reports whether a wildcard group source may merge
// into the leaf destination d. It may when d is a `security-zone <name>`
// statement with no body, directly under `security zones`.
//
// #9801: a zone written as a leaf compiles as the same zone as its braced
// spelling, but the wildcard merge visited only non-leaf destinations, so the
// leaf lost the group's statements. Measured at 36dfa8e5a with
// `security-zone <*> { screen edge; }` applied: `security-zone trust;`
// compiled ScreenProfile="", and `security-zone trust { }` compiled "edge".
//
// The scope is zones on purpose. An interface or a routing instance written as
// a leaf compiles no instance at all (#9838). Letting a wildcard group turn it
// into a container would create the instance only when a group applies.
func zoneLeafTakesWildcard9801(ancestorPath [][]string, d *Node) bool {
	return len(d.Keys) == 2 && d.Keys[0] == "security-zone" && underZones9801(ancestorPath)
}

// underZones9801 reports whether ancestorPath is the `security zones`
// container.
func underZones9801(ancestorPath [][]string) bool {
	return schemaAtAncestorPath(ancestorPath) == zonesSchema9801
}
