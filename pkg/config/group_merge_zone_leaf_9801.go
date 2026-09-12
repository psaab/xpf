package config

// zonesSchema9801 is the `security zones` schema node.
var zonesSchema9801 = schemaSecurity.children["zones"]

// underZones9801 reports whether ancestorPath is the `security zones`
// container.
func underZones9801(ancestorPath [][]string) bool {
	return schemaAtAncestorPath(ancestorPath) == zonesSchema9801
}

// groupZoneLeaf9831 reports whether the group leaf s is a `security-zone <name>`
// statement directly under `security zones`.
func groupZoneLeaf9831(ancestorPath [][]string, s *Node) bool {
	return len(s.Keys) >= 2 && s.Keys[0] == "security-zone" && underZones9801(ancestorPath)
}

// zoneGroupLeafPeer9831 returns the inline node that the group zone statement s
// merges into or is overridden by, or nil when s is adopted. The peer is the
// first inline statement naming the same zone.
//
// #9831: leafListPeer matched on the keyword alone. So an inline
// `security-zone trust;` took the inline-wins override against a group's
// `security-zone zga;`, and zone zga was dropped. Measured at ed313e4c9: the
// group leaf compiled only when neither side was a leaf.
//
// A group statement that carries keys past the zone name is not made redundant
// by that zone's inline statement, because the override would drop those keys.
// Against a braced zone, #7648 expands a packed statement into it. Otherwise s
// is adopted, as master adopted it beside a braced zone. The #9656
// zone-statement check then judges the extra keys as it judges the same text
// written inline, and duplicate zone statements compile as one zone (#4818).
//
// The rule is scoped to zones on purpose. A zone name compiles as written, and a
// zone statement carries no value list. Two review rounds found a
// schema-generic version misclassifying other named instances:
//   - value lists: `next-hop [ a b ]` compiled a duplicate hop;
//   - named containers marked `multi`, such as `class-of-service schedulers`;
//   - keys the compiler canonicalises: `ospf area 0` against `area 0.0.0.0`.
//
// Those keep the keyword override and are tracked in #9859.
func zoneGroupLeafPeer9831(ancestorPath [][]string, dst []*Node, s *Node) *Node {
	for _, d := range dst {
		if d == nil || len(d.Keys) < 2 || d.Keys[0] != "security-zone" || d.Keys[1] != s.Keys[1] {
			continue
		}
		switch {
		case len(s.Keys) == 2:
			return d
		case !d.IsLeaf && groupPackedLeafBody(ancestorPath, s) != nil:
			return d
		default:
			return nil
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
