package config

// Wildcard-keyed nodes inside a WHOLESALE-adopted group container — #9802.
//
// `mergeNodes` adopts a group container wholesale when the destination has no
// same-keyed container (`*dst = append(*dst, s)`). The adopted subtree is never
// recursed into, so a wildcard-keyed node inside it is never matched against
// anything: it lands in the tree as a literal instance name. Measured at
// ef390f3ac, with `groups { G { security { zones { security-zone <*> { tcp-rst; } } } } }`
// applied by a top-level `apply-groups G;`:
//
//	target `security { screen { … } }` with no `zones`  ->  a compiled zone named `<*>`
//	target with no `interfaces` at all                  ->  a compiled interface named `<*>`
//
// That is the #9423 defect reached by a different route. #9423 fixed the
// MATCHER, so a pattern that matches nothing "applies nothing, invents
// nothing"; its fixtures all put the parent container in the target, so the
// wildcard reaches the wildcard branch. When the parent container is absent,
// the wildcard never reaches that branch at all.
//
// A wildcard-keyed node in an adopted subtree matched nothing by construction:
// there was no destination container for it to match. It is therefore dropped,
// which is what the wildcard branch does for a pattern with no match.
//
// SCOPE: only a wildcard in an INSTANCE-NAME position is dropped. A wildcard in
// a MEMBER slot is not an instance key and must stay loudly refused, which is
// what `TestGroupKeyWildcardLeafMemberStillRefused9423` pins. Measured at
// ef390f3ac, a group zone carrying `interfaces { <ge-*>; }` is refused on strict
// through wholesale adoption too:
//
//	security zone "trust" references interface "<ge-*>", which is not defined …
//
// Dropping that member would turn a loud refusal into a silent one, so the
// predicate below excludes leaf-list (member) slots and any key position the
// schema does not model as an instance name.
func pruneWildcardInstances9802(nodes []*Node) []*Node {
	out := nodes[:0:0]
	for _, n := range nodes {
		if n == nil {
			continue
		}
		if wildcardInstanceNode9802(n) {
			continue
		}
		if len(n.Children) > 0 {
			n.Children = pruneWildcardInstances9802(n.Children)
		}
		out = append(out, n)
	}
	return out
}

// wildcardInstanceNode9802 reports whether n is a wildcard-keyed node that the
// wildcard branch would have fanned out, had the destination container existed.
// Those matched nothing by construction and are dropped.
//
// The discriminator is the node's SHAPE, not the schema. The schema cannot tell
// the two cases apart: a zone's `interfaces` member slot is declared as a
// wildcard child WITH children (schema_security.go), exactly like a dynamic
// instance name, so a schema-shape predicate prunes the member too. Measured at
// ef390f3ac + that predicate, `interfaces { <ge-*>; }` inside an adopted group
// zone stopped being refused and committed clean — a loud refusal turned
// silent.
//
//   - A wildcard-keyed CONTAINER is what `mergeNodes` routes to the wildcard
//     branch (that branch runs only for non-leaf sources), so with no
//     destination it applied nothing: `security-zone <*> { tcp-rst; }`,
//     `<*> { description … }`.
//   - A wildcard-keyed LEAF carrying an instance name (keyword plus the
//     wildcard, two or more keys) is the bodyless spelling of the same thing:
//     `security-zone <*>;`.
//   - A single-key wildcard LEAF is a MEMBER, not an instance key:
//     `interfaces { <ge-*>; }` inside a zone. It takes the leaf branch, is
//     adopted as it is today, and stays loudly refused by the compiler's
//     interface-reference check (#9423).
func wildcardInstanceNode9802(n *Node) bool {
	if n == nil || len(n.Keys) == 0 || !keysContainWildcard(n.Keys) {
		return false
	}
	return !n.IsLeaf || len(n.Keys) >= 2
}

// sameKeyedContainers9802 returns every destination container a group container
// with these keys could merge into. A level spread over two blocks is one
// hierarchy level to the operator and to the compiler, which is the rule
// `siblingsExcludeGroup` already applies to `apply-groups-except` (#9422).
func sameKeyedContainers9802(dst []*Node, keys []string) []*Node {
	var out []*Node
	for _, d := range dst {
		if d != nil && !d.IsLeaf && keysEqual(d.Keys, keys) {
			out = append(out, d)
		}
	}
	return out
}

// splitWildcardChildren9802 divides a group container's body into the
// wildcard-keyed children, which every same-keyed destination must see, and the
// rest, which exactly one destination receives.
//
// #9802: merging the whole body into every sibling would duplicate the concrete
// blocks. Measured at ef390f3ac, a group body can carry both
// (`zones { security-zone zg { } security-zone <*> { tcp-rst; } }`).
func splitWildcardChildren9802(children []*Node) (wild, rest []*Node) {
	for _, c := range children {
		if c != nil && keysContainWildcard(c.Keys) {
			wild = append(wild, c)
			continue
		}
		rest = append(rest, c)
	}
	return wild, rest
}

// receivingContainer9802 picks the destination container that already holds a
// match for one of the group body's children, or the first one.
//
// #9802: `mergeNodes` merged into the FIRST same-keyed container and stopped, so
// a group `security { zones { … } }` landed in a `security` stanza that holds
// only `screen`, and the zones in a second stanza never saw the group. Measured
// at ef390f3ac: with the stanzas in that order, `trust` compiled without the
// group's statement.
func receivingContainer9802(targets []*Node, children []*Node) *Node {
	for _, d := range targets {
		for _, c := range children {
			if c == nil || len(c.Keys) == 0 {
				continue
			}
			for _, dc := range d.Children {
				if dc == nil || len(dc.Keys) == 0 {
					continue
				}
				if keysEqual(dc.Keys, c.Keys) || dc.Keys[0] == c.Keys[0] {
					return d
				}
			}
		}
	}
	return targets[0]
}
