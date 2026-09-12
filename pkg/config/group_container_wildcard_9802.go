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
func pruneWildcardInstances9802(ancestorPath [][]string, nodes []*Node) []*Node {
	out := nodes[:0:0]
	for _, n := range nodes {
		if n == nil {
			continue
		}
		if wildcardInstanceNode9802(ancestorPath, n) {
			continue
		}
		if len(n.Children) > 0 {
			n.Children = pruneWildcardInstances9802(appendPath(ancestorPath, n.Keys), n.Children)
		}
		out = append(out, n)
	}
	return out
}

// wildcardInstanceNode9802 reports whether n is a wildcard-keyed node standing
// where an INSTANCE NAME goes, so nothing in the destination could ever have
// named it. Those are dropped from a wholesale-adopted subtree; everything else
// is adopted unchanged.
//
// The first cut keyed on the node's SHAPE (`!IsLeaf || len(Keys) >= 2`) and was
// wrong in the silent direction. Measured at ef390f3ac against 4cc9b66e6:
//
//	description "<*>";            kept  -> DROPPED   (an ordinary scalar value)
//	interfaces <ge-*>;  (compact) refused -> COMMITS  (a zone MEMBER, and the
//	                                         strict refusal naming the token
//	                                         disappeared with it)
//
// Both are two-key leaves, which is why a shape rule cannot separate them from
// `security-zone <*>;`. The schema can: an instance name is an ARG of a
// container-shaped child, while `description` is a scalar and a zone's
// `interfaces` member slot takes no args at all (its wildcard child IS the
// member). So the test is:
//
//   - a wildcard-keyed CONTAINER, which the wildcard branch would have fanned
//     out had the destination existed; or
//   - a wildcard inside the IDENTITY SPAN (keyword plus args) of a child the
//     schema declares with `args >= 1` and children or a wildcard of its own.
//
// A wildcard anywhere else is a value or a member, and is left alone: the
// compiler's own checks judge it exactly as they judge the braced spelling
// (#9423).
func wildcardInstanceNode9802(ancestorPath [][]string, n *Node) bool {
	if n == nil || len(n.Keys) == 0 || !keysContainWildcard(n.Keys) {
		return false
	}
	if !n.IsLeaf {
		return true
	}
	parent := schemaAtAncestorPath(ancestorPath)
	if parent == nil {
		return false
	}
	// Container-shaped is the whole test. `scalar` and an args floor were tried
	// beside it and are redundant: a scalar declares no children or wildcard, and
	// an args-0 child leaves an EMPTY identity span below, which no wildcard can
	// sit inside. The matrix showed both as escapes, so they are gone rather than
	// carried as conditions nothing can break.
	cs := resolveSchemaChild(parent, n.Keys[0])
	if cs == nil || (cs.children == nil && cs.wildcard == nil) {
		return false
	}
	span := 1 + cs.args
	if span > len(n.Keys) {
		span = len(n.Keys)
	}
	return keysContainWildcard(n.Keys[1:span])
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
func receivingContainer9802(targets []*Node, child *Node) *Node {
	if child == nil || len(child.Keys) == 0 {
		return targets[0]
	}
	// An exact key match first: `from-zone trust to-zone untrust` must not be
	// captured by a stanza holding `from-zone trust to-zone dmz`.
	for _, d := range targets {
		for _, dc := range d.Children {
			if dc != nil && keysEqual(dc.Keys, child.Keys) {
				return d
			}
		}
	}
	for _, d := range targets {
		for _, dc := range d.Children {
			if dc != nil && len(dc.Keys) > 0 && dc.Keys[0] == child.Keys[0] {
				return d
			}
		}
	}
	return targets[0]
}
