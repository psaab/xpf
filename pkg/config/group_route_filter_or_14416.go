package config

import "strings"

// #14416 (DR15-H1): `route-filter` under a routing policy-statement
// term `from` is a Junos OR-member list, not a scalar. The schema
// documents it as such (schema_routing.go: prefix-list / route-filter /
// community / as-path "may all be repeated within one term (Junos OR's
// repeated same-type `from` matches)"), and the compiler appends EVERY
// sibling route-filter into term.RouteFilters. But the apply-groups
// leaf merge could not union it: leafListUnionEligible requires
// args <= 1 and route-filter is args:2 (prefix + match-type), while the
// packed-peer promotion paths require a children-bearing schema node
// and route-filter has none. A group route-filter beside an inline
// route-filter therefore fell through to the inline-wins override and
// was silently dropped — a reject term written in two halves matched
// only the inline half, and the group half's prefixes fell through to
// the next term.
//
// The helpers below give route-filter the member-level treatment the
// schema already promises, without widening the generic args>=2
// override: only this keyword, only at a policy-term `from`, and only
// when the full member (prefix + match-type + optional trailing
// upto/prefix-length-range/through token) is not already present
// inline. mergeLeafListInto is deliberately NOT reused: it unions
// Keys[1:] token streams, which would mash two (prefix, match-type)
// pairs into one corrupt leaf. Adoption appends the group leaf beside
// the inline peer as a distinct sibling — exactly the shape SetPath
// and the brace parser produce for repeated inline route-filters.

// isRouteFilterORMember14416 reports whether s is a route-filter leaf
// standing at a policy-statement term `from` level. The schema check
// is primary: it resolves only where the modelled grammar declares
// route-filter as the args:2 multi leaf. The ancestor-shape fallback
// covers the same statement reached through a path the schema walk
// cannot resolve (e.g. a routing-instance nesting), keyed on the
// exact policy-statement/term/from tail so no other `from` qualifies.
func isRouteFilterORMember14416(ancestorPath [][]string, s *Node) bool {
	if s == nil || len(s.Keys) < 3 || s.Keys[0] != "route-filter" {
		return false
	}
	if parent := schemaAtAncestorPath(ancestorPath); parent != nil {
		if leaf := resolveSchemaChild(parent, "route-filter"); leaf != nil {
			return leaf.multi && leaf.children == nil && leaf.args == 2
		}
	}
	n := len(ancestorPath)
	if n < 3 {
		return false
	}
	return len(ancestorPath[n-3]) > 0 && ancestorPath[n-3][0] == "policy-statement" &&
		len(ancestorPath[n-2]) > 0 && ancestorPath[n-2][0] == "term" &&
		len(ancestorPath[n-1]) > 0 && ancestorPath[n-1][0] == "from"
}

// routeFilterMemberIdentity14416 is the full OR-member identity of a
// route-filter node: every key after the keyword (prefix, match-type,
// and a Keys-carried trailing modifier), plus the trailing modifier
// when it arrives as a first child instead (the flat-set SetPath
// shape routeFilterTrailingToken also reads). Two members with the
// same prefix but different match-types — or the same match-type with
// different upto/range/through tails — are distinct members.
func routeFilterMemberIdentity14416(n *Node) string {
	if n == nil || len(n.Keys) == 0 {
		return ""
	}
	id := strings.Join(n.Keys[1:], "\x00")
	if len(n.Keys) < 4 {
		if tok := routeFilterTrailingToken(n); tok != "" {
			id += "\x00" + tok
		}
	}
	return id
}

// routeFilterMemberExists14416 reports whether dst already holds a
// route-filter sibling carrying src's full member identity. A
// duplicate keeps the existing inline-wins drop (dedup, not
// duplication); a distinct member is adopted beside the inline peer.
func routeFilterMemberExists14416(dst []*Node, src *Node) bool {
	want := routeFilterMemberIdentity14416(src)
	for _, d := range dst {
		if d == nil || len(d.Keys) == 0 || d.Keys[0] != "route-filter" {
			continue
		}
		if routeFilterMemberIdentity14416(d) == want {
			return true
		}
	}
	return false
}

// #14741: cross-twin dedup for the adoption above. One group body is
// merged once per same-keyed destination container at a level (#9802
// fan-out routes the same body into every policy-statement/term/from
// twin), and each merge sees only its own twin's children, so
// routeFilterMemberExists14416 cannot see a sibling adopted into
// another twin of the same `from` level. The compiler folds the
// twins' from bags into one term, so adopting into both twins
// duplicates the member. The expansion budget records (destination
// level, member identity) for every adoption; the second merge into
// a twin of the same level is then a no-op. The destination level is
// keyed by ancestor path (which carries the term identity) plus the
// inline peer's member identity: twins of one level are merged
// against peers carrying the same inline member, while distinct
// terms and distinct inline members never collide.
func routeFilterLevelKey14741(ancestorPath [][]string, peer *Node) string {
	var b strings.Builder
	for _, pk := range ancestorPath {
		b.WriteString(strings.Join(pk, "\x1f"))
		b.WriteByte('\x1e')
	}
	if peer != nil {
		b.WriteString(routeFilterMemberIdentity14416(peer))
	}
	return b.String()
}

// routeFilterAlreadyAdopted14741 reports whether this expansion has
// already adopted src's member at the destination level peer stands
// in. A nil budget (direct mergeNodes callers in tests) never
// suppresses: those callers merge once per level by construction.
func (b *groupExpandBudget) routeFilterAlreadyAdopted14741(ancestorPath [][]string, peer, src *Node) bool {
	if b == nil || len(b.adoptedRouteFilters14741) == 0 {
		return false
	}
	members := b.adoptedRouteFilters14741[routeFilterLevelKey14741(ancestorPath, peer)]
	return members[routeFilterMemberIdentity14416(src)]
}

// recordRouteFilterAdopted14741 notes src's adoption at peer's level.
func (b *groupExpandBudget) recordRouteFilterAdopted14741(ancestorPath [][]string, peer, src *Node) {
	if b == nil {
		return
	}
	if b.adoptedRouteFilters14741 == nil {
		b.adoptedRouteFilters14741 = map[string]map[string]bool{}
	}
	key := routeFilterLevelKey14741(ancestorPath, peer)
	members := b.adoptedRouteFilters14741[key]
	if members == nil {
		members = map[string]bool{}
		b.adoptedRouteFilters14741[key] = members
	}
	members[routeFilterMemberIdentity14416(src)] = true
}
