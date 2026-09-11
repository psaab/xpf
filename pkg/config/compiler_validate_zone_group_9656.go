package config

import (
	"fmt"
	"strings"
)

// zonesSchema9656 is the `security zones` schema node.
var zonesSchema9656 = schemaSecurity.children["zones"]

// zoneGroupMembers9656 counts the zones that a body-less security-zone
// statement names. They are the tokens after `security-zone`, up to the first
// keyword the security-zone schema declares or an apply statement keyword. #9685
// declares no apply keyword inside a zone.
//
// Brackets are not consulted. Format drops them from every node and FormatSet
// drops them from a leaf, so a peer compiling the rendered text must reach the
// same verdict.
func zoneGroupMembers9656(ch *Node, zone *schemaNode) int {
	j := 1
	for j < len(ch.Keys) && zone.children[ch.Keys[j]] == nil && !isApplyStatementKeyword(ch.Keys[j]) {
		j++
	}
	return j - 1
}

// validateZoneGroupsHaveBody9656 refuses a security-zone statement that names
// two or more zones without a non-empty braced body.
//
// #9656 (M40): measured at e09f425dd, strict commit accepted each of these. Each
// compiled only zone zga, through namedInstances:
//
//	security-zone [ zga zgb ] screen edge;          zga without its screen, no zgb
//	security-zone [ zga zgb ];                      no zgb
//	security-zone [ zga zgb ] { }                   no zgb
//	security-zone [ zga zgb ] { apply-groups G; }   no zgb; expansion empties the body
//
// A group with a non-empty body is left alone. bracketedGroupInstances8794
// compiles it for every member (#8794).
//
// Why refuse rather than expand: an earlier cut expanded each group into one
// statement per zone in the #8662 normalizer. Three review rounds found the
// per-member statements it materialised colliding with the node budgets
// downstream:
//   - clones with no bound;
//   - a budget kept per `zones` node;
//   - a group subtree pushed past the apply-groups work budget, so one cluster
//     node's tolerant load failed;
//   - cloned bodies that grew again under normalization;
//   - a second normalization with a fresh budget.
//
// The braced spelling already compiles for every member, and the #9656
// acceptance allows a strict refusal that names the spelling.
//
// This check reads the group-expanded, inactive-pruned tree that
// runPreWalkGates is given. A body that group expansion emptied is therefore
// refused, and an inactive group is not. Strict commit refuses. The tolerant
// load and peer-sync paths warn and compile the statement as before, so a
// persisted configuration still boots (#1960).
func validateZoneGroupsHaveBody9656(nodes []*Node, lenient bool) ([]string, error) {
	zone := zonesSchema9656.children["security-zone"]
	var warnings []string
	for _, sec := range nodes {
		if sec == nil || len(sec.Keys) != 1 || sec.Keys[0] != "security" {
			continue
		}
		for _, zs := range sec.Children {
			if zs == nil || len(zs.Keys) != 1 || zs.Keys[0] != "zones" {
				continue
			}
			for _, ch := range zs.Children {
				if ch == nil || len(ch.Keys) < 3 || ch.Keys[0] != "security-zone" || len(ch.Children) > 0 {
					continue
				}
				members := zoneGroupMembers9656(ch, zone)
				if members < 2 {
					continue
				}
				msg := zoneGroupMessage9656(ch, members)
				if !lenient {
					return nil, fmt.Errorf("%s", msg)
				}
				warnings = append(warnings, msg)
			}
		}
	}
	return warnings, nil
}

// zoneGroupMessage9656 names the statement, the zones it names (at most three),
// and the spellings that compile every one of them.
func zoneGroupMessage9656(ch *Node, members int) string {
	names := ch.Keys[1 : 1+members]
	shown := strings.Join(names[:min(len(names), 3)], " ")
	if len(names) > 3 {
		shown += " …"
	}
	stmt := strings.Join(ch.Keys, " ")
	if len(stmt) > 120 {
		stmt = stmt[:120] + " …"
	}
	body := "without a braced body"
	if !ch.IsLeaf {
		body = "with an empty braced body"
	}
	fix := "Write one security-zone statement per zone."
	if tail := strings.Join(ch.Keys[1+members:], " "); tail != "" {
		fix = fmt.Sprintf("Put the shared statement in braces, security-zone [ %s ] { %s; }, or write one statement per zone.", shown, tail)
	}
	return fmt.Sprintf("security zones %s: names %d zones (%s) %s, and would compile only zone %q. %s (#9656)",
		stmt, members, shown, body, names[0], fix)
}
