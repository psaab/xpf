package config

import (
	"fmt"
	"strings"
)

// validateZoneStatementTails9656 refuses a security-zone statement whose keys
// after the zone name would be dropped.
//
// Every reader of a zone goes through bracketedGroupInstances8794. For a
// statement with no braced body, that reads only Keys[1], so whatever follows
// the name reaches no compiler. That covers both further zone names and a
// statement the #8662 fold did not move into a body. Measured at 6cf4305ab,
// after normalization and group expansion:
//
//	security-zone [ zga zgb ] screen edge;          only zga, without its screen (#9656 M40)
//	security-zone [ zga zgb ];                      only zga
//	security-zone [ zga zgb ] { }                   only zga
//	security-zone [ zga zgb ] { apply-groups G; }   only zga; expansion empties the body
//	security-zone [ tcp-rst zgb ];                  only tcp-rst
//	security-zone trust apply-groups G;             trust without G (#9788)
//	security-zone trust scren edge;                 trust; the mistyped statement is dropped
//
// Three kinds of statement are left alone:
//   - A statement the fold moves into a body, such as
//     `security-zone trust screen edge;`, already has a child by the time this
//     runs.
//   - A braced group is compiled for every member by
//     bracketedGroupInstances8794 (#8794).
//   - A repeat of the name, as in `security-zone [ zga zga ];`, loses nothing.
//
// Why a refusal: an earlier cut expanded groups in the normalizer, and three
// review rounds found the per-member statements it materialised colliding with
// the node budgets downstream. The #9656 acceptance allows a strict refusal that
// names the spelling.
//
// This check reads the group-expanded, inactive-pruned tree that runPreWalkGates
// is given. Strict commit refuses. The tolerant load and peer-sync paths warn
// and compile the statement as before, so a persisted configuration still boots
// (#1960).
func validateZoneStatementTails9656(nodes []*Node, lenient bool) ([]string, error) {
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
				if !zoneTailDropsKeys9656(ch) {
					continue
				}
				msg := zoneTailMessage9656(ch)
				if !lenient {
					return nil, fmt.Errorf("%s", msg)
				}
				warnings = append(warnings, msg)
			}
		}
	}
	return warnings, nil
}

// zoneTailDropsKeys9656 reports whether a childless security-zone statement
// carries a key after the name that is not a repeat of the name.
func zoneTailDropsKeys9656(ch *Node) bool {
	for _, k := range ch.Keys[2:] {
		if k != ch.Keys[1] {
			return true
		}
	}
	return false
}

// zoneTailMessage9656 names the zone that compiles and the text that is dropped.
func zoneTailMessage9656(ch *Node) string {
	rest := strings.Join(ch.Keys[2:], " ")
	if len(rest) > 80 {
		rest = rest[:80] + " …"
	}
	written := "without a braced body"
	if !ch.IsLeaf {
		written = "with an empty braced body"
	}
	return fmt.Sprintf("security zones security-zone %s: written %s, only zone %q compiles, and %q is dropped. Group zones with a braced body (security-zone [ a b ] { … }), write each zone as its own statement, or put the statement in braces (#9656)",
		ch.Keys[1], written, ch.Keys[1], rest)
}
