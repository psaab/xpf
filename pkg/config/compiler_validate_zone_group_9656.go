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
// Four kinds of statement are left alone:
//   - A statement the fold moves into a body, such as
//     `security-zone trust screen edge;`, already has a child by the time this
//     runs.
//   - A braced group is compiled for every member by
//     bracketedGroupInstances8794 (#8794).
//   - An exact unbracketed `apply-macro` tail (`security-zone trust
//     apply-macro M`). No compiler consumes a macro, so it compiles exactly
//     like its braced spelling. Extra keys after M — or a bracketed zone
//     member hiding behind the same spelling, which names a zone rather than
//     a macro (#12828, #13094) — remain dropped content and are refused.
//   - A braced statement whose apply-macro header is not exactly
//     `… apply-macro <name>` (#13094): bracketedGroupInstances8794 hides that
//     body from every zone reader without checking a macro name is present,
//     so a missing name, extra trailing tokens, or the keyword sitting in the
//     zone-name slot drops authored content and is refused.
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
				if ch == nil || len(ch.Keys) < 3 || ch.Keys[0] != "security-zone" {
					continue
				}
				var msg string
				if len(ch.Children) > 0 {
					// #14343: a braced body whose header tail is not a
					// bracketed group fans out phantom zones in
					// bracketedGroupInstances8794. A valid group is either
					// authored bracketed or is the bracket-stripped form
					// Format emits (Keys[1:] are bare zone names and the
					// body holds only declared zone properties). Any other
					// tail token colliding with a declared zone child
					// (tcp-reset, screen, description, interfaces,
					// host-inbound-traffic, address-book, tcp-rst) is a
					// header token, not a zone name.
					if msg14343 := zoneUnbracketedHeaderToken14343(ch); msg14343 != "" {
						msg = msg14343
					} else if msg13094 := zoneMalformedApplyMacroHeader13094(ch); msg13094 != "" {
						// #13094: a braced statement whose apply-macro header is
						// malformed has its whole body hidden from zone readers by
						// bracketedGroupInstances8794, which never checks that a
						// macro name follows the keyword. Refuse the dropped body
						// instead of losing it silently.
						msg = msg13094
					}
					if msg == "" {
						continue
					}
				} else {
					// A complete unbracketed apply-macro tail is inert, but any
					// token beyond its single macro name — or a bracketed zone
					// member hiding behind the same spelling (#13094) — remains
					// dropped content and must be refused.
					if (len(ch.Keys) == 4 && ch.Keys[2] == "apply-macro" &&
						!ch.KeyBracketed(2) && !ch.KeyBracketed(3)) || !zoneTailDropsKeys9656(ch) {
						continue
					}
					msg = zoneTailMessage9656(ch)
				}
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

// zoneMalformedApplyMacroHeader13094 reports why a braced security-zone
// statement's apply-macro header drops authored content, or "" when every
// unbracketed apply-macro token on the header forms a complete
// `<zone> … apply-macro <name>` tail behind a zone name.
//
// bracketedGroupInstances8794 stops its fanout at the first unbracketed
// apply-macro token and hands zone readers a bodyless view of the statement,
// so a header that is not exactly that shape silently discards content
// (#13094, the #12828 residual):
//
//	security-zone trust apply-macro { … }          body dropped; no macro name
//	security-zone trust apply-macro M extra { … }  body and "extra" dropped
//	security-zone apply-macro M { … }              nothing compiles; no zone name
//
// A bracketed member named apply-macro is a zone name, not a macro statement
// (#12828), so bracket provenance gates every position; a tree without
// provenance keeps the conservative macro reading, matching
// bracketedGroupInstances8794.
func zoneMalformedApplyMacroHeader13094(ch *Node) string {
	for k := 1; k < len(ch.Keys); k++ {
		if ch.Keys[k] != "apply-macro" || ch.KeyBracketed(k) {
			continue
		}
		const advice = "Write security-zone <zone> { … } or security-zone <zone> apply-macro <name> { … } (#13094)"
		if k == 1 {
			return fmt.Sprintf("security zones security-zone %s: apply-macro is written in the zone-name slot, so no zone compiles and the braced body is dropped. %s",
				strings.Join(ch.Keys[1:], " "), advice)
		}
		if k+1 >= len(ch.Keys) {
			return fmt.Sprintf("security zones security-zone %s: apply-macro is missing its macro name, so the braced body never compiles as zone properties. %s",
				ch.Keys[1], advice)
		}
		if k+2 < len(ch.Keys) {
			rest := strings.Join(ch.Keys[k+2:], " ")
			if len(rest) > 80 {
				rest = rest[:80] + " …"
			}
			return fmt.Sprintf("security zones security-zone %s: apply-macro must be followed by exactly its macro name, and %q after macro name %q is dropped with the braced body. %s",
				ch.Keys[1], rest, ch.Keys[k+1], advice)
		}
		return ""
	}
	return ""
}

// zoneUnbracketedHeaderToken14343 reports a braced security-zone header
// whose unbracketed tail token is a declared zone child rather than a
// zone name, or "" when the header is a legitimate group.
//
// A legitimate unbracketed group is the bracket-stripped form Format
// emits for `security-zone [ a b ] { ... }`: it has already lost its
// bracket provenance, so it cannot be told from header garbage by
// provenance alone. The discriminator is the token itself: a zone may
// be named anything except a token the zone schema declares as a child
// keyword in that slot, because Junos reserves those words there and
// XPF's own fan-out would otherwise mint a phantom zone (e.g.
// `security-zone trust tcp-reset { ... }` created zone "tcp-reset").
// Bracketed members keep their names even when they collide (a zone
// literally named tcp-rst inside brackets, #9656 allowed row).
func zoneUnbracketedHeaderToken14343(ch *Node) string {
	if ch == nil || len(ch.Keys) < 3 || len(ch.Children) == 0 {
		return ""
	}
	zoneSchema := securityZoneSchema9792()
	if zoneSchema == nil {
		return ""
	}
	for i := 2; i < len(ch.Keys); i++ {
		if ch.KeyBracketed(i) {
			continue
		}
		tok := ch.Keys[i]
		// apply-macro tails are judged by zoneMalformedApplyMacroHeader13094.
		if tok == "apply-macro" {
			return ""
		}
		if _, isChild := zoneSchema.children[tok]; isChild {
			return fmt.Sprintf("security zones security-zone %s: header token %q is a security-zone child keyword, not a zone name, so it must not fan out a phantom zone or carry the braced body. Write security-zone %s { %s ...; } inside the zone body, security-zone [ a b ] { ... } for a zone group, or each zone as its own statement (#14343)",
				ch.Keys[1], tok, ch.Keys[1], tok)
		}
	}
	return ""
}
