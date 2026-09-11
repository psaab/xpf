package config

import (
	"fmt"
	"strings"
)

// zonesSchema9656 is the `security zones` schema node. `groups` mirrors reach
// the same pointer, so the fan-out applies inside a group body as well.
var zonesSchema9656 = schemaSecurity.children["zones"]

// zoneGroupPass9656 carries the zone-group fan-out budget for one normalization
// of a tree. The budget spans every `zones` node the walk reaches. The #9656
// round-2 review measured a per-`zones` budget failing: 83 group stanzas, each
// under the limit, cloned 16.6 million nodes from a 15.84 MiB configuration of
// 332 parsed nodes.
type zoneGroupPass9656 struct {
	budget, spent int
}

func newZoneGroupPass9656() *zoneGroupPass9656 {
	return &zoneGroupPass9656{budget: maxParseNodes}
}

// zoneGroupSplit9656 returns how many keys after `security-zone` name zones, and
// the index where a packed statement tail starts. The tail index is
// len(ch.Keys) when there is no tail.
//
// With a non-empty braced body, every token names a zone. That is #8794's
// reading, and it keeps `security-zone [ zga zgb host-inbound-traffic ]
// { tcp-rst; }` as three zones. Two #9656 review rounds found the alternative,
// reading a keyword before the body as the body's head, losing a zone named
// after that keyword (`tcp-rst`, `screen`, `host-inbound-traffic`, `interfaces`,
// `apply-macro`). A body therefore admits no tail at all.
//
// A leaf, or an empty `{ }`, which FormatSet renders the same way, has no body
// to decide with. Its members are the tokens before the first keyword the
// security-zone schema declares, or before an apply statement keyword. #9685
// declares none of those inside a zone. The remaining tokens are a packed
// statement tail.
func zoneGroupSplit9656(ch *Node, zone *schemaNode) (members, tail int) {
	n := len(ch.Keys)
	if len(ch.Children) > 0 {
		return n - 1, n
	}
	j := 1
	for j < n && zone.children[ch.Keys[j]] == nil && !isApplyStatementKeyword(ch.Keys[j]) {
		j++
	}
	return j - 1, j
}

// expandZoneGroups9656 fans every security-zone group under a `zones` node out
// into one zone statement per member. The result has the shape the longhand
// spelling parses to, and group expansion and validation read it that way.
//
// #9656 (M40): a group was fanned out only by bracketedGroupInstances8794, and
// only when the node had a braced body. Measured at e09f425dd, strict commit
// accepted each of these without error:
//
//	security-zone [ zga zgb ] screen edge;   zone zga with no screen, and no zgb
//	security-zone [ zga zgb ];               no zgb
//	security-zone [ zga zgb ] { }            no zgb
//
// Members and tail follow zoneGroupSplit9656. Each member gets the tail, or its
// own clone of the braced body.
//
// Brackets are not consulted. Format drops them from every node and FormatSet
// from a leaf, so a peer that re-parses the rendered text must reach the same
// zones without them.
//
// The whole cost, members × (1 + body nodes + tail), is charged against the
// pass budget before anything is cloned (countNodes), as group expansion does
// for its clones. A group that does not fit is left as parsed, and
// validateZoneGroupsExpanded9656 refuses it on strict. A statement with a
// single member is left for the scoped fold.
func expandZoneGroups9656(zones *Node, zone *schemaNode, pass *zoneGroupPass9656) int {
	if zones == nil || zone == nil || pass == nil {
		return 0
	}
	var out []*Node
	changed := 0
	for _, ch := range zones.Children {
		if ch == nil || len(ch.Keys) < 3 || ch.Keys[0] != "security-zone" {
			out = append(out, ch)
			continue
		}
		n := len(ch.Keys)
		members, j := zoneGroupSplit9656(ch, zone)
		if members < 2 {
			out = append(out, ch)
			continue
		}
		perMember := 1 + countNodes(ch.Children)
		if j < n {
			perMember++
		}
		if pass.spent+members*perMember > pass.budget {
			out = append(out, ch)
			continue
		}
		pass.spent += members * perMember
		quoted := keyMask8921(ch.KeysQuoted, n)
		bracketed := keyMask8921(ch.KeysBracketed, n)
		for k := 1; k < j; k++ {
			z := &Node{
				Keys:          []string{ch.Keys[0], ch.Keys[k]},
				IsLeaf:        ch.IsLeaf,
				Annotation:    ch.Annotation,
				InheritedFrom: ch.InheritedFrom,
				Inactive:      ch.Inactive,
				Line:          ch.Line,
				Column:        ch.Column,
			}
			if quoted != nil {
				z.setKeysQuoted([]bool{quoted[0], quoted[k]})
			}
			switch {
			case j < n:
				tail := &Node{
					Keys:   append([]string(nil), ch.Keys[j:]...),
					IsLeaf: true,
					Line:   ch.Line,
					Column: ch.Column,
				}
				tail.setKeysQuoted(maskSlice8921(quoted, j, n))
				tail.setKeysBracketed(maskSlice8921(bracketed, j, n))
				z.Children = []*Node{tail}
				z.IsLeaf = false
			case len(ch.Children) > 0:
				z.Children = cloneNodes(ch.Children)
				z.IsLeaf = false
			}
			out = append(out, z)
		}
		changed++
	}
	if changed > 0 {
		zones.Children = out
	}
	return changed
}

// validateZoneGroupsExpanded9656 refuses a security-zone group that the fan-out
// left unexpanded because the pass budget was spent. It reads the normalized,
// group-expanded tree, where any group that did fit has already been fanned
// out.
//
// Left as parsed, a leaf or empty group compiles only its first zone, and a
// braced group compiles through bracketedGroupInstances8794 without expanding
// groups inside its body. Strict commit refuses. The tolerant load and
// peer-sync paths warn, so a persisted configuration still boots (#1960).
func validateZoneGroupsExpanded9656(nodes []*Node, lenient bool) ([]string, error) {
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
				if ch == nil || len(ch.Keys) < 3 || ch.Keys[0] != "security-zone" {
					continue
				}
				members, _ := zoneGroupSplit9656(ch, zone)
				if members < 2 {
					continue
				}
				shown := ch.Keys[1 : 1+min(members, 3)]
				more := ""
				if members > 3 {
					more = " …"
				}
				msg := fmt.Sprintf("security zones security-zone %s%s: a group of %d zones was not expanded, because expanding it would exceed the %d-node configuration budget. Write it as smaller groups or separate statements (#9656)",
					strings.Join(shown, " "), more, members, maxParseNodes)
				if !lenient {
					return nil, fmt.Errorf("%s", msg)
				}
				warnings = append(warnings, msg)
			}
		}
	}
	return warnings, nil
}
