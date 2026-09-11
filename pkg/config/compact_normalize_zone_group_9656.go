package config

// zonesSchema9656 is the `security zones` schema node. `groups` mirrors reach
// the same pointer, so the fan-out applies inside a group body as well.
var zonesSchema9656 = schemaSecurity.children["zones"]

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
// Members are the tokens before the first keyword that the security-zone schema
// node declares, or before an apply statement keyword. setSchema does not
// declare apply-groups, apply-groups-except or apply-macro inside a zone
// (#9685), so without that stop `security-zone trust apply-groups G;` would
// count as three zones. The remaining keys are a packed body, placed under each
// member. That body owns the braced body when the statement has one.
//
// Brackets are not consulted. The renderers drop them on a leaf, so a peer that
// re-parses `show configuration` must reach the same zones without them.
//
// A node with a single member is left for the scoped fold.
func expandZoneGroups9656(zones *Node, zone *schemaNode) int {
	if zones == nil || zone == nil {
		return 0
	}
	var out []*Node
	changed := 0
	for _, ch := range zones.Children {
		n := 0
		if ch != nil {
			n = len(ch.Keys)
		}
		if n < 3 || ch.Keys[0] != "security-zone" {
			out = append(out, ch)
			continue
		}
		j := 1
		for j < n && zone.children[ch.Keys[j]] == nil && !isApplyStatementKeyword(ch.Keys[j]) {
			j++
		}
		if j-1 < 2 {
			out = append(out, ch)
			continue
		}
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
			body := cloneNodes(ch.Children)
			if j < n {
				tail := &Node{
					Keys:   append([]string(nil), ch.Keys[j:]...),
					IsLeaf: len(body) == 0,
					Line:   ch.Line,
					Column: ch.Column,
				}
				tail.setKeysQuoted(maskSlice8921(quoted, j, n))
				tail.setKeysBracketed(maskSlice8921(bracketed, j, n))
				if len(body) > 0 {
					tail.Children = body
				}
				body = []*Node{tail}
			}
			if len(body) > 0 {
				z.Children = body
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
