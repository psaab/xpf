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
// A braced body decides how a keyword tail reads. The tail is a packed head
// only when zoneTailHoldsBody9656 says the body can hang under it; otherwise
// every token names a zone, which is how #8794 read a braced group.
// `security-zone [ zga zgb tcp-rst ] { tcp-rst; }` is three zones, because a
// `tcp-rst` flag cannot hold a body. A leaf, or an empty `{ }` that FormatSet
// cannot distinguish from one, has no body to decide with, so its keyword tail
// is always a statement.
//
// Brackets are not consulted. Format drops them from every node and FormatSet
// from a leaf, so a peer that re-parses the rendered text must reach the same
// zones without them.
//
// A node with a single member is left for the scoped fold.
func expandZoneGroups9656(zones *Node, zone *schemaNode) int {
	return expandZoneGroupsWithin9656(zones, zone, maxParseNodes)
}

// expandZoneGroupsWithin9656 is expandZoneGroups9656 with the node budget as a
// parameter, so a test can reach the limit without building a 200,000-node body.
//
// Every member gets its own clone of the body, so a group costs members × body
// nodes. The whole cost is charged before anything is cloned (countNodes), the
// same way group expansion charges a clone. A group over the budget is left as
// parsed and compiles through bracketedGroupInstances8794, which shares one
// body between the members.
func expandZoneGroupsWithin9656(zones *Node, zone *schemaNode, budget int) int {
	if zones == nil || zone == nil {
		return 0
	}
	var out []*Node
	changed, spent := 0, 0
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
		if j < n && len(ch.Children) > 0 && !zoneTailHoldsBody9656(ch.Keys[j:], zone) {
			j = n
		}
		members := j - 1
		if members < 2 {
			out = append(out, ch)
			continue
		}
		perMember := 1 + countNodes(ch.Children)
		if j < n {
			perMember++
		}
		if spent+members*perMember > budget {
			out = append(out, ch)
			continue
		}
		spent += members * perMember
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

// zoneTailHoldsBody9656 reports whether tail, the keys after a group's members,
// reads as one complete statement under the security-zone schema that ends at a
// node able to hold a braced body. Examples are `interfaces`,
// `interfaces ge-0/0/0.0`, `host-inbound-traffic`, `address-book` and
// `apply-macro M`.
//
// A tail that fails this check, such as `tcp-rst` or `screen`, cannot be the
// head of the braced body. The #9656 Codex review measured the cost of reading
// it as one anyway: `security-zone [ zga zgb tcp-rst ] { tcp-rst; }` created
// three zones at e09f425dd and lost zone `tcp-rst` under the first cut.
func zoneTailHoldsBody9656(tail []string, zone *schemaNode) bool {
	if isApplyStatementKeyword(tail[0]) {
		return tail[0] == "apply-macro" && len(tail) == 2
	}
	cur := zone
	for len(tail) > 0 {
		child := resolveSchemaChild(cur, tail[0])
		if child == nil {
			return false
		}
		k, refined := consumeNodeKeys(tail, child)
		tail = tail[k:]
		cur = refined
	}
	return cur.children != nil || cur.wildcard != nil
}
