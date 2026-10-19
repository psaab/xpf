package config

// Group container beside an inline packed leaf (#14418, DR15-H3).
//
// mergeNodes' container branch finds peers only among containers
// (sameKeyedContainers9802), so a group container `term t1 { ... }` whose
// inline peer is a PACKED leaf (`term t1 from ... then reject;`) found no
// peer, the single-key #4325 C-guard could not fire (term has two keys), and
// the container was adopted beside the leaf: two `term t1` nodes survived.
// Routing composed them last-wins (group accept overwrote inline reject);
// firewall appended both first-match (group-only traffic accepted by twin).
//
// The fix mirrors #9855 in the opposite direction: promote the inline packed
// leaf to its braced shape and merge the group container's children into it.
// The recursive merge applies ordinary leaf override/union one level down, so
// inline precedence is preserved (a conflicting group terminal action is
// dropped when the promoted inline body already carries one; see
// dropConflictingTerminalThen14418 for the `then`-container shape, where both
// sides would otherwise land as sibling leaves under one `then`).
//
// Admission is deliberately narrow: same raw full identity via
// identitySpan9855 (keyword + instance, span >= 2), schema container with
// children and not a value-list, not a zone leaf, not a default-policy stanza,
// no wildcard keys, and the inline leaf's tail must expand (packedBodyChildren
// or, for routing-policy terms, policyTermBody12537). Any failure keeps the
// existing adopt-beside behaviour rather than guessing.

// containerLeafPeer14418 finds the inline packed leaf peer for group
// container s and, if admissible, promotes it in place. It returns the
// promoted peer, or nil when adopt-beside must stand.
func containerLeafPeer14418(ancestorPath [][]string, dst []*Node, s *Node) *Node {
	if s == nil || s.IsLeaf || len(s.Keys) == 0 || len(s.Children) == 0 {
		return nil
	}
	if keysContainWildcard(s.Keys) || groupZoneLeaf9831(ancestorPath, s) ||
		isDefaultPolicyGroupStanza12923(ancestorPath, s) || isDefaultPolicyGroupBlock12823(ancestorPath, s) {
		return nil
	}
	parent := schemaAtAncestorPath(ancestorPath)
	if parent == nil {
		return nil
	}
	leafSchema := resolveSchemaChild(parent, s.Keys[0])
	if leafSchema == nil || leafSchema.children == nil || leafSchema.valueList {
		return nil
	}
	if _, ok := identitySpan9855(leafSchema, s.Keys, s.Keys); !ok {
		return nil
	}
	// Bracketed address peers own a dedicated union route (#9859).
	if bracketedAddressPeer9859(ancestorPath, dst, s) != nil {
		return nil
	}
	for _, d := range dst {
		if d == nil || !d.IsLeaf || len(d.Keys) == 0 || d.Keys[0] != s.Keys[0] {
			continue
		}
		if _, ok := identitySpan9855(leafSchema, s.Keys, d.Keys); ok {
			if promotePackedLeafPeer14418(leafSchema, d) {
				return d
			}
			return nil
		}
	}
	return nil
}

// promotePackedLeafPeer14418 rewrites leaf peer in place to its braced shape.
// It reports false (peer untouched) when the peer has no tail or its tail
// does not expand under the schema.
func promotePackedLeafPeer14418(leafSchema *schemaNode, peer *Node) bool {
	if peer == nil || !peer.IsLeaf || len(peer.Children) > 0 {
		return false
	}
	span, ok := identitySpan9855(leafSchema, peer.Keys, peer.Keys)
	if !ok || span >= len(peer.Keys) {
		return false
	}
	body := packedBodyChildren(peer, leafSchema)
	if sameNodes9855(body, peer.Children) {
		body = policyTermBody12537(leafSchema, peer, true)
	}
	if body == nil {
		return false
	}
	oldKeys := peer.Keys
	peer.Keys = append([]string(nil), oldKeys[:span]...)
	if len(peer.KeysQuoted) == len(oldKeys) {
		peer.KeysQuoted = append([]bool(nil), peer.KeysQuoted[:span]...)
	} else if len(peer.KeysQuoted) != 0 {
		peer.KeysQuoted = nil
	}
	if len(peer.KeysBracketed) == len(oldKeys) {
		peer.KeysBracketed = append([]bool(nil), peer.KeysBracketed[:span]...)
	} else if len(peer.KeysBracketed) != 0 {
		peer.KeysBracketed = nil
	}
	peer.Children = body
	peer.IsLeaf = false
	markSynthTerminals9855(peer.Children)
	return true
}

var terminalThenActions14418 = map[string]bool{
	"accept": true, "reject": true, "discard": true,
}

// #15259: `then next policy` is a flow-control peer of a routing
// terminal, so it is kept beside the inline terminal for the #11780
// gate rather than dropped as a conflicting terminal here. The drop
// below therefore treats `next` as a terminal-class peer on the group
// side (a group `next` beside an inline accept/reject is kept), while
// a group terminal beside an inline `next policy` is also kept so the
// same gate sees it. Routing-only: firewall `then` has no `next
// policy`, and `next term` there stays a non-terminal fall-through.
func routingThenPeerKeepsNext15259(peer *Node, children []*Node) bool {
	if peer == nil {
		return false
	}
	inlineHasNext := false
	inlineHasTerminal := false
	for _, c := range peer.Children {
		for _, a := range thenActionKeys14418(c) {
			if a == "next" {
				inlineHasNext = true
			}
			if terminalThenActions14418[a] {
				inlineHasTerminal = true
			}
		}
		// Packed `then next ...` on the promoted inline peer.
		if c != nil && len(c.Keys) > 2 && c.Keys[0] == "then" && c.Keys[1] == "next" {
			inlineHasNext = true
		}
	}
	if !inlineHasNext && !inlineHasTerminal {
		return false
	}
	// Only routing peers qualify: the inline `then` must carry a
	// routing terminal or a next clause (firewall discard/next-term
	// shapes never carry `next policy`, and a group firewall `next`
	// child is `next term`, which must keep its current drop/keep
	// behaviour — it is not in terminalThenActions14418, so it is
	// already kept; this helper only widens routing).
	for _, c := range children {
		if c == nil || len(c.Keys) == 0 || c.Keys[0] != "then" {
			continue
		}
		if routingTermThenNextPolicy15259(c) && inlineHasTerminal {
			return true
		}
		for _, a := range thenActionKeys14418(c) {
			if terminalThenActions14418[a] && inlineHasNext {
				return true
			}
		}
		if len(c.Keys) > 2 && c.Keys[1] == "next" && inlineHasTerminal {
			return true
		}
	}
	return false
}

// dropConflictingTerminalThen14418 filters a group terminal action that
// conflicts with the inline peer's (caller passes clones, so the group
// source is never mutated). thenActionKeys14418 returns the action heads
// of a `then` node in either spelling: braced children, or packed
// `then accept` (Keys[1]).
func thenActionKeys14418(c *Node) []string {
	if c == nil || len(c.Keys) == 0 || c.Keys[0] != "then" {
		return nil
	}
	if !c.IsLeaf && len(c.Children) > 0 {
		var out []string
		for _, gc := range c.Children {
			if gc != nil && len(gc.Keys) > 0 {
				out = append(out, gc.Keys[0])
			}
		}
		return out
	}
	if len(c.Keys) > 1 {
		return []string{c.Keys[1]}
	}
	return nil
}

func dropConflictingTerminalThen14418(peer *Node, children []*Node) []*Node {
	if routingThenPeerKeepsNext15259(peer, children) {
		return children
	}
	inline := terminalActionsInThen14418(peer)
	if len(inline) == 0 {
		return children
	}
	out := make([]*Node, 0, len(children))
	changed := false
	for _, c := range children {
		if c == nil || len(c.Keys) == 0 || c.Keys[0] != "then" {
			out = append(out, c)
			continue
		}
		if !c.IsLeaf && len(c.Children) > 0 {
			kept := make([]*Node, 0, len(c.Children))
			for _, gc := range c.Children {
				if gc != nil && len(gc.Keys) > 0 && terminalThenActions14418[gc.Keys[0]] && !inline[gc.Keys[0]] {
					changed = true
					continue
				}
				kept = append(kept, gc)
			}
			if len(kept) == len(c.Children) {
				out = append(out, c)
				continue
			}
			if len(kept) == 0 {
				changed = true
				continue
			}
			clone := *c
			clone.Children = kept
			clone.KeysQuoted = nil
			clone.KeysBracketed = nil
			out = append(out, &clone)
			changed = true
			continue
		}
		// Packed `then <action> ...` leaf: drop when its action conflicts.
		if len(c.Keys) > 1 && terminalThenActions14418[c.Keys[1]] && !inline[c.Keys[1]] {
			changed = true
			continue
		}
		out = append(out, c)
	}
	if !changed {
		return children
	}
	return out
}

func terminalActionsInThen14418(peer *Node) map[string]bool {
	out := map[string]bool{}
	for _, c := range peer.Children {
		for _, a := range thenActionKeys14418(c) {
			if terminalThenActions14418[a] {
				out[a] = true
			}
		}
	}
	return out
}
