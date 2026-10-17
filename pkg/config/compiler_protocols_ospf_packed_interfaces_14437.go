package config

// Split of a packed run carrying two or more OSPF/OSPFv3 `interface` heads
// into one node per head — #14437 (DR18-H1).
//
// THE SHAPE. Inside a braced area,
//
//	area 0.0.0.0 {
//	    interface ge-0/0/0.0 authentication simple-password "SECRET"
//	        interface ge-0/0/1.0 cost 10;
//	}
//
// arrives as ONE child of the area node whose Keys carry the whole run and
// whose Children are empty. The area loops therefore see one interface, and
// packedBodyChildren on that node bails out whole when the tail reaches the
// second `interface` token: that keyword is declared at no open level of the
// per-interface call (the interface schema and the `authentication`
// sub-schema), so the helper returns node.Children unchanged — i.e. empty.
// The first interface compiles with NO properties at all (AuthType/AuthKey
// empty, so pkg/frr activates it unauthenticated) and the second interface
// never becomes a node. The single-interface packed spelling is unaffected
// (#7653): its tail never contains a second head, so it never bails.
//
// THE SPLIT, AND WHY IT IS SOUND. Within the OSPF/OSPFv3 area interface
// schema no interface-body child takes a bare `interface` token as its
// value, so every token before the second `interface` keyword belongs to
// the first interface's body. Splitting the Keys run at each subsequent
// `interface` keyword therefore recovers exactly the braced twin: one node
// per interface, each feeding the existing packedBodyChildren +
// find-or-create (#8436) path unchanged. A QUOTED `interface` token is
// never a head — a quoted instance name or credential value spelled
// "interface" must stay with the body it was authored in — so the scan
// consults KeyQuoted and ignores quoted candidates.
//
// BOUNDS. Only a childless node (the pure packed-run shape) is split on its
// own Keys; a node carrying Children keeps existing behaviour (braced
// bodies, #8850 shapes) and is returned unsplit — with ONE exception: the
// compact normalizer reshapes some two-head runs before compilation (e.g. a
// v3 `cost`-first run) into a head node carrying a single childless child
// whose Keys are the fused remainder (`cost 5 interface … cost 10`). That
// child is the same packed run one level down, so it is split the same way
// and its fragments become sibling interface nodes after the head fragment.
// Children that do not start a further `interface` head keep the node
// unsplit. A run with fewer than two heads is returned unchanged (the
// identical slice, so the common path allocates nothing).

// splitPackedSiblingInterfaceNodes14437 expands every packed run in nodes
// that carries more than one `interface` head into one synthetic node per
// head, in order. Nodes that are not such a run pass through unchanged
// (same pointer), so braced and single-interface spellings are untouched.
func splitPackedSiblingInterfaceNodes14437(nodes []*Node) []*Node {
	var out []*Node
	changed := false
	for _, n := range nodes {
		frags := splitOnePackedInterfaceRun14437(n)
		if frags == nil {
			out = append(out, n)
			continue
		}
		changed = true
		out = append(out, frags...)
	}
	if !changed {
		return nodes
	}
	return out
}

// splitOnePackedInterfaceRun14437 returns the per-head fragments of n, or
// nil when n is not a multi-head packed run.
func splitOnePackedInterfaceRun14437(n *Node) []*Node {
	if n == nil || len(n.Keys) < 2 || n.Keys[0] != "interface" {
		return nil
	}
	if len(n.Children) == 0 {
		return splitPackedInterfaceKeys14437(n)
	}
	// Child-carried fused tail (normalizer shape): exactly one childless
	// child whose run contains a further `interface` head. The child's
	// leading segment is the head interface's remaining body, so it joins
	// the head fragment; each later segment is its own interface.
	if len(n.Children) != 1 {
		return nil
	}
	child := n.Children[0]
	if child == nil || len(child.Children) > 0 || len(child.Keys) == 0 {
		return nil
	}
	var heads []int
	for i := range child.Keys {
		if child.Keys[i] == "interface" && !child.KeyQuoted(i) {
			heads = append(heads, i)
		}
	}
	if len(heads) == 0 {
		return nil
	}
	head := packedInterfaceFragment14437(n, 0, len(n.Keys))
	head.Keys = append(head.Keys, child.Keys[:heads[0]]...)
	if len(child.KeysQuoted) == len(child.Keys) {
		// Rebuild the combined mask: parent span then child's head segment.
		quoted := make([]bool, 0, len(head.Keys))
		if len(n.KeysQuoted) == len(n.Keys) {
			quoted = append(quoted, n.KeysQuoted...)
		} else {
			quoted = append(quoted, make([]bool, len(n.Keys))...)
		}
		quoted = append(quoted, child.KeysQuoted[:heads[0]]...)
		if len(quoted) == len(head.Keys) {
			head.setKeysQuoted(quoted)
		}
	}
	if len(child.KeysBracketed) == len(child.Keys) {
		bracketed := make([]bool, 0, len(head.Keys))
		if len(n.KeysBracketed) == len(n.Keys) {
			bracketed = append(bracketed, n.KeysBracketed...)
		} else {
			bracketed = append(bracketed, make([]bool, len(n.Keys))...)
		}
		bracketed = append(bracketed, child.KeysBracketed[:heads[0]]...)
		if len(bracketed) == len(head.Keys) {
			head.setKeysBracketed(bracketed, n.BracketedClosed || child.BracketedClosed)
		}
	}
	head.Children = nil
	frags := []*Node{head}
	for j, h := range heads {
		end := len(child.Keys)
		if j+1 < len(heads) {
			end = heads[j+1]
		}
		frags = append(frags, packedInterfaceFragment14437(child, h, end))
	}
	return frags
}

// splitPackedInterfaceKeys14437 splits src's own Keys at every unquoted
// `interface` token after the first head, returning nil when there is no
// second head.
func splitPackedInterfaceKeys14437(src *Node) []*Node {
	var heads []int
	for i := range src.Keys {
		if i > 0 && src.Keys[i] == "interface" && !src.KeyQuoted(i) {
			heads = append(heads, i)
		}
	}
	if len(heads) == 0 {
		return nil
	}
	frags := make([]*Node, 0, len(heads)+1)
	start := 0
	for _, h := range heads {
		frags = append(frags, packedInterfaceFragment14437(src, start, h))
		start = h
	}
	frags = append(frags, packedInterfaceFragment14437(src, start, len(src.Keys)))
	return frags
}

// packedInterfaceFragment14437 builds one fragment node carrying
// src.Keys[from:to] plus the per-key quote/bracket provenance for exactly
// that span, so a quoted instance name or credential keeps its authored
// quote bit through packedBodyChildren. The input node is never mutated.
func packedInterfaceFragment14437(src *Node, from, to int) *Node {
	frag := &Node{
		Keys:          append([]string(nil), src.Keys[from:to]...),
		IsLeaf:        true,
		Annotation:    src.Annotation,
		InheritedFrom: src.InheritedFrom,
		Inactive:      src.Inactive,
		Line:          src.Line,
		Column:        src.Column,
		// Group provenance travels with the fragment: a group-authored run
		// expanded by ExpandGroups carries fromGroups, and dropping it
		// would exempt the split interfaces from apply-groups-except
		// filtering that the unsplit node honoured.
		fromGroups: append([]string(nil), src.fromGroups...),
	}
	if len(src.KeysQuoted) == len(src.Keys) {
		frag.setKeysQuoted(append([]bool(nil), src.KeysQuoted[from:to]...))
	}
	if len(src.KeysBracketed) == len(src.Keys) {
		frag.setKeysBracketed(append([]bool(nil), src.KeysBracketed[from:to]...), src.BracketedClosed)
	}
	return frag
}
