package config

// normalizePackedStaticRouteQualifiedNextHop splits a compact static-route
// next-hop tail at a qualified-next-hop clause. The general compact statement
// splitter intentionally does not guess multi-value leaf boundaries; this
// bounded route form has an explicit next-hop keyword followed by the
// qualified-next-hop keyword, so preserving the two schema siblings is safe.
//
// Only complete qualified-next-hop clauses are split. An incomplete gateway
// or unrecognized suffix stays fused so SchemaValidate can reject it rather
// than this normalizer guessing where the operator intended a boundary.
func normalizePackedStaticRouteQualifiedNextHop(tree *ConfigTree) int {
	if tree == nil {
		return 0
	}
	changed := 0
	var walk func(nodes []*Node, parent, grandparent, greatGrandparent *Node)
	walk = func(nodes []*Node, parent, grandparent, greatGrandparent *Node) {
		for _, node := range nodes {
			if node == nil {
				continue
			}
			if node.Name() == "route" && isStaticRouteNode12648(parent, grandparent, greatGrandparent) {
				changed += splitPackedRouteQualifiedNextHop(node)
			}
			walk(node.Children, node, parent, grandparent)
		}
	}
	walk(tree.Children, nil, nil, nil)
	return changed
}

func isStaticRouteNode12648(parent, grandparent, greatGrandparent *Node) bool {
	if parent == nil || parent.Name() != "static" || grandparent == nil {
		return false
	}
	switch grandparent.Name() {
	case "routing-options":
		return true
	case "rib":
		return greatGrandparent != nil && greatGrandparent.Name() == "routing-options"
	default:
		return false
	}
}

func splitPackedRouteQualifiedNextHop(route *Node) int {
	if route == nil {
		return 0
	}
	changed := 0
	for i := 0; i < len(route.Children); i++ {
		nextHop := route.Children[i]
		if nextHop == nil || nextHop.Name() != "next-hop" {
			continue
		}
		for _, child := range nextHop.Children {
			if child == nil || child.Name() != "interface" || len(child.Keys) < 4 {
				continue
			}
			qnh := -1
			for j := 2; j < len(child.Keys); j++ {
				if child.Keys[j] == "qualified-next-hop" &&
					!child.KeyQuoted(j) && !child.KeyBracketed(j) {
					qnh = j
					break
				}
			}
			if qnh < 2 || qnh+1 >= len(child.Keys) {
				continue
			}
			nextHop.Keys = append(nextHop.Keys, child.Keys[qnh:]...)
			nextHop.setKeysQuoted(append(nextHop.KeysQuoted, maskSlice8921(child.KeysQuoted, qnh, len(child.Keys))...))
			nextHop.setKeysBracketed(append(nextHop.KeysBracketed, maskSlice8921(child.KeysBracketed, qnh, len(child.Keys))...), child.BracketedClosed)
			child.Keys = append([]string(nil), child.Keys[:qnh]...)
			child.setKeysQuoted(maskSlice8921(child.KeysQuoted, 0, qnh))
			child.setKeysBracketed(maskSlice8921(child.KeysBracketed, 0, qnh), child.BracketedClosed)
			child.IsLeaf = len(child.Children) == 0
		}
		qnh := -1
		for j := 1; j < len(nextHop.Keys); j++ {
			if nextHop.Keys[j] == "qualified-next-hop" &&
				!nextHop.KeyQuoted(j) && !nextHop.KeyBracketed(j) {
				qnh = j
				break
			}
		}
		if qnh <= 1 || qnh+1 >= len(nextHop.Keys) {
			continue
		}
		gateway := qnh + 1
		if isRouteInlineKeyword(nextHop.Keys[gateway]) &&
			!nextHop.KeyQuoted(gateway) && !nextHop.KeyBracketed(gateway) {
			continue
		}

		qualified := &Node{
			Keys:   append([]string(nil), nextHop.Keys[qnh:qnh+2]...),
			IsLeaf: true,
			Line:   nextHop.Line,
			Column: nextHop.Column,
		}
		copyPackedRouteKeyMasks(nextHop, qnh, qnh+2, qualified)
		var modifiers []*Node
		valid := true
		for j := qnh + 2; j < len(nextHop.Keys); {
			keyword := nextHop.Keys[j]
			if j+1 >= len(nextHop.Keys) {
				valid = false
				break
			}
			switch keyword {
			case "interface", "preference", "metric":
				modifier := &Node{
					Keys:   append([]string(nil), nextHop.Keys[j:j+2]...),
					IsLeaf: true,
					Line:   nextHop.Line,
					Column: nextHop.Column,
				}
				copyPackedRouteKeyMasks(nextHop, j, j+2, modifier)
				modifiers = append(modifiers, modifier)
				j += 2
			default:
				valid = false
			}
			if !valid {
				break
			}
		}
		if !valid {
			continue
		}
		qualified.Children = modifiers
		qualified.IsLeaf = len(modifiers) == 0

		nextHop.Keys = append([]string(nil), nextHop.Keys[:qnh]...)
		nextHop.setKeysQuoted(maskSlice8921(nextHop.KeysQuoted, 0, qnh))
		nextHop.setKeysBracketed(maskSlice8921(nextHop.KeysBracketed, 0, qnh), nextHop.BracketedClosed)
		nextHop.IsLeaf = len(nextHop.Children) == 0

		children := make([]*Node, 0, len(route.Children)+1)
		children = append(children, route.Children[:i+1]...)
		children = append(children, qualified)
		children = append(children, route.Children[i+1:]...)
		route.Children = children
		changed++
		i++
	}
	return changed
}

func copyPackedRouteKeyMasks(source *Node, start, end int, dest *Node) {
	dest.setKeysQuoted(maskSlice8921(source.KeysQuoted, start, end))
	dest.setKeysBracketed(maskSlice8921(source.KeysBracketed, start, end), source.BracketedClosed)
}
