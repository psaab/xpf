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
	var walk func([]*Node)
	walk = func(nodes []*Node) {
		for _, node := range nodes {
			if node == nil {
				continue
			}
			if node.Name() == "route" {
				changed += splitPackedRouteQualifiedNextHop(node)
			}
			walk(node.Children)
		}
	}
	walk(tree.Children)
	return changed
}

func splitPackedRouteQualifiedNextHop(route *Node) int {
	if route == nil {
		return 0
	}
	for i, nextHop := range route.Children {
		if nextHop == nil || nextHop.Name() != "next-hop" || len(nextHop.Keys) < 4 {
			continue
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
		return 1
	}
	return 0
}

func copyPackedRouteKeyMasks(source *Node, start, end int, dest *Node) {
	dest.setKeysQuoted(maskSlice8921(source.KeysQuoted, start, end))
	dest.setKeysBracketed(maskSlice8921(source.KeysBracketed, start, end), source.BracketedClosed)
}
