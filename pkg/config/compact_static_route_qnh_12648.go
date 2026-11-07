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
		// #15777: hierarchical `rib { <name> { static ... } }` nests the
		// table name between `rib` and `static`.
		return greatGrandparent != nil && greatGrandparent.Name() == "rib"
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
			for j := qnh; j < len(child.Keys); j++ {
				nextHop.appendKey(child.Keys[j], child.KeyQuoted(j), child.KeyBracketed(j))
			}
			nextHop.setKeysBracketed(nextHop.KeysBracketed, child.BracketedClosed)
			child.replaceKeys(child.Keys[:qnh],
				maskSlice(keyMask(child.KeysQuoted, len(child.Keys)), 0, qnh),
				maskSlice(keyMask(child.KeysBracketed, len(child.Keys)), 0, qnh),
				child.BracketedClosed)
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

		qualified := nextHop.keySpan(qnh, qnh+2)
		qualified.Line = nextHop.Line
		qualified.Column = nextHop.Column
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
				modifier := nextHop.keySpan(j, j+2)
				modifier.Line = nextHop.Line
				modifier.Column = nextHop.Column
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

		nextHop.replaceKeys(nextHop.Keys[:qnh],
			maskSlice(keyMask(nextHop.KeysQuoted, len(nextHop.Keys)), 0, qnh),
			maskSlice(keyMask(nextHop.KeysBracketed, len(nextHop.Keys)), 0, qnh),
			nextHop.BracketedClosed)
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
