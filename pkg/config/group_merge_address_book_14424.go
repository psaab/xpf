package config

// #14424: address-book `address` identity (keyword + name at Keys[1]) must be
// honoured by group merging.
//
// The `address` schema node is a leaf (children == nil, args 2, multi), so the
// generic machinery cannot treat it as a named container:
//
//   - #9859 (namedLeafPeer9859) requires children != nil, so a group LEAF
//     `address A <prefix>` falls back to leafListPeer keyword matching. That
//     accidentally does the right thing for leaf-vs-leaf (inline wins), but
//     it also means a DIFFERENT name (`address B`) is suppressed whenever any
//     inline `address` leaf exists — B is silently dropped.
//   - A group CONTAINER `address A { <prefix>; }` has no same-keyed container
//     peer (the inline spelling is a leaf, or a container with different
//     Keys), so mergeNodes adopts it beside the inline node. The compiler
//     (parseAddressBookEntries) then folds both nodes into one Address map
//     entry with last-wins, and the group value — adopted after the inline
//     node — overwrites the inline prefix.
//   - Container-vs-container adopts beside for the same reason (Keys differ
//     only in shape, but sameKeyedContainers9802 requires exact Keys), and
//     the same last-wins fold lets the group prefix win. Inside one braced
//     container, repeated prefix children also fold last-wins.
//
// Fix: register the two address-book `address` schema nodes (global book and
// zone-local book) as identity sites. Before the generic container/leaf-list
// handling, a group `address` node whose name matches an existing destination
// `address` node is merged INTO that destination with inline precedence;
// a group `address` naming a new instance is adopted on the leaf path
// (leaf branch only — container adoption already keeps new names).

var addressBookAddressNodes14424 = map[*schemaNode]bool{}

func init() {
	if global := schemaSecurity.children["address-book"]; global != nil {
		if g := global.children["global"]; g != nil {
			if a := g.children["address"]; a != nil {
				addressBookAddressNodes14424[a] = true
			}
		}
	}
	if zones := schemaSecurity.children["zones"]; zones != nil {
		if zone := zones.children["security-zone"]; zone != nil {
			if book := zone.children["address-book"]; book != nil {
				if a := book.children["address"]; a != nil {
					addressBookAddressNodes14424[a] = true
				}
			}
		}
	}
}

func isAddressBookAddress14424(ancestorPath [][]string, s *Node) bool {
	if s == nil || len(s.Keys) < 2 || s.Keys[0] != "address" {
		return false
	}
	parent := schemaAtAncestorPath(ancestorPath)
	if parent == nil {
		return false
	}
	return addressBookAddressNodes14424[resolveSchemaChild(parent, s.Keys[0])]
}

func addressBookPeer14424(dst []*Node, s *Node) *Node {
	if s == nil || len(s.Keys) < 2 {
		return nil
	}
	for _, d := range dst {
		if d != nil && len(d.Keys) >= 2 && d.Keys[0] == "address" && d.Keys[1] == s.Keys[1] {
			return d
		}
	}
	return nil
}

// mergeAddressBookGroupInto14424 merges group source s into inline peer with
// inline precedence, recursively reusing mergeNodes for container children so
// nested apply-groups-except / wildcard handling stays identical. It reports
// whether s was consumed. Leaf-vs-leaf and container-vs-container conflicts
// are scalar inline-wins; disjoint attributes (prefix vs description) union.
func mergeAddressBookGroupInto14424(dst *[]*Node, s *Node, ancestorPath [][]string, budget *groupExpandBudget, group string, vars map[string]string, excluded map[string]bool, haveExcept bool, deferWildcards bool) (bool, error) {
	peer := addressBookPeer14424(*dst, s)
	if peer == nil {
		return false, nil
	}
	childPath := appendPath(ancestorPath, peer.Keys)
	if !s.IsLeaf && !peer.IsLeaf {
		// Container vs container: merge children. Repeated bare prefix
		// children carry no keyword, so mergeNodes would adopt the group
		// prefix beside the inline one and the compiler's last-wins fold
		// would let the group win. Drop group bare leaves whose value
		// position is already occupied inline.
		children := s.Children
		if addressHasBarePrefix14424(peer) {
			filtered := make([]*Node, 0, len(children))
			for _, c := range children {
				if isBarePrefixLeaf14424(c) {
					continue
				}
				filtered = append(filtered, c)
			}
			children = filtered
		}
		if len(children) > 0 {
			if err := mergeNodes(&peer.Children, children, childPath, budget, group, vars, excluded, haveExcept, deferWildcards); err != nil {
				return true, err
			}
		}
		return true, nil
	}
	if !s.IsLeaf && peer.IsLeaf {
		// Group container into inline leaf: promote the leaf to its braced
		// shape (mirrors #9855 promotion). The leaf's packed tail becomes
		// children so group children merge under inline precedence.
		promoteAddressLeaf14424(peer)
		children := s.Children
		if addressHasBarePrefix14424(peer) {
			filtered := make([]*Node, 0, len(children))
			for _, c := range children {
				if isBarePrefixLeaf14424(c) {
					continue
				}
				filtered = append(filtered, c)
			}
			children = filtered
		}
		if len(children) > 0 {
			if err := mergeNodes(&peer.Children, children, childPath, budget, group, vars, excluded, haveExcept, deferWildcards); err != nil {
				return true, err
			}
		}
		return true, nil
	}
	if s.IsLeaf && !peer.IsLeaf {
		// Group leaf into inline container: a prefix leaf conflicts with an
		// existing bare prefix child (inline wins); otherwise it is a new
		// attribute and becomes a bare child. A `description ...` tail is
		// routed through a synthesized description child so it does not
		// masquerade as a bare prefix.
		if len(s.Keys) >= 3 && s.Keys[2] != "description" && looksLikeIPOrCIDR(s.Keys[2]) && addressHasBarePrefix14424(peer) {
			return true, nil
		}
		var body []*Node
		if len(s.Keys) >= 3 && s.Keys[2] == "description" {
			desc := &Node{Keys: append([]string(nil), s.Keys[2:]...), IsLeaf: true, InheritedFrom: s.InheritedFrom}
			if len(s.KeysQuoted) == len(s.Keys) {
				desc.KeysQuoted = append([]bool(nil), s.KeysQuoted[2:]...)
			}
			if len(s.KeysBracketed) == len(s.Keys) {
				desc.KeysBracketed = append([]bool(nil), s.KeysBracketed[2:]...)
			}
			body = []*Node{desc}
		} else if len(s.Keys) >= 3 {
			val := &Node{Keys: []string{s.Keys[2]}, IsLeaf: true, InheritedFrom: s.InheritedFrom}
			if len(s.KeysQuoted) == len(s.Keys) {
				val.KeysQuoted = []bool{s.KeysQuoted[2]}
			}
			body = []*Node{val}
			// Preserve any trailing tokens as inert trailing content on
			// the value child so strict trailing-token gates still see
			// them (mergeAddressNode reads leaf prefix children only,
			// so extra keys on a 1-key child are ignored there — keep
			// them on the child Keys for gate visibility).
			if len(s.Keys) > 3 {
				val.Keys = append(val.Keys, s.Keys[3:]...)
				if len(s.KeysQuoted) == len(s.Keys) {
					val.KeysQuoted = append(val.KeysQuoted, s.KeysQuoted[3:]...)
				}
			}
		}
		if len(body) > 0 {
			markSynthTerminals9855(body)
			if err := mergeNodes(&peer.Children, body, childPath, budget, group, vars, excluded, haveExcept, deferWildcards); err != nil {
				return true, err
			}
		}
		return true, nil
	}
	// Leaf vs leaf: inline wins when both carry a value (prefix or
	// description text). Disjoint attributes union by folding the group
	// tail into the inline leaf's packed form (mergeAddressNode reads
	// both the prefix slot and the description tail).
	if len(s.Keys) < 3 {
		return true, nil
	}
	if s.Keys[2] == "description" {
		// Group `address A description gd` beside inline prefix leaf:
		// append the description tail so mergeAddressNode routes it.
		if len(peer.Keys) >= 3 && peer.Keys[2] == "description" {
			return true, nil // both descriptions: inline wins
		}
		peer.Keys = append(peer.Keys, s.Keys[2:]...)
		if len(s.KeysQuoted) == len(s.Keys) {
			for len(peer.KeysQuoted) < len(peer.Keys) {
				peer.KeysQuoted = append(peer.KeysQuoted, false)
			}
			copy(peer.KeysQuoted[len(peer.KeysQuoted)-(len(s.Keys)-2):], s.KeysQuoted[2:])
		}
		return true, nil
	}
	// Group prefix (or unsupported form) beside inline leaf.
	if len(peer.Keys) >= 3 {
		if peer.Keys[2] == "description" {
			// Inline description-only leaf: adopt group prefix after the
			// description text — mergeAddressNode's packed-description
			// arm reads Keys[4] as the prefix.
			peer.Keys = append(peer.Keys, s.Keys[2:]...)
			if len(s.KeysQuoted) == len(s.Keys) {
				for len(peer.KeysQuoted) < len(peer.Keys) {
					peer.KeysQuoted = append(peer.KeysQuoted, false)
				}
				copy(peer.KeysQuoted[len(peer.KeysQuoted)-(len(s.Keys)-2):], s.KeysQuoted[2:])
			}
		}
		// else inline already carries a value: inline wins.
		return true, nil
	}
	// Inline bare `address A;` (no value): adopt the group tail.
	peer.Keys = append(peer.Keys, s.Keys[2:]...)
	if len(s.KeysQuoted) == len(s.Keys) {
		for len(peer.KeysQuoted) < len(peer.Keys) {
			peer.KeysQuoted = append(peer.KeysQuoted, false)
		}
		copy(peer.KeysQuoted[len(peer.KeysQuoted)-(len(s.Keys)-2):], s.KeysQuoted[2:])
	}
	return true, nil
}

func isBarePrefixLeaf14424(n *Node) bool {
	return n != nil && n.IsLeaf && len(n.Keys) == 1 && looksLikeIPOrCIDR(n.Keys[0])
}

func addressHasBarePrefix14424(n *Node) bool {
	if n == nil {
		return false
	}
	if n.IsLeaf {
		return len(n.Keys) >= 3 && looksLikeIPOrCIDR(n.Keys[2])
	}
	for _, c := range n.Children {
		if isBarePrefixLeaf14424(c) {
			return true
		}
	}
	return false
}

// promoteAddressLeaf14424 turns an inline leaf `address A <prefix>` (or
// `address A description <text>`) into the equivalent braced container:
// Keys keep [address A], the value tail becomes children.
func promoteAddressLeaf14424(peer *Node) {
	old := peer.Keys
	var children []*Node
	if len(old) >= 3 {
		if old[2] == "description" {
			desc := &Node{Keys: append([]string(nil), old[2:]...), IsLeaf: true, InheritedFrom: peer.InheritedFrom}
			if len(peer.KeysQuoted) == len(old) {
				desc.KeysQuoted = append([]bool(nil), peer.KeysQuoted[2:]...)
			}
			children = append(children, desc)
		} else {
			val := &Node{Keys: append([]string(nil), old[2:]...), IsLeaf: true, InheritedFrom: peer.InheritedFrom}
			if len(peer.KeysQuoted) == len(old) {
				val.KeysQuoted = append([]bool(nil), peer.KeysQuoted[2:]...)
			}
			if len(peer.KeysBracketed) == len(old) {
				val.KeysBracketed = append([]bool(nil), peer.KeysBracketed[2:]...)
			}
			children = append(children, val)
		}
	}
	peer.Keys = append([]string(nil), old[:2]...)
	if len(peer.KeysQuoted) == len(old) {
		peer.KeysQuoted = append([]bool(nil), peer.KeysQuoted[:2]...)
	} else {
		peer.KeysQuoted = nil
	}
	if len(peer.KeysBracketed) == len(old) {
		peer.KeysBracketed = append([]bool(nil), peer.KeysBracketed[:2]...)
	} else {
		peer.KeysBracketed = nil
	}
	peer.Children = children
	peer.IsLeaf = false
}

// addressBookGroupContainerHandled14424 reports whether a group container
// `address A { ... }` was fully handled (merged into a same-name peer or
// suppressed as a same-name conflict). A different name returns false so
// the caller adopts it as a new instance.
func addressBookGroupContainerHandled14424(dst *[]*Node, s *Node, ancestorPath [][]string, budget *groupExpandBudget, group string, vars map[string]string, excluded map[string]bool, haveExcept bool, deferWildcards bool) (bool, error) {
	if !isAddressBookAddress14424(ancestorPath, s) {
		return false, nil
	}
	if addressBookPeer14424(*dst, s) == nil {
		return false, nil
	}
	return mergeAddressBookGroupInto14424(dst, s, ancestorPath, budget, group, vars, excluded, haveExcept, deferWildcards)
}
