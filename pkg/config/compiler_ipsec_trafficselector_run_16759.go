package config

// compiler_ipsec_trafficselector_run_16759.go carries the run-aware
// traffic-selector discovery shared by compileIPsec and
// validateIPsecTrafficSelectorsStrict (#16759).
//
// A traffic-selector chained after other VPN leaves in one flat set
// command --
//
//	set security ipsec vpn v1 gateway gw1 ipsec-policy epol1
//	    bind-interface st0.0 traffic-selector ts1 local-ip 10.1.0.0/24
//	    remote-ip 10.2.0.0/24
//
// is segmented by expandIPsecVPNRun9088 into a synthesized node with
// Keys=[traffic-selector ts1 local-ip <l> remote-ip <r>] and no
// children: the schema declares traffic-selector with children, so
// expandFlatRun cannot descend into it. Reading only direct
// FindChildren("traffic-selector") therefore lost the selector with
// no error, while EffectiveTrafficSelectors widened the SA to
// any<->any and the #4098/#5692 shape gate was bypassed. Both readers
// must discover selectors through this one helper so they cannot
// diverge (#9088).

// trafficSelectorInstances16759 returns every traffic-selector instance
// under a vpn node, in discovery order, across both parser shapes: direct
// children (braced / split set commands) and synthesized segments of a
// packed flat run (chained set commands, including the compact hierarchical
// tail carried on the VPN node's own Keys).
//
// Each returned instance has Keys=[traffic-selector <name>] and contains
// the combined children of all distinct fragments with that name. A
// fragment is deduplicated only when its complete selector body repeats
// an earlier body; name/header keys alone do not establish identity.
// This preserves complementary fragments for both compilation and
// validation, while an exact re-sighting is not counted as a repeated
// local-ip / remote-ip value.
func trafficSelectorInstances16759(vpn *Node) []struct {
	name string
	node *Node
} {
	var out []struct {
		name string
		node *Node
	}
	seenPtr := map[*Node]bool{}
	seenBody := map[string][]*Node{}
	indexByName := map[string]int{}
	add := func(name string, node *Node) {
		if name == "" || node == nil || seenPtr[node] {
			return
		}
		for _, prev := range seenBody[name] {
			if trafficSelectorBodyEqual16759(prev, node) {
				seenPtr[node] = true
				return
			}
		}
		seenPtr[node] = true
		seenBody[name] = append(seenBody[name], node)

		if idx, ok := indexByName[name]; ok {
			merged := out[idx].node
			merged.Children = append(merged.Children, node.Children...)
			if len(merged.Children) > 0 {
				merged.IsLeaf = false
			}
			return
		}
		merged := *node
		merged.Children = append([]*Node(nil), node.Children...)
		indexByName[name] = len(out)
		out = append(out, struct {
			name string
			node *Node
		}{name, &merged})
	}

	// Direct children: braced blocks and split set commands. These nodes
	// keep their authored children.
	for _, inst := range namedInstances(vpn.FindChildren("traffic-selector")) {
		add(inst.name, inst.node)
	}

	// Run segments: chained set commands and the compact tail. A direct
	// child also appears here unchanged (same pointer) and is skipped;
	// nested/chained selectors are reconstructed from their flat keys.
	for _, seg := range expandIPsecVPNRun9088(vpn) {
		if seg == nil || len(seg.Keys) == 0 || seg.Keys[0] != "traffic-selector" {
			continue
		}
		if seenPtr[seg] {
			continue
		}
		name, body := trafficSelectorFromRunSegment16759(seg)
		add(name, body)
	}
	return out
}

// trafficSelectorBodyEqual16759 compares a selector fragment's body, ignoring
// AST wrappers that differ between named properties and reconstructed chained
// selectors. A block-valued local-ip / remote-ip leaf is normalized to the same
// key/value shape as its scalar spelling at any selector-body depth. All other
// body keys, values, leaf multiplicity, and child order remain significant.
func trafficSelectorBodyEqual16759(a, b *Node) bool {
	return trafficSelectorNodesEqual16759(a, b, true)
}

func trafficSelectorNodesEqual16759(a, b *Node, selectorRoot bool) bool {
	if a == nil || b == nil {
		return a == b
	}
	aStart, bStart := 0, 0
	if selectorRoot {
		if len(a.Keys) >= 2 && a.Keys[0] == "traffic-selector" {
			aStart = 1
		}
		if len(b.Keys) >= 2 && b.Keys[0] == "traffic-selector" {
			bStart = 1
		}
	}
	aBlockValue := !selectorRoot && trafficSelectorBlockValue16759(a)
	bBlockValue := !selectorRoot && trafficSelectorBlockValue16759(b)
	aKeyCount := len(a.Keys) - aStart
	bKeyCount := len(b.Keys) - bStart
	if aBlockValue {
		aKeyCount++
	}
	if bBlockValue {
		bKeyCount++
	}
	aChildCount, bChildCount := len(a.Children), len(b.Children)
	if aBlockValue {
		aChildCount--
	}
	if bBlockValue {
		bChildCount--
	}
	aLeaf, bLeaf := a.IsLeaf || aBlockValue, b.IsLeaf || bBlockValue
	if aLeaf != bLeaf || aKeyCount != bKeyCount || aChildCount != bChildCount {
		return false
	}
	for i := range aKeyCount {
		aKey := ""
		if i < len(a.Keys)-aStart {
			aKey = a.Keys[aStart+i]
		} else {
			aKey = a.Children[0].Keys[0]
		}
		bKey := ""
		if i < len(b.Keys)-bStart {
			bKey = b.Keys[bStart+i]
		} else {
			bKey = b.Children[0].Keys[0]
		}
		if aKey != bKey {
			return false
		}
	}
	ai, bi := 0, 0
	if aBlockValue {
		ai++
	}
	if bBlockValue {
		bi++
	}
	for ai < len(a.Children) {
		if !trafficSelectorNodesEqual16759(a.Children[ai], b.Children[bi], false) {
			return false
		}
		ai++
		bi++
	}
	return true
}

// trafficSelectorBlockValue16759 reports the only block-value property nodes
// in the selector grammar, represented as a one-key leaf with one bare
// single-key value child. Other child-bearing / malformed forms stay distinct.
func trafficSelectorBlockValue16759(n *Node) bool {
	if n == nil || len(n.Keys) != 1 || len(n.Children) != 1 ||
		(n.Keys[0] != "local-ip" && n.Keys[0] != "remote-ip") {
		return false
	}
	value := n.Children[0]
	return value != nil && value.IsLeaf && len(value.Keys) == 1 && len(value.Children) == 0
}

// trafficSelectorFromRunSegment16759 reconstructs a traffic-selector
// instance node from one expanded run segment. Children already in
// selector shape (local-ip / remote-ip nodes, possibly with a packed
// remote-ip nested under local-ip) are kept and re-segmented by the
// caller; flat keys after the selector name are split at the
// local-ip / remote-ip keywords into synthesized leaf nodes.
func trafficSelectorFromRunSegment16759(seg *Node) (string, *Node) {
	if len(seg.Keys) < 2 {
		return "", nil
	}
	name := seg.Keys[1]
	body := &Node{Keys: []string{"traffic-selector", name}}
	// Braced children ride along unchanged.
	body.Children = append(body.Children, seg.Children...)
	// Flat tail: traffic-selector <name> local-ip <l> remote-ip <r>.
	rest := seg.Keys[2:]
	for i := 0; i < len(rest); {
		kw := rest[i]
		if kw != "local-ip" && kw != "remote-ip" {
			// Unknown token: keep it attached to the previous leaf
			// if one exists so trafficSelectorValues still sees
			// every token of a bracketed or malformed value;
			// otherwise drop it (no leaf owns it).
			if n := len(body.Children); n > 0 {
				last := body.Children[n-1]
				last.Keys = append(last.Keys, kw)
				last.IsLeaf = len(last.Children) == 0
			}
			i++
			continue
		}
		leaf := &Node{Keys: []string{kw}, IsLeaf: true}
		i++
		if i < len(rest) {
			leaf.Keys = append(leaf.Keys, rest[i])
			i++
		}
		body.Children = append(body.Children, leaf)
	}
	if len(body.Children) > 0 {
		body.IsLeaf = false
	}
	return name, body
}
