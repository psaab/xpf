package config

// #14447: group root-login leaves adopted beside an inline/group peer
// must stay visible to validateDuplicateRootLoginAST, mirroring the
// #12823/#12923 default-policy adopt-beside pattern. Inline still
// wins silently is NOT correct here for the gate: inline+group with
// conflicting values is an authored conflict the strict gate must
// see (issue spec: "collect root-login leaves" across pooled ssh).
// But to preserve Junos precedence for lenient (inline wins), the
// reader's last-wins would pick the later (group) node if adopted
// after inline. Therefore adopt-beside only when peer is group-
// adopted; inline peer keeps override (group dropped, inline wins,
// single effective value -> no conflict). Group-group conflicting
// pairs adopt beside and are gated.

// isRootLoginLeaf14447 reports whether n carries a `root-login <val>`
// at system/services/ssh, in any spelling (#15716):
//   - braced leaf: Keys=[root-login <val>], ancestor ends system/services/ssh
//   - packed ssh leaf: Keys=[ssh root-login <val>], ancestor ends system/services
//   - packed services leaf: Keys=[services ssh root-login <val>], ancestor ends system
//   - packed system leaf: Keys=[system services ssh root-login <val>], ancestor empty
func isRootLoginLeaf14447(ancestorPath [][]string, n *Node) bool {
	if n == nil || len(n.Keys) == 0 {
		return false
	}
	keysEq := func(k []string, name string) bool { return len(k) > 0 && k[0] == name }
	// Braced spelling.
	if n.Keys[0] == "root-login" {
		if len(ancestorPath) < 3 {
			return false
		}
		return keysEq(ancestorPath[len(ancestorPath)-3], "system") &&
			keysEq(ancestorPath[len(ancestorPath)-2], "services") &&
			keysEq(ancestorPath[len(ancestorPath)-1], "ssh")
	}
	// Packed spellings: the leaf's own Keys carry the tail.
	switch n.Keys[0] {
	case "ssh":
		if len(n.Keys) >= 3 && n.Keys[1] == "root-login" {
			return len(ancestorPath) >= 2 &&
				keysEq(ancestorPath[len(ancestorPath)-2], "system") &&
				keysEq(ancestorPath[len(ancestorPath)-1], "services")
		}
	case "services":
		if len(n.Keys) >= 4 && n.Keys[1] == "ssh" && n.Keys[2] == "root-login" {
			return len(ancestorPath) >= 1 &&
				keysEq(ancestorPath[len(ancestorPath)-1], "system")
		}
	case "system":
		if len(n.Keys) >= 5 && n.Keys[1] == "services" && n.Keys[2] == "ssh" && n.Keys[3] == "root-login" {
			return len(ancestorPath) == 0
		}
	}
	return false
}

func markGroupRootLoginLeaf14447(budget *groupExpandBudget, ancestorPath [][]string, n *Node) {
	if budget == nil || !isRootLoginLeaf14447(ancestorPath, n) {
		return
	}
	if budget.groupRootLoginLeaves14447 == nil {
		budget.groupRootLoginLeaves14447 = make(map[*Node]bool)
	}
	budget.groupRootLoginLeaves14447[n] = true
}

// markGroupRootLoginLeaves14447 records every root-login leaf —
// braced or packed, at any depth — in a group-originating subtree, so
// wholly-adopted packed containers (e.g. `system services ssh
// root-login allow;` adopted as one leaf) are still visible as
// group-adopted when a later group merges beside them (#15716).
// Mirrors markDefaultPolicyGroupBlocks12823.
func markGroupRootLoginLeaves14447(budget *groupExpandBudget, ancestorPath [][]string, nodes []*Node) {
	markGroupRootLoginLeavesAtPath14447(budget, ancestorPath, nodes)
}

func markGroupRootLoginLeavesAtPath14447(budget *groupExpandBudget, path [][]string, nodes []*Node) {
	for _, n := range nodes {
		if n == nil {
			continue
		}
		markGroupRootLoginLeaf14447(budget, path, n)
		if !n.IsLeaf && len(n.Children) > 0 {
			markGroupRootLoginLeavesAtPath14447(budget, appendPath(path, n.Keys), n.Children)
		}
	}
}

// propagatePackedGroupRootLogin14447: if s is a packed group leaf
// carrying a root-login tail and peer is a group-adopted peer that
// promoteLeafPeerForPackedGroup9855 promotes, mark the synthesized
// root-login child in body (the promoted peer's new children from
// the group body) so a later group's conflicting value adopts beside
// it instead of being suppressed as an inline peer (#15716).
func propagatePackedGroupRootLogin14447(budget *groupExpandBudget, ancestorPath [][]string, peer, s *Node, body []*Node) {
	if budget == nil || peer == nil || s == nil {
		return
	}
	if !isRootLoginLeaf14447(ancestorPath, s) && !packedLeafCarriesRootLogin14447(s) {
		return
	}
	if !budget.groupRootLoginLeaves14447[peer] {
		return
	}
	markSynthesizedRootLoginChildren14447(budget, body)
}

// packedLeafCarriesRootLogin14447 reports whether a packed leaf's
// Keys contain a `... ssh root-login` / `root-login` tail at any
// offset (e.g. `services ssh root-login allow`).
func packedLeafCarriesRootLogin14447(n *Node) bool {
	if n == nil {
		return false
	}
	for i, k := range n.Keys {
		if k == "root-login" && i > 0 && n.Keys[i-1] == "ssh" {
			return true
		}
	}
	return false
}

func markSynthesizedRootLoginChildren14447(budget *groupExpandBudget, nodes []*Node) {
	for _, n := range nodes {
		if n == nil {
			continue
		}
		if len(n.Keys) > 0 && n.Keys[0] == "root-login" {
			if budget.groupRootLoginLeaves14447 == nil {
				budget.groupRootLoginLeaves14447 = make(map[*Node]bool)
			}
			budget.groupRootLoginLeaves14447[n] = true
		}
		markSynthesizedRootLoginChildren14447(budget, n.Children)
	}
}

// synthesizePackedSystemRootLogin15716 builds the braced shape
// `system { services { ssh { root-login <val> } } }` from a packed
// group leaf `system services ssh root-login <val>` (#15716), or nil.
func synthesizePackedSystemRootLogin15716(s *Node) *Node {
	if s == nil || len(s.Keys) < 5 || s.Keys[0] != "system" || s.Keys[1] != "services" || s.Keys[2] != "ssh" || s.Keys[3] != "root-login" || s.Keys[4] == "" {
		return nil
	}
	rl := &Node{Keys: []string{"root-login", s.Keys[4]}, IsLeaf: true, InheritedFrom: s.InheritedFrom}
	ssh := &Node{Keys: []string{"ssh"}, Children: []*Node{rl}}
	svc := &Node{Keys: []string{"services"}, Children: []*Node{ssh}}
	return &Node{Keys: []string{"system"}, Children: []*Node{svc}}
}
