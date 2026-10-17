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

func isRootLoginLeaf14447(ancestorPath [][]string, n *Node) bool {
	if n == nil || len(n.Keys) == 0 || n.Keys[0] != "root-login" {
		return false
	}
	// ancestorPath must end with system/services/ssh
	if len(ancestorPath) < 3 {
		return false
	}
	keysEq := func(k []string, name string) bool { return len(k) > 0 && k[0] == name }
	return keysEq(ancestorPath[len(ancestorPath)-3], "system") &&
		keysEq(ancestorPath[len(ancestorPath)-2], "services") &&
		keysEq(ancestorPath[len(ancestorPath)-1], "ssh")
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
