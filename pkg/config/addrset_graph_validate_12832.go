package config

// validateAddressSetGraphDepthAndCycles12832 walks every path that contributes
// nested-set edges to literal expansion. Address-set members always traverse;
// address members traverse only when no address shadows a same-named set.
func validateAddressSetGraphDepthAndCycles12832(name string, ab *AddressBook) error {
	memo := newAddrSetGraphMemo15003(ab)
	_, err := memo.check(name, 0, make(map[string]bool))
	return err
}

// validateAddressSetGraphForBook15003 (#15003) validates every root in names
// (in order) against ONE shared memo, returning the first failing root and
// its error. validateAddressSetMembersDefinedStrict previously re-ran the
// un-memoised per-root walk once per set.
func validateAddressSetGraphForBook15003(names []string, ab *AddressBook) (string, error) {
	memo := newAddrSetGraphMemo15003(ab)
	for _, name := range names {
		if _, err := memo.check(name, 0, make(map[string]bool)); err != nil {
			return name, err
		}
	}
	return "", nil
}

// addrSetGraphMemo15003 (#15003, A04-02) collapses the repeated traversal of
// the SAME address-set within one validation pass. Without it, a nest of
// sets each referencing B others re-walks every shared subtree on every
// path that reaches it; the depth cap of 5 fixes the exponent at ~B^6
// across all roots, so a ~741-line legal lattice cost ~5.5s per compile on
// the strict and tolerant paths -- under the store read lock on commit
// check, and again on commit, boot load and SyncApply.
//
// heights memoises the MAXIMUM number of nested edges below each node
// (0 for a set with no set edges), recorded only after the node's whole
// subtree has validated cleanly. A completed entry therefore proves the
// subtree is acyclic and every node in it passes
// addressSetForExpansion. Re-entering it never re-walks the subtree: the
// node's own addressSetForExpansion(depth) entry check (depth and cycle
// vs. the current path) runs BEFORE the memo is consulted, and the depth
// cap for the memoised subtree is then decided arithmetically
// (depth+height). When that arithmetic overflows, depthErrorBelow
// reconstructs the exact first-node-wins error the naive walker would
// have produced (verified against naiveExpand / the naive gate walk in
// addrset_graph_memo_15003_test.go). Cycle errors always come from the
// live entry check: a memoised subtree is acyclic by construction, so a
// name on the current path can never hit the memo. Entries are never
// recorded on error, so a subtree that failed under one ancestor path
// is never served as a cached success under another.
type addrSetGraphMemo15003 struct {
	ab      *AddressBook
	heights map[string]int
}

func newAddrSetGraphMemo15003(ab *AddressBook) *addrSetGraphMemo15003 {
	return &addrSetGraphMemo15003{ab: ab, heights: make(map[string]int)}
}

// graphEdges15003 returns the nested-set edges of set in the exact order the
// pre-#15003 traversal walked them: cross-kind `address` members that name
// a set (a same-named address shadows the set and terminates the edge),
// then every `address-set` member.
func graphEdges15003(set *AddressSet, ab *AddressBook) []string {
	var edges []string
	for _, member := range set.Addresses {
		if _, isAddress := ab.Addresses[member]; isAddress {
			continue
		}
		if _, isSet := ab.AddressSets[member]; !isSet {
			continue // the definedness pass reports dangling names
		}
		edges = append(edges, member)
	}
	return append(edges, set.AddressSets...)
}

// checkDepth checks the child at the next depth below a parent entered at
// parentDepth, so the child's own depth entry check runs at parentDepth+1
// before any memo shortcut.
func (m *addrSetGraphMemo15003) checkDepth(name string, parentDepth int, visited map[string]bool) (int, error) {
	return m.check(name, parentDepth+1, visited)
}

// check validates the subtree rooted at name entered at depth, returning
// the subtree height on success. visited is the path-local cycle set,
// shared across sibling edges exactly as before.
func (m *addrSetGraphMemo15003) check(name string, depth int, visited map[string]bool) (int, error) {
	set, err := addressSetForExpansion(name, m.ab, visited, depth)
	if err != nil {
		return 0, err
	}
	if height, ok := m.heights[name]; ok {
		if depth+height > maxAddressSetDepth {
			return 0, m.depthErrorBelow(name, depth, height)
		}
		return height, nil
	}
	visited[name] = true
	defer delete(visited, name)

	height := 0
	for _, member := range graphEdges15003(set, m.ab) {
		childHeight, err := m.checkDepth(member, depth, visited)
		if err != nil {
			return 0, err
		}
		if childHeight+1 > height {
			height = childHeight + 1
		}
	}
	m.heights[name] = height
	return height, nil
}

// depthErrorBelow reconstructs the naive walker's depth error for a fully
// memoised subtree entered at depth with the given height. It descends
// longest-path-first (first edge wins ties, exactly as naive checks in
// member order) and reports via addressSetForExpansion so the message,
// error type and named node match the live entry check: the first node
// that would be entered at depth maxAddressSetDepth+1.
func (m *addrSetGraphMemo15003) depthErrorBelow(name string, depth, height int) error {
	cur, curDepth := name, depth
	for {
		set := m.ab.AddressSets[cur]
		if set == nil {
			return addressSetExpansionErrorf(cur, "address-set nesting too deep (max %d): %s", maxAddressSetDepth, cur)
		}
		best, bestNext, found := -1, "", false
		for _, member := range graphEdges15003(set, m.ab) {
			childHeight, ok := m.heights[member]
			if !ok {
				continue
			}
			if curDepth+1+childHeight <= maxAddressSetDepth {
				continue
			}
			if childHeight > best {
				best, bestNext, found = childHeight, member, true
			}
		}
		if !found {
			_, err := addressSetForExpansion(cur, m.ab, make(map[string]bool), maxAddressSetDepth+1)
			return err
		}
		cur, curDepth = bestNext, curDepth+1
	}
}
