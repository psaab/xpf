package config

import "regexp"

// #14444 (DR18-H9): the container branch of mergeNodes ignored
// groupReplace/range on block/block pairs.
//
// A single-key group container whose schema leaf is groupReplace
// (firewall destination-port/source-port/*-except, NAT match
// destination-port, NAT pool address, policy then community /
// as-path-prepend) failed isLeafListSchema (which excludes
// groupReplace), so it fell through to the generic container
// child-merge. That merge adopts any group member whose first token
// differs from the inline members — a UNION even for ranges. The leaf
// path for the same statement drops the group value (inline wins).
// Block/block therefore compiled traffic the override semantics say
// to discard (positive hyphen range) or let discard-scoped traffic
// escape (except hyphen range), on both strict and lenient paths.
//
// The container branch must take the SAME decision as the leaf path,
// refined per DR16-H1 for ports:
//
//   - port leaves: UNION iff neither side carries a range, else
//     OVERRIDE (inline only). A blanket drop would reintroduce the
//     DR16-H1 fail-open through the block shape (group {443} beside
//     inline {80} must union to {80,443}).
//   - every non-port groupReplace leaf: OVERRIDE unconditionally.
//   - no inline peer: ADOPT (genuine inheritance, unchanged).
//   - inline empty block: OVERRIDE (empty is a peer, group dropped).
//
// Port-leaf identity is keyed on the schema node pointer, not the
// bare keyword, so a destination-port under a non-port parent is not
// misclassified and a future port leaf at another path is not
// silently unioned.

// groupReplacePortLeaves14444 is the closed set of schema leaves that
// are both groupReplace and ports, where range-free union is the
// prescribed DR16-H1 behaviour. Keyed by schema node pointer.
var groupReplacePortLeaves14444 map[*schemaNode]bool

func init() {
	groupReplacePortLeaves14444 = map[*schemaNode]bool{}
	add := func(n *schemaNode) {
		if n != nil {
			groupReplacePortLeaves14444[n] = true
		}
	}
	child := func(n *schemaNode, k string) *schemaNode {
		if n == nil {
			return nil
		}
		return n.children[k]
	}
	// Firewall filter from ports, family inet + inet6.
	for _, fam := range []string{"inet", "inet6"} {
		from := child(child(child(child(child(schemaFirewall, "family"), fam), "filter"), "term"), "from")
		for _, k := range []string{"destination-port", "source-port", "destination-port-except", "source-port-except"} {
			add(child(from, k))
		}
	}
	// NAT match destination-port (source + destination rule-sets).
	nat := child(schemaSecurity, "nat")
	for _, dir := range []string{"source", "destination"} {
		add(child(child(child(child(child(nat, dir), "rule-set"), "rule"), "match"), "destination-port"))
	}
}

// groupReplaceSchema14444 resolves the schema leaf for key at
// ancestorPath, or nil when unmodelled.
func groupReplaceSchema14444(ancestorPath [][]string, key string) *schemaNode {
	parent := schemaAtAncestorPath(ancestorPath)
	if parent == nil {
		return nil
	}
	return resolveSchemaChild(parent, key)
}

// groupReplaceLeafAt14444 reports whether key at ancestorPath is a
// schema groupReplace leaf (multi, children==nil — the same shape the
// leaf path classifies via isLeafListSchema's groupReplace exclusion).
func groupReplaceLeafAt14444(ancestorPath [][]string, key string) bool {
	leaf := groupReplaceSchema14444(ancestorPath, key)
	return leaf != nil && leaf.groupReplace && leaf.children == nil
}

// isGroupReplacePortLeaf14444 reports whether key at ancestorPath is
// one of the port groupReplace leaves (pointer identity).
func isGroupReplacePortLeaf14444(ancestorPath [][]string, key string) bool {
	leaf := groupReplaceSchema14444(ancestorPath, key)
	return leaf != nil && groupReplacePortLeaves14444[leaf]
}

var hyphenRange14444 = regexp.MustCompile(`^\d+-\d+$`)

// groupReplaceBlockCarriesRange14444 reports whether a block (or leaf)
// node's members carry a range: any member token equal to the "to"
// separator, any hyphen-range token (digits-digits — the form
// leafListCarriesRange misses), a multi-token member (e.g. a child
// leaf "1000 to 2000" whose Keys pack the separator), or a "port"
// separator token (DNAT pool address packs `address <ip> port <n>`;
// its presence means the value is not a plain member set — only
// consulted for non-port leaves via the unconditional override, kept
// here for completeness of the range predicate).
func groupReplaceBlockCarriesRange14444(n *Node) bool {
	if n == nil {
		return false
	}
	if leafListCarriesRange(n) {
		return true
	}
	for _, m := range leafListMembers9627(n) {
		if hyphenRange14444.MatchString(m.value) {
			return true
		}
	}
	// Multi-token child leaves: `1000 to 2000;` inside a block parses
	// to a child with Keys [1000 to 2000]; leafListMembers9627 flattens
	// it, so the "to" check above already sees it. A child with more
	// than one key that is not flattened as separate members still
	// counts as packed (defensive).
	for _, c := range n.Children {
		if c != nil && len(c.Keys) > 1 {
			return true
		}
	}
	return false
}

// groupReplaceBlockPeer14444 returns the inline peer for a groupReplace
// block source s: a same-keyed container (generic path peer), or a
// same-keyed leaf (mixed shape — block group beside collapsed inline
// leaf takes the same decision). Returns nil when no peer exists.
func groupReplaceBlockPeer14444(dst []*Node, s *Node) *Node {
	if targets := sameKeyedContainers9802(dst, s.Keys); len(targets) > 0 {
		return targets[0]
	}
	// Mixed shape: inline collapsed leaf with same Keys[0].
	if len(s.Keys) == 1 {
		if peer := leafListPeer(dst, s.Keys[0]); peer != nil {
			return peer
		}
	}
	return nil
}

// groupReplaceBlockHandled14444 applies the #14444 decision for a
// single-key groupReplace block source. It reports handled=true when
// the generic container path must not see s (union done or override
// drop). handled=false means no inline peer — fall through to normal
// adoption.
func groupReplaceBlockHandled14444(ancestorPath [][]string, dst *[]*Node, s *Node) bool {
	if s == nil || s.IsLeaf || len(s.Keys) != 1 {
		return false
	}
	if !groupReplaceLeafAt14444(ancestorPath, s.Keys[0]) {
		return false
	}
	peer := groupReplaceBlockPeer14444(*dst, s)
	if peer == nil {
		return false
	}
	if isGroupReplacePortLeaf14444(ancestorPath, s.Keys[0]) &&
		!groupReplaceBlockCarriesRange14444(peer) &&
		!groupReplaceBlockCarriesRange14444(s) {
		mergeLeafListInto(peer, s)
		appendDuplicateBlockMergeMarkersToLeaves9023([]*Node{peer},
			duplicateBlockMergeMarkers9023(s))
		return true
	}
	// OVERRIDE: inline (or earlier-adopted group) peer wins.
	return true
}
