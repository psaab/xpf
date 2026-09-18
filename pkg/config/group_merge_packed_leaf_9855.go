package config

// Packed group leaves against leaf peers (#9855).
//
// A group's packed named-instance statement (`host 10.0.0.1 any any;`,
// `vrrp-group 1 priority 200;`) is a leaf in the AST, so the leaf branch of
// mergeNodes handles it. Its inline peer naming the same instance is also a
// leaf (`host 10.0.0.1;`, `vrrp-group 1 virtual-address ...;`), and the #7648
// expansion runs only against a container peer (ast_groups.go). The
// inline-wins override then drops the packed tail: the host compiles with no
// facilities, the VRRP group with the default priority 100. The braced
// spelling of the same group inherits correctly.
//
// The fix promotes the inline leaf peer to the container its braced spelling
// is (#9801-style promotion, keyed on same-instance identity instead of
// zones) and merges the group's expanded tail into it, so the two spellings
// of one group produce one outcome. Adopting beside is NOT an option: two
// `host` statements for one address compile two destinations (#9854).
//
// Same-statement conflicts resolve exactly as the braced merge does. The
// expansion synthesizes children with IsLeaf=false (compact_tail.go), which
// would bypass the leaf branch and append, so the helpers below mark
// synthesized TERMINALS as leaves before merging: group `any emergency`
// beside inline `any info` keeps `info` (flat-set and braced-merge agree),
// and a multi value such as `virtual-address` takes the leaf-list union
// path. Different properties union by adoption.
//
// Promotion is recorded on the expansion budget because a promoted peer is
// invisible to leafListPeer: successive same-keyword group leaves must
// resolve against it (raw match merges, including across the peer!=nil /
// peer==nil split) or be suppressed as the base suppressed them via the
// pre-promotion leaf. Bare twins and canonical-equal aliases keep that
// suppression; #9859/#10056-qualified different instances are admitted
// instead. The delta against the base is exactly: raw-same packed leaves merge
// instead of dropping or adopting; distinct named instances now survive beside
// their inline peers.

// notePromoted9855 records a node promoteLeafPeerForPackedGroup9855 promoted.
// The map is created lazily — most expansions promote nothing. A nil budget
// (no caller passes one — charge would already have panicked) records
// nothing rather than crashing.
func (b *groupExpandBudget) notePromoted9855(n *Node) {
	if b == nil || n == nil {
		return
	}
	if b.promoted9855 == nil {
		b.promoted9855 = map[*Node]bool{}
	}
	b.promoted9855[n] = true
}

// isPromoted9855 reports whether this expansion promoted n.
func (b *groupExpandBudget) isPromoted9855(n *Node) bool {
	return b != nil && n != nil && b.promoted9855[n]
}

// hasPromotedSibling9855 reports whether dst holds a promoted node naming
// keyword. Zones never appear: promotion declines them, and the #9801
// wildcard promotion does not record.
func (b *groupExpandBudget) hasPromotedSibling9855(dst []*Node, keyword string) bool {
	if b == nil || keyword == "" {
		return false
	}
	for _, d := range dst {
		if d != nil && len(d.Keys) > 0 && d.Keys[0] == keyword && b.promoted9855[d] {
			return true
		}
	}
	return false
}

// packedLeafMergeParts9855 resolves what a packed group leaf needs for a
// same-instance merge: its container schema and its expanded body. It reports
// false whenever the existing override/adopt behavior must stand: zone
// statements (owned by #9801/#9831), scalar/unmodelled/no-tail leaves (the
// #7648 expansion declines them all), and a schema the ancestor path cannot
// resolve.
func packedLeafMergeParts9855(ancestorPath [][]string, s *Node) (leafSchema *schemaNode, body []*Node, ok bool) {
	if s == nil || groupZoneLeaf9831(ancestorPath, s) {
		return nil, nil, false
	}
	if body = groupPackedLeafBody(ancestorPath, s); body == nil {
		return nil, nil, false
	}
	parent := schemaAtAncestorPath(ancestorPath)
	if parent == nil {
		return nil, nil, false
	}
	if leafSchema = resolveSchemaChild(parent, s.Keys[0]); leafSchema == nil || leafSchema.children == nil {
		return nil, nil, false
	}
	return leafSchema, body, true
}

// identitySpan9855 returns the shared identity-span length when a and b name
// the same instance under leafSchema: equal consumed spans (keyword +
// instance keys via consumeNodeKeys) of length >= 2. A bare keyword
// (span 1) keeps override — this rule is for named instances. Raw key
// equality: canonical aliases (`ospf area 0` vs `area 0.0.0.0`) keep
// override rather than risk a duplicate (#9859).
func identitySpan9855(leafSchema *schemaNode, a, b []string) (int, bool) {
	ac, _ := consumeNodeKeys(a, leafSchema)
	bc, _ := consumeNodeKeys(b, leafSchema)
	if ac < 2 || ac != bc || !keysEqual(a[:ac], b[:bc]) {
		return 0, false
	}
	return ac, true
}

// sameNodes9855 reports whether two node slices hold the same nodes.
// packedBodyChildren returns the input children unchanged when a tail leaves
// the modelled grammar, so identity here means "the tail did not expand".
func sameNodes9855(a, b []*Node) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// markSynthTerminals9855 marks childless synthesized nodes as leaves so the
// recursive merge takes the ordinary leaf override/union path for them. Only
// freshly synthesized roots may be passed: both callers bail when either
// side already carries children (unreachable for parser leaves — a `;`
// carries no braces — so the bail is pure defense and the mark never touches
// an operator-authored node).
func markSynthTerminals9855(nodes []*Node) {
	for _, n := range nodes {
		if n == nil {
			continue
		}
		if len(n.Children) == 0 {
			n.IsLeaf = true
			continue
		}
		markSynthTerminals9855(n.Children)
	}
}

// promoteLeafPeerForPackedGroup9855 merges a packed group leaf s into a
// same-instance inline LEAF peer by promoting the peer to the container its
// braced spelling is, and returns the group body for the caller to merge
// into the promoted children. It reports false — keeping the existing
// override — unless every gate holds: a clean leaf peer, an expandable
// packed group body, the same raw instance, and a peer tail (if any) that
// expands under the schema. An unexpandable peer tail bails so truncation
// cannot drop tail tokens that downstream gates scanning Keys must see.
func promoteLeafPeerForPackedGroup9855(ancestorPath [][]string, peer, s *Node) ([]*Node, bool) {
	if peer == nil || !peer.IsLeaf || s == nil {
		return nil, false
	}
	if len(s.Children) > 0 || len(peer.Children) > 0 {
		return nil, false
	}
	leafSchema, body, ok := packedLeafMergeParts9855(ancestorPath, s)
	if !ok {
		return nil, false
	}
	span, ok := identitySpan9855(leafSchema, s.Keys, peer.Keys)
	if !ok {
		return nil, false
	}
	var peerBody []*Node
	if tail := peer.Keys[span:]; len(tail) > 0 {
		peerBody = packedBodyChildren(peer, leafSchema)
		if sameNodes9855(peerBody, peer.Children) {
			return nil, false
		}
	}
	oldKeys := peer.Keys
	peer.Keys = append([]string(nil), oldKeys[:span]...)
	if len(peer.KeysQuoted) == len(oldKeys) {
		peer.KeysQuoted = append([]bool(nil), peer.KeysQuoted[:span]...)
	}
	if len(peer.KeysBracketed) == len(oldKeys) {
		peer.KeysBracketed = append([]bool(nil), peer.KeysBracketed[:span]...)
	}
	peer.Children = peerBody
	peer.IsLeaf = false
	markSynthTerminals9855(peerBody)
	markSynthTerminals9855(body)
	return body, true
}

// sameInstanceContainerPeer9855 finds the container a packed group leaf merges
// into when the leaf branch found no peer. A promoted peer is a two-key
// container, which leafListPeer cannot select, so without this a second
// packed group leaf for the same instance would adopt beside the first and
// compile a second destination (review finding 1). The scan also reaches an
// inline braced stanza naming the same instance — one node, merged — which
// converges with the braced-merge semantics and with #10048's expectation
// for that shape. Distinct instances and canonical aliases remain on the
// existing adopt/override path.
func sameInstanceContainerPeer9855(ancestorPath [][]string, dst []*Node, s *Node) (*Node, []*Node, bool) {
	if s == nil || len(s.Keys) == 0 || len(s.Children) > 0 {
		return nil, nil, false
	}
	_, body, ok := packedLeafMergeParts9855(ancestorPath, s)
	if !ok {
		return nil, nil, false
	}
	peer := rawInstanceContainer9855(ancestorPath, dst, s)
	if peer == nil {
		return nil, nil, false
	}
	markSynthTerminals9855(body)
	return peer, body, true
}

// rawInstanceContainer9855 returns the dst container naming the same raw
// instance as the group leaf s, or nil. Unlike the fallback above it needs
// no packed body: a bare (`host A;`) twin is redundant against it too. Zones
// are excluded (owned by #9801/#9831); value lists never match (their schema
// carries no children, so there is no instance span to compare).
func rawInstanceContainer9855(ancestorPath [][]string, dst []*Node, s *Node) *Node {
	if s == nil || len(s.Keys) == 0 || groupZoneLeaf9831(ancestorPath, s) {
		return nil
	}
	parent := schemaAtAncestorPath(ancestorPath)
	if parent == nil {
		return nil
	}
	leafSchema := resolveSchemaChild(parent, s.Keys[0])
	if leafSchema == nil || leafSchema.children == nil {
		return nil
	}
	for _, d := range dst {
		if d == nil || d.IsLeaf || len(d.Keys) == 0 || d.Keys[0] != s.Keys[0] {
			continue
		}
		if _, ok := identitySpan9855(leafSchema, s.Keys, d.Keys); ok {
			return d
		}
	}
	return nil
}

// suppressSuccessiveLeaf9855 reports whether a group leaf with no raw peer
// must be suppressed instead of adopted. TWO paths at the #9859 boundary must
// evolve together: namedLeafPeer9859's keyword/identity override when a peer
// exists, and this successive-merge guard when a promoted sibling exists but
// no raw peer remains. If the first path admits a different-instance leaf, the
// second must admit its counterpart too, or the same pair resolves differently
// by source order relative to promotion (#10056).
//
// A nested-group promotion can also surface as a container source against a
// leaf destination (container-src versus leaf-dst), the pre-existing braced
// group plus inline-leaf class. Such twins coalesce at compile (#10048 syslog;
// VRRP merges by group ID last-wins); future changes on this branch must treat
// nested-promoted sources consistently.
//
// Two successive-merge hazards share it, and both restore what the base did
// before promotion existed:
//
//   - a BARE twin of a promoted container (`host A;` trailing `host A any
//     any;`) names an instance already present and adds nothing — adopting
//     it twins the node (failure 2). A raw braced twin still adopts: the
//     base adopts there too, and #10048 coalesces the pair at compile.
//   - a leaf naming no raw peer while a promoted same-keyword sibling exists:
//     the base suppressed it via the pre-promotion leaf. Canonical aliases,
//     value lists, and unqualified shapes keep that suppression; a qualified
//     different named-container instance is admitted by #9859/#10056 before
//     this guard so it is not lost beside the promoted sibling.
func suppressSuccessiveLeaf9855(budget *groupExpandBudget, ancestorPath [][]string, dst []*Node, s *Node) bool {
	if s == nil || len(s.Keys) == 0 {
		return false
	}
	if c := rawInstanceContainer9855(ancestorPath, dst, s); c != nil {
		return budget.isPromoted9855(c)
	}
	// #9859/#10056: once peer selection admits named-container leaves by
	// identity, a different instance must be adopted even when an earlier
	// same-keyword leaf promoted a sibling. Keep the old suppression for
	// value lists, canonical-alias sites, and all unqualified shapes.
	if namedLeafCanAdopt9859(ancestorPath, dst, s) {
		return false
	}
	return budget.hasPromotedSibling9855(dst, s.Keys[0])
}
