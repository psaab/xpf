package config

// Packed wildcard group leaves (#16548).
//
// A hierarchical group statement such as
// `interface <*> authentication md5 1 key K;` parses as ONE leaf whose Keys
// pack the wildcard identity and its whole body (the brace-elided or compact
// spelling, documented as equivalent to the braced one by #8662/#7648). The
// leaf arm of mergeNodes has no wildcard check — the only
// keysContainWildcard check sat after it, on the container path — so the
// packed leaf was adopted literally whenever no inline leaf shared its
// first key. The compiler then built an OSPF interface literally named
// `<*>` carrying the md5 key, while the real ge-0/0/0.0 stayed
// unauthenticated behind only the indirect #9405 advisory naming the
// phantom. The braced spelling `interface <*> { authentication { ... } }`
// is a container and takes the wildcard branch, fanning the body out to
// every matching destination.
//
// packedWildcardLeafBraced16548 splits the packed leaf at its identity
// span and rebuilds exactly that braced container, so mergeNodes routes
// both spellings through the same wildcard branch: the body reaches every
// matching destination, and a pattern matching nothing invents nothing
// (#9423). This is the source-side counterpart of #9423/#9802, which
// fixed the container matcher and the wholesale-adoption prune but could
// not see a wildcard packed into a leaf's Keys.
//
// Admission is deliberately narrow, mirroring wildcardInstanceNode9802:
// the wildcard must sit inside the identity span (keyword + schema args,
// via consumeNodeKeys so compound keys count too) of a container-shaped
// schema child, and the packed tail past the span must expand under that
// schema or be carried as the #12530 unmodelled tail. Therefore:
//
//   - a wildcard in a VALUE position (`description "<*>";`) or a MEMBER
//     position (`interfaces <ge-*>;` — span 1, no arg to hold it) is not
//     an instance key and keeps its existing handling: the member stays
//     loudly refused (TestGroupKeyWildcardLeafMemberStillRefused9423) and
//     the scalar value stays an ordinary leaf;
//   - a scalar or unmodelled leaf, an identity-only leaf (nothing to fan
//     out — binding a bare destination leaf is the sibling #16543
//     question, not this one), and a tail the schema cannot carry all
//     keep the existing leaf path;
//   - a destination written bare (`interface ge-0/0/0.0;`) is the
//     sibling #16543 bare-leaf binding (landed in 4975225633): the two
//     spellings stay equal there by construction, since both route
//     through the same wildcard branch after this split.
//
// The destination side needs no new code: a braced destination already
// takes the fan-out, a brace-elided destination is promoted by #15032
// inside the wildcard branch, and a bare-leaf destination takes the
// #9801/#16543 promotion in that same branch.

// packedWildcardLeafBraced16548 returns the braced equivalent of a packed
// group leaf whose identity span carries a wildcard key, or nil when s is
// not such a leaf (#16548). A hierarchical statement such as
// `interface <*> authentication md5 1 key K;` parses as ONE leaf whose Keys
// pack the wildcard identity and its whole body. The leaf arm of mergeNodes
// has no wildcard check, so it adopted that leaf literally and compiled a
// phantom OSPF interface named `<*>` while the real interfaces stayed
// unauthenticated. The braced spelling
// `interface <*> { authentication { ... } }` is a container and takes the
// wildcard branch. Splitting the packed leaf at its identity span rebuilds
// exactly that container, so both spellings fan the same body out to the
// same destinations and a pattern matching nothing invents nothing (#9423).
//
// Admission is deliberately narrow, mirroring wildcardInstanceNode9802:
// the wildcard must sit inside the identity span (keyword + schema args)
// of a container-shaped schema child, and the packed tail must expand
// under that schema or be carried as the #12530 unmodelled tail. A
// wildcard in a value or MEMBER position (`interfaces <ge-*>;`,
// `description "<*>";`) is not an instance key and keeps its existing
// loud refusal or ordinary leaf handling. A scalar/unmodelled leaf, an
// identity-only leaf (nothing to fan out — the bare-leaf binding question
// owned by the sibling cohort), and a tail the schema cannot carry all
// keep the existing leaf path.
func packedWildcardLeafBraced16548(ancestorPath [][]string, s *Node) *Node {
	if s == nil || !s.IsLeaf || len(s.Keys) < 2 || len(s.Children) > 0 ||
		!keysContainWildcard(s.Keys) {
		return nil
	}
	parent := schemaAtAncestorPath(ancestorPath)
	if parent == nil {
		return nil
	}
	// Dynamic instance slots (`interfaces { <name> { ... } }`) declare no
	// named child for the instance: the level's own wildcard schema IS the
	// instance schema, and the leaf's first key is the instance name
	// itself, so the identity span is that single key.
	if _, isWildcardKey := groupKeyPattern(s.Keys[0]); isWildcardKey &&
		parent.children == nil && parent.wildcard != nil &&
		(parent.wildcard.children != nil || parent.wildcard.wildcard != nil) {
		wrapped := &Node{
			Keys:          append([]string{"", s.Keys[0]}, s.Keys[1:]...),
			IsLeaf:        true,
			InheritedFrom: s.InheritedFrom,
		}
		if len(s.KeysQuoted) == len(s.Keys) {
			wrapped.setKeysQuoted(append([]bool{false, false}, s.KeysQuoted[1:]...))
		}
		if len(s.KeysBracketed) == len(s.Keys) {
			wrapped.setKeysBracketed(append([]bool{false, false}, s.KeysBracketed[1:]...), s.BracketedClosed)
		}
		body := packedBodyChildren(wrapped, parent.wildcard)
		if len(body) == 0 || sameNodes9855(body, wrapped.Children) {
			body = groupPackedLeafUnmodelledTailAt16548(parent.wildcard, wrapped, 2)
		}
		if body == nil {
			return nil
		}
		braced := &Node{
			Keys:          append([]string(nil), s.Keys[:1]...),
			InheritedFrom: s.InheritedFrom,
			Inactive:      s.Inactive,
			Annotation:    s.Annotation,
			Line:          s.Line,
			Column:        s.Column,
		}
		if len(s.KeysQuoted) == len(s.Keys) {
			braced.setKeysQuoted(append([]bool(nil), s.KeysQuoted[:1]...))
		}
		if len(s.KeysBracketed) == len(s.Keys) {
			braced.setKeysBracketed(append([]bool(nil), s.KeysBracketed[:1]...), s.BracketedClosed)
		}
		braced.fromGroups = append([]string(nil), s.fromGroups...)
		braced.Children = body
		return braced
	}
	leafSchema := resolveSchemaChild(parent, s.Keys[0])
	if leafSchema == nil || (leafSchema.children == nil && leafSchema.wildcard == nil) {
		return nil
	}
	consumed, _ := consumeNodeKeys(s.Keys, leafSchema)
	if consumed < 2 || consumed >= len(s.Keys) ||
		!keysContainWildcard(s.Keys[1:consumed]) {
		return nil
	}
	body := groupPackedLeafBody(ancestorPath, s)
	if body == nil {
		body = groupPackedLeafUnmodelledTail(ancestorPath, s)
	}
	if body == nil {
		return nil
	}
	braced := &Node{
		Keys:          append([]string(nil), s.Keys[:consumed]...),
		InheritedFrom: s.InheritedFrom,
		Inactive:      s.Inactive,
		Annotation:    s.Annotation,
		Line:          s.Line,
		Column:        s.Column,
	}
	if len(s.KeysQuoted) == len(s.Keys) {
		braced.setKeysQuoted(append([]bool(nil), s.KeysQuoted[:consumed]...))
	}
	if len(s.KeysBracketed) == len(s.Keys) {
		braced.setKeysBracketed(append([]bool(nil), s.KeysBracketed[:consumed]...), s.BracketedClosed)
	}
	braced.fromGroups = append([]string(nil), s.fromGroups...)
	braced.Children = body
	return braced
}

// groupPackedLeafUnmodelledTailAt16548 is groupPackedLeafUnmodelledTail for
// a caller that already holds the instance schema: the tail past the
// identity span (identity keys, 1 for a dynamic instance name) rides as one
// leaf so post-expansion gates judge the tokens exactly as authored.
func groupPackedLeafUnmodelledTailAt16548(leafSchema *schemaNode, s *Node, consumed int) []*Node {
	if s == nil || leafSchema == nil || consumed <= 0 || consumed >= len(s.Keys) {
		return nil
	}
	tail := &Node{
		Keys:          append([]string(nil), s.Keys[consumed:]...),
		IsLeaf:        true,
		InheritedFrom: s.InheritedFrom,
	}
	if len(s.KeysQuoted) == len(s.Keys) {
		tail.setKeysQuoted(append([]bool(nil), s.KeysQuoted[consumed:]...))
	}
	if len(s.KeysBracketed) == len(s.Keys) {
		tail.setKeysBracketed(append([]bool(nil), s.KeysBracketed[consumed:]...), s.BracketedClosed)
	}
	return []*Node{tail}
}
