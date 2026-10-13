package cmdtree

// EveryWordIsAKeyword reports whether words spell one argument-free command
// path against tree: every word names a real node in the tree rather than
// being consumed by a value slot, and only the LAST word may be a leaf. A
// leaf is a complete command, so a word after it is an argument or, under a
// node that declares Options, a second option: `summary zone` under
// `show security flow session` is two keywords and still not one path
// (#12527).
//
// A word that is a literal `<…>` placeholder never passes either: a table
// entry holding `show route <destination> exact` names a value slot, not a
// command path (#12582). No current entry contains one.
//
// Deliberately NOT a change to Canonicalize: absorbing operator data into
// value slots, and taking options in any order (#9505), is exactly what
// canonicalization must do for a command an operator typed. The distinction
// is that the authorization command TABLES (gRPC #7172, REST #9952) hold
// argument-free command paths, so the stricter rule belongs to the tables'
// validity checks and not to the shared canonicalizer. This helper is the
// one implementation both surfaces' checks share, so they cannot drift.
func EveryWordIsAKeyword(tree map[string]*Node, words []string) bool {
	current := tree
	for i, w := range words {
		if isPlaceholder(w) {
			return false
		}
		node, ok := current[w]
		if !ok {
			return false
		}
		if node.Children == nil {
			// A leaf: any further word would be an argument or a second
			// option, which these tables must not contain (#12527). The old
			// code returned true here unconditionally, so `show security
			// flow session summary zone` passed: `summary` is a leaf and
			// `zone` was never examined, while Canonicalize re-enters the
			// Options map and also accepts it.
			return i == len(words)-1
		}
		current = node.Children
	}
	return true
}
