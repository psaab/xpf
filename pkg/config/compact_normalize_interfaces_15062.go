package config

// normalizeElidedInterface15062 rewrites a brace-elided top-level
// `interfaces <name> { ... }` stanza into the braced shape the parser
// builds for the same statements (#15062, A01-01):
//
//	interfaces ge-0/0/0 { unit 0 { family inet { address 10.9.9.1/24; } } }
//	interfaces { ge-0/0/0 { unit 0 { family inet { address 10.9.9.1/24; } } } }
//
// Mechanism before this fix: compileSections dispatches on node.Name()
// (Keys[0] == "interfaces") and ignores Keys[1:], so the elided node
// reached compileInterfaces as the `interfaces` container itself. Every
// child of that node — `unit`, `family`, ... — then became an
// InterfaceConfig named child.Name(), producing phantom interfaces such
// as `unit` while the named interface (ge-0/0/0, fxp0) and its
// address/DHCP/MTU were lost on a clean commit. The same shape reaches
// the day-0 path: configstore.CheckText is compileTreeStrict, so a
// top-level elided fxp0 stanza validated clean there too.
//
// The scoped fold cannot do this: its pair at this site would be
// (interfaces, <operator-chosen name>), and no scope entry can name an
// instance name (#8879). This mirrors normalizeElidedRoutingInstance9620
// (#9620) for routing-instances, but the interfaces case is simpler:
// the elided node carries exactly one extra key — the interface name —
// and its braced body already is the interface body. No statement
// splitting is needed; the body moves under a synthesized
// `<name>` node verbatim, and the scoped fold / packedBody readers then
// handle any packed tails inside it exactly as in the braced spelling.
//
// Deliberately NOT rewritten:
//   - `interfaces { ... }` (len(Keys)==1): the ordinary braced form.
//   - `interfaces <name>;` as a leaf with no body and no tail beyond
//     the name: there is no interface body to preserve, and the braced
//     equivalent `interfaces { <name>; }` compiles to no interface
//     (compileInterfaces skips a childless leaf with no bandwidth), so
//     both spellings already agree. Only a leaf whose Keys run PAST
//     the name (`interfaces ge-0/0/0 unit 0 family inet dhcp;`) carries
//     statements that would otherwise become phantoms, so it is folded.
//   - apply statements at the top level (`interfaces apply-groups G;`
//     and siblings, #9685): schemaChildFor resolves them before the
//     wildcard, group expansion consumes them by name, and they are
//     not interface names. Rewriting one into
//     `interfaces { apply-groups { G; } }` would change its shape.
//   - A name token that is itself a declared child keyword of the
//     interfaces wildcard cannot occur: the wildcard has no declared
//     children at the name slot, and any token in Keys[1] is by
//     construction the operator's interface name. (A quoted name that
//     spells a keyword, e.g. `interfaces "unit" { ... }`, is still a
//     name: ValidateInterfaceName is the gate for its characters, and
//     the braced spelling treats it identically.)
//
// KeysQuoted / KeysBracketed are per-key masks (ast.go: nil or exactly
// len(Keys)); they move with the name key onto the synthesized node so
// no provenance is dropped or misaligned (#8921 discipline).
//
// Returns 1 when it rewrote the node, 0 otherwise.
func normalizeElidedInterface15062(node *Node) int {
	if node == nil || len(node.Keys) < 2 {
		return 0
	}
	// A top-level apply statement packs its keyword into Keys[1]
	// (`interfaces apply-groups G;`): it is not an interface name
	// (#9685). isApplyStatementNode checks Keys[0], so test Keys[1] here.
	if isApplyStatementKeyword(node.Keys[1]) {
		return 0
	}
	// A bare leaf `interfaces <name>;` carries no body: nothing is lost
	// today and the braced spelling agrees, so leave it untouched.
	if node.IsLeaf && len(node.Children) == 0 && len(node.Keys) == 2 {
		return 0
	}
	quoted := keyMask8921(node.KeysQuoted, len(node.Keys))
	bracketed := keyMask8921(node.KeysBracketed, len(node.Keys))
	bracketedClosed := node.BracketedClosed

	name := &Node{
		Keys:   []string{node.Keys[1]},
		Line:   node.Line,
		Column: node.Column,
	}
	name.setKeysQuoted(maskSlice8921(quoted, 1, 2))
	name.setKeysBracketed(maskSlice8921(bracketed, 1, 2), bracketedClosed)

	if len(node.Keys) > 2 {
		// Packed tail past the name, e.g.
		// `interfaces ge-0/0/0 unit 0 { ... }` or the leaf
		// `interfaces ge-0/0/0 unit 0 family inet dhcp;`.
		// Keep the tail on the name node; compileInterfaces already
		// expands an interface node's packed tail through the schema
		// (packedBody / expandResolvingRun9792, #14442), and the scoped
		// fold recursing into the rewritten body handles the rest, so
		// this spelling compiles exactly as the braced one does.
		name.Keys = append(name.Keys, node.Keys[2:]...)
		name.setKeysQuoted(maskSlice8921(quoted, 1, len(node.Keys)))
		// Recompute bracketed mask over the full new key span.
		name.setKeysBracketed(maskSlice8921(bracketed, 1, len(node.Keys)), bracketedClosed)
	}
	if len(node.Children) > 0 {
		name.Children = node.Children
		name.IsLeaf = false
	} else if node.IsLeaf {
		// Leaf with a packed tail: stays a leaf; its tail is the
		// interface body in packed form.
		name.IsLeaf = true
	}

	node.Keys = node.Keys[:1:1]
	node.setKeysQuoted(maskSlice8921(quoted, 0, 1))
	node.setKeysBracketed(maskSlice8921(bracketed, 0, 1), bracketedClosed)
	node.Children = []*Node{name}
	node.IsLeaf = false
	return 1
}
