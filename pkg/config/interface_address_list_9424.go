package config

import "fmt"

// Bracketed interface address lists — #9424.
//
// `family inet { address [ 10.0.0.1/24 10.0.0.2/24 ]; }` compiled to ONE
// address. The second and every further address was discarded with no error and
// no warning, through all four config channels and in both AST shapes, on both
// families. The two-separate-stanzas spelling of the same configuration works,
// which is what makes the loss invisible: nothing about the compiled unit says
// an address is missing.
//
// This is the #2419 class. The lexer strips `[`/`]`, so a bracketed list
// collapses onto ONE leaf's Keys in the hierarchical shape and into a CHAIN in
// the flat-set shape:
//
//	hier  [family inet] > [address 10.0.0.1/24 10.0.0.2/24]
//	flat  [family inet] > [address 10.0.0.1/24] > [10.0.0.2/24]
//
// and `namedInstances` (compiler_protocols.go) reads slot 0 only — `Keys[1]`
// and nothing else — so both shapes lose everything past the first. #6662 and
// #7653 both swept `namedInstances` callers and did not reach this one.
//
// # Accumulate, not refuse, and the discriminator that makes that safe
//
// The sibling members of this class were resolved by REFUSING — `security-zone
// [ a b ]` (#8794), a bracketed to-zone list (#9246), `device-map interface
// [ a b ]` (#8810). Each of those refused because EXPANDING would have invented
// a semantics the platform does not have: one policy name living in several
// zone-pair contexts, one device mapped twice. That argument does not apply
// here. A logical unit with two addresses is an ordinary, fully supported
// configuration — the two-stanza control compiles exactly it — so the bracketed
// spelling is a spelling of something real, not a request for something
// undefined.
//
// The reason accumulation needs care is that the packed shape is AMBIGUOUS with
// the brace-elided sub-statement spelling. These parse identically:
//
//	address 10.0.0.1/24 10.0.0.2/24;   a bracketed list  -> two ADDRESSES
//	address 10.0.0.1/24 primary;       an elided body    -> one address + a flag
//
// so a detector keyed on "the node carries extra Keys" refuses the legal
// spelling too. That is the false-positive shape #9246 hit twice and found by
// running the suite rather than by reasoning.
//
// The discriminator is taken from the SCHEMA rather than from a hand-written
// list, so it cannot drift from what the grammar declares: a trailing token is
// an ADDRESS if the address node's own `keyValidator` accepts it
// (ValidateIPv4CIDR / ValidateIPv6CIDR — the exact function the typed-leaf gate
// runs on the first address), a SUB-STATEMENT if it names a declared child of
// `address`, and MALFORMED otherwise.
//
// The malformed arm is not decoration. Without it the fix would turn one silent
// drop into another: `address [ 10.0.0.1/24 not-an-address ]` is accepted today
// with the garbage discarded, and the typed-leaf gate validates only the FIRST
// key slot, so accumulating the valid extras while ignoring the invalid ones
// would leave exactly this issue's defect in place for the case that matters
// most. Malformed tokens are recorded on InterfacesConfig.MalformedAddresses
// and refused by validateInterfaceAddressListStrict — the same
// record-at-compile / reject-in-a-strict-gate shape as
// ScreenProfile.UnknownLeaves and SecurityConfig.MalformedZonePairs, with the
// #1960 lenient downgrade.
//
// OUT OF SCOPE, deliberately: the elided `address 10.0.0.1/24 primary;` spelling
// still loses `primary` in the HIERARCHICAL shape while the flat spelling
// applies it. That is the brace-elision class #9056 owns (its remedy is an
// admission into compactNormalizeInScope), it is a different mechanism, and it
// is measured unchanged by this change rather than assumed unchanged — a cell
// pins the current behaviour so the divergence is visible instead of forgotten.

// addressListInstance is one address configured under a family node, with the
// node its sub-statements (primary / preferred / vrrp-group) hang off.
//
// For an extra address that arrived packed onto a leaf's Keys there is no node
// of its own — the operator could not have attached a sub-statement to it in
// that spelling — so a childless placeholder is used and every FindChild below
// correctly finds nothing. That is deliberate rather than incidental: reusing
// the NAMED instance's node here would apply its `primary` to every address in
// the bracket.
type addressListInstance struct {
	name string
	node *Node
}

// interfaceAddressSchema returns the `address` schema node for a family, so the
// compiler's discriminator and the typed-leaf gate read the SAME declaration.
// Walked explicitly rather than through schemaForPath because the interface
// name and the unit number are instance-name slots, and spelling that path in
// keywords is less legible than the four map lookups it stands for.
func interfaceAddressSchema(family string) *schemaNode {
	ifs := setSchema.children["interfaces"]
	if ifs == nil || ifs.wildcard == nil {
		return nil
	}
	unit := ifs.wildcard.children["unit"]
	if unit == nil {
		return nil
	}
	fam := unit.children["family"]
	if fam == nil {
		return nil
	}
	af := fam.children[family]
	if af == nil {
		return nil
	}
	return af.children["address"]
}

// unitAddressInstances returns every address configured under a family node —
// including the ones a bracketed list packed onto one leaf or nested into a
// chain — plus any trailing token that is neither an address nor a declared
// sub-statement of `address`.
//
// family is "inet" or "inet6" and selects the address validator.
func unitAddressInstances(afNode *Node, family string) (addrs []addressListInstance, malformed []string) {
	if afNode == nil {
		return nil, nil
	}
	schema := interfaceAddressSchema(family)
	// isAddress / isSubStatement fall back to "neither" with a nil schema, which
	// keeps the pre-#9424 behaviour (first address only, nothing recorded)
	// rather than inventing a classification the grammar did not supply.
	isAddress := func(tok string) bool {
		if schema == nil || schema.keyValidator == nil {
			return false
		}
		return schema.keyValidator(tok) == nil
	}
	isSubStatement := func(tok string) bool {
		if schema == nil {
			return false
		}
		_, ok := schema.children[tok]
		return ok
	}

	for _, inst := range namedInstances(afNode.FindChildren("address")) {
		addrs = append(addrs, addressListInstance{inst.name, inst.node})

		// The HIERARCHICAL shape: the rest of the bracket sits on this leaf's
		// own Keys, after the name. instanceValueTail (#7568) anchors on the
		// name rather than on a fixed index, so it is correct for both node
		// shapes namedInstances can hand back.
		a, m := scanAddressTail9424(instanceValueTail(inst.node, inst.name), isAddress, isSubStatement)
		addrs = append(addrs, a...)
		malformed = append(malformed, m...)

		// The FLAT-SET shape: SetPath nests each further bracket element as a
		// CHILD of the previous one, so the rest of the list is a chain. Each
		// link keeps its own node, so a sub-statement the operator attached to a
		// later address is honoured rather than reassigned to the first.
		collectChainedAddresses9424(inst.node, isAddress, isSubStatement, &addrs, &malformed)
	}
	return addrs, malformed
}

// collectChainedAddresses9424 walks the flat-set chain hanging off an address
// node. A child whose first key is an address is another element of the
// bracketed list; the walk then continues through IT, because a longer list
// nests deeper. A child naming a declared sub-statement is the node's own body
// and terminates that branch.
//
// The child's OWN Keys[1:] have to be read as well, which is the same #2419
// trap one level down and is not hypothetical — it was measured. SetPath does
// not nest a three-element list three deep: the second element has no schema
// children, so it ABSORBS the third onto its own Keys and
// `[ a b c ]` becomes
//
//	[address a] > [b c]
//
// A reader taking only `c.Keys[0]` here recovers `b` and loses `c` — the exact
// shape of the defect being fixed, reintroduced by the fix.
func collectChainedAddresses9424(node *Node, isAddress, isSubStatement func(string) bool,
	addrs *[]addressListInstance, malformed *[]string) {
	if node == nil {
		return
	}
	for _, c := range node.Children {
		if c == nil || len(c.Keys) == 0 {
			continue
		}
		tok := c.Keys[0]
		switch {
		case isAddress(tok):
			*addrs = append(*addrs, addressListInstance{tok, c})
			// Trailing elements absorbed onto this link's own Keys. They carry
			// no node, exactly as in the hierarchical shape.
			a, m := scanAddressTail9424(c.Keys[1:], isAddress, isSubStatement)
			*addrs = append(*addrs, a...)
			*malformed = append(*malformed, m...)
			collectChainedAddresses9424(c, isAddress, isSubStatement, addrs, malformed)
		case isSubStatement(tok):
			// The address's own body. Its readers handle it; nothing under a
			// sub-statement is a bracket element (a `vrrp-group` carries
			// IP-valued leaves of its own, and descending would collect them).
		default:
			// A token that is neither. In the flat shape this is where a
			// malformed bracket element lands, and it is silently dropped today.
			*malformed = append(*malformed, tok)
		}
	}
}

// validateInterfaceAddressListStrict hard-rejects a bracketed interface address
// list carrying a token that is neither a valid address for the family nor a
// declared sub-statement of `address` (#9424).
//
// The typed-leaf schema gate validates only the FIRST key slot of an `address`
// leaf, so before this the garbage in `address [ 10.0.0.1/24 not-an-address ]`
// was accepted and discarded — the same silence this issue is about, for the
// case where the operator most needs to be told. Strict on the commit /
// commit-check path; downgraded to a cfg.Warnings entry on the tolerant load /
// peer-sync path (#1960 no-brick), where the compiled unit simply carries the
// addresses that did parse.
//
// Deterministic: MalformedAddresses is appended in config order by
// compileInterfaces, which iterates the interface list and its units in order.
func validateInterfaceAddressListStrict(cfg *Config) error {
	if cfg == nil || len(cfg.Interfaces.MalformedAddresses) == 0 {
		return nil
	}
	return fmt.Errorf(
		"interface address list: %s is not a valid address for its family and is "+
			"not an `address` sub-statement (primary / preferred / vrrp-group), so it "+
			"would be silently dropped and the address the operator configured would "+
			"be absent; a bracketed list `address [ a b ]` must contain addresses only "+
			"(#9424)",
		cfg.Interfaces.MalformedAddresses[0])
}

// scanAddressTail9424 classifies the tokens packed onto an address node after
// its name.
//
// It STOPS at the first token naming a declared `address` sub-statement, and
// that stop is the whole safety of the walk rather than a tidiness choice.
// Everything after such a keyword is that sub-statement's BODY, not more
// addresses:
//
//	address 10.0.0.1/24 vrrp-group 1 virtual-address 10.0.0.100/24;
//
// is the brace-elided spelling of a VRRP stanza. Without the stop, `1` and
// `virtual-address` classify as malformed (so a config an earlier binary
// ACCEPTED starts failing at commit) and `10.0.0.100/24` classifies as an
// ADDRESS — the VIP would be installed on the interface as a real address on
// the tolerant path. Both were measured, not imagined: the repo's own
// #8662/#2419 census flipped two `family inet[6] address <a> vrrp-group` sites
// from drop-shape "empty" to "partial" on the first version of this walk, which
// is a repo-wide guard scanning by CONTENT catching what the per-issue cells
// could not.
//
// A bracketed list never contains a sub-statement keyword, so the stop costs
// this fix nothing. What follows the keyword belongs to the brace-elision class
// #9056 owns, and is left exactly as it was.
func scanAddressTail9424(tail []string, isAddress, isSubStatement func(string) bool) (addrs []addressListInstance, malformed []string) {
	for _, tok := range tail {
		switch {
		case isSubStatement(tok):
			return addrs, malformed
		case isAddress(tok):
			addrs = append(addrs, addressListInstance{tok, &Node{Keys: []string{tok}}})
		default:
			malformed = append(malformed, tok)
		}
	}
	return addrs, malformed
}
