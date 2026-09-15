package config

// #9017: `set firewall family any filter BLOCK term T1 then discard` COMMITTED
// CLEAN AND MINTED ZERO FILTERS. A Junos-valid deny-everything-not-matched
// filter, authored on the primary configuration surface, displayed in `show`
// and enforced nothing -- no counter, no warning, and no difference in output
// between "installed" and "does not exist".
//
// The hierarchical spelling of the same configuration worked, which is what
// kept it invisible.
//
// TWO SEPARATE DEFECTS SHARED ONE SYMPTOM, and fixing only the first leaves the
// worse one live:
//
//  1. `any` was not DECLARED as a `family` child, so the flat-set path could
//     not nest it and never delivered the token to compiler_firewall.go -- which
//     has handled `case "any": dests = {Inet, Inet6}` all along. The support
//     existed; the spelling could not reach it.
//
//  2. The `family` compound key was OPEN-WORLD, so ANY undeclared
//     address-family token collapsed the same way. `family inett` -- a typo --
//     also committed clean and minted zero filters. A fix aimed only at `any`
//     leaves every typo voiding a filter silently, which is the fail-open half.
//
// Both are fixed here: `any` is declared, and the compound key is closed so an
// unknown family is REFUSED at the commit gate with the token named.
func init() {
	fam := schemaFirewall.children["family"]
	inet := fam.children["inet"]

	// `any` gets a DEEP COPY of inet's subtree, not a shared pointer.
	//
	// Sharing was tried first and is wrong for a reason worth recording: this
	// tree is walked by a dozen schema CENSUSES, and several of them dedup by
	// NODE IDENTITY. With one node reachable at two paths, a census attributes
	// it to whichever path it reaches first and the other path silently stops
	// being covered -- measured directly, as #8768 reporting that
	// `firewall/family/inet/filter/term/then` "no longer opts in" while
	// `firewall/family/any/filter/term/then` appeared with no fixtures. Nothing
	// about inet had changed; only its visibility to the instrument had.
	//
	// A copy costs drift instead, and drift is the failure a test can see:
	// TestFirewallFamiliesAcceptTheSameGrammar9017 compares the explicit
	// families and implicit inet, so grammar drift fails visibly.
	fam.children["any"] = &schemaNode{
		desc:     "IPv4 and IPv6 firewall filters (compiles to both families)",
		children: deepCopySchemaChildren9017(inet.children, 0),
	}

	// Junos permits [edit firewall filter] as implicit family inet (#9899).
	// Give this spelling its own schema identities for the same census reason.
	schemaFirewall.children["filter"] = deepCopySchemaChildren9017(inet.children, 0)["filter"]

	// The undeclared-token half of #9017 is NOT done here. `closedWorld: true`
	// on the compound key was tried and reverted: the flag INHERITS, so it
	// closed the whole filter grammar beneath `family` and began rejecting
	// `from source-prefix-list trusted` -- valid, shipped configuration. The
	// scoped gate is validateFirewallFilterFamilyTokensAST.
}

// deepCopySchemaChildren9017 copies a schema subtree. The depth bound is a
// guard against a cyclic schema rather than an expected limit -- `groups`
// mirrors the top-level children, so a copy that wandered upward would not
// terminate. The firewall filter subtree is about six levels deep.
func deepCopySchemaChildren9017(src map[string]*schemaNode, depth int) map[string]*schemaNode {
	if src == nil || depth > 24 {
		return nil
	}
	out := make(map[string]*schemaNode, len(src))
	for k, v := range src {
		if v == nil {
			continue
		}
		c := *v // copy every scalar field, including validators and value hints
		c.children = deepCopySchemaChildren9017(v.children, depth+1)
		if v.wildcard != nil {
			w := *v.wildcard
			w.children = deepCopySchemaChildren9017(v.wildcard.children, depth+1)
			c.wildcard = &w
		}
		out[k] = &c
	}
	return out
}
