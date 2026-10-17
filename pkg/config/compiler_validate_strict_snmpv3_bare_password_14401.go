package config

import "fmt"

// compiler_validate_strict_snmpv3_bare_password_14401.go — #14401.
//
// A bare `authentication-password` / `privacy-password` leaf directly under
// an SNMPv3 `user` (with no protocol container) was dropped by both
// compilers: the hierarchical switch in compileSNMPv3 has cases only for
// the five protocol containers, and parseSNMPv3UserKeys switches on the
// protocol keyword only. The user still registered with empty protocols,
// so the agent served it noAuthNoPriv (bare auth password) or authNoPriv
// (bare privacy password beside a valid auth stanza — PDUs in the clear)
// with nothing said at commit.
//
// The compiled config cannot distinguish that user from a deliberately
// protocol-less noAuthNoPriv user, so this gate runs on the AST like the
// #9155 gate beside it. It mirrors the compiler's own expansion
// (hoistAndSplitRun8939 over the user's children, plus the user node's
// own packed Keys run) so flat-set, packed, and braced spellings are all
// seen in the shape the compiler sees them.
//
// NOT fired on: the five nested-container spellings (the password leaf
// sits INSIDE its protocol container, never as a hoisted sibling of the
// user body, and a password token later in a packed run belongs to its
// protocol container); a protocol-less user with NO password leaves
// (deliberate noAuthNoPriv); the #9155 password-leaf exemption (nested
// passwords must keep passing that gate — unchanged).

// validateSNMPv3BarePasswordLeafStrict rejects a bare password leaf
// directly under an SNMPv3 USM user.
func validateSNMPv3BarePasswordLeafStrict(tree *ConfigTree) error {
	if tree == nil {
		return nil
	}
	for _, root := range tree.Children {
		if root.Name() != "snmp" {
			continue
		}
		for _, v3 := range root.Children {
			if v3.Name() != "v3" {
				continue
			}
			for _, usm := range v3.Children {
				if usm.Name() != "usm" {
					continue
				}
				for _, eng := range usm.Children {
					if eng.Name() != "local-engine" {
						continue
					}
					for _, user := range eng.FindChildren("user") {
						if err := checkSNMPv3BarePasswordLeaf14401(user); err != nil {
							return err
						}
					}
				}
			}
		}
	}
	return nil
}

func isSNMPv3PasswordLeaf14401(tok string) bool {
	return tok == "authentication-password" || tok == "privacy-password"
}

func checkSNMPv3BarePasswordLeaf14401(user *Node) error {
	name := "<unnamed>"
	if len(user.Keys) > 1 {
		name = user.Keys[1]
	}
	// (ii) Packed run on the user node's own Keys:
	// Keys = ["user", "<name>", <run...>]. Scan the run exactly as the
	// compiler's parseSNMPv3UserKeys does — a password leaf is bare only
	// when it appears outside a protocol container, i.e. as the first
	// token of the run or immediately after a completed
	// `protocol password value` triple. A password token in the value
	// slot of a protocol (keys[1] of that triple) belongs to its
	// container and must NOT fire.
	if len(user.Keys) > 2 {
		if err := scanPackedRunBarePassword14401(name, user.Keys[2:]); err != nil {
			return err
		}
	}
	// (i) Direct children BEFORE hoisting: hoistAndSplitRun8939 prunes a
	// nested bare password from under a password leaf (it resolves as a
	// user-schema leaf foreign to the password body), which would hide
	// bob's trailing `privacy-password` in the flat-set chain. A direct
	// child named as a password leaf is bare by definition.
	for _, child := range user.Children {
		if len(child.Keys) > 0 && isSNMPv3PasswordLeaf14401(child.Keys[0]) {
			return barePasswordLeafError14401(name, child.Keys[0])
		}
	}
	// A direct protocol child may carry a NESTED bare password (the
	// flat-set chain nests the next statement under the password leaf):
	// `authentication-sha256 > authentication-password A > privacy-password P`.
	// That nested password is not a hoisted sibling; walk each child.
	for _, child := range user.Children {
		if err := checkNestedBarePassword14401(name, child); err != nil {
			return err
		}
	}
	// Hoisted siblings: expand the body exactly as the compiler does.
	// Mirror compileSNMPv3's body selection: when the user node carries
	// no name+run keys, the body may be nested one level down.
	userChildren := user.Children
	if len(user.Keys) < 2 && len(user.Children) > 0 {
		userChildren = user.Children[0].Children
	}
	expanded := hoistAndSplitRun8939(userChildren,
		schemaForPath("snmp", "v3", "usm", "local-engine", "user"))
	for _, prop := range expanded {
		if len(prop.Keys) == 0 {
			continue
		}
		if isSNMPv3PasswordLeaf14401(prop.Keys[0]) {
			return barePasswordLeafError14401(name, prop.Keys[0])
		}
		// A hoisted protocol node may carry a packed tail. A trailing
		// bare password packed AFTER a completed auth triple on the
		// node (`authentication-sha256 authentication-password S
		// privacy-password P` as one node's Keys) is bare; the first
		// token after the protocol keyword belongs to the container.
		// Scan the tail as a leaf's own Keys, where every token counts.
		if len(prop.Keys) > 2 && (snmpV3AuthKeywords[prop.Keys[0]] || snmpV3PrivKeywords[prop.Keys[0]]) {
			for _, tok := range prop.Keys[2:] {
				if isSNMPv3PasswordLeaf14401(tok) {
					return barePasswordLeafError14401(name, tok)
				}
			}
		}
		// A hoisted sibling may itself carry a nested raw chain with a
		// bare password nested under its password leaf (the hoist keeps
		// body-owning leaves' subtrees attached).
		if err := checkNestedBarePassword14401(name, prop); err != nil {
			return err
		}
	}
	return nil
}

// checkNestedBarePassword14401 walks a user-body node's subtree: a
// password leaf found anywhere EXCEPT as the direct password child of
// its matching protocol container is bare. The direct child
// `authentication-sha256 > authentication-password` (and the priv pair)
// is the nested spelling and is skipped without descending — its own
// children, if any, are a nested flat-set chain whose head is bare
// (e.g. a `privacy-password` nested under an `authentication-password`).
func checkNestedBarePassword14401(user string, n *Node) error {
	if n == nil || len(n.Keys) == 0 {
		return nil
	}
	head := n.Keys[0]
	for _, c := range n.Children {
		if len(c.Keys) == 0 {
			continue
		}
		chead := c.Keys[0]
		if isSNMPv3PasswordLeaf14401(chead) {
			// Direct password child of its matching protocol container
			// is nested (legal); anything else here is bare.
			legal := (snmpV3AuthKeywords[head] && chead == "authentication-password") ||
				(snmpV3PrivKeywords[head] && chead == "privacy-password")
			if !legal {
				return barePasswordLeafError14401(user, chead)
			}
			// The password leaf's own children are a nested chain: a
			// password head there is bare (it is not inside any
			// protocol container).
			for _, gc := range c.Children {
				if len(gc.Keys) > 0 && isSNMPv3PasswordLeaf14401(gc.Keys[0]) {
					return barePasswordLeafError14401(user, gc.Keys[0])
				}
				if err := checkNestedBarePassword14401(user, gc); err != nil {
					return err
				}
			}
			continue
		}
		if err := checkNestedBarePassword14401(user, c); err != nil {
			return err
		}
	}
	return nil
}

// scanPackedRunBarePassword14401 scans a packed key run whose first token
// is expected to be a protocol keyword (or a bare password). It consumes
// `protocol [password value]` triples; a password leaf encountered where
// a protocol keyword is expected is bare.
func scanPackedRunBarePassword14401(user string, run []string) error {
	i := 0
	for i < len(run) {
		tok := run[i]
		if isSNMPv3PasswordLeaf14401(tok) {
			return barePasswordLeafError14401(user, tok)
		}
		if snmpV3AuthKeywords[tok] || snmpV3PrivKeywords[tok] {
			i++
			// Nested password for this protocol: skip `password value`.
			if i < len(run) && isSNMPv3PasswordLeaf14401(run[i]) {
				i += 2 // password + its value
			}
			continue
		}
		// Unknown or value token: not a bare password; the #9155 gate
		// owns unknown protocol spellings. Stop attributing structure.
		return nil
	}
	return nil
}

func barePasswordLeafError14401(user, leaf string) error {
	container := "authentication-md5, authentication-sha or authentication-sha256"
	if leaf == "privacy-password" {
		container = "privacy-des or privacy-aes128"
	}
	return fmt.Errorf("snmp v3 usm local-engine user %q carries a bare %s leaf with no protocol container. "+
		"The compiler recognises %s only INSIDE %s, and a bare password leaf is DROPPED SILENTLY: "+
		"the user compiles with no key material for that leaf, so the agent derives no key from it, "+
		"applies no security floor for it, and answers %q at a LOWER security level than configured "+
		"(noAuthNoPriv for a bare authentication-password, authNoPriv with PDUs in the clear for a "+
		"bare privacy-password) — with nothing said at commit. Nest the password inside its protocol "+
		"container (e.g. `%s { %s ...; }`), or remove the bare %s leaf to configure the lower level "+
		"deliberately (#14401)",
		user, leaf, leaf, container, user, protocolForPasswordLeaf14401(leaf), leaf, leaf)
}

func protocolForPasswordLeaf14401(leaf string) string {
	if leaf == "privacy-password" {
		return "privacy-aes128"
	}
	return "authentication-sha256"
}
