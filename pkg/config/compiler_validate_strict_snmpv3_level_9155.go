package config

import (
	"fmt"
	"sort"
	"strings"
)

// compiler_validate_strict_snmpv3_level_9155.go — #9155.
//
// Two ordinary operator commits produced an SNMPv3 USM user whose configured
// security level was not the level the agent served, and #7530's gate could not
// see either one. Both are rejected here.
//
// HOLE A — AN UNRECOGNISED PROTOCOL SPELLING SILENTLY DROPPED THE WHOLE STANZA.
// `compileSNMPv3Users` switches on the exact keyword and has no default arm, so
// `authentication-sha512` — a real protocol this agent does not implement, and
// the obvious thing to type — left `AuthProtocol` EMPTY. #7530's gate fires on
// `AuthProtocol != "" && AuthPassword == ""`, so it cannot fire: there is no
// protocol to be missing material for. The operator asked for authentication
// and committed a bare noAuthNoPriv user, with nothing said at commit and
// nothing visible in `show snmp`.
//
// This gate runs on the TREE rather than the compiled *Config for the same
// reason the zone-interfaces gate does: the compiled form cannot distinguish
// "no protocol configured" from "a protocol that compiled to nothing". The
// keyword IS the evidence, and it exists only in the AST.
//
// HOLE B — PRIVACY WITHOUT AUTHENTICATION. USM has no privacy-only level (RFC
// 3414: noAuthNoPriv, authNoPriv, authPriv — there is no noAuthPriv), and key
// derivation for BOTH keys is gated on the AUTH hash function, so a user with
// `privacy-aes128` and no auth protocol derives NO privacy key either. The
// #7530 privacy arm requires `PrivPassword == ""` and a password IS present, so
// it does not fire; the user is then served with an unencrypted scopedPDU while
// the configuration reads authPriv.
//
// REJECT-ONLY, in both arms. Nothing that compiled before compiles differently;
// a bug here is a loud false rejection caught by the positive controls, never a
// silently weaker agent. That is the same property #7530 claimed and the reason
// this can be a hard reject on the commit path.
//
// The runtime floor is fixed too, in pkg/snmp/v3.go, and the two are not
// redundant: a commit gate cannot help a config that is already persisted or
// arrives by peer sync, which is exactly the population that reaches
// Store.Load / Store.SyncApply. The floor is what makes the tolerant path safe.

// snmpV3AuthKeywords and snmpV3PrivKeywords are the spellings compileSNMPv3Users
// actually recognises. Kept beside the gate deliberately: if a protocol is added
// to the compiler and not here, the gate rejects a config the compiler
// understands — a loud, immediate failure — which is the safe direction for a
// list that can drift.
var snmpV3AuthKeywords = map[string]bool{
	"authentication-md5":    true,
	"authentication-sha":    true,
	"authentication-sha256": true,
}

var snmpV3PrivKeywords = map[string]bool{
	"privacy-des":    true,
	"privacy-aes128": true,
}

// #14405: the walk below must read the same shapes the compiler reads.
// compileSNMPv3 expands a packed ancestor (`v3 usm { ... }`,
// `usm local-engine { ... }`) with packedBodyChildren at each level and
// hoists a descendant flat-chain statement under a user with
// hoistAndSplitRun8939. A gate that walks only direct children and only
// a user's direct children's Keys therefore skips exactly the users the
// compiler creates from those spellings, and the unknown protocol
// keyword inside them is dropped silently — the #9155 harm again.
// Expanding with the compiler's own helpers keeps the two in step: a
// shape the compiler cannot expand is not expanded here either.
//
// validateSNMPv3SecurityKeywordStrict rejects an unrecognised
// `authentication-*` / `privacy-*` keyword under an SNMPv3 USM user.
func validateSNMPv3SecurityKeywordStrict(tree *ConfigTree) error {
	if tree == nil {
		return nil
	}
	for _, root := range tree.Children {
		if root.Name() != "snmp" {
			continue
		}
		for _, v3 := range packedBodyChildren(root, schemaForPath("snmp")) {
			if v3.Name() != "v3" {
				continue
			}
			for _, usm := range packedBodyChildren(v3, schemaForPath("snmp", "v3")) {
				if usm.Name() != "usm" {
					continue
				}
				for _, eng := range packedBodyChildren(usm, schemaForPath("snmp", "v3", "usm")) {
					if eng.Name() != "local-engine" {
						continue
					}
					for _, user := range eng.FindChildren("user") {
						if err := checkSNMPv3UserKeywords9155(user); err != nil {
							return err
						}
					}
					// A fully packed tail can synthesise the user
					// itself (`v3 usm local-engine user u1 ...`):
					// packedBodyChildren on the engine yields the
					// user nodes directly when the engine was packed.
					for _, user := range packedBodyChildren(eng, schemaForPath("snmp", "v3", "usm", "local-engine")) {
						if user.Name() != "user" {
							continue
						}
						// FindChildren above already covered a
						// braced engine's users; packedBodyChildren
						// returns Children unchanged when there is
						// no tail, so skip nodes already checked.
						seen := false
						for _, u := range eng.FindChildren("user") {
							if u == user {
								seen = true
								break
							}
						}
						if seen {
							continue
						}
						if err := checkSNMPv3UserKeywords9155(user); err != nil {
							return err
						}
					}
				}
			}
		}
	}
	return nil
}

// checkSNMPv3UserKeywords9155 inspects one `user <name>` node.
//
// Both the packed flat spelling and the braced spelling have to be checked, and
// they put the keyword in different places: `set ... user u authentication-sha512
// authentication-password X` packs the run onto the user node's own Keys, while
// the braced form makes it a child. Checking only one is how a gate ends up
// covering the spelling its author happened to test with.
//
// #14405: a flat `set` chain nests each later statement under the previous
// one, so a privacy (or second auth) keyword can be a GRANDCHILD of the
// user. Hoist the user's children with the same helper the compiler uses
// so every hoisted statement's Keys are examined, then also scan any
// remaining descendant Keys: an unknown protocol keyword
// (`authentication-foo` / `privacy-bar`) is not a declared child of the
// user schema, so the hoist leaves it nested where it was authored —
// exactly where a direct-children-only scan cannot see it.
func checkSNMPv3UserKeywords9155(user *Node) error {
	name := "<unnamed>"
	if len(user.Keys) > 1 {
		name = user.Keys[1]
	}
	// Packed tail on the user node itself: Keys = ["user", "<name>", "authentication-sha512", ...]
	for _, tok := range user.Keys[min9155(2, len(user.Keys)):] {
		if err := rejectUnknownSNMPv3Keyword9155(name, tok); err != nil {
			return err
		}
	}
	hoisted := hoistAndSplitRun8939(user.Children,
		schemaForPath("snmp", "v3", "usm", "local-engine", "user"))
	for _, prop := range hoisted {
		for _, tok := range prop.Keys {
			if err := rejectUnknownSNMPv3Keyword9155(name, tok); err != nil {
				return err
			}
		}
	}
	// Descendant scan for keywords the hoist cannot lift (unknown heads
	// do not resolve as user-schema leaves). Password leaves and known
	// protocols are exempted inside rejectUnknownSNMPv3Keyword9155, and
	// values are never `authentication-*`/`privacy-*` heads in a valid
	// spelling, so scanning every descendant token is safe.
	var scan func(n *Node) error
	scan = func(n *Node) error {
		if n == nil {
			return nil
		}
		for _, tok := range n.Keys {
			if err := rejectUnknownSNMPv3Keyword9155(name, tok); err != nil {
				return err
			}
		}
		for _, c := range n.Children {
			if err := scan(c); err != nil {
				return err
			}
		}
		return nil
	}
	for _, prop := range user.Children {
		if err := scan(prop); err != nil {
			return err
		}
	}
	return nil
}

func min9155(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func rejectUnknownSNMPv3Keyword9155(user, tok string) error {
	isAuth := strings.HasPrefix(tok, "authentication-")
	isPriv := strings.HasPrefix(tok, "privacy-")
	if !isAuth && !isPriv {
		return nil
	}
	// The password leaves share the prefix and are not protocol names.
	if tok == "authentication-password" || tok == "privacy-password" {
		return nil
	}
	if isAuth && snmpV3AuthKeywords[tok] {
		return nil
	}
	if isPriv && snmpV3PrivKeywords[tok] {
		return nil
	}
	known := snmpV3AuthKeywords
	kind := "authentication"
	if isPriv {
		known = snmpV3PrivKeywords
		kind = "privacy"
	}
	names := make([]string, 0, len(known))
	for k := range known {
		names = append(names, k)
	}
	sort.Strings(names)
	return fmt.Errorf("snmp v3 usm local-engine user %q names unknown %s protocol %q. "+
		"The compiler recognises only %s, and an unrecognised spelling is DROPPED "+
		"SILENTLY: the user compiles with no %s protocol at all, so the agent derives "+
		"no key, applies no security floor, and answers a noAuthNoPriv request naming "+
		"%q unauthenticated and in plaintext — the opposite of what was configured, "+
		"with nothing said at commit and nothing visible in `show snmp` (#9155)",
		user, kind, tok, strings.Join(names, ", "), kind, user)
}
