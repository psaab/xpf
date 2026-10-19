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
// `authentication-*` / `privacy-*` keyword under an SNMPv3 USM user, and
// (#14411) a recognised one placed where the compiler never reads it.
//
// #14411 extends the #9155 scan three ways, one per placement that compiled
// to a weaker level than written:
//   - the prefix test is case-insensitive while the known-set match stays
//     exact-case, so `Authentication-SHA256` is rejected rather than dropped
//     silently by the parser's exact-case switch;
//   - the scan recurses the WHOLE user subtree (wrapper containers such as
//     `authentication { ... }`), not just direct children;
//   - a RECOGNISED protocol keyword outside a `user` subtree — a braced
//     block under `v3`/`usm`/`local-engine`, a wrapper under the user, or
//     one packed onto an ancestor node's own Keys with no `user` token
//     before it — is rejected as misplaced: compileSNMPv3 never reads it
//     there, so it would otherwise compile to nothing silently. The
//     ancestor scan covers only recognised keywords; an unrecognised
//     `authentication-*` token outside any user stays under the
//     schema/inert-statement handling, mirroring the pre-#14411 gate's
//     user-scoped remit (#14405 owns the flat-chain ancestor shapes).
//     Packed runs that DO reach a `user` token (the flat line, elided
//     chains) are legitimate placements the compiler reads, and are
//     validated by checkSNMPv3UserKeywords9155 instead.
func validateSNMPv3SecurityKeywordStrict(tree *ConfigTree) error {
	if tree == nil {
		return nil
	}
	// Top-level `snmp` roots, plus any `snmp` child under `system`
	// (compileSystem dispatches that spelling to the same compileSNMP).
	// #14767 (residual of #14411): the synthetic brace-elided form
	// (`system snmp v3 …` packed onto the system node's own Keys) is
	// synthesised by compileSystem the same way, so mirror it here too.
	var snmpRoots []*Node
	snmpRoots = append(snmpRoots, tree.FindChildren("snmp")...)
	for _, sys := range tree.FindChildren("system") {
		snmpRoots = append(snmpRoots, sys.FindChildren("snmp")...)
		if len(sys.Keys) > 1 && sys.Keys[1] == "snmp" {
			snmpRoots = append(snmpRoots, &Node{Keys: sys.Keys[1:], Children: sys.Children})
		}
	}
	for _, snmp := range snmpRoots {
		// #14767: compileSNMP iterates EVERY `v3` child, so gate every
		// one — checking only the first (the merged #14411 gate) lets a
		// second `v3` block's bad user through. The same
		// packedBodyChildren calls locate each v3 node, the usm node,
		// the local-engine, and its users across braced, packed, and
		// elided spellings. Any OTHER node in those subtrees is a place
		// the compiler never reads a protocol keyword from.
		if err := checkSNMPv3MisplacedPacked14411(snmp); err != nil {
			return err
		}
		// #14767: fully-packed flat form: compact normalization splits
		// `snmp v3 usm …` into an `snmp` root carrying ONE `v3 …` child
		// whose Keys hold the whole remaining run. When that run reaches
		// `user <name>` (including the synthetic `system snmp …` root),
		// compileSNMPv3's flat branch reads it directly, so gate it here
		// — the per-v3 walk below cannot synthesise a user from a run
		// whose tail is a user, not a v3 body.
		for _, c := range snmp.Children {
			if len(c.Keys) >= 4 && c.Keys[0] == "v3" && c.Keys[1] == "usm" &&
				c.Keys[2] == "local-engine" && c.Keys[3] == "user" {
				if err := checkSNMPv3UserKeywords9155(c); err != nil {
					return err
				}
			}
		}
		if len(snmp.Keys) >= 5 && snmp.Keys[1] == "v3" && snmp.Keys[2] == "usm" &&
			snmp.Keys[3] == "local-engine" && snmp.Keys[4] == "user" {
			if err := checkSNMPv3UserKeywords9155(snmp); err != nil {
				return err
			}
		}
		for _, v3 := range packedBodyChildren(snmp, resolveSchemaChild(setSchema, "snmp")) {
			if v3.Name() != "v3" {
				continue
			}
			if err := validateSNMPv3Node14767(v3); err != nil {
				return err
			}
		}
	}
	return nil
}

// validateSNMPv3Node14767 gates one resolved `v3` node: misplaced packed
// and braced keywords anywhere the compiler never reads them, plus the
// per-user #9155 keyword checks through the compiler's own expansion. Its
// body is validateSNMPv3SecurityKeywordStrict's per-v3 walk, unchanged.
func validateSNMPv3Node14767(v3 *Node) error {
	if err := checkSNMPv3MisplacedPacked14411(v3); err != nil {
		return err
	}
	// The v3 node itself may BE the elided user node (its Keys carry
	// the whole `v3 usm local-engine user <name>` path); then it is
	// the user body and its direct children are legitimate protocols.
	if isSNMPv3UserNode14411(v3) {
		if err := checkSNMPv3BracedKeywords14411(v3, v3); err != nil {
			return err
		}
	} else if err := checkSNMPv3BracedKeywords14411(v3, nil); err != nil {
		return err
	}
	var usm *Node
	for _, c := range packedBodyChildren(v3, schemaForPath("snmp", "v3")) {
		if c.Name() == "usm" {
			usm = c
			break
		}
	}
	if usm == nil {
		return nil
	}
	if err := checkSNMPv3MisplacedPacked14411(usm); err != nil {
		return err
	}
	// #14405: expand the engine level too — a fully packed tail
	// (`v3 usm local-engine { ... }` / `usm local-engine user u1 ...`)
	// can synthesise the user itself from the engine node.
	for _, eng := range packedBodyChildren(usm, schemaForPath("snmp", "v3", "usm")) {
		if eng.Name() != "local-engine" {
			continue
		}
		if err := checkSNMPv3MisplacedPacked14411(eng); err != nil {
			return err
		}
		for _, user := range eng.FindChildren("user") {
			if err := checkSNMPv3UserKeywords9155(user); err != nil {
				return err
			}
			// #15706: two-level `user { <name> { ... } }` — the instances
			// are the user's children; check each as a user body.
			if len(user.Keys) < 2 {
				for _, inst := range user.Children {
					synth := &Node{Keys: append([]string{"user", inst.Name()}, inst.Keys[1:]...), Children: inst.Children}
					if err := checkSNMPv3UserKeywords9155(synth); err != nil {
						return err
					}
				}
			}
		}
		// A fully packed tail can synthesise the user itself
		// (`v3 usm local-engine user u1 ...`): packedBodyChildren
		// on the engine yields the user nodes directly.
		for _, user := range packedBodyChildren(eng, schemaForPath("snmp", "v3", "usm", "local-engine")) {
			if user.Name() != "user" {
				continue
			}
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
	// Elided user (`v3 usm local-engine user u1 { … }`): there is no
	// local-engine child to hang the user on — v3 itself carries the
	// user path in its Keys and the protocol body as its children.
	if isSNMPv3UserNode14411(v3) {
		if err := checkSNMPv3UserKeywords9155(v3); err != nil {
			return err
		}
	}
	return nil
}

// checkSNMPv3MisplacedPacked14411 rejects a recognised protocol keyword
// packed onto n's own Keys past the node's identity. Packed runs need
// run-aware reading: a flat/elided run legitimately carries protocol
// tokens, but only as a user's own run — entered at a `user` token that
// is followed by a NAME (the path token alone, e.g. inside
// `v3 usm local-engine user`, opens nothing) — or packed onto a node
// whose head is itself a protocol keyword (that statement's own run:
// password leaf + value, whose placement the braced-head walk judges).
// The token after a protocol keyword is its password leaf and the token
// after that its value; both are consumed as pair slots and never read
// as keywords, so a password VALUE spelling a protocol keyword is not
// re-parsed. A protocol token anywhere else — before any user, or in a
// run with no user at all (e.g. packed onto the local-engine line) —
// names no placement the compiler reads.
func checkSNMPv3MisplacedPacked14411(n *Node) error {
	tokens := n.Keys
	// A node that IS a protocol statement (`authentication-sha256 …`
	// packed) carries its own run: password leaf + value. Whether that
	// statement sits under a user is the braced-head walk's verdict, not
	// this token scan's.
	if len(tokens) > 0 && (snmpV3AuthKeywords[tokens[0]] || snmpV3PrivKeywords[tokens[0]]) {
		return nil
	}
	for i := 1; i < len(tokens); i++ {
		tok := tokens[i]
		if tok == "user" && i+1 < len(tokens) {
			return nil
		}
		if snmpV3AuthKeywords[tokens[i-1]] || snmpV3PrivKeywords[tokens[i-1]] {
			continue // password leaf of the preceding protocol pair
		}
		if i >= 2 && (snmpV3AuthKeywords[tokens[i-2]] || snmpV3PrivKeywords[tokens[i-2]]) {
			continue // password value slot of the preceding protocol pair
		}
		if err := rejectMisplacedSNMPv3Keyword14411(tok); err != nil {
			return err
		}
	}
	return nil
}

// isSNMPv3UserNode14411 reports whether n's Keys carry a `user <name>`
// pair — i.e. n IS the user node in an elided/packed spelling
// (`v3 usm local-engine user u1`, `local-engine user u1`, …), so its
// direct children are that user's protocol statements.
func isSNMPv3UserNode14411(n *Node) bool {
	for i := 0; i+1 < len(n.Keys); i++ {
		if n.Keys[i] == "user" {
			return true
		}
	}
	return false
}

// checkSNMPv3BracedKeywords14411 rejects a recognised protocol keyword used
// as a braced statement head (Keys[0] of a descendant) anywhere in n's
// subtree that the compiler's user reader never treats as a protocol:
// every descendant when outside a user, and — inside a user — everything
// below the user's direct children. The R02 SetPath chain is the one
// exception inside a user: it nests the second protocol under the first
// protocol's password node (`authentication-password A` carrying
// `privacy-aes128 …`), and compileSNMPv3's hoistAndSplitRun8939 lifts it
// back to a direct user child before reading — so a protocol head whose
// chain from the user is exactly [protocol, its password leaf, protocol]
// is legitimate. Any other nesting (a wrapper container, a deeper chain)
// is never lifted and never read. userBody is the enclosing user node
// when inside one, else nil; a `user` child starts a user body.
func checkSNMPv3BracedKeywords14411(n *Node, userBody *Node) error {
	return checkSNMPv3BracedKeywordsDepth14411(n, userBody, nil)
}

// chain holds the statement heads from the enclosing user node down to n
// (nil outside a user, or when n IS the user).
func isTwoLevelUserContainer15706(n *Node) bool {
	return n != nil && n.Name() == "user" && len(n.Keys) < 2
}

func checkSNMPv3BracedKeywordsDepth14411(n *Node, userBody *Node, chain []string) error {
	// #15706: children of a two-level `user { <name> { ... } }` container
	// (outside any user) are instances, not statements: each starts a
	// user body. Intercept before the generic misplaced check, which
	// would reject their protocol children as outside any user.
	if (userBody == nil || userBody == n) && isTwoLevelUserContainer15706(n) {
		for _, inst := range n.Children {
			synth := &Node{Keys: append([]string{"user", inst.Name()}, inst.Keys[1:]...), Children: inst.Children}
			if err := checkSNMPv3BracedKeywords14411(synth, synth); err != nil {
				return err
			}
		}
		return nil
	}
	for _, child := range n.Children {
		var childChain []string
		if userBody != nil {
			childChain = append(append([]string{}, chain...), child.Name())
		}
		if userBody == nil || n != userBody {
			if err := rejectMisplacedSNMPv3Keyword14411(child.Name()); err != nil {
				if !(userBody != nil && isSNMPv3HoistedChain14411(childChain)) {
					return err
				}
			}
		}
		next := userBody
		nextChain := childChain
		if child.Name() == "user" {
			next = child
			nextChain = nil
		}
		if err := checkSNMPv3BracedKeywordsDepth14411(child, next, nextChain); err != nil {
			return err
		}
	}
	return nil
}

// isSNMPv3HoistedChain14411 reports whether chain (heads from the user
// node to the candidate node, inclusive) is exactly
// [protocol, that protocol's password leaf, protocol] — the shape
// hoistAndSplitRun8939 lifts to a direct user child.
func isSNMPv3HoistedChain14411(chain []string) bool {
	if len(chain) != 3 {
		return false
	}
	if snmpV3AuthKeywords[chain[0]] {
		return chain[1] == "authentication-password" &&
			(snmpV3AuthKeywords[chain[2]] || snmpV3PrivKeywords[chain[2]])
	}
	if snmpV3PrivKeywords[chain[0]] {
		return chain[1] == "privacy-password" &&
			(snmpV3AuthKeywords[chain[2]] || snmpV3PrivKeywords[chain[2]])
	}
	return false
}

func rejectMisplacedSNMPv3Keyword14411(tok string) error {
	if snmpV3AuthKeywords[tok] || snmpV3PrivKeywords[tok] {
		return fmt.Errorf("snmp v3 usm local-engine: %s protocol %q is placed outside "+
			"any `user` node. compileSNMPv3 reads protocol keywords only under "+
			"`user <name>`, so this keyword is DROPPED SILENTLY: the user it was "+
			"meant for compiles with no such protocol and the agent serves it "+
			"below the configured security level. Move %q under the intended "+
			"`user <name>` node (#14411)", snmpv3KeywordKind14411(tok), tok, tok)
	}
	return nil
}

func snmpv3KeywordKind14411(tok string) string {
	if snmpV3PrivKeywords[tok] {
		return "privacy"
	}
	return "authentication"
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
//
// #14411: the descendant scan first runs the token-level unknown-spelling
// check over the whole subtree (so a case-variant or unknown keyword inside
// a wrapper is named), then the statement-head misplaced check (so a
// RECOGNISED keyword nested below the user's direct protocol children —
// inside a wrapper, or inside a protocol node's password body — is
// rejected as misplaced; the parser reads only direct children, so it
// would otherwise compile to nothing). The R02 hoisted chain is the sole
// tolerated nesting (see checkSNMPv3BracedKeywordsDepth14411).
func checkSNMPv3UserKeywords9155(user *Node) error {
	// #15706: a nameless `user { <name> { ... } }` container is not itself
	// a user; validate each instance and return.
	if isTwoLevelUserContainer15706(user) {
		for _, inst := range user.Children {
			synth := &Node{Keys: append([]string{"user", inst.Name()}, inst.Keys[1:]...), Children: inst.Children}
			if err := checkSNMPv3UserKeywords9155(synth); err != nil {
				return err
			}
		}
		return nil
	}
	name := "<unnamed>"
	if len(user.Keys) > 1 {
		// Elided user node: the name is the token after `user`, not Keys[1].
		name = user.Keys[1]
		for i, tok := range user.Keys {
			if tok == "user" && i+1 < len(user.Keys) {
				name = user.Keys[i+1]
				break
			}
		}
	}
	// Packed tail on the user node itself: Keys = ["user", "<name>", "authentication-sha512", ...]
	// For an elided node the tail starts after the `user <name>` pair.
	tailStart := min9155(2, len(user.Keys))
	for i, tok := range user.Keys {
		if tok == "user" && i+1 < len(user.Keys) {
			tailStart = i + 2
			break
		}
	}
	for _, tok := range user.Keys[tailStart:] {
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
	for _, prop := range user.Children {
		if err := checkSNMPv3DescendantKeywords9155(prop, name); err != nil {
			return err
		}
		// A recognised keyword nested BELOW this direct child (wrapper,
		// password body) is misplaced, except the R02 hoisted chain.
		if err := checkSNMPv3BracedKeywordsDepth14411(prop, user, []string{prop.Name()}); err != nil {
			return err
		}
	}
	return nil
}

func checkSNMPv3DescendantKeywords9155(n *Node, user string) error {
	for _, tok := range n.Keys {
		if err := rejectUnknownSNMPv3Keyword9155(user, tok); err != nil {
			return err
		}
	}
	for _, child := range n.Children {
		if err := checkSNMPv3DescendantKeywords9155(child, user); err != nil {
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
	// #14411: the prefix test is case-insensitive but the known-set match
	// below stays exact-case, so a case-variant spelling such as
	// `Authentication-SHA256` — dropped silently by the parser's exact-case
	// switch — is rejected here instead of compiling to a bare user.
	lower := strings.ToLower(tok)
	isAuth := strings.HasPrefix(lower, "authentication-")
	isPriv := strings.HasPrefix(lower, "privacy-")
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
