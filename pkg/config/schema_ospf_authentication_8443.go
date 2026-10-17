package config

import "fmt"

// #8443: an unmatched keyword under an OSPF interface's `authentication { }`
// block committed clean and left the adjacency UNAUTHENTICATED.
//
// #8473 closed the IS-IS and RIP half of #8443, where `authentication-type` is
// a real free-form leaf and an unrecognised value downgraded md5 to plaintext.
// OSPF's half is a different grammar and was left open deliberately. OSPF has
// no `authentication-type` leaf at all — it uses a nested block whose CHILD
// KEYWORD selects the algorithm:
//
//	interface ge-0/0/0.0 { authentication { md5 <key-id> { key "s"; } } }
//	interface ge-0/0/0.0 { authentication { simple-password "s"; } }
//
// `compiler_protocols.go` assigns `OSPFInterface.AuthType` ONLY from a matched
// `md5` / `simple-password`, so there is no free-form value to type-check. A
// keyword that matches neither leaves `AuthType == ""`, and the renderer emits
// nothing — the adjacency forms unauthenticated while `show configuration`
// echoes the authentication block back to the operator verbatim. Measured
// before this change, every row committing clean:
//
//	authentication { md5 1 { key "SEKRIT"; } }      AuthType="md5"  correct
//	authentication { md5-typo 1 { key "SEKRIT"; } } AuthType=""     UNAUTHENTICATED
//	authentication { md5 1 { keyy "SEKRIT"; } }     AuthType="md5"  key dropped, renders nothing
//	authentication-type md5;                        AuthType=""     UNAUTHENTICATED
//
// The failure direction is what makes this a defect rather than an
// inconvenience: the operator believes the adjacency is protected, and every
// surface they can check agrees with them.
//
// Two mechanisms close it, because the four rows above are two different shapes:
//
//   - The first three are unmodeled keywords INSIDE a modeled subtree, so
//     `closedWorld: true` on the `authentication` node is exactly the right
//     instrument. It is opt-in per subtree and inherits down (schema_walk.go),
//     which is what also catches the misspelled `key` child of `md5`.
//   - The fourth is a leaf that does not exist under OSPF at all, so closing
//     `authentication`'s world cannot see it. It is modeled here SOLELY so it
//     is refused, in the shape #7971 established for the login-class
//     `*-regexps` family. Closing the whole OSPF `interface` world would also
//     catch it, and was measured to leave the pkg/config suite green — but it
//     converts EVERY unmodeled protocol leaf from inert to refused, which is
//     the #8296 class and a much larger decision than this issue's scope.
func unmodeledOSPFAuthTypeLeaf() *schemaNode {
	return &schemaNode{
		desc: "authentication-type (IS-IS/RIP spelling — OSPF uses a nested " +
			"`authentication { }` block; rejected at commit)",
		args:        1,
		placeholder: "<type>",
		// ValueEnumOf with no examples: the acceptable set is genuinely empty.
		// ValueAny would leave the validator uninvoked (schema.go) and
		// reproduce the silent-accept this file exists to fix — the same trap
		// documented on unimplementedRegexpsLeaf.
		valueType: ValueEnumOf,
		valueDesc: "not an OSPF leaf; use `authentication { md5 ... }` or " +
			"`authentication { simple-password ... }`",
		validator: rejectOSPFAuthType,
		children:  nil,
	}
}

// rejectOSPFAuthType refuses the value slot unconditionally and names the
// grammar that does work. An operator reaching this has almost certainly
// carried the IS-IS or RIP spelling across, so the message says which protocols
// that spelling belongs to rather than only that this one is wrong.
func rejectOSPFAuthType(_ string, _ *Config) error {
	return fmt.Errorf(
		"protocols ospf ... interface ... authentication-type: OSPF has no " +
			"`authentication-type` leaf — that spelling belongs to IS-IS and RIP. " +
			"Under OSPF the algorithm is the CHILD KEYWORD of a nested block: " +
			"`authentication { md5 <key-id> { key \"<secret>\"; } }` or " +
			"`authentication { simple-password \"<secret>\"; }`. This is refused " +
			"rather than ignored because ignoring it leaves the adjacency " +
			"UNAUTHENTICATED while the configuration reads as though it is " +
			"protected (#8443)")
}

// #14402: the KEY leaf carried over from RIP/IS-IS/BGP. #8443 refused the
// sibling `authentication-type` leaf (above) but not `authentication-key`.
// OSPF has no direct `authentication-key` child under `interface` — the
// compiler switch in compiler_protocols.go has no case for it, so the key
// was dropped, AuthType/AuthKey stayed empty, and the renderer emitted
// `ip ospf area` with no auth lines. Modelled ONLY so it is REFUSED, in
// exactly the unmodeledOSPFAuthTypeLeaf shape. Because `authentication-key`
// is a secret leaf (secret.go), typedLeafInvalidErrorf redacts its value
// from the diagnostic; the validator message itself never contains it.
func unmodeledOSPFAuthKeyLeaf() *schemaNode {
	return &schemaNode{
		desc: "authentication-key (RIP/IS-IS/BGP spelling — OSPF uses a nested " +
			"`authentication { }` block; rejected at commit)",
		args:        1,
		placeholder: "<key>",
		valueType:   ValueEnumOf,
		valueDesc: "not an OSPF leaf; use `authentication { md5 ... }` or " +
			"`authentication { simple-password ... }`",
		validator: rejectOSPFAuthKey,
		children:  nil,
	}
}

func rejectOSPFAuthKey(_ string, _ *Config) error {
	return fmt.Errorf(
		"protocols ospf ... interface ... authentication-key: OSPF has no " +
			"`authentication-key` leaf — that spelling belongs to RIP, IS-IS, and BGP. " +
			"Under OSPF the key lives inside the nested block: " +
			"`authentication { md5 <key-id> { key \"<secret>\"; } }` or " +
			"`authentication { simple-password \"<secret>\"; }`. This is refused " +
			"rather than ignored because ignoring it leaves the adjacency " +
			"UNAUTHENTICATED while the configuration reads as though it is " +
			"protected (#14402)")
}
