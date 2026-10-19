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

// #15136 (A89-04): the residual auth spellings #8443/#14402 did not cover.
//
//   - OSPFv3 has no native authentication field (RFC 5340 removed it);
//     Junos protects OSPFv3 interfaces and virtual links ONLY with a manual
//     IPsec SA (`ipsec-sa <name>`), and shares the OSPFv2
//     `authentication { md5|simple-password|keychain }` block grammar at
//     the interface/virtual-link hierarchy. xpf implements neither: the
//     OSPFv3 compiler switch has no auth case, `OSPFv3Interface` has no
//     auth field, and FRR renders no `ipv6 ospf6 authentication` line.
//   - OSPFv2 virtual links accept the same Junos auth leaves
//     (`authentication { ... }`, `authentication-key`, `authentication-type`,
//     `ipsec-sa`, `keychain`) beside `transit-area`, but the compiler reads
//     only `transit-area` and `OSPFVirtualLink` has no auth field, so FRR
//     renders a bare `area A virtual-link R` — unauthenticated.
//
// Every spelling below committed clean and left the adjacency / virtual
// link UNAUTHENTICATED while the configuration read as protected — the
// exact #8443 fail-open. Modelled ONLY so they are REFUSED, in the
// unmodeledOSPFAuthTypeLeaf shape. If OSPFv3 IPsec or virtual-link auth
// is ever implemented, these stubs must be replaced by the real grammar
// and the spelling-gate ceilings adjusted back down.

// unmodeledOSPFIPsecSALeaf refuses `ipsec-sa <name>`, the Junos manual-SA
// selector for OSPFv2/OSPFv3 interfaces and OSPFv2/OSPFv3 virtual links.
// The SA name is not a secret, but the refusal is value-independent.
func unmodeledOSPFIPsecSALeaf() *schemaNode {
	return &schemaNode{
		desc: "ipsec-sa (Junos manual IPsec SA for OSPF/OSPFv3 — not " +
			"implemented by xpf; rejected at commit)",
		args:        1,
		placeholder: "<sa-name>",
		valueType:   ValueEnumOf,
		valueDesc: "not implemented by xpf; OSPF/OSPFv3 IPsec authentication " +
			"is not rendered to FRR",
		validator: rejectOSPFIPsecSA,
		children:  nil,
	}
}

func rejectOSPFIPsecSA(_ string, _ *Config) error {
	return fmt.Errorf(
		"ipsec-sa: OSPF/OSPFv3 IPsec authentication is not implemented by " +
			"xpf — no manual SA is rendered to FRR, so the adjacency would " +
			"form UNAUTHENTICATED while the configuration reads as though " +
			"it is protected. Remove the ipsec-sa statement; OSPFv2 " +
			"interface authentication (`authentication { md5 ... }` / " +
			"`authentication { simple-password ... }`) is the only OSPF " +
			"authentication xpf renders (#15136)")
}

// unmodeledOSPFKeychainLeaf refuses `keychain <name>`, the Junos OSPF
// authentication-block alternative (`authentication { keychain <name>; }`)
// and the virtual-link sibling (`keychain <name>;`).
func unmodeledOSPFKeychainLeaf() *schemaNode {
	return &schemaNode{
		desc: "keychain (Junos OSPF keychain authentication — not " +
			"implemented by xpf; rejected at commit)",
		args:        1,
		placeholder: "<keychain-name>",
		valueType:   ValueEnumOf,
		valueDesc: "not implemented by xpf; OSPF keychain authentication " +
			"is not rendered to FRR",
		validator: rejectOSPFKeychain,
		children:  nil,
	}
}

func rejectOSPFKeychain(_ string, _ *Config) error {
	return fmt.Errorf(
		"keychain: OSPF keychain authentication is not implemented by xpf " +
			"— no keychain is rendered to FRR, so the adjacency would form " +
			"UNAUTHENTICATED while the configuration reads as though it is " +
			"protected. Remove the keychain statement; OSPFv2 interface " +
			"authentication (`authentication { md5 ... }` / " +
			"`authentication { simple-password ... }`) is the only OSPF " +
			"authentication xpf renders (#15136)")
}

// unmodeledOSPFv3AuthTypeLeaf is the OSPFv3 spelling of
// unmodeledOSPFAuthTypeLeaf: same refusal, OSPFv3 wording.
func unmodeledOSPFv3AuthTypeLeaf() *schemaNode {
	return &schemaNode{
		desc: "authentication-type (IS-IS/RIP spelling — OSPFv3 uses " +
			"`ipsec-sa`; rejected at commit)",
		args:        1,
		placeholder: "<type>",
		valueType:   ValueEnumOf,
		valueDesc: "not an OSPFv3 leaf; OSPFv3 authentication is IPsec " +
			"(`ipsec-sa`), which xpf does not implement",
		validator: rejectOSPFv3AuthType,
		children:  nil,
	}
}

func rejectOSPFv3AuthType(_ string, _ *Config) error {
	return fmt.Errorf(
		"protocols ospf3 ... interface ... authentication-type: OSPFv3 has " +
			"no `authentication-type` leaf — that spelling belongs to IS-IS " +
			"and RIP. OSPFv3 authentication is IPsec (`ipsec-sa <name>`), " +
			"which xpf does not implement. This is refused rather than " +
			"ignored because ignoring it leaves the adjacency " +
			"UNAUTHENTICATED while the configuration reads as though it " +
			"is protected (#15136)")
}

// unmodeledOSPFv3AuthKeyLeaf is the OSPFv3 spelling of
// unmodeledOSPFAuthKeyLeaf. `authentication-key` is a secret leaf, so the
// typed-leaf diagnostic redacts its value.
func unmodeledOSPFv3AuthKeyLeaf() *schemaNode {
	return &schemaNode{
		desc: "authentication-key (RIP/IS-IS/BGP spelling — OSPFv3 uses " +
			"`ipsec-sa`; rejected at commit)",
		args:        1,
		placeholder: "<key>",
		valueType:   ValueEnumOf,
		valueDesc: "not an OSPFv3 leaf; OSPFv3 authentication is IPsec " +
			"(`ipsec-sa`), which xpf does not implement",
		validator: rejectOSPFv3AuthKey,
		children:  nil,
	}
}

func rejectOSPFv3AuthKey(_ string, _ *Config) error {
	return fmt.Errorf(
		"protocols ospf3 ... interface ... authentication-key: OSPFv3 has " +
			"no `authentication-key` leaf — that spelling belongs to RIP, " +
			"IS-IS, and BGP. OSPFv3 authentication is IPsec " +
			"(`ipsec-sa <name>`), which xpf does not implement. This is " +
			"refused rather than ignored because ignoring it leaves the " +
			"adjacency UNAUTHENTICATED while the configuration reads as " +
			"though it is protected (#15136)")
}

// unmodeledVLAuthTypeLeaf refuses `authentication-type` under an OSPFv2
// virtual link. The refusal message carries `authentication-type` so the
// diagnostic names the leaf wherever it appears.
func unmodeledVLAuthTypeLeaf() *schemaNode {
	return &schemaNode{
		desc: "authentication-type (IS-IS/RIP spelling — OSPF virtual " +
			"links use a nested `authentication { }` block; rejected at commit)",
		args:        1,
		placeholder: "<type>",
		valueType:   ValueEnumOf,
		valueDesc: "not an OSPF virtual-link leaf; virtual-link " +
			"authentication is not implemented by xpf",
		validator: rejectVLAuthType,
		children:  nil,
	}
}

func rejectVLAuthType(_ string, _ *Config) error {
	return fmt.Errorf(
		"authentication-type: OSPF virtual-link authentication is not " +
			"implemented by xpf — that spelling belongs to IS-IS and RIP, " +
			"and the virtual-link nested `authentication { md5 ... }` / " +
			"`authentication { simple-password ... }` block is not rendered " +
			"to FRR either, so the virtual link would form UNAUTHENTICATED " +
			"while the configuration reads as though it is protected. " +
			"Remove the authentication statement from the virtual link (#15136)")
}

// unmodeledVLAuthKeyLeaf refuses `authentication-key` under an OSPFv2
// virtual link (secret leaf; value redacted by the typed-leaf path).
func unmodeledVLAuthKeyLeaf() *schemaNode {
	return &schemaNode{
		desc: "authentication-key (RIP/IS-IS/BGP spelling — OSPF virtual " +
			"links use a nested `authentication { }` block; rejected at commit)",
		args:        1,
		placeholder: "<key>",
		valueType:   ValueEnumOf,
		valueDesc: "not an OSPF virtual-link leaf; virtual-link " +
			"authentication is not implemented by xpf",
		validator: rejectVLAuthKey,
		children:  nil,
	}
}

func rejectVLAuthKey(_ string, _ *Config) error {
	return fmt.Errorf(
		"authentication-key: OSPF virtual-link authentication is not " +
			"implemented by xpf — that spelling belongs to RIP, IS-IS, and " +
			"BGP, and the virtual-link nested `authentication { md5 ... }` " +
			"block is not rendered to FRR either, so the virtual link would " +
			"form UNAUTHENTICATED while the configuration reads as though " +
			"it is protected. Remove the authentication statement from the " +
			"virtual link (#15136)")
}

// unmodeledOSPFAuthenticationContainer refuses the whole Junos
// `authentication { md5|simple-password|keychain ... }` container where
// xpf renders no virtual-link / OSPFv3 authentication at all. It is a
// closed-world container whose every child is itself a refusal stub, so
// both the braced spelling (children walked under closedWorld) and the
// packed spelling (`authentication md5 1 key ...`, whose tail tokens the
// nodeValidator rejects) refuse, and a misspelled child is caught by the
// closed world instead of committing clean.
func unmodeledOSPFAuthenticationContainer() *schemaNode {
	return &schemaNode{
		desc: "Authentication (not implemented by xpf at this hierarchy — " +
			"rejected at commit)",
		closedWorld: true,
		// nodeValidator errors are deliberately NOT typed-leaf classified
		// (schema_walk.go), so on the tolerant Load/SyncApply path this
		// refusal is only logged, not persisted in cfg.Warnings. That is
		// the same posture as every other nodeValidator gate; the strict
		// commit path — the operator boundary this issue gates — refuses
		// regardless. The typed sibling leaves (ipsec-sa,
		// authentication-key, ...) DO persist named tolerant warnings.
		nodeValidator: rejectOSPFAuthenticationContainer,
		children: map[string]*schemaNode{
			"md5":             unmodeledOSPFAuthContainerChild("md5"),
			"simple-password": unmodeledOSPFAuthContainerChild("simple-password"),
			"keychain":        unmodeledOSPFKeychainLeaf(),
		},
	}
}

// unmodeledOSPFAuthContainerChild refuses one algorithm child of the
// refused `authentication` container. Modelled as a typed leaf in the
// unmodeledOSPFAuthTypeLeaf shape (empty ValueEnumOf set + unconditional
// validator): the braced spelling's key-id token is its value, and the
// `key` child below is a declared modifier so the nested
// `md5 1 { key "..."; }` shape reaches the validator instead of an
// unknown-modifier error.
func unmodeledOSPFAuthContainerChild(name string) *schemaNode {
	return &schemaNode{
		desc: "Authentication (not implemented by xpf at this hierarchy — " +
			"rejected at commit)",
		args:        1,
		placeholder: "<key-id>",
		valueType:   ValueEnumOf,
		valueDesc: "not implemented by xpf at this hierarchy; " +
			"authentication here is not rendered to FRR",
		validator: rejectOSPFAuthContainerChild,
		children: map[string]*schemaNode{
			"key": {desc: "Authentication key", args: 1, placeholder: "<key>", children: nil},
		},
	}
}

func rejectOSPFAuthContainerChild(_ string, _ *Config) error {
	return fmt.Errorf(
		"authentication: authentication at this hierarchy is not " +
			"implemented by xpf — nothing is rendered to FRR, so the " +
			"adjacency / virtual link would form UNAUTHENTICATED while " +
			"the configuration reads as though it is protected. Remove " +
			"the authentication statement; OSPFv2 interface authentication " +
			"(`authentication { md5 ... }` / `authentication { " +
			"simple-password ... }`) is the only OSPF authentication xpf " +
			"renders (#15136)")
}

func rejectOSPFAuthenticationContainer(_ *Node, _ *schemaNode) error {
	return fmt.Errorf(
		"authentication: authentication at this hierarchy is not " +
			"implemented by xpf — nothing is rendered to FRR, so the " +
			"adjacency / virtual link would form UNAUTHENTICATED while " +
			"the configuration reads as though it is protected. Remove " +
			"the authentication statement; OSPFv2 interface authentication " +
			"(`authentication { md5 ... }` / `authentication { " +
			"simple-password ... }`) is the only OSPF authentication xpf " +
			"renders (#15136)")
}
