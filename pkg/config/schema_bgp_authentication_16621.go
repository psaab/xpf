package config

import (
	"fmt"
	"strings"
)

// #16621: BGP authentication spellings xpf cannot render committed with
// only the generic #10707 open-world advisory, and the peer was rendered
// without TCP-MD5.
//
// Junos accepts `authentication-key`, `authentication-key-chain` and
// `authentication-algorithm` at [edit protocols bgp], group and neighbor
// level. xpf implements only the direct `authentication-key` at group
// and neighbor level (`BGPNeighbor.AuthPassword` -> FRR
// `neighbor X password`). Before this change:
//
//   - top-level `protocols bgp authentication-key` had no schema leaf
//     and no compiler reader, so one key for every peer — the canonical
//     Junos spelling — was dropped;
//   - `authentication-key-chain` / `authentication-algorithm` at bgp,
//     group and neighbor level had no leaf and no reader, so a keychain
//     or algorithm statement was dropped while `show configuration`
//     still displayed it as protected.
//
// The fix direction in #16621 is either/or: implement top-level
// inheritance, or refuse. This file does BOTH halves that are honest:
//
//   - Top-level `authentication-key` is IMPLEMENTED (schema leaf in
//     schema_routing.go + compiler inheritance in compiler_protocols.go):
//     most-specific wins — neighbor key beats group key beats the
//     protocol-level key — exactly as Junos inherits it.
//   - `authentication-key-chain` and `authentication-algorithm` are
//     REFUSED at bgp, group and neighbor level, in the
//     unmodeledOSPFKeychainLeaf shape (#8443/#15136): modelled SOLELY so
//     they are refused. xpf has no keychain store and FRR's
//     `neighbor X password` takes a literal key, so rendering a named
//     chain would be a lie; and an `authentication-algorithm` other
//     than the TCP-MD5 default the rendered `password` implies cannot
//     be honoured. If keychains are ever implemented, these stubs must
//     be replaced by the real grammar.
//
// The tolerant path: SchemaValidate is the strict commit gate; the
// tolerant load/sync path downgrades typed-leaf violations to warnings
// (configstore compileTreeLenient), and warnBGPAuth16621 below adds the
// same specific warning on BOTH compile paths so a persisted config
// carrying these spellings names the statement instead of only the
// generic #10707 advisory. The keychain/algorithm values are chain /
// algorithm NAMES, not secrets, so naming them in a warning discloses
// no credential; the top-level key itself is never warned about because
// it is now rendered.

// unmodeledBGPKeychainLeaf refuses `authentication-key-chain <name>` at
// bgp, group and neighbor level. Modelled ONLY so it is REFUSED, in the
// unmodeledOSPFKeychainLeaf shape: ValueEnumOf with no examples (the
// acceptable set is genuinely empty — ValueAny would leave the
// validator uninvoked and reproduce the silent accept).
func unmodeledBGPKeychainLeaf() *schemaNode {
	return &schemaNode{
		desc: "authentication-key-chain (Junos BGP keychain authentication — not " +
			"implemented by xpf; rejected at commit)",
		args:        1,
		placeholder: "<keychain-name>",
		valueType:   ValueEnumOf,
		valueDesc: "not implemented by xpf; BGP keychain authentication " +
			"is not rendered to FRR",
		validator: rejectBGPKeychain,
		children:  nil,
	}
}

func rejectBGPKeychain(_ string) error {
	return fmt.Errorf(
		"authentication-key-chain: BGP keychain authentication is not implemented by xpf " +
			"— no keychain is rendered to FRR, so the session would run " +
			"without TCP-MD5 while the configuration reads as though it is " +
			"protected. Remove the authentication-key-chain statement and use " +
			"`authentication-key <key>` at the bgp, group or neighbor level, " +
			"which xpf renders as the peer password (#16621)")
}

// unmodeledBGPAuthAlgorithmLeaf refuses `authentication-algorithm
// <name>` at bgp, group and neighbor level, in the same shape.
// Junos' algorithm selects the TCP authentication option algorithm;
// the FRR `neighbor X password` xpf renders is TCP-MD5 only, so any
// authored algorithm selection cannot be honoured — and an operator
// who pinned a stronger algorithm would silently get MD5 or nothing.
func unmodeledBGPAuthAlgorithmLeaf() *schemaNode {
	return &schemaNode{
		desc: "authentication-algorithm (Junos BGP TCP authentication algorithm — not " +
			"implemented by xpf; rejected at commit)",
		args:        1,
		placeholder: "<algorithm>",
		valueType:   ValueEnumOf,
		valueDesc: "not implemented by xpf; BGP authentication-algorithm " +
			"selection is not rendered to FRR",
		validator: rejectBGPAuthAlgorithm,
		children:  nil,
	}
}

func rejectBGPAuthAlgorithm(_ string) error {
	return fmt.Errorf(
		"authentication-algorithm: BGP authentication-algorithm selection is not implemented by xpf " +
			"— the rendered peer password is TCP-MD5 only, so the session would run " +
			"with a different (or no) algorithm than configured while the " +
			"configuration reads as though it is protected. Remove the " +
			"authentication-algorithm statement and use `authentication-key <key>` " +
			"at the bgp, group or neighbor level (#16621)")
}

// bgpAuthRefusedKeyword16621 reports whether keyword is one of the
// refused BGP authentication spellings above.
func bgpAuthRefusedKeyword16621(keyword string) bool {
	return keyword == "authentication-key-chain" || keyword == "authentication-algorithm"
}

// warnBGPAuth16621 returns specific warnings for refused BGP
// authentication spellings (`authentication-key-chain` /
// `authentication-algorithm`) anywhere under a `protocols bgp` subtree
// — top level, group, or neighbor, in the default instance or a
// routing instance. It walks the (already group-expanded) tree the
// compiler consumes, so flat-set, hierarchical and packed spellings
// are all seen: a refused spelling packed onto a parent line appears
// either as a child node or as a tail token of an ancestor node, and
// both are scanned.
//
// Why a compiler warning in addition to the strict SchemaValidate
// refusal: on the tolerant load/peer-sync path the schema violation is
// downgraded to a generic warning, and on the strict compile path
// CompileConfig does not run SchemaValidate at all — without this, a
// direct compile of either path shows only the generic #10707
// "may be silently ignored" advisory (or nothing, for packed tails the
// #10707 walk cannot segment). The warning NAMES the statement and
// says it is not rendered, which is the acceptance bar in #16621.
//
// The scan is keyword-only: it never reads the leaf's value, so no
// credential can leak into a warning. (Keychain/algorithm values are
// names, not secrets, but the key that may share the line is one.)
func warnBGPAuth16621(tree *ConfigTree) []string {
	if tree == nil {
		return nil
	}
	var warnings []string
	seen := map[string]struct{}{}
	var walk func(nodes []*Node, path []string)
	walk = func(nodes []*Node, path []string) {
		for _, node := range nodes {
			if node == nil || len(node.Keys) == 0 {
				continue
			}
			// The BGP subtree root: `bgp` directly under `protocols`
			// (default instance) or under a routing instance's
			// `protocols`. Everything below it is bgp/group/neighbor
			// scope for this gate.
			inBGP := false
			for i, p := range path {
				if p == "bgp" && i > 0 && path[i-1] == "protocols" {
					inBGP = true
					break
				}
			}
			isBGPRoot := node.Keys[0] == "bgp" && len(path) > 0 && path[len(path)-1] == "protocols"
			if inBGP || isBGPRoot {
				for _, tok := range node.Keys {
					if !bgpAuthRefusedKeyword16621(tok) {
						continue
					}
					loc := append(append([]string(nil), path...), node.Keys[0])
					msg := fmt.Sprintf("%s: %s is not implemented by xpf and is not rendered — the BGP session runs without the configured authentication; use authentication-key instead (#16621)",
						strings.Join(loc, " "), tok)
					if _, dup := seen[msg]; !dup {
						seen[msg] = struct{}{}
						warnings = append(warnings, msg)
					}
				}
			}
			walk(node.Children, append(append([]string(nil), path...), node.Keys[0]))
		}
	}
	walk(tree.Children, nil)
	return warnings
}
