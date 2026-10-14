package config

import "fmt"

// validateALGPackedTokens rejects tokens that the ALG compiler does not consume.
// Known ALG classes accept only the optional `disable` token; unknown classes
// remain opaque because their vendor-specific bodies are intentionally tolerated.
func validateALGPackedTokens(node *Node, _ *schemaNode) error {
	if node == nil || len(node.Keys) == 0 {
		return nil
	}
	proto := node.Keys[0]
	tokens := node.Keys[1:]
	if proto == "alg" {
		if len(tokens) == 0 {
			return nil
		}
		proto = tokens[0]
		tokens = tokens[1:]
	}
	switch proto {
	case "dns", "ftp", "sip", "tftp":
		for _, token := range tokens {
			if token != "disable" {
				return fmt.Errorf("unknown configuration keyword %q under ALG %q (valid: disable)", token, proto)
			}
		}
	}
	return nil
}

// algDisabled reports whether `security alg <proto>` carries a `disable`
// statement, in EITHER AST shape (#6564).
//
// `alg { dns { disable; } }` gives a "dns" child with a "disable" child, but
// `alg { dns disable; }` is ONE leaf with Keys=["dns","disable"] and no
// children at all — the parser packs a `;`-terminated statement onto a single
// node. Reading Children alone (the pre-#6564 form) was blind to the second
// spelling, so an operator-disabled ALG silently stayed ENABLED with no
// warning: the #4232 unsupported-proto advisory does not fire either, because
// the four protos here ARE wired.
//
// This is the same accumulate-both-sides discipline as firewallMatchValues /
// addressSetMemberValues.
func algDisabled(algNode *Node, proto string) bool {
	for _, protoNode := range algNode.FindChildren(proto) {
		if protoNode.FindChild("disable") != nil {
			return true
		}
		for _, k := range protoNode.Keys[1:] {
			if k == "disable" {
				return true
			}
		}
	}
	return false
}

func compileALG(node *Node, sec *SecurityConfig) error {
	sec.ALG.DNSDisable = sec.ALG.DNSDisable || algDisabled(node, "dns")
	sec.ALG.FTPDisable = sec.ALG.FTPDisable || algDisabled(node, "ftp")
	sec.ALG.SIPDisable = sec.ALG.SIPDisable || algDisabled(node, "sip")
	sec.ALG.TFTPDisable = sec.ALG.TFTPDisable || algDisabled(node, "tftp")
	// #4232 (fable-167 P-4a): record any `security alg <proto>` whose proto is
	// not one of the four the dataplane wires. The whole stanza (bare `disable`
	// or a richer child like `h323 gatekeeper ...`) was previously dropped
	// silently; recording the proto lets the compiler emit an accepted-but-inert
	// advisory (validateSecurityAcceptedOnly). Iterate node.Children in config
	// order for a deterministic warning.
	// #8823: the proto may be packed onto THIS node's Keys instead of being a
	// child, in two shapes the loop below cannot read:
	//
	//	security { alg ftp disable; }      Keys=[alg ftp disable]  children=[]
	//	security { alg ftp { disable; } }  Keys=[alg ftp]          children=[disable]
	//
	// In both, `alg` carries the PROTO and any children belong to the proto
	// rather than to `alg`. Measured before the fix, on a clean commit:
	//
	//	alg ftp disable;        ftp=false  unsupported=[]          <- silent drop
	//	alg ftp { disable; }    ftp=false  unsupported=[disable]   <- WRONG advisory
	//	alg h323 { gatekeeper; }           unsupported=[gatekeeper]<- WRONG name
	//
	// The mixed shape is worse than the silent one: the #4232 advisory exists to
	// report a proto the dataplane does not wire, and it named `disable` and
	// `gatekeeper` -- a keyword and a sub-statement -- as though they were
	// protocols. A reader acting on that looks for an ALG that does not exist.
	//
	// Handled HERE rather than by admitting ("alg",<proto>) to the #8690
	// normalizer, and that choice was measured rather than reasoned. Admitting
	// the pair fixes the four DECLARED protos and cannot reach an undeclared one
	// at all -- the pass asks nothing for `h323` (`asked=[]`), which is the
	// #8800 signature -- and declaring unsupported protos to make it ask would
	// defeat the advisory those declarations exist to preserve. A compiler-side
	// read covers both classes at one site. It also mirrors algDisabled, which
	// already reads a packed tail one level down.
	if len(node.Keys) > 1 {
		proto := node.Keys[1]
		tail := node.Keys[2:]
		switch proto {
		case "dns":
			sec.ALG.DNSDisable = sec.ALG.DNSDisable || algPackedDisable(tail, node.Children)
		case "ftp":
			sec.ALG.FTPDisable = sec.ALG.FTPDisable || algPackedDisable(tail, node.Children)
		case "sip":
			sec.ALG.SIPDisable = sec.ALG.SIPDisable || algPackedDisable(tail, node.Children)
		case "tftp":
			sec.ALG.TFTPDisable = sec.ALG.TFTPDisable || algPackedDisable(tail, node.Children)
		default:
			sec.ALG.UnsupportedProtos = append(sec.ALG.UnsupportedProtos, proto)
		}
		// The children belong to the packed proto, not to `alg`, so the loop
		// below must not read them as protos -- that is what produced
		// `unsupported=[disable]`.
		return nil
	}
	for _, child := range node.Children {
		switch child.Name() {
		case "dns", "ftp", "sip", "tftp":
			// wired above
		default:
			sec.ALG.UnsupportedProtos = append(sec.ALG.UnsupportedProtos, child.Name())
		}
	}
	return nil
}

// algPackedDisable reports whether a packed proto's body carries `disable`, in
// either the Keys tail (`alg ftp disable;`) or a child (`alg ftp { disable; }`).
func algPackedDisable(tail []string, children []*Node) bool {
	for _, k := range tail {
		if k == "disable" {
			return true
		}
	}
	for _, c := range children {
		if c.Name() == "disable" {
			return true
		}
	}
	return false
}
