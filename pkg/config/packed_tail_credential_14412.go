package config

import "strings"

// #14412 (DR13-H5): credential tokens carried in a packed tail that no
// reader consumes.
//
// A credential keyword is drawn from the existing secret resolutions —
// secretLeafKeywords (secret.go) plus the distinctive keywords
// secretIndices (ast_redact.go) knows — never a new list. Generic dual-use
// keywords (`key`, `password`, `secret`, `community`) are deliberately
// excluded: they need ancestor context to mean "credential" (see
// secretIndices), and gating on them here would false-reject ordinary
// value tokens. Case-insensitive matching is the point: `Authentication-Key`
// names nothing in the (lowercase) schema yet is unambiguously an
// attempted credential.
func isPackedTailCredentialToken14412(tok string) bool {
	switch strings.ToLower(tok) {
	case "authentication-key", "additional-authentication-key",
		"authentication-password", "privacy-password",
		"encrypted-password", "simple-password",
		"pre-shared-key", "preshared-key", "private-key",
		"api-key", "api-token", "aws-secret-key", "tsig-secret":
		return true
	}
	return false
}

// packedTailCredential14412 returns the first dropped credential token in
// node.Keys[from:], with its index in node.Keys, or ""/-1. A token is
// consumed — not dropped — when its exact-case form resolves as a child
// of the descendent schema (a validly placed credential owns its packed
// spelling). A token authored as a quoted or bracketed value (#9635) is a
// value, not a statement head, and is never reported.
func packedTailCredential14412(node *Node, descend *schemaNode, from int) (string, int) {
	if node == nil || descend == nil || from >= len(node.Keys) {
		return "", -1
	}
	mask := authoredValueMask9635(node.KeysQuoted, node.KeysBracketed, len(node.Keys))
	for i := from; i < len(node.Keys); i++ {
		tok := node.Keys[i]
		if !isPackedTailCredentialToken14412(tok) {
			continue
		}
		if mask != nil && mask[i] {
			continue
		}
		if resolveSchemaChild(descend, tok) != nil {
			continue
		}
		return tok, i
	}
	return "", -1
}
