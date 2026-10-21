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

// packedTailCredentialRefused14412 reports whether child, resolved at a
// statement HEAD, is modelled only so it is refused (its typed-leaf
// validator rejects every value — the unmodeled*Leaf shape of
// schema_ospf_authentication_8443.go). Such a child packed at a head is
// never validated on the non-packedTail path, so it is dropped exactly
// as a misplaced credential. A credential child with any other validator
// (or none) is genuinely consumed/validated at its head. #16108.
func packedTailCredentialRefused14412(child *schemaNode) bool {
	if child == nil || child.validator == nil || child.valueType != ValueEnumOf || len(child.valueExamples) != 0 {
		return false
	}
	// A refusal stub rejects EVERY value; a real enum leaf only rejects
	// values outside its (here empty) example set but its validator may
	// still accept. Probe with a sentinel: refusal stubs ignore the
	// value and always error.
	return child.validator("xpf-probe-16108", nil) != nil
}

// packedTailCredential14412 returns the first dropped credential token in
// node.Keys[from:], with its index in node.Keys, or ""/-1. Only STATEMENT
// HEAD positions count: the tail is walked through descend's grammar the
// way packedBodyChildren / firstUnknownPackedKeyword15778 walk it — a
// resolving head consumes its 1+args span (plus a compoundKey sub-token),
// a leaf with no children/wildcard owns the rest of the tail as values,
// and a multi/valueList leaf absorbs values until a sibling head or its
// own modifier child appears. A credential-spelled token in a VALUE
// position (e.g. the bare MD5 key in
// `authentication md5 1 key authentication-key`) is consumed, never
// reported (#16108 fold). A head token is dropped when it does not
// resolve as a child of the current grammar level (misplaced or
// case-variant), or when it resolves only to a refusal stub
// (packedTailCredentialRefused14412). Walking stops at the first token
// that leaves the modelled grammar: heads at/after it cannot be judged
// (their predecessors were not consumed either), except that a
// credential head already seen at a judged position is reported first.
// A token authored as a quoted or bracketed value (#9635) is a value,
// not a statement head, and is never reported.
func packedTailCredential14412(node *Node, descend *schemaNode, from int) (string, int) {
	if node == nil || descend == nil || from >= len(node.Keys) || descend.packedTail || descend.closedWorldOpaque {
		return "", -1
	}
	mask := authoredValueMask9635(node.KeysQuoted, node.KeysBracketed, len(node.Keys))
	// Open grammar levels, deepest last — the stack packedBodyChildren
	// keeps. A head resolves at the deepest level declaring it; levels
	// below that are popped. A childless leaf therefore does not end
	// the walk: the next token is judged again at the shallower levels
	// (`passive authentication-key …`).
	levels := []*schemaNode{descend}
	i := from
	for i < len(node.Keys) {
		tok := node.Keys[i]
		if mask != nil && mask[i] {
			// A quoted/bracketed token at a would-be head is an authored
			// value (#9635); its arity is unknowable, so stop judging.
			return "", -1
		}
		at := -1
		var child *schemaNode
		for lvl := len(levels) - 1; lvl >= 0; lvl-- {
			if cs := resolveSchemaChild(levels[lvl], tok); cs != nil {
				at, child = lvl, cs
				break
			}
		}
		if child == nil {
			if isPackedTailCredentialToken14412(tok) {
				return tok, i
			}
			// Outside the modelled grammar: heads past here cannot be
			// judged (this statement's arity is unknown).
			return "", -1
		}
		if isPackedTailCredentialToken14412(tok) && packedTailCredentialRefused14412(child) {
			return tok, i
		}
		owner := levels[at]
		if child.multi || child.valueList {
			consumed, _ := consumeNodeKeys(node.Keys[i:], child)
			j := i + consumed
			if node.BracketedClosed {
				return "", -1
			}
			resumed := false
			for j < len(node.Keys) {
				if mask != nil && mask[j] {
					j++
					continue
				}
				t := node.Keys[j]
				if mod, isMod := child.children[t]; isMod {
					j += 1 + mod.args
					continue
				}
				if resolveSchemaChild(owner, t) != nil {
					// Resume as a head owned by `owner`; it is
					// re-resolved on the next iteration against
					// the stack truncated to owner.
					levels = levels[:at+1]
					i = j
					resumed = true
					break
				}
				j++
			}
			if !resumed {
				return "", -1
			}
			continue
		}
		consumed, next := consumeNodeKeys(node.Keys[i:], child)
		i += consumed
		levels = append(levels[:at+1], next)
	}
	return "", -1
}
