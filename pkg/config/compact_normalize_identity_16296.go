package config

// normalizeElidedSecurityIdentity16296 folds a TOP-LEVEL elided security
// identity stanza (`security authentication-source { foo; }`,
// `security user-identification { ... }`) into its braced shape. The
// generic fold cannot name this pair: the node is the `security` root
// itself (Keys[0] == "security", Keys[1] is the stanza), so no
// (container, head) scope pair fires for it (#16296 rebase, following
// the #15062 elided-interface precedent). Without the fold the schema
// walker validates the elided node's children at the closed security
// level and rejects the first authored leaf, while the braced spelling
// passes through the opaque identity node.
func normalizeElidedSecurityIdentity16296(nodes []*Node) int {
	n := 0
	for _, node := range nodes {
		if node == nil || len(node.Keys) < 2 || node.Keys[0] != "security" {
			continue
		}
		if !userIdentificationStanzas[node.Keys[1]] && node.Keys[1] != "user-identification" {
			continue
		}
		if len(node.Keys) == 2 && len(node.Children) == 0 {
			continue // bare leaf, nothing to fold
		}
		quoted := keyMask(node.KeysQuoted, len(node.Keys))
		bracketed := keyMask(node.KeysBracketed, len(node.Keys))
		closed := node.BracketedClosed
		child := &Node{Keys: []string{node.Keys[1]}, Line: node.Line, Column: node.Column, Children: node.Children, IsLeaf: node.IsLeaf && len(node.Children) == 0}
		child.replaceKeys(node.Keys[1:], maskSlice(quoted, 1, len(node.Keys)),
			maskSlice(bracketed, 1, len(node.Keys)), closed)
		node.replaceKeys(node.Keys[:1], maskSlice(quoted, 0, 1),
			maskSlice(bracketed, 0, 1), closed)
		node.Children = []*Node{child}
		node.IsLeaf = false
		n++
	}
	return n
}
