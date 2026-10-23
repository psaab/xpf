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
		child := &Node{Keys: []string{node.Keys[1]}, Line: node.Line, Column: node.Column, Children: node.Children, IsLeaf: node.IsLeaf && len(node.Children) == 0}
		if len(node.Keys) > 2 {
			child.Keys = append(child.Keys, node.Keys[2:]...)
		}
		node.Keys = node.Keys[:1]
		node.Children = []*Node{child}
		node.IsLeaf = false
		n++
	}
	return n
}
