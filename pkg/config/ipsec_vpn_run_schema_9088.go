package config

// ipsecVPNRunSchema9088 is the schema `expandFlatRun` reads when segmenting a
// packed run under `security ipsec vpn <name>`.
//
// #9088 found that compileIPsec and the bind-interface gate read `gateway` and
// `ipsec-policy`, while setSchema did not declare them. A packed run therefore
// had no cut points and silently dropped every leaf after its head.
//
// #10327 promotes those compiler-read direct leaves into setSchema, alongside
// the existing nested `ike` form. Keep this helper name so both readers still
// share one resolver; it now returns the declared VPN schema directly rather
// than manufacturing a second, compiler-only child map.
func ipsecVPNRunSchema9088() *schemaNode {
	return ipsecVPNLeafSchema8939()
}

// expandIPsecVPNRun9088 feeds both AST serializations to the shared reader:
// SetPath and braced blocks put VPN leaves in Children, while the compact
// hierarchical spelling `vpn <name> gateway <g>;` keeps the direct tail on
// the VPN node's own Keys. Ignoring that tail recreates #2419's compact-blind
// loss even though the leaves are declared in setSchema.
func expandIPsecVPNRun9088(vpn *Node) []*Node {
	if vpn == nil {
		return nil
	}
	schema := ipsecVPNRunSchema9088()
	out := expandFlatRun(vpn.Children, schema)
	if len(vpn.Keys) <= 2 {
		return out
	}
	tail := &Node{Keys: vpn.Keys[2:], IsLeaf: true}
	return append(out, expandFlatRun([]*Node{tail}, schema)...)
}
