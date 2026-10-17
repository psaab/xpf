package config

// #14450 (DR20-H5): duplicate `tunnel` blocks under one interface/unit.
//
// compileInterfaces used FindChild("tunnel") (first-only) at both the
// interface and unit sites, so a second `tunnel { ... }` sibling was
// never read. With
//
//	tunnel { mode gre; destination 10.0.0.1; }
//	tunnel { mode wireguard; wireguard { ... } }
//
// the installed tunnel was plaintext GRE with no WireGuard peers.
// Junos-merge reads both blocks: scalars are last-wins (the same rule
// the per-block prop loops already apply within one block) and
// wireguard peers accumulate via parseTunnelWireguard's append.
// Duplicate peer pubkeys across blocks are NOT deduped here — the
// existing validateWireguardPeers duplicate-pubkey gate rejects them
// fail-closed once both peers are actually compiled.

// lastModeTunnelNode14450 returns the latest tunnel block that authors
// a non-empty `mode` leaf (consulting the expanded run children, as the
// compile loops do), or nil when no block authors a mode.
// unitSharesInterfaceWireguardDevice reads ONE node's mode and treats
// an absent mode as "inherits the interface mode", so the call site
// must supply this node — not blindly the last block, whose absent
// mode would hide an earlier block's merged mode.
func lastModeTunnelNode14450(nodes []*Node) *Node {
	var found *Node
	for _, n := range nodes {
		// Raw children first (braced `mode { wireguard; }`, #14440),
		// then the expanded run (flat/packed spellings), mirroring the
		// compile loops' two passes per block.
		for _, prop := range n.Children {
			if prop.Name() == "mode" && nodeVal(prop) != "" {
				found = n
			}
		}
		for _, prop := range tunnelRunChildren9156(n) {
			if prop.Name() == "mode" && nodeVal(prop) != "" {
				found = n
			}
		}
	}
	return found
}
