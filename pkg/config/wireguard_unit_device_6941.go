package config

// WireGuard unit device resolution (#6941), split out of
// compiler_interfaces.go: adding the rule and its rationale there pushed that
// file past the 1500 LOC [WATCH] modularity floor
// (pkg/refactoraudit). The rule is a self-contained question about ONE leaf --
// which Linux device a unit's tunnel stanza resolves to -- so it reads better
// beside its own reasoning than inline in the interface compiler.

// unitSharesInterfaceWireguardDevice reports whether a unit's own `tunnel`
// stanza should resolve to the INTERFACE's Linux device rather than its own
// "uN" device (#6941).
//
// True only when the interface carries `tunnel mode wireguard` AND the unit
// does not override the mode. Both halves are load-bearing.
//
// WHY THE UNIT SHARES THE DEVICE. An interface-level WireGuard interface is
// ONE persistent TUN, and the emitter produces exactly ONE endpoint for it,
// keyed by the lowest configured unit ref (#1910). At most one device can
// therefore ever carry its WireGuard traffic. Giving such a unit its own
// device produced a netdev that could not:
//
//   - it holds the unit's ADDRESSES, because address placement follows this
//     same name; and
//   - it can hold no endpoint of its own, because the interface's single
//     endpoint binds whichever device the LOWEST unit resolves to.
//
// So whenever the lowest configured unit was not the one carrying the tunnel
// stanza, the unit's addresses sat on one device while the WireGuard engine
// serving that unit's peers ran on another, and routing materialised the loser
// as an orphan. This became reachable rather than merely latent once #7786
// made those per-unit peers actually install: before it, they were discarded,
// so the orphan device referenced nothing.
//
// WHY A MODE-OVERRIDING UNIT KEEPS ITS OWN DEVICE. A unit that writes
// `tunnel mode gre` (or ipip) under a WireGuard interface is a different kind
// of tunnel, and collectAppliedTunnels emits a TunnelConfig per record while
// pkg/routing/tunnel.go keys its desired set by Name. Sharing the name would
// hand routing two records for ONE device with DIFFERENT modes — one taking
// the applyWireguardTunLocked path and one the kernel-tunnel/anchor path —
// which is a conflict rather than the benign same-name/same-mode sharing that
// key already relies on. Those units keep "uN" and are unchanged, which is
// also what keeps the #6861 anchor advisory's model intact.
//
// A per-unit WireGuard interface with NO interface-level stanza is likewise
// untouched: each of its units emits its own endpoint through the per-unit
// branch, so each genuinely needs its own device.
func unitSharesInterfaceWireguardDevice(ifc *InterfaceConfig, unitTunnelNode *Node) bool {
	if ifc == nil || ifc.Tunnel == nil || ifc.Tunnel.Mode != TunnelModeWireGuard {
		return false
	}
	// Read the unit's authored mode directly. The unit's TunnelConfig does not
	// exist yet at the call site (its Name is what is being decided), and an
	// absent `mode` means it inherits the interface's WireGuard mode.
	if unitTunnelNode == nil {
		return true
	}
	modeNode := unitTunnelNode.FindChild("mode")
	if modeNode == nil {
		return true
	}
	return nodeVal(modeNode) == "wireguard"
}
