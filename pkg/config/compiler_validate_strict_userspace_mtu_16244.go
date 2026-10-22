package config

import (
	"fmt"
	"sort"
)

// validateUserspaceRxMTUStrict hard-rejects a userspace-dataplane-bound
// parent whose effective MTU exceeds userspaceRxMTUBudget (#16244).
//
// Trace (config mtu -> netdev -> XDP/AF_XDP):
//   - config: `interfaces <if> mtu` / unit family mtu compile to
//     InterfaceConfig.MTU / InterfaceUnit.MTU (compiler_interfaces.go).
//   - netdev: planPhysDesired (pkg/dataplane) merges zoned refs into one
//     physDesired.mtu per netdev; mapZoneInterface writes it with
//     LinkSetMTU BEFORE LinkSetUp and before the deferred XDP attach, so
//     the write itself already survives XDP attach in-order. networkd
//     also renders the same value as MTUBytes.
//   - XDP/AF_XDP: the shim is attached after the MTU write, and the Rust
//     helper binds AF_XDP sockets without multi-buffer (XDP_USE_SG)
//     support into fixed 4096-byte UMEM frames (UMEM_FRAME_SIZE in
//     userspace-dp/src/afxdp/mod.rs). A frame larger than one UMEM frame
//     minus headroom cannot reach a worker: in copy mode the kernel drops
//     it (kernel_rx_dropped); a zero-copy driver may refuse the bind.
//
// The gate must judge the same value the actuator writes to the actual
// bind parent. userspaceRxMTUBoundParents therefore applies
// planPhysDesired's precedence to the resolved parent: an interface MTU
// supplies the parent unless a referenced, enabled, untagged unit
// overrides it, with the lowest referenced untagged unit winning.
// Tagged units never lower or raise the parent: their own MTU belongs
// to the VLAN child, whereas AF_XDP binds the physical parent. For a
// RETH reference, the `reth<N>` stanza supplies that parent MTU and
// the resolved local member is the named bind netdev.
//
// Named refusal (#16244 acceptance, second arm): strict commit /
// commit-check reject an over-budget effective parent MTU naming the
// authored interface, the resolved bind netdev when it differs, the
// effective MTU, and the single-frame budget. Jumbo propagation stays
// blocked until the UMEM frame-size redesign (multi-buffer or larger
// frames) lands; this gate must then be widened with the budget, which
// TestUserspaceUMEMConstantsMatchTheHelper9727 already binds to the
// Rust constants.
//
// Strict on commit / commit-check; downgraded to a cfg.Warnings entry
// on the tolerant load / peer-sync paths (flag
// lenientUserspaceRxMTU16244) so an already-persisted or peer-synced
// config still boots (#1960 no-brick). The #9727 advisory remains a
// warning and is suppressed on those paths, so the downgraded gate is
// the tolerant paths' only MTU signal. Parents are visited in resolved
// netdev order so commit-check surfaces a stable first error.
func validateUserspaceRxMTUStrict(cfg *Config) error {
	bound := userspaceRxMTUBoundParents(cfg)
	names := make([]string, 0, len(bound))
	for name, parent := range bound {
		if parent.MTU > userspaceRxMTUBudget {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return nil
	}
	sort.Strings(names)
	parent := bound[names[0]]
	parentName := parent.Parent
	if parentName == "" {
		parentName = parent.AuthoredBase
	}
	device := ""
	if parent.Netdev != "" && LinuxIfName(parentName) != parent.Netdev {
		device = fmt.Sprintf(" (bind netdev %s)", parent.Netdev)
	}
	return fmt.Errorf(
		"interface %s%s has effective MTU %d, above the userspace dataplane's single-frame receive "+
			"budget of %d bytes (a %d-byte UMEM frame minus %d bytes of headroom — "+
			"%d bytes of kernel XDP_PACKET_HEADROOM plus %d bytes of UMEM headroom — and the "+
			"Ethernet/VLAN header; AF_XDP is bound without multi-buffer support): frames "+
			"larger than the budget cannot reach a worker, so this MTU would commit clean "+
			"and then drop at line rate or refuse the AF_XDP bind. Lower the effective "+
			"parent mtu to at most %d, or remove %s from its security zone (#16244)",
		parentName, device, parent.MTU, userspaceRxMTUBudget, userspaceUMEMFrameSize,
		userspaceXDPacketHeadroom+userspaceUMEMHeadroom, userspaceXDPacketHeadroom,
		userspaceUMEMHeadroom, userspaceRxMTUBudget, parentName)
}
