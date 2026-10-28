package config

import (
	"fmt"
	"sort"
)

// #9727: the userspace dataplane receives into fixed-size UMEM frames and binds
// its AF_XDP sockets without multi-buffer (XDP_USE_SG) support, so a frame
// larger than one UMEM frame cannot reach a worker. In copy mode the kernel
// drops it and counts it in the XSK rx_dropped counter (surfaced as
// kernel_rx_dropped); a zero-copy driver may refuse the XSK setup instead, and
// the #7191 arm then fails closed. The interface `mtu` leaf accepts any value,
// so a jumbo MTU on a bound interface committed clean and turned into drops or
// a refused bind with nothing at commit saying why.

const (
	// userspaceUMEMFrameSize and userspaceUMEMHeadroom mirror UMEM_FRAME_SIZE
	// and UMEM_HEADROOM in userspace-dp/src/afxdp/mod.rs;
	// TestUserspaceUMEMConstantsMatchTheHelper9727 binds them.
	userspaceUMEMFrameSize = 4096
	userspaceUMEMHeadroom  = 256
	// userspaceXDPacketHeadroom is the kernel's fixed XDP_PACKET_HEADROOM
	// (256). xsk_pool_get_headroom sums it with the configured UMEM headroom,
	// so the kernel's usable RX frame size is the frame size minus both.
	userspaceXDPacketHeadroom = 256
	// userspaceRxMTUBudget is the largest MTU whose frame fits one UMEM frame:
	// the frame minus both headroom terms (the kernel's XDP_PACKET_HEADROOM
	// plus the configured UMEM headroom), a 14-byte Ethernet header and one
	// 4-byte 802.1Q tag (FCS is stripped before XDP).
	userspaceRxMTUBudget = userspaceUMEMFrameSize - (userspaceXDPacketHeadroom + userspaceUMEMHeadroom) - 14 - 4
)

// appendUserspaceRxMTUAdvisoryLocked warns once per AF_XDP bind parent
// whose effective MTU exceeds userspaceRxMTUBudget.
//
// The parent set and effective MTU come from
// userspaceRxMTUBoundParents: InterfaceZoneMap supplies surviving zone
// membership, ResolveKernelIfName resolves each logical row to its
// netdev, tagged rows redirect to their physical parent, and a
// referenced untagged unit (lowest unit number) overrides the
// interface MTU. Config-owned tunnel/secure-tunnel rows, lifeline
// names, and local-fabric rows are excluded. Live-kernel xfrm state
// cannot be known at commit time and remains outside this predicate.
//
// The zone name is deliberately absent. `mgmt` and `control` are
// operator-controlled labels, not lifeline identity; a data NIC in one
// of those zones is still AF_XDP-bound and policy-adjudicated (#10308).
//
// A WARNING, not an error. Commit cannot tell a copy-mode binding
// (drops counted) from a zero-copy one (a refused bind), and a jumbo
// MTU remains correct for the kernel-forwarded traffic of an
// interface. The strict #16244 gate uses the same effective parents.
// opts.tolerant silences it on the tolerant
// boot and peer-sync paths, for the reason given at
// appendContestedTrunkZoneAdvisoryLocked.
func appendUserspaceRxMTUAdvisoryLocked(cfg *Config, opts compileOpts) {
	if cfg == nil || opts.tolerant {
		return
	}
	over := userspaceRxMTUOverBudget(cfg)
	bases := make([]string, 0, len(over))
	for base := range over {
		bases = append(bases, base)
	}
	sort.Strings(bases)
	for _, base := range bases {
		cfg.Warnings = append(cfg.Warnings, fmt.Sprintf(
			"interface %s has MTU %d, above the userspace dataplane's single-frame receive "+
				"budget of %d bytes (a %d-byte UMEM frame minus %d bytes of headroom — "+
				"%d bytes of kernel XDP_PACKET_HEADROOM plus %d bytes of UMEM headroom — and the "+
				"Ethernet/VLAN header; AF_XDP is bound without multi-buffer support): frames "+
				"larger than the budget cannot reach a worker. They are dropped and counted in "+
				"kernel_rx_dropped, or a zero-copy driver refuses the AF_XDP bind (#9727).",
			base, over[base], userspaceRxMTUBudget, userspaceUMEMFrameSize,
			userspaceXDPacketHeadroom+userspaceUMEMHeadroom, userspaceXDPacketHeadroom, userspaceUMEMHeadroom))
	}
}

// userspaceRxMTUOverBudget returns authored parent name -> the
// effective MTU above the budget for its resolved AF_XDP bind parent.
// The map key remains the authored parent stanza (for a RETH reference,
// `reth<N>`) because the advisory and refusal name what the operator
// configured; userspaceRxMTUBoundParents records the distinct Linux
// bind netdev separately for callers that need it.
func userspaceRxMTUOverBudget(cfg *Config) map[string]int {
	out := map[string]int{}
	for _, parent := range userspaceRxMTUBoundParents(cfg) {
		name := parent.Parent
		if name == "" {
			name = parent.AuthoredBase
		}
		if parent.MTU > userspaceRxMTUBudget && parent.MTU > out[name] {
			out[name] = parent.MTU
		}
	}
	return out
}
