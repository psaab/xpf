package userspace

import (
	"fmt"
	"log/slog"
	"net"
	"slices"
	"sort"

	"github.com/psaab/xpf/pkg/config"
)

// #19110 F4, the narrowed guard: a RETH data member that ended up in GENERIC XDP
// mode after a native refusal is not a member a node should be handed traffic
// on.
//
// On loss, two members in exactly that state proved XSK liveness, promoted, and
// forwarded nothing. After #19110's reclaim and refusal fixes, a kernel refusal
// (EBUSY/EEXIST) can no longer produce generic. A generic fallback still
// follows any other native error:
//   - mlx5 refuses native XDP with EINVAL while LRO/HW-GRO is on
//     (mlx5e_xdp_allowed);
//   - a resource failure (ENOMEM, ...).
// The one native error that is NOT counted is EOPNOTSUPP from a driver with no
// native XDP at all (no ndo_bpf, e.g. iavf). That generic is the supported
// deployment (pkg/dataplane TestArmProofGenericFallbackCountsAsArmed).
// pkg/dataplane (*Manager).UnintendedGenericXDP owns that classification.
//
// The members come from the CONFIG (RethToPhysical), so a fabric parent or any
// other non-data interface is never counted, and no xdp_features probe is
// needed.
//
// Effect:
//   - with the peer alive, each such member is a takeover-readiness reason, so
//     a healthy native peer keeps the RGs;
//   - a lone owner has no better node, so the reason is omitted (the #16844
//     precedent for the fabric clause). It gets an ERROR log, and the takeover
//     blocker metric, which is computed in the peer-alive form, shows
//     xdp_generic_data_member.

// genericDataMemberReasonMarker is the substring MapHATakeoverBlocker keys on.
const genericDataMemberReasonMarker = "attached in generic XDP mode"

// ifindexByNameFn resolves a Linux interface name. It is a seam for the cells.
var ifindexByNameFn = func(name string) (int, error) {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return 0, err
	}
	return ifi.Index, nil
}

// unintendedGenericXDP is the shim manager's record, or the test hook.
func (m *Manager) unintendedGenericXDP() map[int]string {
	if m.unintendedGenericXDPHook != nil {
		return m.unintendedGenericXDPHook()
	}
	if m.bpfShim == nil {
		return nil
	}
	return m.bpfShim.UnintendedGenericXDP()
}

// refreshGenericDataMembers recomputes the set after an attach pass. Call it
// WITHOUT m.mu held: it reads the shim manager and resolves interface names.
func (m *Manager) refreshGenericDataMembers(cfg *config.Config) {
	var reasons []string
	if cfg != nil && cfg.Chassis.Cluster != nil {
		if unintended := m.unintendedGenericXDP(); len(unintended) > 0 {
			members := cfg.RethToPhysical()
			names := make([]string, 0, len(members))
			for _, phys := range members {
				names = append(names, config.LinuxIfName(phys))
			}
			sort.Strings(names)
			for _, name := range slices.Compact(names) {
				ifindex, err := ifindexByNameFn(name)
				if err != nil {
					continue
				}
				if why, ok := unintended[ifindex]; ok {
					reasons = append(reasons, fmt.Sprintf(
						"userspace data interface %s %s (native refused: %s)",
						name, genericDataMemberReasonMarker, why))
				}
			}
		}
	}
	m.mu.Lock()
	changed := !slices.Equal(m.genericDataMembers, reasons)
	m.genericDataMembers = reasons
	m.mu.Unlock()
	if !changed {
		return
	}
	if len(reasons) > 0 {
		slog.Error("RETH data member in generic XDP mode: this node is not takeover-ready while a peer "+
			"is alive, and a lone owner forwards it in skb mode with AF_XDP in copy mode",
			"members", reasons, "issue", "#19110",
			"remediation", "fix the native refusal (for mlx5: disable LRO and HW-GRO), then re-commit "+
				"or restart xpfd")
		return
	}
	slog.Info("no RETH data member is in generic XDP mode any more", "issue", "#19110")
}

// genericDataMemberReasonsLocked returns the readiness reasons. Caller holds
// m.mu.
func (m *Manager) genericDataMemberReasonsLocked(peerAlive bool) []string {
	if !peerAlive || len(m.genericDataMembers) == 0 {
		return nil
	}
	return append([]string(nil), m.genericDataMembers...)
}
