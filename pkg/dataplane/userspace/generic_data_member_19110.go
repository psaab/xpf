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

// refreshGenericDataMembers re-resolves the RETH data members after a compile
// attach pass. Call it WITHOUT m.mu held. The #14133 refresh path, which holds
// m.mu, uses resolveGenericDataMembers plus setGenericDataMembersLocked.
//
// The readiness reason itself is NOT cached here (Codex note: cached
// readiness). genericDataMemberReasonsLocked checks the resolved members
// against the shim's LIVE generic-fallback record each time, so a post-
// acceptance DetachXDP clears the blocker at once. This keeps only the member
// map, which needs syscalls, and the last-logged reasons for the
// log-on-change.
func (m *Manager) refreshGenericDataMembers(cfg *config.Config) {
	members := m.resolveGenericDataMembers(cfg)
	m.mu.Lock()
	// This compile's config becomes the membership AUTHORITY. A later
	// refresh or revalidation re-resolves THIS config's members, never its
	// own snapshot's, so a stale retained publication cannot replace them
	// (Codex delta P2-2).
	m.genericDataMemberCfg = cfg
	reasons, changed := m.setGenericDataMembersLocked(members)
	m.mu.Unlock()
	if changed {
		logGenericDataMembers(reasons)
	}
}

// resolveGenericDataMembers maps the config's local RETH data members to their
// ifindexes. It takes no Manager lock.
func (m *Manager) resolveGenericDataMembers(cfg *config.Config) map[int]string {
	names := localDataMemberNames(cfg)
	if names == nil {
		return nil
	}
	out := map[int]string{}
	for _, name := range names {
		if ifindex, err := ifindexByNameFn(name); err == nil {
			out[ifindex] = name
		}
	}
	return out
}

// genericDataMemberReasonsFor is the live readiness computation: the members
// the shim currently records as unintended generic.
func genericDataMemberReasonsFor(members map[int]string, unintended map[int]string) []string {
	var reasons []string
	for ifindex, why := range unintended {
		if name, ok := members[ifindex]; ok {
			reasons = append(reasons, fmt.Sprintf(
				"userspace data interface %s %s (native refused: %s)",
				name, genericDataMemberReasonMarker, why))
		}
	}
	sort.Strings(reasons)
	return reasons
}

// setGenericDataMembersLocked stores the member map and reports whether the
// live reasons changed since the last log. Caller holds m.mu.
func (m *Manager) setGenericDataMembersLocked(members map[int]string) ([]string, bool) {
	m.genericDataMemberNames = members
	reasons := genericDataMemberReasonsFor(members, m.unintendedGenericXDP())
	changed := !slices.Equal(m.genericDataMembersLogged, reasons)
	m.genericDataMembersLogged = reasons
	return reasons, changed
}

func logGenericDataMembers(reasons []string) {
	if len(reasons) > 0 {
		slog.Error("RETH data member in generic XDP mode: this node is not takeover-ready while a peer "+
			"is alive, and a lone owner forwards it in skb mode with AF_XDP in copy mode",
			"members", reasons, "issue", "#19110",
			"remediation", "fix the native refusal (for mlx5: disable LRO and HW-GRO), then RESTART xpfd; "+
				"a re-commit keeps the existing generic link")
		return
	}
	slog.Info("no RETH data member is in generic XDP mode any more", "issue", "#19110")
}

// genericDataMemberReasonsLocked returns the readiness reasons, computed from
// the shim's LIVE record. Caller holds m.mu (lock order: userspace m.mu, then
// the shim manager's own mutex, as for XDPLinks in the refresh reconcile).
func (m *Manager) genericDataMemberReasonsLocked(peerAlive bool) []string {
	if !peerAlive || len(m.genericDataMemberNames) == 0 {
		return nil
	}
	return genericDataMemberReasonsFor(m.genericDataMemberNames, m.unintendedGenericXDP())
}
