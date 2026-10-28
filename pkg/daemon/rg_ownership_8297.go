package daemon

import "github.com/psaab/xpf/pkg/config"

// rg_ownership_8297.go carries a THREE-state ownership answer for consumers
// whose safe fail direction is "act" rather than "stay silent".
//
// #8342 is the reason this exists. #8314 gated proxy-ARP on
// `isRethMasterState` -> `AllVRRPMaster()` -> `allMasterLocked()`, which
// returns FALSE when the RG has no known VRRP instances:
//
//	if len(s.vrrpInstances) == 0 { return false }
//
// For the DHCP relay that predicate was written for, "nothing known -> do not
// relay" avoids a duplicate and failing closed is right. For proxy-ARP it is an
// OUTAGE: the entry is not installed, nobody answers for the address, and every
// NAT pool / DNAT / static-NAT external address on that segment goes dark. The
// revert measured exactly that — `fw0=0 fw1=0`, empty on both nodes.
//
// **A predicate's fail DIRECTION belongs to its consumer, not to its name.**
// That sentence is #8342's, and this file is what it asks for: the two-state
// bool cannot express the difference between "we are not the owner" and "we do
// not know who is", and proxy-ARP must treat those oppositely.
//
// Proxy ARP for NAT is a shipped, High-priority feature (`docs/feature-gaps.md`)
// — "Required when SNAT pool, DNAT, or static-NAT external addresses are on same
// L2 segment" — so silence is never the safe default for it. Answering twice is
// a defect (#8297); answering zero times is a bigger one.

// rgOwnership is a three-state answer to "does this node own redundancy-group
// N?", kept distinct from a bool so a caller cannot silently collapse the
// unknown case into either verdict.
type rgOwnership int

const (
	// rgOwnershipUnknown: no VRRP instance state is known for the RG, so this
	// node cannot say whether it owns it. Consumers whose silence is an outage
	// must ACT on this, not suppress.
	rgOwnershipUnknown rgOwnership = iota
	// rgOwnershipOwner: every VRRP instance for the RG is MASTER here.
	rgOwnershipOwner
	// rgOwnershipNotOwner: instances ARE known and this node is not master of
	// all of them. The only state in which suppressing is justified, because it
	// is the only one that affirmatively names another node as owner.
	rgOwnershipNotOwner
)

// Ownership reports the three-state ownership of the RG this state machine
// tracks.
//
// The `len(vrrpInstances) == 0` case is the whole point: `AllVRRPMaster` folds
// it into false, and this does not.
func (s *rgStateMachine) Ownership() rgOwnership {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.vrrpInstances) == 0 {
		return rgOwnershipUnknown
	}
	for _, isMaster := range s.vrrpInstances {
		if !isMaster {
			return rgOwnershipNotOwner
		}
	}
	return rgOwnershipOwner
}

// rgOwnershipFor is the daemon-level accessor, mirroring isRethMasterState's
// shape so the two sit side by side and the difference is visible at the call
// site rather than buried in a helper.
func (d *Daemon) rgOwnershipFor(rgID int) rgOwnership {
	return d.getOrCreateRGState(rgID).Ownership()
}

// clusterRGOwnership answers ownership from the CLUSTER's per-RG election
// state, which is the same source that decides whether this node holds the RG's
// VIPs at all.
//
// #8640: this exists because the VRRP-derived `Ownership()` above answers
// `Unknown` as a STEADY STATE on a real cluster. `vrrpInstances` is populated
// from one place — VRRP state-change EVENTS (`daemon_ha.go:902`/`:930`, gated on
// `isRethVRRPEvent`) — and nothing seeds it from current state. Measured on the
// loss userspace cluster: `show chassis cluster status` reports
// `vrrp-master=none` for EVERY redundancy group while simultaneously reporting
// `node0 primary / node1 secondary`, and ten fresh ARP probes for a pool address
// were answered by BOTH nodes with their own per-node RETH virtual MACs. So
// `Unknown` there does not mean "ownership is unknowable"; it means "no VRRP
// event has reached that handler".
//
// `cluster.GroupState(rgID).State == StatePrimary` is the predicate
// `shouldOwnDirectVIPs` (daemon_ha_vip.go) already uses to decide whether this
// node ADDS the RG's VIPs — which is why node0 held 172.16.80.8 and node1 did
// not in that same measurement. Reading it here makes one invariant true:
//
//	a node answers proxy-ARP for an address on an interface exactly when it
//	holds that interface's VIPs
//
// because both questions now read the SAME predicate and therefore cannot
// disagree. A node that does not hold the address should not draw traffic for
// it; that is the whole of what #8297 was trying to express.
//
// Returns rgOwnershipUnknown when the cluster manager cannot answer at all
// (standalone, or an RG it does not track), which hands the decision back to
// the VRRP-derived path unchanged.
func (d *Daemon) clusterRGOwnership(rgID int) rgOwnership {
	if d.cluster == nil {
		return rgOwnershipUnknown
	}
	// LocalGroupPrimary, NOT GroupState. This runs per inbound ARP frame on the
	// #8621 responder's socket, which any host on the segment can drive:
	// `GroupState` copies the whole group struct, allocates for MonitorFails and
	// ReadinessReasons, and calls `transferReadinessFn` outside the lock — a
	// per-frame allocation and callback on an attacker-drivable path, which is
	// the exact cost the responder's rgID snapshot was designed to avoid.
	primary, known := d.cluster.LocalGroupPrimary(rgID)
	if !known {
		return rgOwnershipUnknown
	}
	if primary {
		return rgOwnershipOwner
	}
	return rgOwnershipNotOwner
}

// proxyARPSuppressedForRG reports whether this node must NOT answer proxy-ARP
// for an address on an interface belonging to rgID.
//
// Suppress ONLY on an affirmative not-owner. Unknown answers — the #8342 fail
// direction, and the reason is unchanged: answering twice is a defect,
// answering zero times is a bigger one. rgID <= 0 (an interface in no
// redundancy group) answers because there is no ownership question to ask.
//
// #8640 changed only WHICH SOURCE is asked first, not what to do when nothing
// knows. The cluster election state is consulted ahead of the VRRP-event cache
// because it is discriminating where the cache is silent; the cache remains the
// fallback so a node whose cluster manager cannot answer behaves exactly as it
// did before this change. Suppressing on `Unknown` was considered and refused:
// it asks "do we KNOW who owns this?" and answers "no" permanently wherever the
// cache is empty, silencing every node — reinstating the very outage #8621
// fixed. The cluster predicate asks a different question, "do we HOLD this
// address?", whose wrong answer is bounded by the same condition that governs
// whether the address is on this node at all.
func (d *Daemon) proxyARPSuppressedForRG(rgID int) bool {
	if rgID <= 0 {
		return false
	}
	switch d.clusterRGOwnership(rgID) {
	case rgOwnershipOwner:
		return false
	case rgOwnershipNotOwner:
		return true
	}
	// The cluster manager cannot answer. Fall back to the VRRP-derived signal,
	// preserving pre-#8640 behaviour exactly.
	return d.rgOwnershipFor(rgID) == rgOwnershipNotOwner
}

// proxyARPRedundancyGroupFor resolves the redundancy group of the interface a
// `proxy-arp` entry names, or 0 when it belongs to none.
//
// The entry names a Junos ref such as `reth0.80`; the redundancy group lives on
// the RETH owner, reached through config.Config.InterfaceRefRG (#17086 SSOT):
// unit split, RedundantParent chain, RethRGOwners membership. A ref that
// resolves to no RETH owner returns 0 — answer — for the same reason the
// unknown ownership state does.
func proxyARPRedundancyGroupFor(cfg *config.Config, ifaceRef string) int {
	if cfg == nil {
		return 0
	}
	return cfg.RefRG(ifaceRef)
}

// proxyARPEntrySuppressed is the wiring the #8297 fix turns on: it is what
// makes the standby stop answering. Kept as one named predicate so the gate is
// bindable by a test rather than living inline in the reconcile loop.
func (d *Daemon) proxyARPEntrySuppressed(cfg *config.Config, ifaceRef string) bool {
	return d.proxyARPSuppressedForRG(proxyARPRedundancyGroupFor(cfg, ifaceRef))
}
