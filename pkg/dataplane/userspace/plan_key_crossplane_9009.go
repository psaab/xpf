package userspace

import "github.com/psaab/xpf/pkg/config"

// The Go and Rust binding-plan keys are two independently transcribed answers
// to one question — "did the AF_XDP binding plan change?" — and #9009 ran the
// diff #8901 left unrun. Six divergences; the helpers below close the four the
// issue names as acceptance, plus the fabric rx_queues resolution.
//
// WHAT "AGREE" MEANS HERE, because it is not what it first looks like. The two
// keys are never compared to each other: each side compares ITS OWN key across
// consecutive snapshots. So they do not need to be byte-identical, and making
// them so is not the goal. They need to MOVE TOGETHER — a change that moves one
// must move the other. That is why Go keeps hashing LogicalOnly (D5) even
// though Rust has no such field: the flip cannot occur alone, so the extra
// field never moves Go's key by itself.
//
// RUST IS AUTHORITATIVE for every divergence closed here, and not by default.
// Its filters and its rx_queues resolution mirror `replan_queues`, the function
// that actually builds the layout; the #2915 invariant is that the key must
// move whenever the layout would. Go's key gates the same-plan refresh
// EXCEPTION, so a Go key that fails to move where the layout does is the
// dangerous direction: Go publishes a "same plan" refresh straight through the
// pending-XSK-startup window while the helper rebuilds its bindings.
//
// The over-detect direction is not merely wasteful either. `!samePlan` reaches
// `stopForNewGenerationLocked` -> `stopLocked` + `ensureProcessLocked`, a full
// AF_XDP teardown and rebind, and during the XSK-startup window it also means
// the snapshot is not published at all. A forwarding interruption, not CPU.

// planKeyResolvedLinuxName mirrors Rust's `linux_name.is_empty()` fallback:
// a row with no explicit netdev binds the name derived from its Junos name.
func planKeyResolvedLinuxName(iface InterfaceSnapshot) string {
	if iface.LinuxName != "" {
		return iface.LinuxName
	}
	return config.LinuxIfName(iface.Name)
}

// planKeyVLANChildParent mirrors Rust's `vlan_child_parent_netdev`: the parent
// netdev a VLAN child actually binds through, or "" when the row binds its own
// netdev. The `!= resolvedLinux` arm is what stops a row whose parent name
// happens to equal its own from being treated as a child of itself.
func planKeyVLANChildParent(iface InterfaceSnapshot, resolvedLinux string) string {
	if iface.VLANID != 0 && iface.ParentLinuxName != "" && iface.ParentLinuxName != resolvedLinux {
		return iface.ParentLinuxName
	}
	return ""
}

// planKeyIncludesInterface is Go's `include_userspace_binding_interface`. It is
// the pair the ingress loops already use, kept in one place so the plan key and
// the alias builder cannot drift: zone-empty, plus the DEVICE half (unbindable)
// and the ROW half (local-fabric member) that userspaceSkipsIngressInterface
// owns. Zone names (`mgmt`/`control`) deliberately do not filter data NICs
// (#10308).
func planKeyIncludesInterface(iface InterfaceSnapshot) bool {
	return iface.Zone != "" && !userspaceSkipsIngressInterface(iface)
}

// planKeySnapshotHasParentCandidate mirrors Rust's
// `snapshot_has_parent_candidate`: is there a row that binds the PHYSICAL
// netdev `parent` itself? The second clause is load-bearing — another VLAN
// child sharing the name string is not a parent candidate.
func planKeySnapshotHasParentCandidate(snap *ConfigSnapshot, parent string) bool {
	for _, p := range snap.Interfaces {
		if !planKeyIncludesInterface(p) {
			continue
		}
		pl := planKeyResolvedLinuxName(p)
		if pl == parent && planKeyVLANChildParent(p, pl) == "" {
			return true
		}
	}
	return false
}

// planKeyEffectiveRXQueues is Rust's `effective_rx_queues` (#3007): hash the
// count the planner will actually use. A snapshot carrying the degenerate 0
// resolves from sysfs, so an out-of-band `ethtool -L <if> combined N` — no
// config commit — moves the key instead of leaving it identical while the
// layout changes underneath.
func planKeyEffectiveRXQueues(snapshotRXQueues int, linuxName string) int {
	if snapshotRXQueues > 0 {
		return snapshotRXQueues
	}
	return userspaceRXQueueCount(linuxName)
}

// planKeyRXQueues is Rust's `plan_key_rx_queues` (#9009 D1).
//
// For an ORPHAN VLAN child — a child whose parent is NOT itself a binding
// candidate — the layout re-keys onto the PARENT's hardware queue count
// (#3175), so the key must hash that same number. Go hashed the child's own
// count, which is a different number responding to a different stimulus: the
// two sides were not sampling one value twice, they were tracking two values.
// That is why the #8901 guard's "not a config commit, and this key is about
// config snapshots" dismissal does not cover the orphan case — the divergence
// persists across commits rather than being one number sampled at two instants.
//
// The orphan shape is SHIPPED, not hypothetical: the unzoned-parent fixture
// in TestOrphanVLANChildHashesTheParentsQueueCount9009 has no candidate for
// the parent (`mgmt`/`control` zone names no longer exclude rows since #10308).
func planKeyRXQueues(snap *ConfigSnapshot, iface InterfaceSnapshot, resolvedLinux string) int {
	if parent := planKeyVLANChildParent(iface, resolvedLinux); parent != "" {
		if !planKeySnapshotHasParentCandidate(snap, parent) {
			return userspaceRXQueueCount(parent)
		}
	}
	return planKeyEffectiveRXQueues(iface.RXQueues, resolvedLinux)
}

// planKeyBindingTargetRefused is Rust's `binding_target_is_refused` (#9009 D3):
// a row whose BIND TARGET the snapshot refuses produces no candidate in
// `replan_queues`, so it must not be hashed. Only a VLAN child has a bind
// target distinct from itself; a non-VLAN row binds its own netdev, which its
// own row already passed planKeyIncludesInterface for.
//
// The refusal tally is Go's own `buildUserspaceRefusedNetdevs`
// (snapshotNetdevVotes), which Rust's `snapshot_refuses_parent_netdev`
// documents itself as mirroring — so this reuses the shared predicate rather
// than adding a third spelling of "is this netdev refused?".
func planKeyBindingTargetRefused(refused userspaceRefusedNetdevs, iface InterfaceSnapshot, resolvedLinux string) bool {
	parent := planKeyVLANChildParent(iface, resolvedLinux)
	if parent == "" {
		return false
	}
	return refused.refusesNetdev(parent, iface.ParentIfindex)
}
