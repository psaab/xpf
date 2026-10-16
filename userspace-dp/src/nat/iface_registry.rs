//! #6751 PR 2/3: the interface-mode source-NAT translated-identity registry.
//!
//! Interface SNAT rewrites the source ADDRESS to the egress interface's own
//! address and — before this module — PRESERVED the source port
//! unconditionally, minting no allocation, no reservation and no occupancy
//! token of any kind. Two internal hosts that picked the same source port to
//! the same server therefore produced ONE external five-tuple, and the reply
//! `(S:80 -> E:5555)` carries no field that can tell them apart. The 1:N
//! reverse index keeps both forward handles and `reply_matches_forward_session`
//! validates BOTH, so every reply for the ambiguous tuple was un-NAT'd to
//! whichever session was installed first: H2's return traffic delivered to H1.
//!
//! The remedy is the one the pool-mode address-only path already ships
//! (#5269/#5336/#5341/#6041/#6226): an identity-keyed occupancy token on the
//! FULL reverse identity `(protocol, translated ip, translated port, remote ip,
//! remote port)`, minted at admission, released by the existing teardown path.
//! What interface mode adds on top is the PAT fallback: pool mode denies a
//! colliding address-only flow as exhaustion because it cannot move the port,
//! while interface mode CAN move it — so the LATER collider is PAT'd onto a
//! free port instead of being dropped. Preserve-first keeps the wire
//! byte-identical for every non-colliding flow, which is the intentional xpf
//! semantic (Junos allocates unconditionally; see the issue's Junos-parity
//! note).
//!
//! # Why a registry rather than a rule-carried allocator
//!
//! Interface mode has NO pool: `rewrite_src` is the egress interface's own
//! address, and the reverse-lookup namespace it lands in is global BY ADDRESS
//! (`session/key.rs` keys on the wire tuple; nothing carries ingress interface,
//! zone or VRF onto the reverse path — #2387, since CLOSED; #9062 added the
//! routing domain to the FORWARD flow and allocator keys, and the reverse path
//! is still address-keyed). Two different
//! interface-mode rules that egress the same interface therefore share one
//! identity space, and a per-rule allocator would let each mint the same
//! identity. The registry keys ONE `PortAllocator` per egress ADDRESS, which is
//! exactly the granularity of the ambiguity being removed.
//!
//! # Lifetime
//!
//! Node-lifetime. The registry is held as an `Arc` on `ForwardingState` and
//! CARRIED OVER on every apply (`build_forwarding_state_*` passes
//! `Some(&self.forwarding)`), the same way `parse_source_nat_rules_with_previous`
//! carries pool allocators and `Nat64State::from_snapshots_with_previous`
//! carries NAT64 allocators. Rebuilding it on commit would drop the occupancy of
//! every live session and let a fresh flow preserve an identity that is still on
//! the wire — the exact defect this closes.

use super::allocator::PortAllocator;
use rustc_hash::{FxHashMap, FxHashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

/// PAT candidate range for a colliding interface-mode flow. Deliberately the
/// ephemeral range and NOT the full 0-65535: a well-known source port below
/// 1024 is meaningful to some peers, and a translation that moves a flow ONTO
/// one would be worse than the collision. A flow whose own source port is below
/// 1024 still PRESERVES it when free — only the later collider is moved, and it
/// is moved into the ephemeral range.
pub(crate) const IFACE_PAT_PORT_LOW: u16 = 1024;
pub(crate) const IFACE_PAT_PORT_HIGH: u16 = 65535;

/// IKE/NAT-T ports that interface-NAT must not mint on the firewall's own
/// egress address. The value is shared with the IPsec classifier/admission.
pub(crate) const IFACE_RESERVED_UDP_PORTS: [u16; 2] = crate::ip_proto::IKE_UDP_PORTS;

/// Whether a translated source port aliases the firewall's fixed-port
/// IKE/NAT-T reverse identity for this remote destination.
#[inline]
pub(crate) fn conflicts_with_local_control_tuple(
    protocol: u8,
    translated_src_port: u16,
    dst_port: u16,
) -> bool {
    protocol == crate::ip_proto::PROTO_UDP
        && translated_src_port == dst_port
        && IFACE_RESERVED_UDP_PORTS.contains(&translated_src_port)
}

/// Retained-allocator cap. This bounds RETAINED cardinality, not
/// ever-created: an allocator whose live set has drained is reclaimable, so a
/// node that cycles egress addresses does not accumulate. Hitting the cap with
/// nothing reclaimable fails the admission CLOSED (counted separately from
/// identity exhaustion, see `registry_cap_exhaustion_total`) — it never evicts
/// a live allocator, because eviction is indistinguishable from the bug: the
/// evicted occupancy is exactly what stops a new flow from preserving a live
/// identity.
const MAX_RETAINED_INTERFACE_ALLOCATORS: usize = 256;

/// #6751 §5.8: identity-mint conflicts that took the PAT probe — i.e. how often
/// the ambiguous-tuple shape this fix exists for actually occurs. Cumulative,
/// process-global, exactly like `NAT_REVERSE_KEY_SHARED_DISPLACEMENTS`
/// (`afxdp/shared_ops.rs`), so tests read it as a delta. Surfaced as
/// `xpf_userspace_interface_snat_pat_collisions_total`.
pub(crate) static INTERFACE_SNAT_PAT_COLLISIONS: AtomicU64 = AtomicU64::new(0);

/// #6751 §5.8: interface-mode admissions that failed CLOSED because no
/// translated identity was available — a completed full-cycle PAT probe
/// (every port in 1024-65535 taken for this `(egress, remote)` identity) or a
/// port-less protocol whose single identity is already owned. Surfaced as
/// `xpf_userspace_interface_snat_identity_exhaustion_total`.
pub(crate) static INTERFACE_SNAT_IDENTITY_EXHAUSTION: AtomicU64 = AtomicU64::new(0);

/// #6751 §5.8: peer-synced interface-SNAT imports DROPPED because a DIFFERENT
/// live flow on this node already owns the translated identity the active
/// assigned. Fail-closed is the safer posture — the standby never holds a
/// session it cannot own — but it is an HA-FIDELITY loss, not a data-path
/// drop, so it gets its own series rather than inflating the admission
/// counter above. A non-zero value means individual synced flows will not
/// survive a failover. Surfaced as
/// `xpf_userspace_interface_snat_sync_identity_conflict_drops_total`.
pub(crate) static INTERFACE_SNAT_SYNC_IDENTITY_CONFLICT_DROPS: AtomicU64 = AtomicU64::new(0);

/// #6751 §5.8: interface-mode admissions that failed CLOSED because no more
/// REGISTRY state could be created — the retained-allocator cap above with
/// nothing reclaimable, or the per-address tracked-flow cap
/// (`PortAllocator::max_tracked_flows`, 64512 for a 1024-65535 range). Kept
/// DISTINCT from identity exhaustion: the two have different remedies (raise
/// capacity vs. the identity space for one remote is genuinely full). Surfaced
/// as `xpf_userspace_interface_snat_registry_cap_exhaustion_total`.
pub(crate) static INTERFACE_SNAT_REGISTRY_CAP_EXHAUSTION: AtomicU64 = AtomicU64::new(0);

/// Node-lifetime interface-mode SNAT identity registry: one `PortAllocator` per
/// egress ADDRESS.
///
/// The allocator instances are used for their ADDRESS-ONLY occupancy machinery
/// (`address_only_owners`, keyed on the full reverse identity) and their
/// `live_by_flow` ownership records — NOT for the per-address port bitmap,
/// which stays empty because interface mode never claims a pool port. That is
/// what makes "same source port to two DIFFERENT servers" both preserve: the
/// occupancy key carries the remote endpoint, so those are two distinct
/// identities.
#[derive(Debug, Default)]
pub(crate) struct InterfaceNatAllocators {
    map: RwLock<FxHashMap<IpAddr, Arc<PortAllocator>>>,
}

impl InterfaceNatAllocators {
    /// #6979: clear `worker_id`'s holder bit across every interface-mode
    /// allocator, freeing any record the clear empties. Returns records freed.
    ///
    /// The per-allocator primitive (`PortAllocator::retire_worker`, #7092)
    /// landed sound but UNWIRED — its own doc says so — because choosing the
    /// call site was left as a separate decision. This is the interface-mode
    /// half of that wiring; the pool-mode and NAT64 halves are the sibling
    /// sweeps in `nat::retire_worker_from_pool_rules` and
    /// `Nat64State::retire_worker`.
    ///
    /// Read lock, not write: retirement mutates each allocator's OWN state
    /// through its interior mutex and never touches this map's shape, so it
    /// must not serialise against the new-flow admission path that
    /// `allocator_for`'s read fast path exists to keep clear.
    pub(crate) fn retire_worker(&self, worker_id: u32, now_ns: u64) -> usize {
        let map = self.map.read().unwrap_or_else(|e| e.into_inner());
        map.values()
            .map(|alloc| alloc.retire_worker(worker_id, now_ns))
            .sum()
    }

    /// Resolve (creating on first use) the allocator that owns `egress`'s
    /// identity space.
    ///
    /// READ-LOCK FAST PATH. This runs once per NEW interface-mode flow on every
    /// worker, and in the steady state the allocator already exists — taking the
    /// write lock there would serialise admission across all workers on one
    /// exclusive lock, which is exactly the new-flow contention site #4800
    /// exists to keep clear. The write lock is taken only to CREATE, which
    /// happens once per egress address for the node's lifetime.
    ///
    /// Creation re-checks under the write lock, so two workers racing a first
    /// packet for the same address still both get the STORED winner rather than
    /// two allocators splitting one identity space.
    ///
    /// FALLIBLE. `None` means the retained-allocator cap is reached and nothing
    /// was reclaimable, and the caller must fail the admission closed.
    pub(crate) fn allocator_for(&self, egress: IpAddr) -> Option<Arc<PortAllocator>> {
        {
            let map = self.map.read().unwrap_or_else(|e| e.into_inner());
            if let Some(existing) = map.get(&egress) {
                return Some(Arc::clone(existing));
            }
        }
        let mut map = self.map.write().unwrap_or_else(|e| e.into_inner());
        // Re-check: another worker may have created it in the gap between the
        // two acquisitions. Returning the stored value is what makes the
        // registry single-winner despite the lock upgrade not being atomic.
        if let Some(existing) = map.get(&egress) {
            return Some(Arc::clone(existing));
        }
        if map.len() >= MAX_RETAINED_INTERFACE_ALLOCATORS {
            // Opportunistic reclaim: an allocator with no live records holds no
            // occupancy anyone depends on, so dropping it is free. Only if that
            // frees nothing do we fail closed.
            map.retain(|_, alloc| alloc.live_flow_count() > 0);
            if map.len() >= MAX_RETAINED_INTERFACE_ALLOCATORS {
                INTERFACE_SNAT_REGISTRY_CAP_EXHAUSTION.fetch_add(1, Ordering::Relaxed);
                return None;
            }
        }
        let alloc = Arc::new(PortAllocator::new(
            1,
            IFACE_PAT_PORT_LOW,
            IFACE_PAT_PORT_HIGH,
        ));
        map.insert(egress, Arc::clone(&alloc));
        Some(alloc)
    }

    /// LOOKUP-ONLY resolution for the RELEASE path. Never creates: a release
    /// for an address that owns no allocator has nothing to free, and creating
    /// one there would let a teardown storm push the registry to its cap with
    /// empty allocators.
    pub(crate) fn allocator_if_present(&self, egress: IpAddr) -> Option<Arc<PortAllocator>> {
        let map = self.map.read().unwrap_or_else(|e| e.into_inner());
        map.get(&egress).map(Arc::clone)
    }

    /// Apply-time reclamation: drop the allocator for every address that is no
    /// longer an egress address AND holds no live records.
    ///
    /// Both conditions are required. "Absent from the egress set" alone is not
    /// enough — an address can leave the set while sessions minted on it are
    /// still forwarding, and their releases must still reach the allocator that
    /// holds their records or the identity leaks. "Empty" alone is not enough
    /// either, or a busy address would be dropped in the gap between two flows.
    pub(crate) fn reclaim_absent(&self, live_egress: &FxHashSet<IpAddr>) {
        let mut map = self.map.write().unwrap_or_else(|e| e.into_inner());
        map.retain(|addr, alloc| live_egress.contains(addr) || alloc.live_flow_count() > 0);
    }

    /// Retained allocator count. Test/diagnostic seam.
    #[cfg(test)]
    pub(crate) fn retained_len(&self) -> usize {
        self.map.read().unwrap_or_else(|e| e.into_inner()).len()
    }
}
