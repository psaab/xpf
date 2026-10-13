use super::*;
use std::collections::{HashMap, HashSet};
use crate::session::{BareSessionTuple, PMechWaiterRef, SessionScope};
use rustc_hash::FxSeededState;
use std::sync::atomic::{AtomicU64, Ordering};

// #1035 P4: shared CoS lease + V_min coordination types split into a
// sibling submodule. Re-exported at pub(super) so the rest of afxdp/
// continues to find them as `super::types::SharedCoS*`.
mod shared_cos_lease;
pub(super) use shared_cos_lease::{
    AcquireV8ShortfallCause, ExactDemandQueueMask, NOT_PARTICIPATING, PaddedVtimeSlot,
    SharedCoSExactBacklog, SharedCoSQueueLease, SharedCoSQueueVtimeFloor, SharedCoSRootLease,
    V8RateMode,
};

// Issue 68.1: CoS shaper / queue / flow-fair / runtime types extracted
// into types/cos.rs. Re-exported here so call sites that reach
// `crate::afxdp::types::*` resolve unchanged.
mod cos;
pub(in crate::afxdp) use cos::*;

// Issue 68.2: routing/forwarding types extracted into types/forwarding.rs.
mod forwarding;
pub(in crate::afxdp) use forwarding::*;
// Three forwarding types had wider-than-pub(super) visibility in the original
// types/mod.rs and are re-exported at their original surface so afxdp.rs's
// `pub(crate) use self::types::{...};` and external pub callers continue to
// resolve them.
pub use forwarding::NeighborEntry;
pub(crate) use forwarding::{ForwardingDisposition, ForwardingResolution};

// Issue 68.3: TX-request types extracted into types/tx.rs.
mod tx;
pub(in crate::afxdp) use tx::*;

// Issue 68.4: worker / runtime types extracted into types/runtime.rs.
mod runtime;
pub(in crate::afxdp) use runtime::*;

// #6592: the atomically-paired worker-visible (validation, forwarding) view.
// Declared AFTER `runtime` and `forwarding` so it can name both halves.
mod runtime_view;
pub(in crate::afxdp) use runtime_view::*;

pub(super) type FastMap<K, V> = FxHashMap<K, V>;
pub(super) type FastSet<T> = FxHashSet<T>;
pub(super) type OwnerRgSessionIndex = FastMap<i32, FastSet<SessionKey>>;

/// Bounded history of reverse aliases. Domain-neutral owners let an unstamped
/// fabric reply reject a tuple that exists in multiple routing instances.
/// Once the bound is reached, every such exception fails closed.
pub(super) struct SharedNatAmbiguityIndex {
    aliases: FastMap<SessionKey, Option<SessionKey>>,
    saturated: bool,
}

impl Default for SharedNatAmbiguityIndex {
    fn default() -> Self {
        Self {
            aliases: FastMap::default(),
            saturated: false,
        }
    }
}

impl SharedNatAmbiguityIndex {
    const MAX_KEYS: usize = 16_384;

    fn remember(&mut self, key: SessionKey, owner: Option<SessionKey>) {
        if self.saturated {
            return;
        }
        if let Some(existing) = self.aliases.get(&key) {
            if existing != &owner {
                self.aliases.insert(key, None);
            }
            return;
        }
        if self.aliases.len() == Self::MAX_KEYS {
            self.saturated = true;
        } else {
            self.aliases.insert(key, owner);
        }
    }

    pub(super) fn mark(&mut self, key: SessionKey) {
        self.remember(key, None);
    }

    pub(super) fn observe(&mut self, key: SessionKey, owner: SessionKey) {
        self.remember(key, Some(owner));
    }

    pub(super) fn contains(&self, key: &SessionKey) -> bool {
        self.saturated || matches!(self.aliases.get(key), Some(None))
    }

    pub(super) fn is_unique_for(&self, key: &SessionKey, owner: &SessionKey) -> bool {
        !self.saturated
            && matches!(self.aliases.get(key), Some(Some(candidate)) if candidate == owner)
    }

    pub(super) fn unique_owner(&self, key: &SessionKey) -> Option<&SessionKey> {
        if self.saturated {
            return None;
        }
        self.aliases.get(key).and_then(Option::as_ref)
    }

    pub(super) fn clear(&mut self) {
        self.aliases.clear();
        self.saturated = false;
    }
}

enum SharedBareTupleScopes {
    One(SessionScope),
    Many(HashSet<SessionScope, FxSeededState>),
}

impl SharedBareTupleScopes {
    fn insert(&mut self, scope: SessionScope, state: &FxSeededState) {
        let replacement = match self {
            Self::One(existing) if *existing == scope => return,
            Self::One(existing) => {
                let mut scopes = HashSet::with_hasher(state.clone());
                scopes.insert(*existing);
                scopes.insert(scope);
                Some(Self::Many(scopes))
            }
            Self::Many(scopes) => {
                scopes.insert(scope);
                None
            }
        };
        if let Some(replacement) = replacement {
            *self = replacement;
        }
    }

    /// Remove a scope. Returns true when its tuple bucket becomes empty.
    fn remove(&mut self, scope: SessionScope) -> bool {
        let (empty, collapse_to) = match self {
            Self::One(existing) => return *existing == scope,
            Self::Many(scopes) => {
                if !scopes.remove(&scope) {
                    return false;
                }
                (
                    scopes.is_empty(),
                    (scopes.len() == 1).then(|| *scopes.iter().next().expect("one scope remains")),
                )
            }
        };
        if let Some(only) = collapse_to {
            *self = Self::One(only);
        }
        empty
    }

    fn has_other_scope(&self, scope: SessionScope) -> bool {
        match self {
            Self::One(existing) => *existing != scope,
            Self::Many(scopes) => {
                !scopes.is_empty() && (scopes.len() > 1 || !scopes.contains(&scope))
            }
        }
    }
}

pub(super) struct SharedSessionBareTupleIndex {
    scopes: HashMap<BareSessionTuple, SharedBareTupleScopes, FxSeededState>,
    state: FxSeededState,
}

impl Default for SharedSessionBareTupleIndex {
    fn default() -> Self {
        let state = FxSeededState::with_seed(
            crate::hot_hash_seed::hot_path_hash_seed() as usize,
        );
        Self {
            scopes: HashMap::with_hasher(state.clone()),
            state,
        }
    }
}

impl SharedSessionBareTupleIndex {
    pub(super) fn insert(&mut self, key: &SessionKey) {
        let bare_tuple = key.bare_tuple();
        let scope = key.scope();
        self.scopes
            .entry(bare_tuple)
            .and_modify(|scopes| scopes.insert(scope, &self.state))
            .or_insert(SharedBareTupleScopes::One(scope));
    }

    pub(super) fn remove(&mut self, key: &SessionKey) {
        let bare_tuple = key.bare_tuple();
        let scope = key.scope();
        let remove_tuple = self
            .scopes
            .get_mut(&bare_tuple)
            .is_some_and(|scopes| scopes.remove(scope));
        if remove_tuple {
            self.scopes.remove(&bare_tuple);
        }
    }

    pub(super) fn has_other_scope(&self, key: &SessionKey) -> bool {
        self.scopes
            .get(&key.bare_tuple())
            .is_some_and(|scopes| scopes.has_other_scope(key.scope()))
    }

    pub(super) fn clear(&mut self) {
        self.scopes.clear();
    }
}

#[derive(Clone)]
pub(super) struct SharedSessionOwnerRgIndexes {
    pub(super) sessions: Arc<Mutex<OwnerRgSessionIndex>>,
    pub(super) nat_sessions: Arc<Mutex<OwnerRgSessionIndex>>,
    pub(super) forward_wire_sessions: Arc<Mutex<OwnerRgSessionIndex>>,
    pub(super) reverse_prewarm_sessions: Arc<Mutex<OwnerRgSessionIndex>>,
    pub(super) nat_ambiguities: Arc<Mutex<SharedNatAmbiguityIndex>>,
    pub(super) bare_tuple_sessions: Arc<Mutex<SharedSessionBareTupleIndex>>,
}

impl Default for SharedSessionOwnerRgIndexes {
    fn default() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(FastMap::default())),
            nat_sessions: Arc::new(Mutex::new(FastMap::default())),
            forward_wire_sessions: Arc::new(Mutex::new(FastMap::default())),
            reverse_prewarm_sessions: Arc::new(Mutex::new(FastMap::default())),
            nat_ambiguities: Arc::new(Mutex::new(SharedNatAmbiguityIndex::default())),
            bare_tuple_sessions: Arc::new(Mutex::new(SharedSessionBareTupleIndex::default())),
        }
    }
}


impl SharedSessionOwnerRgIndexes {
    /// #6653: RECOVERING locks, for the same reason as the session maps this
    /// mirrors. `if let Ok(..)` skipped a poisoned index, so a teardown could
    /// empty the maps and leave an index populated (or the reverse) — the
    /// indexes exist to mirror the maps, and a poisoned one that survives
    /// teardown is precisely the divergence they cannot represent.
    pub(super) fn clear(
        &self,
        shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    ) {
        // Keep the primary map and bare-tuple index paired under the same
        // lock order used by publish, removal, and close validation.
        let mut sessions = crate::afxdp::shared_ops::lock_shared_recover(shared_sessions);
        let mut bare_tuple_sessions =
            crate::afxdp::shared_ops::lock_shared_recover(&self.bare_tuple_sessions);
        sessions.clear();
        bare_tuple_sessions.clear();
        drop(bare_tuple_sessions);
        drop(sessions);

        crate::afxdp::shared_ops::lock_shared_recover(&self.sessions).clear();
        crate::afxdp::shared_ops::lock_shared_recover(&self.nat_sessions).clear();
        crate::afxdp::shared_ops::lock_shared_recover(&self.forward_wire_sessions).clear();
        crate::afxdp::shared_ops::lock_shared_recover(&self.reverse_prewarm_sessions).clear();
        crate::afxdp::shared_ops::lock_shared_recover(&self.nat_ambiguities).clear();
    }
}

/// Packet buffered while waiting for ARP/NDP neighbor resolution.
pub(super) struct PendingNeighPacket {
    pub(super) addr: u64,
    pub(super) desc: XdpDesc,
    pub(super) meta: UserspaceDpMeta,
    pub(super) decision: SessionDecision,
    pub(super) flow_key: Option<SessionKey>,
    pub(super) queued_ns: u64,
    /// Cold-start probe schedule attempts (GEMINI-NEXT.md Section 3).
    /// 0 means no retries fired yet beyond the initial probe; each
    /// retry from `retry_pending_neigh` increments this. Capped by
    /// `PROBE_SCHEDULE_NS.len()`.
    pub(super) probe_attempts: u8,
    /// #10917: the validated fabric zone stamp is needed by the retry-time
    /// fragment-overlap key, which must use the same routing domain as inline
    /// fabric-ingress siblings.
    pub(super) fabric_ingress_zone: Option<u16>,
}

/// Reverse packet held by its arrival binding until the owning IPsec install
/// becomes Live. The XDP descriptor remains in this worker's UMEM.
pub(super) struct PendingPMechReversePacket {
    pub(super) desc: XdpDesc,
    pub(super) meta: UserspaceDpMeta,
    pub(super) waiter: PMechWaiterRef,
    pub(super) token: u64,
    pub(super) owner_generation: u64,
    pub(super) is_injected: bool,
}

// Compile-time size guard: pending-neighbor retry carries the session key so
// runtime TX-selection policers still meter packets after ARP/NDP resolution.
//
// 296 -> 304 (#11411). ForwardingResolution now carries selected-route and
// tunnel-transport MTU constraints; PendingNeighPacket embeds the decision.
// At the 4096-hop cap that adds ~32 KB, preserving both budgets during neighbor
// resolution.
// 288 -> 296 (#11064). `SessionDecision` gained the typed source-NAT ICMP
// fingerprint; this struct embeds one, and alignment rounds the 4-byte
// decision growth to 8 bytes. At the `MAX_PENDING_NEIGH` cap of ~4096, that is
// ~32 KB more for the bounded queue. The metadata must stay with the decision:
// retries retain the translated mapping's protocol application identity.
//
// 280 -> 288 (#9752). `SessionDecision` gained the installing-table identity
// (`install_table_domain` + `install_table_check`), and this struct embeds
// one, so it grew by 8 bytes (~32 KB more at the `MAX_PENDING_NEIGH` cap of
// ~4096). Accepted deliberately on the same reasoning as the growths below:
// this queue carries the decision so a retried packet re-resolves in its
// installing table, and a decision that could not name it would re-resolve a
// retried PBR packet in the default table — the #9752 defect for retried flows.
//
// 272 -> 280 (#7160/#2387). `SessionKey` gained the `routing_domain` u32 that
// makes two tenants' identical 5-tuples distinct sessions, and this struct
// embeds one; with alignment that is 8 more bytes, ~32 KB more at the
// `MAX_PENDING_NEIGH` cap. Accepted on the same reasoning as the #7188 growth
// below: the queue carries the key so post-resolution policing meters the right
// session, and a key that could not tell two routing instances apart would
// meter a retried packet against the WRONG TENANT's session.
//
// 264 -> 272 (#7188). `SessionKey` gained the `TunnelDiscriminator` field, and
// this struct embeds one, so it grew by the enum's 8 bytes (4-byte discriminant
// + 4-byte RFC 2890 key payload, aligned). At the `MAX_PENDING_NEIGH` cap of
// ~4096 that is ~32 KB more for the bounded queue — accepted deliberately
// rather than bumped silently, because the discriminator is part of session
// IDENTITY and this queue carries the key precisely so post-resolution policing
// meters the right tunnel's session. Dropping it here to save the bytes would
// mean a retried packet metered against a DIFFERENT tunnel's session than the
// one it belongs to.
// #10917: the fabric stamp uses the existing tail padding, so added no size.
const _: () = assert!(
    core::mem::size_of::<PendingNeighPacket>() == 304,
    "PendingNeighPacket size changed — update afxdp.rs MAX_PENDING_NEIGH commentary",
);

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct UserspaceDpMeta {
    pub(super) magic: u32,
    pub(super) version: u16,
    pub(super) length: u16,
    pub(super) ingress_ifindex: u32,
    pub(super) rx_queue_index: u32,
    pub(super) ingress_vlan_id: u16,
    pub(super) ingress_pcp: u8,
    pub(super) ingress_vlan_present: u8,
    pub(super) ingress_zone: u16,
    pub(super) routing_table: u32,
    pub(super) l3_offset: u16,
    pub(super) l4_offset: u16,
    pub(super) payload_offset: u16,
    /// THE LENGTH OF THE BUFFER THIS META DESCRIBES, measured from offset 0 —
    /// not the L3 packet length (#8581).
    ///
    /// Every offset field above is relative to the same origin, and `pkt_len`
    /// is the extent of that same buffer, so the L3 length is uniformly
    /// `pkt_len - l3_offset` at EVERY construction site. That uniformity is the
    /// property, and it is what makes the bytes counted for a packet
    /// independent of which path presented it:
    ///
    ///   * `userspace-xdp/src/lib.rs` — an Ethernet frame, `l3_offset` 14/18,
    ///     `pkt_len = data_end - data`;
    ///   * `coordinator/inject.rs` (frame arm) — an Ethernet frame,
    ///     `l3_offset` 14/18, `pkt_len = frame_len`;
    ///   * `coordinator/inject.rs` (raw arm) — a bare IP packet, `l3_offset` 0,
    ///     `pkt_len = packet_length`;
    ///   * `tunnel.rs::local_origin_packet_meta` — a bare IP packet,
    ///     `l3_offset` 0, `pkt_len = packet.len()`;
    ///   * `logical_ingress.rs` — a SYNTHETIC 14-byte Ethernet header plus the
    ///     decapsulated inner packet, `l3_offset` 14, `pkt_len = 14 + inner`.
    ///
    /// The last one carried the INNER length until #8581, which made the same
    /// L3 packet count 14 bytes fewer in every filter, policy, policer, session
    /// and zone byte counter when it arrived decapsulated than when it arrived
    /// native — a difference an operator comparing those totals cannot see and
    /// would not suspect. `trim_l3_payload` tolerated both spellings (its
    /// metadata FALLBACK tries `pkt_len` as an L3 length before trying it as a
    /// frame length, and the two arms self-select on the `l3_offset` a site
    /// carries), which is why nothing was red.
    ///
    /// A NEW construction site owes this invariant. A `pkt_len` that is not the
    /// buffer's length makes `pkt_len - l3_offset` mean something different
    /// depending on who built the meta, and no consumer can tell which it has.
    pub(super) pkt_len: u16,
    pub(super) addr_family: u8,
    pub(super) protocol: u8,
    pub(super) tcp_flags: u8,
    pub(super) meta_flags: u8,
    pub(super) dscp: u8,
    pub(super) dscp_rewrite: u8,
    pub(super) reserved: u16,
    pub(super) flow_src_port: u16,
    pub(super) flow_dst_port: u16,
    pub(super) flow_src_addr: [u8; 16],
    pub(super) flow_dst_addr: [u8; 16],
    pub(super) config_generation: u64,
    pub(super) fib_generation: u32,
    pub(super) reserved2: u32,
}

const _: [(); 96] = [(); std::mem::size_of::<UserspaceDpMeta>()];
const _: [(); 18] = [(); std::mem::offset_of!(UserspaceDpMeta, ingress_pcp)];
const _: [(); 19] = [(); std::mem::offset_of!(UserspaceDpMeta, ingress_vlan_present)];
const _: [(); 20] = [(); std::mem::offset_of!(UserspaceDpMeta, ingress_zone)];
const _: [(); 24] = [(); std::mem::offset_of!(UserspaceDpMeta, routing_table)];
const _: [(); 36] = [(); std::mem::offset_of!(UserspaceDpMeta, addr_family)];
const _: [(); 40] = [(); std::mem::offset_of!(UserspaceDpMeta, dscp)];
const _: [(); 80] = [(); std::mem::offset_of!(UserspaceDpMeta, config_generation)];

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct ForwardPacketMeta {
    pub(super) ingress_ifindex: u32,
    pub(super) ingress_vlan_id: u16,
    pub(super) ingress_pcp: u8,
    pub(super) ingress_vlan_present: u8,
    pub(super) l3_offset: u16,
    pub(super) l4_offset: u16,
    pub(super) payload_offset: u16,
    /// Buffer length from offset 0, carried through unchanged from
    /// `UserspaceDpMeta::pkt_len` — see that field for the invariant (#8581).
    pub(super) pkt_len: u16,
    pub(super) addr_family: u8,
    pub(super) protocol: u8,
    pub(super) tcp_flags: u8,
    pub(super) meta_flags: u8,
    pub(super) dscp: u8,
    pub(super) flow_src_port: u16,
    pub(super) flow_dst_port: u16,
    // #5467: shim-stamped L3 addresses from the wire, carried for the flowless
    // output-filter evaluator. Zeroed synthetic/test metadata represents the
    // parsed unspecified address; `l3_addrs()` preserves it as `0.0.0.0`/`::`.
    // Transit source martians are separately rejected by #10689 after route
    // resolution, before the ordinary egress path.
    pub(super) flow_src_addr: [u8; 16],
    pub(super) flow_dst_addr: [u8; 16],
}

impl ForwardPacketMeta {
    /// Address-level L3 tuple used by `l3_enforcement_flow_from_meta`.
    ///
    /// Preserves parsed unspecified addresses so enforcement can distinguish
    /// them from an unparseable family. Returns `None` only when the family is
    /// not IPv4 or IPv6; does not touch the witness counter (#7890).
    pub(in crate::afxdp) fn l3_addrs_unfiltered(&self) -> Option<(IpAddr, IpAddr)> {
        match self.addr_family as i32 {
            libc::AF_INET => {
                let src = self.flow_src_addr.get(..4)?;
                let dst = self.flow_dst_addr.get(..4)?;
                Some((
                    IpAddr::V4(Ipv4Addr::new(src[0], src[1], src[2], src[3])),
                    IpAddr::V4(Ipv4Addr::new(dst[0], dst[1], dst[2], dst[3])),
                ))
            }
            libc::AF_INET6 => Some((
                IpAddr::V6(Ipv6Addr::from(self.flow_src_addr)),
                IpAddr::V6(Ipv6Addr::from(self.flow_dst_addr)),
            )),
            _ => None,
        }
    }

    /// #5467: addresses supplied to the flowless output-filter evaluator.
    /// Preserves unspecified values and increments the witness counter when
    /// either address is unspecified. Transit source disposition is handled
    /// separately by #10689's post-FIB gate.
    pub(super) fn l3_addrs(&self) -> Option<(IpAddr, IpAddr)> {
        let (src_ip, dst_ip) = match self.addr_family as i32 {
            libc::AF_INET => {
                let src = self.flow_src_addr.get(..4)?;
                let dst = self.flow_dst_addr.get(..4)?;
                (
                    IpAddr::V4(Ipv4Addr::new(src[0], src[1], src[2], src[3])),
                    IpAddr::V4(Ipv4Addr::new(dst[0], dst[1], dst[2], dst[3])),
                )
            }
            libc::AF_INET6 => (
                IpAddr::V6(Ipv6Addr::from(self.flow_src_addr)),
                IpAddr::V6(Ipv6Addr::from(self.flow_dst_addr)),
            ),
            _ => return None,
        };
        if src_ip.is_unspecified() || dst_ip.is_unspecified() {
            // #7890: SEEN, not refused. Keep the parsed address distinct from a
            // refused session identity; `l3_addrs()` is an address accessor.
            // #10689 separately rejects martian source addresses on transit
            // before the normal egress output-filter path.
            //
            // The counter remains a witness for tests that prove this reachable
            // address-value arm was entered.
            crate::afxdp::frame::L3_CTX_NONE_UNSPECIFIED_ADDR
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        Some((src_ip, dst_ip))
    }
}

impl From<UserspaceDpMeta> for ForwardPacketMeta {
    fn from(meta: UserspaceDpMeta) -> Self {
        Self {
            ingress_ifindex: meta.ingress_ifindex,
            ingress_vlan_id: meta.ingress_vlan_id,
            ingress_pcp: meta.ingress_pcp,
            ingress_vlan_present: meta.ingress_vlan_present,
            l3_offset: meta.l3_offset,
            l4_offset: meta.l4_offset,
            payload_offset: meta.payload_offset,
            pkt_len: meta.pkt_len,
            addr_family: meta.addr_family,
            protocol: meta.protocol,
            tcp_flags: meta.tcp_flags,
            meta_flags: meta.meta_flags,
            dscp: meta.dscp,
            flow_src_port: meta.flow_src_port,
            flow_dst_port: meta.flow_dst_port,
            flow_src_addr: meta.flow_src_addr,
            flow_dst_addr: meta.flow_dst_addr,
        }
    }
}

impl From<ForwardPacketMeta> for UserspaceDpMeta {
    fn from(meta: ForwardPacketMeta) -> Self {
        Self {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            ingress_ifindex: meta.ingress_ifindex,
            rx_queue_index: 0,
            ingress_vlan_id: meta.ingress_vlan_id,
            ingress_pcp: meta.ingress_pcp,
            ingress_vlan_present: meta.ingress_vlan_present,
            ingress_zone: 0,
            routing_table: 0,
            l3_offset: meta.l3_offset,
            l4_offset: meta.l4_offset,
            payload_offset: meta.payload_offset,
            pkt_len: meta.pkt_len,
            addr_family: meta.addr_family,
            protocol: meta.protocol,
            tcp_flags: meta.tcp_flags,
            meta_flags: meta.meta_flags,
            dscp: meta.dscp,
            dscp_rewrite: 0,
            reserved: 0,
            flow_src_port: meta.flow_src_port,
            flow_dst_port: meta.flow_dst_port,
            flow_src_addr: meta.flow_src_addr,
            flow_dst_addr: meta.flow_dst_addr,
            config_generation: 0,
            fib_generation: 0,
            reserved2: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PacketDisposition {
    Valid,
    NoSnapshot,
    ConfigGenerationMismatch,
    FibGenerationMismatch,
    UnsupportedPacket,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SessionFlow {
    pub(super) src_ip: IpAddr,
    pub(super) dst_ip: IpAddr,
    pub(super) forward_key: SessionKey,
}

impl SessionFlow {
    /// Rebuild the flow against a POST-translation destination.
    ///
    /// #9034: this used to take the address alone and carry
    /// `forward_key.dst_port` over unchanged, so a composed DNAT -> source-NAT
    /// matched the source-NAT rule against a HALF-TRANSLATED destination — the
    /// post-DNAT address with the PRE-DNAT port. A `destination-nat` that moved
    /// the port (443 -> 8443, the ordinary VIP shape) therefore matched a
    /// source-NAT rule written against the real service port, or missed one
    /// written against the translated port.
    ///
    /// The port is a REQUIRED parameter rather than an `Option` or a second
    /// method: the whole defect was that a caller could forget it and still
    /// compile. `poll_descriptor` already derives exactly this value for POLICY
    /// matching (`policy_dst_port`), whose comment records that it "carries the
    /// correct post-translation tuple for all inbound destination translations
    /// (DNAT/static-DNAT/NPTv6/NAT64)". Source-NAT matching was the one consumer
    /// left on the pre-translation port.
    pub(super) fn with_destination(&self, dst_ip: IpAddr, dst_port: u16) -> Self {
        let mut forward_key = self.forward_key.clone();
        forward_key.dst_ip = dst_ip;
        forward_key.dst_port = dst_port;
        Self {
            src_ip: self.src_ip,
            dst_ip,
            forward_key,
        }
    }

    pub(super) fn reverse_key_with_nat(&self, nat: NatDecision) -> SessionKey {
        reverse_session_key(&self.forward_key, nat)
    }
}

#[cfg(test)]
mod flow_rr_ring_tests {
    use super::*;

    // #694 / #711: `FlowRrRing` invariant pins. Colocated with the production
    // FlowRrRing struct + impl in types/mod.rs (split back from the
    // shared_cos_lease test mod per Codex P4 review).

    #[test]
    fn flow_rr_ring_push_pop_round_robin_order() {
        let mut ring = FlowRrRing::default();
        assert!(ring.is_empty());
        assert_eq!(ring.len(), 0);
        assert_eq!(ring.front(), None);

        ring.push_back(7);
        ring.push_back(11);
        ring.push_back(13);
        assert_eq!(ring.len(), 3);
        assert_eq!(ring.front(), Some(7));

        // FIFO dequeue preserves push order.
        assert_eq!(ring.pop_front(), Some(7));
        assert_eq!(ring.pop_front(), Some(11));
        assert_eq!(ring.pop_front(), Some(13));
        assert_eq!(ring.pop_front(), None);
        assert!(ring.is_empty());
    }

    #[test]
    fn flow_rr_ring_push_front_places_at_head() {
        let mut ring = FlowRrRing::default();
        ring.push_back(5);
        ring.push_back(9);
        ring.push_front(3); // restore at head
        assert_eq!(ring.len(), 3);
        assert_eq!(ring.pop_front(), Some(3));
        assert_eq!(ring.pop_front(), Some(5));
        assert_eq!(ring.pop_front(), Some(9));
    }

    #[test]
    fn flow_rr_ring_wraps_around_buffer_end_correctly() {
        // Drive the head past the backing-array end and back around.
        // A naive implementation that uses `head + len` without mod
        // breaks exactly here.
        let mut ring = FlowRrRing::default();
        // Fill to 3/4 of capacity, drain half, then fill by another
        // half-capacity worth — the tail write crosses the backing-
        // array end and wraps. Total in-flight stays within capacity.
        let first = COS_FLOW_FAIR_BUCKETS * 3 / 4;
        let second = COS_FLOW_FAIR_BUCKETS / 2;
        for i in 0..first {
            ring.push_back(i as u16);
        }
        for _ in 0..(first / 2) {
            ring.pop_front();
        }
        for i in 0..second {
            ring.push_back((i + 10_000) as u16);
        }
        let mut drained = Vec::with_capacity(ring.len());
        while let Some(b) = ring.pop_front() {
            drained.push(b);
        }
        let mut expected: Vec<u16> = ((first / 2)..first).map(|i| i as u16).collect();
        expected.extend((0..second).map(|i| (i + 10_000) as u16));
        assert_eq!(drained, expected);
    }

    #[test]
    fn flow_rr_ring_iter_yields_same_order_as_pop() {
        let mut ring = FlowRrRing::default();
        for v in [17u16, 3, 11, 29, 7] {
            ring.push_back(v);
        }
        let iter_snapshot: Vec<u16> = ring.iter().collect();
        let mut pop_snapshot = Vec::new();
        while let Some(b) = ring.pop_front() {
            pop_snapshot.push(b);
        }
        assert_eq!(iter_snapshot, pop_snapshot);
    }

    #[test]
    fn flow_rr_ring_accepts_full_cap_minus_one_without_wraparound_bug() {
        // Exactly-at-capacity-minus-one fills: common off-by-one site
        // for ring buffers where the "full" condition is tested.
        let mut ring = FlowRrRing::default();
        let cap = COS_FLOW_FAIR_BUCKETS as u16;
        for i in 0..(cap - 1) {
            ring.push_back(i);
        }
        assert_eq!(ring.len(), usize::from(cap - 1));
        // Drain and re-fill to force internal head advancement past
        // 3/4 of the buffer.
        for _ in 0..((cap - 1) / 2) {
            ring.pop_front();
        }
        // Push enough to wrap past the buffer end.
        for i in 0..((cap - 1) / 2) {
            ring.push_back(i + 10_000);
        }
        // Drain and assert no duplicate IDs and no spurious values.
        let mut seen = std::collections::BTreeSet::new();
        while let Some(b) = ring.pop_front() {
            assert!(seen.insert(b), "ring produced duplicate bucket id: {b}");
        }
        assert!(ring.is_empty());
    }

    #[test]
    fn flow_rr_ring_holds_full_bucket_count_without_panic() {
        // The ring's own capacity is `COS_FLOW_FAIR_BUCKETS`. The
        // caller guards against duplicate pushes, so in practice the
        // ring holds at most `COS_FLOW_FAIR_BUCKETS` entries. Verify
        // that exactly-at-capacity is well-defined (no push_back
        // panic in release, no wrong head index) and that the ring
        // empties correctly.
        let mut ring = FlowRrRing::default();
        for i in 0..COS_FLOW_FAIR_BUCKETS {
            ring.push_back(i as u16);
        }
        assert_eq!(ring.len(), COS_FLOW_FAIR_BUCKETS);
        // Front is 0, tail write would wrap — but we're not over-
        // filling, so this is the well-defined "exactly at capacity"
        // case.
        assert_eq!(ring.front(), Some(0));
        // Drain and verify every ID came back exactly once.
        let mut count = 0usize;
        while let Some(b) = ring.pop_front() {
            assert_eq!(b, count as u16);
            count += 1;
        }
        assert_eq!(count, COS_FLOW_FAIR_BUCKETS);
    }

    #[test]
    fn flow_rr_ring_memory_footprint_fits_expected_budget() {
        // Sanity pin: `FlowRrRing` should be ~`2 * COS_FLOW_FAIR_BUCKETS`
        // bytes (N u16 entries + two u16 indices + padding). A future
        // refactor that accidentally widens the entry type to u32 would
        // double this without a loud signal; this bound catches it.
        // Sized off the constant so it tracks with future bucket-count
        // bumps automatically.
        let size = std::mem::size_of::<FlowRrRing>();
        let budget = 2 * COS_FLOW_FAIR_BUCKETS + 64;
        assert!(
            size <= budget,
            "FlowRrRing unexpectedly large: {size} bytes (budget {budget})"
        );
    }
}

#[cfg(test)]
mod l3_addrs_tests_7890 {
    use super::*;

    /// Address extraction keeps an unspecified value distinct from an
    /// unparseable address family. Session identity still refuses this value;
    /// transit source disposition is separately checked in the poll path by
    /// #10689. This test binds the accessor contract, while the #10689 poll
    /// cells bind the observable transit-drop behavior.
    #[test]
    fn l3_addrs_yields_an_unspecified_source_rather_than_refusing_7890() {
        let mut dst = [0u8; 16];
        dst[..4].copy_from_slice(&[203, 0, 113, 9]);
        let meta = ForwardPacketMeta {
            addr_family: libc::AF_INET as u8,
            flow_src_addr: [0u8; 16],
            flow_dst_addr: dst,
            ..ForwardPacketMeta::default()
        };

        let (src, dst_ip) = meta
            .l3_addrs()
            .expect("an IP-family address is preserved even when unspecified");
        assert_eq!(src, "0.0.0.0".parse::<IpAddr>().unwrap());
        assert_eq!(dst_ip, "203.0.113.9".parse::<IpAddr>().unwrap());

        // An unparseable family still has no addresses to extract.
        let bad = ForwardPacketMeta {
            addr_family: libc::AF_UNIX as u8,
            ..meta
        };
        assert!(
            bad.l3_addrs().is_none(),
            "only an IP-family packet has extractable L3 addresses"
        );
    }
}

#[cfg(test)]
mod with_destination_port_tests_9034 {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn flow_9034() -> SessionFlow {
        let client = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
        let vip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10));
        SessionFlow {
            src_ip: client,
            dst_ip: vip,
            forward_key: SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: crate::afxdp::PROTO_TCP,
                src_ip: client,
                dst_ip: vip,
                src_port: 51000,
                dst_port: 443,
                discriminator: Default::default(),
                routing_domain: 0,
            },
        }
    }

    /// #9034: `with_destination` must carry the POST-translation port, not just
    /// the address.
    ///
    /// The composed shape is DNAT (443 -> 8443 on an internal server) followed
    /// by source-NAT. Before this, the source-NAT rule was matched against the
    /// post-DNAT ADDRESS and the PRE-DNAT PORT — a tuple that existed on no
    /// wire — so a rule written against the real service port 8443 did not
    /// match, and one written against 443 matched when it should not have.
    #[test]
    fn with_destination_carries_the_translated_port_9034() {
        let server = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        let out = flow_9034().with_destination(server, 8443);

        assert_eq!(out.dst_ip, server, "address is translated");
        assert_eq!(
            out.forward_key.dst_ip, server,
            "the key the source-NAT matcher reads must carry the translated address"
        );
        assert_eq!(
            out.forward_key.dst_port, 8443,
            "the key the source-NAT matcher reads must carry the translated PORT — \
             carrying the pre-DNAT port matches the rule against a half-translated \
             destination that existed on no wire (#9034)"
        );
    }

    /// The fields that are NOT the destination must survive untouched. A
    /// `with_destination` that rebuilt the whole key would silently drop the
    /// source identity, which no assertion above would catch.
    #[test]
    fn with_destination_preserves_the_rest_of_the_key_9034() {
        let before = flow_9034();
        let after = before.with_destination(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), 8443);

        assert_eq!(after.src_ip, before.src_ip, "source address preserved");
        assert_eq!(
            after.forward_key.src_ip, before.forward_key.src_ip,
            "key source address preserved"
        );
        assert_eq!(
            after.forward_key.src_port, before.forward_key.src_port,
            "key source PORT preserved — the destination rewrite must not disturb it"
        );
        assert_eq!(
            after.forward_key.protocol, before.forward_key.protocol,
            "protocol preserved"
        );
        assert_eq!(
            after.forward_key.routing_domain, before.forward_key.routing_domain,
            "routing_domain preserved (#7160 identity field)"
        );
    }

    /// CONTROL: an UNCHANGED port must round-trip. Passing the flow's own port
    /// has to leave the key identical, or every caller with no port translation
    /// would silently acquire a wrong one.
    #[test]
    fn with_destination_unchanged_port_is_identity_9034() {
        let before = flow_9034();
        let after = before.with_destination(before.dst_ip, before.forward_key.dst_port);
        assert_eq!(
            after.forward_key, before.forward_key,
            "no translation must leave the key untouched"
        );
    }
}
