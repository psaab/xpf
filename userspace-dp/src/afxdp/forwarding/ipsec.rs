//! #5650: IPsec traffic classification and inbound admission decision. Pure
//! code-motion split out of `forwarding/mod.rs` (behavior-identical).

use super::*;

/// Returns true if the packet is IPsec traffic (ESP protocol 50, AH protocol
/// 51, or IKE UDP ports 500/4500) that should be passed to the kernel for
/// XFRM processing.
///
/// AH (Authentication Header, proto 51) is a configurable host-terminated
/// IPsec protocol (`set security ipsec proposal ... protocol ah`,
/// pkg/config/schema_security.go). Like ESP it carries no transport port, so
/// only the protocol-number arm applies.
///
/// The predicate is family-symmetric — it keys solely on `meta.protocol` —
/// but in practice `meta.protocol == PROTO_AH` only ever occurs for **IPv4
/// AH**. The XDP shim's IPv6 parser treats AH as an extension header and
/// walks THROUGH it (`NEXTHDR_AUTH` arm in `userspace-xdp/src/lib.rs`),
/// setting `meta.protocol` to AH's inner next-header rather than 51. So the
/// `PROTO_AH` arm is a v4-only backstop; it never fires for IPv6 AH.
///
/// This is not a functional gap. IPv6 host-terminated AH-to-self still
/// reaches the kernel XFRM stack via the shim's `is_local_destination`
/// shunt, which fires for any local-destination packet *before* the
/// userspace dataplane runs this predicate; transit AH (v4 or v6) takes
/// ordinary forwarding. ESP (proto 50) is parsed as a terminal protocol on
/// both families, so ESP is recognized here for v4 and v6 alike. Giving this
/// predicate true IPv6 AH coverage would require the shim to surface an
/// "AH present" signal instead of walking past the header — out of scope
/// here, and unnecessary given the local-dest shunt.
#[inline]
pub(in crate::afxdp) fn is_ipsec_traffic(protocol: u8, dst_port: u16) -> bool {
    protocol == PROTO_ESP
        || protocol == PROTO_AH
        || (protocol == PROTO_UDP && (dst_port == 500 || dst_port == 4500))
}

/// #4323: the Stage-11 admission class of an IPsec packet that `is_ipsec_traffic`
/// already matched. Only a NEW inbound IKE initiation is subject to the per-zone
/// host-inbound `ike`/`ipsec` gate; every other IPsec class is exempt (the
/// negotiated SA is the authorization) — with the #6471 refinement that a
/// set-Responder-SPI IKE packet on the secondary path is exempt ONLY while a
/// live seeded exchange matches it (see `classify_ipsec_admission`'s call-site
/// discriminator; a forged set-SPI packet mints no admission).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::afxdp) enum IpsecAdmissionClass {
    /// ESP/AH raw data plane, ESP-in-UDP, a NAT-T keepalive, OR a NON-initial
    /// IKE packet of a LIVE exchange (the exchange already carries a responder
    /// SPI AND — #6471 secondary path — a seeded (Initiator SPI, peer, local)
    /// match exists). Passthrough for ESP/AH and NAT-T keepalives mirrors the
    /// kernel host-inbound chain's global `meta l4proto { 50, 51 } accept`;
    /// return IKE mirrors `ct established,related accept` via the seed table —
    /// an unmatched set-SPI packet falls through to the NEW-initiation gate.
    Exempt,
    /// The FIRST packet of a NEW inbound IKE exchange (we would be the
    /// responder): an ISAKMP header whose Responder SPI/cookie is all-zero
    /// (IKEv2 IKE_SA_INIT request / IKEv1 Main- or Aggressive-mode first
    /// message). This is the packet the Junos `system-services ike` knob is
    /// meant to gate, so it is subject to the per-zone host-inbound admit check.
    NewInboundIke,
}

/// #6471: the ISAKMP demux of a UDP/500-or-4500 payload — the single source
/// of truth for "is this an IKE message, and where does its ISAKMP header
/// start" shared by [`classify_ipsec_admission`] and the SPI extractors
/// below. Callers guarantee `is_ipsec_traffic` already matched, so a
/// non-4500 UDP packet here is UDP/500 (direct ISAKMP, no marker).
enum IsakmpDemux<'a> {
    /// Not an IKE payload: ESP/AH (non-UDP protocol), ESP-in-UDP on 4500
    /// (non-zero ESP SPI in the first payload word), or a NAT-T keepalive.
    NotIsakmp,
    /// An IKE payload (possibly truncated — the caller bounds-checks the
    /// ISAKMP fields it reads).
    Isakmp(&'a [u8]),
    /// The UDP payload itself is truncated (frame ends inside the 8-byte
    /// UDP header) — unclassifiable, must fail CLOSED.
    Truncated,
}

/// #6471: demux the IKE payload out of a packet `is_ipsec_traffic` matched.
/// `l4_offset` is the UDP header offset within `packet_frame`; the ISAKMP
/// header follows the 8-byte UDP header (and, on NAT-T UDP 4500, the 4-byte
/// RFC 3948 non-ESP marker).
fn isakmp_demux(
    packet_frame: &[u8],
    l4_offset: usize,
    protocol: u8,
    dst_port: u16,
) -> IsakmpDemux<'_> {
    // ESP (50) / AH (51): raw IPsec data plane — never ISAKMP.
    if protocol != PROTO_UDP {
        return IsakmpDemux::NotIsakmp;
    }
    // UDP payload (ISAKMP or, on NAT-T UDP 4500, the non-ESP marker) is
    // bounded by BOTH the fixed UDP header and the UDP-declared datagram
    // length. The caller has already trimmed packet_frame to the IP-declared
    // end, so this second bound rejects bytes hidden in UDP/IP slack.
    let header_end = l4_offset.checked_add(8);
    let Some(header_end) = header_end else {
        return IsakmpDemux::Truncated;
    };
    let Some(header) = packet_frame.get(l4_offset..header_end) else {
        return IsakmpDemux::Truncated;
    };
    let udp_len = u16::from_be_bytes([header[4], header[5]]) as usize;
    if udp_len < 8 {
        return IsakmpDemux::Truncated;
    }
    let Some(udp_end) = l4_offset.checked_add(udp_len) else {
        return IsakmpDemux::Truncated;
    };
    // A UDP declaration extending beyond the authoritative IP/frame end is
    // itself truncated. Do not clamp it: a complete-looking marker/header
    // prefix in the available bytes must never become positive IKE.
    if udp_end > packet_frame.len() {
        if dst_port == 4500 {
            let Some(prefix) = packet_frame.get(header_end..) else {
                return IsakmpDemux::Truncated;
            };
            if matches!(prefix.get(0..4), Some([0, 0, 0, 0])) {
                return IsakmpDemux::Truncated;
            }
            // Non-marker 4500 remains on the ESP-in-UDP path, whose strict
            // UDP-length parser returns a truncated miss.
            return IsakmpDemux::NotIsakmp;
        }
        return IsakmpDemux::Truncated;
    }
    let Some(payload) = packet_frame.get(header_end..udp_end) else {
        return IsakmpDemux::Truncated;
    };
    if dst_port == 4500 {
        // RFC 3948 NAT-T demux: a 4-byte all-zero non-ESP marker precedes IKE
        // on UDP 4500. Anything else on 4500 is ESP-in-UDP (its non-zero ESP
        // SPI is the first word) or a 1-byte NAT-T keepalive — both the IPsec
        // data plane, not IKE.
        match payload.get(0..4) {
            Some([0, 0, 0, 0]) => IsakmpDemux::Isakmp(&payload[4..]),
            _ => IsakmpDemux::NotIsakmp,
        }
    } else {
        // UDP 500 — ISAKMP directly, no non-ESP marker.
        IsakmpDemux::Isakmp(payload)
    }
}

/// #4323: classify an IPsec packet (one `is_ipsec_traffic` matched) into its
/// Stage-11 admission class. Only a NEW inbound IKE initiation
/// ([`IpsecAdmissionClass::NewInboundIke`]) is gated on host-inbound; every
/// other class is [`IpsecAdmissionClass::Exempt`] (unconditional passthrough).
///
/// New-vs-established is derived from the ISAKMP header: the first packet of
/// a new exchange has an all-zero Responder SPI, and every later packet
/// carries the responder's SPI. #6471 layers the live-exchange discriminator
/// on top of the `Exempt` class (see [`IkeExchangeTable`]): a non-zero
/// Responder SPI alone no longer proves established — it is attacker-
/// controlled, so an unmatched Responder-SPI-nonzero IKE packet is handed
/// back to the host-inbound gate instead of passing unconditionally.
///
/// `l4_offset` is the UDP header offset within `packet_frame`; the ISAKMP header
/// follows the 8-byte UDP header (and, on NAT-T UDP 4500, the 4-byte non-ESP
/// marker). A missing / too-short ISAKMP header fails CLOSED (`NewInboundIke`) so
/// a truncated IKE to an unpermitted source is gated, never silently admitted.
pub(in crate::afxdp) fn classify_ipsec_admission(
    packet_frame: &[u8],
    l4_offset: usize,
    protocol: u8,
    dst_port: u16,
) -> IpsecAdmissionClass {
    match isakmp_demux(packet_frame, l4_offset, protocol, dst_port) {
        IsakmpDemux::NotIsakmp => IpsecAdmissionClass::Exempt,
        IsakmpDemux::Truncated => IpsecAdmissionClass::NewInboundIke,
        // ISAKMP header: Initiator SPI [0..8], Responder SPI [8..16]. A new
        // exchange's first packet carries an all-zero Responder SPI; a set
        // Responder SPI means the exchange claims to be under way.
        IsakmpDemux::Isakmp(isakmp) => match isakmp.get(8..16) {
            Some(responder_spi) if responder_spi.iter().all(|&b| b == 0) => {
                IpsecAdmissionClass::NewInboundIke
            }
            Some(_) => IpsecAdmissionClass::Exempt,
            None => IpsecAdmissionClass::NewInboundIke,
        },
    }
}

/// Stage-11 outlet discriminator for an already-admitted IKE packet.  The
/// admission stage may permit a short NEW-IKE packet, but only a complete
/// ISAKMP header can be forwarded to the kernel.  A complete responder-SPI
/// header is likewise required before this branch bypasses the ESP gate.
#[inline]
pub(in crate::afxdp) fn is_admitted_positive_ike(
    packet_frame: &[u8],
    l4_offset: usize,
    protocol: u8,
    dst_port: u16,
) -> bool {
    matches!(
        isakmp_demux(packet_frame, l4_offset, protocol, dst_port),
        IsakmpDemux::Isakmp(payload) if payload.len() >= 16
    )
}

/// Return true for a packet that demuxes as IKE but cannot carry the complete
/// 16-byte SPI prefix required by the outlet discriminator.  UDP-4500 values
/// without the four-byte non-ESP marker remain ESP-in-UDP data and are handled
/// by the SPI parser instead.
#[inline]
pub(in crate::afxdp) fn is_malformed_ike(
    packet_frame: &[u8],
    l4_offset: usize,
    protocol: u8,
    dst_port: u16,
) -> bool {
    match isakmp_demux(packet_frame, l4_offset, protocol, dst_port) {
        IsakmpDemux::Truncated => true,
        IsakmpDemux::Isakmp(payload) => payload.len() < 16,
        IsakmpDemux::NotIsakmp => false,
    }
}

/// #6471: the Initiator SPI of a genuine IKE INITIATION (an ISAKMP header
/// with an all-zero Responder SPI), or `None` when the packet is not a
/// parseable initiation (not IKE, truncated, or Responder SPI non-zero).
/// Used to SEED the exchange table only for real exchange starts — a
/// Responder-SPI-nonzero packet must never seed (a forged one would
/// otherwise mint its own "established" entry).
pub(in crate::afxdp) fn ike_initiation_spi(
    packet_frame: &[u8],
    l4_offset: usize,
    dst_port: u16,
) -> Option<u64> {
    let IsakmpDemux::Isakmp(isakmp) = isakmp_demux(packet_frame, l4_offset, PROTO_UDP, dst_port)
    else {
        return None;
    };
    let header = isakmp.get(0..16)?;
    let (initiator, responder) = header.split_at(8);
    if responder.iter().all(|&b| b == 0) {
        Some(u64::from_be_bytes(initiator.try_into().ok()?))
    } else {
        None
    }
}

/// #6471: the Initiator SPI of an IKE packet claiming to be ESTABLISHED (an
/// ISAKMP header with a non-zero Responder SPI), or `None` for every other
/// class (ESP-in-UDP, NAT-T keepalive, truncated, or a zero-Responder
/// initiation — those follow their own paths). The returned SPI keys the
/// live-exchange lookup: only a packet whose (Initiator SPI, peer/local
/// addresses) matches a seeded exchange is treated as established.
pub(in crate::afxdp) fn established_ike_initiator_spi(
    packet_frame: &[u8],
    l4_offset: usize,
    dst_port: u16,
) -> Option<u64> {
    let IsakmpDemux::Isakmp(isakmp) = isakmp_demux(packet_frame, l4_offset, PROTO_UDP, dst_port)
    else {
        return None;
    };
    let header = isakmp.get(0..16)?;
    let (initiator, responder) = header.split_at(8);
    if responder.iter().any(|&b| b != 0) {
        Some(u64::from_be_bytes(initiator.try_into().ok()?))
    } else {
        None
    }
}

/// #6471: hard cap on tracked live IKE exchanges per node. Far above any
/// legitimate site-to-site count on this class of box (hundreds); the bound
/// keeps a forged-initiation flood on an IKE-permitting zone from growing
/// the table without limit. On full, the OLDEST entry is evicted (see
/// [`IkeExchangeTable::seed`]).
pub(in crate::afxdp) const IKE_EXCHANGE_TABLE_CAP: usize = 4096;

/// #6471: sliding idle timeout for a seeded exchange. Refreshed on every
/// matched packet, so any live SA (rekeys, INFORMATIONALs, DPD all carry the
/// seeded Initiator SPI) keeps its seed; a seed outliving the SA by up to
/// this window is harmless — a forged packet still has to guess the 64-bit
/// Initiator SPI plus the exchange's address pair, and strongSwan rejects a
/// semantically invalid SPI regardless. 24h comfortably covers typical IKE
/// SA lifetimes (1-8h); an SA with rekeying disabled AND no DPD that stays
/// IKE-silent longer than this degrades to the post-restart posture
/// (follow-ups re-gated on host-inbound; self-heals on the firewall's next
/// outbound IKE for firewall-initiated exchanges).
pub(in crate::afxdp) const IKE_EXCHANGE_IDLE_NS: u64 = 24 * 3600 * 1_000_000_000;

const _: () = assert!(IKE_EXCHANGE_TABLE_CAP >= 1);

/// #6471: identity of a live IKE exchange for the established-vs-forged
/// discriminator. Keyed on the Initiator SPI plus the exchange's address
/// pair — NOT the IKE ports, so an RFC 5996 NAT-T port float (500 -> 4500
/// mid-exchange) does not strand the seed; the Initiator SPI (64-bit random
/// per exchange) is the collision-proof discriminator strongSwan itself
/// uses. The Responder SPI is deliberately absent: the responder's reply is
/// never observed on the inbound-only dataplane, so its value cannot be
/// learned here. This mirrors the kernel conntrack match the PRIMARY path
/// relies on (a 4-tuple-established entry, likewise MOBIKE-fragile) rather
/// than strengthening it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(in crate::afxdp) struct IkeExchangeKey {
    pub(in crate::afxdp) initiator_spi: u64,
    pub(in crate::afxdp) peer_ip: IpAddr,
    pub(in crate::afxdp) local_ip: IpAddr,
}

impl IkeExchangeKey {
    pub(in crate::afxdp) fn new(initiator_spi: u64, peer_ip: IpAddr, local_ip: IpAddr) -> Self {
        Self {
            initiator_spi,
            peer_ip,
            local_ip,
        }
    }
}

/// #6471: the shared table of live IKE exchanges backing the Stage-11
/// established-vs-forged discriminator on the AF_XDP SECONDARY path
/// (DNAT/static-NAT-to-self, native-GRE-inner). The PRIMARY path (direct IKE
/// to an interface IP) gets the same NEW-vs-established split from kernel
/// conntrack in the nftables host-inbound chain; the secondary path installs
/// no session for a passthrough flow, so it tracks exchanges explicitly:
///
/// - SEEDED inbound at Stage 11 when a NEW IKE initiation (all-zero
///   Responder SPI) PASSES the per-zone host-inbound `ike` gate. A denied
///   initiation MUST NOT seed — otherwise a forged follow-up on a
///   closed zone would mint its own "established" entry and re-open the
///   bypass this table closes.
/// - SEEDED outbound in the native-GRE local-origin path
///   (`build_local_origin_tunnel_tx_request`) when the firewall itself
///   initiates IKE through a tunnel: the peer's replies arrive GRE-inner on
///   Stage 11 with a non-zero Responder SPI and no inbound seed.
/// - MATCHED at Stage 11 for every Responder-SPI-nonzero IKE packet to a
///   firewall-local address: a hit (refreshed) admits; a miss hands the
///   packet to the SAME host-inbound gate a NEW initiation faces, so a
///   forged Responder SPI on a zone that omits `ike` is denied instead of
///   reaching strongSwan, while an IKE-permitting zone keeps its
///   config-sanctioned open posture (primary-path parity: the kernel chain
///   also admits NEW IKE there).
///
/// Sharing + locking: one table per node, shared by every packet worker and
/// the GRE local-origin threads (`Arc<IkeExchangeTable>` — RSS does not pin
/// an exchange's packets to the seeding worker, and the outbound seed is
/// written by a non-worker thread). The `Mutex` is taken ONLY for
/// IKE-to-self packets (control plane, pps-bounded, and flood-bounded
/// upstream by the stage-10 udp-flood screen) — never for ESP/AH or the
/// general session path — mirroring the `shared_sessions` precedent. A
/// poisoned lock is recovered (`into_inner`): a worker that panicked
/// mid-seed/match must not permanently deafen the gate — the same recovery
/// policy as `worker_queue::lock_recover` (#1807), whose helper is typed to
/// the command-queue deque and so cannot be reused for this map.
///
/// NOT HA-synced: after RG failover the new node's table is empty, so
/// secondary-path IKE control on `ike`-omitting zones stalls until the
/// exchange's next initiation — the SAME gap the primary path has (kernel
/// conntrack for host-terminated IKE is not synced either). Likewise an
/// xpfd restart drops all seeds; firewall-initiated exchanges re-seed on
/// strongSwan's next outbound IKE packet (DPD / rekey / re-auth), and the
/// ESP data plane is exempt throughout.
pub(in crate::afxdp) struct IkeExchangeTable {
    inner: Mutex<IkeExchangeInner>,
    /// #6747: count of live exchanges evicted to make room. Non-zero means the
    /// cap is binding — either a genuinely large deployment or a forged-
    /// initiation flood churning legitimate seeds. The condition was previously
    /// unobservable. Relaxed: it is a diagnostic, ordered against nothing.
    evictions: AtomicU64,
}

/// #6747: the LRU slot index sentinel. IKE_EXCHANGE_TABLE_CAP is 4096, so a
/// u32 index is ample and the const assert below keeps that true if the cap
/// ever moves.
const IKE_SLOT_NIL: u32 = u32::MAX;
const _: () = assert!(IKE_EXCHANGE_TABLE_CAP < IKE_SLOT_NIL as usize);

/// One tracked exchange plus its links in the recency list.
///
/// The key is stored here as well as in the index because eviction starts from
/// the list head and has to reach the index to remove it — the whole point of
/// the structure is that it never has to search for the victim.
struct IkeExchangeSlot {
    key: IkeExchangeKey,
    seen_ns: u64,
    prev: u32,
    next: u32,
}

/// #6747: an intrusive LRU over a slab, replacing the `min_by_key` scan.
///
/// The old shape was `Mutex<FastMap<Key, u64>>`, and on a full table `seed`
/// chose its victim with `entries.iter().min_by_key(...)` — a full traversal of
/// all 4096 entries plus the empty hashbrown slots, a key clone and a second
/// hash lookup for the remove, all under a lock that `matches` takes on the hot
/// admission path for every Responder-SPI IKE packet, on a table `Arc`-shared
/// by every packet worker. One worker's scan stalled the others.
///
/// The scan is reachable exactly when 4096 DISTINCT live exchanges are
/// resident, which is also precisely the state a forged-initiation flood
/// produces — so the worst case and the attack case are the same case. An
/// amortised "reap the idle ones first" would not have helped there: under a
/// flood every entry is fresh.
///
/// SEMANTICS ARE UNCHANGED, and that is deliberate. `min_by_key(seen)` is
/// least-recently-touched, and `matches` refreshes `seen` on every hit, so the
/// old policy was already LRU — just computed by scanning. This keeps exact
/// LRU and makes it O(1): `touch` unlinks and re-appends at the tail, eviction
/// pops the head. Nothing about WHICH entry is evicted changes, so the
/// availability reasoning in `seed`'s doc comment still holds verbatim.
///
/// FIFO was rejected. It is simpler (insertion-ordered queue, no touch on the
/// read path) but it would evict a long-lived exchange that DPD refreshes every
/// 30s in favour of a brand-new forged initiation — strictly worse under the
/// flood this cap exists for, and a behaviour change where none is needed.
///
/// Allocation-free after the first fill: slots are recycled through `free`, and
/// `slots` never shrinks. Bounded by the cap, so ~4096 * (key + u64 + 2*u32).
struct IkeExchangeInner {
    index: FastMap<IkeExchangeKey, u32>,
    slots: Vec<IkeExchangeSlot>,
    free: Vec<u32>,
    /// Least recently touched; the eviction victim.
    head: u32,
    /// Most recently touched.
    tail: u32,
}

impl IkeExchangeInner {
    fn new() -> Self {
        Self {
            index: FastMap::default(),
            slots: Vec::new(),
            free: Vec::new(),
            head: IKE_SLOT_NIL,
            tail: IKE_SLOT_NIL,
        }
    }

    /// Detach `idx` from the recency list, leaving its payload intact.
    fn unlink(&mut self, idx: u32) {
        let (prev, next) = {
            let s = &self.slots[idx as usize];
            (s.prev, s.next)
        };
        if prev == IKE_SLOT_NIL {
            self.head = next;
        } else {
            self.slots[prev as usize].next = next;
        }
        if next == IKE_SLOT_NIL {
            self.tail = prev;
        } else {
            self.slots[next as usize].prev = prev;
        }
        let s = &mut self.slots[idx as usize];
        s.prev = IKE_SLOT_NIL;
        s.next = IKE_SLOT_NIL;
    }

    /// Append `idx` at the MRU end. The slot must already be unlinked.
    fn push_tail(&mut self, idx: u32) {
        let old = self.tail;
        self.slots[idx as usize].prev = old;
        self.slots[idx as usize].next = IKE_SLOT_NIL;
        if old == IKE_SLOT_NIL {
            self.head = idx;
        } else {
            self.slots[old as usize].next = idx;
        }
        self.tail = idx;
    }

    fn touch(&mut self, idx: u32, now_ns: u64) {
        self.slots[idx as usize].seen_ns = now_ns;
        self.unlink(idx);
        self.push_tail(idx);
    }

    /// Remove `idx` from the list, the index and the live set, recycling it.
    fn drop_slot(&mut self, idx: u32) {
        self.unlink(idx);
        let key = self.slots[idx as usize].key.clone();
        self.index.remove(&key);
        self.free.push(idx);
    }

    fn insert(&mut self, key: IkeExchangeKey, now_ns: u64) {
        let idx = match self.free.pop() {
            Some(idx) => {
                let s = &mut self.slots[idx as usize];
                s.key = key.clone();
                s.seen_ns = now_ns;
                s.prev = IKE_SLOT_NIL;
                s.next = IKE_SLOT_NIL;
                idx
            }
            None => {
                let idx = self.slots.len() as u32;
                self.slots.push(IkeExchangeSlot {
                    key: key.clone(),
                    seen_ns: now_ns,
                    prev: IKE_SLOT_NIL,
                    next: IKE_SLOT_NIL,
                });
                idx
            }
        };
        self.index.insert(key, idx);
        self.push_tail(idx);
    }
}

impl IkeExchangeTable {
    pub(in crate::afxdp) fn new() -> Self {
        Self {
            inner: Mutex::new(IkeExchangeInner::new()),
            evictions: AtomicU64::new(0),
        }
    }

    fn lock_entries(&self) -> std::sync::MutexGuard<'_, IkeExchangeInner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// #6747: live exchanges evicted because the table was at cap.
    pub(in crate::afxdp) fn evictions(&self) -> u64 {
        self.evictions.load(Ordering::Relaxed)
    }

    /// Record (or refresh) a live exchange. On a full table the OLDEST entry
    /// is evicted to make room: refusing the insert (drop-newest) would
    /// strand the exchange that just legitimately started — its follow-ups
    /// would be host-inbound-gated and dropped on `ike`-omitting zones —
    /// while the oldest entry is the one most likely stale. A flood of
    /// forged initiations on an IKE-PERMITTING zone can still churn
    /// legitimate seeds out of the table (bounded by the cap) — and because
    /// eviction is oldest-first GLOBALLY, the victim can be a seed serving a
    /// DIFFERENT, closed zone (e.g. a firewall-initiated GRE exchange whose
    /// reply then re-gates); the blast radius is availability-only and
    /// self-heals at the next re-auth, and the stage-10 udp-flood screen is
    /// the rate limiter.
    pub(in crate::afxdp) fn seed(&self, key: IkeExchangeKey, now_ns: u64) {
        let mut entries = self.lock_entries();
        if let Some(&idx) = entries.index.get(&key) {
            entries.touch(idx, now_ns);
            return;
        }
        // #6747: O(1). The victim is the recency list HEAD — the same entry the
        // old `min_by_key(seen)` scan selected, reached without traversing.
        if entries.index.len() >= IKE_EXCHANGE_TABLE_CAP {
            let victim = entries.head;
            if victim != IKE_SLOT_NIL {
                entries.drop_slot(victim);
                self.evictions.fetch_add(1, Ordering::Relaxed);
            }
        }
        entries.insert(key, now_ns);
    }

    /// True iff `key` names a live seeded exchange (and refreshes it —
    /// sliding window). A seed idle past [`IKE_EXCHANGE_IDLE_NS`] is reaped
    /// lazily here and treated as a miss, so a dead SA's seed cannot admit
    /// forged packets forever.
    pub(in crate::afxdp) fn matches(&self, key: &IkeExchangeKey, now_ns: u64) -> bool {
        let mut entries = self.lock_entries();
        let Some(&idx) = entries.index.get(key) else {
            return false;
        };
        if now_ns.saturating_sub(entries.slots[idx as usize].seen_ns) > IKE_EXCHANGE_IDLE_NS {
            entries.drop_slot(idx);
            return false;
        }
        entries.touch(idx, now_ns);
        true
    }

    /// Test/telemetry seam: current entry count.
    #[cfg(test)]
    pub(in crate::afxdp) fn len(&self) -> usize {
        self.lock_entries().index.len()
    }
}

/// #6471: the shared handle workers + GRE local-origin threads hold.
pub(in crate::afxdp) type SharedIkeExchangeTable = Arc<IkeExchangeTable>;

/// #6471: seed the exchange table for a FIREWALL-INITIATED IKE exchange
/// routed via a local-origin tunnel (native GRE). The outbound initiation is
/// read off the tunnel's TUN device by `local_tunnel_source_loop` and never
/// crosses Stage 11, so without this seed the peer's replies (Responder SPI
/// non-zero) would fail the established-exchange lookup and be host-inbound
/// gated — a regression for firewall-initiated tunnels on zones that omit
/// `ike` (the primary path admits those replies via conntrack-established).
///
/// `packet_frame`/`l4_offset` describe the INNER frame (post
/// `wrap_raw_ip_packet_for_tunnel`, so offsets are L2-adjusted); `flow` is the
/// parsed inner flow — its `dst_ip` names the IKE peer and its `src_ip` the
/// firewall's local address (the seed is keyed reply-direction, so the
/// peer's inbound packets match). Only a genuine initiation (all-zero
/// Responder SPI) seeds — IKE replies/retransmissions the firewall sends
/// later in the exchange are ignored, and non-IKE UDP on 500/4500 cannot
/// parse as an initiation.
pub(in crate::afxdp) fn maybe_seed_local_origin_ike(
    table: &IkeExchangeTable,
    packet_frame: &[u8],
    l4_offset: usize,
    flow: &SessionFlow,
    now_ns: u64,
) {
    let protocol = flow.forward_key.protocol;
    let dst_port = flow.forward_key.dst_port;
    if protocol != PROTO_UDP || (dst_port != 500 && dst_port != 4500) {
        return;
    }
    if let Some(initiator_spi) = ike_initiation_spi(packet_frame, l4_offset, dst_port) {
        table.seed(
            IkeExchangeKey::new(initiator_spi, flow.dst_ip, flow.src_ip),
            now_ns,
        );
    }
}

#[cfg(test)]
mod tests {
    //! #6471: unit pins for the ISAKMP SPI extractors and the exchange-table
    //! state machine (seed / match / idle-reap / cap-evict). The Stage-11
    //! fail-on-revert coverage (forged Responder SPI denied, seeded exchange
    //! admitted) lives in `poll_stages_tests.rs`.
    use super::*;

    /// Minimal IPv4/UDP frame whose UDP payload carries an ISAKMP header;
    /// same layout contract as the poll_stages_tests `ike_v4_frame` (only
    /// the bytes at/after `l4_offset` = 34 matter).
    fn ike_frame(natt_marker: bool, initiator: u64, responder: u64) -> Vec<u8> {
        let mut frame = vec![0u8; 42];
        if natt_marker {
            frame.extend_from_slice(&[0, 0, 0, 0]);
        }
        frame.extend_from_slice(&initiator.to_be_bytes());
        frame.extend_from_slice(&responder.to_be_bytes());
        frame.extend_from_slice(&[0x00, 0x20, 0x22, 0x08]); // np/ver/exchange/flags
        frame.extend_from_slice(&0u32.to_be_bytes()); // message id
        frame.extend_from_slice(&0u32.to_be_bytes()); // length
        set_udp_len(&mut frame);
        frame
    }

    fn set_udp_len(frame: &mut [u8]) {
        let udp_len = (frame.len() - 34) as u16;
        frame[38..40].copy_from_slice(&udp_len.to_be_bytes());
    }

    #[test]
    fn initiation_spi_only_for_zero_responder() {
        let init = ike_frame(false, 0x1122_3344_5566_7788, 0);
        assert_eq!(
            ike_initiation_spi(&init, 34, 500),
            Some(0x1122_3344_5566_7788)
        );
        assert_eq!(established_ike_initiator_spi(&init, 34, 500), None);
        let est = ike_frame(false, 0x1122_3344_5566_7788, 0xdead_beef_cafe_0001);
        assert_eq!(ike_initiation_spi(&est, 34, 500), None);
        assert_eq!(
            established_ike_initiator_spi(&est, 34, 500),
            Some(0x1122_3344_5566_7788)
        );
    }

    #[test]
    fn spi_extractors_honor_natt_marker() {
        let init = ike_frame(true, 0xaabb_ccdd_eeff_0011, 0);
        assert_eq!(
            ike_initiation_spi(&init, 34, 4500),
            Some(0xaabb_ccdd_eeff_0011)
        );
        let est = ike_frame(true, 0xaabb_ccdd_eeff_0011, 1);
        assert_eq!(
            established_ike_initiator_spi(&est, 34, 4500),
            Some(0xaabb_ccdd_eeff_0011)
        );
        // ESP-in-UDP (non-zero first word, no marker) is NOT IKE: no SPI.
        let mut esp = vec![0u8; 42];
        esp.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);
        esp.extend_from_slice(&[0u8; 16]);
        set_udp_len(&mut esp);
        assert_eq!(established_ike_initiator_spi(&esp, 34, 4500), None);
        assert_eq!(ike_initiation_spi(&esp, 34, 4500), None);
    }

    #[test]
    fn spi_extractors_fail_safe_on_truncation() {
        // Frame ends inside the ISAKMP header: neither extractor may invent
        // an SPI (classification still fails CLOSED via NewInboundIke).
        let short = vec![0u8; 42 + 8];
        assert_eq!(ike_initiation_spi(&short, 34, 500), None);
        assert_eq!(established_ike_initiator_spi(&short, 34, 500), None);
        // Frame ends inside the UDP header itself.
        let shorter = vec![0u8; 36];
        assert_eq!(ike_initiation_spi(&shorter, 34, 500), None);
        assert_eq!(established_ike_initiator_spi(&shorter, 34, 500), None);
    }

    #[test]
    fn classify_demux_unchanged_by_6471_refactor() {
        // Behavior-preservation pin for the isakmp_demux extraction: every
        // class resolves exactly as the pre-refactor open-coded match did.
        let init = ike_frame(false, 1, 0);
        assert_eq!(
            classify_ipsec_admission(&init, 34, PROTO_UDP, 500),
            IpsecAdmissionClass::NewInboundIke
        );
        let est = ike_frame(false, 1, 2);
        assert_eq!(
            classify_ipsec_admission(&est, 34, PROTO_UDP, 500),
            IpsecAdmissionClass::Exempt
        );
        let natt_init = ike_frame(true, 1, 0);
        assert_eq!(
            classify_ipsec_admission(&natt_init, 34, PROTO_UDP, 4500),
            IpsecAdmissionClass::NewInboundIke
        );
        let natt_est = ike_frame(true, 1, 2);
        assert_eq!(
            classify_ipsec_admission(&natt_est, 34, PROTO_UDP, 4500),
            IpsecAdmissionClass::Exempt
        );
        let mut esp_in_udp = vec![0u8; 42];
        esp_in_udp.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);
        esp_in_udp.extend_from_slice(&[0u8; 16]);
        set_udp_len(&mut esp_in_udp);
        assert_eq!(
            classify_ipsec_admission(&esp_in_udp, 34, PROTO_UDP, 4500),
            IpsecAdmissionClass::Exempt
        );
        // ESP / AH — the raw data plane.
        assert_eq!(
            classify_ipsec_admission(&init, 34, PROTO_ESP, 0),
            IpsecAdmissionClass::Exempt
        );
        assert_eq!(
            classify_ipsec_admission(&init, 34, PROTO_AH, 0),
            IpsecAdmissionClass::Exempt
        );
        // Truncated ISAKMP and truncated UDP payload fail CLOSED.
        let short = vec![0u8; 42 + 8];
        assert_eq!(
            classify_ipsec_admission(&short, 34, PROTO_UDP, 500),
            IpsecAdmissionClass::NewInboundIke
        );
        let shorter = vec![0u8; 36];
        assert_eq!(
            classify_ipsec_admission(&shorter, 34, PROTO_UDP, 500),
            IpsecAdmissionClass::NewInboundIke
        );
    }
    #[test]
    fn demux_honors_udp_declared_length_over_backing_slack() {
        let mut slack = ike_frame(false, 0x1122_3344_5566_7788, 0xdead_beef_cafe_0001);
        // Keep the complete non-zero-responder ISAKMP header in backing
        // memory, but declare an empty UDP payload. The bytes beyond UDP end
        // are slack and must not turn this into an established IKE packet.
        slack[38..40].copy_from_slice(&8u16.to_be_bytes());
        assert_eq!(
            classify_ipsec_admission(&slack, 34, PROTO_UDP, 500),
            IpsecAdmissionClass::NewInboundIke
        );
        assert!(is_malformed_ike(&slack, 34, PROTO_UDP, 500));
        assert_eq!(established_ike_initiator_spi(&slack, 34, 500), None);
        let mut truncated_marker = ike_frame(true, 0x1122_3344_5566_7788, 0xdead_beef_cafe_0001);
        let udp_len_past_frame = (truncated_marker.len() - 34 + 4) as u16;
        truncated_marker[38..40].copy_from_slice(&udp_len_past_frame.to_be_bytes());
        assert_eq!(
            classify_ipsec_admission(&truncated_marker, 34, PROTO_UDP, 4500),
            IpsecAdmissionClass::NewInboundIke
        );
        assert!(is_malformed_ike(&truncated_marker, 34, PROTO_UDP, 4500));
        assert_eq!(
            established_ike_initiator_spi(&truncated_marker, 34, 4500),
            None
        );
    }

    fn key(spi: u64) -> IkeExchangeKey {
        IkeExchangeKey::new(
            spi,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)),
        )
    }

    #[test]
    fn exchange_seed_match_refresh() {
        let table = IkeExchangeTable::new();
        assert!(!table.matches(&key(7), 1_000));
        table.seed(key(7), 1_000);
        assert!(table.matches(&key(7), 2_000));
        // A different SPI or address pair must NOT match.
        assert!(!table.matches(&key(8), 2_000));
        assert!(!table.matches(
            &IkeExchangeKey::new(
                7,
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11)),
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5))
            ),
            2_000
        ));
    }

    #[test]
    fn exchange_idle_reap_treats_stale_as_miss() {
        let table = IkeExchangeTable::new();
        table.seed(key(7), 1_000);
        assert!(table.matches(&key(7), 1_000 + IKE_EXCHANGE_IDLE_NS));
        // Refresh slid the window: another full idle span is tolerated.
        let t2 = 1_000 + 2 * IKE_EXCHANGE_IDLE_NS;
        assert!(table.matches(&key(7), t2));
        // Past the window with no traffic: stale seed reaped, reads as miss.
        let t3 = t2 + IKE_EXCHANGE_IDLE_NS + 1;
        assert!(!table.matches(&key(7), t3));
        assert_eq!(table.len(), 0, "stale entry must be reaped, not retained");
    }

    #[test]
    fn exchange_full_evicts_oldest_not_newest() {
        let table = IkeExchangeTable::new();
        for spi in 0..IKE_EXCHANGE_TABLE_CAP as u64 {
            table.seed(key(spi), spi); // insertion order = age order
        }
        assert_eq!(table.len(), IKE_EXCHANGE_TABLE_CAP);
        let cap = IKE_EXCHANGE_TABLE_CAP as u64;
        table.seed(key(cap), cap);
        assert_eq!(table.len(), IKE_EXCHANGE_TABLE_CAP);
        // The OLDEST (spi 0) was evicted; the just-inserted seed survives —
        // refusing the insert would strand a live exchange's follow-ups.
        assert!(!table.matches(&key(0), cap + 1));
        assert!(table.matches(&key(cap), cap + 1));
        assert!(table.matches(&key(1), cap + 1));
    }

    /// #6747: the victim must stay LEAST-RECENTLY-TOUCHED, not
    /// least-recently-INSERTED.
    ///
    /// This is the cell that separates the O(1) LRU from the obvious cheaper
    /// rewrite. An insertion-ordered FIFO queue removes the scan just as well
    /// and passes `exchange_full_evicts_oldest_not_newest` above — every entry
    /// there is inserted once and never refreshed, so insertion order and
    /// recency order are the same sequence. They diverge only when something
    /// REFRESHES an old entry, which is exactly what a live SA does: DPD, rekey
    /// and INFORMATIONAL all carry the seeded Initiator SPI and land in
    /// `matches`.
    ///
    /// Under FIFO the longest-lived exchange on the box is evicted in favour of
    /// a brand-new forged initiation — strictly worse under the flood the cap
    /// exists for. `min_by_key(seen)` never did that, and neither must this.
    #[test]
    fn exchange_eviction_is_recency_not_insertion_order_6747() {
        let table = IkeExchangeTable::new();
        let cap = IKE_EXCHANGE_TABLE_CAP as u64;
        for spi in 0..cap {
            table.seed(key(spi), spi);
        }
        assert_eq!(table.len(), IKE_EXCHANGE_TABLE_CAP);

        // The OLDEST-INSERTED entry is refreshed, as a live SA's DPD would.
        // Its insertion rank is unchanged; its recency rank is now the newest.
        assert!(table.matches(&key(0), cap + 1));

        // One more distinct initiation forces exactly one eviction.
        table.seed(key(cap), cap + 2);
        assert_eq!(table.len(), IKE_EXCHANGE_TABLE_CAP);

        assert!(
            table.matches(&key(0), cap + 3),
            "the refreshed exchange was evicted: eviction is following INSERTION \
             order, so a live SA that DPD keeps alive loses its seed to a brand-new \
             (possibly forged) initiation — the regression a FIFO rewrite of #6747 \
             would introduce, and the one min_by_key(seen) never had",
        );
        assert!(
            !table.matches(&key(1), cap + 3),
            "spi 1 is now the least-recently-touched entry and must be the victim; \
             if it survived, something other than the LRU head was evicted",
        );
        assert!(table.matches(&key(cap), cap + 3), "the new seed must be resident");
        assert_eq!(table.evictions(), 1, "exactly one live exchange was evicted");
    }

    /// #6747: the eviction path must recycle slots rather than grow the slab.
    ///
    /// The scan is gone, but an O(1) victim is worth nothing if the structure
    /// that provides it leaks a slot per eviction — a sustained forged-
    /// initiation flood is unbounded in TIME, not just in distinct keys, so a
    /// per-eviction leak is the same denial-of-service through a different
    /// door. Churns 4x the cap through a full table and asserts the slab never
    /// exceeds it.
    #[test]
    fn exchange_eviction_recycles_slots_6747() {
        let table = IkeExchangeTable::new();
        let cap = IKE_EXCHANGE_TABLE_CAP as u64;
        for spi in 0..(5 * cap) {
            table.seed(key(spi), spi);
        }
        assert_eq!(table.len(), IKE_EXCHANGE_TABLE_CAP);
        assert_eq!(
            table.evictions(),
            4 * cap,
            "every insert past the cap must evict exactly one entry",
        );
        let inner = table.lock_entries();
        assert!(
            inner.slots.len() <= IKE_EXCHANGE_TABLE_CAP,
            "slab grew to {} for a table capped at {}: eviction is leaking a slot \
             per victim, so a sustained flood exhausts memory even though the \
             live-entry count is bounded",
            inner.slots.len(),
            IKE_EXCHANGE_TABLE_CAP,
        );
    }

    /// #6747: the recency list must stay structurally consistent with the index
    /// under a mixed workload.
    ///
    /// unlink/push_tail are the only places the invariant can break, and a
    /// broken link is silent: a severed list still answers `matches` correctly
    /// from the index, so every behavioural cell above would pass while
    /// eviction walked a truncated list and evicted the wrong entry — or
    /// nothing at all, quietly turning the cap off. Walk the list from head to
    /// tail and require it to visit every indexed entry exactly once, in
    /// non-decreasing `seen_ns` order.
    #[test]
    fn exchange_recency_list_matches_the_index_6747() {
        let table = IkeExchangeTable::new();
        let cap = IKE_EXCHANGE_TABLE_CAP as u64;
        // Fill, refresh a scattered third, reap some, then overflow.
        for spi in 0..cap {
            table.seed(key(spi), spi);
        }
        for spi in (0..cap).step_by(3) {
            assert!(table.matches(&key(spi), cap + spi));
        }
        for spi in (1..cap).step_by(7) {
            // Past the idle window: reaped through the matches() path.
            assert!(!table.matches(&key(spi), 3 * cap + IKE_EXCHANGE_IDLE_NS + spi));
        }
        for spi in cap..(cap + 128) {
            table.seed(key(spi), 4 * cap + spi);
        }

        let inner = table.lock_entries();
        let mut seen = 0usize;
        let mut prev_ns = 0u64;
        let mut idx = inner.head;
        let mut back = IKE_SLOT_NIL;
        while idx != IKE_SLOT_NIL {
            let slot = &inner.slots[idx as usize];
            assert_eq!(slot.prev, back, "prev link is not the reverse of next");
            assert_eq!(
                inner.index.get(&slot.key).copied(),
                Some(idx),
                "a slot on the recency list is not the one the index names for its key",
            );
            assert!(
                slot.seen_ns >= prev_ns,
                "recency list is out of order at slot {idx}: {} < {prev_ns} — the head \
                 is then not the least-recently-touched entry and eviction picks the \
                 wrong victim",
                slot.seen_ns,
            );
            prev_ns = slot.seen_ns;
            back = idx;
            idx = slot.next;
            seen += 1;
            assert!(seen <= inner.slots.len(), "recency list contains a cycle");
        }
        assert_eq!(back, inner.tail, "tail is not the last node reached from head");
        assert_eq!(
            seen,
            inner.index.len(),
            "the recency list visits {seen} slots but the index holds {} — a severed \
             or duplicated link makes eviction walk the wrong set while every \
             behavioural assertion still passes",
            inner.index.len(),
        );
    }

    #[test]
    fn local_origin_seed_only_for_udp_ike_initiation() {
        fn seed_flow(protocol: u8, dst_port: u16) -> SessionFlow {
            let src_ip = IpAddr::V4(Ipv4Addr::new(10, 255, 0, 1)); // firewall local
            let dst_ip = IpAddr::V4(Ipv4Addr::new(10, 255, 0, 2)); // tunnel peer
            SessionFlow {
                src_ip,
                dst_ip,
                forward_key: SessionKey {
                    addr_family: libc::AF_INET as u8,
                    protocol,
                    src_ip,
                    dst_ip,
                    src_port: 500,
                    dst_port,
                                    discriminator: Default::default(),
                                    routing_domain: 0,
                },
            }
        }
        let table = IkeExchangeTable::new();
        let src = IpAddr::V4(Ipv4Addr::new(10, 255, 0, 1)); // firewall local
        let dst = IpAddr::V4(Ipv4Addr::new(10, 255, 0, 2)); // tunnel peer
        let init = ike_frame(false, 0x5152_5354_5556_5758, 0);
        maybe_seed_local_origin_ike(&table, &init, 34, &seed_flow(PROTO_UDP, 500), 1_000);
        // The peer's REPLY direction lookup: (initiator SPI, peer, local).
        assert!(table.matches(&IkeExchangeKey::new(0x5152_5354_5556_5758, dst, src), 2_000));

        // Non-IKE UDP (wrong port), non-initiation (responder set), and ESP
        // must not seed.
        let table2 = IkeExchangeTable::new();
        maybe_seed_local_origin_ike(&table2, &init, 34, &seed_flow(PROTO_UDP, 53), 1_000);
        let est = ike_frame(false, 9, 9);
        maybe_seed_local_origin_ike(&table2, &est, 34, &seed_flow(PROTO_UDP, 500), 1_000);
        maybe_seed_local_origin_ike(&table2, &init, 34, &seed_flow(PROTO_ESP, 0), 1_000);
        assert_eq!(table2.len(), 0);
    }
}
