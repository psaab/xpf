//! #9950 (F-035): stateful IPv4/IPv6 fragment-overlap tracker.
//!
//! The stateless screens (`screen/stateless.rs`) inspect only the FIRST fragment's
//! L4 flags (`check_tcp_flag_screens` skips non-first) and state they are NOT overlap
//! detectors. Enforcement (zone policy `application any`, screens, NAT) therefore runs
//! on bytes a later overlapping fragment can rewrite before the receiver reassembles —
//! an IDS/enforcement-evasion primitive. This tracker closes the ordering gap by dropping
//! overlapping fragments (RFC 5722 / Juniper `tear-drop` semantics).
//!
//! Key is the receiver's reassembly key plus the routing domain and the
//! ingress security zone (#14321):
//! `(family, src, dst, ident, proto, routing_domain, ingress_zone)` for IPv4, with `protocol` pinned
//! to 0 for IPv6 (the receiver reassembles on src/dst/ident only, RFC 8200 §4.5, while
//! the Fragment Header's Next Header is vary-able — keying it would let an attacker
//! split overlap keys the receiver still reassembles together). The zone is
//! part of membership: two zones sharing one VRF must not share one overlap
//! entry, otherwise a spoofed fragment in an untrusted zone poisons a trusted
//! zone's datagram and one zone's incomplete entries exhaust the other's
//! quota (see the fairness paragraph). WITHOUT ingress interface/authority
//! beyond the zone (ECMP/LAG L4-hash routinely splits one datagram's fragments
//! across ingress interfaces in the same zone; interface-scoping would
//! under-drop the threat itself), but WITH the
//! routing domain: overlapping tenant tuples in isolated VRFs never share a receiver,
//! so a domain-free key would let tenant A drop tenant B's fragments (cross-VRF
//! poisoning). The domain is stamped by the caller from the same SSOT as session keys
//! (`forwarding::ingress_routing_domain`, or the parsed flow's stamped domain), and
//! the zone from the same ingress inputs enforcement uses
//! (`frag_ingress_authority`'s zone resolution: validated fabric override, else
//! the logical unit's configured zone, else 0).
//!
//! Lifetimes cover realistic reassembly windows, not packet spacing. Linux holds
//! incomplete datagrams up to `ipfrag_time` (30s); a 2s tracker TTL would reopen the
//! evasion by WAITING (fragments 3s apart share no tracker entry yet reassemble
//! together). Hence: 30s idle TTL (refreshed on record) + 60s absolute bound (never
//! refreshed; reclaims sustained same-key streams). Memory is cap-bounded, not
//! TTL-bounded: ≈48B key + 128B ranges (16×8B) + stamps ≈ 200B/entry × 1024 entries
//! (16 shards × 64) ≈ 200KB fixed. The TTL only sets how long attack residue squats,
//! which the absolute bound + shard caps contain.
//! Fairness (#10658, #14321, #15103, #15288): one sender (`routing_domain`, family, `src`) holds at most
//! 8 incomplete entries per shard; a `(routing_domain, ingress_zone)` pair
//! holds at most 32 entries per shard (`OVERLAP_CAP_PER_ZONE_PER_SHARD`).
//! Completed entries remain overlap anchors and do not
//! consume a sender's incomplete-datagram quota, avoiding modest-rate refusal
//! of conformant completed traffic. All entries count toward their zone's
//! 32-entry reserve; at the bound, the oldest completed anchor in that zone
//! may be reclaimed to admit a new key. At the fixed 64-entry shard cap
//! (#15103), a candidate whose zone is below its reserve reclaims the
//! globally oldest completed anchor of any zone in its routing domain
//! (`FRAG_OVERLAP_CROSS_ZONE_RECLAIMED`) instead of starving a third zone
//! behind two zones' completed anchors. When no completed anchor is
//! reclaimable (#15288), the same below-reserve candidate reclaims the
//! globally oldest incomplete anchor of a DIFFERENT zone in its routing
//! domain (`FRAG_OVERLAP_CROSS_ZONE_INCOMPLETE_RECLAIMED`) — the sole
//! exception to the never-reclaim-incomplete rule, without which two
//! zones at their reserves of incomplete anchors leave a third zone no
//! admission path at all. Failed (poisoned) anchors are never reclaimed
//! on either path, and all entries
//! remain subject to the fixed 64-entry shard cap, which stays the aggregate
//! memory bound when many zones share one shard. Post-translation entries
//! charge the sender quota to the pre-translation origin (`fairness_origin`,
//! #14127) instead of the shared pool address, so tenants translated through
//! one pool IP keep independent incomplete-fragment budgets; cross-origin
//! entries in the same downstream domain count again once an origin's
//! pending fragments have failed (the datagram is then poisoned and its
//! ranges must stay anchored — see `overlap_entry_counts_for_sender_quota`).
//! A fragment routed to a different egress domain with no address rewrite
//! also gets a post key (egress domain only), so the downstream domain's
//! anchor set is checked instead of skipped (#14127). Post-translation keys
//! inherit the arrival `ingress_zone`: the downstream receiver is reached
//! under the same ingress enforcement domain, and a translated fragment must
//! not land in a different zone's quota/membership than its arrival key.
//!
//! Failure directions (explicit — they differ from `fragment_assoc`):
//!   * Overlap/empty/overflow/capacity all fail CLOSED (drop). Sender quota
//!     applies to incomplete entries; the zone cap counts all entries in
//!     its (domain, zone) and reclaims completed anchors only at that cap;
//!     the shard cap reclaims the oldest completed anchor of any zone in
//!     the domain (#15103), or — with none reclaimable — the oldest
//!     incomplete anchor of a different zone in the domain (#15288),
//!     and otherwise fails closed. Failed anchors are never reclaimed.
//!   * Check/record SPLIT (no refused-traffic planting): the early hook only CHECKS
//!     (pure — drops overlaps before enforcement verdicts are earned); recording happens
//!     post-commit at the TX site, so only ADMITTED fragments plant ranges. A refused
//!     cross-domain tail therefore cannot poison a later same-domain tail, and dropped
//!     flood traffic leaves no residue. Admitted same-key fragments reach the same
//!     receiver anyway, so planting adds no capability beyond direct corruption;
//!     cross-VRF planting is closed by the domain key regardless.
//!   * 16-bit ident wrap (RFC 6864): near-1Gbps fragmented flows wrap idents inside
//!     the 30s window, turning strict-overlap into self-inflicted drops for a
//!     conformant sender that reuses an ident while its earlier datagram's ranges
//!     persist. Same inherent hazard `fragment_assoc` documents (RFC 8200 §4.5 unique
//!     ident per (src,dst) assumed); the blast radius here is wider (all fragmented
//!     traffic, not just NAT'd). The drop counter makes the rate observable; sustained
//!     wrap-window drops indicate a sender outpacing reassembly-safe ident spacing.
//!
//! Ranges are inline `[(u32,u32); 16]` (no per-packet alloc, #2211), coalesced on
//! insert: in-order datagrams hold 1 range (a 44-fragment 64KB datagram never
//! overflows), and a 17-fragment even/odd reordered interleave peaks at 9 disjoint
//! ranges (≤16) before coalescing as the gaps fill. The 17th disjoint range fails
//! closed (evict-oldest would be a bypass: N disjoint plants evicting the anchor).
//!
//! Post-translation identity (parent review): the pre-translation key is the ARRIVAL
//! identity, but the receiver downstream reassembles the TRANSLATED packet. Same-family
//! NAT changes addresses (two pre-keys can share one post-key), and NAT64 v6→v4
//! truncates the 32-bit ident to 16 bits (`nat64.rs`: `(frag.ident & 0xFFFF)`), so
//! `0x00010001`/`0x00020001` share a post-key. The TX-site hook therefore re-checks
//! [`translated_overlap_key`] (same byte ranges — translation preserves fragmentation
//! geometry) and drops post-collisions. IPv6's pre-key still drops the vary-able Next
//! Header as required by reassembly, but the NAT64 post-key uses the parsed Fragment
//! Header Next Header as IPv4 Protocol. Missing either NAT64 address rewrite is
//! fail-closed because no downstream key exists. Pure port-PAT (no addr change, same domain)
//! yields an identical key and is SKIPPED by the caller (same key+range would
//! self-overlap — a false positive, not a finding). NAT64 v4→v6 needs no post-check:
//! the v6 ident is the zero-extended v4 ident (`nat64.rs`: `u32::from(v4_ident)`) and
//! the v6 addrs derive injectively from the v4 session, so a post-collision implies a
//! pre-collision (fixed pool) — the pre-check already covers it.
//!
//! Hook: a pure CHECK pre-site (post-screen, pre-IPsec-passthrough, pre-flow-cache,
//! post-decap inner) plus recording post-commit at the common TX site (which re-checks
//! under the shard lock) and in the IPsec-passthrough arm (local delivery IS admission).
//! Post-screen preserves byte-for-byte drop precedence + malformation attribution;
//! pre-cache because the 5-tuple cache key has no ident. Residuals, all explicit: the
//! SYN-cookie-challenge path `continue`s before the hook (challenged SYNs plant nothing —
//! recording unproven SYNs would let spoofed floods squat shards); ESP/AH outers are
//! checked (and planted only when Passthrough-delivered) while their encrypted inner is
//! unknowable; non-IPsec LocalDelivery fragments are checked but never recorded (host
//! stack reassembles; screens still inspect their firsts).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};

use crate::hot_hash_seed::{frag_overlap_shard_seed, keyed_shard_index};
use crate::ip_proto::{PROTO_ICMP, PROTO_ICMPV6};
use crate::nat::NatDecision;

/// Overlap drops (strict overlap `max(starts) < min(ends)`, plus empty ranges).
/// Read as a delta in tests; the post-NAT hook counts to POST_NAT instead.
pub(crate) static FRAG_OVERLAP_DROPPED: AtomicU64 = AtomicU64::new(0);
/// Range-cap overflow drops (17th disjoint range, fail-closed).
pub(crate) static FRAG_OVERLAP_OVERFLOW_DROPPED: AtomicU64 = AtomicU64::new(0);
/// Capacity drops (sender/zone quota or full shard without reclaimable anchors).
pub(crate) static FRAG_OVERLAP_SHARD_FULL_DROPPED: AtomicU64 = AtomicU64::new(0);
/// Completed anchors reclaimed across zones at the shard cap (#15103):
/// a candidate whose zone is below its reserve evicts the globally oldest
/// completed anchor of any zone in its routing domain instead of ShardFull.
/// A rising rate means shards are saturated with completed anchors; the
/// evicted anchors lose overlap protection for the rest of their TTL.
pub(crate) static FRAG_OVERLAP_CROSS_ZONE_RECLAIMED: AtomicU64 = AtomicU64::new(0);
/// Incomplete anchors reclaimed across zones at the shard cap (#15288):
/// when no completed anchor of any zone is reclaimable, a candidate whose
/// own (domain, zone) is strictly below its reserve evicts the globally
/// oldest settled-incomplete anchor — `pending == 0`, not failed, ranges
/// not covering a terminal end — of a DIFFERENT zone in its routing
/// domain instead of ShardFull. This is the sole exception to the
/// "incomplete anchors are never reclaimed" invariant; it exists because
/// two zones at their 32-entry reserves of incomplete anchors otherwise
/// leave a third zone no completed anchor to reclaim (#15103) and no
/// admission path at all. A rising rate means shards are saturated with
/// other zones' incomplete datagrams; the evicted anchors lose overlap
/// protection for the rest of their TTL. Failed (poisoned) anchors are
/// never reclaimed on this path either.
pub(crate) static FRAG_OVERLAP_CROSS_ZONE_INCOMPLETE_RECLAIMED: AtomicU64 = AtomicU64::new(0);
/// Post-translation overlap drops (TX-site hook, translated key).
pub(crate) static FRAG_OVERLAP_POST_NAT_DROPPED: AtomicU64 = AtomicU64::new(0);
/// Absolute-lifetime evictions (sustained same-key streams).
pub(crate) static FRAG_OVERLAP_MAX_LIFETIME_EVICTIONS: AtomicU64 = AtomicU64::new(0);

pub(crate) const OVERLAP_SHARDS: usize = 16;
const _: () = assert!(OVERLAP_SHARDS >= 2 && OVERLAP_SHARDS.is_power_of_two());
pub(crate) const OVERLAP_CAP_PER_SHARD: usize = 64;
/// Max entries one sender holds per shard (#10658).
pub(crate) const OVERLAP_CAP_PER_SENDER_PER_SHARD: usize = 8;
/// A `(routing_domain, ingress_zone)` pair can use at most half a shard
/// (#14321); completed entries in that zone may be reclaimed at this limit.
/// The name is kept as `OVERLAP_CAP_PER_DOMAIN_PER_SHARD` alias for existing
/// callers/tests that read the per-domain reserve value.
pub(crate) const OVERLAP_CAP_PER_ZONE_PER_SHARD: usize = OVERLAP_CAP_PER_SHARD / 2;
pub(crate) const OVERLAP_CAP_PER_DOMAIN_PER_SHARD: usize = OVERLAP_CAP_PER_ZONE_PER_SHARD;
/// 30s idle TTL — covers the Linux `ipfrag_time` reassembly window (see docs).
pub(crate) const OVERLAP_TTL_NS: u64 = 30_000_000_000;
/// 60s absolute bound from first sighting — never refreshed by later fragments.
pub(crate) const OVERLAP_MAX_LIFETIME_NS: u64 = 60_000_000_000;
/// Max disjoint ranges per datagram; the 17th fails closed.
pub(crate) const OVERLAP_MAX_RANGES: usize = 16;

/// Receiver's reassembly key + routing domain + ingress zone (#14321).
/// `protocol` is the IPv4 Protocol byte;
/// for IPv6 it is always 0 (dropped from the key — see module docs). `routing_domain`
/// is stamped by the caller (flow's stamped domain, else the ingress SSOT); parse
/// leaves it 0. `ingress_zone` is stamped by the caller from the same ingress
/// inputs enforcement uses (validated fabric override, else the logical
/// unit's configured zone, else 0); parse leaves it 0. It IS part of overlap
/// membership and of the per-zone quota: two zones sharing one VRF must not
/// share one entry or one reserve. `fairness_origin` is `None` on arrival keys; post-translation
/// keys carry the arrival sender for quota accounting only — it never
/// participates in overlap membership (see the field doc).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct OverlapKey {
    pub(crate) addr_family: u8,
    pub(crate) src: IpAddr,
    pub(crate) dst: IpAddr,
    pub(crate) ident: u32,
    pub(crate) protocol: u8,
    pub(crate) routing_domain: u32,
    /// Ingress security zone (#14321); see the struct doc. Part of
    /// membership (`overlap_same_datagram`) and of the per-zone quota.
    pub(crate) ingress_zone: u16,
    /// Pre-translation arrival identity, set only on keys derived by
    /// `translated_overlap_key`. It is NOT part of the reassembly key:
    /// downstream receivers merge fragments by the translated tuple
    /// alone, so overlap membership must stay keyed on the fields
    /// above. The origin only scopes the sender-fairness quota
    /// (`overlap_sender`) so tenants sharing one translated source do
    /// not share an incomplete-fragment budget (#14127). `None` on
    /// arrival keys.
    pub(crate) fairness_origin: Option<(u32, u8, IpAddr)>,
}

#[derive(Clone, Copy)]
struct OverlapEntry {
    key: OverlapKey,
    ranges: [(u32, u32); OVERLAP_MAX_RANGES],
    len: u8,
    terminal_end: Option<u32>,
    /// Revision of the current range set. Completion snapshots use this to
    /// reject stale releases after a concurrent mutation.
    revision: u64,
    /// Incarnation of this key's entry. Admission tokens use this stable value
    /// while several queued fragments commit out of order.
    incarnation: u64,
    /// Number of recorded fragments whose final admission outcome is pending.
    pending: u32,
    /// A failed admission makes this datagram permanently ineligible for
    /// completion reclaim. Its ranges remain as overlap protection until TTL.
    failed: bool,
    deadline_ns: u64,
    created_ns: u64,
}

/// Tri-state L3 parse: proven-non-fragment and proven-fragment drive the table,
/// while `Unreadable` (truncated headers) must skip the table AND the flow-cache —
/// an unreadable packet is not a proven non-fragment, so caching it would let a
/// fragment ride the ident-less 5-tuple fast path past both overlap and assoc installs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OverlapParse {
    NonFragment,
    Fragment(OverlapKey, u8, u32, u32, bool),
    Unreadable,
}

/// Cross-worker overlap tracker. Cheap to `Clone` (Arc-backed shards).
#[derive(Clone)]
pub(crate) struct OverlapTracker {
    shards: Arc<Vec<Mutex<Vec<OverlapEntry>>>>,
    next_revision: Arc<AtomicU64>,
    seed: u64,
}

impl std::fmt::Debug for OverlapTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OverlapTracker")
    }
}

impl Default for OverlapTracker {
    fn default() -> Self {
        Self::new()
    }
}

fn ip_octets(ip: IpAddr, out: &mut [u8; 16]) -> usize {
    match ip {
        IpAddr::V4(v4) => {
            out[..4].copy_from_slice(&v4.octets());
            4
        }
        IpAddr::V6(v6) => {
            out.copy_from_slice(&v6.octets());
            16
        }
    }
}

/// Seeded FNV-1a plus a keyed splitmix64 finalizer over the coarse
/// `(family, src, dst, ident)` digest. Protocol and routing domain are deliberately
/// excluded so same-datagram candidates (hostile proto-varying v4, cross-domain floods)
/// co-locate in one shard; membership is by full-key equality.
pub(crate) fn overlap_shard_index_seeded(key: &OverlapKey, seed: u64) -> usize {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut mix = |b: u8| {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    };
    mix(key.addr_family);
    let mut buf = [0u8; 16];
    let n = ip_octets(key.src, &mut buf);
    for &b in &buf[..n] {
        mix(b);
    }
    let n = ip_octets(key.dst, &mut buf);
    for &b in &buf[..n] {
        mix(b);
    }
    for b in key.ident.to_be_bytes() {
        mix(b);
    }
    keyed_shard_index(h, seed, 0x6f76_6572_6c61_7001, OVERLAP_SHARDS)
}

#[cfg(test)]
pub(crate) fn overlap_shard_index(key: &OverlapKey) -> usize {
    overlap_shard_index_seeded(key, frag_overlap_shard_seed())
}
/// Fairness identity (#10658): the admitted sender. `dst`/`ident`/`protocol` are
/// excluded — keying them would let one sender mint fresh quota by varying the
/// destination, ident, or (v4) protocol byte. On post-translation keys the
/// identity is the pre-translation arrival sender (`fairness_origin`, #14127):
/// the translated `src` is a shared pool address, so keying the quota on it
/// would let one tenant's incomplete fragments exhaust every other tenant
/// translated through the same pool address. The translated tuple still keys
/// overlap membership (the downstream receiver reassembles on it alone), and
/// an origin-less (arrival) key keys its quota on its own tuple.
#[inline]
fn overlap_sender(key: &OverlapKey) -> (u32, u8, IpAddr) {
    key.fairness_origin
        .unwrap_or((key.routing_domain, key.addr_family, key.src))
}

/// Reassembly membership ignores `fairness_origin`: downstream
/// receivers merge by the translated tuple alone, so two tenants'
/// fragments for one downstream datagram must find the same entry
/// even though their fairness origins differ (#14127). Membership DOES
/// include `ingress_zone` (#14321): fragments arriving in different zones
/// are adjudicated under different enforcement domains, and a fragment in
/// one zone must not poison or merge into another zone's entry even when
/// the receiver tuple coincides. Post-translation keys inherit the
/// arrival zone, so a datagram keeps one membership identity across NAT.
/// Callers comparing a pre-translation key with its derived post key
/// MUST use this datagram identity, never derived `PartialEq`:
/// `translated_overlap_key` stamps `fairness_origin: Some(..)` on every
/// post key while arrival keys carry `None`, so `post != pre` is always
/// true and an identity address rewrite would re-record (and drop)
/// its own datagram (#15788).
#[inline]
pub(crate) fn overlap_same_datagram(a: &OverlapKey, b: &OverlapKey) -> bool {
    a.addr_family == b.addr_family
        && a.src == b.src
        && a.dst == b.dst
        && a.ident == b.ident
        && a.protocol == b.protocol
        && a.routing_domain == b.routing_domain
        && a.ingress_zone == b.ingress_zone
}

#[inline]
fn overlap_entry_live(e: &OverlapEntry, now_ns: u64, lifetime_evictions: &mut u64) -> bool {
    let idle_live = e.deadline_ns > now_ns;
    let absolutely_live = now_ns.saturating_sub(e.created_ns) < OVERLAP_MAX_LIFETIME_NS;
    if idle_live && !absolutely_live {
        FRAG_OVERLAP_MAX_LIFETIME_EVICTIONS.fetch_add(1, Ordering::Relaxed);
        *lifetime_evictions += 1;
    }
    idle_live && absolutely_live
}

#[inline]
fn ranges_cover_terminal(e: &OverlapEntry, terminal_end: u32) -> bool {
    if e.len == 0 || e.ranges[0].0 != 0 {
        return false;
    }
    let mut covered_end = 0u32;
    for &(start, end) in e.ranges.iter().take(e.len as usize) {
        if start > covered_end {
            return false;
        }
        covered_end = covered_end.max(end);
    }
    covered_end == terminal_end
}

#[inline]
fn overlap_entry_complete(e: &OverlapEntry) -> bool {
    e.pending == 0
        && !e.failed
        && e.terminal_end
            .is_some_and(|terminal_end| ranges_cover_terminal(e, terminal_end))
}
/// An anchor whose datagram never completed and is no longer in flight:
/// every recorded fragment has settled (`pending == 0`), it has not
/// failed, and its ranges do not cover a terminal end — the settled
/// counterpart of a completed anchor. This is the class the cross-zone
/// incomplete reclaim (#15288) may evict, and only for a candidate from
/// a different zone below its own reserve. Still-pending anchors
/// (`pending > 0`) are outside this class; the fallback's
/// `pending == 0` gate leaves them anchored for settlement.
#[inline]
fn overlap_entry_incomplete(e: &OverlapEntry) -> bool {
    e.pending == 0 && !e.failed && !overlap_entry_complete(e)
}

/// Whether an existing entry counts against a candidate's sender fairness
/// quota. Completed entries never count (#13937). An incomplete entry
/// counts when it shares the candidate's origin (same tenant, same
/// arrival identity) — always true when the candidate has no origin
/// (arrival path: `#10658` behaviour unchanged). Origin-distinct
/// incomplete entries count only once the candidate origin's pending
/// fragments have failed admission (#14127): origin-keying alone would
/// let two tenants reuse one downstream datagram's ident (e.g. NAT64's
/// 16-bit truncation), extend each other's ranges, and complete the
/// datagram jointly, bypassing the anchored entry's overlap
/// protection. After a failure the datagram is poisoned anyway, so
/// reverting to the shared budget for incomplete entries of the same
/// downstream routing domain restores the pre-#14127 cross-tenant
/// protection without reintroducing the pre-failure starvation.
#[inline]
fn overlap_entry_counts_for_sender_quota(
    e: &OverlapEntry,
    candidate: &OverlapKey,
    sender: (u32, u8, IpAddr),
    poisoned: bool,
) -> bool {
    if overlap_entry_complete(e) {
        return false;
    }
    match candidate.fairness_origin {
        None => overlap_sender(&e.key) == sender,
        Some(_) => {
            e.key.fairness_origin == candidate.fairness_origin
                || (poisoned
                    && !e.failed
                    && e.key.routing_domain == candidate.routing_domain)
        }
    }
}
/// Reject ranges that conflict with an already observed terminal fragment.
/// Once a terminal end is known, every range must end at/before it; only the
/// terminal fragment itself may end exactly there. When terminal is first
/// observed, existing ranges may not extend past its end.
#[inline]
fn terminal_conflict(e: &OverlapEntry, end: u32, is_last: bool) -> bool {
    if let Some(terminal_end) = e.terminal_end {
        end > terminal_end || (is_last && end != terminal_end) || (!is_last && end == terminal_end)
    } else {
        is_last
            && e.ranges
                .iter()
                .take(e.len as usize)
                .any(|&(_, range_end)| range_end > end)
    }
}

#[inline]
fn completion_token(e: &OverlapEntry) -> Option<OverlapCompletionToken> {
    let terminal_end = e.terminal_end?;
    ranges_cover_terminal(e, terminal_end).then_some(OverlapCompletionToken {
        key: e.key,
        terminal_end,
        revision: e.revision,
    })
}

/// Dry-run merge of `new` into `len` ranges: sort by start, coalesce adjacency
/// (`nxt.0 <= cur.1`), return the merged set — or `Err(())` on would-overflow.
/// Shared by [`OverlapTracker::check_overlap`] (discards) and
/// [`OverlapTracker::check_and_record`] (commits) so their verdicts agree by construction.
fn merge_ranges(
    ranges: &[(u32, u32); OVERLAP_MAX_RANGES],
    len: usize,
    new: (u32, u32),
) -> Result<([(u32, u32); OVERLAP_MAX_RANGES], u8), ()> {
    let mut tmp = [(0u32, 0u32); OVERLAP_MAX_RANGES + 1];
    tmp[..len].copy_from_slice(&ranges[..len]);
    tmp[len] = new;
    let n = len + 1;
    // Insertion sort by start (n <= 17, tiny).
    for i in 1..n {
        let mut j = i;
        while j > 0 && tmp[j].0 < tmp[j - 1].0 {
            tmp.swap(j, j - 1);
            j -= 1;
        }
    }
    let mut out = [(0u32, 0u32); OVERLAP_MAX_RANGES];
    let mut out_len = 0usize;
    let mut cur = tmp[0];
    for &nxt in tmp.iter().take(n).skip(1) {
        if nxt.0 <= cur.1 {
            if nxt.1 > cur.1 {
                cur.1 = nxt.1;
            }
        } else {
            if out_len >= OVERLAP_MAX_RANGES {
                return Err(());
            }
            out[out_len] = cur;
            out_len += 1;
            cur = nxt;
        }
    }
    if out_len >= OVERLAP_MAX_RANGES {
        return Err(());
    }
    out[out_len] = cur;
    Ok((out, (out_len + 1) as u8))
}

/// Classification returned by the detailed overlap APIs. The global atomics
/// remain the alerting path; callers use this reason to batch the same event
/// onto their binding-local telemetry without an atomic operation per packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OverlapDropReason {
    Overlap,
    Overflow,
    /// Fairness quota or shard-capacity refusal; no live entry was evicted.
    ShardFull,
}

/// A reservation for one fragment that was recorded but has not yet reached
/// its final forwarding outcome. The entry incarnation remains stable while
/// queued fragments commit out of order. The token is intentionally non-Copy:
/// settlement transfers ownership so a caller cannot settle the same
/// reservation twice.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct OverlapAdmissionToken {
    key: OverlapKey,
    incarnation: u64,
}

/// A pair of reservations for the arrival and translated reassembly identities.
/// The pair owns the tracker handle so every queue/drop path has RAII failure
/// semantics; only an explicit commit disarms the tokens.
pub(crate) struct OverlapAdmissionTokens {
    tracker: OverlapTracker,
    pub(crate) pre: Option<OverlapAdmissionToken>,
    pub(crate) post: Option<OverlapAdmissionToken>,
}

impl std::fmt::Debug for OverlapAdmissionTokens {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OverlapAdmissionTokens")
            .field("pre", &self.pre)
            .field("post", &self.post)
            .finish()
    }
}

impl OverlapAdmissionTokens {
    pub(crate) fn new(
        tracker: OverlapTracker,
        pre: Option<OverlapAdmissionToken>,
        post: Option<OverlapAdmissionToken>,
    ) -> Self {
        Self { tracker, pre, post }
    }

    /// Final TX submission accepted both identities. This consumes the
    /// reservations without invoking their failure-on-drop guard.
    pub(crate) fn commit(&mut self) {
        if let Some(token) = self.pre.take() {
            self.tracker.commit_admission(token);
        }
        if let Some(token) = self.post.take() {
            self.tracker.commit_admission(token);
        }
    }
}

impl Drop for OverlapAdmissionTokens {
    fn drop(&mut self) {
        if let Some(token) = self.pre.take() {
            self.tracker.fail_admission(token);
        }
        if let Some(token) = self.post.take() {
            self.tracker.fail_admission(token);
        }
    }
}

/// A completion snapshot held until every recorded fragment has settled.
/// Reclaim validates the entry's incarnation under the shard lock, so a
/// concurrent worker cannot cause a stale completion to delete newer ranges.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OverlapCompletionToken {
    key: OverlapKey,
    terminal_end: u32,
    revision: u64,
}

#[derive(Debug)]
pub(crate) struct OverlapCheckResult {
    pub(crate) dropped: bool,
    pub(crate) reason: Option<OverlapDropReason>,
    pub(crate) lifetime_evictions: u64,
    /// Snapshot for diagnostics/tests; production settlement uses `admission`
    /// because completion can be observed before other fragments settle.
    pub(crate) completion: Option<OverlapCompletionToken>,
    /// Reservation ownership that must be committed or failed exactly once.
    pub(crate) admission: Option<OverlapAdmissionToken>,
    /// Tracker used by the drop guard when a caller discards an admission
    /// without transferring it to a final forwarding owner.
    pub(crate) tracker: Option<OverlapTracker>,
}

impl Default for OverlapCheckResult {
    fn default() -> Self {
        Self {
            dropped: false,
            reason: None,
            lifetime_evictions: 0,
            completion: None,
            admission: None,
            tracker: None,
        }
    }
}

impl PartialEq for OverlapCheckResult {
    fn eq(&self, other: &Self) -> bool {
        self.dropped == other.dropped
            && self.reason == other.reason
            && self.lifetime_evictions == other.lifetime_evictions
            && self.completion == other.completion
            && self.admission == other.admission
    }
}

impl Eq for OverlapCheckResult {}

impl Drop for OverlapCheckResult {
    fn drop(&mut self) {
        if let (Some(tracker), Some(token)) = (self.tracker.as_ref(), self.admission.take()) {
            tracker.fail_admission(token);
        }
    }
}

impl OverlapTracker {
    pub(crate) fn new() -> Self {
        Self::with_seed(frag_overlap_shard_seed())
    }

    fn with_seed(seed: u64) -> Self {
        let mut shards = Vec::with_capacity(OVERLAP_SHARDS);
        for _ in 0..OVERLAP_SHARDS {
            shards.push(Mutex::new(Vec::with_capacity(OVERLAP_CAP_PER_SHARD)));
        }
        Self {
            shards: Arc::new(shards),
            next_revision: Arc::new(AtomicU64::new(1)),
            seed,
        }
    }

    #[inline]
    fn shard_index(&self, key: &OverlapKey) -> usize {
        overlap_shard_index_seeded(key, self.seed)
    }

    /// Pure overlap CHECK: same verdict [`Self::check_and_record`] would return, but
    /// records nothing, refreshes nothing, allocates nothing (no shard-full condition).
    /// The early (pre-enforcement) hook uses this — dropping an overlap before policy/NAT
    /// verdicts are earned — while recording happens post-commit at the TX site, so
    /// refused traffic never plants ranges (no cross-domain plant-then-duplicate
    /// poisoning, no flood-driven squat behind drops).
    pub(crate) fn check_overlap(
        &self,
        key: OverlapKey,
        start: u32,
        end: u32,
        now_ns: u64,
        drop_counter: &AtomicU64,
    ) -> bool {
        let result =
            self.check_overlap_fragment_detailed(key, start, end, false, now_ns, drop_counter);
        result.dropped
    }

    pub(crate) fn check_overlap_fragment(
        &self,
        key: OverlapKey,
        start: u32,
        end: u32,
        is_last: bool,
        now_ns: u64,
        drop_counter: &AtomicU64,
    ) -> bool {
        let result =
            self.check_overlap_fragment_detailed(key, start, end, is_last, now_ns, drop_counter);
        result.dropped
    }

    pub(crate) fn check_overlap_detailed(
        &self,
        key: OverlapKey,
        start: u32,
        end: u32,
        now_ns: u64,
        drop_counter: &AtomicU64,
    ) -> OverlapCheckResult {
        self.check_overlap_fragment_detailed(key, start, end, false, now_ns, drop_counter)
    }

    pub(crate) fn check_overlap_fragment_detailed(
        &self,
        key: OverlapKey,
        start: u32,
        end: u32,
        is_last: bool,
        now_ns: u64,
        drop_counter: &AtomicU64,
    ) -> OverlapCheckResult {
        if start >= end {
            drop_counter.fetch_add(1, Ordering::Relaxed);
            return OverlapCheckResult {
                dropped: true,
                reason: Some(OverlapDropReason::Overlap),
                lifetime_evictions: 0,
                completion: None,
                admission: None,
                tracker: None,
            };
        }
        let idx = self.shard_index(&key);
        let mut shard = self.shards[idx]
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut lifetime_evictions = 0;
        shard.retain(|e| overlap_entry_live(e, now_ns, &mut lifetime_evictions));
        let Some(pos) = shard.iter().position(|e| overlap_same_datagram(&e.key, &key)) else {
            return OverlapCheckResult {
                dropped: false,
                reason: None,
                lifetime_evictions,
                completion: None,
                admission: None,
                tracker: None,
            };
        };
        if terminal_conflict(&shard[pos], end, is_last) {
            drop_counter.fetch_add(1, Ordering::Relaxed);
            return OverlapCheckResult {
                dropped: true,
                reason: Some(OverlapDropReason::Overlap),
                lifetime_evictions,
                completion: None,
                admission: None,
                tracker: None,
            };
        }
        for i in 0..(shard[pos].len as usize) {
            let (rs, re) = shard[pos].ranges[i];
            if start.max(rs) < end.min(re) {
                drop_counter.fetch_add(1, Ordering::Relaxed);
                return OverlapCheckResult {
                    dropped: true,
                    reason: Some(OverlapDropReason::Overlap),
                    lifetime_evictions,
                    completion: None,
                    admission: None,
                    tracker: None,
                };
            }
        }
        if merge_ranges(&shard[pos].ranges, shard[pos].len as usize, (start, end)).is_err() {
            FRAG_OVERLAP_OVERFLOW_DROPPED.fetch_add(1, Ordering::Relaxed);
            return OverlapCheckResult {
                dropped: true,
                reason: Some(OverlapDropReason::Overflow),
                lifetime_evictions,
                completion: None,
                admission: None,
                tracker: None,
            };
        }
        OverlapCheckResult {
            dropped: false,
            reason: None,
            lifetime_evictions,
            completion: None,
            admission: None,
            tracker: None,
        }
    }

    /// Late (post-commit) check AND record: re-checks `(start, end)` under the shard lock
    /// (closing the cross-worker race between the early [`Self::check_overlap`] and the
    /// commit), then records on pass (coalescing adjacency, refreshing the idle deadline,
    /// LRU-refreshing). Returns `true` (drop, entry left byte-identical) on: strict
    /// overlap, empty range (counted to `drop_counter`), range-cap overflow (`OVERFLOW`),
    /// or shard-full (`SHARD_FULL`). Only admitted (forwarding) fragments reach this —
    /// refused traffic never plants ranges. The caller selects `drop_counter`
    /// (`DROPPED` for the pre-translation key, `POST_NAT_DROPPED` for the translated key).
    pub(crate) fn check_and_record(
        &self,
        key: OverlapKey,
        start: u32,
        end: u32,
        now_ns: u64,
        drop_counter: &AtomicU64,
    ) -> bool {
        let mut result =
            self.check_and_record_fragment_detailed(key, start, end, false, now_ns, drop_counter);
        let dropped = result.dropped;
        if let Some(admission) = result.admission.take() {
            self.commit_admission(admission);
        }
        dropped
    }

    pub(crate) fn check_and_record_fragment(
        &self,
        key: OverlapKey,
        start: u32,
        end: u32,
        is_last: bool,
        now_ns: u64,
        drop_counter: &AtomicU64,
    ) -> bool {
        let mut result =
            self.check_and_record_fragment_detailed(key, start, end, is_last, now_ns, drop_counter);
        let dropped = result.dropped;
        if let Some(admission) = result.admission.take() {
            self.commit_admission(admission);
        }
        dropped
    }

    pub(crate) fn check_and_record_detailed(
        &self,
        key: OverlapKey,
        start: u32,
        end: u32,
        now_ns: u64,
        drop_counter: &AtomicU64,
    ) -> OverlapCheckResult {
        self.check_and_record_fragment_detailed(key, start, end, false, now_ns, drop_counter)
    }

    pub(crate) fn check_and_record_fragment_detailed(
        &self,
        key: OverlapKey,
        start: u32,
        end: u32,
        is_last: bool,
        now_ns: u64,
        drop_counter: &AtomicU64,
    ) -> OverlapCheckResult {
        if start >= end {
            drop_counter.fetch_add(1, Ordering::Relaxed);
            return OverlapCheckResult {
                dropped: true,
                reason: Some(OverlapDropReason::Overlap),
                lifetime_evictions: 0,
                completion: None,
                admission: None,
                tracker: None,
            };
        }
        let idx = self.shard_index(&key);
        let mut shard = self.shards[idx]
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut lifetime_evictions = 0;
        shard.retain(|e| overlap_entry_live(e, now_ns, &mut lifetime_evictions));
        if let Some(pos) = shard.iter().position(|e| overlap_same_datagram(&e.key, &key)) {
            if terminal_conflict(&shard[pos], end, is_last) {
                drop_counter.fetch_add(1, Ordering::Relaxed);
                return OverlapCheckResult {
                    dropped: true,
                    reason: Some(OverlapDropReason::Overlap),
                    lifetime_evictions,
                    completion: None,
                    admission: None,
                    tracker: None,
                };
            }
            for i in 0..(shard[pos].len as usize) {
                let (rs, re) = shard[pos].ranges[i];
                if start.max(rs) < end.min(re) {
                    drop_counter.fetch_add(1, Ordering::Relaxed);
                    return OverlapCheckResult {
                        dropped: true,
                        reason: Some(OverlapDropReason::Overlap),
                        lifetime_evictions,
                        completion: None,
                        admission: None,
                        tracker: None,
                    };
                }
            }
            // No overlap: merge via the shared dry-run, then commit. The overflow drop
            // leaves the live entry untouched (no MRU move, no deadline refresh).
            match merge_ranges(&shard[pos].ranges, shard[pos].len as usize, (start, end)) {
                Err(()) => {
                    FRAG_OVERLAP_OVERFLOW_DROPPED.fetch_add(1, Ordering::Relaxed);
                    return OverlapCheckResult {
                        dropped: true,
                        reason: Some(OverlapDropReason::Overflow),
                        lifetime_evictions,
                        completion: None,
                        admission: None,
                        tracker: None,
                    };
                }
                Ok((ranges, len)) => {
                    let mut e = shard.remove(pos);
                    e.ranges = ranges;
                    e.len = len;
                    if is_last && e.terminal_end.is_none() {
                        e.terminal_end = Some(end);
                    }
                    e.revision = self.next_revision.fetch_add(1, Ordering::Relaxed);
                    e.pending = e.pending.saturating_add(1);
                    e.deadline_ns = now_ns.saturating_add(OVERLAP_TTL_NS);
                    // created_ns NEVER refreshed (absolute bound from first sighting).
                    let completion = completion_token(&e);
                    let admission = Some(OverlapAdmissionToken {
                        key: e.key,
                        incarnation: e.incarnation,
                    });
                    shard.push(e);
                    return OverlapCheckResult {
                        dropped: false,
                        reason: None,
                        lifetime_evictions,
                        completion,
                        admission,
                        tracker: Some(self.clone()),
                    };
                }
            }
        }
        // #10658: incomplete entries consume sender fairness quotas, and all
        // entries count against their (routing_domain, ingress_zone)
        // reserve (#14321). Reclaiming the
        // oldest completed anchor in that zone at that limit lets #13937 conformant traffic
        // continue without allowing completions to bypass zone fairness,
        // and without letting one zone's fill starve another zone sharing
        // the same VRF.
        // #14127: post-translation candidates key the sender quota on their
        // pre-translation origin, so tenants sharing one pool address do not
        // share a budget; cross-origin entries in the same downstream
        // domain count again once this origin's pending fragments have
        // failed (poisoned — see `overlap_entry_counts_for_sender_quota`),
        // and the zone reserve below always counts the downstream
        // (domain, arrival-zone) pair (post keys inherit the arrival zone).
        let sender = overlap_sender(&key);
        let poisoned = key.fairness_origin.is_some()
            && shard.iter().any(|e| {
                overlap_sender(&e.key) == sender
                    && e.key.fairness_origin == key.fairness_origin
                    && e.failed
            });
        let mut sender_entries = 0usize;
        let mut zone_entries = 0usize;
        for e in shard.iter() {
            if overlap_entry_counts_for_sender_quota(e, &key, sender, poisoned) {
                sender_entries += 1;
            }
            if e.key.routing_domain == key.routing_domain
                && e.key.ingress_zone == key.ingress_zone
            {
                zone_entries += 1;
            }
        }
        if sender_entries >= OVERLAP_CAP_PER_SENDER_PER_SHARD {
            FRAG_OVERLAP_SHARD_FULL_DROPPED.fetch_add(1, Ordering::Relaxed);
            return OverlapCheckResult {
                dropped: true,
                reason: Some(OverlapDropReason::ShardFull),
                lifetime_evictions,
                completion: None,
                admission: None,
                tracker: None,
            };
        }
        if zone_entries >= OVERLAP_CAP_PER_ZONE_PER_SHARD {
            let mut reclaim_pos = None;
            let mut oldest_created_ns = u64::MAX;
            for (pos, entry) in shard.iter().enumerate() {
                if entry.key.routing_domain == key.routing_domain
                    && entry.key.ingress_zone == key.ingress_zone
                    && overlap_entry_complete(entry)
                    && entry.created_ns < oldest_created_ns
                {
                    reclaim_pos = Some(pos);
                    oldest_created_ns = entry.created_ns;
                }
            }
            let Some(pos) = reclaim_pos else {
                FRAG_OVERLAP_SHARD_FULL_DROPPED.fetch_add(1, Ordering::Relaxed);
                return OverlapCheckResult {
                    dropped: true,
                    reason: Some(OverlapDropReason::ShardFull),
                    lifetime_evictions,
                    completion: None,
                    admission: None,
                    tracker: None,
                };
            };
            shard.remove(pos);
        }
        if shard.len() >= OVERLAP_CAP_PER_SHARD {
            // #15103 (A74-02): the shard is full but the candidate's zone is
            // below its own reserve (otherwise it already reclaimed or
            // refused above). The occupants are other zones' entries; a
            // third zone must not be starved by two zones filling the shard
            // with completed anchors. Reclaim the globally oldest COMPLETED
            // anchor of ANY (domain, zone) — the same anchor class the
            // per-zone path reclaims (pending==0, not failed, ranges cover
            // the terminal end). With no completed anchor reclaimable,
            // the #15288 fallback below reclaims the globally oldest
            // INCOMPLETE anchor of a different zone in the domain; a
            // shard whose only other-zone anchors are failed still
            // refuses fail-closed. Per-zone fairness is preserved: the
            // candidate's zone is below 32, and no zone can exceed 32
            // because its own-zone check above runs first (this branch
            // only ever removes another zone's anchor or a completed
            // anchor, never admits past a zone cap).
            let mut reclaim_pos = None;
            let mut oldest_created_ns = u64::MAX;
            for (pos, entry) in shard.iter().enumerate() {
                if entry.key.routing_domain == key.routing_domain
                    && overlap_entry_complete(entry)
                    && entry.created_ns < oldest_created_ns
                {
                    reclaim_pos = Some(pos);
                    oldest_created_ns = entry.created_ns;
                }
            }
            let Some(pos) = reclaim_pos.or_else(|| {
                // #15288 (gemini D4-01): no completed anchor of any zone
                // is reclaimable — the shard is held by incomplete (and
                // possibly failed) anchors. The candidate's own
                // (domain, zone) is strictly below its reserve, so the
                // per-zone check above has already refused to let it
                // take a 33rd slot; admitting it here can only displace
                // a DIFFERENT zone's anchor, never grow its own zone
                // past 32. Reclaim the globally oldest settled-INCOMPLETE anchor
                // of a different zone in the same routing domain
                // (`overlap_entry_incomplete`: `pending == 0`, not
                // failed, not covering a terminal end). Failed anchors
                // are poison — their ranges must stay anchored — and
                // are never reclaimed on this path either. This is the sole
                // exception to "incomplete anchors are never reclaimed":
                // without it, two zones at their reserves of incomplete
                // anchors leave a third zone no admission path at all,
                // defeating the #14321 per-zone reserve for exactly the
                // traffic it exists to protect. The evicted anchor loses
                // overlap protection for the rest of its TTL — the same
                // trade #14321/#15103 accept for completed anchors.
                let mut fallback_pos = None;
                let mut fallback_oldest_ns = u64::MAX;
                for (pos, entry) in shard.iter().enumerate() {
                    if entry.key.routing_domain == key.routing_domain
                        && entry.key.ingress_zone != key.ingress_zone
                        && overlap_entry_incomplete(entry)
                        && entry.created_ns < fallback_oldest_ns
                    {
                        fallback_pos = Some(pos);
                        fallback_oldest_ns = entry.created_ns;
                    }
                }
                if fallback_pos.is_some() {
                    FRAG_OVERLAP_CROSS_ZONE_INCOMPLETE_RECLAIMED.fetch_add(1, Ordering::Relaxed);
                }
                fallback_pos
            }) else {
                FRAG_OVERLAP_SHARD_FULL_DROPPED.fetch_add(1, Ordering::Relaxed);
                return OverlapCheckResult {
                    dropped: true,
                    reason: Some(OverlapDropReason::ShardFull),
                    lifetime_evictions,
                    completion: None,
                    admission: None,
                    tracker: None,
                };
            };
            if reclaim_pos.is_some() {
                FRAG_OVERLAP_CROSS_ZONE_RECLAIMED.fetch_add(1, Ordering::Relaxed);
            }
            shard.remove(pos);
        }
        let mut ranges = [(0u32, 0u32); OVERLAP_MAX_RANGES];
        ranges[0] = (start, end);
        let incarnation = self.next_revision.fetch_add(1, Ordering::Relaxed);
        let entry = OverlapEntry {
            key,
            ranges,
            len: 1,
            terminal_end: is_last.then_some(end),
            revision: incarnation,
            incarnation,
            pending: 1,
            failed: false,
            deadline_ns: now_ns.saturating_add(OVERLAP_TTL_NS),
            created_ns: now_ns,
        };
        let completion = completion_token(&entry);
        let admission = Some(OverlapAdmissionToken { key, incarnation });
        shard.push(entry);
        OverlapCheckResult {
            dropped: false,
            reason: None,
            lifetime_evictions,
            completion,
            admission,
            tracker: Some(self.clone()),
        }
    }

    /// Settle a recorded fragment after its final TX admission succeeds.
    ///
    /// #13680 (D12-07): when every recorded fragment has settled, none
    /// failed, and the ranges cover the terminal end, the datagram is
    /// complete — but the entry is NOT deleted here. Deleting it on
    /// completion reopened overlap detection for the same ident: a
    /// replayed/overlapping fragment arriving within the reassembly
    /// window (e.g. a decoy tail that never reached the destination)
    /// would start a fresh entry and bypass the recorded ranges. The
    /// completed ranges are held as overlap anchors until the idle TTL
    /// (`OVERLAP_TTL_NS`, refreshed by each recorded fragment) or the
    /// 60s absolute lifetime expires them via the usual liveness sweep.
    /// Completed anchors do not consume sender quotas, but count toward the
    /// (domain, zone) reserve and may be reclaimed there. Incomplete anchors are
    /// evicted for capacity only by the cross-zone incomplete reclaim (#15288).
    ///
    /// Returns `true` when this settlement completes the datagram
    /// (all settled, no failure, ranges cover the terminal end); the
    /// entry itself remains recorded either way.
    pub(crate) fn commit_admission(&self, token: OverlapAdmissionToken) -> bool {
        let idx = self.shard_index(&token.key);
        let mut shard = self.shards[idx]
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(pos) = shard.iter().position(|e| overlap_same_datagram(&e.key, &token.key)) else {
            return false;
        };
        let e = &mut shard[pos];
        if e.incarnation != token.incarnation || e.pending == 0 {
            return false;
        }
        e.pending -= 1;
        if e.pending == 0 && !e.failed {
            if let Some(terminal_end) = e.terminal_end {
                if ranges_cover_terminal(e, terminal_end) {
                    return true;
                }
            }
        }
        false
    }

    /// Settle a recorded fragment after a final admission/drop failure.
    /// Failed datagrams retain their ranges as overlap protection but can
    /// never be reclaimed by later completion coverage.
    pub(crate) fn fail_admission(&self, token: OverlapAdmissionToken) -> bool {
        let idx = self.shard_index(&token.key);
        let mut shard = self.shards[idx]
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(pos) = shard.iter().position(|e| overlap_same_datagram(&e.key, &token.key)) else {
            return false;
        };
        let e = &mut shard[pos];
        if e.incarnation != token.incarnation || e.pending == 0 {
            return false;
        }
        e.pending -= 1;
        e.failed = true;
        true
    }

    /// Test-only compatibility for the snapshot API. Production settlement
    /// uses [`Self::commit_admission`] so queued fragments cannot reclaim early.
    #[cfg(test)]
    pub(crate) fn release_completed(&self, token: OverlapCompletionToken) -> bool {
        let idx = self.shard_index(&token.key);
        let mut shard = self.shards[idx]
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(pos) = shard.iter().position(|e| overlap_same_datagram(&e.key, &token.key)) else {
            return false;
        };
        let e = &shard[pos];
        if e.revision != token.revision
            || e.terminal_end != Some(token.terminal_end)
            || !ranges_cover_terminal(e, token.terminal_end)
            || e.pending != 0
            || e.failed
        {
            return false;
        }
        shard.remove(pos);
        true
    }
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.shards
            .iter()
            .map(|s| {
                s.lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .len()
            })
            .sum()
    }
}

/// Parse the overlap decision from an L3-relative packet slice. `addr_family` selects
/// the arm; the IP version nibble is verified against the wire (a family/wire mismatch
/// yields `Unreadable`, never a bogus key — and a bogus key could not alias real
/// entries anyway since addrs come from the slice). `routing_domain` is left 0 for the
/// caller to stamp. Declared lengths are clamped to wire bytes.
pub(crate) fn overlap_parse(l3_packet: &[u8], addr_family: i32) -> OverlapParse {
    match addr_family {
        libc::AF_INET => {
            if l3_packet.len() < 20 || l3_packet[0] >> 4 != 4 {
                return OverlapParse::Unreadable;
            }
            let ihl = ((l3_packet[0] & 0x0F) as usize) * 4;
            if ihl < 20 || l3_packet.len() < ihl {
                return OverlapParse::Unreadable;
            }
            let total_len = u16::from_be_bytes([l3_packet[2], l3_packet[3]]) as usize;
            let frag_off = u16::from_be_bytes([l3_packet[6], l3_packet[7]]);
            if (frag_off & 0x3FFF) == 0 {
                return OverlapParse::NonFragment;
            }
            let ident = u16::from_be_bytes([l3_packet[4], l3_packet[5]]) as u32;
            let proto = l3_packet[9];
            let src = Ipv4Addr::new(l3_packet[12], l3_packet[13], l3_packet[14], l3_packet[15]);
            let dst = Ipv4Addr::new(l3_packet[16], l3_packet[17], l3_packet[18], l3_packet[19]);
            let start = ((frag_off & 0x1FFF) as u32) << 3;
            let declared = total_len.saturating_sub(ihl);
            let wire = l3_packet.len().saturating_sub(ihl);
            let end = start.saturating_add(declared.min(wire) as u32);
            OverlapParse::Fragment(
                OverlapKey {
                    addr_family: libc::AF_INET as u8,
                    src: IpAddr::V4(src),
                    dst: IpAddr::V4(dst),
                    ident,
                    protocol: proto,
                    routing_domain: 0,
                    ingress_zone: 0,
                    fairness_origin: None,
                },
                proto,
                start,
                end,
                (frag_off & 0x2000) == 0 && wire >= declared,
            )
        }
        libc::AF_INET6 => {
            if l3_packet.len() < 40 || l3_packet[0] >> 4 != 6 {
                return OverlapParse::Unreadable;
            }
            let walk = crate::afxdp::frame::walk_ipv6_ext_chain(l3_packet, 0);
            if walk.fragment_truncated {
                return OverlapParse::Unreadable;
            }
            let Some(frag) = walk.first_non_atomic_fragment else {
                return OverlapParse::NonFragment;
            };
            let Some(bytes) = frag.bytes else {
                return OverlapParse::Unreadable;
            };
            let frag_off = u16::from_be_bytes([bytes[2], bytes[3]]);
            // Byte offset, not units: the 13-bit unit count occupies bits 15..3, so
            // masking the low 3 (Res+M) yields units*8 directly. (v4 shifts because its
            // units sit in the LOW 13 bits; do not "fix" this into a >>3 — that is the
            // identity here, and *8 after it would 8x the offset.)
            let start = (frag_off & 0xFFF8) as u32;
            let ident = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
            let mut src_b = [0u8; 16];
            let mut dst_b = [0u8; 16];
            src_b.copy_from_slice(&l3_packet[8..24]);
            dst_b.copy_from_slice(&l3_packet[24..40]);
            let payload_len = u16::from_be_bytes([l3_packet[4], l3_packet[5]]) as usize;
            let frag_data_off = (frag.header_offset + 8).saturating_sub(40);
            let declared = payload_len.saturating_sub(frag_data_off);
            let wire = l3_packet.len().saturating_sub(frag.header_offset + 8);
            let next_header = bytes[0];
            let end = start.saturating_add(declared.min(wire) as u32);
            OverlapParse::Fragment(
                OverlapKey {
                    addr_family: libc::AF_INET6 as u8,
                    src: IpAddr::V6(Ipv6Addr::from(src_b)),
                    dst: IpAddr::V6(Ipv6Addr::from(dst_b)),
                    ident,
                    protocol: 0,
                    routing_domain: 0,
                    ingress_zone: 0,
                    fairness_origin: None,
                },
                next_header,
                start,
                end,
                (frag_off & 1) == 0 && wire >= declared,
            )
        }
        _ => OverlapParse::NonFragment,
    }
}

/// Map the IPv6 upper-layer protocol to its post-NAT64 v4 value (ICMPv6↔ICMP).
const fn map_v6_to_v4_proto(p: u8) -> u8 {
    if p == PROTO_ICMPV6 {
        PROTO_ICMP
    } else {
        p
    }
}

/// Result of deriving the downstream overlap identity. Missing either NAT64 rewrite
/// address on a v6 fragment is an explicit fail-closed outcome, not a skipped check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TranslatedOverlapKey {
    NotApplicable,
    Key(OverlapKey),
    DropMissingNat64Rewrite,
}

/// Compute the POST-translation overlap key for a fragment whose pre-translation key
/// is `pre` under NAT decision `nat`. `fragment_next_header` is parsed from the packet,
/// independently of the v6 pre-key's intentionally-zero protocol. NAT64 v6→v4 with
/// either rewrite address missing yields an explicit fail-closed outcome. Returns
/// `NotApplicable` when no post-check is needed. `egress_domain` is the downstream
/// receiver's routing domain, resolved from the egress interface.
///
/// Every returned key carries `fairness_origin` = the pre-translation
/// sender (`overlap_sender(pre)`), including a domain-change key with no
/// address rewrite (#14127): the downstream domain's overlap anchors are
/// checked under the egress domain, but the sender-fairness quota stays
/// charged to the arrival tenant (see `overlap_sender`).
pub(crate) fn translated_overlap_key(
    pre: &OverlapKey,
    fragment_next_header: u8,
    nat: &NatDecision,
    egress_domain: u32,
) -> TranslatedOverlapKey {
    let fairness_origin = Some(overlap_sender(pre));
    if nat.nat64 {
        if pre.addr_family as i32 == libc::AF_INET6 {
            // v6→v4: pool + server addrs from the decision, ident truncated to 16 bits.
            let (Some(src), Some(dst)) = (nat.rewrite_src, nat.rewrite_dst) else {
                return TranslatedOverlapKey::DropMissingNat64Rewrite;
            };
            TranslatedOverlapKey::Key(OverlapKey {
                addr_family: libc::AF_INET as u8,
                src,
                dst,
                ident: pre.ident & 0xFFFF,
                protocol: map_v6_to_v4_proto(fragment_next_header),
                routing_domain: egress_domain,
                ingress_zone: pre.ingress_zone,
                fairness_origin,
            })
        } else {
            // v4→v6: post-key is injective in the pre-key (zero-extended ident +
            // injectively-derived v6 addrs under a fixed pool), so a post-collision
            // implies a pre-collision the pre-check already caught. No post-check.
            TranslatedOverlapKey::NotApplicable
        }
    } else if nat.rewrite_src.is_some() || nat.rewrite_dst.is_some() {
        TranslatedOverlapKey::Key(OverlapKey {
            addr_family: pre.addr_family,
            src: nat.rewrite_src.unwrap_or(pre.src),
            dst: nat.rewrite_dst.unwrap_or(pre.dst),
            ident: pre.ident,
            protocol: pre.protocol,
            routing_domain: egress_domain,
            ingress_zone: pre.ingress_zone,
            fairness_origin,
        })
    } else if egress_domain != pre.routing_domain {
        // #14127: no address rewrite, but the fragment crosses into a
        // different downstream routing domain. The pre-key anchors only
        // the arrival domain; the egress domain's receiver needs its own
        // anchor set, so derive a post key that differs from `pre` only
        // in routing domain (and the fairness origin stamp). Callers
        // skip `post_key == pre_key`, and the domain change makes this
        // key distinct, so the post-check runs.
        TranslatedOverlapKey::Key(OverlapKey {
            routing_domain: egress_domain,
            ingress_zone: pre.ingress_zone,
            fairness_origin,
            ..*pre
        })
    } else {
        TranslatedOverlapKey::NotApplicable
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn v4_key() -> OverlapKey {
        OverlapKey {
            addr_family: libc::AF_INET as u8,
            src: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            ident: 0xBEEF,
            protocol: 6,
            routing_domain: 0,
            ingress_zone: 0,
            fairness_origin: None,
        }
    }

    fn v6_key() -> OverlapKey {
        OverlapKey {
            addr_family: libc::AF_INET6 as u8,
            src: IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 100)),
            dst: IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0x0db8, 0, 1, 0, 0, 0, 200)),
            ident: 0xBEEF,
            protocol: 6,
            routing_domain: 0,
            ingress_zone: 0,
            fairness_origin: None,
        }
    }

    fn dropped_delta(f: impl FnOnce()) -> u64 {
        let d0 = FRAG_OVERLAP_DROPPED.load(Ordering::Relaxed);
        f();
        FRAG_OVERLAP_DROPPED.load(Ordering::Relaxed).wrapping_sub(d0)
    }

    fn ipv6_fragment_packet(
        src: Ipv6Addr,
        dst: Ipv6Addr,
        next_header: u8,
        ident: u32,
        offset_bytes: u16,
        more: bool,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut pkt = vec![0u8; 48 + payload.len()];
        pkt[0] = 0x60;
        pkt[4..6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        pkt[6] = 44;
        pkt[7] = 64;
        pkt[8..24].copy_from_slice(&src.octets());
        pkt[24..40].copy_from_slice(&dst.octets());
        pkt[40] = next_header;
        let frag_off = offset_bytes | u16::from(more);
        pkt[42..44].copy_from_slice(&frag_off.to_be_bytes());
        pkt[44..48].copy_from_slice(&ident.to_be_bytes());
        pkt[48..].copy_from_slice(payload);
        pkt
    }

    #[test]
    fn adjacent_ranges_do_not_overlap_9950() {
        let t = OverlapTracker::new();
        assert!(!t.check_and_record(v4_key(), 0, 16, 1_000, &FRAG_OVERLAP_DROPPED));
        assert!(!t.check_and_record(v4_key(), 16, 24, 2_000, &FRAG_OVERLAP_DROPPED));
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn strict_overlap_drops_both_orders_9950() {
        for (a, b) in [((0u32, 16u32), (8u32, 24u32)), ((8, 24), (0, 16))] {
            let t = OverlapTracker::new();
            let d = dropped_delta(|| {
                assert!(!t.check_and_record(v4_key(), a.0, a.1, 1_000, &FRAG_OVERLAP_DROPPED));
                assert!(t.check_and_record(v4_key(), b.0, b.1, 2_000, &FRAG_OVERLAP_DROPPED));
            });
            assert_eq!(d, 1);
        }
    }

    #[test]
    fn identical_retransmit_drops_9950() {
        // Byte-identical retransmit is strict overlap. Harmless (single delivery); TCP
        // retransmits mint new idents, so this never fires benignly for TCP.
        // RED-on-revert: adjacency-only comparison (`<=`) would pass the duplicate.
        let t = OverlapTracker::new();
        assert!(!t.check_and_record(v4_key(), 0, 16, 1_000, &FRAG_OVERLAP_DROPPED));
        assert!(t.check_and_record(v4_key(), 0, 16, 2_000, &FRAG_OVERLAP_DROPPED));
    }

    #[test]
    fn empty_range_drops_fail_closed_9950() {
        let t = OverlapTracker::new();
        assert!(t.check_and_record(v4_key(), 8, 8, 1_000, &FRAG_OVERLAP_DROPPED));
        assert!(t.check_and_record(v4_key(), 16, 8, 1_000, &FRAG_OVERLAP_DROPPED));
    }

    #[test]
    fn large_in_order_datagram_coalesces_to_one_range_9950() {
        // 44-fragment 64KB datagram, in-order adjacent 1480B chunks: coalescing keeps
        // 1 range. RED-on-revert: without coalescing this needs 44 slots → overflow.
        let t = OverlapTracker::new();
        let mut off = 0u32;
        for _ in 0..44 {
            assert!(
                !t.check_and_record(v4_key(), off, off + 1480, 1_000, &FRAG_OVERLAP_DROPPED),
                "off={off}"
            );
            off += 1480;
        }
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn benign_reordered_interleave_forwards_9950() {
        // 17-fragment even/odd reordered interleave (the GPT-6 availability case): evens
        // arrive disjoint (peak 9 ranges ≤ 16), odds fill gaps and coalesce. All forward.
        // RED-on-revert: an 8-range cap drops the 9th even (valid traffic blackholed).
        let t = OverlapTracker::new();
        for i in (0..17u32).step_by(2) {
            assert!(
                !t.check_and_record(v4_key(), i * 8, i * 8 + 8, 1_000, &FRAG_OVERLAP_DROPPED),
                "even i={i}"
            );
        }
        for i in (1..17u32).step_by(2) {
            assert!(
                !t.check_and_record(v4_key(), i * 8, i * 8 + 8, 2_000, &FRAG_OVERLAP_DROPPED),
                "odd i={i}"
            );
        }
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn sparse_disjoint_overflow_drops_fail_closed_9950() {
        // 16 disjoint 8B ranges with 16B gaps fill the slots; the 17th fails closed.
        // RED-on-revert: evict-oldest would drop the anchor and forward the 17th.
        let t = OverlapTracker::new();
        let o0 = FRAG_OVERLAP_OVERFLOW_DROPPED.load(Ordering::Relaxed);
        for i in 0..16u32 {
            let s = i * 24;
            assert!(
                !t.check_and_record(v4_key(), s, s + 8, 1_000, &FRAG_OVERLAP_DROPPED),
                "i={i}"
            );
        }
        assert!(t.check_and_record(v4_key(), 16 * 24, 16 * 24 + 8, 1_000, &FRAG_OVERLAP_DROPPED));
        assert_eq!(
            FRAG_OVERLAP_OVERFLOW_DROPPED.load(Ordering::Relaxed).wrapping_sub(o0),
            1
        );
        // The live entry is untouched by the overflow drop (no MRU move, still 16).
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn shard_full_drops_without_evicting_live_9950() {
        // Fill one shard (8 domains × 8 senders) without hitting either fairness
        // quota, then prove the 65th key drops fail-closed AND the first entry's
        // ranges still detect overlap. The hash omits routing_domain, so brute-force
        // (src, ident) pairs to place all keys in the target shard.
        // RED-on-revert: evict-oldest would admit the 65th and blind the first key.
        let t = OverlapTracker::new();
        let target = overlap_shard_index(&v4_key());
        let mut keys = Vec::new();
        let mut per_sender = [0usize; 8];
        let mut ident = 0u32;
        while keys.len() < OVERLAP_CAP_PER_SHARD {
            for s in 0..8 {
                if per_sender[s] >= OVERLAP_CAP_PER_SENDER_PER_SHARD {
                    continue;
                }
                let mut k = v4_key();
                k.routing_domain = (s + 1) as u32;
                k.src = IpAddr::V4(Ipv4Addr::new(10, 0, 61, (100 + s) as u8));
                k.ident = ident;
                if overlap_shard_index(&k) == target {
                    keys.push(k);
                    per_sender[s] += 1;
                    if keys.len() == OVERLAP_CAP_PER_SHARD {
                        break;
                    }
                }
            }
            ident += 1;
        }
        for k in &keys {
            assert!(!t.check_and_record(*k, 0, 8, 1_000, &FRAG_OVERLAP_DROPPED));
        }
        let s0 = FRAG_OVERLAP_SHARD_FULL_DROPPED.load(Ordering::Relaxed);
        let mut klast = v4_key();
        klast.routing_domain = 99;
        klast.src = IpAddr::V4(Ipv4Addr::new(10, 0, 61, 108));
        let mut li = 0u32;
        loop {
            klast.ident = li;
            if overlap_shard_index(&klast) == target {
                break;
            }
            li += 1;
        }
        assert!(t.check_and_record(klast, 0, 8, 1_000, &FRAG_OVERLAP_DROPPED));
        assert_eq!(
            FRAG_OVERLAP_SHARD_FULL_DROPPED.load(Ordering::Relaxed).wrapping_sub(s0),
            1
        );
        assert!(t.check_and_record(keys[0], 4, 12, 2_000, &FRAG_OVERLAP_DROPPED));
    }

    #[test]
    fn routing_domain_separates_tenants_9950() {
        // Same wire tuple in two routing domains must not false-overlap (cross-VRF).
        // RED-on-revert: a domain-free key drops the second tenant's fragment.
        let t = OverlapTracker::new();
        let mut a = v4_key();
        a.routing_domain = 1;
        let mut b = v4_key();
        b.routing_domain = 2;
        assert!(!t.check_and_record(a, 0, 16, 1_000, &FRAG_OVERLAP_DROPPED));
        assert!(!t.check_and_record(b, 0, 16, 1_000, &FRAG_OVERLAP_DROPPED));
        assert!(t.check_and_record(a, 8, 24, 2_000, &FRAG_OVERLAP_DROPPED));
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn v4_parse_clamps_atomic_and_tristate_9950() {
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&28u16.to_be_bytes());
        ip[4..6].copy_from_slice(&0xBEEFu16.to_be_bytes());
        ip[6..8].copy_from_slice(&0x0000u16.to_be_bytes());
        ip[9] = 6;
        ip[12..16].copy_from_slice(&[10, 0, 61, 100]);
        ip[16..20].copy_from_slice(&[172, 16, 80, 200]);
        let mut pkt = ip.clone();
        pkt.extend_from_slice(&[0u8; 8]);
        assert_eq!(overlap_parse(&pkt, libc::AF_INET), OverlapParse::NonFragment);
        // Lying declared len (120) with 8 wire bytes → clamped 0..8.
        let mut first = ip.clone();
        first[2..4].copy_from_slice(&120u16.to_be_bytes());
        first[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
        let mut pkt = first;
        pkt.extend_from_slice(&[0u8; 8]);
        match overlap_parse(&pkt, libc::AF_INET) {
            OverlapParse::Fragment(k, next_header, s, e, is_last) => {
                assert_eq!((s, e), (0, 8));
                assert!(!is_last);
                assert_eq!(k.ident, 0xBEEF);
                assert_eq!(k.protocol, 6);
                assert_eq!(next_header, 6);
            }
            other => panic!("expected Fragment, got {other:?}"),
        }
        let mut truncated_last = pkt.clone();
        truncated_last[6..8].copy_from_slice(&0x0001u16.to_be_bytes());
        match overlap_parse(&truncated_last, libc::AF_INET) {
            OverlapParse::Fragment(_, _, _, _, is_last) => {
                assert!(!is_last, "truncated IPv4 last fragment cannot complete");
            }
            other => panic!("expected truncated IPv4 Fragment, got {other:?}"),
        }
        // Truncated (<20B) and version-mismatched slices are Unreadable, never keys.
        assert_eq!(overlap_parse(&pkt[..10], libc::AF_INET), OverlapParse::Unreadable);
        let mut wrongver = pkt.clone();
        wrongver[0] = 0x60;
        assert_eq!(overlap_parse(&wrongver, libc::AF_INET), OverlapParse::Unreadable);
        assert_eq!(overlap_parse(&pkt, 99), OverlapParse::NonFragment);
    }

    #[test]
    fn v6_parse_drops_proto_and_tristate_9950() {
        let mut pkt = vec![0u8; 40 + 8 + 16];
        pkt[0] = 0x60;
        pkt[4..6].copy_from_slice(&24u16.to_be_bytes());
        pkt[6] = 44;
        pkt[7] = 64;
        pkt[8..24].copy_from_slice(&[0x20, 1, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        pkt[24..40].copy_from_slice(&[0x20, 1, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        pkt[40] = 6;
        pkt[42..44].copy_from_slice(&0x0001u16.to_be_bytes());
        pkt[44..48].copy_from_slice(&0x01020304u32.to_be_bytes());
        let (k, next_header, s, e, is_last) = match overlap_parse(&pkt, libc::AF_INET6) {
            OverlapParse::Fragment(k, next_header, s, e, is_last) => {
                (k, next_header, s, e, is_last)
            }
            other => panic!("expected Fragment, got {other:?}"),
        };
        assert_eq!((s, e), (0, 16));
        assert!(!is_last);
        assert_eq!(next_header, 6);
        assert_eq!(k.protocol, 0);
        assert_eq!(k.ident, 0x01020304);
        // Same datagram, different Next Header (UDP=17): SAME key (proto dropped).
        // RED-on-revert: keying Next Header would split overlap detection.
        let mut pkt2 = pkt.clone();
        pkt2[40] = 17;
        pkt2[42..44].copy_from_slice(&0x0009u16.to_be_bytes());
        let (k2, next_header2, s2, e2, is_last2) = match overlap_parse(&pkt2, libc::AF_INET6) {
            OverlapParse::Fragment(k, next_header, s, e, is_last) => {
                (k, next_header, s, e, is_last)
            }
            other => panic!("expected Fragment, got {other:?}"),
        };
        assert_eq!(k2, k);
        assert!(!is_last2);
        assert_eq!(next_header2, 17);
        assert_eq!((s2, e2), (8, 24));
        let mut truncated_last = pkt.clone();
        truncated_last[42..44].copy_from_slice(&0x0008u16.to_be_bytes());
        truncated_last.truncate(60);
        match overlap_parse(&truncated_last, libc::AF_INET6) {
            OverlapParse::Fragment(_, _, _, _, is_last) => {
                assert!(!is_last, "truncated IPv6 last fragment cannot complete");
            }
            other => panic!("expected truncated IPv6 Fragment, got {other:?}"),
        }
        let t = OverlapTracker::new();
        assert!(!t.check_and_record(k, s, e, 1_000, &FRAG_OVERLAP_DROPPED));
        assert!(t.check_and_record(k2, s2, e2, 2_000, &FRAG_OVERLAP_DROPPED));
        // Atomic → NonFragment; truncated header → Unreadable; no frag header → NonFragment.
        let mut atomic = pkt.clone();
        atomic[42..44].copy_from_slice(&0x0000u16.to_be_bytes());
        assert_eq!(overlap_parse(&atomic, libc::AF_INET6), OverlapParse::NonFragment);
        assert_eq!(
            overlap_parse(&pkt[..44], libc::AF_INET6),
            OverlapParse::Unreadable
        );
        let mut nofrag = pkt;
        nofrag[6] = 6;
        assert_eq!(overlap_parse(&nofrag, libc::AF_INET6), OverlapParse::NonFragment);
    }

    #[test]
    fn translated_key_same_family_collision_9950() {
        // Two internal hosts, same ident+dst, interface-SNAT to one pool addr: distinct
        // pre-keys share one post-key, and overlapping post-ranges must drop.
        // RED-on-revert: pre-only checking forwards both (downstream reassembly).
        let pool = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8));
        let ext = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let nat = NatDecision { rewrite_src: Some(pool), rewrite_dst: None, rewrite_src_port: None, rewrite_dst_port: None, source_nat_icmp: None, nat64: false, nptv6: false };
        let mut a = v4_key();
        a.src = IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100));
        a.dst = ext;
        let mut b = v4_key();
        b.src = IpAddr::V4(Ipv4Addr::new(10, 0, 61, 101));
        b.dst = ext;
        assert_ne!(a, b);
        let TranslatedOverlapKey::Key(pa) = translated_overlap_key(&a, a.protocol, &nat, 0) else {
            panic!("same-family address translation requires a post-key");
        };
        let TranslatedOverlapKey::Key(pb) = translated_overlap_key(&b, b.protocol, &nat, 0) else {
            panic!("same-family address translation requires a post-key");
        };
        // #14127: the translated reassembly tuple is shared, but the
        // fairness origin keeps the two tenants' quotas distinct — so
        // assert the shared tuple fields, not whole-key equality.
        assert_eq!(
            (pa.addr_family, pa.src, pa.dst, pa.ident, pa.protocol, pa.routing_domain),
            (pb.addr_family, pb.src, pb.dst, pb.ident, pb.protocol, pb.routing_domain)
        );
        assert_ne!(pa.fairness_origin, pb.fairness_origin);
        assert_eq!(pa.src, pool);
        let t = OverlapTracker::new();
        assert!(!t.check_and_record(pa, 0, 16, 1_000, &FRAG_OVERLAP_POST_NAT_DROPPED));
        let p0 = FRAG_OVERLAP_POST_NAT_DROPPED.load(Ordering::Relaxed);
        assert!(t.check_and_record(pb, 8, 24, 1_000, &FRAG_OVERLAP_POST_NAT_DROPPED));
        assert_eq!(
            FRAG_OVERLAP_POST_NAT_DROPPED.load(Ordering::Relaxed).wrapping_sub(p0),
            1
        );
        assert_eq!(
            translated_overlap_key(&a, a.protocol, &NatDecision::default(), 0),
            TranslatedOverlapKey::NotApplicable
        );
        // Pure port-PAT (no addr rewrite) → identical key → caller must skip.
        let port_only = NatDecision {
            rewrite_src_port: Some(40000),
            ..NatDecision::default()
        };
        assert_eq!(
            translated_overlap_key(&a, a.protocol, &port_only, 0),
            TranslatedOverlapKey::NotApplicable
        );
    }
    #[test]
    fn translated_key_identity_rewrite_same_datagram_15788() {
        // #15788: an identity address rewrite (rewrite addrs == arrival
        // addrs, same egress domain) yields a post key that differs from
        // the pre key ONLY in `fairness_origin` (pre: None, post: Some).
        // The callers' post-check guard uses datagram identity
        // (`overlap_same_datagram`), so it must skip the post-check:
        // recording the same range under the post key would find the
        // pre-recorded entry and drop the fragment against itself with
        // FRAG_OVERLAP_POST_NAT_DROPPED. A genuinely different post key
        // must still take the post-check and record.
        let pre = v4_key();
        let identity = NatDecision {
            rewrite_src: Some(pre.src),
            rewrite_dst: Some(pre.dst),
            ..NatDecision::default()
        };
        let TranslatedOverlapKey::Key(post) =
            translated_overlap_key(&pre, pre.protocol, &identity, pre.routing_domain)
        else {
            panic!("identity address rewrite requires a post-key");
        };
        // Fixture pin: the two keys really do differ under derived
        // PartialEq (fairness_origin None vs Some) — that is the defect
        // trigger — yet they are the same datagram.
        assert_ne!(post, pre);
        assert_eq!(post.fairness_origin, Some(overlap_sender(&pre)));
        assert!(overlap_same_datagram(&post, &pre));
        // Genuinely different post-NAT keys (src or routing domain
        // changed) are NOT the same datagram and must still be recorded.
        let mut moved = post;
        moved.src = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8));
        assert!(!overlap_same_datagram(&moved, &pre));
        let mut other_domain = post;
        other_domain.routing_domain = pre.routing_domain + 1;
        assert!(!overlap_same_datagram(&other_domain, &pre));
        // End-to-end consequence: record the pre key once; the identity
        // post key is guarded out (never recorded), while the moved key
        // is recorded — disjoint range passes, overlapping range drops.
        let t = OverlapTracker::new();
        assert!(!t.check_and_record(pre, 0, 16, 1_000, &FRAG_OVERLAP_DROPPED));
        let p0 = FRAG_OVERLAP_POST_NAT_DROPPED.load(Ordering::Relaxed);
        if !overlap_same_datagram(&moved, &pre) {
            assert!(!t.check_and_record(moved, 16, 32, 1_000, &FRAG_OVERLAP_POST_NAT_DROPPED));
            assert!(t.check_and_record(moved, 8, 24, 1_000, &FRAG_OVERLAP_POST_NAT_DROPPED));
        }
        assert_eq!(
            FRAG_OVERLAP_POST_NAT_DROPPED.load(Ordering::Relaxed).wrapping_sub(p0),
            1
        );
    }


    #[test]
    fn translated_key_nat64_truncation_collision_9950() {
        // v6 idents 0x00010001/0x00020001 truncate to the same v4 ident 1 with the same
        // translated addrs: distinct pre-keys, one post-key, overlapping post-ranges drop.
        let v4src = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 50));
        let v4dst = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let nat = NatDecision { rewrite_src: Some(v4src), rewrite_dst: Some(v4dst), rewrite_src_port: None, rewrite_dst_port: None, source_nat_icmp: None, nat64: true, nptv6: false };
        let mk = |ident: u32| OverlapKey {
            addr_family: libc::AF_INET6 as u8,
            src: IpAddr::V6(Ipv6Addr::LOCALHOST),
            dst: IpAddr::V6(Ipv6Addr::LOCALHOST),
            ident,
            protocol: 0,
            routing_domain: 0,
            ingress_zone: 0,
            fairness_origin: None,
        };
        let a = mk(0x0001_0001);
        let b = mk(0x0002_0001);
        let TranslatedOverlapKey::Key(pa) = translated_overlap_key(&a, 6, &nat, 0) else {
            panic!("NAT64 v6→v4 with both rewrites requires a post-key");
        };
        let TranslatedOverlapKey::Key(pb) = translated_overlap_key(&b, 6, &nat, 0) else {
            panic!("NAT64 v6→v4 with both rewrites requires a post-key");
        };
        assert_eq!(
            (pa.addr_family, pa.src, pa.dst, pa.ident, pa.protocol, pa.routing_domain),
            (pb.addr_family, pb.src, pb.dst, pb.ident, pb.protocol, pb.routing_domain)
        );
        assert_eq!(pa.ident, 1);
        assert_eq!(pa.addr_family, libc::AF_INET as u8);
        let t = OverlapTracker::new();
        assert!(!t.check_and_record(pa, 0, 16, 1_000, &FRAG_OVERLAP_POST_NAT_DROPPED));
        assert!(t.check_and_record(pb, 8, 24, 1_000, &FRAG_OVERLAP_POST_NAT_DROPPED));
        // v4→v6 direction needs no post-check (injectivity proof in module docs).
        let mut v4pre = v4_key();
        v4pre.routing_domain = 0;
        let nat64v4 = NatDecision {
            nat64: true,
            ..NatDecision::default()
        };
        assert_eq!(
            translated_overlap_key(&v4pre, v4pre.protocol, &nat64v4, 0),
            TranslatedOverlapKey::NotApplicable
        );
    }
    #[test]
    fn nat64_tcp_udp_trains_with_colliding_truncated_ids_complete_10861() {
        let tcp_src: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let udp_src: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let dst: Ipv6Addr = "64:ff9b::808:808".parse().unwrap();
        let pool_v4 = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 50));
        let dst_v4 = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let nat = NatDecision { rewrite_src: Some(pool_v4), rewrite_dst: Some(dst_v4), rewrite_src_port: None, rewrite_dst_port: None, source_nat_icmp: None, nat64: true, nptv6: false };
        let mut tcp_segment = [0u8; 72];
        tcp_segment[0..2].copy_from_slice(&12345u16.to_be_bytes());
        tcp_segment[2..4].copy_from_slice(&443u16.to_be_bytes());
        tcp_segment[12] = 0x50;
        tcp_segment[13] = 0x10;
        let mut udp_segment = [0u8; 72];
        udp_segment[0..2].copy_from_slice(&23456u16.to_be_bytes());
        udp_segment[2..4].copy_from_slice(&443u16.to_be_bytes());
        let udp_len = udp_segment.len() as u16;
        udp_segment[4..6].copy_from_slice(&udp_len.to_be_bytes());

        let tracker = OverlapTracker::new();
        let mut tcp_post = None;
        let mut udp_post = None;
        for offset_bytes in [0u16, 24, 48] {
            for (src, next_header, ident, segment) in [
                (tcp_src, 6, 0x0001_0001, &tcp_segment),
                (udp_src, 17, 0x0002_0001, &udp_segment),
            ] {
                let offset = offset_bytes as usize;
                let packet = ipv6_fragment_packet(
                    src,
                    dst,
                    next_header,
                    ident,
                    offset_bytes,
                    offset_bytes < 48,
                    &segment[offset..offset + 24],
                );
                let OverlapParse::Fragment(pre, parsed_next_header, start, end, is_last) =
                    overlap_parse(&packet, libc::AF_INET6)
                else {
                    panic!("expected parsed NAT64 fragment");
                };
                assert_eq!(
                    pre.protocol, 0,
                    "v6 pre-key must remain protocol-independent"
                );
                assert_eq!(parsed_next_header, next_header);
                let TranslatedOverlapKey::Key(post) =
                    translated_overlap_key(&pre, parsed_next_header, &nat, 0)
                else {
                    panic!("NAT64 fragment with both rewrite addresses needs a post-key");
                };
                assert_eq!(post.src, pool_v4);
                assert_eq!(post.dst, dst_v4);
                assert_eq!(post.ident, 1, "the colliding low-16 idents are preserved");
                assert_eq!(post.protocol, next_header);
                let slot = if next_header == 6 {
                    &mut tcp_post
                } else {
                    &mut udp_post
                };
                if let Some(previous) = *slot {
                    assert_eq!(previous, post);
                } else {
                    *slot = Some(post);
                }

                let mut result = tracker.check_and_record_fragment_detailed(
                    post,
                    start,
                    end,
                    is_last,
                    u64::from(offset_bytes) + u64::from(next_header),
                    &FRAG_OVERLAP_POST_NAT_DROPPED,
                );
                assert!(!result.dropped, "TCP and UDP ranges must be independent");
                let admission = result
                    .admission
                    .take()
                    .expect("recorded fragment admission");
                let completed = tracker.commit_admission(admission);
                assert_eq!(completed, offset_bytes == 48);
                if next_header == 6 && offset_bytes == 48 {
                    assert_eq!(
                        tracker.len(),
                        2,
                        "completed TCP and live UDP trains both retain their anchors"
                    );
                }
            }
        }
        let tcp_post = tcp_post.expect("TCP post-key");
        let udp_post = udp_post.expect("UDP post-key");
        assert_ne!(tcp_post, udp_post);
        assert_eq!(tcp_post.protocol, 6);
        assert_eq!(udp_post.protocol, 17);
        assert_eq!(tracker.len(), 2, "both completed trains remain protected");
    }

    #[test]
    fn nat64_protocols_do_not_union_completion_coverage_10861() {
        let src_tcp: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let src_udp: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let dst = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let nat = NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 50))),
            rewrite_dst: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            nat64: true,
            ..NatDecision::default()
        };
        let pre = |src, ident| OverlapKey {
            addr_family: libc::AF_INET6 as u8,
            src: IpAddr::V6(src),
            dst,
            ident,
            protocol: 0,
            routing_domain: 0,
            ingress_zone: 0,
            fairness_origin: None,
        };
        let TranslatedOverlapKey::Key(tcp_key) =
            translated_overlap_key(&pre(src_tcp, 0x0001_0001), 6, &nat, 0)
        else {
            panic!("TCP NAT64 post-key");
        };
        let TranslatedOverlapKey::Key(udp_key) =
            translated_overlap_key(&pre(src_udp, 0x0002_0001), 17, &nat, 0)
        else {
            panic!("UDP NAT64 post-key");
        };
        let tracker = OverlapTracker::new();
        let record = |key, start, end, is_last, now_ns| {
            let mut result = tracker.check_and_record_fragment_detailed(
                key,
                start,
                end,
                is_last,
                now_ns,
                &FRAG_OVERLAP_POST_NAT_DROPPED,
            );
            assert!(!result.dropped);
            let admission = result
                .admission
                .take()
                .expect("recorded fragment admission");
            tracker.commit_admission(admission);
        };
        // TCP has a gap [8,16); UDP's disjoint [8,16) range must not complete it.
        record(tcp_key, 0, 8, false, 1_000);
        record(udp_key, 8, 16, false, 2_000);
        record(tcp_key, 16, 24, true, 3_000);
        assert_eq!(tracker.len(), 2, "neither independent datagram is complete");
    }

    #[test]
    fn nat64_missing_rewrite_pair_is_a_drop_10861() {
        let pre = OverlapKey {
            addr_family: libc::AF_INET6 as u8,
            src: IpAddr::V6(Ipv6Addr::LOCALHOST),
            dst: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            ident: 0x0001_0001,
            protocol: 0,
            routing_domain: 0,
            ingress_zone: 0,
            fairness_origin: None,
        };
        for nat in [
            NatDecision {
                nat64: true,
                ..NatDecision::default()
            },
            NatDecision {
                rewrite_dst: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
                nat64: true,
                ..NatDecision::default()
            },
            NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 50))),
                nat64: true,
                ..NatDecision::default()
            },
        ] {
            assert_eq!(
                translated_overlap_key(&pre, 6, &nat, 0),
                TranslatedOverlapKey::DropMissingNat64Rewrite
            );
        }
    }

    #[test]
    fn check_is_pure_and_agrees_with_record_9950() {
        // check_overlap mutates nothing: repeated checks never self-overlap and len stays
        // 0; after a record, the same inputs fire. RED-on-revert: recording inside check
        // makes the second check overlap (and reintroduces refused-traffic planting).
        let t = OverlapTracker::new();
        assert!(!t.check_overlap(v4_key(), 0, 16, 1_000, &FRAG_OVERLAP_DROPPED));
        assert!(!t.check_overlap(v4_key(), 0, 16, 1_000, &FRAG_OVERLAP_DROPPED));
        assert_eq!(t.len(), 0);
        assert!(!t.check_and_record(v4_key(), 0, 16, 1_000, &FRAG_OVERLAP_DROPPED));
        assert!(t.check_overlap(v4_key(), 8, 24, 2_000, &FRAG_OVERLAP_DROPPED));
        assert!(!t.check_overlap(v4_key(), 16, 24, 2_000, &FRAG_OVERLAP_DROPPED));
    }

    #[test]
    fn check_catches_would_overflow_without_mutating_9950() {
        // 16 disjoint recorded; check() of a 17th reports the overflow-drop while leaving
        // the anchor ranges intact (an overlapping check still fires as overlap, not miss).
        let t = OverlapTracker::new();
        for i in 0..16u32 {
            let s = i * 24;
            assert!(!t.check_and_record(v4_key(), s, s + 8, 1_000, &FRAG_OVERLAP_DROPPED));
        }
        let o0 = FRAG_OVERLAP_OVERFLOW_DROPPED.load(Ordering::Relaxed);
        assert!(t.check_overlap(v4_key(), 16 * 24, 16 * 24 + 8, 1_000, &FRAG_OVERLAP_DROPPED));
        assert_eq!(
            FRAG_OVERLAP_OVERFLOW_DROPPED.load(Ordering::Relaxed).wrapping_sub(o0),
            1
        );
        let d = dropped_delta(|| {
            assert!(t.check_overlap(v4_key(), 4, 12, 2_000, &FRAG_OVERLAP_DROPPED));
        });
        assert_eq!(d, 1);
    }


    #[test]
    fn completed_datagram_rate_does_not_exhaust_sender_quota_13937() {
        fn send_train(tracker: &OverlapTracker, mut key: OverlapKey) {
            let full0 = FRAG_OVERLAP_SHARD_FULL_DROPPED.load(Ordering::Relaxed);
            // 10 complete 2-fragment datagrams per second for 60 seconds.
            for ident in 0..600u32 {
                key.ident = ident;
                let now_ns = 1_000 + u64::from(ident) * 100_000_000;
                let mut first = tracker.check_and_record_fragment_detailed(
                    key,
                    0,
                    8,
                    false,
                    now_ns,
                    &FRAG_OVERLAP_DROPPED,
                );
                assert!(!first.dropped, "head fragment {ident} is admitted");
                let mut last = tracker.check_and_record_fragment_detailed(
                    key,
                    8,
                    16,
                    true,
                    now_ns + 1,
                    &FRAG_OVERLAP_DROPPED,
                );
                assert!(!last.dropped, "tail fragment {ident} is admitted");
                assert!(!tracker.commit_admission(first.admission.take().unwrap()));
                assert!(tracker.commit_admission(last.admission.take().unwrap()));
            }
            assert_eq!(
                FRAG_OVERLAP_SHARD_FULL_DROPPED
                    .load(Ordering::Relaxed)
                    .wrapping_sub(full0),
                0,
                "completed datagrams do not consume sender incomplete-entry quota"
            );
        }

        // Arrival-key and translated-key trackers both charge the stable
        // sender identity; the translated path is the SNAT quota funnel.
        send_train(&OverlapTracker::new(), v4_key());
        send_train(&OverlapTracker::new(), v6_key());
    }

    #[test]
    fn completed_datagram_stays_protected_through_reassembly_window_13680() {
        let t = OverlapTracker::new();
        let mut first = t.check_and_record_fragment_detailed(
            v4_key(),
            0,
            8,
            false,
            1_000,
            &FRAG_OVERLAP_DROPPED,
        );
        assert!(!first.dropped);
        let mut last = t.check_and_record_fragment_detailed(
            v4_key(),
            8,
            16,
            true,
            2_000,
            &FRAG_OVERLAP_DROPPED,
        );
        assert!(!last.dropped);
        let first_admission = first.admission.take().expect("head admission");
        let last_admission = last.admission.take().expect("tail admission");
        assert_eq!(t.len(), 1, "release is deferred until all gates pass");
        assert!(!t.commit_admission(last_admission));
        assert_eq!(t.len(), 1, "tail may settle before the head");
        assert!(
            t.commit_admission(first_admission),
            "completed datagram is reported complete but held for the reassembly window"
        );
        assert_eq!(t.len(), 1);
        assert!(t.check_overlap(v4_key(), 0, 16, 3_000, &FRAG_OVERLAP_DROPPED));
    }

    #[test]
    fn completion_waits_for_tail_first_gaps_10285() {
        let t = OverlapTracker::new();
        let key = v4_key();
        let mut tail = t.check_and_record_fragment_detailed(
            key,
            16,
            24,
            true,
            1_000,
            &FRAG_OVERLAP_DROPPED,
        );
        assert!(tail.completion.is_none(), "tail-first datagram still has a gap");
        let mut first = t.check_and_record_fragment_detailed(
            key,
            0,
            8,
            false,
            2_000,
            &FRAG_OVERLAP_DROPPED,
        );
        assert!(
            first.completion.is_none(),
            "endpoint coverage must not hide the middle gap"
        );
        let mut middle = t.check_and_record_fragment_detailed(
            key,
            8,
            16,
            false,
            3_000,
            &FRAG_OVERLAP_DROPPED,
        );
        let tail_admission = tail.admission.take().expect("tail admission");
        let first_admission = first.admission.take().expect("head admission");
        let middle_admission = middle.admission.take().expect("middle admission");
        assert!(!t.commit_admission(tail_admission));
        assert_eq!(t.len(), 1, "head and middle remain unsettled");
        assert!(!t.commit_admission(first_admission));
        assert!(t.commit_admission(middle_admission));
        assert_eq!(t.len(), 1, "completed entry is held, not reclaimed early");
    }

    #[test]
    fn admission_token_does_not_delete_reinserted_state_10285() {
        let t = OverlapTracker::new();
        let key = v4_key();
        let mut first = t.check_and_record_fragment_detailed(
            key,
            0,
            8,
            false,
            1_000,
            &FRAG_OVERLAP_DROPPED,
        );
        let first_admission = first.admission.take().expect("head admission");
        let stale_incarnation = first_admission.incarnation;
        let mut done = t.check_and_record_fragment_detailed(
            key,
            8,
            16,
            true,
            2_000,
            &FRAG_OVERLAP_DROPPED,
        );
        let done_admission = done.admission.take().expect("tail admission");
        assert!(!t.commit_admission(done_admission));
        assert!(t.commit_admission(first_admission));
        assert_eq!(t.len(), 1, "settled-complete entry held for TTL window");

        // Advancing past TTL expires the held entry; the same key then starts fresh.
        let mut second = t.check_and_record_fragment_detailed(
            key,
            0,
            8,
            true,
            3_000 + OVERLAP_TTL_NS + 1,
            &FRAG_OVERLAP_DROPPED,
        );
        let current = second.admission.take().expect("reinserted admission");
        assert!(
            !t.commit_admission(OverlapAdmissionToken {
                key,
                incarnation: stale_incarnation,
            }),
            "incarnation IDs prevent ABA deletion"
        );
        assert_eq!(t.len(), 1);
        assert!(
            t.commit_admission(current),
            "freshly completed single-fragment entry reports completion but stays held"
        );
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn failed_admission_keeps_overlap_protection_10285() {
        let t = OverlapTracker::new();
        let key = v4_key();
        let mut head = t.check_and_record_fragment_detailed(
            key,
            0,
            8,
            false,
            1_000,
            &FRAG_OVERLAP_DROPPED,
        );
        let mut tail = t.check_and_record_fragment_detailed(
            key,
            8,
            16,
            true,
            1_001,
            &FRAG_OVERLAP_DROPPED,
        );
        assert!(t.fail_admission(head.admission.take().expect("head admission")));
        assert!(!t.commit_admission(tail.admission.take().expect("tail admission")));
        assert_eq!(t.len(), 1, "failed datagrams are not reclaimable");
        assert!(t.check_overlap(key, 4, 12, 2_000, &FRAG_OVERLAP_DROPPED));
    }

    #[test]
    fn completed_entries_hold_shard_capacity_until_expiry_10285() {
        let t = OverlapTracker::new();
        let target = overlap_shard_index(&v4_key());
        let mut keys = Vec::new();
        // 8 domains × 8 senders: filling the shard stays below both fairness caps.
        let mut per_sender = [0usize; 8];
        let mut ident = 0u32;
        while keys.len() < OVERLAP_CAP_PER_SHARD {
            for s in 0..8 {
                if per_sender[s] >= OVERLAP_CAP_PER_SENDER_PER_SHARD {
                    continue;
                }
                let mut key = v4_key();
                key.routing_domain = (s + 1) as u32;
                key.src = IpAddr::V4(Ipv4Addr::new(10, 0, 61, (100 + s) as u8));
                key.ident = ident;
                if overlap_shard_index(&key) == target {
                    keys.push(key);
                    per_sender[s] += 1;
                    if keys.len() == OVERLAP_CAP_PER_SHARD {
                        break;
                    }
                }
            }
            ident += 1;
        }
        // 65th key from a 9th domain in the same shard.
        let mut last = v4_key();
        last.routing_domain = 99;
        last.src = IpAddr::V4(Ipv4Addr::new(10, 0, 61, 108));
        let mut li = 0u32;
        loop {
            last.ident = li;
            if overlap_shard_index(&last) == target {
                break;
            }
            li += 1;
        }
        keys.push(last);
        let mut tokens = Vec::new();
        for key in keys.iter().take(OVERLAP_CAP_PER_SHARD) {
            let mut result = t.check_and_record_fragment_detailed(
                *key,
                0,
                8,
                true,
                1_000,
                &FRAG_OVERLAP_DROPPED,
            );
            tokens.push(result.admission.take().expect("single-fragment admission"));
        }
        let full0 = FRAG_OVERLAP_SHARD_FULL_DROPPED.load(Ordering::Relaxed);
        let refused = t.check_and_record_fragment_detailed(
            keys[OVERLAP_CAP_PER_SHARD],
            0,
            8,
            true,
            1_000,
            &FRAG_OVERLAP_DROPPED,
        );
        assert!(refused.dropped);
        assert_eq!(
            FRAG_OVERLAP_SHARD_FULL_DROPPED
                .load(Ordering::Relaxed)
                .wrapping_sub(full0),
            1
        );
        for token in tokens {
            assert!(t.commit_admission(token));
        }
        assert_eq!(t.len(), OVERLAP_CAP_PER_SHARD);
        let full1 = FRAG_OVERLAP_SHARD_FULL_DROPPED.load(Ordering::Relaxed);
        let still_full = t.check_and_record_fragment_detailed(
            keys[OVERLAP_CAP_PER_SHARD],
            0,
            8,
            true,
            2_000,
            &FRAG_OVERLAP_DROPPED,
        );
        assert!(still_full.dropped, "completed live anchors are not evicted");
        assert_eq!(
            FRAG_OVERLAP_SHARD_FULL_DROPPED
                .load(Ordering::Relaxed)
                .wrapping_sub(full1),
            1
        );
        let mut admitted = t.check_and_record_fragment_detailed(
            keys[OVERLAP_CAP_PER_SHARD],
            0,
            8,
            true,
            1_000 + OVERLAP_TTL_NS + 1,
            &FRAG_OVERLAP_DROPPED,
        );
        assert!(!admitted.dropped, "expired anchors release capacity");
        assert!(t.commit_admission(admitted.admission.take().expect("admitted token")));
        assert_eq!(t.len(), 1);

    }

    #[test]
    fn completion_rejects_bytes_beyond_terminal_end_10285() {
        let t = OverlapTracker::new();
        let key = v4_key();
        assert!(!t
            .check_and_record_fragment_detailed(
                key,
                16,
                24,
                false,
                1_000,
                &FRAG_OVERLAP_DROPPED,
            )
            .dropped);
        assert!(!t
            .check_and_record_fragment_detailed(
                key,
                0,
                8,
                false,
                2_000,
                &FRAG_OVERLAP_DROPPED,
            )
            .dropped);
        let last = t.check_and_record_fragment_detailed(
            key,
            8,
            16,
            true,
            3_000,
            &FRAG_OVERLAP_DROPPED,
        );
        assert!(
            last.dropped,
            "a previously recorded range extending past the terminal end conflicts"
        );
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn terminal_end_conflicts_match_pure_and_record_checks_13680() {
        let t = OverlapTracker::new();
        let key = v4_key();
        let mut first = t.check_and_record_fragment_detailed(
            key,
            0,
            8,
            false,
            1_000,
            &FRAG_OVERLAP_DROPPED,
        );
        assert!(!first.dropped);
        assert!(!t.commit_admission(first.admission.take().expect("first admission")));
        let mut last = t.check_and_record_fragment_detailed(
            key,
            8,
            16,
            true,
            2_000,
            &FRAG_OVERLAP_DROPPED,
        );
        assert!(!last.dropped);
        assert!(t.commit_admission(last.admission.take().expect("terminal admission")));

        assert!(t.check_overlap_fragment(
            key,
            16,
            24,
            false,
            3_000,
            &FRAG_OVERLAP_DROPPED,
        ));
        let beyond_terminal = t.check_and_record_fragment_detailed(
            key,
            16,
            24,
            false,
            3_000,
            &FRAG_OVERLAP_DROPPED,
        );
        assert!(beyond_terminal.dropped);
        assert!(
            t.check_overlap_fragment(
                key,
                24,
                32,
                true,
                4_000,
                &FRAG_OVERLAP_DROPPED,
            ),
            "a second terminal end cannot replace the established terminal"
        );
        let wrong_terminal = t.check_and_record_fragment_detailed(
            key,
            24,
            32,
            true,
            4_000,
            &FRAG_OVERLAP_DROPPED,
        );
        assert!(wrong_terminal.dropped);
        assert_eq!(t.len(), 1, "conflicts leave the recorded anchor unchanged");
    }

    #[test]
    fn stale_token_cannot_delete_reinserted_identical_state_10285() {
        let t = OverlapTracker::new();
        let key = v4_key();
        let mut first = t.check_and_record_fragment_detailed(
            key,
            0,
            8,
            true,
            1_000,
            &FRAG_OVERLAP_DROPPED,
        );
        let stale = first.admission.take().expect("first admission");
        let stale_incarnation = stale.incarnation;
        assert!(t.commit_admission(stale));
        // A new incarnation is possible only after the old live anchor expires.
        let mut second = t.check_and_record_fragment_detailed(
            key,
            0,
            8,
            true,
            1_000 + OVERLAP_TTL_NS + 1,
            &FRAG_OVERLAP_DROPPED,
        );
        let current = second.admission.take().expect("reinserted admission");
        assert!(
            !t.commit_admission(OverlapAdmissionToken {
                key,
                incarnation: stale_incarnation,
            }),
            "incarnation IDs prevent ABA deletion"
        );
        assert_eq!(t.len(), 1);
        assert!(t.commit_admission(current));
        assert_eq!(t.len(), 1);
    }


    #[test]
    fn completed_anchors_preserve_routing_domain_reserve_14009() {
        let tracker = OverlapTracker::new();
        let target = overlap_shard_index(&v4_key());
        let mut attacker = v4_key();
        attacker.routing_domain = 7;
        let mut ident = 0u32;

        // Completed entries cannot let one tenant exceed its 32-entry reserve:
        // arrivals beyond that point replace its oldest completed anchor.
        for _ in 0..OVERLAP_CAP_PER_SHARD {
            let key = loop {
                attacker.ident = ident;
                ident += 1;
                if overlap_shard_index(&attacker) == target {
                    break attacker;
                }
            };
            let mut admission = tracker.check_and_record_fragment_detailed(
                key,
                0,
                8,
                true,
                u64::from(ident),
                &FRAG_OVERLAP_DROPPED,
            );
            assert!(!admission.dropped, "completed anchor {ident} is admitted");
            assert!(tracker.commit_admission(admission.admission.take().unwrap()));
        }
        assert_eq!(tracker.len(), OVERLAP_CAP_PER_DOMAIN_PER_SHARD);

        // A competing routing domain can use the other half of the shard
        // (its (domain, zone) reserve is independent).
        let mut victim = v4_key();
        victim.routing_domain = 8;
        victim.src = IpAddr::V4(Ipv4Addr::new(10, 0, 61, 101));
        let mut victim_key = victim;
        for _ in 0..OVERLAP_CAP_PER_DOMAIN_PER_SHARD {
            victim_key = loop {
                victim.ident = ident;
                ident += 1;
                if overlap_shard_index(&victim) == target {
                    break victim;
                }
            };
            let mut admitted = tracker.check_and_record_fragment_detailed(
                victim_key,
                0,
                8,
                true,
                u64::from(ident),
                &FRAG_OVERLAP_DROPPED,
            );
            assert!(!admitted.dropped, "victim reserve entry {ident} is admitted");
            assert!(tracker.commit_admission(admitted.admission.take().unwrap()));
        }
        assert_eq!(tracker.len(), OVERLAP_CAP_PER_SHARD);
        assert!(tracker.check_overlap(
            victim_key,
            0,
            8,
            u64::from(ident + 1),
            &FRAG_OVERLAP_DROPPED
        ));
    }

    #[test]
    fn cross_vrf_attacker_cannot_starve_victim_10658() {
        // One tenant's never-completing, policy-admitted fragments must not
        // blackhole another VRF: the attacker floods 2048 idents from VRF 7
        // (~128/shard, first-fragment ranges, no tail so nothing completes),
        // then a victim datagram in VRF 8 must still forward in every shard.
        // RED-on-revert: pre-quota, the flood fills all 16 shards and every
        // victim key drops fail-closed for the 30s window.
        let t = OverlapTracker::new();
        let now_ns = 1_000u64;
        let mut atk = v4_key();
        atk.routing_domain = 7;
        for ident in 0..2048u32 {
            atk.ident = ident;
            let _ = t.check_and_record(atk, 0, 8, now_ns, &FRAG_OVERLAP_DROPPED);
        }
        // 16 shards x 8 per-sender (named constant lands with the quota impl).
        assert!(
            t.len() <= 128,
            "single sender must hold at most 8 entries per shard, len={}",
            t.len()
        );
        let mut victim = v4_key();
        victim.routing_domain = 8;
        victim.src = IpAddr::V4(Ipv4Addr::new(10, 0, 61, 101));
        let mut first_victim: Option<OverlapKey> = None;
        for target in 0..OVERLAP_SHARDS {
            let mut ident = 0u32;
            let key = loop {
                let mut k = victim;
                k.ident = ident;
                if overlap_shard_index(&k) == target {
                    break k;
                }
                ident += 1;
            };
            if target == 0 {
                first_victim = Some(key);
            }
            assert!(
                !t.check_and_record(key, 0, 8, now_ns, &FRAG_OVERLAP_DROPPED),
                "cross-VRF victim must forward in shard {target}"
            );
        }
        // Victim protection is intact: an overlapping tail on a victim key drops.
        let v0 = first_victim.expect("shard-0 victim key");
        assert!(t.check_and_record(v0, 4, 12, now_ns + 1, &FRAG_OVERLAP_DROPPED));
    }

    #[test]
    fn one_domain_cannot_starve_other_domains_10658() {
        // A tenant can vary source addresses, so the per-sender quota alone is not
        // enough: fill VRF 7 to its 32-entry/domain/shard budget from 8 senders, then
        // verify a VRF 8 victim still admits in every shard.
        // RED-on-revert: without a per-domain cap, 8 senders × 8 keys fills all 64
        // entries per shard and the victim fails closed.
        let t = OverlapTracker::new();
        let mut per_sender = [[0usize; OVERLAP_SHARDS]; 8];
        for s in 0..8 {
            let mut ident = 0u32;
            while per_sender[s]
                .iter()
                .any(|&n| n < OVERLAP_CAP_PER_SENDER_PER_SHARD)
            {
                let mut attack = v4_key();
                attack.routing_domain = 7;
                attack.src = IpAddr::V4(Ipv4Addr::new(10, 0, 61, (100 + s) as u8));
                attack.ident = ident;
                let shard = overlap_shard_index(&attack);
                if per_sender[s][shard] < OVERLAP_CAP_PER_SENDER_PER_SHARD {
                    let dropped =
                        t.check_and_record(attack, 0, 8, 1_000, &FRAG_OVERLAP_DROPPED);
                    if s < OVERLAP_CAP_PER_DOMAIN_PER_SHARD
                        / OVERLAP_CAP_PER_SENDER_PER_SHARD
                    {
                        assert!(!dropped, "initial domain quota should admit sender {s}");
                    } else {
                        assert!(dropped, "domain quota should reject sender {s}");
                    }
                    per_sender[s][shard] += 1;
                }
                ident += 1;
            }
        }
        assert_eq!(
            t.len(),
            OVERLAP_CAP_PER_DOMAIN_PER_SHARD * OVERLAP_SHARDS,
            "one domain must stay at its per-shard quota"
        );

        let mut victim = v4_key();
        victim.routing_domain = 8;
        victim.src = IpAddr::V4(Ipv4Addr::new(10, 0, 61, 200));
        for target in 0..OVERLAP_SHARDS {
            let mut ident = 0u32;
            let key = loop {
                let mut k = victim;
                k.ident = ident;
                if overlap_shard_index(&k) == target {
                    break k;
                }
                ident += 1;
            };
            assert!(
                !t.check_and_record(key, 0, 8, 1_000, &FRAG_OVERLAP_DROPPED),
                "other-domain victim must forward in shard {target}"
            );
        }
    }

    #[test]
    fn sustained_fill_leaves_victims_admitted_10658() {
        // 1024 policy-admitted, never-completing datagrams arrive evenly across
        // the 30s reassembly window (≈34pps). The attacker brute-forces ident values
        // to plant 64 keys in every shard; a cross-VRF AND same-VRF other-sender
        // victim must remain admitted at each quarter-window checkpoint.
        // RED-on-revert: without quotas, the 1024th key fills all shards and the
        // final victim insert fails closed before the first entries expire.
        let t = OverlapTracker::new();
        let mut atk = v4_key();
        atk.routing_domain = 7;
        let mut xvrf = v4_key();
        xvrf.routing_domain = 8;
        xvrf.src = IpAddr::V4(Ipv4Addr::new(10, 0, 61, 101));
        let mut mate = v4_key();
        mate.routing_domain = 7;
        mate.src = IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102));
        let mut attempts_per_shard = [0usize; OVERLAP_SHARDS];
        let mut attempts = 0u64;
        let mut ident = 0u32;
        while attempts_per_shard
            .iter()
            .any(|&n| n < OVERLAP_CAP_PER_SHARD)
        {
            atk.ident = ident;
            let shard = overlap_shard_index(&atk);
            if attempts_per_shard[shard] < OVERLAP_CAP_PER_SHARD {
                let now_ns = 1 + attempts * OVERLAP_TTL_NS / 1024;
                let _ = t.check_and_record(atk, 0, 8, now_ns, &FRAG_OVERLAP_DROPPED);
                attempts_per_shard[shard] += 1;
                attempts += 1;
                if attempts % 256 == 0 {
                    let round = (attempts / 256) as u32 - 1;
                    xvrf.ident = 500_000 + round;
                    assert!(
                        !t.check_and_record(xvrf, 0, 8, now_ns, &FRAG_OVERLAP_DROPPED),
                        "cross-VRF victim must forward in round {round}"
                    );
                    mate.ident = 600_000 + round;
                    assert!(
                        !t.check_and_record(mate, 0, 8, now_ns, &FRAG_OVERLAP_DROPPED),
                        "same-VRF other-sender victim must forward in round {round}"
                    );
                }
            }
            ident += 1;
        }
        assert_eq!(attempts, OVERLAP_CAP_PER_SHARD as u64 * OVERLAP_SHARDS as u64);
        assert_eq!(
            t.len(),
            OVERLAP_CAP_PER_SENDER_PER_SHARD * OVERLAP_SHARDS + 8,
            "attacker residue must stay sender-quota-bounded alongside victims"
        );
    }
    #[test]
    fn seeded_index_defeats_targeted_single_shard_fill_12189() {
        // DSM-027: four permitted sources can each hold eight incomplete
        // datagram anchors. This set is regenerated for the post-fold keyed
        // finalizer: seed zero places every key in TARGET_SHARD, while seed
        // one disperses the set across shards.
        const ATTACK_SOURCES: [u8; 4] = [101, 102, 103, 104];
        const DOMAIN: u32 = 7;
        const TARGET_SHARD: usize = 5;
        let dst = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200));
        let attack_idents: [[u32; 8]; 4] = [
            [29, 68, 83, 91, 95, 115, 168, 177],
            [4, 37, 42, 44, 45, 53, 57, 68],
            [65, 80, 121, 128, 139, 145, 178, 192],
            [13, 48, 77, 101, 107, 108, 125, 134],
        ];
        let t = OverlapTracker::with_seed(1);
        let now_ns = 1_000u64;
        let mut admitted = 0usize;
        for (s, idents) in ATTACK_SOURCES.iter().zip(attack_idents.iter()) {
            for ident in idents {
                let key = OverlapKey {
                    addr_family: libc::AF_INET as u8,
                    src: IpAddr::V4(Ipv4Addr::new(10, 0, 61, *s)),
                    dst,
                    ident: *ident,
                    protocol: 6,
                    routing_domain: DOMAIN,
                    ingress_zone: 0,
                    fairness_origin: None,
                };
                if !t.check_and_record(key, 0, 8, now_ns, &FRAG_OVERLAP_DROPPED) {
                    admitted += 1;
                }
            }
        }
        assert_eq!(
            admitted,
            OVERLAP_CAP_PER_DOMAIN_PER_SHARD,
            "crafted attack set must fully admit"
        );

        let mut seen = [false; OVERLAP_SHARDS];
        for (s, idents) in ATTACK_SOURCES.iter().zip(attack_idents.iter()) {
            for ident in idents {
                let key = OverlapKey {
                    addr_family: libc::AF_INET as u8,
                    src: IpAddr::V4(Ipv4Addr::new(10, 0, 61, *s)),
                    dst,
                    ident: *ident,
                    protocol: 6,
                    routing_domain: DOMAIN,
                    ingress_zone: 0,
                    fairness_origin: None,
                };
                assert_eq!(
                    overlap_shard_index_seeded(&key, 0),
                    TARGET_SHARD,
                    "without the secret seed the precomputed key remains in the target shard"
                );
                seen[t.shard_index(&key)] = true;
            }
        }
        let spread = seen.iter().filter(|&&shard_has_keys| shard_has_keys).count();
        assert!(
            spread >= 2,
            "seeded index must scatter the offline-computed set (spread={spread})"
        );

        let mut victim = OverlapKey {
            addr_family: libc::AF_INET as u8,
            src: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 200)),
            dst,
            ident: 0,
            protocol: 6,
            routing_domain: DOMAIN,
            ingress_zone: 0,
            fairness_origin: None,
        };
        while t.shard_index(&victim) != TARGET_SHARD {
            victim.ident += 1;
        }
        let mut same_datagram = victim;
        same_datagram.protocol = 17;
        same_datagram.routing_domain = DOMAIN + 1;
        assert_eq!(
            t.shard_index(&same_datagram),
            t.shard_index(&victim),
            "protocol and routing domain must not split same-datagram shard placement"
        );

        let result = t.check_and_record_detailed(victim, 0, 8, now_ns, &FRAG_OVERLAP_DROPPED);
        assert!(
            !result.dropped,
            "legitimate same-domain key in shard {TARGET_SHARD} must forward, reason={:?}",
            result.reason
        );
    }

    #[test]
    fn seeded_finalizer_scatters_high_nibble_keys_12189() {
        // The finalizer avalanches the full digest and post-fold seed, so
        // high-nibble-only inputs spread even though FNV low bits preserve
        // input-byte locality. Fixed seed/input vectors make this deterministic.
        const SRCS: [u8; 4] = [0x65, 0x75, 0x45, 0x55];
        const IDENTS: [u32; 8] = [0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70];
        const SEEDS: [u64; 3] = [1, 7, 42];
        let dst = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200));
        for seed in SEEDS {
            let t = OverlapTracker::with_seed(seed);
            let mut seen = [false; OVERLAP_SHARDS];
            for s in SRCS {
                for ident in IDENTS {
                    let key = OverlapKey {
                        addr_family: libc::AF_INET as u8,
                        src: IpAddr::V4(Ipv4Addr::new(10, 0, 61, s)),
                        dst,
                        ident,
                        protocol: 6,
                        routing_domain: 7,
                        ingress_zone: 0,
                        fairness_origin: None,
                };
                    seen[t.shard_index(&key)] = true;
                }
            }
            let spread = seen.iter().filter(|&&shard_has_keys| shard_has_keys).count();
            assert!(
                spread >= 2,
                "finalizer must scatter high-nibble-only keys at seed {seed} (spread={spread})"
            );
        }
    }

    #[test]
    fn high_seed_bytes_scatter_precomputed_shard_collisions_12602() {
        // These vectors collide under the previous seeded multiply-shift
        // index at seed 0x5c, not merely at seed zero. The fixed low byte
        // reproduces the attacker's partial-seed knowledge; each higher seed
        // byte is then varied independently.
        const ATTACK_SOURCES: [u8; 4] = [101, 102, 103, 104];
        const IDENTS: [[u32; 8]; 4] = [
            [9, 23, 61, 70, 99, 108, 122, 142],
            [3, 18, 25, 40, 62, 65, 72, 87],
            [15, 35, 40, 57, 82, 102, 111, 124],
            [0, 22, 45, 58, 71, 84, 96, 107],
        ];
        let dst = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200));
        let legacy_index = |key: &OverlapKey, seed: u64| {
            let mut h = 0xcbf2_9ce4_8422_2325 ^ seed;
            let mut mix = |b: u8| {
                h ^= u64::from(b);
                h = h.wrapping_mul(0x0000_0100_0000_01b3);
            };
            mix(key.addr_family);
            let mut buf = [0u8; 16];
            let n = ip_octets(key.src, &mut buf);
            for &b in &buf[..n] {
                mix(b);
            }
            let n = ip_octets(key.dst, &mut buf);
            for &b in &buf[..n] {
                mix(b);
            }
            for b in key.ident.to_be_bytes() {
                mix(b);
            }
            (h.wrapping_mul(0x9e37_79b9_7f4a_7c15) >> 60) as usize
        };
        for (src, idents) in ATTACK_SOURCES.iter().zip(IDENTS.iter()) {
            for ident in idents {
                let key = OverlapKey {
                    addr_family: libc::AF_INET as u8,
                    src: IpAddr::V4(Ipv4Addr::new(10, 0, 61, *src)),
                    dst,
                    ident: *ident,
                    protocol: 6,
                    routing_domain: 7,
                    ingress_zone: 0,
                    fairness_origin: None,
                };
                assert_eq!(
                    legacy_index(&key, 0x5c),
                    5,
                    "fixture key must collide under the old index at the known low byte"
                );
            }
        }
        for seed_byte in 1..8u32 {
            let mut reached = [false; OVERLAP_SHARDS];
            for high in 0..256u64 {
                let seed = 0x5cu64 | (high << (seed_byte * 8));
                let mut occupancy = [0usize; OVERLAP_SHARDS];
                let mut old_occupancy = [0usize; OVERLAP_SHARDS];
                for (src, idents) in ATTACK_SOURCES.iter().zip(IDENTS.iter()) {
                    for ident in idents {
                        let key = OverlapKey {
                            addr_family: libc::AF_INET as u8,
                            src: IpAddr::V4(Ipv4Addr::new(10, 0, 61, *src)),
                            dst,
                            ident: *ident,
                            protocol: 6,
                            routing_domain: 7,
                            ingress_zone: 0,
                            fairness_origin: None,
                };
                        let old_shard = legacy_index(&key, seed);
                        old_occupancy[old_shard] += 1;
                        let shard = overlap_shard_index_seeded(&key, seed);
                        assert!(shard < OVERLAP_SHARDS);
                        occupancy[shard] += 1;
                    }
                }
                let spread = occupancy.iter().filter(|&&n| n != 0).count();
                let max = *occupancy.iter().max().unwrap();
                let old_spread = old_occupancy.iter().filter(|&&n| n != 0).count();
                assert!(
                    old_spread <= 2,
                    "seed byte {seed_byte}, seed {seed:#x}: old index spread={old_spread}"
                );
                assert!(
                    spread >= 4 && max <= 14,
                    "seed byte {seed_byte}, seed {seed:#x}: spread={spread}, max={max}"
                );
                for (i, &n) in occupancy.iter().enumerate() {
                    reached[i] |= n > 0;
                }
            }
            assert!(
                reached.into_iter().all(|seen| seen),
                "seed byte {seed_byte} did not reach every shard"
            );
        }
    }

    #[test]
    fn seeded_index_is_deterministic_in_range_and_distributed_12602() {
        for seed in [0, 1, 0x5c, 0xdead_beef_c0de_f00d] {
            let mut counts = [0usize; OVERLAP_SHARDS];
            for i in 0..8192u32 {
                let mut key = v4_key();
                key.ident = i.wrapping_mul(0x9e37_79b1);
                key.src = IpAddr::V4(Ipv4Addr::new(
                    10, (i >> 16) as u8, (i >> 8) as u8, i as u8,
                ));
                let shard = overlap_shard_index_seeded(&key, seed);
                assert!(shard < OVERLAP_SHARDS);
                assert_eq!(shard, overlap_shard_index_seeded(&key, seed));
                counts[shard] += 1;
            }
            // v6 keys (family + 16-byte addresses) scatter the same way.
            let mut v6counts = [0usize; OVERLAP_SHARDS];
            for i in 0..8192u32 {
                let mut key = v6_key();
                key.ident = i.wrapping_mul(0x9e37_79b1);
                key.src = IpAddr::V6(std::net::Ipv6Addr::new(
                    0x2001, 0x0db8, 0, 0, 0, 0, (i >> 8) as u16, i as u16,
                ));
                let shard = overlap_shard_index_seeded(&key, seed);
                assert!(shard < OVERLAP_SHARDS);
                v6counts[shard] += 1;
            }
            for (shard, count) in v6counts.into_iter().enumerate() {
                assert!(
                    (256..=1024).contains(&count),
                    "seed {seed:#x}: v6 shard {shard} got {count}/8192 keys"
                );
            }
            for (shard, count) in counts.into_iter().enumerate() {
                assert!(
                    (256..=1024).contains(&count),
                    "seed {seed:#x}: shard {shard} got {count}/8192 keys"
                );
            }
        }
    }

    #[test]
    fn post_nat_sender_quota_is_per_tenant_14127() {
        // Decisive check from #14127: two permitted tenants sharing one
        // translated source and one post-NAT shard. Tenant A leaves eight
        // distinct first fragments incomplete; tenant B's different
        // incomplete fragment must still be admitted on the post-NAT key
        // (its pre-NAT key fits trivially), while tenant A's ninth is
        // refused. RED on master: the post key's sender is the shared
        // pool address, so B is denied by A's quota.
        let pool = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8));
        let ext = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let nat = NatDecision {
            rewrite_src: Some(pool),
            ..NatDecision::default()
        };
        let post_key = |src: Ipv4Addr, ident: u32| {
            let mut pre = v4_key();
            pre.src = IpAddr::V4(src);
            pre.dst = ext;
            pre.ident = ident;
            let TranslatedOverlapKey::Key(post) =
                translated_overlap_key(&pre, pre.protocol, &nat, 0)
            else {
                panic!("SNAT fragment requires a post-key");
            };
            post
        };
        // Force every datagram into one shard so the per-shard quota is
        // the binding constraint (the shard hashes family/src/dst/ident,
        // and the post src/dst are identical for both tenants).
        let seed = 1u64;
        let tracker = OverlapTracker::with_seed(seed);
        let mut idents_in_shard = |src: Ipv4Addr, shard: usize, count: usize| {
            let mut out = Vec::new();
            let mut ident = 0u32;
            while out.len() < count {
                let post = post_key(src, ident);
                if overlap_shard_index_seeded(&post, seed) == shard {
                    out.push(ident);
                }
                ident += 1;
            }
            out
        };
        let tenant_a = Ipv4Addr::new(10, 0, 61, 100);
        let tenant_b = Ipv4Addr::new(10, 0, 61, 101);
        let shard = overlap_shard_index_seeded(&post_key(tenant_a, 0), seed);
        let a_idents = idents_in_shard(tenant_a, shard, OVERLAP_CAP_PER_SENDER_PER_SHARD + 1);
        let b_ident = idents_in_shard(tenant_b, shard, OVERLAP_CAP_PER_SENDER_PER_SHARD + 2)
            [OVERLAP_CAP_PER_SENDER_PER_SHARD + 1];
        let now_ns = 1_000u64;
        // Tenant A: eight incomplete first fragments admitted.
        for &ident in &a_idents[..OVERLAP_CAP_PER_SENDER_PER_SHARD] {
            let post = post_key(tenant_a, ident);
            assert!(
                !tracker.check_and_record(post, 0, 8, now_ns, &FRAG_OVERLAP_POST_NAT_DROPPED),
                "tenant A incomplete datagram {ident} must be admitted"
            );
        }
        // Tenant B: a different incomplete fragment through the same
        // pool address and shard must not be denied by A's quota.
        let b_post = post_key(tenant_b, b_ident);
        assert!(
            !tracker.check_and_record(b_post, 0, 8, now_ns, &FRAG_OVERLAP_POST_NAT_DROPPED),
            "tenant B must not share tenant A's post-NAT sender quota"
        );
        // Tenant A's ninth incomplete datagram exceeds its own quota.
        let a_ninth = post_key(tenant_a, a_idents[OVERLAP_CAP_PER_SENDER_PER_SHARD]);
        assert!(
            tracker.check_and_record(a_ninth, 0, 8, now_ns, &FRAG_OVERLAP_POST_NAT_DROPPED),
            "tenant A's ninth incomplete datagram must fail closed on its own quota"
        );
        // Completing tenant A's datagrams does not retroactively deny
        // tenant B: B can still add a tail to its admitted head.
        for &ident in &a_idents[..OVERLAP_CAP_PER_SENDER_PER_SHARD] {
            let post = post_key(tenant_a, ident);
            assert!(
                !tracker.check_and_record(post, 8, 16, now_ns, &FRAG_OVERLAP_POST_NAT_DROPPED),
                "tenant A tail for {ident} must be admitted"
            );
        }
        assert!(
            !tracker.check_and_record(b_post, 8, 16, now_ns, &FRAG_OVERLAP_POST_NAT_DROPPED),
            "tenant B tail must remain admitted after A completes"
        );
    }

    #[test]
    fn domain_change_without_rewrite_gets_post_key_14127() {
        // No address rewrite but egress_domain != pre.routing_domain:
        // the downstream domain needs its own anchor set. RED on
        // master: translated_overlap_key returns NotApplicable.
        let mut pre = v4_key();
        pre.routing_domain = 1;
        let TranslatedOverlapKey::Key(post) =
            translated_overlap_key(&pre, pre.protocol, &NatDecision::default(), 2)
        else {
            panic!("domain change without rewrite requires a post-key");
        };
        assert_eq!(post.routing_domain, 2);
        assert_eq!(post.src, pre.src);
        assert_eq!(post.dst, pre.dst);
        assert_ne!(post, pre);
        // Same-domain no-NAT stays NotApplicable (callers would skip
        // an identical key anyway).
        assert_eq!(
            translated_overlap_key(&pre, pre.protocol, &NatDecision::default(), 1),
            TranslatedOverlapKey::NotApplicable
        );
        // The egress-domain anchor actually anchors: a range recorded
        // under the post key drops an overlapping second fragment, and
        // the arrival domain's ranges do not leak into it.
        let tracker = OverlapTracker::new();
        assert!(!tracker.check_and_record(post, 0, 16, 1_000, &FRAG_OVERLAP_POST_NAT_DROPPED));
        assert!(tracker.check_and_record(post, 8, 24, 1_000, &FRAG_OVERLAP_POST_NAT_DROPPED));
        assert!(!tracker.check_and_record(pre, 0, 16, 1_000, &FRAG_OVERLAP_DROPPED));
    }

    #[test]
    fn failed_post_nat_admission_keeps_cross_tenant_protection_14127() {
        // A failed admission pins the entry (`failed`), so it can never
        // complete or be reclaimed as a completion. Cross-origin
        // incomplete entries in the same downstream domain must count
        // against a later candidate from a poisoned origin again —
        // otherwise two tenants could jointly complete one downstream
        // datagram past the anchored ranges.
        let pool = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8));
        let ext = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let nat = NatDecision {
            rewrite_src: Some(pool),
            ..NatDecision::default()
        };
        let post_key = |src: Ipv4Addr, ident: u32| {
            let mut pre = v4_key();
            pre.src = IpAddr::V4(src);
            pre.dst = ext;
            pre.ident = ident;
            let TranslatedOverlapKey::Key(post) =
                translated_overlap_key(&pre, pre.protocol, &nat, 0)
            else {
                panic!("SNAT fragment requires a post-key");
            };
            post
        };
        let seed = 1u64;
        let tracker = OverlapTracker::with_seed(seed);
        let tenant_a = Ipv4Addr::new(10, 0, 61, 100);
        let tenant_b = Ipv4Addr::new(10, 0, 61, 101);
        let shard = overlap_shard_index_seeded(&post_key(tenant_a, 0), seed);
        let mut in_shard = |src: Ipv4Addr, count: usize| {
            let mut out = Vec::new();
            let mut ident = 0u32;
            while out.len() < count {
                if overlap_shard_index_seeded(&post_key(src, ident), seed) == shard {
                    out.push(ident);
                }
                ident += 1;
            }
            out
        };
        let now_ns = 1_000u64;
        // Tenant B fills its own post-NAT quota with incomplete heads.
        let b_idents = in_shard(tenant_b, OVERLAP_CAP_PER_SENDER_PER_SHARD);
        for &ident in &b_idents {
            assert!(!tracker.check_and_record(
                post_key(tenant_b, ident),
                0,
                8,
                now_ns,
                &FRAG_OVERLAP_POST_NAT_DROPPED
            ));
        }
        // Tenant A records one head, then its admission fails (the
        // packet is dropped downstream of the overlap record).
        let a_ident = in_shard(tenant_a, OVERLAP_CAP_PER_SENDER_PER_SHARD + 1)[OVERLAP_CAP_PER_SENDER_PER_SHARD];
        let a_post = post_key(tenant_a, a_ident);
        let mut a_result = tracker.check_and_record_fragment_detailed(
            a_post,
            0,
            8,
            false,
            now_ns,
            &FRAG_OVERLAP_POST_NAT_DROPPED,
        );
        assert!(!a_result.dropped);
        assert!(tracker.fail_admission(a_result.admission.take().expect("A admission")));
        // A's failed entry stays anchored: an overlapping range drops.
        assert!(tracker.check_overlap(a_post, 4, 12, now_ns, &FRAG_OVERLAP_POST_NAT_DROPPED));
        assert_eq!(tracker.len(), OVERLAP_CAP_PER_SENDER_PER_SHARD + 1);
        // With A poisoned, B's eight incomplete entries count against
        // A again: A's next distinct datagram is refused fail-closed
        // instead of minting a fresh origin-only budget past B's fill.
        let a_next = in_shard(tenant_a, OVERLAP_CAP_PER_SENDER_PER_SHARD + 2)
            [OVERLAP_CAP_PER_SENDER_PER_SHARD + 1];
        assert_ne!(a_next, a_ident);
        assert!(
            tracker.check_and_record(
                post_key(tenant_a, a_next),
                0,
                8,
                now_ns,
                &FRAG_OVERLAP_POST_NAT_DROPPED
            ),
            "poisoned origin must not bypass the shared downstream budget"
        );
    }

    #[test]
    fn cross_zone_domain_fill_cannot_starve_other_zone_14321() {
        // #14321: four senders in zone 1 fill its per-(domain,zone) quota;
        // a victim in zone 2 sharing the same routing domain must still be
        // admitted. RED on master: domain quota is zone-blind (32/domain),
        // so the fill exhausts the domain and the victim drops ShardFull.
        let t = OverlapTracker::with_seed(1);
        let dst = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200));
        let mk = |src_last: u8, ident: u32, zone: u16| OverlapKey {
            addr_family: libc::AF_INET as u8,
            src: IpAddr::V4(Ipv4Addr::new(10, 0, 61, src_last)),
            dst,
            ident,
            protocol: 6,
            routing_domain: 0,
            ingress_zone: zone,
            fairness_origin: None,
        };
        // Find a shard and fill zone 1 there: 4 senders x 8 = 32 entries.
        let probe = mk(101, 0, 1);
        let shard = t.shard_index(&probe);
        let mut idents: std::collections::HashMap<u8, Vec<u32>> =
            std::collections::HashMap::new();
        let mut ident = 0u32;
        while idents.values().map(|v: &Vec<u32>| v.len()).sum::<usize>()
            < OVERLAP_CAP_PER_ZONE_PER_SHARD
        {
            for s in 101..=104u8 {
                let k = mk(s, ident, 1);
                if t.shard_index(&k) == shard
                    && idents.entry(s).or_default().len() < OVERLAP_CAP_PER_SENDER_PER_SHARD
                {
                    idents.entry(s).or_default().push(ident);
                }
            }
            ident += 1;
            assert!(ident < 1_000_000, "must find same-shard idents");
        }
        let now_ns = 1_000u64;
        for (s, list) in &idents {
            for &id in list {
                let r = t.check_and_record_fragment_detailed(
                    mk(*s, id, 1),
                    0,
                    8,
                    false,
                    now_ns,
                    &FRAG_OVERLAP_DROPPED,
                );
                assert!(!r.dropped, "zone-1 fill ident {id} from {s} must admit, reason={:?}", r.reason);
            }
        }
        // Zone 1 is at its own quota: its 5th sender (new sender, same zone)
        // must be refused fail-closed (per-zone quota), not evict.
        let mut z1_extra = None;
        let mut id = 0u32;
        while z1_extra.is_none() {
            let k = mk(109, id, 1);
            if t.shard_index(&k) == shard { z1_extra = Some(k); }
            id += 1;
        }
        let z1_extra = z1_extra.unwrap();
        let r = t.check_and_record_fragment_detailed(z1_extra, 0, 8, false, now_ns, &FRAG_OVERLAP_DROPPED);
        assert!(r.dropped && r.reason == Some(OverlapDropReason::ShardFull),
            "zone-1 over-quota datagram must fail closed, got dropped={} reason={:?}", r.dropped, r.reason);
        // Victim in zone 2, same routing domain and shard, must be admitted.
        let mut victim = None;
        let mut id = 0u32;
        while victim.is_none() {
            let k = mk(200, id, 2);
            if t.shard_index(&k) == shard { victim = Some(k); }
            id += 1;
        }
        let victim = victim.unwrap();
        let r = t.check_and_record_fragment_detailed(victim, 0, 8, false, now_ns, &FRAG_OVERLAP_DROPPED);
        assert!(!r.dropped,
            "zone-2 victim must not be starved by zone-1 fill, reason={:?}", r.reason);
    }

    #[test]
    fn cross_zone_overlap_does_not_poison_other_zone_14321() {
        // #14321 (2): overlapping fragment in zone 1 with same tuple as an
        // active datagram in zone 2 must not poison the zone-2 entry.
        // RED on master: overlap_same_datagram ignores ingress_zone, so the
        // zone-1 overlap drops / merges into the zone-2 entry.
        let t = OverlapTracker::new();
        let mut trust = v4_key();
        trust.ingress_zone = 2;
        let mut untrust = trust;
        untrust.ingress_zone = 1;
        assert!(!t.check_and_record(trust, 0, 16, 1_000, &FRAG_OVERLAP_DROPPED),
            "trust head must admit");
        // Same tuple, other zone, overlapping range: separate datagram for
        // overlap purposes — must admit as its own entry, not drop as overlap.
        assert!(!t.check_and_record(untrust, 8, 24, 1_000, &FRAG_OVERLAP_DROPPED),
            "cross-zone overlapping fragment must not poison/drop via trust entry");
        // Trust tail (adjacent, non-overlapping) still admits and is protected:
        assert!(!t.check_and_record(trust, 16, 32, 1_000, &FRAG_OVERLAP_DROPPED),
            "trust tail must still admit");
        // And a true same-zone overlap still drops fail-closed.
        assert!(t.check_and_record(trust, 8, 24, 1_000, &FRAG_OVERLAP_DROPPED),
            "same-zone overlap must still drop");
        assert!(t.check_and_record(untrust, 16, 32, 1_000, &FRAG_OVERLAP_DROPPED),
            "same-zone (untrust) overlap with its own entry must still drop");
    }
    #[test]
    fn third_zone_admitted_by_cross_zone_completed_reclaim_15103() {
        // #15103 (A74-02): zones A=1 and B=2 each hold 32 COMPLETED anchors
        // in one shard (64 = OVERLAP_CAP_PER_SHARD). A new datagram from
        // zone C=3 must be admitted by reclaiming the globally oldest
        // completed anchor of any zone, instead of ShardFull — the old code
        // reclaims only at the candidate's own 32-entry zone cap (zone C has
        // 0 entries) and then refuses at the 64-entry shard cap.
        // Controls: neither A nor B may exceed 32 (a fresh A/B key with no
        // completed anchor of its own zone left? see below), and a shard
        // full of incomplete anchors still refuses a same-domain third
        // zone only when the candidate is in a different routing domain.
        let t = OverlapTracker::with_seed(1);
        let dst = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200));
        let mk = |src_last: u8, ident: u32, zone: u16| OverlapKey {
            addr_family: libc::AF_INET as u8,
            src: IpAddr::V4(Ipv4Addr::new(10, 0, 71, src_last)),
            dst,
            ident,
            protocol: 6,
            routing_domain: 0,
            ingress_zone: zone,
            fairness_origin: None,
        };
        // Target shard from a probe key.
        let probe = mk(101, 0, 1);
        let shard = t.shard_index(&probe);
        // Collect same-shard idents per sender, respecting the 8/sender cap:
        // zone A: senders 101..=104, zone B: senders 201..=204.
        let collect = |senders: &[u8], per_sender: usize, total: usize| -> Vec<(u8, u32)> {
            let mut out: Vec<(u8, u32)> = Vec::new();
            let mut counts: std::collections::HashMap<u8, usize> = std::collections::HashMap::new();
            let mut ident = 0u32;
            while out.len() < total {
                for &s in senders {
                    if *counts.get(&s).unwrap_or(&0) >= per_sender {
                        continue;
                    }
                    let k = mk(s, ident, if (101..=104).contains(&s) { 1 } else { 2 });
                    if t.shard_index(&k) == shard {
                        out.push((s, ident));
                        *counts.entry(s).or_insert(0) += 1;
                        if out.len() == total {
                            break;
                        }
                    }
                }
                ident += 1;
                assert!(ident < 10_000_000, "must find same-shard idents");
            }
            out
        };
        let zone_a = collect(&[101, 102, 103, 104], 8, OVERLAP_CAP_PER_ZONE_PER_SHARD);
        let zone_b = collect(&[201, 202, 203, 204], 8, OVERLAP_CAP_PER_ZONE_PER_SHARD);
        assert_eq!(zone_a.len(), 32);
        assert_eq!(zone_b.len(), 32);
        // Plant every entry as a COMPLETED single-fragment datagram
        // (is_last=true, ranges cover terminal end), then commit so
        // pending==0 — the only reclaimable kind.
        let now_ns = 1_000u64;
        let mut planted_keys: Vec<OverlapKey> = Vec::new();
        for &(s, id) in zone_a.iter().chain(zone_b.iter()) {
            let zone = if s < 200 { 1 } else { 2 };
            let k = mk(s, id, zone);
            planted_keys.push(k);
            let mut r =
                t.check_and_record_fragment_detailed(k, 0, 8, true, now_ns, &FRAG_OVERLAP_DROPPED);
            assert!(
                !r.dropped,
                "fill s={s} ident={id} zone={zone} must admit, reason={:?}",
                r.reason
            );
            let tok = r.admission.take().expect("admission");
            assert!(
                t.commit_admission(tok),
                "single-fragment datagram completes"
            );
        }
        assert_eq!(t.len(), OVERLAP_CAP_PER_SHARD, "two zones fill the shard");
        // Control 1: a fresh zone-A datagram cannot exceed 32. It can only
        // reclaim its own zone's completed anchors, so it IS admitted by
        // replacing an A anchor — shard size stays 64 and zone A stays 32.
        // (Sender 109 is new; per-zone reclaim keeps the cap.)
        let mut a_extra = None;
        let mut id = 0u32;
        while a_extra.is_none() {
            let k = mk(109, id, 1);
            if t.shard_index(&k) == shard {
                a_extra = Some(k);
            }
            id += 1;
            assert!(id < 1_000_000);
        }
        let a_extra = a_extra.unwrap();
        let mut r = t.check_and_record_fragment_detailed(
            a_extra,
            0,
            8,
            true,
            now_ns,
            &FRAG_OVERLAP_DROPPED,
        );
        assert!(
            !r.dropped,
            "zone-A extra must reclaim its own completed anchor, reason={:?}",
            r.reason
        );
        assert!(t.commit_admission(r.admission.take().unwrap()));
        assert_eq!(t.len(), OVERLAP_CAP_PER_SHARD);
        // Victim: zone C's first datagram in the same shard. Pre-fix this
        // drops ShardFull (zone C has 0 entries, shard is at 64). Post-fix
        // the globally oldest completed anchor (any zone) is reclaimed.
        let mut victim = None;
        let mut id = 0u32;
        while victim.is_none() {
            let k = mk(250, id, 3);
            if t.shard_index(&k) == shard {
                victim = Some(k);
            }
            id += 1;
            assert!(id < 1_000_000);
        }
        let victim = victim.unwrap();
        let full0 = FRAG_OVERLAP_SHARD_FULL_DROPPED.load(Ordering::Relaxed);
        let reclaim0 = FRAG_OVERLAP_CROSS_ZONE_RECLAIMED.load(Ordering::Relaxed);
        let mut r =
            t.check_and_record_fragment_detailed(victim, 0, 8, true, now_ns, &FRAG_OVERLAP_DROPPED);
        assert!(
            !r.dropped,
            "zone-C victim must be admitted by cross-zone completed reclaim, reason={:?}",
            r.reason
        );
        assert!(t.commit_admission(r.admission.take().unwrap()));
        assert_eq!(
            t.len(),
            OVERLAP_CAP_PER_SHARD,
            "reclaim keeps the 64-entry bound"
        );
        assert_eq!(
            FRAG_OVERLAP_SHARD_FULL_DROPPED
                .load(Ordering::Relaxed)
                .wrapping_sub(full0),
            0,
            "admitted victim must not count as a shard-full refusal"
        );
        assert_eq!(
            FRAG_OVERLAP_CROSS_ZONE_RECLAIMED
                .load(Ordering::Relaxed)
                .wrapping_sub(reclaim0),
            1,
            "exactly the globally oldest completed anchor is reclaimed"
        );
        // Control 2: a shard full of INCOMPLETE anchors (no terminal end,
        // never completable) in routing domain 0 must still refuse a
        // candidate from a DIFFERENT routing domain fail-closed — the
        // #15288 cross-zone incomplete fallback is scoped to the
        // candidate's own routing domain (same-domain third zones are
        // admitted by that fallback; see the _15288 regression).
        let t2 = OverlapTracker::with_seed(1);
        let probe2 = t2.shard_index(&mk(101, 0, 1));
        let inc_a = collect(&[101, 102, 103, 104], 8, OVERLAP_CAP_PER_ZONE_PER_SHARD);
        // collect() targets t's shard; t and t2 share seed 1 so indices agree.
        let _ = probe2;
        let inc_b = collect(&[201, 202, 203, 204], 8, OVERLAP_CAP_PER_ZONE_PER_SHARD);
        for &(s, id) in inc_a.iter().chain(inc_b.iter()) {
            let zone = if s < 200 { 1 } else { 2 };
            let k = mk(s, id, zone);
            // is_last=false: no terminal end, never completes.
            assert!(
                !t2.check_and_record_fragment(k, 0, 8, false, now_ns, &FRAG_OVERLAP_DROPPED),
                "incomplete fill s={s} ident={id} must admit"
            );
        }
        assert_eq!(t2.len(), OVERLAP_CAP_PER_SHARD);
        let mut victim2 = None;
        let mut id = 0u32;
        while victim2.is_none() {
            let mut k = mk(250, id, 3);
            k.routing_domain = 99;
            if t2.shard_index(&k) == shard {
                victim2 = Some(k);
            }
            id += 1;
            assert!(id < 1_000_000);
        }
        let victim2 = victim2.unwrap();
        let r2 = t2.check_and_record_fragment_detailed(
            victim2,
            0,
            8,
            true,
            now_ns,
            &FRAG_OVERLAP_DROPPED,
        );
        assert!(r2.dropped && r2.reason == Some(OverlapDropReason::ShardFull),
            "cross-domain candidate must not reclaim another domain's incomplete anchors: must fail closed, got dropped={} reason={:?}",
            r2.dropped, r2.reason);
        assert_eq!(t2.len(), OVERLAP_CAP_PER_SHARD, "refusal must not evict");
    }

    #[test]
    fn third_zone_admitted_past_incomplete_zones_via_incomplete_reclaim_15288() {
        // #15288 (gemini D4-01): zones A=1 and B=2 each hold 32
        // settled-INCOMPLETE anchors in one shard (64 =
        // OVERLAP_CAP_PER_SHARD, none completed, none failed). A new
        // datagram from zone C=3 must be admitted by reclaiming the
        // globally oldest settled-incomplete anchor of another zone in
        // the same routing domain (bumping
        // FRAG_OVERLAP_CROSS_ZONE_INCOMPLETE_RECLAIMED), instead of the
        // ShardFull the current code returns because it only reclaims
        // completed anchors (#15103). Controls: neither A nor B may
        // exceed 32, the evicted anchor's overlap protection is gone, a
        // C key survives a same-created_ns A victim's churn, and a
        // shard of FAILED anchors still refuses zone C fail-closed
        // (failed anchors are poison and are never reclaimed).
        let t = OverlapTracker::with_seed(1);
        let dst = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200));
        let mk = |src_last: u8, ident: u32, zone: u16| OverlapKey {
            addr_family: libc::AF_INET as u8,
            src: IpAddr::V4(Ipv4Addr::new(10, 0, 81, src_last)),
            dst,
            ident,
            protocol: 6,
            routing_domain: 0,
            ingress_zone: zone,
            fairness_origin: None,
        };
        let probe = mk(101, 0, 1);
        let shard = t.shard_index(&probe);
        let collect = |senders: &[u8], zone: u16, total: usize| -> Vec<(u8, u32)> {
            let mut out: Vec<(u8, u32)> = Vec::new();
            let mut counts: std::collections::HashMap<u8, usize> = std::collections::HashMap::new();
            let mut ident = 0u32;
            while out.len() < total {
                for &s in senders {
                    if *counts.get(&s).unwrap_or(&0) >= OVERLAP_CAP_PER_SENDER_PER_SHARD {
                        continue;
                    }
                    let k = mk(s, ident, zone);
                    if t.shard_index(&k) == shard {
                        out.push((s, ident));
                        *counts.entry(s).or_insert(0) += 1;
                        if out.len() == total {
                            break;
                        }
                    }
                }
                ident += 1;
                assert!(ident < 10_000_000, "must find same-shard idents");
            }
            out
        };
        let find_key =
            |t: &OverlapTracker, src_last: u8, zone: u16, skip: &[(u8, u32)]| -> OverlapKey {
                let mut ident = 0u32;
                loop {
                    let k = mk(src_last, ident, zone);
                    if t.shard_index(&k) == shard && !skip.contains(&(src_last, ident)) {
                        return k;
                    }
                    ident += 1;
                    assert!(ident < 10_000_000, "must find same-shard key");
                }
            };
        let zone_a = collect(&[101, 102, 103, 104], 1, OVERLAP_CAP_PER_ZONE_PER_SHARD);
        let zone_b = collect(&[201, 202, 203, 204], 2, OVERLAP_CAP_PER_ZONE_PER_SHARD);
        assert_eq!(zone_a.len(), 32);
        assert_eq!(zone_b.len(), 32);
        // Plant every entry as a SETTLED-INCOMPLETE anchor: record one
        // non-terminal fragment (is_last=false, no terminal end, never
        // completable) via the detailed API and commit its admission, so
        // pending settles to 0 without completing — the production shape
        // of a forwarded first fragment whose tail has not arrived.
        let now_ns = 1_000u64;
        for &(s, id) in zone_a.iter().chain(zone_b.iter()) {
            let zone = if s < 200 { 1 } else { 2 };
            let k = mk(s, id, zone);
            let mut r =
                t.check_and_record_fragment_detailed(k, 0, 8, false, now_ns, &FRAG_OVERLAP_DROPPED);
            assert!(
                !r.dropped,
                "incomplete fill s={s} ident={id} zone={zone} must admit, reason={:?}",
                r.reason
            );
            assert!(
                !t.commit_admission(r.admission.take().expect("fill admission")),
                "non-terminal fragment must not complete"
            );
        }
        assert_eq!(
            t.len(),
            OVERLAP_CAP_PER_SHARD,
            "two zones fill the shard with incomplete entries"
        );
        // Victim: zone C's first datagram in the same shard. Pre-fix this
        // drops ShardFull (no completed anchor exists to reclaim).
        let victim_c = find_key(&t, 250, 3, &[]);
        let full0 = FRAG_OVERLAP_SHARD_FULL_DROPPED.load(Ordering::Relaxed);
        let inc0 = FRAG_OVERLAP_CROSS_ZONE_INCOMPLETE_RECLAIMED.load(Ordering::Relaxed);
        let comp0 = FRAG_OVERLAP_CROSS_ZONE_RECLAIMED.load(Ordering::Relaxed);
        let mut r = t.check_and_record_fragment_detailed(
            victim_c,
            0,
            8,
            false,
            now_ns,
            &FRAG_OVERLAP_DROPPED,
        );
        assert!(
            !r.dropped,
            "zone-C victim must be admitted by cross-zone incomplete reclaim, reason={:?}",
            r.reason
        );
        assert_eq!(
            t.len(),
            OVERLAP_CAP_PER_SHARD,
            "reclaim keeps the 64-entry bound"
        );
        assert_eq!(
            FRAG_OVERLAP_SHARD_FULL_DROPPED
                .load(Ordering::Relaxed)
                .wrapping_sub(full0),
            0,
            "admitted victim must not count as a shard-full refusal"
        );
        assert_eq!(
            FRAG_OVERLAP_CROSS_ZONE_INCOMPLETE_RECLAIMED
                .load(Ordering::Relaxed)
                .wrapping_sub(inc0),
            1,
            "exactly the globally oldest incomplete anchor is reclaimed"
        );
        assert_eq!(
            FRAG_OVERLAP_CROSS_ZONE_RECLAIMED
                .load(Ordering::Relaxed)
                .wrapping_sub(comp0),
            0,
            "no completed anchor exists, so the completed counter must not move"
        );
        // The globally oldest incomplete anchor is zone A's first planted
        // entry (all planted at the same now_ns; Vec order breaks the tie).
        // Its ranges no longer detect overlap: a fragment that would have
        // overlapped it now plants a fresh entry instead of dropping.
        let evicted = mk(zone_a[0].0, zone_a[0].1, 1);
        let mut r = t.check_and_record_fragment_detailed(
            evicted,
            4,
            12,
            false,
            now_ns,
            &FRAG_OVERLAP_DROPPED,
        );
        assert!(
            !r.dropped,
            "evicted anchor must no longer drop overlapping fragments, reason={:?}",
            r.reason
        );
        // Settle the two fresh admissions so they cannot be reclaimed as
        // incomplete victims by the churn below.
        assert!(!t.commit_admission(r.admission.take().expect("evicted replant admission")));
        // Control: zone A cannot exceed 32 via churn that reclaims C.
        // A fresh A key arrives while A is back at 32 (31 originals + the
        // replanted evicted key). Its own-zone path has no completed A
        // anchor to reclaim, so it refuses -- it must NOT steal C's slot
        // through the cross-zone incomplete path.
        let a_extra = find_key(&t, 109, 1, &zone_a);
        let r = t.check_and_record_fragment_detailed(
            a_extra,
            0,
            8,
            false,
            now_ns,
            &FRAG_OVERLAP_DROPPED,
        );
        assert!(
            r.dropped && r.reason == Some(OverlapDropReason::ShardFull),
            "zone-A over-quota datagram must fail closed, got dropped={} reason={:?}",
            r.dropped,
            r.reason
        );
        // C's entry survived A's churn attempt: its ranges still drop.
        assert!(
            t.check_overlap(victim_c, 4, 12, now_ns, &FRAG_OVERLAP_DROPPED),
            "zone-C anchor must still detect overlap after zone-A churn"
        );
        // Control: a shard full of FAILED anchors still refuses zone C
        // fail-closed -- failed anchors are poison and never reclaimed.
        let t2 = OverlapTracker::with_seed(1);
        for &(s, id) in zone_a.iter().chain(zone_b.iter()) {
            let zone = if s < 200 { 1 } else { 2 };
            let k = mk(s, id, zone);
            let mut r = t2.check_and_record_fragment_detailed(
                k,
                0,
                8,
                false,
                now_ns,
                &FRAG_OVERLAP_DROPPED,
            );
            assert!(!r.dropped, "failed-fill s={s} ident={id} must admit");
            assert!(
                t2.fail_admission(r.admission.take().expect("failed-fill admission")),
                "fail_admission must settle the fill entry"
            );
        }
        assert_eq!(t2.len(), OVERLAP_CAP_PER_SHARD);
        let victim2 = find_key(&t2, 250, 3, &[]);
        let inc1 = FRAG_OVERLAP_CROSS_ZONE_INCOMPLETE_RECLAIMED.load(Ordering::Relaxed);
        let r2 = t2.check_and_record_fragment_detailed(
            victim2,
            0,
            8,
            false,
            now_ns,
            &FRAG_OVERLAP_DROPPED,
        );
        assert!(r2.dropped && r2.reason == Some(OverlapDropReason::ShardFull),
            "failed anchors must never be reclaimed: zone-C must fail closed, got dropped={} reason={:?}",
            r2.dropped, r2.reason);
        assert_eq!(t2.len(), OVERLAP_CAP_PER_SHARD, "refusal must not evict");
        assert_eq!(
            FRAG_OVERLAP_CROSS_ZONE_INCOMPLETE_RECLAIMED
                .load(Ordering::Relaxed)
                .wrapping_sub(inc1),
            0,
            "failed-anchor refusal must not bump the incomplete-reclaim counter"
        );
    }
}
