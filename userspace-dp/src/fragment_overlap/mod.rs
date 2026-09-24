//! #9950 (F-035): stateful IPv4/IPv6 fragment-overlap tracker.
//!
//! The stateless screens (`screen/stateless.rs`) inspect only the FIRST fragment's
//! L4 flags (`check_tcp_flag_screens` skips non-first) and state they are NOT overlap
//! detectors. Enforcement (zone policy `application any`, screens, NAT) therefore runs
//! on bytes a later overlapping fragment can rewrite before the receiver reassembles —
//! an IDS/enforcement-evasion primitive. This tracker closes the ordering gap by dropping
//! overlapping fragments (RFC 5722 / Juniper `tear-drop` semantics).
//!
//! Key is the receiver's reassembly key plus the routing domain:
//! `(family, src, dst, ident, proto, routing_domain)` for IPv4, with `protocol` pinned
//! to 0 for IPv6 (the receiver reassembles on src/dst/ident only, RFC 8200 §4.5, while
//! the Fragment Header's Next Header is vary-able — keying it would let an attacker
//! split overlap keys the receiver still reassembles together). WITHOUT ingress
//! interface/zone/authority (ECMP/LAG L4-hash routinely splits one datagram's fragments
//! across ingresses; authority-scoping would under-drop the threat itself), but WITH the
//! routing domain: overlapping tenant tuples in isolated VRFs never share a receiver,
//! so a domain-free key would let tenant A drop tenant B's fragments (cross-VRF
//! poisoning). The domain is stamped by the caller from the same SSOT as session keys
//! (`forwarding::ingress_routing_domain`, or the parsed flow's stamped domain).
//!
//! Lifetimes cover realistic reassembly windows, not packet spacing. Linux holds
//! incomplete datagrams up to `ipfrag_time` (30s); a 2s tracker TTL would reopen the
//! evasion by WAITING (fragments 3s apart share no tracker entry yet reassemble
//! together). Hence: 30s idle TTL (refreshed on record) + 60s absolute bound (never
//! refreshed; reclaims sustained same-key streams). Memory is cap-bounded, not
//! TTL-bounded: ≈48B key + 128B ranges (16×8B) + stamps ≈ 200B/entry × 1024 entries
//! (16 shards × 64) ≈ 200KB fixed. The TTL only sets how long attack residue squats,
//! which the absolute bound + shard caps contain.
//! Fairness (#10658): one sender (`routing_domain`, family, `src`) holds at most
//! 8 entries per shard; a routing domain holds at most 32 per shard. New keys over
//! either cap fail closed without evicting live ranges, reserving at least half of
//! every shard for other domains and preserving same-domain senders' overlap anchors.
//! A sender's ninth key in a shard is dropped, not allowed to evict an older datagram.
//!
//! Failure directions (explicit — they differ from `fragment_assoc`):
//!   * Overlap/empty/overflow/capacity all fail CLOSED (drop). Sender/domain quota and
//!     full-shard limits drop new keys without evicting live ranges, preserving every
//!     admitted datagram's overlap anchor. Flood-time availability loss at the
//!     sender/domain quota is the correct trade for a security control.
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
//! geometry) and drops post-collisions. Pure port-PAT (no addr change, same domain)
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

use crate::ip_proto::{PROTO_ICMP, PROTO_ICMPV6};
use crate::nat::NatDecision;

/// Overlap drops (strict overlap `max(starts) < min(ends)`, plus empty ranges).
/// Read as a delta in tests; the post-NAT hook counts to POST_NAT instead.
pub(crate) static FRAG_OVERLAP_DROPPED: AtomicU64 = AtomicU64::new(0);
/// Range-cap overflow drops (17th disjoint range, fail-closed).
pub(crate) static FRAG_OVERLAP_OVERFLOW_DROPPED: AtomicU64 = AtomicU64::new(0);
/// Capacity drops (sender/domain quota or a full shard; fail-closed, no live eviction).
pub(crate) static FRAG_OVERLAP_SHARD_FULL_DROPPED: AtomicU64 = AtomicU64::new(0);
/// Post-translation overlap drops (TX-site hook, translated key).
pub(crate) static FRAG_OVERLAP_POST_NAT_DROPPED: AtomicU64 = AtomicU64::new(0);
/// Absolute-lifetime evictions (sustained same-key streams).
pub(crate) static FRAG_OVERLAP_MAX_LIFETIME_EVICTIONS: AtomicU64 = AtomicU64::new(0);

pub(crate) const OVERLAP_SHARDS: usize = 16;
pub(crate) const OVERLAP_CAP_PER_SHARD: usize = 64;
/// Max entries one sender holds per shard (#10658).
pub(crate) const OVERLAP_CAP_PER_SENDER_PER_SHARD: usize = 8;
/// A routing domain can use at most half a shard, preserving capacity for other domains.
pub(crate) const OVERLAP_CAP_PER_DOMAIN_PER_SHARD: usize = OVERLAP_CAP_PER_SHARD / 2;
/// 30s idle TTL — covers the Linux `ipfrag_time` reassembly window (see docs).
pub(crate) const OVERLAP_TTL_NS: u64 = 30_000_000_000;
/// 60s absolute bound from first sighting — never refreshed by later fragments.
pub(crate) const OVERLAP_MAX_LIFETIME_NS: u64 = 60_000_000_000;
/// Max disjoint ranges per datagram; the 17th fails closed.
pub(crate) const OVERLAP_MAX_RANGES: usize = 16;

/// Receiver's reassembly key + routing domain. `protocol` is the IPv4 Protocol byte;
/// for IPv6 it is always 0 (dropped from the key — see module docs). `routing_domain`
/// is stamped by the caller (flow's stamped domain, else the ingress SSOT); parse
/// leaves it 0.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct OverlapKey {
    pub(crate) addr_family: u8,
    pub(crate) src: IpAddr,
    pub(crate) dst: IpAddr,
    pub(crate) ident: u32,
    pub(crate) protocol: u8,
    pub(crate) routing_domain: u32,
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
    Fragment(OverlapKey, u32, u32, bool),
    Unreadable,
}

/// Cross-worker overlap tracker. Cheap to `Clone` (Arc-backed shards).
#[derive(Clone)]
pub(crate) struct OverlapTracker {
    shards: Arc<Vec<Mutex<Vec<OverlapEntry>>>>,
    next_revision: Arc<AtomicU64>,
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

/// FNV-1a over the coarse `(family, src, dst, ident)` digest. Protocol and routing
/// domain are deliberately excluded so same-datagram candidates (hostile proto-varying
/// v4, cross-domain floods) co-locate in one shard; membership is by full-key equality.
pub(crate) fn overlap_shard_index(key: &OverlapKey) -> usize {
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
    (h as usize) & (OVERLAP_SHARDS - 1)
}
/// Fairness identity (#10658): the admitted sender. `dst`/`ident`/`protocol` are
/// excluded — keying them would let one sender mint fresh quota by varying the
/// destination, ident, or (v4) protocol byte.
#[inline]
fn overlap_sender(key: &OverlapKey) -> (u32, u8, IpAddr) {
    (key.routing_domain, key.addr_family, key.src)
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
        let mut shards = Vec::with_capacity(OVERLAP_SHARDS);
        for _ in 0..OVERLAP_SHARDS {
            shards.push(Mutex::new(Vec::with_capacity(OVERLAP_CAP_PER_SHARD)));
        }
        Self {
            shards: Arc::new(shards),
            next_revision: Arc::new(AtomicU64::new(1)),
        }
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
        _is_last: bool,
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
        let idx = overlap_shard_index(&key);
        let mut shard = self.shards[idx]
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut lifetime_evictions = 0;
        shard.retain(|e| overlap_entry_live(e, now_ns, &mut lifetime_evictions));
        let Some(pos) = shard.iter().position(|e| e.key == key) else {
            return OverlapCheckResult {
                dropped: false,
                reason: None,
                lifetime_evictions,
                completion: None,
                admission: None,
                tracker: None,
            };
        };
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
        let idx = overlap_shard_index(&key);
        let mut shard = self.shards[idx]
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut lifetime_evictions = 0;
        shard.retain(|e| overlap_entry_live(e, now_ns, &mut lifetime_evictions));
        if let Some(pos) = shard.iter().position(|e| e.key == key) {
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
        // #10658: reserve shard capacity by routing domain and sender. Quota hits
        // fail closed rather than evicting another datagram's live anchor ranges.
        let sender = overlap_sender(&key);
        let mut sender_entries = 0usize;
        let mut domain_entries = 0usize;
        for e in shard.iter() {
            if overlap_sender(&e.key) == sender {
                sender_entries += 1;
            }
            if e.key.routing_domain == key.routing_domain {
                domain_entries += 1;
            }
        }
        if sender_entries >= OVERLAP_CAP_PER_SENDER_PER_SHARD
            || domain_entries >= OVERLAP_CAP_PER_DOMAIN_PER_SHARD
            || shard.len() >= OVERLAP_CAP_PER_SHARD
        {
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
    /// Reclaim happens only when every recorded fragment has settled, the
    /// datagram has a terminal range, and no admission failed.
    pub(crate) fn commit_admission(&self, token: OverlapAdmissionToken) -> bool {
        let idx = overlap_shard_index(&token.key);
        let mut shard = self.shards[idx]
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(pos) = shard.iter().position(|e| e.key == token.key) else {
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
                    shard.remove(pos);
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
        let idx = overlap_shard_index(&token.key);
        let mut shard = self.shards[idx]
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(pos) = shard.iter().position(|e| e.key == token.key) else {
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
        let idx = overlap_shard_index(&token.key);
        let mut shard = self.shards[idx]
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(pos) = shard.iter().position(|e| e.key == token.key) else {
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
                },
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
            let end = start.saturating_add(declared.min(wire) as u32);
            OverlapParse::Fragment(
                OverlapKey {
                    addr_family: libc::AF_INET6 as u8,
                    src: IpAddr::V6(Ipv6Addr::from(src_b)),
                    dst: IpAddr::V6(Ipv6Addr::from(dst_b)),
                    ident,
                    protocol: 0,
                    routing_domain: 0,
                },
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

/// Compute the POST-translation overlap key for a fragment whose pre-translation key
/// is `pre` under NAT decision `nat`. Returns `None` when no translation applies
/// (caller skips — the pre-check sufficed) or when the translated key is identical to
/// `pre` (pure port-PAT: same key+range would self-overlap — the caller MUST skip the
/// post-check on key equality). Returns `None` for NAT64 v4→v6 by the injectivity proof
/// in the module docs. `egress_domain` is the post-translation routing domain (the
/// downstream receiver's domain, resolved from the egress interface).
pub(crate) fn translated_overlap_key(
    pre: &OverlapKey,
    nat: &NatDecision,
    egress_domain: u32,
) -> Option<OverlapKey> {
    if nat.nat64 {
        if pre.addr_family as i32 == libc::AF_INET6 {
            // v6→v4: pool + server addrs from the decision, ident truncated to 16 bits.
            Some(OverlapKey {
                addr_family: libc::AF_INET as u8,
                src: nat.rewrite_src?,
                dst: nat.rewrite_dst?,
                ident: pre.ident & 0xFFFF,
                protocol: map_v6_to_v4_proto(pre.protocol),
                routing_domain: egress_domain,
            })
        } else {
            // v4→v6: post-key is injective in the pre-key (zero-extended ident +
            // injectively-derived v6 addrs under a fixed pool), so a post-collision
            // implies a pre-collision the pre-check already caught. No post-check.
            None
        }
    } else if nat.rewrite_src.is_some() || nat.rewrite_dst.is_some() {
        Some(OverlapKey {
            addr_family: pre.addr_family,
            src: nat.rewrite_src.unwrap_or(pre.src),
            dst: nat.rewrite_dst.unwrap_or(pre.dst),
            ident: pre.ident,
            protocol: pre.protocol,
            routing_domain: egress_domain,
        })
    } else {
        None
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
        }
    }

    fn dropped_delta(f: impl FnOnce()) -> u64 {
        let d0 = FRAG_OVERLAP_DROPPED.load(Ordering::Relaxed);
        f();
        FRAG_OVERLAP_DROPPED.load(Ordering::Relaxed).wrapping_sub(d0)
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
            OverlapParse::Fragment(k, s, e, is_last) => {
                assert_eq!((s, e), (0, 8));
                assert!(!is_last);
                assert_eq!(k.ident, 0xBEEF);
                assert_eq!(k.protocol, 6);
            }
            other => panic!("expected Fragment, got {other:?}"),
        }
        let mut truncated_last = pkt.clone();
        truncated_last[6..8].copy_from_slice(&0x0001u16.to_be_bytes());
        match overlap_parse(&truncated_last, libc::AF_INET) {
            OverlapParse::Fragment(_, _, _, is_last) => {
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
        let (k, s, e, is_last) = match overlap_parse(&pkt, libc::AF_INET6) {
            OverlapParse::Fragment(k, s, e, is_last) => (k, s, e, is_last),
            other => panic!("expected Fragment, got {other:?}"),
        };
        assert_eq!((s, e), (0, 16));
        assert!(!is_last);
        assert_eq!(k.protocol, 0);
        assert_eq!(k.ident, 0x01020304);
        // Same datagram, different Next Header (UDP=17): SAME key (proto dropped).
        // RED-on-revert: keying Next Header would split overlap detection.
        let mut pkt2 = pkt.clone();
        pkt2[40] = 17;
        pkt2[42..44].copy_from_slice(&0x0009u16.to_be_bytes());
        let (k2, s2, e2, is_last2) = match overlap_parse(&pkt2, libc::AF_INET6) {
            OverlapParse::Fragment(k, s, e, is_last) => (k, s, e, is_last),
            other => panic!("expected Fragment, got {other:?}"),
        };
        assert_eq!(k2, k);
        assert!(!is_last2);
        assert_eq!((s2, e2), (8, 24));
        let mut truncated_last = pkt.clone();
        truncated_last[42..44].copy_from_slice(&0x0008u16.to_be_bytes());
        truncated_last.truncate(60);
        match overlap_parse(&truncated_last, libc::AF_INET6) {
            OverlapParse::Fragment(_, _, _, is_last) => {
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
        let nat = NatDecision {
            rewrite_src: Some(pool),
            rewrite_dst: None,
            rewrite_src_port: None,
            rewrite_dst_port: None,
            nat64: false,
            nptv6: false,
        };
        let mut a = v4_key();
        a.src = IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100));
        a.dst = ext;
        let mut b = v4_key();
        b.src = IpAddr::V4(Ipv4Addr::new(10, 0, 61, 101));
        b.dst = ext;
        assert_ne!(a, b);
        let pa = translated_overlap_key(&a, &nat, 0).expect("post");
        let pb = translated_overlap_key(&b, &nat, 0).expect("post");
        assert_eq!(pa, pb);
        assert_eq!(pa.src, pool);
        let t = OverlapTracker::new();
        assert!(!t.check_and_record(pa, 0, 16, 1_000, &FRAG_OVERLAP_POST_NAT_DROPPED));
        let p0 = FRAG_OVERLAP_POST_NAT_DROPPED.load(Ordering::Relaxed);
        assert!(t.check_and_record(pb, 8, 24, 1_000, &FRAG_OVERLAP_POST_NAT_DROPPED));
        assert_eq!(
            FRAG_OVERLAP_POST_NAT_DROPPED.load(Ordering::Relaxed).wrapping_sub(p0),
            1
        );
        // No rewrite → None (pre-check sufficed).
        assert!(translated_overlap_key(&a, &NatDecision::default(), 0).is_none());
        // Pure port-PAT (no addr rewrite) → identical key → caller must skip.
        let port_only = NatDecision {
            rewrite_src_port: Some(40000),
            ..NatDecision::default()
        };
        // (No addr rewrite at all → None; addr-preserving covered by equality rule.)
        assert!(translated_overlap_key(&a, &port_only, 0).is_none());
    }

    #[test]
    fn translated_key_nat64_truncation_collision_9950() {
        // v6 idents 0x00010001/0x00020001 truncate to the same v4 ident 1 with the same
        // translated addrs: distinct pre-keys, one post-key, overlapping post-ranges drop.
        let v4src = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 50));
        let v4dst = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let nat = NatDecision {
            rewrite_src: Some(v4src),
            rewrite_dst: Some(v4dst),
            rewrite_src_port: None,
            rewrite_dst_port: None,
            nat64: true,
            nptv6: false,
        };
        let mk = |ident: u32| OverlapKey {
            addr_family: libc::AF_INET6 as u8,
            src: IpAddr::V6(Ipv6Addr::LOCALHOST),
            dst: IpAddr::V6(Ipv6Addr::LOCALHOST),
            ident,
            protocol: 0,
            routing_domain: 0,
        };
        let a = mk(0x0001_0001);
        let b = mk(0x0002_0001);
        let pa = translated_overlap_key(&a, &nat, 0).expect("post");
        let pb = translated_overlap_key(&b, &nat, 0).expect("post");
        assert_eq!(pa, pb);
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
        assert!(translated_overlap_key(&v4pre, &nat64v4, 0).is_none());
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
    fn completed_datagram_reclaims_only_after_all_admissions_10285() {
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
        assert!(t.commit_admission(first_admission));
        assert_eq!(t.len(), 0, "completed datagram is reclaimed immediately");
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
        assert_eq!(t.len(), 0);
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
        assert_eq!(t.len(), 0);

        let mut second = t.check_and_record_fragment_detailed(
            key,
            0,
            8,
            true,
            3_000,
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
        assert_eq!(t.len(), 0);
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
    fn completed_entries_free_shard_capacity_without_eviction_10285() {
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
        let mut admitted = t.check_and_record_fragment_detailed(
            keys[OVERLAP_CAP_PER_SHARD],
            0,
            8,
            true,
            2_000,
            &FRAG_OVERLAP_DROPPED,
        );
        assert!(!admitted.dropped);
        assert!(t.commit_admission(admitted.admission.take().expect("admitted token")));
        assert_eq!(t.len(), 0);
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
            last.completion.is_none(),
            "ranges extending past the terminal fragment are not completion"
        );
        assert_eq!(t.len(), 1);
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
        let mut second = t.check_and_record_fragment_detailed(
            key,
            0,
            8,
            true,
            2_000,
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
        assert_eq!(t.len(), 0);
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

}
