//! #2562 / #3291-stage-4: session-bound, port-free fragment-association cache.
//!
//! A non-first fragment carries NO L4 header, so it cannot recover the first
//! fragment's flow/session key. The cache lets NAT64 and same-family NAT
//! fragments inherit their translation, and lets plain-forward fragments
//! inherit an admitted no-NAT session decision (#11412).
//!
//! Design (converged /research pass; see issue #2562 / PR #4686):
//!
//!   * Key is PORT-FREE — `(addr_family, src, dst, ip_id, protocol,
//!     ingress-authority)` since #5798 — so ALL fragments of one datagram
//!     co-locate (the #2344 invariant — payload bytes are NEVER read as L4
//!     ports). Every added dimension is an L3 field present in EVERY fragment
//!     (`protocol` is the IPv4 Protocol byte / the IPv6 Fragment Header's Next
//!     Header) or a property of the INGRESS, so widening the key did not cost
//!     the co-location property: first and non-first fragments of one datagram
//!     arriving on one interface still build the identical key.
//!   * Value is the first fragment's FULL, per-flow `SessionDecision`
//!     (resolution + NatDecision) — data-sufficient for the forward direction
//!     (`decision.nat` carries this flow's snat_v4/dst_v4) — plus the optional
//!     `Nat64ReverseInfo` for the reverse direction, plus a monotonic-ns
//!     deadline. NOTE the value is per-FLOW, not per-(src,dst): the pool SNAT
//!     source is round-robin (`address_persistent = false`), so two flows that
//!     share (src_v6,dst_v6) but differ in L4 port can be assigned DIFFERENT
//!     pool source addresses. Since the key is port-free, a non-first fragment
//!     could in principle inherit a *sibling* flow's snat_v4.
//!   * CORRECTNESS / why the port-free key is safe: RFC 8200 §4.5 requires a
//!     source to use a UNIQUE Fragment Identification per (source, destination)
//!     for the maximum lifetime a fragment may exist. So for a CONFORMANT sender
//!     exactly one datagram — hence one flow — owns a given (src,dst,ip_id)
//!     within our 2s TTL, and the inherited snat_v4 is that flow's own. The only
//!     residual is a sender that DELIBERATELY reuses one ident across two
//!     concurrent flows to the same (src,dst); its worst case is fail-SAFE: the
//!     non-first fragment may translate to the sibling flow's pool SOURCE, so
//!     the receiver cannot reassemble (fragments arrive from different sources)
//!     and DROPS — it is NEVER mistranslated to a wrong DESTINATION (dst is in
//!     the key and derives the synthetic-prefix v4 dst identically for both).
//!     This is the same inherent NAT + fragmentation + ident-reuse hazard
//!     RFC 6864 describes, not a new exposure.
//!   * ONLY a first fragment (offset 0, MF=1, admitted + resolved + COMMITTED)
//!     INSTALLS an entry. #5146: the install fires at the POST-COMMIT site (after
//!     `can_admit` passes AND the forward session install succeeds), NOT at NAT64
//!     source-allocation time — a first fragment that is then rolled back
//!     (hop-limit ICMP-TE, admission refusal, install-partial) never publishes an
//!     association, so a non-first fragment cannot inherit a rolled-back verdict +
//!     a released (reusable) translation. Non-first fragments only CONSULT — the
//!     load-bearing DoS property: an attacker cannot grow the table with cheap
//!     headerless fragments.
//!   * BOUNDED: a fixed shard count x a fixed per-shard cap, with no growth.
//!     Shards are selected by the seeded source hash, and one admitting session
//!     (tuple plus incarnation) has a smaller 32-entry quota within each shard.
//!     Quotas do not trust claimed source addresses, so a spoofing session cannot
//!     spend another session's quota. Reaching a quota refuses new keys rather
//!     than evicting a live association; the shard cap bounds aggregate memory.
//!   * PRUNE-BEFORE-REFUSE (#5447): before refusing an install at the per-session
//!     shard quota or a full shard, it reclaims EXPIRED entries FIRST (same
//!     monotonic clock `lookup` prunes with). Expired slots are reclaimed
//!     before capacity checks, so they cannot alone cause a refusal.
//!   * SESSION-BOUND: each entry carries the admitting session key and unique
//!     incarnation id. Consult removes the entry as soon as that exact session
//!     is no longer live, including a same-tuple replacement session.
//!   * CROSS-WORKER visible for free: the cache rides `Nat64State`, which is
//!     shared across all workers behind `Arc<ForwardingState>` (ArcSwap) and
//!     threaded across config reloads by `from_snapshots_with_previous` — the
//!     same Arc-sharing pattern the `PortAllocator` uses. No new sharded mutex,
//!     no session-sync/control-socket traffic. HA does NOT sync it, and #6835
//!     corrected what that costs: the TTL is an IDLE timeout, RE-STAMPED on
//!     every hit (`lookup`), so a continuously hit entry does NOT expire in two
//!     seconds — it lives as long as fragments keep arriving. Calling the state
//!     "transient, sub-second" and "bounded" was true of an idle entry and false
//!     of a busy one, and the difference mattered: an association that outlives
//!     an RG transition kept serving the OLD owner. What bounds it now is
//!     enforcement, not time — the hit arm re-runs `enforce_ha_resolution_snapshot`
//!     on the cached resolution every packet, so an inactive owner is demoted to
//!     `HAInactive` on the very next fragment however often the entry is
//!     refreshed. Memory is separately bounded (16 shards x 64 entries).
//!
//! Miss (reorder / orphan / eviction / cross-node failover) falls to a
//! fail-closed drop (`nat64_frag_dropped`) when the packet would otherwise have
//! been FORWARDED — that is the disposition the Pref64 gate is scoped to
//! (`ForwardCandidate`). It is not a blanket claim over every disposition:
//! NoRoute, MissingNeighbor, HAInactive and LocalDelivery reach their own arms,
//! none of which emits the packet natively, so they are safe for their own
//! reasons rather than by this gate (#6835 r2).
//! Plain/no-NAT misses still follow flowless L3 policy: an L4-only permit does
//! not match without ports, and an explicit port-deny overlap remains fail-closed.
//! Denied first fragments install no session-bound association, so their tails
//! cannot inherit a permit.
//! #6835: that was an ASPIRATION until the Pref64-destination gate on the
//! flowless arm (`poll_descriptor/mod.rs`) existed. `nat64_consult_forward_fragment_assoc`
//! returning `None` only means "no association"; the packet then resolved like
//! any other IPv6 destination and, with a default route, FORWARDED — untranslated,
//! to a synthetic Pref64 address, with the client's real IPv6 source on the wire.
//! Every test agreed with this comment because the fixture deleted `::/0`.
//!
//! ---
//!
//! #7899: extracted from `nat64.rs` (4537 LOC) into its own component. The
//! cache was never NAT64-only: the ordinary same-family SNAT/DNAT/static-NAT/
//! NPTv6 arm installs into and consults the SAME table (#5689), and plain
//! forwarding now reuses it to carry a committed no-NAT session decision
//! (#11412). The data model is family-neutral — `FragKey` carries an
//! `addr_family` byte and no translation-specific fields.
//!
//! The cache INSTANCE still hangs off `Nat64State` (`forwarding.nat64.frag_assoc`).
//! Re-homing it is a lifecycle change, not motion: the Arc is threaded across
//! config reloads inside `Nat64State::from_snapshots_with_previous` so in-flight
//! datagrams keep translating. Deliberately left for a separate change.

use crate::hot_hash_seed::hot_path_hash_seed;
use crate::nat64::{Nat64ReverseInfo, ipv6_fragment_header};
use crate::session::{SessionDecision, SessionKey};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

mod key;
pub(crate) use key::{first_fragment_key, nonfirst_fragment_key};

/// Number of independent shards. Power of two so the shard index is a mask.
/// #7056 (#5798 required-fix #5): fragment-association misses caused by the
/// #5798 key REFUSING an alias, split by which field refused it.
///
/// The fail-closed behaviour these count was delivered by #6835 — a cross-domain
/// or protocol-aliased fragment builds a different key, misses, and dies on the
/// Pref64 gate or the #6122 discriminator. What was missing is the ability to
/// SEE it: every such miss landed on `nat64_frag_dropped` /
/// `nat_frag_untranslated_dropped` alongside reorders, TTL straddles, shard
/// evictions and config-generation bumps.
///
/// Those causes are not interchangeable to an operator. A reorder or TTL straddle
/// is a path-MTU / cache-pressure story; a refused alias is a TRAFFIC story, and
/// the only one of the group that can indicate an attempt to ride another
/// domain's association. One drop counter answers neither question — the same
/// failure as a diagnostic that names the wrong condition.
///
/// TWO counters, not one "alias refused" total, because they are different
/// operator stories:
///
///   - `CROSS_DOMAIN` — a same-datagram entry exists under a DIFFERENT ingress
///     `FragAuthority`: the #5798 defect proper, a fragment in one security
///     domain probing an association minted in another.
///   - `PROTOCOL_ALIAS` — same authority, different upper-layer protocol: a TCP
///     and a UDP datagram colliding on `(src, dst, ident)`, which required-fix
///     #2 added `protocol` to the key to separate.
///
/// Cumulative and process-global, like `INTERFACE_SNAT_PAT_COLLISIONS`, so tests
/// read them as a delta.
// #7899: these two keep their `NAT64_FRAG_` names while every other item in
// this module dropped the prefix. They are not mislabelled -- they ARE the
// shipped Prometheus series `xpf_userspace_nat64_frag_cross_domain_misses_total`
// and `..._protocol_alias_misses_total`, so the identifier is the grep path
// from an alert to the code that moves it. Renaming them would break that
// path to make a module read tidier.
pub(crate) static NAT64_FRAG_CROSS_DOMAIN_MISSES: AtomicU64 = AtomicU64::new(0);

/// See `NAT64_FRAG_CROSS_DOMAIN_MISSES`.
pub(crate) static NAT64_FRAG_PROTOCOL_ALIAS_MISSES: AtomicU64 = AtomicU64::new(0);

/// #9901 (F-010): associations reclaimed by the ABSOLUTE lifetime bound rather
/// than the idle TTL. An idle-TTL expiry is routine churn; an absolute expiry
/// means one key was consulted continuously for the whole maximum lifetime —
/// the sustained same-key fragment stream this bound exists to stop. Read as a
/// delta in tests; surfaced as `xpf_userspace_frag_max_lifetime_evictions_total`.
pub(crate) static FRAG_MAX_LIFETIME_EVICTIONS: AtomicU64 = AtomicU64::new(0);

pub(crate) const FRAG_SHARDS: usize = 16;
/// Fixed per-shard entry cap. Total ceiling is
/// `FRAG_SHARDS * FRAG_CAP_PER_SHARD` = 1024 entries; each entry is
/// a `Copy` `SessionDecision` + an optional `Nat64ReverseInfo` + a deadline —
/// a few hundred bytes, so a few hundred KB fixed ceiling. No payload bytes are
/// stored (no amplification by datagram size).
pub(crate) const FRAG_CAP_PER_SHARD: usize = 64;
/// Maximum associations charged to one admitted session in a shard. Session
/// identity includes its tuple and incarnation; packet source addresses are
/// untrusted claims and must not let a spoofing sender spend another session's
/// quota.
pub(crate) const FRAG_CAP_PER_SESSION_PER_SHARD: usize = FRAG_CAP_PER_SHARD / 2;
/// reassembly timeout): we associate a first fragment's decision with its
/// non-first fragments, which arrive on the fast path within
/// microseconds-milliseconds. Refreshed on every hit.
pub(crate) const FRAG_TTL_NS: u64 = 2_000_000_000;
/// #9901 (F-010): ABSOLUTE association lifetime, alongside the idle `FRAG_TTL_NS`
/// above. The idle TTL is re-stamped on every hit, so a stream of non-first
/// fragments spaced under 2s held the first fragment's permit open
/// indefinitely. No legitimate fragment train needs more than milliseconds of
/// spread; 10s is vast headroom and still bounds the spoof-hold window. Unlike
/// `deadline_ns` this is NEVER refreshed by a consult — only a fresh first
/// fragment re-admitted through enforcement (a re-install) re-stamps it.
pub(crate) const FRAG_MAX_LIFETIME_NS: u64 = 10_000_000_000;

/// #5798: the INGRESS SECURITY AUTHORITY a fragment association was minted
/// under — the part of the key that makes "same key" mean "same enforcement
/// domain".
///
/// A fragment-association HIT short-circuits the flowless enforcement arm and
/// returns the FIRST fragment's whole `SessionDecision` (permit + egress
/// resolution + NAT translation). Without an authority in the key, a non-first
/// fragment arriving from a DIFFERENT security domain that merely reproduces
/// `(family, src, dst, ident)` inherits the first domain's permit and is
/// forwarded under an authority it was never granted — bypassing its own
/// interface input filter, PBR, zone derivation and zone security policy.
/// Fragment-ID guessing is not an authorization mechanism.
///
/// Carrying the authority IN THE KEY (rather than validating it in the value)
/// makes the fix FAIL-CLOSED BY CONSTRUCTION: a cross-domain fragment computes
/// a DIFFERENT key, so it simply MISSES and falls through to the full
/// enforcement arm under its own real identity. There is no window in which a
/// wrong decision is returned and then rejected.
///
/// Dimensions, and why these: the **effective logical ingress interface**
/// (`ingress_ifindex` + `ingress_vlan_id`) is the finest binding and the one
/// that DETERMINES the gates a hit bypasses — the interface input filter is
/// bound per logical interface, so two interfaces in the SAME zone can carry
/// DIFFERENT filters and keying on zone alone would still alias them. `zone`
/// is a function of that interface but is carried EXPLICITLY, because it can
/// differ from the interface-implied value: a fabric/tunnel
/// `ingress_zone_override` re-homes a packet's zone, the enforcement arm reads
/// the overridden value directly, and a key must be derived from EXACTLY the
/// ingress inputs enforcement uses for "same key <=> same domain" to hold.
///
/// `routing_table` does NOT earn its place the same way, and #7051 is the issue
/// that asked. The asymmetry is measurable in `prerouting_ingress_scope`:
/// `zone_name` consults `zone_override` FIRST, while `routing_instance` is read
/// unconditionally from `ifindex_to_routing_instance[logical_ifindex]` — there
/// is no routing-instance override anywhere on the path. That map is populated
/// one entry per interface (`forwarding_build/interfaces.rs`), so the VRF is a
/// PURE FUNCTION of the logical unit, and this key already carries that unit.
/// Even populated correctly the field could not separate two authorities that
/// `ingress_ifindex` + `ingress_vlan_id` do not already separate.
///
/// It is also INERT today: `meta.routing_table` is a literal 0 at both of its
/// only assignments — the shim writer (`userspace-xdp/src/lib.rs`) and the
/// `Default` impl (`afxdp/types/mod.rs`) — so no real packet carries a non-zero
/// value into `frag_ingress_authority`. That is CHECKED rather than asserted in
/// prose, by `frag_authority_routing_table_is_inert_in_production_7051`.
///
/// So count THREE live dimensions here, not four — which is what #7051 reported
/// and what an auditor reading the previous wording got wrong. The field is
/// nevertheless KEPT rather than dropped, a deliberate decision already recorded
/// by #6927 r2 at
/// `tests_nat64_tunnel::nat64_frag_authority_dimensions_are_threaded_end_to_end_5798`:
/// the key is ready if the shim ever stamps it, and the direction is safe — a
/// stamped value can only make the key FINER, which is a MISS and therefore
/// fail-closed, never a false inherit. If it is ever made live, relabel that
/// test's fabricated case and drive it from a real ingress.
///
/// NOT included: the config/FIB generation, which `FragEntry.generation`
/// already fences (#5624), and direction, which is constant — the cache is
/// forward-install / forward-consult only.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct FragAuthority {
    /// Effective logical ingress interface index.
    pub(crate) ingress_ifindex: u32,
    /// Effective ingress VLAN (0 = untagged); part of the LOGICAL interface
    /// identity, so two VLAN siblings on one physical port never alias.
    pub(crate) ingress_vlan_id: u16,
    /// Ingress security zone after the RAW zone-encoded fabric/tunnel stamp
    /// (`ingress_zone_override`), which can re-home a packet's zone; otherwise
    /// the logical unit's configured zone.
    ///
    /// This is the RAW stamp, NOT the post-#6458 value. The flowless arm later
    /// re-binds `ingress_zone_override` through
    /// `gate_fabric_zone_override_on_owner_rg`, which DISCARDS the stamp when
    /// the resolution's owner RG is not forwarding-active locally — but that
    /// gate takes a RESOLVED forwarding decision, which does not exist yet at
    /// the association install/consult sites (resolving one is the very work a
    /// hit skips). Install and consult both read the same pre-gate value, so
    /// the key stays symmetric and "same key <=> same ingress authority" holds.
    ///
    /// Residual, NARROWED in #6835 r2 because the original wording outlived the
    /// fix. Because the owner-RG gate is runtime HA state (not config, so
    /// `build_generation` does not fence it), an RG that stops forwarding
    /// locally between a first and a non-first fragment leaves the association
    /// keyed on a stamp the post-gate enforcement would now ignore.
    ///
    /// What that no longer implies is that the fragment is FORWARDED under the
    /// stale authority. #6835 runs `enforce_ha_resolution_snapshot` on the hit
    /// arm (poll_descriptor/mod.rs), so an inactive owner is demoted to
    /// `HAInactive` on the very next fragment and the shared safety net
    /// fabric-redirects it to the node that now owns the egress RG. Measured:
    /// deleting that call makes the inactive leg of
    /// `nat64_frag_assoc_hit_reenforces_owner_rg_6927` forward again.
    ///
    /// What genuinely remains is the ZONE-POLICY half: a hit still inherits the
    /// first fragment's permit and re-runs only the INTERFACE filter, so a
    /// policy change between fragments is not re-applied.
    ///
    /// Be precise about the WINDOW, because the obvious reading is wrong and an
    /// earlier revision of this paragraph got it wrong. `FRAG_TTL_NS` is
    /// 2s, but `FragAssoc::lookup` RE-STAMPS `deadline_ns` on every hit
    /// (pre-existing, #2562/#5624 — not introduced here), so it is an IDLE
    /// timeout — and #9901 (F-010) caps the hold it renews with an ABSOLUTE
    /// lifetime (`FRAG_MAX_LIFETIME_NS`, 10s from install, never refreshed by
    /// a consult). A stream of non-first fragments carrying the same (src,
    /// dst, ident, protocol, authority) spaced under 2s used to renew the
    /// association indefinitely, and the Fragment Identification is
    /// attacker-chosen; now the window is "as long as fragments of that
    /// datagram keep arriving, up to 10s from the first". For a legitimate
    /// sender, which uses a fresh Identification per datagram and completes a
    /// train in milliseconds, the bound never fires.
    ///
    /// Nothing else bounds it: the config fence (`build_generation`) does not
    /// move on an RG transition, eviction lives in `install` so a pure-consult
    /// stream never triggers it (but BOTH prune sites now apply the absolute
    /// bound, so the stream's own entry still expires under it),
    /// and the input filter this PR runs on a hit is the INTERFACE filter — it
    /// does not re-apply zone policy. (It DOES re-apply the owner-RG gate:
    /// #6835 added `enforce_ha_resolution_snapshot` to the hit arm,
    /// poll_descriptor/mod.rs. An earlier revision of this sentence said
    /// otherwise and contradicted the module header above, which had it right.)
    /// This is the same
    /// already-admitted-flow property the flow-backed session table has across
    /// an RG transition; do not describe it as bounded by a shorter lifetime
    /// than the 10s absolute cap.
    pub(crate) ingress_zone: u16,
    /// Routing instance / VRF the ingress resolves in — **inert in production**
    /// (#7051): every assignment of `meta.routing_table` is a literal 0, so on a
    /// real packet this is always 0.
    ///
    /// Kept rather than dropped, and it costs nothing in discrimination either
    /// way: the VRF is a pure function of the logical ingress unit
    /// (`ifindex_to_routing_instance` is keyed by ifindex and, unlike
    /// `ingress_zone`, has no override), so `ingress_ifindex` already separates
    /// two ingresses in different routing instances. Full reasoning in the
    /// type's doc block above; the guard that keeps this comment honest is
    /// `frag_authority_routing_table_is_inert_in_production_7051`.
    pub(crate) routing_table: u32,
}

/// Port-free fragment-association key (#2562). Identical shape for both NAT64
/// directions; the family byte distinguishes a v6->v4 forward association from
/// a v4->v6 reverse one, so a forward and a reverse datagram that happen to
/// share addresses/ident never alias.
///
/// #5798: additionally scoped by upper-layer protocol and by the ingress
/// security authority (see [`FragAuthority`]) so a datagram can only inherit a
/// decision minted for the SAME protocol in the SAME enforcement domain.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct FragKey {
    pub(crate) addr_family: u8,
    pub(crate) src: IpAddr,
    pub(crate) dst: IpAddr,
    /// IPv6 Fragment Header 32-bit Identification (v6 side) or the IPv4 16-bit
    /// Identification zero-extended (v4 side). The SAME value labels every
    /// fragment of one datagram, so it co-locates them under one key.
    pub(crate) ident: u32,
    /// #5798: upper-layer protocol — the IPv4 header's Protocol field, or the
    /// IPv6 Fragment Header's Next Header. BOTH are L3 fields present and
    /// IDENTICAL in EVERY fragment of a datagram (no payload byte is read as
    /// L4, per required-fix #2), so install and consult derive the same value
    /// while a TCP datagram and a UDP datagram that collide on
    /// `(src, dst, ident)` no longer alias.
    pub(crate) protocol: u8,
    /// #5798: the ingress security domain the association was minted under.
    pub(crate) authority: FragAuthority,
}

#[derive(Clone)]
struct FragEntry {
    key: FragKey,
    decision: SessionDecision,
    reverse: Option<Nat64ReverseInfo>,
    deadline_ns: u64,
    /// Key and unique incarnation of the session that admitted this fragment.
    admitting_session: SessionKey,
    admitting_session_id: u64,
    /// #9901 (F-010): install instant (`now_ns` at `install`), NEVER refreshed
    /// by a consult. The absolute lifetime is measured from here: an entry
    /// older than `FRAG_MAX_LIFETIME_NS` is reclaimed even when idle-fresh. A
    /// same-key re-install (a fresh first fragment re-admitted through current
    /// enforcement) re-stamps it — the new admission owns the association now.
    created_ns: u64,
    /// #5624: the config-snapshot generation the FIRST fragment was admitted +
    /// resolved under (stamped at `install`). A `lookup` under a DIFFERENT
    /// current generation treats the entry as a miss and evicts it, so a config
    /// change (deny/NAT64 rules) invalidates associations minted under the old
    /// config instead of silently forwarding fragments the new config would drop.
    generation: u64,
    /// #6857: the owner redundancy group of the resolution the FIRST fragment
    /// was admitted under, or 0 when no RG-bound interface owns it.
    ///
    /// The config generation above is a CONFIG fence and does its job. An RG
    /// transition is RUNTIME HA state: it changes no config and bumps no
    /// snapshot generation, so a config-generation counter is structurally the
    /// wrong instrument for invalidating state whose validity depends on
    /// runtime ownership. This is the runtime fence beside it.
    ///
    /// ZERO MEANS NOT RG-DEPENDENT, and that distinction is load-bearing rather
    /// than a convenience: on a standalone box (no chassis cluster) every
    /// resolution has owner RG 0, so treating 0 as "not entitled" would evict
    /// every association on every consult and disable fragment association
    /// outright for the non-HA deployment. Only a POSITIVE owner RG is checked
    /// against `is_forwarding_active`.
    owner_rg: i32,
}

/// Cross-family fragment-association cache (#2562). Cheap to `Clone` (shares the
/// Arc-backed shards across every per-worker `Nat64State`), so a first fragment
/// that translates on any worker is visible to a non-first fragment that lands
/// on any other worker.
#[derive(Clone)]
pub(crate) struct FragAssoc {
    shards: Arc<Vec<Mutex<Vec<FragEntry>>>>,
}

impl std::fmt::Debug for FragAssoc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FragAssoc")
    }
}

impl Default for FragAssoc {
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

/// Seeded FNV-1a over the source address -> shard index. Stable within a process
/// so every association for one source maps to one bucket on every worker, but
/// randomized at boot to prevent offline collision precomputation.
pub(crate) fn frag_shard_index_seeded(key: &FragKey, seed: u64) -> usize {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325 ^ seed;
    let mut mix = |b: u8| {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    };
    let mut buf = [0u8; 16];
    let n = ip_octets(key.src, &mut buf);
    for &b in &buf[..n] {
        mix(b);
    }
    (h.wrapping_mul(0x9e37_79b9_7f4a_7c15) >> (u64::BITS - FRAG_SHARDS.trailing_zeros())) as usize
}

pub(crate) fn frag_shard_index(key: &FragKey) -> usize {
    frag_shard_index_seeded(key, hot_path_hash_seed())
}

/// #9901 (F-010): absolute-lifetime-aware liveness — the ONE predicate both
/// prune sites (`install` reclaim and the `lookup` pre-pass) share, so a
/// sustained same-key stream cannot squat toward the shard cap on either path.
/// An entry is live only while idle-fresh (`deadline_ns`, re-stamped per hit)
/// AND absolutely young (`created_ns`, never re-stamped by a consult).
/// A prune of an otherwise-viable (idle-fresh) entry bumps
/// `FRAG_MAX_LIFETIME_EVICTIONS` — that is the bound firing, not routine idle
/// churn. An entry that is ALSO idle-stale died of idleness (it would have
/// been pruned within 2s of going quiet) and is not counted as an absolute
/// eviction. `saturating_sub` keeps a backward clock (or test time-travel)
/// fail-open toward live rather than underflowing.
#[inline]
fn frag_entry_live(e: &FragEntry, now_ns: u64) -> bool {
    let idle_live = e.deadline_ns > now_ns;
    let absolutely_live = now_ns.saturating_sub(e.created_ns) < FRAG_MAX_LIFETIME_NS;
    if idle_live && !absolutely_live {
        FRAG_MAX_LIFETIME_EVICTIONS.fetch_add(1, Ordering::Relaxed);
    }
    idle_live && absolutely_live
}

impl FragAssoc {
    pub(crate) fn new() -> Self {
        let mut shards = Vec::with_capacity(FRAG_SHARDS);
        for _ in 0..FRAG_SHARDS {
            shards.push(Mutex::new(Vec::with_capacity(FRAG_CAP_PER_SHARD)));
        }
        Self {
            shards: Arc::new(shards),
        }
    }

    /// Install (or refresh) an association for a committed FIRST fragment.
    /// Within a shard, the cap is charged to the admitting session tuple and
    /// incarnation, not the untrusted packet source claim. A new key at quota
    /// is refused rather than replacing any live entry.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn install_with_session(
        &self,
        key: FragKey,
        decision: SessionDecision,
        reverse: Option<Nat64ReverseInfo>,
        admitting_session: SessionKey,
        admitting_session_id: u64,
        now_ns: u64,
        generation: u64,
        owner_rg: i32,
    ) -> bool {
        let deadline_ns = now_ns.saturating_add(FRAG_TTL_NS);
        let idx = frag_shard_index(&key);
        let mut shard = self.shards[idx]
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(pos) = shard.iter().position(|e| e.key == key) {
            let mut e = shard.remove(pos);
            e.decision = decision;
            e.reverse = reverse;
            e.deadline_ns = deadline_ns;
            // Re-stamp: a fresh first fragment re-admitted under the current
            // config owns this association now, so it adopts the current
            // generation. A stale-generation refresh would otherwise resurrect
            // a prior-config verdict.
            e.admitting_session = admitting_session;
            e.admitting_session_id = admitting_session_id;
            e.generation = generation;
            // #6857: refresh the owner RG too. A refresh happens when a LATER
            // first fragment of the same datagram re-admits under current
            // state, so the entry must carry THAT admission's entitlement, not
            // the original one — otherwise a refresh under a now-active RG
            // would leave the entry stamped with the old value.
            e.owner_rg = owner_rg;
            // #9901 (F-010): a re-install is a FRESH admission — the new first
            // fragment re-ran enforcement under current config/state — so the
            // absolute clock restarts here. Only a consult never re-stamps it.
            e.created_ns = now_ns;
            shard.push(e);
            return false;
        }
        let session_len = shard
            .iter()
            .filter(|e| {
                e.admitting_session == admitting_session
                    && e.admitting_session_id == admitting_session_id
            })
            .count();
        if session_len >= FRAG_CAP_PER_SESSION_PER_SHARD || shard.len() >= FRAG_CAP_PER_SHARD {
            // Prune before refusing a live session quota or a full shard.
            shard.retain(|e| frag_entry_live(e, now_ns));
            let session_len = shard
                .iter()
                .filter(|e| {
                    e.admitting_session == admitting_session
                        && e.admitting_session_id == admitting_session_id
                })
                .count();
            if session_len >= FRAG_CAP_PER_SESSION_PER_SHARD || shard.len() >= FRAG_CAP_PER_SHARD {
                return false;
            }
        }
        shard.push(FragEntry {
            key,
            decision,
            reverse,
            deadline_ns,
            admitting_session,
            admitting_session_id,
            created_ns: now_ns,
            generation,
            owner_rg,
        });
        false
    }

    #[cfg(test)]
    pub(crate) fn install(
        &self,
        key: FragKey,
        decision: SessionDecision,
        reverse: Option<Nat64ReverseInfo>,
        now_ns: u64,
        generation: u64,
        owner_rg: i32,
    ) -> bool {
        let admitting_session = SessionKey {
            addr_family: key.addr_family,
            protocol: key.protocol,
            src_ip: key.src,
            dst_ip: key.dst,
            src_port: 12345,
            dst_port: 443,
            discriminator: Default::default(),
            routing_domain: 0,
        };
        self.install_with_session(
            key,
            decision,
            reverse,
            admitting_session,
            1,
            now_ns,
            generation,
            owner_rg,
        )
    }

    /// Consult the association for a NON-first fragment. Prunes expired entries
    /// lazily, then, on a live hit, refreshes the deadline + moves the entry to
    /// the back (LRU) and returns a copy of the first fragment's decision +
    /// reverse info. A miss (never installed / expired / evicted) returns
    /// `None`, and the caller drops fail-closed (#4617).
    ///
    /// #5624: `generation` is the CURRENT config-snapshot generation. An entry
    /// whose stamped generation differs was resolved under a prior config whose
    /// deny/NAT64 rules may no longer admit this datagram, so it is treated as a
    /// MISS and EVICTED (not hit-refreshed) — the non-first fragment then falls
    /// to the #4617 fail-closed drop, and only a NEW first fragment re-admitted
    /// under the current config can re-establish the association. Mirrors the
    /// flow-cache `config_generation` guard (afxdp/flow_cache.rs).
    pub(crate) fn lookup_with_session(
        &self,
        key: &FragKey,
        now_ns: u64,
        generation: u64,
        session_is_live: impl Fn(&SessionKey, u64) -> bool,
        owner_rg_forwarding_active: impl Fn(i32) -> bool,
    ) -> Option<(SessionDecision, Option<Nat64ReverseInfo>)> {
        let idx = frag_shard_index(key);
        let mut shard = self.shards[idx]
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        shard.retain(|e| frag_entry_live(e, now_ns));
        let Some(pos) = shard.iter().position(|e| e.key == *key) else {
            // #7056 (#5798 required-fix #5): classify the miss before returning
            // it. A full-key miss has several causes with very different
            // meanings, and until now every one landed on the same
            // `nat64_frag_dropped` / `nat_frag_untranslated_dropped` counter: a
            // reorder, a TTL straddle, a shard eviction, a config-generation
            // bump — and an ALIASING ATTEMPT the #5798 key deliberately refused.
            //
            // The last is the only one that says something about the TRAFFIC
            // rather than about cache pressure, and the one required-fix #5 asks
            // to be distinguishable.
            //
            // The scan is single-shard BY CONSTRUCTION, which is why it belongs
            // here rather than at a call site: `frag_shard_index`
            // deliberately digests only `(family, src, dst, ident)`, excluding
            // `authority` and `protocol` precisely so same-datagram candidates
            // stay CO-LOCATED. Every alias candidate is already in the bucket
            // this function has locked and just scanned.
            //
            // Ordering matters: this runs only on a FULL-KEY miss, so the
            // generation and owner-RG fences below cannot reach it. A
            // config-generation eviction is an ordinary commit invalidating the
            // cache and must NOT be reported as an alias.
            let alias = shard.iter().find(|e| {
                e.key.addr_family == key.addr_family
                    && e.key.src == key.src
                    && e.key.dst == key.dst
                    && e.key.ident == key.ident
            });
            if let Some(e) = alias {
                if e.key.authority != key.authority {
                    NAT64_FRAG_CROSS_DOMAIN_MISSES.fetch_add(1, Ordering::Relaxed);
                } else if e.key.protocol != key.protocol {
                    NAT64_FRAG_PROTOCOL_ALIAS_MISSES.fetch_add(1, Ordering::Relaxed);
                }
            }
            return None;
        };
        // Config-generation guard (#5624): a match minted under a stale config
        // generation is evicted and reported as a miss, so a commit that
        // changed deny/NAT64 rules invalidates the association instead of
        // letting stale fragments keep inheriting the old verdict.
        // Session key alone is insufficient: a later flow can reuse the same
        // tuple after close. The stable session id fences that replacement.
        if !session_is_live(
            &shard[pos].admitting_session,
            shard[pos].admitting_session_id,
        ) {
            shard.remove(pos);
            return None;
        }
        if shard[pos].generation != generation {
            shard.remove(pos);
            return None;
        }
        // #6857 RUNTIME-OWNERSHIP fence, beside the config one above.
        //
        // The association carries a permit this node granted while it was
        // entitled to. An RG transition (failover, tracked-interface demotion)
        // revokes that entitlement without touching config, so the generation
        // guard above cannot see it: a later fragment would still HIT and
        // inherit the earlier permit + egress + NAT on a node that is no longer
        // forwarding-active for the owning RG. That is exactly what the #6458
        // owner-RG gate exists to prevent on the enforcement path.
        //
        // owner_rg == 0 means NOT RG-dependent and is deliberately NOT checked:
        // on a standalone box every resolution has owner RG 0, so checking it
        // would evict every association on every consult and disable fragment
        // association for the entire non-HA deployment.
        if shard[pos].owner_rg > 0 && !owner_rg_forwarding_active(shard[pos].owner_rg) {
            shard.remove(pos);
            return None;
        }
        let mut e = shard.remove(pos);
        e.deadline_ns = now_ns.saturating_add(FRAG_TTL_NS);
        let value = (e.decision, e.reverse);
        shard.push(e);
        Some(value)
    }
    #[cfg(test)]
    pub(crate) fn lookup(
        &self,
        key: &FragKey,
        now_ns: u64,
        generation: u64,
        owner_rg_forwarding_active: impl Fn(i32) -> bool,
    ) -> Option<(SessionDecision, Option<Nat64ReverseInfo>)> {
        self.lookup_with_session(
            key,
            now_ns,
            generation,
            |_, _| true,
            owner_rg_forwarding_active,
        )
    }

    /// Total live entry count across all shards (test-only; backs the bound /
    /// eviction / TTL RED-on-revert tests).
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
