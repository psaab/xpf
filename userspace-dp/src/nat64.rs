//! NAT64 (RFC 6052 / RFC 7915) stateless IPv4↔IPv6 translation for the
//! userspace dataplane.
//!
//! ## ICMP error translation (#2219)
//!
//! Both directions translate ICMP *error* messages, not only echo
//! request/reply: Destination-Unreachable, Time-Exceeded, Parameter-Problem,
//! and Packet-Too-Big↔Fragmentation-Needed (with the 20-byte MTU adjustment for
//! the NAT64 header-size delta, clamped to the IPv6 minimum link MTU on the
//! v4→v6 side) per the RFC 7915 §4.2 (v4→v6) and §5.2 (v6→v4) type/code maps.
//! An ICMP error carries the original (return-direction) packet quoted inside
//! it, so the EMBEDDED IP header (+leading L4 bytes) is also NAT64-translated:
//! its addresses are mapped v6↔v4 and its lengths/checksum fixed, because the
//! embedded packet is the return-direction tuple a receiver matches the error
//! against. Without this, PMTUD blackholes (a server's Fragmentation-Needed
//! never reaches the v6 client) and traceroute shows no hops across NAT64.
//! The embedded packet is translated through a fixed stack scratch buffer
//! ([`MAX_EMBEDDED_LEN`]) — NO per-packet heap allocation, consistent with the
//! zero-alloc invariant below. Types with no IPv4/IPv6 analogue (NDP, MLD,
//! ICMPv4 redirect/source-quench, etc.) are dropped, not mistranslated.
//!
//! Two module invariants the rest of the crate relies on:
//!
//! * **No per-packet heap allocation on the translate hot path (#2211).** The
//!   v6↔v4 translators have an allocation-free core
//!   ([`write_v6_to_v4_into`] / [`write_v4_to_v6_into`]) that writes the
//!   translated L3 directly into a caller-provided buffer, and the
//!   pseudo-header L4 checksum is STREAMED (no per-call `Vec`). The frame
//!   builders ([`build_nat64_v6_to_v4_frame`] / [`build_nat64_v4_to_v6_frame`])
//!   make exactly ONE output allocation — the `TxRequest.bytes` the TX path
//!   requires — and translate straight into its tail, eliminating the former
//!   intermediate L3 `Vec`, the pseudo-header `Vec`s, and the double L4 copy.
//!   The `translate_v6_to_v4` / `translate_v4_to_v6` `Vec`-returning wrappers
//!   are `#[cfg(test)]`-only: the differential tests use them to assert the
//!   `_into` cores are byte-identical to an owned-`Vec` translation. They are
//!   NOT on the forwarding hot path and are absent from the release build.
//! * **Fail SCOPED on an unparseable config rule (#2212, refined by #3888).**
//!   [`Nat64State::from_snapshots`] SKIPS the offending NAT64 rule — logging a
//!   loud one-line warning naming which rule and why — on an empty/malformed
//!   /non-`/96` prefix or a pool address that is neither a bare IPv4 nor a
//!   `/32` host, and publishes the remaining NAT64 rules plus the rest of the
//!   forwarding snapshot. The whole rule is dropped all-or-nothing: a single
//!   bad pool entry drops its rule rather than silently NARROWING the pool
//!   (preserving the #2212 anti-silent-narrowing intent), but one bad NAT64
//!   rule no longer aborts the ENTIRE forwarding rebuild. Pre-#3888 the
//!   fallible `try_from_snapshots` returned a
//!   [`crate::policy::SnapshotIntegrityError`] that propagated via `?` out of
//!   `build_reconcile_forwarding`, so ONE malformed NAT64 rule (from a
//!   mixed-version HA peer-sync or a lenient/corrupt snapshot — paths the Go
//!   commit gate does not cover) froze the whole control→dataplane pipeline,
//!   blocking every OTHER rule type and every later commit. Skipping mirrors
//!   the skip-and-continue posture of the sibling NAT tables (`DnatTable`,
//!   `StaticNatTable`, source NAT — the #1960 lenient-load doctrine) and
//!   downgrades a bad NAT64 rule to a NAT64-only degradation. The primary gate
//!   remains the Go commit-time validation (`pkg/config/compiler_nat.go`,
//!   #2173/#3886); this is the helper-boundary backstop. NPTv6
//!   ([`crate::nptv6::Nptv6State::try_from_snapshots`]) intentionally stays
//!   fail-CLOSED (abort-all): its #2241 overlap rejection is an
//!   order-dependent determinism guard where a blind per-rule skip would be
//!   ambiguous, so it is a flagged follow-up, out of #3888 scope.
//!
//! ## Incremental L4 checksum on translation (#3025)
//!
//! NAT64 changes only the IP layer: the transport payload is copied verbatim
//! (for TCP/UDP) and the transport length + protocol number are identical
//! across the v4↔v6 forms, so the ONLY input to the L4 checksum that changes is
//! the pseudo-header source/destination address pair. The translators therefore
//! adjust the verbatim-copied L4 checksum INCREMENTALLY (RFC 1624 eqn 3,
//! [`adjust_l4_checksum_v6_to_v4_incremental`] /
//! [`adjust_l4_checksum_v4_to_v6_incremental`]) — folding the old address words
//! out and the new ones in — instead of re-summing the whole payload. Because
//! 16-bit one's-complement addition is exact, the incremental result is
//! BYTE-IDENTICAL to a full recompute (folding `0xFFFF` is a one's-complement
//! no-op, so the address words cancel exactly); it is a pure O(changed-words)
//! optimization, not a behavior change. This was already the case for #2488
//! FRAGMENTs (where a full recompute is impossible); #3025 extends it to the
//! non-fragmented fast path that previously re-summed the entire L4 payload.
//!
//! Three cases still take the full recompute, by design:
//!   * **ICMP** — ICMPv4↔ICMPv6 rewrites the message body, and ICMPv4 has no
//!     pseudo-header while ICMPv6 does, so the checksum genuinely changes.
//!   * **v4→v6 UDP with a zero IPv4 checksum** — RFC 768 "no checksum present";
//!     there is no baseline to adjust and IPv6 UDP mandates a checksum, so one
//!     must be GENERATED.
//!   * **v6→v4 UDP with a zero (illegal) IPv6 checksum** — no trustworthy
//!     baseline; defended against with a recompute.
//!
//! Pinned by the `nat64_3025_*` tests: the incremental output equals an
//! independent full recompute (v6→v4 / v4→v6, TCP + UDP), the v4 zero-checksum
//! UDP edge generates a fresh valid checksum, and the fail-on-revert seam — a
//! deliberately-corrupted input checksum is PRESERVED (adjusted) by the
//! incremental path but would be silently repaired by a full recompute.
//!
//! ## Single Ethernet-header writer (#2844)
//!
//! The NAT64 frame builders ([`build_nat64_v6_to_v4_frame`] /
//! [`build_nat64_v4_to_v6_frame`]) serialize their Ethernet header through the
//! shared SSOT writer [`crate::afxdp::write_eth_header_slice`] — the same
//! in-place writer used by `gre.rs`, `icmp.rs`, and the TX segmentation path —
//! NOT a private copy. NAT64 lives at the crate root (`mod nat64;`), outside
//! `crate::afxdp`, so the `pub(in crate::afxdp)` writer is re-exported
//! `pub(crate)` from `afxdp/mod.rs` for it. NAT64 still passes a bare `vlan_id:
//! u16`; the shared writer's `TxVlanTag::from(u16)` reproduces the legacy
//! semantics byte-for-byte (tag present iff `vlan_id > 0`, TPID 0x8100, PCP/DEI
//! 0), so output is identical for every frame the dataplane currently emits.
//! The point of unifying is forward-compatibility: a future TPID / PCP / DEI /
//! 802.1ad (0x88a8) / priority-tagged-VID-0 / ethertype change in the shared
//! frame module now propagates to NAT64 automatically instead of silently
//! drifting. Pinned by the byte-identical fail-on-revert test
//! `nat64_eth_header_is_ssot_byte_identical`.
//!
//! ## Port-allocator durability across a config reload (#4518)
//!
//! A config commit rebuilds the whole forwarding state, and #4381 gave each
//! NAT64 prefix a stateful [`PortAllocator`] (RFC 6146 BIB) so every forward
//! flow claims a UNIQUE translated `(pool v4 address, L4 port / ICMP id)`.
//! Building that allocator FRESH on every rebuild reset it to port-offset 0, so
//! the first flows after any commit deterministically reclaimed the LOW
//! translated ports still owned by live pre-reload sessions. When the colliding
//! port mapped to the same v4 remote, the 1:N reverse index bucket held two
//! handles and v4→v6 replies mis-demuxed until the old session aged out.
//!
//! [`Nat64State::from_snapshots_with_previous`] closes this: the reconcile
//! preflight threads the previous live `Nat64State` in, and each new prefix
//! whose `(prefix bytes, source pool)` is byte-identical REUSES the previous
//! allocator (an `Arc`-backed clone whose live tuple-ownership set carries over)
//! instead of resetting. A pool that changed (addresses added / removed /
//! reordered) still gets a fresh allocator — the old reservations reference a
//! different pool. This mirrors source NAT's `previous_allocators` reuse in
//! `parse_source_nat_rules_with_previous`. Pinned by the fail-on-revert test
//! `nat64_4518_allocator_survives_config_reload`.
//!
//! ## Port-reservation sync across a cross-node HA failover (#4512)
//!
//! The COMPLEMENTARY case to the reload path above: a NAT64 forward flow's
//! translated `(pool v4, port)` is picked by `allocate_source` on the ACTIVE
//! node and synced to the standby inside the [`NatDecision`] (`rewrite_src_port`
//! rides the wire — no new field). But the standby imports that pre-computed
//! decision and never runs `allocate_source`, so its NAT64 allocator has no
//! record the port is in use. Post-failover the standby-turned-active would
//! then `allocate_source` the SAME `(snat_v4, port)` for a fresh local flow —
//! two forward flows colliding on one translated source, the same RFC 6146 BIB
//! violation #4381 closed for the same-node case, reappearing across a failover
//! (1:N reverse index → v4→v6 reply mis-demux).
//!
//! [`reserve_synced_nat64_allocation`] closes this by applying #4388's
//! source-NAT `reserve_synced_source_nat_allocation` treatment to NAT64: on the
//! standby, `handle_upsert_synced` reserves the synced forward flow's translated
//! port in the local NAT64 allocator (via `reserve_nat64_pool_port` →
//! `PortAllocator::reserve_flow`, without advancing the round-robin cursor), and
//! the EXISTING teardown path (`release_nat64_allocation` on reap / purge /
//! delete-sync) frees it with the same flow key. Pinned by the fail-on-revert
//! test `nat64_4512_synced_session_reserves_translated_port`.
//!
//! Scope: this closes the port-COLLISION harm. Reverse-TRANSLATION of a
//! promoted synced NAT64 session (restoring the original client v6 address)
//! still needs `Nat64ReverseInfo` — `orig_src_v6` / `orig_dst_v6`, which are NOT
//! reconstructible from `NatDecision` — to ride the sync payload; that is a
//! separate wire-field follow-up (`ha.rs` sets `nat64_reverse: None`).

use crate::NAT64RuleSnapshot;
// #2844: shared SSOT in-place Ethernet-header writer (one writer for
// the whole dataplane). Re-exported `pub(crate)` from `crate::afxdp`
// because NAT64 lives outside `crate::afxdp`.
use crate::afxdp::write_eth_header_slice;
// #4435: the single canonical IPv6 extension-header loop bound, shared
// with the forwarding/screen paths. The private walkers below use this
// instead of a hardcoded 6 so a valid 7-ext-header packet is not
// NAT64-dropped while the forwarding path accepts it.
use crate::afxdp::MAX_IPV6_EXT_HEADERS;
// #6435: the single canonical IPv6 extension-header WALK, shared with the
// forwarding path (`afxdp::frame::inspect`). The NAT64 L4 / fragment
// resolvers below fold its verdict instead of hand-mirroring the loop, so
// the #4517 ext-header set, the AH arithmetic, and the #2292/#4435
// fail-closed-at-the-bound posture can never drift between copies again.
// Re-exported `pub(crate)` from `crate::afxdp` because NAT64 lives outside
// `crate::afxdp` (same channel as the bound above).
use crate::afxdp::{ExtChainOutcome, walk_ipv6_ext_chain};
use crate::nat::{
    DeterministicV6, NatDecision, PortAllocator, SourceNatFailureReason, SourceNatFlowKey,
    allocate_nat64_pool_port, allocate_nat64_pool_port_deterministic_v6, release_nat64_pool_port,
    reserve_nat64_pool_port,
};
use crate::session::SessionDecision;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// #4381: NAT64 translated-port allocation range. RFC 6146 does not mandate a
/// specific range; the ephemeral 1024..=65535 window (matching the pool-mode
/// SNAT default) maximizes the distinct-flow capacity behind a single pool
/// address while staying clear of the well-known ports.
const NAT64_PORT_LOW: u16 = 1024;
const NAT64_PORT_HIGH: u16 = 65535;

/// NAT64 prefix configuration — one per `security nat nat64` rule.
#[derive(Debug)]
pub(crate) struct Nat64Prefix {
    /// First 96 bits of the NAT64 prefix (e.g. 64:ff9b::).
    pub(crate) prefix_bytes: [u8; 12],
    /// IPv4 source pool addresses for SNAT.
    pub(crate) pool_v4: Vec<Ipv4Addr>,
    /// Round-robin index for pool allocation (atomic for thread safety).
    ///
    /// #4381: retained for the empty-pool / liveness probe only. The
    /// authoritative source selection is now the stateful `port_allocator`,
    /// which picks the pool address AND a unique translated port together.
    pool_index: AtomicUsize,
    /// #4381: stateful pool-mode allocator that hands every NAT64 forward flow
    /// a UNIQUE `(pool v4 address, translated L4 port / ICMP identifier)`. Two
    /// v6 clients sharing a source port behind one pool address get distinct
    /// translated ports, so their reverse (v4→v6) tuples never collide (the
    /// RFC 6146 BIB). Reuses the exact `PortAllocator` the pool-mode source-NAT
    /// path uses (`nat/allocator.rs`); the `Arc`-backed live state is SHARED
    /// across the per-worker `Nat64State` clones, so a port claimed on one
    /// worker is visible to every other worker.
    pub(crate) port_allocator: PortAllocator,
    /// #4559: IPv6-subscriber deterministic CGNAT (mode 2, NAPT64). `Some` when
    /// the referenced source pool carries `port deterministic` with an enforced
    /// IPv6 host (/32 or /64 prefix); the forward `allocate_source` then maps
    /// each IPv6 subscriber to a fixed external IPv4 + port block
    /// (`allocate_deterministic_v6`) instead of round-robin PAT, so the
    /// `(external IPv4, port)` → subscriber reverse needs no per-flow log
    /// (lawful-intercept / CGN audit). `None` => the pre-#4559 round-robin path.
    pub(crate) deterministic_v6: Option<DeterministicV6>,
    /// #6982: this prefix was REFUSED by the aggregate allocator budget, so it
    /// carries an empty pool and no bitmap.
    ///
    /// It is installed rather than skipped on purpose: a skipped prefix does not
    /// match, so its traffic falls through to `NoPrefixMatch` and is ROUTED as
    /// ordinary IPv6 — a memory guard that turns into a translation bypass.
    /// Installed-with-an-empty-pool drops fail-closed instead.
    ///
    /// The flag exists because that makes a refusal LOOK like the legitimate
    /// empty-pool rule the Go side emits for a no-source-pool config: both
    /// classify `MatchUnavailable`. The two have opposite remedies (raise the
    /// budget or split the config vs. add a source pool), so the state is
    /// carried explicitly rather than inferred from `pool_v4.is_empty()`.
    /// Asserted at the CONSUMPTION boundary by
    /// `nat64_6982_over_budget_is_distinguishable_from_empty_pool`.
    pub(crate) over_budget: bool,
}

impl Clone for Nat64Prefix {
    fn clone(&self) -> Self {
        Self {
            prefix_bytes: self.prefix_bytes,
            pool_v4: self.pool_v4.clone(),
            pool_index: AtomicUsize::new(self.pool_index.load(Ordering::Relaxed)),
            // Clone shares the Arc-backed allocator state (see field doc).
            port_allocator: self.port_allocator.clone(),
            deterministic_v6: self.deterministic_v6,
            over_budget: self.over_budget,
        }
    }
}

/// Aggregated NAT64 state built from config snapshots.
#[derive(Clone, Debug, Default)]
pub(crate) struct Nat64State {
    pub(crate) prefixes: Vec<Nat64Prefix>,
    /// Mirrors the global `security nat natv6v4 no-v6-frag-header` option. When
    /// set, the IPv6->IPv4 translator emits a fragmentable (DF=0, non-atomic)
    /// IPv4 packet per RFC 7915 5.1 rather than the default DF=1 atomic framing.
    /// The option is configured once at the natv6v4 level; the Go side
    /// replicates it onto every NAT64 rule snapshot, so any rule carrying it
    /// enables it globally.
    pub(crate) no_v6_frag_header: bool,
    /// #2562: cross-family fragment-association cache. Lets non-first NAT64
    /// fragments inherit the first fragment's translation instead of being
    /// dropped fail-closed (#4617). Arc-backed, so all per-worker clones share
    /// one cache (cross-worker visible) and it survives a config reload (the
    /// Arc is threaded in `from_snapshots_with_previous`). NOT rebuilt from the
    /// snapshot — fragment associations are runtime state, not config.
    pub(crate) frag_assoc: Nat64FragAssoc,
    /// #5624: the config-snapshot generation THIS state was built under. The
    /// `frag_assoc` cache is Arc-shared across config reloads (so in-flight
    /// datagrams keep translating), but each association is a per-flow
    /// deny/NAT64 verdict resolved under one config generation. A commit that
    /// changes deny/NAT64 rules bumps `snapshot.generation`, rebuilding this
    /// `Nat64State` with the new value while the shared cache still holds
    /// PRIOR-generation associations. Stamping every install and re-checking it
    /// on lookup (see `Nat64FragAssoc::install`/`lookup`) invalidates a stale
    /// association whose generation != the current one — mirroring the
    /// flow-cache `config_generation` guard (afxdp/flow_cache.rs). Lives on
    /// `Nat64State` (NOT inside the shared Arc) precisely because it must change
    /// per reload while the cache persists.
    pub(crate) build_generation: u64,
}

/// Reverse-direction state stored with NAT64 sessions so IPv4 replies can be
/// translated back to IPv6.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Nat64ReverseInfo {
    pub(crate) orig_src_v6: Ipv6Addr,
    pub(crate) orig_dst_v6: Ipv6Addr,
}

// ===========================================================================
// #2562 / #3291-stage-4: stateful cross-family fragment-association cache.
//
// A non-first NAT64 fragment carries NO L4 header, so it cannot find the
// flow/session that holds the translation the FIRST fragment resolved (the
// SNAT source v6->v4, or the original v6 addresses v4->v6). Without an
// association it is dropped fail-closed (#4617). This cache lets a non-first
// fragment INHERIT the first fragment's decision so the whole datagram
// traverses NAT64 end-to-end and reassembles at the receiver.
//
// Design (converged /research pass; see issue #2562 / PR #4686):
//   * Key is PORT-FREE — `(addr_family, src, dst, ip_id, protocol,
//     ingress-authority)` since #5798 — so ALL fragments of one datagram
//     co-locate (the #2344 invariant — payload bytes are NEVER read as L4
//     ports). Every added dimension is an L3 field present in EVERY fragment
//     (`protocol` is the IPv4 Protocol byte / the IPv6 Fragment Header's Next
//     Header) or a property of the INGRESS, so widening the key did not cost
//     the co-location property: first and non-first fragments of one datagram
//     arriving on one interface still build the identical key.
//   * Value is the first fragment's FULL, per-flow `SessionDecision`
//     (resolution + NatDecision) — data-sufficient for the forward direction
//     (`decision.nat` carries this flow's snat_v4/dst_v4) — plus the optional
//     `Nat64ReverseInfo` for the reverse direction, plus a monotonic-ns
//     deadline. NOTE the value is per-FLOW, not per-(src,dst): the pool SNAT
//     source is round-robin (`address_persistent = false`), so two flows that
//     share (src_v6,dst_v6) but differ in L4 port can be assigned DIFFERENT
//     pool source addresses. Since the key is port-free, a non-first fragment
//     could in principle inherit a *sibling* flow's snat_v4.
//   * CORRECTNESS / why the port-free key is safe: RFC 8200 §4.5 requires a
//     source to use a UNIQUE Fragment Identification per (source, destination)
//     for the maximum lifetime a fragment may exist. So for a CONFORMANT sender
//     exactly one datagram — hence one flow — owns a given (src,dst,ip_id)
//     within our 2s TTL, and the inherited snat_v4 is that flow's own. The only
//     residual is a sender that DELIBERATELY reuses one ident across two
//     concurrent flows to the same (src,dst); its worst case is fail-SAFE: the
//     non-first fragment may translate to the sibling flow's pool SOURCE, so
//     the receiver cannot reassemble (fragments arrive from different sources)
//     and DROPS — it is NEVER mistranslated to a wrong DESTINATION (dst is in
//     the key and derives the synthetic-prefix v4 dst identically for both).
//     This is the same inherent NAT + fragmentation + ident-reuse hazard
//     RFC 6864 describes, not a new exposure.
//   * ONLY a first fragment (offset 0, MF=1, admitted + resolved + COMMITTED)
//     INSTALLS an entry. #5146: the install fires at the POST-COMMIT site (after
//     `can_admit` passes AND the forward session install succeeds), NOT at NAT64
//     source-allocation time — a first fragment that is then rolled back
//     (hop-limit ICMP-TE, admission refusal, install-partial) never publishes an
//     association, so a non-first fragment cannot inherit a rolled-back verdict +
//     a released (reusable) translation. Non-first fragments only CONSULT — the
//     load-bearing DoS property: an attacker cannot grow the table with cheap
//     headerless fragments.
//   * BOUNDED: a fixed shard count x a fixed per-shard cap, LRU eviction, no
//     growth. Short TTL (~2s): we ASSOCIATE, we do not RFC-reassemble — real
//     fragments of one datagram arrive within microseconds-milliseconds; the
//     short TTL covers reorder/jitter while evicting attack residue fast.
//   * PRUNE-BEFORE-EVICT (#5447): on a full shard `install` reclaims EXPIRED
//     entries FIRST (same monotonic clock `lookup` prunes with) and only evicts
//     the oldest LIVE entry if the shard is STILL at cap. Without this, a flood
//     of first fragments (each a distinct ident) fills the shard and the LRU
//     eviction would sacrifice a still-LIVE association — whose non-first
//     fragments have not yet arrived — to an EXPIRED slot squatting in front,
//     dropping legitimate fragments fail-closed. When every entry is live the
//     hard capacity bound is unchanged (oldest live entry still evicted).
//   * CROSS-WORKER visible for free: the cache rides `Nat64State`, which is
//     shared across all workers behind `Arc<ForwardingState>` (ArcSwap) and
//     threaded across config reloads by `from_snapshots_with_previous` — the
//     same Arc-sharing pattern the `PortAllocator` uses. No new sharded mutex,
//     no session-sync/control-socket traffic. HA does NOT sync it, and #6835
//     corrected what that costs: the TTL is an IDLE timeout, RE-STAMPED on
//     every hit (`lookup`), so a continuously hit entry does NOT expire in two
//     seconds — it lives as long as fragments keep arriving. Calling the state
//     "transient, sub-second" and "bounded" was true of an idle entry and false
//     of a busy one, and the difference mattered: an association that outlives
//     an RG transition kept serving the OLD owner. What bounds it now is
//     enforcement, not time — the hit arm re-runs `enforce_ha_resolution_snapshot`
//     on the cached resolution every packet, so an inactive owner is demoted to
//     `HAInactive` on the very next fragment however often the entry is
//     refreshed. Memory is separately bounded (16 shards x 64 entries).
//
// Miss (reorder / orphan / eviction / cross-node failover) falls to a
// fail-closed drop (`nat64_frag_dropped`) when the packet would otherwise have
// been FORWARDED — that is the disposition the Pref64 gate is scoped to
// (`ForwardCandidate`). It is not a blanket claim over every disposition:
// NoRoute, MissingNeighbor, HAInactive and LocalDelivery reach their own arms,
// none of which emits the packet natively, so they are safe for their own
// reasons rather than by this gate (#6835 r2).
// #6835: that was an ASPIRATION until the Pref64-destination gate on the
// flowless arm (`poll_descriptor/mod.rs`) existed. `nat64_consult_forward_fragment_assoc`
// returning `None` only means "no association"; the packet then resolved like
// any other IPv6 destination and, with a default route, FORWARDED — untranslated,
// to a synthetic Pref64 address, with the client's real IPv6 source on the wire.
// Every test agreed with this comment because the fixture deleted `::/0`.
// ===========================================================================

/// Number of independent shards. Power of two so the shard index is a mask.
const NAT64_FRAG_SHARDS: usize = 16;
/// Fixed per-shard entry cap (LRU eviction on overflow). Total ceiling is
/// `NAT64_FRAG_SHARDS * NAT64_FRAG_CAP_PER_SHARD` = 1024 entries; each entry is
/// a `Copy` `SessionDecision` + an optional `Nat64ReverseInfo` + a deadline —
/// a few hundred bytes, so a few hundred KB fixed ceiling. No payload bytes are
/// stored (no amplification by datagram size).
const NAT64_FRAG_CAP_PER_SHARD: usize = 64;
/// Association lifetime. Deliberately SHORT (2s, not the RFC-6864 60s
/// reassembly timeout): we associate a first fragment's decision with its
/// non-first fragments, which arrive on the fast path within
/// microseconds-milliseconds. Refreshed on every hit.
const NAT64_FRAG_TTL_NS: u64 = 2_000_000_000;

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
/// and `routing_table` are functions of that interface, but they are carried
/// explicitly because the enforcement arm reads them directly (a zone override
/// or a fabric-origin packet can make the effective zone differ from the one
/// the raw ifindex would imply), and a key must be derived from EXACTLY the
/// ingress inputs enforcement uses for "same key <=> same domain" to hold.
///
/// NOT included: the config/FIB generation, which `Nat64FragEntry.generation`
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
    /// earlier revision of this paragraph got it wrong. `NAT64_FRAG_TTL_NS` is
    /// 2s, but `Nat64FragAssoc::lookup` RE-STAMPS `deadline_ns` on every hit
    /// (pre-existing, #2562/#5624 — not introduced here), so it is an IDLE
    /// timeout, not an absolute lifetime. A stream of non-first fragments
    /// carrying the same (src, dst, ident, protocol, authority) spaced under
    /// 2s renews the association indefinitely, and the Fragment Identification
    /// is attacker-chosen. So the window is "as long as fragments of that
    /// datagram keep arriving", NOT ~2s. For a legitimate sender, which uses a
    /// fresh Identification per datagram, it really is ~2s — which is where
    /// that number came from.
    ///
    /// Nothing else bounds it: the config fence (`build_generation`) does not
    /// move on an RG transition, eviction lives in `install` so a pure-consult
    /// stream never triggers it, `retain` only prunes already-expired entries,
    /// and the input filter this PR runs on a hit is the INTERFACE filter — it
    /// does not re-apply zone policy. (It DOES re-apply the owner-RG gate:
    /// #6835 added `enforce_ha_resolution_snapshot` to the hit arm,
    /// poll_descriptor/mod.rs. An earlier revision of this sentence said
    /// otherwise and contradicted the module header above, which had it right.)
    /// This is the same
    /// already-admitted-flow property the flow-backed session table has across
    /// an RG transition; do not describe it as bounded by a shorter lifetime.
    pub(crate) ingress_zone: u16,
    /// Routing instance / VRF the ingress resolves in.
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
pub(crate) struct Nat64FragKey {
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

#[derive(Clone, Copy)]
struct Nat64FragEntry {
    key: Nat64FragKey,
    decision: SessionDecision,
    reverse: Option<Nat64ReverseInfo>,
    deadline_ns: u64,
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
pub(crate) struct Nat64FragAssoc {
    shards: Arc<Vec<Mutex<Vec<Nat64FragEntry>>>>,
}

impl std::fmt::Debug for Nat64FragAssoc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Nat64FragAssoc")
    }
}

impl Default for Nat64FragAssoc {
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

/// FNV-1a over the port-free key -> shard index. Deterministic so the same key
/// always maps to the same shard on install and consult (across workers).
///
/// #5798: the #5798 authority + protocol fields are DELIBERATELY NOT mixed in
/// here. The shard index stays the coarse `(family, src, dst, ident)` digest —
/// including the documented `ident.to_be_bytes()` byte order — for two reasons:
///
///  1. Correctness does not need it. Shard selection only decides WHICH bucket
///     is scanned; membership is decided by full-key equality inside that
///     bucket. A cross-domain fragment lands in the SAME shard, finds no equal
///     key, and misses cleanly — which is exactly the fail-closed outcome.
///  2. It keeps same-datagram candidates CO-LOCATED, so a cross-domain
///     aliasing attempt is observable with a single-shard scan rather than a
///     walk of all `NAT64_FRAG_SHARDS` buckets.
fn nat64_frag_shard_index(key: &Nat64FragKey) -> usize {
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
    (h as usize) & (NAT64_FRAG_SHARDS - 1)
}

impl Nat64FragAssoc {
    pub(crate) fn new() -> Self {
        let mut shards = Vec::with_capacity(NAT64_FRAG_SHARDS);
        for _ in 0..NAT64_FRAG_SHARDS {
            shards.push(Mutex::new(Vec::with_capacity(NAT64_FRAG_CAP_PER_SHARD)));
        }
        Self {
            shards: Arc::new(shards),
        }
    }

    /// Install (or refresh) the association a FIRST fragment established. Only a
    /// first fragment reaches this (the caller gates on offset 0 / MF=1 + an
    /// admitted, resolved decision), so non-first fragments can never grow the
    /// table. On a full shard EXPIRED entries are pruned first (reclaiming dead
    /// slots that a first-fragment flood would otherwise leave squatting), and
    /// only if the shard is STILL at cap is the OLDEST (front) LIVE entry
    /// evicted -> hard, fixed memory ceiling that no longer sacrifices a live
    /// association to an expired one (#5447). A repeat install of the same key
    /// refreshes the deadline and moves the entry to the back
    /// (most-recently-used).
    ///
    /// #5624: `generation` is the current config-snapshot generation the first
    /// fragment was admitted + resolved under. It is stamped on the entry (and
    /// re-stamped on a same-key re-install) so `lookup` can reject an
    /// association left over from a prior config after a commit changed
    /// deny/NAT64 rules.
    pub(crate) fn install(
        &self,
        key: Nat64FragKey,
        decision: SessionDecision,
        reverse: Option<Nat64ReverseInfo>,
        now_ns: u64,
        generation: u64,
        // #6857: owner RG of the resolution this fragment was admitted under;
        // 0 when no RG-bound interface owns it.
        owner_rg: i32,
    ) {
        let deadline_ns = now_ns.saturating_add(NAT64_FRAG_TTL_NS);
        let idx = nat64_frag_shard_index(&key);
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
            e.generation = generation;
            // #6857: refresh the owner RG too. A refresh happens when a LATER
            // first fragment of the same datagram re-admits under current
            // state, so the entry must carry THAT admission's entitlement, not
            // the original one — otherwise a refresh under a now-active RG
            // would leave the entry stamped with the old value.
            e.owner_rg = owner_rg;
            shard.push(e);
            return;
        }
        if shard.len() >= NAT64_FRAG_CAP_PER_SHARD {
            // Reclaim EXPIRED slots before touching a live one. Under a flood of
            // first fragments (each a distinct ident -> a fresh install) the
            // shard fills with entries, some already past their (short) TTL. A
            // bare `remove(0)` would evict the OLDEST entry regardless of
            // liveness, dropping a still-live association whose non-first
            // fragments have not arrived yet (they would then miss + fail
            // closed, #5447). Prune expired first using the SAME monotonic clock
            // `lookup` uses; only if the shard is STILL at cap (every entry
            // live) do we fall back to evicting the oldest live entry — the
            // unavoidable hard capacity bound.
            shard.retain(|e| e.deadline_ns > now_ns);
            if shard.len() >= NAT64_FRAG_CAP_PER_SHARD {
                shard.remove(0);
            }
        }
        shard.push(Nat64FragEntry {
            key,
            decision,
            reverse,
            deadline_ns,
            generation,
            owner_rg,
        });
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
    pub(crate) fn lookup(
        &self,
        key: &Nat64FragKey,
        now_ns: u64,
        generation: u64,
        // #6857: "is this owner RG forwarding-active locally right now?".
        //
        // A predicate rather than the HA map, for two reasons. The RG to ask
        // about is not known until the entry is found, so the caller cannot
        // pre-compute a bool; and passing the map would drag
        // `afxdp::HAGroupRuntime` (which is `pub(in crate::afxdp)`) into this
        // module, widening a type's visibility to serve a fence. The closure
        // keeps the HA vocabulary on the afxdp side of the boundary.
        owner_rg_forwarding_active: impl Fn(i32) -> bool,
    ) -> Option<(SessionDecision, Option<Nat64ReverseInfo>)> {
        let idx = nat64_frag_shard_index(key);
        let mut shard = self.shards[idx]
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        shard.retain(|e| e.deadline_ns > now_ns);
        let pos = shard.iter().position(|e| e.key == *key)?;
        // Config-generation guard (#5624): a match minted under a stale config
        // generation is evicted and reported as a miss, so a commit that
        // changed deny/NAT64 rules invalidates the association instead of
        // letting stale fragments keep inheriting the old verdict.
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
        e.deadline_ns = now_ns.saturating_add(NAT64_FRAG_TTL_NS);
        let value = (e.decision, e.reverse);
        shard.push(e);
        Some(value)
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

/// Parse the port-free fragment fields from an L3-relative packet: the
/// `(key, more, offset_units)` triple. `addr_family` selects the family. Shared
/// by [`nat64_first_fragment_key`] and [`nat64_nonfirst_fragment_key`] so the
/// install and consult key derivations are byte-identical.
///
/// #5798: `authority` is the ingress security domain the caller resolved for
/// THIS packet (see [`FragAuthority`]). It is stamped verbatim into the key so
/// install and consult agree by construction; this ONE builder is the SSOT for
/// both derivations, so the two can never drift into keying on different
/// dimensions. Every other field is read from the packet's L3 headers only —
/// no payload byte is interpreted as L4.
fn nat64_fragment_fields(
    packet: &[u8],
    addr_family: i32,
    authority: FragAuthority,
) -> Option<(Nat64FragKey, bool, u16)> {
    match addr_family {
        libc::AF_INET6 => {
            if packet.len() < 40 {
                return None;
            }
            let frag = ipv6_fragment_header(packet)?;
            let src = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?);
            let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?);
            let key = Nat64FragKey {
                addr_family: libc::AF_INET6 as u8,
                src: IpAddr::V6(src),
                dst: IpAddr::V6(dst),
                ident: frag.ident,
                // The Fragment Header's Next Header — present in every
                // fragment, so first and non-first derive the same protocol.
                protocol: frag.next_header,
                authority,
            };
            Some((key, frag.more, frag.offset_units))
        }
        libc::AF_INET => {
            if packet.len() < 20 {
                return None;
            }
            let frag_word = u16::from_be_bytes([packet[6], packet[7]]);
            let more = (frag_word & 0x2000) != 0;
            let offset_units = frag_word & 0x1FFF;
            let ident = u16::from_be_bytes([packet[4], packet[5]]);
            let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
            let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
            let key = Nat64FragKey {
                addr_family: libc::AF_INET as u8,
                src: IpAddr::V4(src),
                dst: IpAddr::V4(dst),
                ident: u32::from(ident),
                // IPv4 header byte 9 — the Protocol field, present in every
                // fragment (unlike the L4 header, which only the first carries).
                protocol: packet[9],
                authority,
            };
            Some((key, more, offset_units))
        }
        _ => None,
    }
}

/// Association key for a FIRST fragment (offset 0, MF=1) — the fragment that
/// INSTALLS the entry. Returns `None` for a non-first fragment, an atomic
/// fragment (MF=0, offset 0), or a non-fragmented packet.
///
/// #5798: `authority` is the ingress security domain that admitted this first
/// fragment; a non-first fragment can only inherit the entry by presenting the
/// SAME authority.
pub(crate) fn nat64_first_fragment_key(
    packet: &[u8],
    addr_family: i32,
    authority: FragAuthority,
) -> Option<Nat64FragKey> {
    let (key, more, offset_units) = nat64_fragment_fields(packet, addr_family, authority)?;
    if more && offset_units == 0 {
        Some(key)
    } else {
        None
    }
}

/// Association key for a NON-first fragment (offset > 0) — the fragment that
/// CONSULTS the entry. Returns `None` for a first / atomic / non-fragmented
/// packet.
///
/// #5798: `authority` is THIS fragment's own ingress domain. A fragment from a
/// different domain therefore builds a different key and MISSES, falling
/// through to full flowless enforcement under its real identity instead of
/// inheriting the first fragment's permit.
pub(crate) fn nat64_nonfirst_fragment_key(
    packet: &[u8],
    addr_family: i32,
    authority: FragAuthority,
) -> Option<Nat64FragKey> {
    let (key, _more, offset_units) = nat64_fragment_fields(packet, addr_family, authority)?;
    if offset_units != 0 {
        Some(key)
    } else {
        None
    }
}

/// Tri-state result of a NAT64 destination lookup (#2291).
///
/// The pre-fix lookup collapsed "prefix matched but no source could be
/// allocated" into "no NAT64 match" (a bare `Option<...>` whose `None`
/// meant both), so a matched-but-unallocatable destination fell through to
/// ordinary IPv6 route lookup on the SYNTHETIC NAT64 destination
/// (`64:ff9b::a.b.c.d`). With a permissive default IPv6 route present, that
/// silently leaked untranslated synthetic-destination traffic upstream — a
/// fail-OPEN at the NAT64 boundary.
///
/// Splitting the result into three states lets the caller fail CLOSED on the
/// unallocatable case (drop + counter) while still routing genuinely
/// non-matching IPv6 normally. Consistent with the project's fail-closed
/// family (#2124/#2142/#2173/#2175).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Nat64Match {
    /// The destination does not match any configured NAT64 prefix — continue
    /// ordinary IPv6 route lookup. This is the ONLY arm that routes as IPv6.
    NoPrefixMatch,
    /// A prefix matched AND its source pool is non-empty — translate.
    ///
    /// #4381: this no longer PRE-ALLOCATES a source address. The pre-fix code
    /// round-robin-picked a pool address here (before the security policy ran),
    /// but the authoritative selection is now the stateful per-flow allocation
    /// at the Permit branch (`Nat64State::allocate_source`), which picks the
    /// pool address AND a unique translated port/identifier together — only
    /// after the flow is admitted. This arm now just confirms the prefix
    /// matched and a pool exists; the route lookup keys on `dst_v4` (the
    /// destination), not the source, so no source is needed this early.
    MatchReady {
        /// Index of the matched NAT64 prefix in `prefixes`.
        prefix_idx: usize,
        /// IPv4 destination extracted from the synthetic NAT64 address.
        dst_v4: Ipv4Addr,
        /// Original synthetic IPv6 destination (kept for the reverse path).
        dst_v6: Ipv6Addr,
    },
    /// A prefix matched but its source pool is empty (a legitimate wire state
    /// the Go side emits for a no-source-pool rule) OR the stateful allocator
    /// is exhausted. The packet MUST be dropped, not routed as IPv6.
    MatchUnavailable,
    /// #5623: the IPv6 SOURCE is Pref64-INELIGIBLE — it lies within a configured
    /// NAT64 prefix, i.e. a looping/synthesized "already-translated" source (the
    /// RFC 6146 §5 hairpin-loop construction). RFC 6146 §3.5 mandates dropping
    /// every incoming IPv6 packet whose source contains Pref64. The high-96-bit
    /// match subsumes the degenerate boundaries the issue calls out — the lower
    /// boundary `<prefix>::` (embedded v4 `0.0.0.0`), the upper boundary
    /// `<prefix>::ffff:ffff` (embedded v4 `255.255.255.255`), and any source
    /// whose embedded v4 is non-global/looping (still inside the prefix). The
    /// caller MUST drop fail-closed with a distinct counter BEFORE route lookup,
    /// policy, or `allocate_source`, so no session/BIB/allocation state is minted
    /// for a spoofed or looping source. A legitimate global-unicast source
    /// outside every Pref64 never reaches this arm, so eligible traffic is
    /// untouched.
    IneligibleSource,
    /// #6475: the extracted embedded IPv4 DESTINATION is non-global per
    /// RFC 6052 §3.1 — one of `0.0.0.0/8`, `127.0.0.0/8`, `169.254.0.0/16`,
    /// `224.0.0.0/4`, or `240.0.0.0/4` (which subsumes `255.255.255.255/32`).
    /// Pre-gate, `64:ff9b::127.0.0.1` classified `MatchReady(127.0.0.1)` and,
    /// with lo0 configured, resolved LocalDelivery to the localhost-only
    /// control plane (gRPC 50051 / REST 8080) — reachable from any NAT64
    /// client, bidirectionally, through a minted session. The caller MUST drop
    /// fail-closed with a distinct counter BEFORE route lookup (which precedes
    /// the FIB walk AND the `local_v4` LocalDelivery resolution), policy, or
    /// `allocate_source`, so no session/BIB/allocation state is minted for a
    /// non-global embedded destination. The destination-side sibling of
    /// [`Nat64Match::IneligibleSource`] (#5623); a global embedded destination
    /// never reaches this arm, so eligible traffic is untouched.
    IneligibleDestination,
}

/// Parse a NAT64 source-pool IPv4 address that may carry a canonical host
/// mask (`x.x.x.x/32`). Address-range expansion stamps `/32` on every pool
/// IP and `Ipv4Addr::from_str` rejects CIDR, so the mask is stripped before
/// parse (#2123). The pool holds exact host source addresses, so only a bare
/// address or the host mask (`/32`) is accepted; a non-host mask (`/24`) or
/// garbage suffix returns `None` and is filtered, surfacing a misconfigured
/// entry rather than silently coercing it to a host address.
fn parse_pool_v4(s: &str) -> Option<Ipv4Addr> {
    let mut parts = s.splitn(2, '/');
    let addr: Ipv4Addr = parts.next()?.parse().ok()?;
    match parts.next() {
        None => Some(addr),
        Some("32") => Some(addr),
        Some(_) => None,
    }
}

/// #6227 item 1: incremented whenever a NAT64 rule's snapshot requested
/// deterministic NAPT64 mapping (a non-empty `deterministic_host_base_v6`) but
/// [`build_deterministic_v6`] returned `None` — the rule silently downgrades to
/// round-robin PAT and a subscriber's external mapping is no longer
/// deterministic (a CGN compliance loss). A real deployment also sees the
/// paired `eprintln!` at the call site; this counter gives tests (and, via
/// future stats plumbing, operators) a signal that does not require scraping
/// stderr.
/// #6982: aggregate ceiling on the NAT64 allocator bitmaps ONE apply may hold
/// live. The SNAT sibling (#6812, `nat::source::SOURCE_NAT_AGGREGATE_BUDGET`).
///
/// WHY NAT64 NEEDS ITS OWN. #6812 caps `PortAllocator::new` at the SNAT apply
/// boundary, but there are exactly two production construction sites and the
/// other one is here — gated by nothing. A NAT64 prefix costs
/// `pool_v4.len() * (NAT64_PORT_HIGH - NAT64_PORT_LOW + 1)` = `len * 64512`
/// occupancy bits, and unlike SNAT the port range is a FIXED CONSTANT, so every
/// pool address costs the MAXIMUM — there is no narrow-range case to soften it.
/// The ~1.48 GiB scenario #6812 exists to prevent was reachable through this
/// path with #6812 fully in place.
///
/// The three limits are the SNAT values unchanged. Deliberate: the two paths
/// draw on one machine's memory, so a NAT64-specific relaxation would just move
/// the ceiling. They are charged SEPARATELY rather than against one shared
/// counter — see the PR discussion; a shared counter would make a NAT64 apply's
/// admissibility depend on SNAT rule ordering in a different snapshot.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Nat64AggregateBudget {
    /// Max DISTINCT prefix allocator instances.
    pub(crate) max_prefixes: u64,
    /// Max SUM of every prefix's pool address count.
    pub(crate) max_addresses: u64,
    /// Max SUM of (addresses x fixed port range) = occupancy bitmap SLOTS.
    pub(crate) max_port_capacity: u64,
}

pub(crate) const NAT64_AGGREGATE_BUDGET: Nat64AggregateBudget = Nat64AggregateBudget {
    max_prefixes: 1024,
    max_addresses: 16 * crate::nat::MAX_POOL_PREFIX_HOSTS, // 1,048,576
    max_port_capacity: 1 << 33,                            // 8,589,934,592
};

/// Running aggregate charge. u64 with SATURATING adds: a hand-crafted or
/// HA-peer-synced snapshot can claim absurd cardinalities, and saturating
/// (never wrapping) keeps the over-budget verdict fail-closed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Nat64AggregateUse {
    pub(crate) prefixes: u64,
    pub(crate) addresses: u64,
    pub(crate) port_capacity: u64,
}

impl Nat64AggregateUse {
    /// Cumulative use UNCONDITIONALLY including `charge`. Used for keys that
    /// must be accepted regardless of budget (reused live state), and as the
    /// candidate inside `admitted_with`.
    pub(crate) fn saturating_with(self, charge: Self) -> Self {
        Self {
            prefixes: self.prefixes.saturating_add(charge.prefixes),
            addresses: self.addresses.saturating_add(charge.addresses),
            port_capacity: self.port_capacity.saturating_add(charge.port_capacity),
        }
    }

    /// Cumulative use IF `charge` is admitted, or `None` when admitting it
    /// would cross any limit. First-fit: a refused prefix commits NOTHING, so a
    /// later smaller one can still install.
    pub(crate) fn admitted_with(
        self,
        charge: Self,
        budget: &Nat64AggregateBudget,
    ) -> Option<Self> {
        let next = self.saturating_with(charge);
        (next.prefixes <= budget.max_prefixes
            && next.addresses <= budget.max_addresses
            && next.port_capacity <= budget.max_port_capacity)
            .then_some(next)
    }
}

/// The charge one prefix's pool costs. Separated so the test suite can cross a
/// limit by POOL COUNT without materialising 2^33 port slots — a fixture that
/// genuinely allocates the bitmap is a test that gets deleted for being slow,
/// and a deleted guard is no guard (#6982).
pub(crate) fn nat64_prefix_charge(pool_len: usize) -> Nat64AggregateUse {
    Nat64AggregateUse {
        prefixes: 1,
        addresses: pool_len as u64,
        // ONE formula for "port slots this allocator materialises", shared with
        // `PortAllocator::new`'s own capacity arithmetic — the same helper the
        // SNAT charge uses (#6812). Open-coding `len * 64512` here would be a
        // second copy of the allocation formula, and a charge that drifts from
        // what is actually allocated is a budget that does not bind. Pinned by
        // `nat64_6982_charge_uses_the_allocators_own_capacity_formula`.
        port_capacity: crate::nat::allocator_capacity(
            pool_len,
            NAT64_PORT_LOW,
            NAT64_PORT_HIGH,
        ) as u64,
    }
}

/// #6982 phase 1 helper: the (prefix, pool) IDENTITY of a snapshot, or `None`
/// if the rule is one the build loop will skip as malformed.
///
/// SILENT by design. The build loop below logs each skip loudly (#3888
/// all-or-nothing); this pass runs first, over the same snapshots, purely to
/// learn which prefixes will REUSE a live allocator. Logging here would double
/// every malformed-rule warning. It must stay in lockstep with the loop's own
/// parse — `nat64_6982_identity_parser_matches_the_build_loop` binds that, so
/// a rule the loop accepts can never be invisible to the budget.
fn nat64_rule_identity(snap: &NAT64RuleSnapshot) -> Option<([u8; 12], Vec<Ipv4Addr>)> {
    if snap.prefix.is_empty() {
        return None;
    }
    let parts: Vec<&str> = snap.prefix.split('/').collect();
    if parts.len() != 2 || parts[1].parse::<u8>().ok() != Some(96) {
        return None;
    }
    let addr: Ipv6Addr = parts[0].parse().ok()?;
    let octets = addr.octets();
    let mut prefix_bytes = [0u8; 12];
    prefix_bytes.copy_from_slice(&octets[..12]);
    let mut pool_v4 = Vec::with_capacity(snap.pool_addresses.len());
    for s in &snap.pool_addresses {
        pool_v4.push(parse_pool_v4(s)?);
    }
    Some((prefix_bytes, pool_v4))
}

/// #6982: prefixes refused by the aggregate budget since boot.
///
/// A refused prefix is INSTALLED with an empty pool rather than skipped, so
/// traffic to it drops fail-closed (`MatchUnavailable`) instead of falling
/// through to `NoPrefixMatch` and being ROUTED as ordinary IPv6 — skipping
/// would turn a memory guard into a translation bypass. But that makes the
/// refusal look exactly like the legitimate empty-pool rule the Go side emits
/// for a no-source-pool config, which is why the state is ALSO carried
/// explicitly on the prefix (`Nat64Prefix::over_budget`) and counted here.
/// Three states, not two: healthy, empty-by-config, refused-by-budget.
pub(crate) static NAT64_OVER_BUDGET_COUNT: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

pub(crate) static DETERMINISTIC_V6_DOWNGRADE_COUNT: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// #4559: build the mode-2 (NAPT64) deterministic block-allocation params for a
/// NAT64 prefix from its snapshot + the parsed pool size. Returns `None` (the
/// pre-#4559 round-robin fallback) when the pool is not a deterministic NAPT64
/// pool (empty base string, zero block size), the base is unparseable, the
/// prefix length is unsupported (only /32 and /64 map to a subscriber word, per
/// the retired-eBPF split), the block math is degenerate, or the pool is empty.
/// `host_count` is bounded by pool capacity (`num_pool_ips * blocks_per_ip`) —
/// an IPv6 subscriber word extends far beyond the pool, so a subscriber past
/// that fails closed rather than aliasing another subscriber's block.
fn build_deterministic_v6(snap: &NAT64RuleSnapshot, num_pool_ips: usize) -> Option<DeterministicV6> {
    if snap.deterministic_host_base_v6.is_empty() || snap.deterministic_block_size == 0 {
        return None;
    }
    if snap.deterministic_host_prefix_len != 32 && snap.deterministic_host_prefix_len != 64 {
        return None;
    }
    if snap.deterministic_blocks_per_ip == 0 || num_pool_ips == 0 {
        return None;
    }
    let base: Ipv6Addr = snap.deterministic_host_base_v6.parse().ok()?;
    let host_count = (num_pool_ips as u32).checked_mul(snap.deterministic_blocks_per_ip as u32)?;
    if host_count == 0 {
        return None;
    }
    Some(DeterministicV6 {
        block_size: snap.deterministic_block_size,
        blocks_per_ip: snap.deterministic_blocks_per_ip,
        host_prefix_len: snap.deterministic_host_prefix_len,
        host_base: base.octets(),
        host_count,
    })
}

impl Nat64State {
    /// Build from config snapshot NAT64 rules, SKIPPING (fail-scoped) any
    /// unparseable rule (#2212, refined by #3888).
    ///
    /// In a retired-eBPF world (#1373) the userspace helper is the enforcement
    /// plane. The pre-#2212 parser silently `continue`d past a bad prefix and
    /// `filter_map`ped malformed pool entries away, so a mixed-version control
    /// plane, a serialization bug, or a missed Go validation edge could install
    /// a NAT64 rule whose prefix is present but whose pool is silently empty —
    /// `allocate_v4_source` then returns `None` and NAT64 forward translation
    /// stops with no failure surfaced. The primary gate is the Go commit-time
    /// validation (`pkg/config/compiler_nat.go`, #2173/#3886, host-mask + pool
    /// representability); this is the helper-boundary backstop.
    ///
    /// #3888: this is INFALLIBLE (`-> Self`) and skips the offending rule
    /// all-or-nothing, mirroring the sibling `DnatTable::from_snapshots` /
    /// `StaticNatTable::from_snapshots` / source-NAT skip-and-continue posture
    /// (#1960 lenient-load doctrine). Each skip logs a loud one-line
    /// `eprintln!` naming the rule and the reason, so a leniently-loaded bad
    /// rule is VISIBLE, not silent. This preserves #2212's anti-silent-pool-
    /// narrowing intent — a single bad pool entry drops its WHOLE rule rather
    /// than narrowing the pool — while scoping the blast radius to that one
    /// NAT64 rule: the remaining NAT64 rules and every OTHER rule type in the
    /// forwarding snapshot still publish. Pre-#3888 the fallible variant
    /// returned a `SnapshotIntegrityError` that propagated via `?` out of
    /// `build_reconcile_forwarding`, aborting the whole rebuild and freezing
    /// the dataplane on one malformed NAT64 rule.
    ///
    /// An empty pool that is genuinely UNCONFIGURED (no `pool_addresses` on the
    /// wire — the legitimate "no source-pool" state the Go side emits) is NOT
    /// an error and installs a poolless prefix as before: only a pool that was
    /// non-empty on the wire but had an UNPARSEABLE entry drops its rule.
    pub(crate) fn from_snapshots(snaps: &[NAT64RuleSnapshot]) -> Self {
        // Generation 0: this convenience wrapper is used only by tests and the
        // no-previous cold path where the frag-association generation guard is
        // not exercised. The production reconcile path uses
        // `from_snapshots_with_previous` with the real `snapshot.generation`.
        Self::from_snapshots_with_previous(snaps, None, 0, 0)
    }

    /// #4518: build the NAT64 state, PRESERVING live translated-port
    /// reservations across a same-node config reload/commit.
    ///
    /// Identical to [`from_snapshots`] except that, for each new NAT64 prefix
    /// whose `(prefix bytes, source pool)` is byte-identical to a prefix in
    /// `previous`, it REUSES that prefix's `PortAllocator` (an `Arc`-backed
    /// clone) instead of building a fresh one at port-offset 0. The allocator's
    /// live tuple-ownership set lives behind the `Arc`, so the reservations held
    /// by pre-reload NAT64 sessions carry into the rebuilt state: the first
    /// post-commit flows no longer deterministically reclaim the LOW translated
    /// ports still owned by live sessions, which previously double-populated the
    /// (1:N) reverse index bucket and mis-demuxed v4→v6 replies until the old
    /// session aged out.
    ///
    /// The reuse is keyed on the EXACT pool (order-sensitive `Vec` equality):
    /// the allocator's per-address round-robin counters are indexed by pool
    /// position, so a pool with addresses added, removed, or reordered gets a
    /// FRESH allocator — the old reservations reference a different pool and
    /// starting clean is correct. This mirrors source NAT's
    /// `parse_source_nat_rules_with_previous` + `previous_allocators`
    /// (`nat/source.rs`), where an unchanged pool reuses the live allocator and
    /// a changed pool resets. The COMPLEMENTARY HA-failover path — syncing
    /// `Nat64ReverseInfo` and reserving the translated port on the standby so
    /// the reservation survives a cross-node failover — is tracked separately in
    /// #4512; this fix is the same-node reload path only.
    ///
    /// #5624: `generation` is the config-snapshot generation this state is built
    /// under (`snapshot.generation`). It is recorded as `build_generation` and
    /// stamped onto every fragment association installed while this state is
    /// live, so associations minted under a prior generation are invalidated on
    /// lookup after a commit changes deny/NAT64 rules.
    /// `now_ns` is the caller's MONOTONIC clock, threaded to the #6765
    /// retained-address re-seed. Callers that cannot reach one (tests that do
    /// not exercise a pool change) pass 0.
    pub(crate) fn from_snapshots_with_previous(
        snaps: &[NAT64RuleSnapshot],
        previous: Option<&Nat64State>,
        generation: u64,
        now_ns: u64,
    ) -> Self {
        let mut prefixes = Vec::with_capacity(snaps.len());
        // The natv6v4 no-v6-frag-header option is global; the Go side stamps it
        // onto every rule snapshot. Treat the state as enabled if any rule
        // carries the flag (they all carry the same value in practice).
        let no_v6_frag_header = snaps.iter().any(|s| s.no_v6_frag_header);
        // #6982 PHASE 1: reserve every prefix that will REUSE a live allocator,
        // BEFORE any new one is admitted.
        //
        // This ordering is the #6812 F2-round-4 invariant, and it is not
        // optional. Charging reuse where it is MET lets a NEW prefix be admitted
        // against a total that does not yet include reused prefixes appearing
        // LATER in the slice — and those are then accepted unconditionally, so
        // the live set ends up over the cap. Same snapshots, opposite outcome
        // from ORDER alone, repeating one prefix per apply. Bound by
        // `nat64_6982_reuse_is_charged_before_new_prefixes_regardless_of_order`.
        let mut used = Nat64AggregateUse::default();
        if let Some(prev) = previous {
            for snap in snaps {
                if let Some((pb, pool)) = nat64_rule_identity(snap) {
                    if prev.reuse_allocator(&pb, &pool).is_some() {
                        used = used.saturating_with(nat64_prefix_charge(pool.len()));
                    }
                }
            }
        }
        // Labeled so a bad pool entry can skip the WHOLE rule (all-or-nothing,
        // #3888) rather than narrowing the pool (the #2212 fail-open).
        'rules: for snap in snaps {
            // Every NAT64 rule on the wire is enabled (the Go side skips
            // empty-prefix rules in buildNAT64Snapshots), so an empty prefix
            // here is anomalous: skip THIS rule with a loud warning (#3888,
            // consistent with the other malformed-rule skips below) rather than
            // silently dropping it — a disappeared rule stays visible in logs.
            if snap.prefix.is_empty() {
                eprintln!(
                    "xpf nat64: skipping malformed rule {:?}: empty prefix",
                    snap.name
                );
                continue;
            }
            // Parse "64:ff9b::/96" — require EXACTLY `<ipv6>/96`: two
            // '/'-split parts AND a /96 mask. This backstop is the corrupt /
            // lenient-snapshot path (a #1960 leniently-loaded or HA
            // peer-synced config the Go #3886/#3887 commit gate did not vet),
            // so it must be strict: a missing mask (one part), an EXTRA slash
            // ("64:ff9b::/96/garbage" → three parts, whose trailing garbage
            // would otherwise be silently ignored), or a non-/96 length skips
            // the whole rule (#3888) — loudly, so the drop is visible. Mirrors
            // the exact-2-parts `parse_prefix` in nptv6.rs.
            let parts: Vec<&str> = snap.prefix.split('/').collect();
            if parts.len() != 2 || parts[1].parse::<u8>().ok() != Some(96) {
                eprintln!(
                    "xpf nat64: skipping malformed rule {:?}: prefix {:?} (only <ipv6>/96 is supported)",
                    snap.name, snap.prefix
                );
                continue;
            }
            let addr: Ipv6Addr = match parts[0].parse() {
                Ok(a) => a,
                Err(_) => {
                    eprintln!(
                        "xpf nat64: skipping malformed rule {:?}: unparseable prefix address {:?}",
                        snap.name, parts[0]
                    );
                    continue;
                }
            };
            let octets = addr.octets();
            let mut prefix_bytes = [0u8; 12];
            prefix_bytes.copy_from_slice(&octets[..12]);
            // Pool addresses may carry a canonical host mask: an
            // address-range source pool (`address A to B`) is expanded by
            // the Go compiler into per-IP `/32` entries (#2123), and
            // `Ipv4Addr::from_str` rejects CIDR notation. Strip the host mask
            // before parse so range-form pools are not silently dropped,
            // leaving pool_v4 empty and NAT64 forward translation
            // non-functional. A non-host mask (`/24`) or garbage suffix is
            // unparseable: skip the WHOLE rule (#3888, all-or-nothing) rather
            // than silently NARROWING the pool by dropping just the bad entry
            // (the #2212 fail-open). `continue 'rules` bails on the offending
            // rule so no partially-installed pool reaches the dataplane.
            let mut pool_v4 = Vec::with_capacity(snap.pool_addresses.len());
            for s in &snap.pool_addresses {
                match parse_pool_v4(s) {
                    Some(addr) => pool_v4.push(addr),
                    None => {
                        eprintln!(
                            "xpf nat64: skipping malformed rule {:?}: unparseable source-pool address {:?}",
                            snap.name, s
                        );
                        continue 'rules;
                    }
                }
            }
            // #4381: one stateful port allocator per prefix, sized to the pool.
            // An empty pool yields a zero-capacity allocator (allocate returns
            // AllocatorExhausted), which the fail-closed classify path treats
            // exactly like the historical empty-pool `MatchUnavailable`.
            //
            // #4518: on a config reload, REUSE the previous prefix's allocator
            // (an `Arc`-backed clone carrying the live tuple-ownership set) when
            // the pool is byte-identical, so pre-reload NAT64 sessions keep
            // owning their translated ports and new flows do not collide with
            // them at port-offset 0. A changed pool (addresses added / removed /
            // reordered) falls through to a fresh allocator — the round-robin
            // counters are pool-position indexed, so stale reservations against
            // a different pool must not be replayed. Mirrors source NAT's
            // `previous_allocators` reuse in `parse_source_nat_rules_with_previous`.
            //
            // #6982 PHASE 2. A REUSED allocator is accepted unconditionally (it
            // was charged in phase 1): a no-op re-apply must never kill live
            // translations. A NEW one is admitted only if it fits the remaining
            // budget; a refused prefix commits nothing (first-fit), so a later
            // smaller prefix can still install.
            let reused = previous.and_then(|prev| prev.reuse_allocator(&prefix_bytes, &pool_v4));
            let mut over_budget = false;
            if reused.is_none() {
                match used.admitted_with(nat64_prefix_charge(pool_v4.len()), &NAT64_AGGREGATE_BUDGET)
                {
                    Some(next) => used = next,
                    None => {
                        over_budget = true;
                        NAT64_OVER_BUDGET_COUNT.fetch_add(1, Ordering::Relaxed);
                        eprintln!(
                            "xpf nat64: rule {:?} REFUSED by the aggregate allocator budget \
                             (prefixes {}/{}, addresses {}/{}, port slots {}/{} would be \
                             exceeded by a {}-address pool); installing it with an EMPTY pool so \
                             its traffic drops fail-closed rather than routing untranslated \
                             (#6982)",
                            snap.name,
                            used.prefixes,
                            NAT64_AGGREGATE_BUDGET.max_prefixes,
                            used.addresses,
                            NAT64_AGGREGATE_BUDGET.max_addresses,
                            used.port_capacity,
                            NAT64_AGGREGATE_BUDGET.max_port_capacity,
                            pool_v4.len(),
                        );
                        // Drop the pool BEFORE any allocator is built: the whole
                        // point is that no occupancy bitmap is materialised.
                        pool_v4.clear();
                    }
                }
            }
            let port_allocator = reused
                .unwrap_or_else(|| {
                    let fresh =
                        PortAllocator::new(pool_v4.len(), NAT64_PORT_LOW, NAT64_PORT_HIGH);
                    // #6765: the comment above is right that stale reservations
                    // must not be replayed against a DIFFERENT pool — the
                    // counters and the occupancy bitmap are pool-position
                    // indexed. But a pool that RETAINS an address is not a
                    // different pool for that address, and a fresh allocator
                    // reissues its port-offset 0 to a new flow while a
                    // pre-reload session still owns it. Carry the retained
                    // addresses' live ownership across, REMAPPED to their new
                    // indices, rather than replaying raw positions.
                    //
                    // A fully-disjoint pool yields an empty map and re-seeds
                    // nothing, which is the reset
                    // `nat64_4518_pool_change_resets_allocator` pins.
                    if let Some(prev_prefix) = previous.and_then(|prev| {
                        prev.prefixes
                            .iter()
                            .find(|p| p.prefix_bytes == prefix_bytes)
                    }) {
                        let map = crate::nat::retained_pool_index_map_v4(
                            &prev_prefix.pool_v4,
                            &pool_v4,
                        );
                        if !map.is_empty() {
                            let outcome = fresh.reseed_retained_from(
                                &prev_prefix.port_allocator,
                                &map,
                                now_ns,
                            );
                            if outcome.reseeded > 0
                                || outcome.skipped_out_of_range > 0
                                || outcome.refused > 0
                            {
                                eprintln!(
                                    "xpf nat64: pool for rule {:?} changed: carried {} live \
                                     translation(s) onto {} retained address(es); {} not \
                                     carried (port outside the range), {} refused (#6765)",
                                    snap.name,
                                    outcome.reseeded,
                                    map.len(),
                                    outcome.skipped_out_of_range,
                                    outcome.refused,
                                );
                            }
                        }
                    }
                    fresh
                });
            // #4559: build the mode-2 (NAPT64) deterministic block-allocation
            // params when the referenced source pool carried `port deterministic`
            // with an enforced IPv6 host. The Go builder sends a non-empty base +
            // block-size + prefix-len (32/64) + blocks-per-ip (computed against
            // the NAT64 port range); `host_count` is pool-bounded, so it is
            // derived HERE from the parsed pool (`pool_v4.len() * blocks_per_ip`)
            // rather than trusted from the wire — the authoritative pool count is
            // whatever survived `parse_pool_v4`. A malformed base, an unsupported
            // prefix length, degenerate block math, or a `host_count` `u32`
            // overflow leaves it `None` (round-robin fallback) — #6227 item 1:
            // when the rule DID request deterministic mapping (a non-empty
            // `deterministic_host_base_v6`), that fallback is an operator-
            // visible compliance loss (CGN mapping stops being deterministic),
            // so it must not be silent.
            // #6982: a refused prefix has no pool, so it has no deterministic
            // mapping either — and it must NOT emit the downgrade warning below,
            // which would attribute a budget refusal to bad deterministic config.
            let deterministic_v6 = if over_budget {
                None
            } else {
                build_deterministic_v6(snap, pool_v4.len())
            };
            if !over_budget && deterministic_v6.is_none() && !snap.deterministic_host_base_v6.is_empty() {
                DETERMINISTIC_V6_DOWNGRADE_COUNT.fetch_add(1, Ordering::Relaxed);
                eprintln!(
                    "xpf nat64: rule {:?} requested deterministic NAPT64 mapping (host-base {:?}) but failed to build (bad base / unsupported prefix-len / degenerate block math / pool-size overflow) — falling back to round-robin PAT; subscriber mappings are no longer deterministic",
                    snap.name, snap.deterministic_host_base_v6
                );
            }
            prefixes.push(Nat64Prefix {
                prefix_bytes,
                pool_v4,
                pool_index: AtomicUsize::new(0),
                port_allocator,
                deterministic_v6,
                over_budget,
            });
        }
        Self {
            prefixes,
            no_v6_frag_header,
            // #2562: preserve the live fragment-association cache across a
            // config reload (share the Arc) so in-flight fragmented datagrams
            // keep translating; a first commit with no previous state starts a
            // fresh (empty) cache.
            frag_assoc: previous
                .map(|prev| prev.frag_assoc.clone())
                .unwrap_or_default(),
            // #5624: record the generation this state was built under. The
            // shared `frag_assoc` cache above persists across the reload, but
            // every association it holds carries the generation it was installed
            // under; a lookup on this rebuilt state compares against
            // `build_generation`, so any association from a prior generation is
            // treated as a miss + evicted.
            build_generation: generation,
        }
    }

    /// #4518: find a previous NAT64 prefix whose prefix bytes AND source pool
    /// are byte-identical, returning its `Arc`-backed [`PortAllocator`] so live
    /// translated-port reservations survive a config reload.
    ///
    /// Order-sensitive `Vec` equality on `pool_v4` is deliberate: the
    /// allocator's per-address counters are indexed by pool position, so any
    /// change to the pool set OR its order must NOT reuse the old allocator (see
    /// [`from_snapshots_with_previous`]). Returns `None` when no compatible
    /// prefix exists (rule added, prefix changed, or pool changed) — the caller
    /// then builds a fresh allocator.
    fn reuse_allocator(
        &self,
        prefix_bytes: &[u8; 12],
        pool_v4: &[Ipv4Addr],
    ) -> Option<PortAllocator> {
        self.prefixes
            .iter()
            .find(|p| p.prefix_bytes == *prefix_bytes && p.pool_v4.as_slice() == pool_v4)
            .map(|p| p.port_allocator.clone())
    }

    /// Returns true if any NAT64 prefixes are configured.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn is_active(&self) -> bool {
        !self.prefixes.is_empty()
    }

    /// Check if an IPv6 destination matches any NAT64 prefix.
    /// Returns (prefix_index, extracted_ipv4_dest) on match.
    pub(crate) fn match_ipv6_dest(&self, dst: Ipv6Addr) -> Option<(usize, Ipv4Addr)> {
        let octets = dst.octets();
        for (idx, prefix) in self.prefixes.iter().enumerate() {
            if octets[..12] == prefix.prefix_bytes {
                let v4 = Ipv4Addr::new(octets[12], octets[13], octets[14], octets[15]);
                return Some((idx, v4));
            }
        }
        None
    }

    /// #5623: RFC 6146 §3.5 source-eligibility test. A NAT64 translator MUST
    /// drop an incoming IPv6 packet whose SOURCE address itself lies within a
    /// configured Pref64 — such a source is a synthesized / "already-translated"
    /// address, the RFC 6146 §5 hairpin-loop construction. Comparing the high 96
    /// bits against every configured prefix subsumes the degenerate cases the
    /// issue enumerates:
    ///   * the lower boundary `<prefix>::` (embedded v4 `0.0.0.0`),
    ///   * the upper boundary `<prefix>::ffff:ffff` (embedded v4 `255.255.255.255`),
    ///   * any source whose embedded v4 is non-global / looping (it is still
    ///     inside the prefix, so it matches here).
    ///
    /// A legitimate global-unicast source outside every Pref64 never matches, so
    /// eligible traffic is untouched (no over-reject). The scan is one pass over
    /// the small prefix list — identical cost and shape to `match_ipv6_dest` —
    /// and allocation-free, so it is safe on the session-miss hot path.
    pub(crate) fn source_within_pref64(&self, src: Ipv6Addr) -> bool {
        let octets = src.octets();
        self.prefixes
            .iter()
            .any(|prefix| octets[..12] == prefix.prefix_bytes)
    }

    /// #6475: RFC 6052 §3.1 non-global embedded-IPv4 screen. §3.1 is normative
    /// for the Well-Known Prefix 64:ff9b::/96 — an address translator "MUST NOT
    /// translate packets in which an address is composed of the Well-Known
    /// Prefix and a non-global IPv4 address; they MUST drop these packets".
    /// Any configured Pref64 is held to the same bar here, which is stricter
    /// than the RFC requires and is a deliberate hardening choice, not a
    /// restatement of §3.1. Pre-gate, `match_ipv6_dest` extracted the
    /// low 32 bits unconditionally, so `64:ff9b::127.0.0.1` classified
    /// `MatchReady(127.0.0.1)` and — with lo0 configured, whose addresses land
    /// in `state.local_v4` (`afxdp/forwarding_build/interfaces.rs`) — resolved
    /// LocalDelivery: a NAT64 client reached a socket bound to 127.0.0.1 on the
    /// firewall itself (the localhost-only admin plane: gRPC 50051, REST 8080).
    ///
    /// The screened classes (first-octet checks, allocation-free, one short
    /// compare chain per classified packet):
    ///   * `0.0.0.0/8`        — "this host on this network" (RFC 1122 §3.2.1.3);
    ///                          includes the `<prefix>::` lower boundary.
    ///   * `127.0.0.0/8`      — loopback (RFC 1122 §3.2.1.3) — the LocalDelivery
    ///                          exposure above.
    ///   * `169.254.0.0/16`   — link-local (RFC 3927).
    ///   * `224.0.0.0/4`      — multicast (RFC 5771); a translated multicast dst
    ///                          has no unicast FIB/BIB semantics.
    ///   * `240.0.0.0/4`      — reserved (RFC 1112 §4); subsumes
    ///                          `255.255.255.255/32` limited broadcast and the
    ///                          `<prefix>::ffff:ffff` upper boundary.
    ///
    /// §3.1 does not enumerate the non-global ranges itself: it defines them by
    /// reference, as "those defined in [RFC1918] or listed in Section 3 of
    /// [RFC5735]". Every class screened above is an RFC 5735 §3 entry, cited to
    /// its defining RFC rather than to the reference chain.
    ///
    /// That reference also reaches RFC 1918 private space; the issue scopes
    /// screening it to OPTIONAL even for the WKP (an NSP deployment may
    /// legitimately translate to internal v4), so RFC 1918 / TEST-NET embedded
    /// destinations still translate — pinned by the global-control test.
    fn embedded_v4_is_non_global(v4: Ipv4Addr) -> bool {
        let o = v4.octets();
        o[0] == 0
            || o[0] == 127
            || (o[0] == 169 && o[1] == 254)
            || (o[0] & 0xF0) == 0xE0
            || (o[0] & 0xF0) == 0xF0
    }

    /// #5623: source-eligibility-gated NAT64 classification. Runs the RFC 6146
    /// §3.5 source drop BEFORE the destination match, so a Pref64-sourced
    /// (looping/synthesized) packet returns the distinct fail-closed
    /// [`Nat64Match::IneligibleSource`] the caller counts and drops — it never
    /// reaches route lookup, policy, or `allocate_source`, so no session, BIB,
    /// or allocation state is minted for it. An eligible (non-Pref64) source
    /// falls through to the unchanged [`Self::classify_ipv6_dest`], preserving
    /// the exact forward v6→v4 behavior for every legitimate global-unicast
    /// source.
    pub(crate) fn classify_ipv6_packet(&self, src: Ipv6Addr, dst: Ipv6Addr) -> Nat64Match {
        if self.source_within_pref64(src) {
            return Nat64Match::IneligibleSource;
        }
        self.classify_ipv6_dest(dst)
    }

    /// Tri-state NAT64 destination lookup (#2291).
    ///
    /// Returns [`Nat64Match::NoPrefixMatch`] when `dst` matches no configured
    /// prefix (the caller continues IPv6 routing), [`Nat64Match::MatchReady`]
    /// when a prefix matched and a source IPv4 was allocated (translate), or
    /// [`Nat64Match::MatchUnavailable`] when a prefix matched but the pool
    /// could not yield a source (caller MUST drop, never route the synthetic
    /// IPv6 destination upstream). This is the fail-closed replacement for the
    /// `match_ipv6_dest(...).and_then(allocate_v4_source)` chain that
    /// collapsed the unallocatable case into "no match".
    ///
    /// #5623: this stays destination-only; the source-eligibility gate lives in
    /// [`Self::classify_ipv6_packet`], which calls this after clearing the
    /// source. Callers on the forward IPv6 path should use `classify_ipv6_packet`
    /// so an ineligible source is rejected before translation.
    ///
    /// #6475: a prefix-matched destination whose extracted embedded IPv4 is
    /// non-global per RFC 6052 §3.1 (see [`Self::embedded_v4_is_non_global`])
    /// now returns [`Nat64Match::IneligibleDestination`] — fail-closed with a
    /// distinct counter — BEFORE the pool check, so input validation precedes
    /// the capacity/config report and the packet never reaches route lookup,
    /// policy, `allocate_source`, or the `local_v4` LocalDelivery resolution.
    pub(crate) fn classify_ipv6_dest(&self, dst: Ipv6Addr) -> Nat64Match {
        match self.match_ipv6_dest(dst) {
            None => Nat64Match::NoPrefixMatch,
            Some((prefix_idx, dst_v4)) => {
                if Self::embedded_v4_is_non_global(dst_v4) {
                    return Nat64Match::IneligibleDestination;
                }
                match self.prefixes.get(prefix_idx) {
                    // #4381: liveness probe only — a non-empty pool means a source
                    // CAN be allocated at Permit; the actual `(snat_v4, port)`
                    // allocation is deferred to `allocate_source` so a denied flow
                    // never consumes a pool port. An empty pool fails closed.
                    Some(prefix) if !prefix.pool_v4.is_empty() => Nat64Match::MatchReady {
                        prefix_idx,
                        dst_v4,
                        dst_v6: dst,
                    },
                    _ => Nat64Match::MatchUnavailable,
                }
            }
        }
    }

    /// #4381: test-only round-robin address pick, retained so the pre-existing
    /// pool-selection tests still exercise the pool wiring. Production source
    /// selection now goes through `allocate_source` (stateful, port-unique).
    #[cfg(test)]
    pub(crate) fn allocate_v4_source(&self, prefix_idx: usize) -> Option<Ipv4Addr> {
        let prefix = self.prefixes.get(prefix_idx)?;
        if prefix.pool_v4.is_empty() {
            return None;
        }
        let idx = prefix.pool_index.fetch_add(1, Ordering::Relaxed);
        let addr = prefix.pool_v4[idx % prefix.pool_v4.len()];
        Some(addr)
    }

    /// Allocate an UNTRACKED NAT64 source translation — the pre-#6522
    /// single-holder contract, where the first release frees the pool port.
    ///
    /// Compile-time completeness guard (the #6211 F2 idiom): this untracked
    /// entry point is TEST-ONLY, so a production caller that forgot to thread
    /// its `worker_id` is a BUILD FAILURE in the non-test profile rather than a
    /// silent single-holder allocation that every sibling replica can free.
    /// Production uses [`Nat64State::allocate_source_for_worker`].
    #[cfg(test)]
    pub(crate) fn allocate_source(
        &self,
        prefix_idx: usize,
        protocol: u8,
        src_v6: Ipv6Addr,
        dst_v4: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        now_ns: u64,
    ) -> Result<(Ipv4Addr, u16), SourceNatFailureReason> {
        self.allocate_source_with_holder(
            prefix_idx,
            protocol,
            src_v6,
            dst_v4,
            src_port,
            dst_port,
            now_ns,
            crate::nat::NatHolder::Untracked,
        )
    }

    /// #6522: allocate a NAT64 source translation and record `worker_id` as its
    /// holder. The resulting session is replicated to every sibling worker,
    /// each of which reserves against this same record, so an allocation that
    /// does not name its own owner ends up with a holder mask covering every
    /// worker EXCEPT the one forwarding — and the last sibling replica to
    /// age-reap frees a live `(pool_v4, port)`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn allocate_source_for_worker(
        &self,
        prefix_idx: usize,
        protocol: u8,
        src_v6: Ipv6Addr,
        dst_v4: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        now_ns: u64,
        worker_id: u32,
    ) -> Result<(Ipv4Addr, u16), SourceNatFailureReason> {
        self.allocate_source_with_holder(
            prefix_idx,
            protocol,
            src_v6,
            dst_v4,
            src_port,
            dst_port,
            now_ns,
            crate::nat::NatHolder::Worker(worker_id),
        )
    }

    /// #4381: allocate a UNIQUE translated `(pool v4 source, L4 port/identifier)`
    /// for a NAT64 forward flow, reusing the pool-mode SNAT `PortAllocator`
    /// (RFC 6146 BIB). Called at the Permit branch — after the flow is admitted
    /// — so a denied flow never consumes a pool port.
    ///
    /// `protocol` / `src_port` / `dst_port` are the ORIGINAL IPv6 forward-flow
    /// L4 tuple (for ICMP echo, `src_port` is the query identifier and
    /// `dst_port` is 0, per `parse_flow_ports`); `dst_v4` is the extracted IPv4
    /// destination. The returned `(snat_v4, translated)` becomes the forward
    /// decision's `rewrite_src` / `rewrite_src_port`. The reverse (v4→v6) path
    /// maps the translated value back via `NatDecision::reverse` on the reverse
    /// session's decision.
    ///
    /// #6522: `holder` is the WORKER taking the allocation — see
    /// [`Nat64State::allocate_source_for_worker`].
    #[allow(clippy::too_many_arguments)]
    fn allocate_source_with_holder(
        &self,
        prefix_idx: usize,
        protocol: u8,
        src_v6: Ipv6Addr,
        dst_v4: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        now_ns: u64,
        // #6522: the allocating worker. A locally-born NAT64 session is
        // replicated to every SIBLING worker, each of which reserves against
        // this same allocator record; without the owner's own bit the mask
        // holds every worker EXCEPT the one forwarding, and the last sibling
        // replica to age-reap frees a live `(pool_v4, port)`.
        holder: crate::nat::NatHolder,
    ) -> Result<(Ipv4Addr, u16), SourceNatFailureReason> {
        let prefix = self
            .prefixes
            .get(prefix_idx)
            .ok_or(SourceNatFailureReason::AllocatorExhausted)?;
        let flow = SourceNatFlowKey {
            protocol,
            src_ip: IpAddr::V6(src_v6),
            dst_ip: IpAddr::V4(dst_v4),
            src_port,
            dst_port,
        };
        // #4559: a deterministic NAPT64 pool maps the IPv6 subscriber to a fixed
        // external IPv4 + port block (reversible without per-flow state) instead
        // of the round-robin PAT below. An out-of-range subscriber fails CLOSED
        // (DeterministicSubscriberOutOfRange) rather than silently round-robining
        // — the compliance mapping must never quietly degrade.
        if let Some(det) = prefix.deterministic_v6 {
            return allocate_nat64_pool_port_deterministic_v6(
                &prefix.port_allocator,
                flow,
                &prefix.pool_v4,
                det,
                src_v6,
                holder,
            );
        }
        allocate_nat64_pool_port(&prefix.port_allocator, flow, &prefix.pool_v4, now_ns, holder)
    }

    /// Create a NAT64 forward decision: IPv6 packet → IPv4 translated.
    /// `snat_v4` is the SNAT pool address, `dst_v4` is extracted from the
    /// prefix, and `translated_port` (#4381) is the unique per-flow translated
    /// TCP/UDP source port or ICMP echo identifier carried in `rewrite_src_port`
    /// so the frame builder rewrites the L4 field on the forward path and
    /// `NatDecision::reverse` restores the original on the reverse path.
    pub(crate) fn forward_decision(
        snat_v4: Ipv4Addr,
        dst_v4: Ipv4Addr,
        translated_port: u16,
    ) -> NatDecision {
        NatDecision {
            rewrite_src: Some(IpAddr::V4(snat_v4)),
            rewrite_dst: Some(IpAddr::V4(dst_v4)),
            rewrite_src_port: Some(translated_port),
            rewrite_dst_port: None,
            nat64: true,
            nptv6: false,
        }
    }
}

/// #4381: release (`rollback == false`) or roll back (`rollback == true`) a
/// NAT64 forward flow's translated pool port on session teardown / install
/// failure, mirroring `crate::nat::release_source_nat_allocation`.
///
/// A no-op unless this is the FORWARD entry of a NAT64 flow carrying a
/// translated source port (`is_reverse == false && nat.nat64 &&
/// rewrite_src == V4 && rewrite_src_port.is_some()`). The flow key is rebuilt
/// EXACTLY as `Nat64State::allocate_source` built it — `dst_ip` is the
/// translated IPv4 destination (`nat.rewrite_dst`), NOT the synthetic v6
/// destination stored on the session key — so the same-key `release_flow` /
/// `rollback_flow` frees the port the forward flow reserved.
///
/// #6876: EVERY prefix holding this exact `(flow, translated)` is freed — the
/// loop does NOT stop at the first one that frees it. This mirrors the
/// source-NAT sibling (`release_source_nat_allocation_with_mode`) and for the
/// same reason: `reserve_synced_nat64_allocation` takes the first prefix whose
/// allocator ACCEPTS, so selection is OCCUPANCY-dependent, not a pure function
/// of the prefix list. A prefix whose port is transiently held by an unrelated
/// local flow is skipped and the reservation lands on a later prefix; when the
/// earlier one frees and the synced session REFRESHES — every HA session-sync
/// reconnect and every periodic re-upsert re-runs the reserve — the SAME flow
/// becomes held in BOTH. A first-hit `break` then freed one and left the other
/// holding its `(pool_addr, port)` forever: nothing else removes a
/// `live_by_flow` entry (`release_flow` / `rollback_flow` / the stale-tuple
/// replace in `reserve_flow` are the only removers, and `gc_expired_chunked`
/// sweeps persistent LEASES, not live flows).
///
/// Sweeping every prefix cannot over-free: `release_flow` / `rollback_flow`
/// return false unless `live_by_flow[flow].translated` equals THIS `translated`
/// tuple, so a prefix holding a different flow — or the same flow under a
/// different translation — is untouched. For the single-reservation case the
/// outcome is bit-identical; only the early exit is gone. Pinned by
/// `nat64_6876_release_frees_every_prefix_holding_the_flow`.
#[allow(clippy::too_many_arguments)]
fn release_nat64_allocation_with_mode(
    nat64: &Nat64State,
    key: &crate::session::SessionKey,
    nat: NatDecision,
    is_reverse: bool,
    now_ns: u64,
    rollback: bool,
    holder: crate::nat::NatHolder,
) {
    if is_reverse || !nat.nat64 {
        return;
    }
    let Some(IpAddr::V4(snat_v4)) = nat.rewrite_src else {
        return;
    };
    let Some(port) = nat.rewrite_src_port else {
        return;
    };
    let flow = SourceNatFlowKey {
        protocol: key.protocol,
        src_ip: key.src_ip,
        dst_ip: nat.rewrite_dst.unwrap_or(key.dst_ip),
        src_port: key.src_port,
        dst_port: key.dst_port,
    };
    // #6876: no first-hit `break` — see the doc comment above. A flow can be
    // held in more than one prefix's allocator, and a prefix that does not hold
    // it is a cheap no-op (`release_flow` returns false on a tuple mismatch).
    for prefix in &nat64.prefixes {
        release_nat64_pool_port(
            &prefix.port_allocator,
            flow,
            snat_v4,
            port,
            now_ns,
            rollback,
            holder,
        );
    }
}

/// #4381: release a NAT64 forward flow's translated pool port on session
/// teardown (reap / purge / delete-sync), mirroring
/// `release_source_nat_allocation`.
/// Compile-time completeness guard for #6211 F2: this untracked entry point is
/// TEST-ONLY, so a production caller that forgot to thread its `worker_id` is a
/// BUILD FAILURE in the non-test profile rather than a silent single-holder
/// release of a reservation every worker holds. Production uses the
/// `_for_worker` twin.
#[cfg(test)]
pub(crate) fn release_nat64_allocation(
    nat64: &Nat64State,
    key: &crate::session::SessionKey,
    nat: NatDecision,
    is_reverse: bool,
    now_ns: u64,
) {
    release_nat64_allocation_with_mode(
        nat64,
        key,
        nat,
        is_reverse,
        now_ns,
        false,
        crate::nat::NatHolder::Untracked,
    );
}

/// #6211 F2: release THIS worker's hold on a NAT64 reservation. The
/// holder-aware twin of [`release_nat64_allocation`] — the synced NAT64 entry is
/// reserved once per worker against one shared allocator, so only the last
/// holder may free the translated `(pool v4, port)`.
pub(crate) fn release_nat64_allocation_for_worker(
    nat64: &Nat64State,
    key: &crate::session::SessionKey,
    nat: NatDecision,
    is_reverse: bool,
    now_ns: u64,
    worker_id: u32,
) {
    release_nat64_allocation_with_mode(
        nat64,
        key,
        nat,
        is_reverse,
        now_ns,
        false,
        crate::nat::NatHolder::Worker(worker_id),
    );
}

/// #4381: roll back a NAT64 forward flow's translated pool port on an
/// install-failure / admission-refusal / ICMP-error-bounce path, mirroring
/// `rollback_source_nat_allocation`.
/// Compile-time completeness guard for #6211 F2: this untracked entry point is
/// TEST-ONLY, so a production caller that forgot to thread its `worker_id` is a
/// BUILD FAILURE in the non-test profile rather than a silent single-holder
/// release of a reservation every worker holds. Production uses the
/// `_for_worker` twin.
#[cfg(test)]
pub(crate) fn rollback_nat64_allocation(
    nat64: &Nat64State,
    key: &crate::session::SessionKey,
    nat: NatDecision,
    is_reverse: bool,
    now_ns: u64,
) {
    release_nat64_allocation_with_mode(
        nat64,
        key,
        nat,
        is_reverse,
        now_ns,
        true,
        crate::nat::NatHolder::Untracked,
    );
}

/// #6211 F2: roll back THIS worker's hold on a NAT64 reservation. The
/// holder-aware twin of [`rollback_nat64_allocation`].
pub(crate) fn rollback_nat64_allocation_for_worker(
    nat64: &Nat64State,
    key: &crate::session::SessionKey,
    nat: NatDecision,
    is_reverse: bool,
    now_ns: u64,
    worker_id: u32,
) {
    release_nat64_allocation_with_mode(
        nat64,
        key,
        nat,
        is_reverse,
        now_ns,
        true,
        crate::nat::NatHolder::Worker(worker_id),
    );
}

/// #4512: reserve a peer-synced NAT64 forward flow's translated pool port in
/// THIS node's NAT64 allocator so a post-failover local allocation cannot hand
/// the same `(snat_v4, port/identifier)` to a fresh flow — the #4388 treatment
/// applied to NAT64.
///
/// The active node picks the translated `(pool v4, port)` via `allocate_source`
/// and syncs the finished [`NatDecision`] over the fabric (the translated port
/// rides `rewrite_src_port`, which IS synced — no new wire field). The standby
/// imports that pre-computed decision and never runs `allocate_source` itself,
/// so its NAT64 allocator has no record that `(snat_v4, port)` is in use.
/// Post-failover the standby-turned-active would then `allocate_source` the
/// SAME tuple for a new local flow — two forward flows colliding on one
/// translated source, so the 1:N reverse (v4→v6) index bucket mis-demuxes the
/// server's replies (reply mis-delivery / session-hijack surface, the exact
/// RFC 6146 BIB violation #4381 closed for the same-node case).
///
/// This is a no-op unless this is the FORWARD entry of a NAT64 flow carrying a
/// translated source port (`is_reverse == false && nat.nat64 &&
/// rewrite_src == V4 && rewrite_src_port.is_some()`). The flow key is rebuilt
/// EXACTLY as `Nat64State::allocate_source` built it and
/// `release_nat64_allocation` frees it — `dst_ip` is the translated IPv4
/// destination (`nat.rewrite_dst`), NOT the synthetic v6 destination on the
/// session key — so the SAME-key release on the standard teardown path
/// (`handle_delete_synced` / reap / purge, already calling
/// `release_nat64_allocation`) returns the reservation with no new delete site.
/// If the synced pool address is not a member of ANY local NAT64 pool (config
/// drift between nodes) the reserve is skipped gracefully — no panic, no
/// reservation on the wrong pool.
/// Compile-time completeness guard for #6211 F2: this untracked entry point is
/// TEST-ONLY, so a production caller that forgot to thread its `worker_id` is a
/// BUILD FAILURE in the non-test profile rather than a silent single-holder
/// release of a reservation every worker holds. Production uses the
/// `_for_worker` twin.
///
/// #6600: no longer test-only. The COORDINATOR takes an untracked reservation
/// before publishing a peer-synced import, and the per-worker reservations that
/// follow are absorbed by `reserve_flow`'s idempotent early return, so the
/// release semantics the comment above warns about are unchanged — the last
/// worker still frees.
pub(crate) fn reserve_synced_nat64_allocation(
    nat64: &Nat64State,
    key: &crate::session::SessionKey,
    nat: NatDecision,
    is_reverse: bool,
    now_ns: u64,
) -> bool {
    reserve_synced_nat64_allocation_with_holder(
        nat64,
        key,
        nat,
        is_reverse,
        now_ns,
        crate::nat::NatHolder::Untracked,
    )
}

/// #6211 F2: reserve a synced NAT64 translation and record `worker_id` as a
/// HOLDER. `handle_upsert_synced` runs on every worker against ONE shared NAT64
/// allocator, so without the holder bit the first worker to reap or delete-sync
/// frees a translated `(pool v4, port)` the other workers still forward through.
pub(crate) fn reserve_synced_nat64_allocation_for_worker(
    nat64: &Nat64State,
    key: &crate::session::SessionKey,
    nat: NatDecision,
    is_reverse: bool,
    // #6528: the stale-tuple eviction inside `reserve_flow` retires the
    // incumbent with release semantics, which re-arms a persistent lease's idle
    // expiry off a real clock.
    now_ns: u64,
    worker_id: u32,
) -> bool {
    reserve_synced_nat64_allocation_with_holder(
        nat64,
        key,
        nat,
        is_reverse,
        now_ns,
        crate::nat::NatHolder::Worker(worker_id),
    )
}

fn reserve_synced_nat64_allocation_with_holder(
    nat64: &Nat64State,
    key: &crate::session::SessionKey,
    nat: NatDecision,
    is_reverse: bool,
    now_ns: u64,
    holder: crate::nat::NatHolder,
) -> bool {
    // #6600: returns whether the translation is RESERVED — true when a prefix
    // took it, and true when there was nothing to reserve. `false` means every
    // pool prefix REFUSED, i.e. a different live allocation already owns the
    // (pool v4, port). The bool `reserve_nat64_pool_port` already computed was
    // discarded before #6600.
    if is_reverse || !nat.nat64 {
        return true;
    }
    let Some(IpAddr::V4(snat_v4)) = nat.rewrite_src else {
        return true;
    };
    let Some(port) = nat.rewrite_src_port else {
        return true;
    };
    let flow = SourceNatFlowKey {
        protocol: key.protocol,
        src_ip: key.src_ip,
        dst_ip: nat.rewrite_dst.unwrap_or(key.dst_ip),
        src_port: key.src_port,
        dst_port: key.dst_port,
    };
    // #6892: narrow to the prefix the ACTIVE node would have used, by the SAME
    // discriminator it uses, BEFORE falling back to the pool scan below.
    //
    // The scan alone takes the first prefix whose `pool_v4` contains `snat_v4`
    // -- the #6211 shape. That is not merely too loose: each `Nat64Prefix` owns
    // its OWN `port_allocator`, and the active selected its prefix with
    // `match_ipv6_dest`, i.e. on `prefix_bytes` against the IPv6 destination.
    // Two prefixes sharing one pool address therefore diverge because the
    // standby is matching on the WRONG FIELD, and a divergent pick reserves in a
    // different allocator than the one the session actually occupies -- so the
    // port stays free in the allocator that matters and a post-failover local
    // flow can be handed the same translated `(pool v4, port)`.
    //
    // `key.dst_ip` is the PRE-translation synthetic IPv6 destination, not the
    // extracted v4: a NAT64 forward flow is always keyed on the original IPv6
    // 5-tuple (`build_nat64_reverse_rebuild` in the server helpers already
    // extracts the RFC 6052 embedded v4 out of this same field), and
    // `forward_wire_key` exists precisely because the post-translation view is a
    // DIFFERENT key. That is also why `flow.dst_ip` above substitutes
    // `nat.rewrite_dst` for it.
    //
    // The scan is kept as a fallback rather than replaced: a v4-keyed or
    // prefix-less key (config drift between nodes, an old peer) still gets
    // today's behaviour instead of silently reserving nothing.
    let narrowed = match key.dst_ip {
        IpAddr::V6(dst_v6) => nat64.match_ipv6_dest(dst_v6).map(|(idx, _)| idx),
        IpAddr::V4(_) => None,
    };
    if let Some(prefix) = narrowed.and_then(|idx| nat64.prefixes.get(idx)) {
        if let Some(addr_index) = prefix.pool_v4.iter().position(|a| *a == snat_v4) {
            return reserve_nat64_pool_port(
                &prefix.port_allocator,
                flow,
                snat_v4,
                port,
                addr_index,
                prefix.deterministic_v6.is_some(),
                now_ns,
                holder,
            );
        }
    }

    for prefix in &nat64.prefixes {
        // The NAT64 allocator is sized to `pool_v4.len()` with
        // `family_offset == 0`, so the absolute allocator index equals the
        // address's position in `pool_v4` (mirrors `allocate_nat64_pool_port`).
        let Some(addr_index) = prefix.pool_v4.iter().position(|a| *a == snat_v4) else {
            continue;
        };
        // #5178: a NAPT64 (mode 2) deterministic prefix must tag its synced
        // reservation deterministic so the standby releases it via
        // `free_no_recycle`, mirroring the active node's
        // `allocate_deterministic_v6` — otherwise a deterministic pool's synced
        // churn leaks ports into a recycle queue the deterministic path never
        // drains (unbounded standby memory).
        if reserve_nat64_pool_port(
            &prefix.port_allocator,
            flow,
            snat_v4,
            port,
            addr_index,
            prefix.deterministic_v6.is_some(),
            now_ns,
            holder,
        ) {
            return true;
        }
    }
    // No prefix owned the address, or every owner refused. Not distinguished on
    // purpose: from the coordinator's point of view both mean "this node does
    // not own the translation this session names", and publishing a session for
    // either is the thing #6600 fixes.
    false
}

// ---------------------------------------------------------------------------
// Packet translation functions
// ---------------------------------------------------------------------------

const ICMPV6_ECHO_REQUEST: u8 = 128;
const ICMPV6_ECHO_REPLY: u8 = 129;
const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_ECHO_REPLY: u8 = 0;

// ICMPv6 error message types (RFC 4443).
const ICMPV6_DEST_UNREACHABLE: u8 = 1;
const ICMPV6_PACKET_TOO_BIG: u8 = 2;
const ICMPV6_TIME_EXCEEDED: u8 = 3;
const ICMPV6_PARAMETER_PROBLEM: u8 = 4;

// ICMPv4 error message types (RFC 792).
const ICMP_DEST_UNREACHABLE: u8 = 3;
const ICMP_TIME_EXCEEDED: u8 = 11;
const ICMP_PARAMETER_PROBLEM: u8 = 12;

/// Lower bound a Packet-Too-Big MTU is clamped to when it crosses the NAT64
/// boundary. The IPv6 minimum link MTU (RFC 8200) — a translated v6 client
/// must never be told to use a path MTU below this.
const IPV6_MIN_MTU: u32 = 1280;

/// Upper bound an IPv6 Packet-Too-Big MTU is clamped to when translated to an
/// IPv4 Fragmentation-Needed Next-Hop-MTU. The v4 datagram is 20 bytes smaller
/// than the v6 one it was translated from (40-byte v6 header vs 20-byte v4
/// header), so a v6 path-MTU `M` corresponds to a v4 next-hop MTU of `M - 20`
/// (RFC 7915 5.2). Subtracting 20 keeps the advertised v4 MTU consistent with
/// the smaller translated datagram.
const NAT64_HEADER_DELTA: u32 = 20;

use crate::ip_proto::{PROTO_ICMP, PROTO_ICMPV6, PROTO_TCP, PROTO_UDP};
use std::sync::atomic::AtomicU32;

/// Maximum embedded (quoted) original-packet bytes the ICMP-error translator
/// processes. RFC 4443 lets an ICMPv6 error quote "as much of the invoking
/// packet as possible" up to the IPv6 minimum MTU (1280). The translated
/// embedded packet is built into a fixed stack scratch buffer — NO per-packet
/// heap allocation (#2211) — sized for the v6 worst case; v4→v6 embedded
/// translation grows the header by 20 bytes, so the scratch headroom must cover
/// `1280 + 20`.
const MAX_EMBEDDED_LEN: usize = 1280 + NAT64_HEADER_DELTA as usize;

/// Process-global IPv4 Fragment Identification generator for translated,
/// *fragmentable* (DF=0) IPv6->IPv4 packets.
///
/// Whenever this translator emits a DF=0 (non-atomic) datagram it draws the
/// Identification from a per-translator generator, as RFC 7915 5.1 prescribes
/// for the no-Fragment-Header case. RFC 6864 4.1 then *requires* that a source
/// emitting non-atomic datagrams (DF=0) MUST NOT repeat the ID for a given
/// source/destination/protocol tuple within one Maximum Datagram Lifetime. A
/// constant ID (e.g. 0) violates that: if a downstream router fragments two
/// such datagrams between the same hosts, their fragments share an ID and
/// reassemble incorrectly. A monotonically incrementing counter is a
/// conforming, cheap generator. Atomic datagrams (DF=1) are exempt — RFC 6864
/// lets them carry any ID, so the default DF=1 path keeps ID=0.
///
/// Note this generator only governs the *Identification* value. WHEN DF is
/// cleared is a deliberate LOCAL policy (the operator-gated
/// `no-v6-frag-header` option), not the size-driven DF selection RFC 7915 5.1
/// itself describes (clear DF only when the translated IPv4 packet is <= 1260
/// bytes); see `translate_v6_to_v4`.
static NAT64_FRAG_ID: AtomicU32 = AtomicU32::new(0);

/// Return the next non-zero 16-bit Fragment Identification value for a
/// fragmentable translated datagram. The value cycles over the full non-zero
/// 16-bit space `1..=65535` with no two consecutive values equal WITHIN the
/// 65535-value cycle (the value after 65535 is 1, a jump, not a repeat).
/// Skipping 0 keeps the all-zero ID reserved (by convention) for the atomic
/// DF=1 path.
///
/// CAVEAT: at the outer `AtomicU32` counter wrap — once per 2^32 fragmentable
/// translations — two ADJACENT values do collide: `(2^32 - 1) % 65535 == 0`
/// and the wrapped `0 % 65535 == 0` both map to ID 1. This is deliberately
/// accepted (#2014 r3, Codex+AGY): IPv4's 16-bit Identification inherently
/// repeats every 65535 packets regardless, so one extra adjacent duplicate per
/// ~4.3e9 translations is operationally negligible and not worth replacing the
/// lock-free `fetch_add` with a CAS/modulo-65535 counter that would bounce a
/// cache line on this path.
fn next_frag_id() -> u16 {
    // Relaxed is sufficient: we only need a distinct, non-repeating sequence,
    // not ordering against other memory. Map the monotonic 32-bit counter onto
    // 1..=65535 via `(raw % 65535) + 1`. This is what makes the sequence
    // collision-free for RFC 6864 4.1: a naive `truncate-to-u16 then remap 0->1`
    // maps BOTH raw=0 and raw=1 to 1, so two back-to-back DF=0 translations
    // would share an Identification (and the same dup recurs at every 16-bit
    // wrap). `% 65535 + 1` instead yields 1,2,...,65535,1,2,... — every adjacent
    // pair differs.
    let raw = NAT64_FRAG_ID.fetch_add(1, Ordering::Relaxed);
    map_frag_id(raw)
}

/// Pure mapping from a monotonic 32-bit counter value to the 1..=65535
/// Identification space. Factored out of `next_frag_id` so the cycle invariant
/// (non-zero, in-range, no consecutive duplicates within the 65535-value cycle
/// — see the `next_frag_id` caveat for the accepted 2^32-boundary edge) can be
/// unit-tested deterministically without touching the process-global counter.
#[inline]
fn map_frag_id(raw: u32) -> u16 {
    (raw % 65535) as u16 + 1
}

/// Translate an IPv6 packet to IPv4 (forward direction: client→server).
///
/// Input: `packet` starts at L3 (IPv6 header), not Ethernet.
/// `snat_v4` = pool IPv4 source, `dst_v4` = extracted destination.
///
/// `no_v6_frag_header` mirrors the `security nat natv6v4 no-v6-frag-header`
/// option and selects between two DF policies. This is a deliberate LOCAL,
/// option-gated choice — NOT the literal RFC 7915 5.1 algorithm, which keys DF
/// off the *translated* IPv4 size (clear DF only when the result is <= 1260
/// bytes). The two modes are:
///   * `false` (the default): emit an *atomic* datagram — set the
///     Don't-Fragment (DF) flag and leave Identification at 0 (RFC 6864 4.1
///     permits any ID for an atomic datagram).
///   * `true`: clear DF so the packet stays fragmentable in transit (the
///     operator opts into this when downstream PMTU handling needs it).
///
/// Whichever mode clears DF, the Identification MUST stay consistent with it: a
/// DF=0 datagram is non-atomic, so RFC 6864 4.1 forbids a constant/repeated ID
/// and RFC 7915 5.1 prescribes drawing it from a per-translator generator
/// (`next_frag_id`) so a downstream fragmenter produces reassemblable fragments
/// rather than colliding on a constant ID.
///
/// Returns the translated IPv4 packet (L3 only, no Ethernet header).
///
/// Allocating convenience wrapper over [`write_v6_to_v4_into`]. Hot-path
/// callers (the frame builders) write straight into a reserved output buffer
/// with the `_into` core to avoid this per-packet `Vec` (#2211); this wrapper
/// is `#[cfg(test)]`-only — the differential tests use it to assert the `_into`
/// core is byte-identical to an owned-`Vec` translation. No production caller
/// allocates an owned NAT64 packet, so gating it on test keeps the release
/// build free of a dead-code path.
#[cfg(test)]
pub(crate) fn translate_v6_to_v4(
    packet: &[u8],
    snat_v4: Ipv4Addr,
    dst_v4: Ipv4Addr,
    no_v6_frag_header: bool,
) -> Option<Vec<u8>> {
    // Worst case (no shrink relative to input): 20-byte IPv4 header + the IPv6
    // L4 payload. The IPv6 input is `40 + payload_len`, so `20 + payload_len`
    // never exceeds the input length; sizing to the input length is a safe
    // upper bound, then we truncate to the exact written length.
    let mut out = vec![0u8; packet.len()];
    let written = write_v6_to_v4_into(&mut out, packet, snat_v4, dst_v4, no_v6_frag_header)?;
    out.truncate(written);
    Some(out)
}

/// Walk the IPv6 extension-header chain of an L3-relative IPv6 packet to find
/// the terminal transport header (#2290).
///
/// Returns `(l4_offset, l4_protocol)` where `l4_offset` is the byte offset of
/// the real transport header (TCP/UDP/ICMPv6/...) measured from the start of
/// the IPv6 header, and `l4_protocol` is its protocol number. Walks
/// Hop-by-Hop (0), Routing (43), Destination Options (60), AH (51), and
/// Fragment (44) headers, bounded to `MAX_IPV6_EXT_HEADERS` iterations
/// (RFC 8200 §4.1 — a fixed-order chain rarely exceeds a handful).
/// No-Next-Header (59) and a chain that runs off the end of the packet
/// return `None`.
///
/// #6435: this is now a thin fold over the ONE canonical walker,
/// `crate::afxdp::walk_ipv6_ext_chain` (`afxdp::frame::inspect`) — the same
/// walk the forwarding path's `packet_rel_l4_offset_and_protocol` folds, so
/// NAT64 and forwarding resolve the same L4 BY CONSTRUCTION (the #4435
/// bound-share made the bounds agree; this makes the loop itself agree).
/// Every non-`L4` verdict fails CLOSED (`None`), exactly like the canonical
/// walker (#2292): a chain still on an extension header at the
/// `MAX_IPV6_EXT_HEADERS` bound is `OverLimit`, NOT a terminal — before
/// #4435 the post-loop fall-through resolved one header deeper than the
/// canonical walker, a one-level parity skew at the bound.
///
/// The returned offset is only the START of the L4 header; the caller is
/// responsible for the non-first-fragment check (a non-first fragment carries
/// NO L4 header at this offset — its bytes are payload).
fn ipv6_l4_offset_and_protocol(packet: &[u8]) -> Option<(usize, u8)> {
    match walk_ipv6_ext_chain(packet, 0).outcome {
        ExtChainOutcome::L4(offset, protocol) => Some((offset, protocol)),
        _ => None,
    }
}

/// RFC 7915 §5.1 translation-eligibility gate (#5625).
///
/// Walk the IPv6 extension-header chain of an L3-relative IPv6 packet and
/// return `true` iff the packet carries an extension header that a stateless
/// NAT64 v6→v4 translation MUST NOT silently strip/translate. The forward
/// translator (`write_v6_to_v4_into` / `write_v6_to_v4_nonfirst_into`) calls
/// this BEFORE resolving the terminal L4 and rejects (fail-closed drop) when it
/// returns `true`, instead of letting `ipv6_l4_offset_and_protocol` walk PAST
/// the header and translate the deeper transport — which silently drops the
/// extension semantics (there is no IPv4 equivalent) or, for AH, emits an
/// IPv4 packet whose authentication no longer covers the rewritten header.
///
/// INELIGIBLE (returns `true` → drop):
///   * **Authentication Header (51)** — AH's ICV covers IP header fields NAT64
///     rewrites (source/destination address), so a translated packet carries a
///     stale/broken ICV the receiver rejects. RFC 7915 §5.1.1 makes this
///     explicit for the fragmented case ("If the Next Header field of the
///     Fragment Header is an extension header (except ESP, but including the
///     Authentication Header (AH)), then the packet SHOULD be dropped and
///     logged."); we extend the same fail-closed drop to the non-fragmented
///     case, where the literal §5.1 "copy the Next Header value" rule would
///     otherwise strip AH and emit a broken protocol-51 IPv4 packet.
///   * **Routing header (43) with Segments Left > 0** — an ACTIVE source route
///     that has NOT reached its final destination. RFC 7915 §5.1: "If a Routing
///     header with a non-zero Segments Left field is present, then the packet
///     MUST NOT be translated". (Segments Left == 0 is inert and handled below.)
///   * **Mobility (135) / HIP (139) / Shim6 (140)** — active end-to-end
///     extension semantics with NO IPv4 equivalent. The parity walker
///     (`ipv6_l4_offset_and_protocol`, #4517) walks PAST them to resolve the
///     inner L4, so translating would silently strip them and break the
///     protocol (Mobility binding updates, HIP handshakes, Shim6 locator
///     management). Reject rather than translate-and-strip.
///
/// ELIGIBLE (returns `false` → translate normally, no over-reject):
///   * **Hop-by-Hop Options (0) / Destination Options (60) / Routing with
///     Segments Left == 0 (43)** — RFC 7915 §5.1: "those IPv6 extension headers
///     MUST be ignored ... and the packet translated normally." Skipped.
///   * **Fragment (44)** — owned by the NAT64 fragment logic; skipped here.
///   * **ESP (50)** — not flagged here; it falls through to the translator's
///     protocol match, which already drops it (not TCP/UDP/ICMPv6). Unchanged.
///   * **No Next Header (59)** and a real upper-layer protocol — eligible.
///   * A **malformed/truncated** chain is NOT flagged ineligible here; it is
///     dropped fail-closed by the translator's own length guards /
///     `ipv6_l4_offset_and_protocol` returning `None`.
///
/// This gate is NAT64-translate-path specific: it does NOT change the L4
/// resolution the forwarding/screen parity walkers perform (#4435). Bounded to
/// `MAX_IPV6_EXT_HEADERS` like the sibling walkers. For ordinary traffic (the
/// first Next Header is TCP/UDP/ICMPv6) this returns on the first iteration
/// with zero extension-header reads, so the fast path is unaffected.
fn nat64_v6_translation_ineligible(packet: &[u8]) -> bool {
    if packet.len() < 40 {
        return false; // too short → the translator's length guard drops it
    }
    let mut protocol = packet[6];
    let mut offset = 40usize;
    for _ in 0..MAX_IPV6_EXT_HEADERS {
        match protocol {
            // Authentication Header (51): ICV covers rewritten IP fields —
            // MUST NOT translate. RFC 7915 §5.1.1.
            51 => return true,
            // Mobility (135) / HIP (139) / Shim6 (140): active end-to-end
            // semantics with no IPv4 equivalent — reject rather than strip.
            135 | 139 | 140 => return true,
            // Routing header (43): ineligible ONLY when Segments Left > 0 (an
            // active, not-yet-delivered source route — RFC 7915 §5.1). A
            // Routing header with Segments Left == 0 is inert; skip it.
            43 => {
                let hdr = match packet.get(offset..offset + 4) {
                    Some(h) => h,
                    None => return false, // truncated → translator drops it
                };
                if hdr[3] > 0 {
                    return true; // Segments Left > 0 → active source route
                }
                protocol = hdr[0];
                offset = match offset.checked_add((usize::from(hdr[1]) + 1) * 8) {
                    Some(o) => o,
                    None => return false,
                };
                if packet.len() < offset {
                    return false;
                }
            }
            // Hop-by-Hop (0) / Destination Options (60) / experimental
            // (253/254): "MUST be ignored ... translated normally" (RFC 7915
            // §5.1). Length in 8-byte units, not counting the first 8 bytes.
            0 | 60 | 253 | 254 => {
                let hdr = match packet.get(offset..offset + 2) {
                    Some(h) => h,
                    None => return false,
                };
                protocol = hdr[0];
                offset = match offset.checked_add((usize::from(hdr[1]) + 1) * 8) {
                    Some(o) => o,
                    None => return false,
                };
                if packet.len() < offset {
                    return false;
                }
            }
            // Fragment header (44): fixed 8 bytes; NAT64 fragment logic owns it.
            44 => {
                let frag = match packet.get(offset..offset + 8) {
                    Some(f) => f,
                    None => return false,
                };
                protocol = frag[0];
                offset = match offset.checked_add(8) {
                    Some(o) => o,
                    None => return false,
                };
                if packet.len() < offset {
                    return false;
                }
            }
            // No Next Header (59) or a real upper-layer protocol → eligible.
            _ => return false,
        }
    }
    // Chain still on an extension header after the bound: not classified as an
    // eligibility reject here — the translator's `ipv6_l4_offset_and_protocol`
    // fails CLOSED (`None`) at the same bound (#4435), so the packet is dropped
    // regardless. Do not double-attribute it to the ext-header counter.
    false
}

/// #5625: does this L2 frame trigger a NAT64 RFC 7915 §5.1 translation-
/// eligibility drop for the given ingress address family? Only the forward
/// (`AF_INET6` → v6→v4) direction can carry IPv6 extension headers; IPv4 has no
/// extension headers, so the reverse (`AF_INET`) direction is always `false`.
///
/// Used by the TX dispatcher to attribute a NAT64 build-returned-`None` to the
/// `nat64_exthdr_ineligible` counter without re-deriving the reason inline,
/// mirroring `frame_is_nat64_fragment_drop` (#2562). Returns false for a
/// malformed/short frame or an unrecognized family.
pub(crate) fn frame_is_nat64_exthdr_ineligible(frame: &[u8], addr_family: i32) -> bool {
    if addr_family != libc::AF_INET6 {
        return false;
    }
    let Some(l3) = frame_l3_offset(frame) else {
        return false;
    };
    let Some(packet) = frame.get(l3..) else {
        return false;
    };
    nat64_v6_translation_ineligible(packet)
}

/// Is this L3-relative IPv6 packet a NON-first fragment (#2290)?
///
/// Folds the shared `walk_ipv6_ext_chain` (#6435): returns `true` iff the
/// chain declared a Fragment header (44) whose fragment offset (upper 13
/// bits of bytes 2-3, mask `0xFFF8`, RFC 8200 §4.5) is non-zero. A
/// non-first fragment carries no L4 header, so its payload bytes must NOT
/// be read as L4 — the translators fail closed on it. First/atomic
/// fragments (offset 0) and packets without a fragment header return
/// `false`; a declared-but-truncated Fragment header (offset bits
/// unreadable) fails closed (`false`), exactly like the pre-#6435
/// walker's `packet.get(offset..offset + 8)` else-return. Mirrors
/// `afxdp::frame::inspect::ipv6_is_non_first_fragment` — literally: both
/// fold the same recorded first-Fragment sighting.
fn ipv6_is_non_first_fragment(packet: &[u8]) -> bool {
    walk_ipv6_ext_chain(packet, 0)
        .fragment
        .and_then(|frag| frag.bytes)
        .is_some_and(|b| (u16::from_be_bytes([b[2], b[3]]) & 0xFFF8) != 0)
}

/// Parsed IPv6 Fragment Header (next-header 44) fields, RFC 8200 §4.5.
#[derive(Clone, Copy, Debug)]
struct Ipv6FragInfo {
    /// 13-bit fragment offset in 8-byte units (same unit as the IPv4
    /// fragment-offset field, so it is copied verbatim across NAT64).
    offset_units: u16,
    /// The M (More Fragments) flag.
    more: bool,
    /// The 32-bit Identification value.
    ident: u32,
    /// #5798: the Fragment Header's Next Header byte — the upper-layer protocol
    /// (or the next extension-header type). It is a field OF the Fragment
    /// Header, so it is present and identical in EVERY fragment of a datagram,
    /// including non-first ones that carry no L4 header at all.
    next_header: u8,
}

/// Parse the IPv6 Fragment Header (next-header 44) if present (#2488).
///
/// Folds the shared `walk_ipv6_ext_chain` (#6435) and reads the FIRST
/// Fragment Header's offset / M flag / Identification from its recorded
/// sighting. Returns `None` for a packet that carries no Fragment Header
/// (an ordinary, non-fragmented datagram), so the v6→v4 translator can
/// fall back to its option-gated atomic-datagram framing. A
/// declared-but-truncated Fragment header (bytes unreadable) also returns
/// `None`, exactly like the pre-#6435 walker's `packet.get(offset..offset
/// + 8)?`; only the FIRST sighting is consulted, matching the pre-#6435
/// stop-at-first-fragment walk.
fn ipv6_fragment_header(packet: &[u8]) -> Option<Ipv6FragInfo> {
    let bytes = walk_ipv6_ext_chain(packet, 0).fragment?.bytes?;
    // bytes 2-3: FragmentOffset[15:3] | Res[2:1] | M[0].
    let word = u16::from_be_bytes([bytes[2], bytes[3]]);
    Some(Ipv6FragInfo {
        offset_units: word >> 3,
        more: (word & 0x0001) != 0,
        ident: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        // byte 0: Next Header (#5798 protocol scoping).
        next_header: bytes[0],
    })
}

/// #2562: does this L3-relative IPv6 packet trigger the NAT64 v6→v4
/// fail-closed FRAGMENT drop in [`write_v6_to_v4_into`]?
///
/// True for a non-first fragment (offset > 0, ANY protocol) or a real fragment
/// (Fragment Header present with MF=1 or offset > 0) carrying ICMPv6. An ATOMIC
/// fragment (Fragment Header present, MF=0, offset 0 — RFC 6946) and a
/// non-fragmented datagram return false. This mirrors the drop conditions of
/// `write_v6_to_v4_into` (the `ipv6_is_non_first_fragment` drop plus the ICMPv6
/// real-fragment guard) and is the single source of truth the
/// `nat64_frag_dropped` counter reads to attribute a translate-returned-`None`
/// to a fragment drop (vs an unrelated build failure).
pub(crate) fn v6_to_v4_is_fragment_drop(packet: &[u8]) -> bool {
    let Some(info) = ipv6_fragment_header(packet) else {
        return false; // no Fragment Header → not a fragment
    };
    if info.offset_units != 0 {
        return true; // non-first fragment, any protocol
    }
    if !info.more {
        return false; // atomic fragment (MF=0, offset 0) — still translates
    }
    // First fragment (MF=1, offset 0): dropped only when it carries ICMPv6.
    matches!(ipv6_l4_offset_and_protocol(packet), Some((_, PROTO_ICMPV6)))
}

/// #2562: v4→v6 twin of [`v6_to_v4_is_fragment_drop`] for the reverse NAT64
/// direction, mirroring the drop conditions of [`write_v4_to_v6_into`].
///
/// True for a non-first IPv4 fragment (offset > 0, ANY protocol) or a real
/// fragment (MF=1 or offset > 0) carrying ICMP. An atomic fragment
/// (MF=0, offset 0) and a non-fragmented datagram return false.
pub(crate) fn v4_to_v6_is_fragment_drop(packet: &[u8]) -> bool {
    if packet.len() < 20 {
        return false;
    }
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    if ihl < 20 || packet.len() < ihl {
        return false;
    }
    let frag_word = u16::from_be_bytes([packet[6], packet[7]]);
    let more = (frag_word & 0x2000) != 0;
    let offset = frag_word & 0x1FFF;
    if offset != 0 {
        return true; // non-first fragment, any protocol
    }
    if !more {
        return false; // atomic or non-fragmented
    }
    // First fragment (MF=1, offset 0): dropped only when it carries ICMP.
    packet[9] == PROTO_ICMP
}

/// #2562: does this L2 frame trigger a NAT64 fail-closed fragment drop for the
/// given ingress address family (`AF_INET6` → forward v6→v4, `AF_INET` →
/// reverse v4→v6)?
///
/// Used by the TX dispatcher to attribute a NAT64 build-returned-`None` to the
/// `nat64_frag_dropped` counter without re-deriving the drop reason inline.
/// Returns false for a malformed/short frame or an unrecognized family.
pub(crate) fn frame_is_nat64_fragment_drop(frame: &[u8], addr_family: i32) -> bool {
    let Some(l3) = frame_l3_offset(frame) else {
        return false;
    };
    let Some(packet) = frame.get(l3..) else {
        return false;
    };
    match addr_family {
        libc::AF_INET6 => v6_to_v4_is_fragment_drop(packet),
        libc::AF_INET => v4_to_v6_is_fragment_drop(packet),
        _ => false,
    }
}

/// Allocation-free IPv6→IPv4 translation: write the translated IPv4 L3 packet
/// directly into `dst` and return the number of bytes written (#2211).
///
/// `dst` must be at least `20 + ipv6_payload_len` bytes; on a too-small buffer
/// the function returns `None` without writing a partial frame. Behavior is
/// byte-identical to the previous `Vec`-allocating translator: same header
/// fields, same DF/Identification policy, same checksums — the only change is
/// the output destination and the elimination of the intermediate L3 `Vec`
/// plus the pseudo-header `Vec`.
pub(crate) fn write_v6_to_v4_into(
    dst: &mut [u8],
    packet: &[u8],
    snat_v4: Ipv4Addr,
    dst_v4: Ipv4Addr,
    no_v6_frag_header: bool,
) -> Option<usize> {
    write_v6_to_v4_translate(dst, packet, snat_v4, dst_v4, no_v6_frag_header, None)
}

/// #6472: flowless ICMP-error translation entry point (v6→v4). Identical to
/// [`write_v6_to_v4_into`] except the embedded quote's L4 destination port /
/// echo identifier is restored to the session's TRANSLATED (pool) value —
/// the tuple the v4 server actually carries — so the server can associate
/// the error (RFC 7915 §5.2 quote fidelity; the translators previously
/// copied the quoted L4 verbatim, leaving the original v6 client port,
/// which no v4 socket matches). `embedded_dst_port = None` reproduces
/// [`write_v6_to_v4_into`] byte-for-byte.
pub(crate) fn write_v6_to_v4_icmp_error_into(
    dst: &mut [u8],
    packet: &[u8],
    snat_v4: Ipv4Addr,
    dst_v4: Ipv4Addr,
    no_v6_frag_header: bool,
    embedded_dst_port: Option<u16>,
) -> Option<usize> {
    write_v6_to_v4_translate(
        dst,
        packet,
        snat_v4,
        dst_v4,
        no_v6_frag_header,
        embedded_dst_port,
    )
}

/// Shared core of [`write_v6_to_v4_into`] and
/// [`write_v6_to_v4_icmp_error_into`]; `embedded_dst_port` rides
/// [`EmbeddedV6ToV4::mapped_embedded_dst_port`] into the quoted-packet
/// translation (`None` on every data-packet caller).
fn write_v6_to_v4_translate(
    dst: &mut [u8],
    packet: &[u8],
    snat_v4: Ipv4Addr,
    dst_v4: Ipv4Addr,
    no_v6_frag_header: bool,
    embedded_dst_port: Option<u16>,
) -> Option<usize> {
    if packet.len() < 40 {
        return None;
    }
    // #5625: RFC 7915 §5.1 translation-eligibility gate. Reject (fail-closed
    // drop) a packet carrying an Authentication Header (51), an ACTIVE Routing
    // header (43, Segments Left > 0), or Mobility (135) / HIP (139) / Shim6
    // (140) BEFORE resolving the terminal L4 — translating would silently strip
    // the (non-translatable) active extension semantics or break AH
    // authentication. Hop-by-Hop / Destination Options / Routing-with-SL0 /
    // Fragment are eligible and translate normally (no over-reject).
    if nat64_v6_translation_ineligible(packet) {
        return None;
    }
    // IPv6 header fields.
    // Full 8-bit traffic class (DSCP[7:2] | ECN[1:0]) straddling bytes 0-1 of
    // the IPv6 header. Copied verbatim into the IPv4 TOS byte below per the
    // RFC 7915 §5 default (DSCP copied, ECN copied verbatim — NAT64 is
    // stateless translation, not RFC 6040 tunnel encapsulation).
    let traffic_class = ((packet[0] & 0x0f) << 4) | (packet[1] >> 4);
    let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let hop_limit = packet[7];

    if hop_limit <= 1 {
        return None; // TTL expired
    }

    // #2290: walk the IPv6 extension-header chain to learn the terminal L4
    // offset and protocol instead of assuming L4 at byte 40 / reading the
    // raw next-header. A packet carrying Hop-by-Hop / Routing / Dest-Opts /
    // AH / Fragment before its transport header was previously dropped as
    // "unsupported protocol" even though it is legal RFC 8200 input.
    let (l4_offset, l4_protocol) = ipv6_l4_offset_and_protocol(packet)?;

    // A non-first fragment has NO L4 header at `l4_offset` — its bytes are
    // payload. Reading them as a transport header (and translating) would
    // corrupt the datagram, so fail closed (drop).
    if ipv6_is_non_first_fragment(packet) {
        return None;
    }

    // Map protocol from the terminal L4, not the raw next-header.
    let ipv4_protocol = match l4_protocol {
        PROTO_ICMPV6 => PROTO_ICMP,
        PROTO_TCP | PROTO_UDP => l4_protocol,
        _ => return None, // Unsupported protocol
    };

    // #2562 fail-closed: a REAL fragment (Fragment Header present with MF=1 OR
    // a non-zero offset) carrying ICMPv6 CANNOT be translated. The ICMPv4
    // checksum covers the WHOLE ICMP message, but a single fragment holds only
    // a slice of it, so `translate_icmpv6_message_to_icmpv4` below would
    // recompute the checksum over just this fragment's bytes and emit a FIRST
    // fragment with a wrong checksum that the receiver discards. A non-first
    // fragment (offset > 0, any protocol) is already dropped above; this
    // additionally drops the FIRST fragment (MF=1, offset 0) of an ICMPv6
    // datagram. An ATOMIC fragment (Fragment Header present, MF=0, offset 0 —
    // RFC 6946) is NOT a real fragment: it carries the complete ICMP message
    // and still translates normally. The stateful frag-association cache that
    // would let real ICMP fragments traverse end-to-end via reassembly is the
    // deferred principled fix (#2562 / #3291 stage 4).
    if l4_protocol == PROTO_ICMPV6 {
        if let Some(info) = ipv6_fragment_header(packet) {
            if info.more || info.offset_units != 0 {
                return None;
            }
        }
    }

    // The L4 region starts at the walked offset and ends at the IPv6
    // payload boundary (`40 + payload_len`). The ext-header bytes between
    // byte 40 and `l4_offset` are stripped by NAT64: RFC 7915 §5.1 maps the
    // IPv6 packet to an IPv4 packet carrying only the transport payload,
    // dropping the (non-translatable) IPv6 extension headers.
    let l4_end = 40usize.checked_add(payload_len)?;
    if l4_offset > l4_end {
        return None; // ext-header chain overran the advertised payload
    }
    let l4_payload = packet.get(l4_offset..l4_end)?;
    let new_ttl = hop_limit - 1;

    // The L4 length is normally unchanged, but an ICMP *error* message embeds
    // the original (return-direction) packet, which is itself NAT64-translated
    // v6->v4 and so SHRINKS by 20 bytes. The translated L4 therefore never
    // exceeds the input L4, so reserving `20 + l4_payload.len()` is a safe upper
    // bound; the exact written length is computed below.
    let max_total_len = 20usize + l4_payload.len();
    let out = dst.get_mut(..max_total_len)?;

    // Build IPv4 header (total length + checksum patched after the L4 length is
    // known, since an ICMP-error translation can shrink the L4).
    out[0] = 0x45; // version=4, IHL=5
    out[1] = traffic_class; // DSCP/ECN copied from IPv6 traffic class (RFC 7915 §5)
    // #2488: if the IPv6 datagram carries a Fragment Header, the IPv4
    // fragmentation fields MUST be derived from THE PACKET (RFC 7915 §5), not
    // the local no-v6-frag-header policy — otherwise a real first fragment is
    // mistranslated into an atomic (MF=0) datagram and a receiver accepts the
    // truncated first fragment as a complete datagram. When no Fragment Header
    // is present the datagram is atomic and the existing option-gated LOCAL DF
    // policy applies. Either way the flags+frag-offset word (bytes 6-7) and the
    // Identification field (bytes 4-5) must stay mutually consistent:
    //   * Atomic, default (DF=1, 0x4000): non-fragmentable. RFC 6864 4.1
    //     permits any ID for an atomic datagram, so leave ID=0.
    //   * Atomic, no-v6-frag-header (DF=0, 0x0000): a *fragmentable*
    //     (non-atomic) datagram. A non-atomic datagram MUST carry a non-zero
    //     Identification from a per-translator generator (RFC 7915 5.1 / RFC
    //     6864 4.1) so a downstream fragmenter does not collide distinct
    //     datagrams on a constant ID. Pinning ID=0 here while clearing DF was
    //     the bug fixed in #2008 H16.
    //   * Real fragment (Fragment Header present): DF=0, MF copied from the
    //     IPv6 M flag, the 13-bit fragment offset copied verbatim (both fields
    //     count 8-byte units), and the Identification taken from the low 16
    //     bits of the Fragment Header's 32-bit Identification.
    let frag_info = ipv6_fragment_header(packet);
    let (frag_word, identification): (u16, u16) = match frag_info {
        Some(info) => {
            let mf = if info.more { 0x2000u16 } else { 0 };
            (mf | (info.offset_units & 0x1FFF), (info.ident & 0xFFFF) as u16)
        }
        None if no_v6_frag_header => (0x0000, next_frag_id()),
        None => (0x4000, 0),
    };
    out[4..6].copy_from_slice(&identification.to_be_bytes()); // identification
    out[6..8].copy_from_slice(&frag_word.to_be_bytes()); // flags + frag offset
    out[8] = new_ttl;
    out[9] = ipv4_protocol;
    out[10..12].copy_from_slice(&[0, 0]); // header checksum = 0 (computed below)
    out[12..16].copy_from_slice(&snat_v4.octets());
    out[16..20].copy_from_slice(&dst_v4.octets());

    // Translate the L4 region into the output and learn its final length.
    let l4_len = if l4_protocol == PROTO_ICMPV6 {
        // The embedded (quoted) original packet is the RETURN-direction packet:
        // its addresses are the outer error's addresses swapped, so v6->v4 the
        // embedded src maps to `dst_v4` and the embedded dst maps to `snat_v4`.
        let embedded = EmbeddedV6ToV4 {
            mapped_embedded_src: dst_v4,
            mapped_embedded_dst: snat_v4,
            mapped_embedded_dst_port: embedded_dst_port,
        };
        translate_icmpv6_message_to_icmpv4(&mut out[20..], l4_payload, &embedded)?
    } else {
        // Non-ICMP: copy L4 payload verbatim (single copy).
        out[20..max_total_len].copy_from_slice(l4_payload);
        l4_payload.len()
    };

    let ipv4_total_len = 20 + l4_len;
    out[2..4].copy_from_slice(&(ipv4_total_len as u16).to_be_bytes());

    // L4 checksum after the IPv6→IPv4 pseudo-header change. The L4 payload is
    // byte-identical across NAT64 translation (verbatim copy for TCP/UDP), and
    // the transport length + protocol number are unchanged, so ONLY the
    // pseudo-header addresses differ between the v6 and v4 forms. That makes an
    // O(1) RFC 1624 incremental adjustment of the verbatim-copied L4 checksum
    // BYTE-IDENTICAL to a full recompute over the whole payload (one's-complement
    // addition is exact), but without re-summing every byte:
    //
    //   * #2488 FRAGMENT (TCP/UDP): a full recompute is IMPOSSIBLE — the first
    //     fragment's checksum covers the whole reassembled payload that is not
    //     present here — so the incremental adjustment is mandatory.
    //   * #3025 NON-fragment (TCP, or UDP with a non-zero baseline checksum):
    //     a full recompute is possible but wasteful; the incremental adjustment
    //     produces the identical wire result at O(changed-words) cost.
    //   * ICMP: ICMPv6→ICMPv4 genuinely rewrites the message and ICMPv4 carries
    //     no pseudo-header, so `translate_icmpv6_message_to_icmpv4` already set
    //     the correct checksum and the generic recompute re-affirms it.
    //   * Non-fragment UDP with a 0x0000 baseline: an IPv6 UDP checksum of zero
    //     is illegal (no trustworthy baseline to adjust), so fall back to a full
    //     recompute to GENERATE a valid one.
    let nonfrag_incremental = frag_info.is_none()
        && (ipv4_protocol == PROTO_TCP
            || (ipv4_protocol == PROTO_UDP && out.get(26..28) != Some(&[0, 0][..])));
    let frag_incremental = frag_info.is_some() && matches!(ipv4_protocol, PROTO_TCP | PROTO_UDP);
    if frag_incremental || nonfrag_incremental {
        let mut v6_addrs = [0u8; 32];
        v6_addrs.copy_from_slice(&packet[8..40]);
        adjust_l4_checksum_v6_to_v4_incremental(
            &mut out[..ipv4_total_len],
            ipv4_protocol,
            &v6_addrs,
            snat_v4,
            dst_v4,
        )?;
    } else {
        recompute_l4_checksum_after_nat64_v6_to_v4(&mut out[..ipv4_total_len], ipv4_protocol)?;
    }

    // Compute IPv4 header checksum.
    let hdr_sum = checksum16(&out[..20]);
    out[10..12].copy_from_slice(&hdr_sum.to_be_bytes());

    Some(ipv4_total_len)
}

/// Translate an IPv4 packet to IPv6 (reverse direction: server→client reply).
///
/// Input: `packet` starts at L3 (IPv4 header), not Ethernet.
/// `dst_v6` is the original IPv6 client source, `src_v6` is the NAT64 prefix
/// + original IPv4 server address (i.e. orig_dst_v6 for the reply src).
///
/// Returns the translated IPv6 packet (L3 only, no Ethernet header).
///
/// Allocating convenience wrapper over [`write_v4_to_v6_into`]; see the
/// `_into` core for the hot-path, allocation-free entry point (#2211).
/// `#[cfg(test)]`-only (the differential byte-identity tests), like its
/// v6->v4 twin — no production caller allocates an owned NAT64 packet.
#[cfg(test)]
pub(crate) fn translate_v4_to_v6(
    packet: &[u8],
    src_v6: Ipv6Addr,
    dst_v6: Ipv6Addr,
) -> Option<Vec<u8>> {
    // IPv4→IPv6 grows the outer header by 20 bytes (40-byte v6 header vs the
    // 20-byte v4 header). An ICMP-error message ALSO grows its embedded quoted
    // packet by another 20 bytes (the embedded v4 header expands to a v6
    // header). The worst-case output is therefore `packet.len() + 40`. Allocate
    // that upper bound, then truncate to the exact written length.
    let mut out = vec![0u8; packet.len().saturating_add(2 * NAT64_HEADER_DELTA as usize)];
    let written = write_v4_to_v6_into(&mut out, packet, src_v6, dst_v6)?;
    out.truncate(written);
    Some(out)
}

/// Allocation-free IPv4→IPv6 translation: write the translated IPv6 L3 packet
/// directly into `dst` and return the number of bytes written (#2211).
///
/// `dst` must be at least `40 + 8 + (ipv4_total_len - ihl)` bytes for a
/// fragmented input (the extra 8 bytes are the inserted IPv6 Fragment Header,
/// #2488) and `40 + (ipv4_total_len - ihl)` otherwise; on a too-small buffer
/// the function returns `None` without writing a partial frame. Behavior on a
/// non-fragmented input is byte-identical to the previous `Vec`-allocating
/// translator.
pub(crate) fn write_v4_to_v6_into(
    dst: &mut [u8],
    packet: &[u8],
    src_v6: Ipv6Addr,
    dst_v6: Ipv6Addr,
) -> Option<usize> {
    write_v4_to_v6_translate(dst, packet, src_v6, dst_v6, None)
}

/// #6472: flowless ICMP-error translation entry point (v4→v6). Identical to
/// [`write_v4_to_v6_into`] except the embedded quote's L4 source port /
/// echo identifier is restored to the ORIGINAL v6 client value — the tuple
/// the client actually sent — so the client can associate the error with
/// its session (RFC 7915 §4.2 quote fidelity; the translators previously
/// copied the quoted L4 verbatim, leaving the TRANSLATED pool port no
/// client socket matches). `embedded_src_port = None` reproduces
/// [`write_v4_to_v6_into`] byte-for-byte.
pub(crate) fn write_v4_to_v6_icmp_error_into(
    dst: &mut [u8],
    packet: &[u8],
    src_v6: Ipv6Addr,
    dst_v6: Ipv6Addr,
    embedded_src_port: Option<u16>,
) -> Option<usize> {
    write_v4_to_v6_translate(dst, packet, src_v6, dst_v6, embedded_src_port)
}

/// Shared core of [`write_v4_to_v6_into`] and
/// [`write_v4_to_v6_icmp_error_into`]; `embedded_src_port` rides
/// [`EmbeddedV4ToV6::mapped_embedded_src_port`] into the quoted-packet
/// translation (`None` on every data-packet caller).
fn write_v4_to_v6_translate(
    dst: &mut [u8],
    packet: &[u8],
    src_v6: Ipv6Addr,
    dst_v6: Ipv6Addr,
    embedded_src_port: Option<u16>,
) -> Option<usize> {
    if packet.len() < 20 {
        return None;
    }
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    if ihl < 20 || packet.len() < ihl {
        return None;
    }
    // IPv4 TOS byte (DSCP[7:2] | ECN[1:0]) — copied verbatim into the IPv6
    // traffic class below per the RFC 7915 §4 default (DSCP copied, ECN copied
    // verbatim — NAT64 is stateless translation, not RFC 6040 encapsulation).
    let tos = packet[1];
    let ttl = packet[8];
    if ttl <= 1 {
        return None; // TTL expired
    }
    let protocol = packet[9];
    // Trim the L4 payload to the IPv4 Total Length field rather than the end
    // of the slice. The caller passes the whole L3-onward frame, which may
    // include Ethernet padding appended to reach the 60/64-byte minimum frame
    // size (common for TCP ACKs, DNS replies, short HTTP). Copying that padding
    // into the IPv6 packet inflates payload_len and poisons the recomputed L4
    // checksum, so the receiver drops the reply. This mirrors the forward path
    // (translate_v6_to_v4) which trims to the IPv6 payload_len field.
    //
    // total_len is attacker/driver-controlled, so clamp safely: a malformed
    // header could advertise a length shorter than the IPv4 header or longer
    // than the bytes we actually received.
    let ipv4_total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if ipv4_total_len < ihl || ipv4_total_len > packet.len() {
        return None;
    }
    let l4_payload = packet.get(ihl..ipv4_total_len)?;

    // Map protocol.
    let next_header = match protocol {
        PROTO_ICMP => PROTO_ICMPV6,
        PROTO_TCP | PROTO_UDP => protocol,
        _ => return None,
    };

    // #2488: a FIRST IPv4 fragment (MF=1, offset 0) MUST become an IPv6 packet
    // carrying a Fragment Header (next-header 44), per RFC 7915 §4. Without it
    // the receiver treats a truncated first fragment as a complete datagram.
    // Bytes 6-7 are [Res(1) | DF(1) | MF(1) | FragOffset(13)] in 8-byte units
    // (the same unit as the IPv6 Fragment Header offset). Non-first fragments
    // are dropped below.
    let v4_frag_word = u16::from_be_bytes([packet[6], packet[7]]);
    let v4_more = (v4_frag_word & 0x2000) != 0;
    let v4_offset_units = v4_frag_word & 0x1FFF;
    // A NON-first fragment (offset > 0) carries no L4 header — its bytes are
    // payload, not a transport header. It never reaches the reverse NAT64
    // translator anyway (no L4 ports to match the session), but fail closed
    // here, symmetric with the v6→v4 non-first-fragment drop. Only first
    // (offset 0, MF=1) and atomic (offset 0, MF=0) datagrams translate.
    if v4_offset_units != 0 {
        return None;
    }
    let is_fragment = v4_more;
    // #2562 fail-closed: a REAL fragment (MF=1 or offset > 0) carrying ICMP
    // cannot be translated — the ICMPv6 checksum covers the WHOLE datagram, so
    // `translate_icmpv4_message_to_icmpv6` over a single fragment's bytes would
    // emit a FIRST fragment with a wrong checksum the receiver discards. A
    // non-first fragment (offset > 0) is dropped above; this drops the FIRST
    // fragment (MF=1, offset 0) of an ICMP datagram. An ATOMIC fragment
    // (MF=0, offset 0) still translates. Symmetric with the v6→v4 ICMP-fragment
    // guard; the stateful frag-association cache remains deferred (#2562 /
    // #3291 stage 4).
    if protocol == PROTO_ICMP && is_fragment {
        return None;
    }
    let v4_ident = u16::from_be_bytes([packet[4], packet[5]]);
    // RFC 7915 §4.5: a UDP fragment with a zero IPv4 checksum cannot be
    // translated — the IPv6 UDP checksum is mandatory and cannot be computed
    // from a single fragment (the full payload is unavailable). Drop it rather
    // than emit an illegal zero-checksum IPv6 UDP datagram.
    if is_fragment
        && protocol == PROTO_UDP
        && packet.get(ihl + 6..ihl + 8) == Some(&[0, 0][..])
    {
        return None;
    }
    let frag_hdr_len = if is_fragment { 8usize } else { 0 };

    let new_hop_limit = ttl - 1;

    // Build the 40-byte IPv6 header. The 8-bit traffic class straddles bytes
    // 0-1: TC[7:4] in the low nibble of byte 0 (alongside the version=6 nibble)
    // and TC[3:0] in the high nibble of byte 1 (alongside the flow-label high
    // nibble, left at 0). Mirrors apply_dscp_rewrite_to_frame in
    // afxdp/frame/mod.rs:133-134. The caller's buffer may be reused (a TX UMEM
    // frame), so write every byte of the IPv6 header explicitly rather than
    // relying on a zero-initialized destination: zero byte 1's low nibble +
    // bytes 2-3 (the flow label). The payload-length field (bytes 4-5) is
    // patched after the L4 length is known — an ICMP-error translation grows
    // the embedded packet by 20 bytes.
    let hdr = dst.get_mut(..40)?;
    hdr[0] = 0x60 | (tos >> 4); // version=6 | TC[7:4]
    hdr[1] = (tos & 0x0f) << 4; // TC[3:0] | flow-label high nibble (0)
    hdr[2] = 0; // flow label
    hdr[3] = 0; // flow label
    // A fragmented datagram chains a Fragment Header (44) after the base
    // header; the base next-header points at it and the Fragment Header carries
    // the real upper-layer protocol.
    hdr[6] = if is_fragment { 44 } else { next_header };
    hdr[7] = new_hop_limit;
    hdr[8..24].copy_from_slice(&src_v6.octets());
    hdr[24..40].copy_from_slice(&dst_v6.octets());

    // #2488: emit the 8-byte IPv6 Fragment Header (RFC 8200 §4.5) when the
    // input was an IPv4 fragment. The fragment offset is copied verbatim (both
    // count 8-byte units), the M flag mirrors IPv4 MF, and the Identification
    // is the IPv4 16-bit Identification zero-extended to 32 bits (RFC 7915 §4).
    if is_fragment {
        let frag = dst.get_mut(40..48)?;
        frag[0] = next_header;
        frag[1] = 0; // reserved
        let frag_word = (v4_offset_units << 3) | u16::from(v4_more);
        frag[2..4].copy_from_slice(&frag_word.to_be_bytes());
        frag[4..8].copy_from_slice(&u32::from(v4_ident).to_be_bytes());
    }

    // Translate the L4 region into the output tail and learn its final length.
    // `get_mut(l4_off..)` only borrows the space actually present in `dst`; the
    // ICMP-error path may need up to 20 bytes more than the input L4 (embedded
    // packet growth), so the frame builder over-allocates by 20. A Fragment
    // Header shifts the L4 region 8 bytes further into the buffer.
    let l4_off = 40 + frag_hdr_len;
    let l4_dst = dst.get_mut(l4_off..)?;
    let l4_len = if protocol == PROTO_ICMP {
        // The embedded (quoted) original packet is the RETURN-direction packet:
        // its addresses are the outer error's addresses swapped. v4->v6 the
        // embedded src (our SNAT pool v4) maps to the original v6 client
        // (`dst_v6`), and the embedded dst (the v4 server) maps to the NAT64
        // prefix + server address — the prefix being the top 96 bits of the
        // outer translated source (`src_v6` = prefix::server).
        let mut prefix_bytes = [0u8; 12];
        prefix_bytes.copy_from_slice(&src_v6.octets()[..12]);
        let embedded = EmbeddedV4ToV6 {
            mapped_embedded_src: dst_v6,
            prefix_bytes,
            mapped_embedded_src_port: embedded_src_port,
        };
        translate_icmpv4_message_to_icmpv6(l4_dst, l4_payload, &embedded)?
    } else {
        // Non-ICMP: copy L4 payload verbatim (single copy).
        l4_dst.get_mut(..l4_payload.len())?.copy_from_slice(l4_payload);
        l4_payload.len()
    };

    let ipv6_payload_len = frag_hdr_len + l4_len;
    let ipv6_total_len = 40 + ipv6_payload_len;
    dst[4..6].copy_from_slice(&(ipv6_payload_len as u16).to_be_bytes());

    // L4 checksum after the IPv4→IPv6 pseudo-header change. The L4 payload is
    // byte-identical across translation and the transport length + protocol
    // number are unchanged, so ONLY the pseudo-header addresses differ — making
    // an O(1) RFC 1624 incremental adjustment BYTE-IDENTICAL to a full recompute
    // (see the v6→v4 twin for the full rationale).
    //
    //   * #2488 FRAGMENT (TCP/UDP): incremental adjustment is mandatory (the
    //     transport payload is incomplete). Fragmented ICMP keeps whatever
    //     `translate_icmpv4_message_to_icmpv6` produced — a degenerate edge that
    //     is moot because non-first fragments never reach this translator (no L4
    //     ports to match the reverse NAT64 session), so a fragmented datagram
    //     never reassembles regardless.
    //   * #3025 NON-fragment (TCP, or UDP with a non-zero IPv4 checksum): the
    //     incremental adjustment replaces the previous full recompute at no
    //     change to the wire result.
    //   * ICMP: ICMPv4→ICMPv6 rewrites the message AND ICMPv6 (unlike ICMPv4)
    //     uses a pseudo-header, so the checksum genuinely changes — full
    //     recompute.
    //   * Non-fragment UDP with a 0x0000 IPv4 checksum: RFC 768 "no checksum
    //     present". There is no baseline to adjust and IPv6 UDP REQUIRES a
    //     checksum, so a full recompute GENERATES one.
    if is_fragment {
        if matches!(next_header, PROTO_TCP | PROTO_UDP) {
            let mut v6_addrs = [0u8; 32];
            v6_addrs[..16].copy_from_slice(&src_v6.octets());
            v6_addrs[16..].copy_from_slice(&dst_v6.octets());
            let mut v4_addrs = [0u8; 8];
            v4_addrs[..4].copy_from_slice(&packet[12..16]);
            v4_addrs[4..].copy_from_slice(&packet[16..20]);
            adjust_l4_checksum_v4_to_v6_incremental(
                &mut dst[..ipv6_total_len],
                next_header,
                l4_off,
                &v4_addrs,
                &v6_addrs,
            )?;
        }
    } else {
        let udp_no_baseline = next_header == PROTO_UDP
            && dst.get(l4_off + 6..l4_off + 8) == Some(&[0, 0][..]);
        if matches!(next_header, PROTO_TCP | PROTO_UDP) && !udp_no_baseline {
            let mut v6_addrs = [0u8; 32];
            v6_addrs[..16].copy_from_slice(&src_v6.octets());
            v6_addrs[16..].copy_from_slice(&dst_v6.octets());
            let mut v4_addrs = [0u8; 8];
            v4_addrs[..4].copy_from_slice(&packet[12..16]);
            v4_addrs[4..].copy_from_slice(&packet[16..20]);
            adjust_l4_checksum_v4_to_v6_incremental(
                &mut dst[..ipv6_total_len],
                next_header,
                l4_off,
                &v4_addrs,
                &v6_addrs,
            )?;
        } else {
            recompute_l4_checksum_after_nat64_v4_to_v6(&mut dst[..ipv6_total_len], next_header)?;
        }
    }

    Some(ipv6_total_len)
}

/// Map an ICMPv6 error type/code to its ICMPv4 equivalent per RFC 7915 §5.2.
/// Returns `None` for ICMPv6 types that have no IPv4 mapping (e.g. NDP, MLD —
/// which are link-local and never cross the translator) so the caller drops
/// them rather than emitting a malformed ICMPv4 error.
///
/// Packet-Too-Big (type 2) is handled separately by the caller because it also
/// rewrites the MTU field, so it is intentionally absent here.
fn map_icmpv6_error_to_icmpv4(icmpv6_type: u8, icmpv6_code: u8) -> Option<(u8, u8)> {
    match icmpv6_type {
        ICMPV6_DEST_UNREACHABLE => {
            // RFC 7915 5.2: ICMPv6 Destination Unreachable codes map onto the
            // ICMPv4 Destination Unreachable code space.
            let v4_code = match icmpv6_code {
                0 => 1, // no route to destination       -> host unreachable
                1 => 10, // communication administratively prohibited
                //          -> communication with destination host
                //             administratively prohibited
                2 => 1, // beyond scope of source address -> host unreachable
                3 => 1, // address unreachable            -> host unreachable
                4 => 3, // port unreachable               -> port unreachable
                _ => return None,
            };
            Some((ICMP_DEST_UNREACHABLE, v4_code))
        }
        ICMPV6_TIME_EXCEEDED => {
            // RFC 7915 5.2: Time Exceeded (3) maps 1:1 with its code preserved
            // (0 = hop limit exceeded, 1 = fragment reassembly time exceeded).
            Some((ICMP_TIME_EXCEEDED, icmpv6_code))
        }
        ICMPV6_PARAMETER_PROBLEM => {
            // RFC 7915 5.2: Parameter Problem.
            match icmpv6_code {
                // code 0 (erroneous header field) -> ICMPv4 Parameter Problem
                // code 0 (pointer indicates the error). The embedded-pointer
                // remap (RFC 7915 Figure 6) is not performed; the pointer is a
                // best-effort hint, and Junos/vSRX parity does not depend on it.
                0 => Some((ICMP_PARAMETER_PROBLEM, 0)),
                // code 1 (unrecognized Next Header) -> ICMPv4 Destination
                // Unreachable / Protocol Unreachable.
                1 => Some((ICMP_DEST_UNREACHABLE, 2)),
                // code 2 (unrecognized IPv6 option) is silently dropped per
                // RFC 7915 — it has no IPv4 analogue.
                _ => None,
            }
        }
        _ => None,
    }
}

/// Map an ICMPv4 error type/code to its ICMPv6 equivalent per RFC 7915 §4.2.
/// Returns `None` for ICMPv4 types/codes that have no IPv6 mapping so the
/// caller drops them. Fragmentation-Needed (type 3 code 4) is handled
/// separately by the caller because it rewrites the MTU field.
fn map_icmpv4_error_to_icmpv6(icmpv4_type: u8, icmpv4_code: u8) -> Option<(u8, u8)> {
    match icmpv4_type {
        ICMP_DEST_UNREACHABLE => {
            // RFC 7915 4.2: ICMPv4 Destination Unreachable codes map onto the
            // ICMPv6 Destination Unreachable / Packet Too Big code space.
            // (code 4, Fragmentation Needed, is handled by the caller — it
            // becomes Packet Too Big with an MTU rewrite.)
            let mapped = match icmpv4_code {
                0 => (ICMPV6_DEST_UNREACHABLE, 0), // net unreachable -> no route
                1 => (ICMPV6_DEST_UNREACHABLE, 0), // host unreachable -> no route
                2 => (ICMPV6_PARAMETER_PROBLEM, 1), // protocol unreachable ->
                //  parameter problem, unrecognized Next Header
                3 => (ICMPV6_DEST_UNREACHABLE, 4), // port unreachable -> port unreachable
                5 => (ICMPV6_DEST_UNREACHABLE, 0), // source route failed -> no route
                6 => (ICMPV6_DEST_UNREACHABLE, 0), // dest network unknown -> no route
                7 => (ICMPV6_DEST_UNREACHABLE, 0), // dest host unknown -> no route
                8 => (ICMPV6_DEST_UNREACHABLE, 0), // src host isolated -> no route
                11 => (ICMPV6_DEST_UNREACHABLE, 0), // net unreachable for TOS -> no route
                12 => (ICMPV6_DEST_UNREACHABLE, 0), // host unreachable for TOS -> no route
                9 | 10 | 13 | 15 => (ICMPV6_DEST_UNREACHABLE, 1), // admin prohibited
                _ => return None,
            };
            Some(mapped)
        }
        ICMP_TIME_EXCEEDED => {
            // RFC 7915 4.2: Time Exceeded (11) maps 1:1 with its code preserved.
            Some((ICMPV6_TIME_EXCEEDED, icmpv4_code))
        }
        ICMP_PARAMETER_PROBLEM => {
            // RFC 7915 4.2: Parameter Problem (12).
            match icmpv4_code {
                // code 0 (pointer indicates error) and code 2 (bad length) ->
                // ICMPv6 Parameter Problem, erroneous header field.
                0 | 2 => Some((ICMPV6_PARAMETER_PROBLEM, 0)),
                // code 1 (missing required option) has no IPv6 analogue.
                _ => None,
            }
        }
        _ => return None,
    }
}

/// Address mapping for the embedded (quoted) packet of an ICMPv6 error being
/// translated v6->v4. The embedded packet is the RETURN-direction original
/// packet whose addresses are the outer error's addresses swapped, so both
/// embedded addresses are known constants derived from the outer translation —
/// no NAT64 prefix arithmetic is needed in this direction (the outer src/dst v4
/// already carry the fully-mapped values).
struct EmbeddedV6ToV4 {
    /// IPv4 the embedded IPv6 source maps to.
    mapped_embedded_src: Ipv4Addr,
    /// IPv4 the embedded IPv6 destination maps to.
    mapped_embedded_dst: Ipv4Addr,
    /// #6472: optional L4 destination-port / ICMP-identifier rewrite for the
    /// quoted packet, applied before the outer ICMP checksum is computed.
    /// The NAT64 flowless ICMP-error path (v6→v4) translates an error about
    /// the session's RETURN-direction wire packet: the quote's destination
    /// port / echo id is the ORIGINAL v6 client value, which the v4 server
    /// can only associate when it reads back as the TRANSLATED (pool) value
    /// the server actually replied to. `None` leaves the quoted L4 verbatim
    /// (the data-packet callers — byte-identical to pre-#6472).
    mapped_embedded_dst_port: Option<u16>,
}

/// Address mapping for the embedded (quoted) packet of an ICMPv4 error being
/// translated v4->v6. The embedded packet is the RETURN-direction original
/// packet: its IPv4 source (our SNAT pool) maps to the original v6 client
/// (`mapped_embedded_src`); its IPv4 destination (the v4 server) maps to the
/// NAT64 prefix + that destination (`prefix_bytes` :: dst-v4).
struct EmbeddedV4ToV6 {
    /// IPv6 the embedded IPv4 source maps to (the original v6 client).
    mapped_embedded_src: Ipv6Addr,
    /// NAT64 /96 prefix the embedded IPv4 destination is composed onto.
    prefix_bytes: [u8; 12],
    /// #6472: optional L4 source-port / ICMP-identifier rewrite for the
    /// quoted packet, applied before the outer ICMPv6 checksum is computed.
    /// The NAT64 flowless ICMP-error path (v4→v6) translates an error about
    /// the session's FORWARD wire packet: the quote's source port / echo id
    /// is the TRANSLATED (pool) value, which the v6 client can only
    /// associate when it reads back as its ORIGINAL value. `None` leaves
    /// the quoted L4 verbatim (the data-packet callers — byte-identical to
    /// pre-#6472).
    mapped_embedded_src_port: Option<u16>,
}

/// Translate a complete ICMPv6 message (`src`, starting at the ICMPv6 type
/// byte) into ICMPv4 in `dst`, returning the written ICMPv4 message length.
///
/// Handles echo request/reply (length unchanged) AND error messages
/// (Destination Unreachable, Packet Too Big, Time Exceeded, Parameter Problem)
/// per RFC 7915 §5.2 — for an error the leading 8-byte ICMP header is followed
/// by the quoted original packet, whose embedded IPv6 header is NAT64-translated
/// to IPv4 (addresses mapped, lengths/checksums fixed). The ICMPv4 checksum is
/// computed here (ICMPv4 has no pseudo-header), so the caller's generic
/// recompute is a consistent no-op over the already-correct value.
///
/// Allocation-free: the embedded packet is translated through a fixed stack
/// scratch buffer (`MAX_EMBEDDED_LEN`), never the heap (#2211). `None` aborts
/// the frame (drop) for an untranslatable type/code or a malformed/oversized
/// embedded packet.
fn translate_icmpv6_message_to_icmpv4(
    dst: &mut [u8],
    src: &[u8],
    embedded: &EmbeddedV6ToV4,
) -> Option<usize> {
    if src.len() < 4 {
        return None;
    }
    let icmpv6_type = src[0];
    let icmpv6_code = src[1];

    match icmpv6_type {
        ICMPV6_ECHO_REQUEST | ICMPV6_ECHO_REPLY => {
            // Echo: length preserved, only type/code change.
            let out = dst.get_mut(..src.len())?;
            out.copy_from_slice(src);
            out[0] = if icmpv6_type == ICMPV6_ECHO_REQUEST {
                ICMP_ECHO_REQUEST
            } else {
                ICMP_ECHO_REPLY
            };
            out[1] = 0;
            finalize_icmpv4_checksum(out);
            Some(out.len())
        }
        ICMPV6_PACKET_TOO_BIG => {
            // An ICMP error always carries the full 8-byte header (type/code/
            // checksum + the 4-byte rest-of-header). `src` is packet data, so
            // reject a truncated header before indexing the MTU word.
            if src.len() < 8 {
                return None;
            }
            // RFC 7915 5.2: ICMPv6 Packet Too Big (type 2) -> ICMPv4
            // Destination Unreachable / Fragmentation Needed (type 3 code 4).
            // The 4-byte "unused" word of an ICMPv6 PTB carries the MTU; the
            // ICMPv4 Fragmentation-Needed instead carries the Next-Hop MTU in
            // its low 16 bits (bytes 6-7), with bytes 4-5 unused (RFC 1191).
            let mtu = u32::from_be_bytes([src[4], src[5], src[6], src[7]]);
            // The translated v4 datagram is 20 bytes smaller than the v6 one, so
            // advertise an MTU 20 bytes smaller (clamped to a sane 16-bit range
            // and never below the v4 minimum). RFC 7915 5.2.
            let v4_mtu = mtu.saturating_sub(NAT64_HEADER_DELTA).clamp(68, 0xffff) as u16;
            write_icmpv4_error_with_embedded(
                dst,
                src,
                ICMP_DEST_UNREACHABLE,
                4,
                [0, 0, (v4_mtu >> 8) as u8, v4_mtu as u8],
                embedded,
            )
        }
        ICMPV6_DEST_UNREACHABLE | ICMPV6_TIME_EXCEEDED | ICMPV6_PARAMETER_PROBLEM => {
            let (v4_type, v4_code) = map_icmpv6_error_to_icmpv4(icmpv6_type, icmpv6_code)?;
            // RFC 7915 5.2: the 4-byte rest-of-header is ZEROED for these
            // types. Time-Exceeded / Dest-Unreach carry an unused word (zero
            // is correct on the wire). The ICMPv6 Parameter-Problem pointer is
            // intentionally NOT remapped to an ICMPv4 pointer (see
            // map_icmpv6_error_to_icmpv4), so it is dropped to zero rather than
            // translated.
            write_icmpv4_error_with_embedded(
                dst, src, v4_type, v4_code, [0, 0, 0, 0], embedded,
            )
        }
        _ => None, // NDP, MLD, etc. — never crosses the translator.
    }
}

/// Translate a complete ICMPv4 message (`src`, starting at the ICMPv4 type
/// byte) into ICMPv6 in `dst`, returning the written ICMPv6 message length.
///
/// The v6->v4 twin of [`translate_icmpv6_message_to_icmpv4`]; same contract.
/// The ICMPv6 checksum is NOT computed here (it needs the IPv6 pseudo-header):
/// the caller's `recompute_l4_checksum_after_nat64_v4_to_v6` finishes it over
/// the full message, so this leaves the checksum field zeroed.
fn translate_icmpv4_message_to_icmpv6(
    dst: &mut [u8],
    src: &[u8],
    embedded: &EmbeddedV4ToV6,
) -> Option<usize> {
    if src.len() < 4 {
        return None;
    }
    let icmpv4_type = src[0];
    let icmpv4_code = src[1];

    match icmpv4_type {
        ICMP_ECHO_REQUEST | ICMP_ECHO_REPLY => {
            let out = dst.get_mut(..src.len())?;
            out.copy_from_slice(src);
            out[0] = if icmpv4_type == ICMP_ECHO_REQUEST {
                ICMPV6_ECHO_REQUEST
            } else {
                ICMPV6_ECHO_REPLY
            };
            out[1] = 0;
            // Checksum is recomputed by the caller (needs the v6 pseudo-header).
            out[2..4].copy_from_slice(&[0, 0]);
            Some(out.len())
        }
        ICMP_DEST_UNREACHABLE if icmpv4_code == 4 => {
            // An ICMP error always carries the full 8-byte header; reject a
            // truncated header before indexing the Next-Hop MTU word.
            if src.len() < 8 {
                return None;
            }
            // RFC 7915 4.2: ICMPv4 Fragmentation Needed (type 3 code 4) ->
            // ICMPv6 Packet Too Big (type 2). The Next-Hop MTU is in the low
            // 16 bits (bytes 6-7) of the ICMPv4 rest-of-header (RFC 1191); the
            // ICMPv6 PTB carries the MTU as a full 32-bit word (bytes 4-7).
            let v4_mtu = u16::from_be_bytes([src[6], src[7]]) as u32;
            // The translated v6 datagram is 20 bytes larger than the v4 one, so
            // the v6 path MTU is 20 bytes larger; clamp to the v6 minimum link
            // MTU (1280) so a v6 client is never told to go below it.
            let v6_mtu = v4_mtu.saturating_add(NAT64_HEADER_DELTA).max(IPV6_MIN_MTU);
            write_icmpv6_error_with_embedded(
                dst,
                src,
                ICMPV6_PACKET_TOO_BIG,
                0,
                v6_mtu.to_be_bytes(),
                embedded,
            )
        }
        ICMP_DEST_UNREACHABLE | ICMP_TIME_EXCEEDED | ICMP_PARAMETER_PROBLEM => {
            let (v6_type, v6_code) = map_icmpv4_error_to_icmpv6(icmpv4_type, icmpv4_code)?;
            write_icmpv6_error_with_embedded(
                dst, src, v6_type, v6_code, [0, 0, 0, 0], embedded,
            )
        }
        _ => None,
    }
}

/// Build an ICMPv4 error message (8-byte header + translated embedded packet)
/// in `dst` from the ICMPv6 error `src`. `rest_of_header` is the 4-byte word
/// after type/code/checksum. Returns the written length, or `None` on a
/// malformed/oversized embedded packet.
fn write_icmpv4_error_with_embedded(
    dst: &mut [u8],
    src: &[u8],
    v4_type: u8,
    v4_code: u8,
    rest_of_header: [u8; 4],
    embedded: &EmbeddedV6ToV4,
) -> Option<usize> {
    // The quoted original packet starts after the 8-byte ICMPv6 error header.
    let embedded_in = src.get(8..)?;
    // Translate the embedded IPv6 header (+leading L4) into a stack scratch
    // buffer — no heap alloc on the hot path (#2211).
    let mut scratch = [0u8; MAX_EMBEDDED_LEN];
    let embedded_len = translate_embedded_v6_to_v4(&mut scratch, embedded_in, embedded)?;

    let total = 8 + embedded_len;
    let out = dst.get_mut(..total)?;
    out[0] = v4_type;
    out[1] = v4_code;
    out[2..4].copy_from_slice(&[0, 0]); // checksum (computed below)
    out[4..8].copy_from_slice(&rest_of_header);
    out[8..total].copy_from_slice(&scratch[..embedded_len]);
    finalize_icmpv4_checksum(out);
    Some(total)
}

/// Build an ICMPv6 error message (8-byte header + translated embedded packet)
/// in `dst` from the ICMPv4 error `src`. The ICMPv6 checksum is left zeroed —
/// the caller recomputes it with the IPv6 pseudo-header.
fn write_icmpv6_error_with_embedded(
    dst: &mut [u8],
    src: &[u8],
    v6_type: u8,
    v6_code: u8,
    rest_of_header: [u8; 4],
    embedded: &EmbeddedV4ToV6,
) -> Option<usize> {
    let embedded_in = src.get(8..)?;
    let mut scratch = [0u8; MAX_EMBEDDED_LEN];
    let embedded_len = translate_embedded_v4_to_v6(&mut scratch, embedded_in, embedded)?;

    let total = 8 + embedded_len;
    let out = dst.get_mut(..total)?;
    out[0] = v6_type;
    out[1] = v6_code;
    out[2..4].copy_from_slice(&[0, 0]); // checksum recomputed by caller
    out[4..8].copy_from_slice(&rest_of_header);
    out[8..total].copy_from_slice(&scratch[..embedded_len]);
    Some(total)
}

/// Translate the embedded (quoted) IPv6 header + leading L4 bytes of an ICMPv6
/// error into IPv4, writing into `dst` and returning the written length.
///
/// RFC 7915 §5.2: the embedded packet is translated like a normal v6->v4 packet
/// but with the embedded addresses' pre-computed mappings. The embedded L4 is
/// quoted (often truncated to 8 bytes), so its own checksum is left unchanged —
/// it is informational and a receiver does not validate the quoted L4 checksum.
/// The embedded packet is bounded to `MAX_EMBEDDED_LEN`; an oversized or
/// truncated-below-the-IPv6-header quote returns `None`.
fn translate_embedded_v6_to_v4(
    dst: &mut [u8],
    embedded: &[u8],
    map: &EmbeddedV6ToV4,
) -> Option<usize> {
    if embedded.len() < 40 {
        return None; // need a full IPv6 header to translate
    }
    // Clamp the quoted bytes to the scratch capacity (a hostile or large quote
    // must not overflow the fixed buffer); a clamp shortens the quote, which is
    // always legal for an ICMP error.
    let quote_in = &embedded[..embedded.len().min(MAX_EMBEDDED_LEN)];

    let payload_len = u16::from_be_bytes([quote_in[4], quote_in[5]]) as usize;
    let hop_limit = quote_in[7];
    let traffic_class = ((quote_in[0] & 0x0f) << 4) | (quote_in[1] >> 4);

    // #2290: walk the quoted IPv6 packet's extension-header chain to find the
    // terminal L4 offset/protocol rather than assuming L4 at byte 40. The
    // quote is frequently truncated (often to 8 bytes of L4), so the walk may
    // run off the end of `quote_in`; in that case `ipv6_l4_offset_and_protocol`
    // returns `None` and we fail closed — the same drop the outer translator
    // takes — rather than misreading ext-header bytes as a transport header.
    let (l4_offset, l4_protocol) = ipv6_l4_offset_and_protocol(quote_in)?;

    // A non-first fragment carries no L4 header — its bytes are payload. Do
    // not read them as L4 (drop), matching the outer translator (#2290).
    if ipv6_is_non_first_fragment(quote_in) {
        return None;
    }

    // Map protocol (same set the outer translator supports) from the terminal
    // L4. An embedded packet carrying an unsupported protocol can't be
    // faithfully translated -> drop.
    let ipv4_protocol = match l4_protocol {
        PROTO_ICMPV6 => PROTO_ICMP,
        PROTO_TCP | PROTO_UDP => l4_protocol,
        _ => return None,
    };

    // The quoted L4 starts at the walked offset and runs to the end of the
    // advertised IPv6 payload (`40 + payload_len`), capped by the bytes
    // actually quoted. The IPv6 extension headers between byte 40 and
    // `l4_offset` are stripped, mirroring the outer translation.
    let payload_end = 40usize.checked_add(payload_len)?;
    let quoted_end = payload_end.min(quote_in.len());
    if l4_offset > quoted_end {
        return None; // ext-header chain overran the quoted bytes
    }
    let l4 = quote_in.get(l4_offset..quoted_end)?;
    let l4_len = l4.len();

    let total = 20 + l4_len;
    let out = dst.get_mut(..total)?;
    out[0] = 0x45;
    out[1] = traffic_class;
    out[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    out[4..6].copy_from_slice(&[0, 0]); // identification (quoted header)
    out[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF
    out[8] = hop_limit; // embedded hop limit copied verbatim (NOT decremented)
    out[9] = ipv4_protocol;
    out[10..12].copy_from_slice(&[0, 0]); // header checksum (computed below)
    out[12..16].copy_from_slice(&map.mapped_embedded_src.octets());
    out[16..20].copy_from_slice(&map.mapped_embedded_dst.octets());
    out[20..total].copy_from_slice(l4);

    // #6472: restore the quoted L4 destination port / echo identifier to the
    // TRANSLATED (pool) value the v4 server replied to. The quoted L4
    // checksum is intentionally left unchanged — it is informational and a
    // receiver does not validate it (the outer ICMP checksum below covers
    // these bytes). A truncated quote (< the port/id bytes) skips the
    // rewrite, exactly like the non-matching-protocol case.
    if let Some(port) = map.mapped_embedded_dst_port {
        if matches!(l4_protocol, PROTO_TCP | PROTO_UDP) && l4_len >= 4 {
            out[22..24].copy_from_slice(&port.to_be_bytes());
        } else if l4_protocol == PROTO_ICMPV6 && l4_len >= 6 {
            out[24..26].copy_from_slice(&port.to_be_bytes());
        }
    }

    // If the embedded protocol is ICMPv6, fix the embedded ICMP type byte so the
    // quoted v4 packet is internally consistent (the quoted L4 checksum is left
    // as-is — it is not validated by a receiver). Only the leading type/code are
    // touched; a fuller embedded-ICMP translation is unnecessary for the quote.
    if l4_protocol == PROTO_ICMPV6 && l4_len >= 2 {
        if let Some((t, c)) = embedded_icmpv6_type_to_icmpv4(out[20]) {
            out[20] = t;
            out[21] = c;
        }
    }

    let hdr_sum = checksum16(&out[..20]);
    out[10..12].copy_from_slice(&hdr_sum.to_be_bytes());
    Some(total)
}

/// Translate the embedded (quoted) IPv4 header + leading L4 bytes of an ICMPv4
/// error into IPv6, writing into `dst` and returning the written length. The
/// v6->v4 twin of [`translate_embedded_v6_to_v4`]; same quote/checksum policy.
fn translate_embedded_v4_to_v6(
    dst: &mut [u8],
    embedded: &[u8],
    map: &EmbeddedV4ToV6,
) -> Option<usize> {
    if embedded.len() < 20 {
        return None;
    }
    let ihl = ((embedded[0] & 0x0f) as usize) * 4;
    if ihl < 20 || embedded.len() < ihl {
        return None;
    }
    let quote_in = &embedded[..embedded.len().min(MAX_EMBEDDED_LEN - NAT64_HEADER_DELTA as usize)];
    let tos = quote_in[1];
    let ttl = quote_in[8];
    let protocol = quote_in[9];
    let total_len_field = u16::from_be_bytes([quote_in[2], quote_in[3]]) as usize;

    let next_header = match protocol {
        PROTO_ICMP => PROTO_ICMPV6,
        PROTO_TCP | PROTO_UDP => protocol,
        _ => return None,
    };

    // Quoted L4 bytes after the IPv4 header, capped by the advertised total
    // length and what was actually quoted.
    let end = total_len_field.clamp(ihl, quote_in.len());
    let l4 = quote_in.get(ihl..end)?;
    let l4_len = l4.len();

    let total = 40 + l4_len;
    let out = dst.get_mut(..total)?;
    out[0] = 0x60 | (tos >> 4);
    out[1] = (tos & 0x0f) << 4;
    out[2] = 0;
    out[3] = 0;
    out[4..6].copy_from_slice(&(l4_len as u16).to_be_bytes());
    out[6] = next_header;
    out[7] = ttl; // embedded hop limit copied verbatim (NOT decremented)
    // Embedded src (our SNAT pool v4) -> original v6 client.
    out[8..24].copy_from_slice(&map.mapped_embedded_src.octets());
    // Embedded dst (the v4 server) -> NAT64 prefix :: dst-v4.
    out[24..36].copy_from_slice(&map.prefix_bytes);
    out[36..40].copy_from_slice(&quote_in[16..20]);
    out[40..total].copy_from_slice(l4);

    // #6472: restore the quoted L4 source port / echo identifier to the
    // ORIGINAL v6 client value. The quote carries the TRANSLATED (pool)
    // source value; the client only associates the error with its session
    // when the quote reads back as the original tuple it sent. The quoted
    // L4 checksum is left unchanged (informational — same policy as the
    // address rewrite above); the outer ICMPv6 checksum recompute covers
    // these bytes. A truncated quote skips the rewrite.
    if let Some(port) = map.mapped_embedded_src_port {
        if matches!(protocol, PROTO_TCP | PROTO_UDP) && l4_len >= 2 {
            out[40..42].copy_from_slice(&port.to_be_bytes());
        } else if protocol == PROTO_ICMP && l4_len >= 6 {
            out[44..46].copy_from_slice(&port.to_be_bytes());
        }
    }

    if protocol == PROTO_ICMP && l4_len >= 2 {
        if let Some((t, c)) = embedded_icmpv4_type_to_icmpv6(out[40]) {
            out[40] = t;
            out[41] = c;
        }
    }
    Some(total)
}

/// Best-effort embedded ICMPv6->ICMPv4 type/code remap for the quoted L4 of an
/// embedded packet (echo only, which is the realistic embedded-ICMP case for a
/// PMTUD/traceroute error quoting a ping). Returns `None` to leave the byte
/// untouched for anything else — the quoted L4 is informational.
fn embedded_icmpv6_type_to_icmpv4(t: u8) -> Option<(u8, u8)> {
    match t {
        ICMPV6_ECHO_REQUEST => Some((ICMP_ECHO_REQUEST, 0)),
        ICMPV6_ECHO_REPLY => Some((ICMP_ECHO_REPLY, 0)),
        _ => None,
    }
}

/// Best-effort embedded ICMPv4->ICMPv6 type/code remap (echo only); twin of
/// [`embedded_icmpv6_type_to_icmpv4`].
fn embedded_icmpv4_type_to_icmpv6(t: u8) -> Option<(u8, u8)> {
    match t {
        ICMP_ECHO_REQUEST => Some((ICMPV6_ECHO_REQUEST, 0)),
        ICMP_ECHO_REPLY => Some((ICMPV6_ECHO_REPLY, 0)),
        _ => None,
    }
}

/// Zero then recompute the ICMPv4 checksum (no pseudo-header) over `icmp`.
fn finalize_icmpv4_checksum(icmp: &mut [u8]) {
    if icmp.len() < 4 {
        return;
    }
    icmp[2..4].copy_from_slice(&[0, 0]);
    let sum = checksum16(icmp);
    icmp[2..4].copy_from_slice(&sum.to_be_bytes());
}

/// Recompute L4 checksum after IPv6→IPv4 translation.
fn recompute_l4_checksum_after_nat64_v6_to_v4(packet: &mut [u8], protocol: u8) -> Option<()> {
    if packet.len() < 20 {
        return None;
    }
    // Read IP addresses before taking mutable borrow of L4 portion.
    let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let l4 = &mut packet[20..];
    match protocol {
        PROTO_TCP => {
            if l4.len() < 20 {
                return None;
            }
            l4[16..18].copy_from_slice(&[0, 0]);
            let sum = checksum16_ipv4_pseudo(src, dst, protocol, l4);
            l4[16..18].copy_from_slice(&sum.to_be_bytes());
        }
        PROTO_UDP => {
            if l4.len() < 8 {
                return None;
            }
            l4[6..8].copy_from_slice(&[0, 0]);
            let sum = checksum16_ipv4_pseudo(src, dst, protocol, l4);
            // RFC 768 / RFC 1624: in IPv4 UDP a checksum field of 0x0000 is the
            // reserved "no checksum present" sentinel. A genuinely computed
            // checksum of zero MUST be transmitted as 0xFFFF (all-ones) so the
            // receiver still validates it. `checksum16_ipv4_pseudo` returns the
            // final one's-complement value, so a 0x0000 here is a real computed
            // checksum, not an internal sentinel. Mirrors the v4->v6 UDP arm.
            let final_sum = if sum == 0 { 0xFFFF } else { sum };
            l4[6..8].copy_from_slice(&final_sum.to_be_bytes());
        }
        PROTO_ICMP => {
            if l4.len() < 4 {
                return None;
            }
            // ICMPv4 does NOT use pseudo-header — checksum over ICMP message only.
            l4[2..4].copy_from_slice(&[0, 0]);
            let sum = checksum16(l4);
            l4[2..4].copy_from_slice(&sum.to_be_bytes());
        }
        _ => {}
    }
    Some(())
}

/// Recompute L4 checksum after IPv4→IPv6 translation.
fn recompute_l4_checksum_after_nat64_v4_to_v6(packet: &mut [u8], next_header: u8) -> Option<()> {
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(packet.get(8..24)?).ok()?);
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(packet.get(24..40)?).ok()?);
    let l4 = &mut packet[40..];
    match next_header {
        PROTO_TCP => {
            if l4.len() < 20 {
                return None;
            }
            l4[16..18].copy_from_slice(&[0, 0]);
            let sum = checksum16_ipv6_pseudo(src, dst, next_header, l4);
            l4[16..18].copy_from_slice(&sum.to_be_bytes());
        }
        PROTO_UDP => {
            if l4.len() < 8 {
                return None;
            }
            l4[6..8].copy_from_slice(&[0, 0]);
            let sum = checksum16_ipv6_pseudo(src, dst, next_header, l4);
            // UDP over IPv6: zero checksum is illegal, but if it computes to 0
            // the standard says use 0xFFFF.
            let final_sum = if sum == 0 { 0xFFFF } else { sum };
            l4[6..8].copy_from_slice(&final_sum.to_be_bytes());
        }
        PROTO_ICMPV6 => {
            if l4.len() < 4 {
                return None;
            }
            // ICMPv6 DOES use pseudo-header.
            l4[2..4].copy_from_slice(&[0, 0]);
            let sum = checksum16_ipv6_pseudo(src, dst, next_header, l4);
            l4[2..4].copy_from_slice(&sum.to_be_bytes());
        }
        _ => {}
    }
    Some(())
}

// ---------------------------------------------------------------------------
// Checksum helpers
// ---------------------------------------------------------------------------

fn checksum16(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let Some(&last) = chunks.remainder().first() {
        sum += (last as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Add `bytes` into a running one's-complement 16-bit partial sum. Mirrors
/// the scalar reference in `afxdp/frame/checksum.rs::checksum16_add_bytes`
/// so the pseudo-header checksum can be accumulated by streaming the
/// pseudo-header fields and the L4 payload directly, with NO intermediate
/// `Vec` allocation per packet (#2211). The fold result is bit-identical to
/// building a contiguous buffer and running `checksum16` over it because
/// 16-bit one's-complement addition is associative across the concatenation.
#[inline]
fn checksum16_add(mut sum: u32, bytes: &[u8]) -> u32 {
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum = sum.wrapping_add(u16::from_be_bytes([chunk[0], chunk[1]]) as u32);
    }
    if let Some(&last) = chunks.remainder().first() {
        sum = sum.wrapping_add((last as u32) << 8);
    }
    sum
}

/// Fold a running partial sum into the final one's-complement 16-bit value.
/// Identical fold to `checksum16`'s tail so streaming and buffer-building
/// produce the same checksum.
#[inline]
fn checksum16_fold(mut sum: u32) -> u16 {
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// IPv4 pseudo-header + L4 checksum, streamed (no per-packet `Vec`, #2211).
fn checksum16_ipv4_pseudo(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, payload: &[u8]) -> u16 {
    let mut sum = 0u32;
    sum = checksum16_add(sum, &src.octets());
    sum = checksum16_add(sum, &dst.octets());
    sum = checksum16_add(sum, &[0, protocol]);
    sum = checksum16_add(sum, &(payload.len() as u16).to_be_bytes());
    sum = checksum16_add(sum, payload);
    checksum16_fold(sum)
}

/// IPv6 pseudo-header + L4 checksum, streamed (no per-packet `Vec`, #2211).
fn checksum16_ipv6_pseudo(src: Ipv6Addr, dst: Ipv6Addr, next_header: u8, payload: &[u8]) -> u16 {
    let mut sum = 0u32;
    sum = checksum16_add(sum, &src.octets());
    sum = checksum16_add(sum, &dst.octets());
    sum = checksum16_add(sum, &(payload.len() as u32).to_be_bytes());
    sum = checksum16_add(sum, &[0, 0, 0, next_header]);
    sum = checksum16_add(sum, payload);
    checksum16_fold(sum)
}

/// Incremental one's-complement checksum update (RFC 1624 eqn 3): given an
/// existing checksum `old_cksum` and a set of 16-bit words that changed from
/// `old_bytes` to `new_bytes`, return the new checksum WITHOUT re-summing the
/// rest of the protected data. Used for translated TCP/UDP FRAGMENTs (#2488)
/// where the transport payload is incomplete and only the IP pseudo-header
/// addresses differ between the v4 and v6 forms. `old_bytes` / `new_bytes` are
/// big-endian and may be any (even) length; a trailing odd byte is padded with
/// zero, matching the standard checksum word split.
fn checksum16_incremental(old_cksum: u16, old_bytes: &[u8], new_bytes: &[u8]) -> u16 {
    // HC' = ~( ~HC + sum(~m_i) + sum(m'_i) )
    let mut sum: u32 = u32::from(!old_cksum);
    for w in old_bytes.chunks(2) {
        let val = u16::from_be_bytes([w[0], *w.get(1).unwrap_or(&0)]);
        sum += u32::from(!val);
    }
    for w in new_bytes.chunks(2) {
        let val = u16::from_be_bytes([w[0], *w.get(1).unwrap_or(&0)]);
        sum += u32::from(val);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Adjust a translated v6→v4 TCP/UDP L4 checksum for the pseudo-header address
/// change only (RFC 1624 incremental). The L4 header at `out[20..]` was copied
/// verbatim and still holds the IPv6-pseudo-header checksum; fold the 32-byte v6
/// address pair out and the 8-byte v4 address pair in. The L4 length and
/// protocol number are identical across the translation so they cancel.
///
/// Used for BOTH the #2488 FRAGMENT path (where the transport payload is
/// incomplete and a full recompute is impossible) AND the #3025 non-fragment
/// fast path (where the payload IS present but only the pseudo-header changed, so
/// the O(1) adjustment is byte-identical to a full recompute over the whole
/// payload — one's-complement addition is exact, RFC 1624 §3). The caller must
/// only invoke this when the verbatim L4 checksum is a trustworthy baseline: for
/// non-fragment UDP a zero baseline means "no checksum present" on the v6 input
/// (illegal, but defended against) and must take the full recompute instead.
fn adjust_l4_checksum_v6_to_v4_incremental(
    out: &mut [u8],
    protocol: u8,
    v6_src_dst: &[u8; 32],
    v4_src: Ipv4Addr,
    v4_dst: Ipv4Addr,
) -> Option<()> {
    let field = match protocol {
        PROTO_TCP => 16usize,
        PROTO_UDP => 6,
        _ => return Some(()),
    };
    let l4 = out.get_mut(20..)?;
    let cksum = l4.get(field..field + 2)?;
    let old = u16::from_be_bytes([cksum[0], cksum[1]]);
    let mut v4_addrs = [0u8; 8];
    v4_addrs[..4].copy_from_slice(&v4_src.octets());
    v4_addrs[4..].copy_from_slice(&v4_dst.octets());
    let updated = checksum16_incremental(old, v6_src_dst, &v4_addrs);
    // RFC 768: a computed UDP checksum of 0x0000 is transmitted as 0xFFFF.
    let final_sum = if protocol == PROTO_UDP && updated == 0 {
        0xFFFF
    } else {
        updated
    };
    l4[field..field + 2].copy_from_slice(&final_sum.to_be_bytes());
    Some(())
}

/// Adjust a translated v4→v6 TCP/UDP L4 checksum for the pseudo-header address
/// change only (RFC 1624 incremental). The L4 header sits at `dst[l4_off..]`
/// (past any inserted IPv6 Fragment Header) and still holds the
/// IPv4-pseudo-header checksum; fold the 8-byte v4 address pair out and the
/// 32-byte v6 address pair in.
///
/// Used for BOTH the #2488 FRAGMENT path AND the #3025 non-fragment fast path
/// (byte-identical to a full recompute; see the v6→v4 twin). The caller must
/// only invoke this when the verbatim IPv4 L4 checksum is a trustworthy
/// baseline: an IPv4 UDP checksum of 0 means "no checksum present" (RFC 768), so
/// there is no baseline to adjust and — because IPv6 UDP mandates a checksum —
/// that case MUST take the full recompute to GENERATE one. (A zero IPv4 UDP
/// checksum was already rejected upstream for a fragment, so on the fragment
/// path `old` is non-zero here.)
fn adjust_l4_checksum_v4_to_v6_incremental(
    dst: &mut [u8],
    next_header: u8,
    l4_off: usize,
    v4_src_dst: &[u8; 8],
    v6_src_dst: &[u8; 32],
) -> Option<()> {
    let field = match next_header {
        PROTO_TCP => 16usize,
        PROTO_UDP => 6,
        _ => return Some(()),
    };
    let l4 = dst.get_mut(l4_off..)?;
    let cksum = l4.get(field..field + 2)?;
    let old = u16::from_be_bytes([cksum[0], cksum[1]]);
    let updated = checksum16_incremental(old, v4_src_dst, v6_src_dst);
    // UDP over IPv6: a zero checksum is illegal, so a computed 0x0000 is written
    // as 0xFFFF. (Both callers guarantee a non-zero `old`: the fragment path
    // rejects a zero IPv4 UDP checksum upstream, and the #3025 non-fragment path
    // routes a zero baseline to the full recompute instead.)
    let final_sum = if next_header == PROTO_UDP && updated == 0 {
        0xFFFF
    } else {
        updated
    };
    l4[field..field + 2].copy_from_slice(&final_sum.to_be_bytes());
    Some(())
}

// ---------------------------------------------------------------------------
// Frame building helpers for NAT64
// ---------------------------------------------------------------------------

/// #2562: translate a NON-first IPv6 fragment to IPv4, L3-only.
///
/// A non-first fragment (Fragment Header present, offset > 0) has NO L4 header —
/// every byte after the Fragment Header is opaque payload. This is the sibling
/// of [`write_v6_to_v4_into`] for that case: it does NOT parse or checksum an L4
/// header (there is none). It strips the IPv6 base + extension + Fragment
/// headers, emits a 20-byte IPv4 header whose fragmentation fields are copied
/// from the IPv6 Fragment Header (DF=0, MF from the M flag, the 13-bit offset
/// verbatim in 8-byte units, and **IPv4 Identification = the low 16 bits of the
/// IPv6 32-bit Identification** — the SAME truncation the first fragment used,
/// which is load-bearing for reassembly at the receiver), copies the payload
/// verbatim, and recomputes ONLY the IPv4 header checksum.
///
/// The `snat_v4`/`dst_v4` come from the FIRST fragment's cached association
/// (`Nat64FragAssoc`), so all fragments translate to the same source and
/// reassemble. Fragmented ICMPv6 is NOT handled here (the ICMP checksum covers
/// the whole datagram and cannot be recomputed from a fragment) — it stays the
/// #4617 fail-closed drop, so only TCP/UDP are accepted.
pub(crate) fn write_v6_to_v4_nonfirst_into(
    dst: &mut [u8],
    packet: &[u8],
    snat_v4: Ipv4Addr,
    dst_v4: Ipv4Addr,
) -> Option<usize> {
    if packet.len() < 40 {
        return None;
    }
    // #5625: RFC 7915 §5.1 translation-eligibility gate — same reject as the
    // first-fragment/atomic translator. A fragmented datagram whose
    // unfragmentable part carries an ACTIVE Routing header (SL > 0), or whose
    // Fragment Header's Next Header names AH / Mobility / HIP / Shim6, is not
    // safely translatable v6→v4; drop fail-closed rather than strip.
    if nat64_v6_translation_ineligible(packet) {
        return None;
    }
    let traffic_class = ((packet[0] & 0x0f) << 4) | (packet[1] >> 4);
    let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let hop_limit = packet[7];
    if hop_limit <= 1 {
        return None; // TTL expired
    }
    // `ipv6_l4_offset_and_protocol` walks the chain and, for a non-first
    // fragment, returns the offset of the byte AFTER the Fragment Header (where
    // the opaque payload starts) and the Fragment Header's Next Header (the real
    // upper-layer protocol) — exactly what we need.
    let (payload_off, l4_protocol) = ipv6_l4_offset_and_protocol(packet)?;
    let frag = ipv6_fragment_header(packet)?;
    if frag.offset_units == 0 {
        return None; // not a non-first fragment — caller must use the first path
    }
    // TCP/UDP only. ICMPv6 fragments stay the #4617 fail-closed drop.
    let ipv4_protocol = match l4_protocol {
        PROTO_TCP | PROTO_UDP => l4_protocol,
        _ => return None,
    };
    let l4_end = 40usize.checked_add(payload_len)?;
    if payload_off > l4_end {
        return None; // ext-header chain overran the advertised payload
    }
    let payload = packet.get(payload_off..l4_end)?;
    let total_len = 20usize.checked_add(payload.len())?;
    let out = dst.get_mut(..total_len)?;
    out[0] = 0x45; // version=4, IHL=5
    out[1] = traffic_class;
    out[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    let ident = (frag.ident & 0xFFFF) as u16;
    out[4..6].copy_from_slice(&ident.to_be_bytes());
    let mf = if frag.more { 0x2000u16 } else { 0 };
    let frag_word = mf | (frag.offset_units & 0x1FFF);
    out[6..8].copy_from_slice(&frag_word.to_be_bytes());
    out[8] = hop_limit - 1;
    out[9] = ipv4_protocol;
    out[10..12].copy_from_slice(&[0, 0]); // header checksum (computed below)
    out[12..16].copy_from_slice(&snat_v4.octets());
    out[16..20].copy_from_slice(&dst_v4.octets());
    out[20..total_len].copy_from_slice(payload);
    let hdr_sum = checksum16(&out[..20]);
    out[10..12].copy_from_slice(&hdr_sum.to_be_bytes());
    Some(total_len)
}

/// #2562: translate a NON-first IPv4 fragment to IPv6, L3-only.
///
/// Sibling of [`write_v4_to_v6_into`] for a non-first IPv4 fragment (offset > 0,
/// no L4 header). Emits a 40-byte IPv6 header + an 8-byte Fragment Header whose
/// M flag / 13-bit offset are copied from the IPv4 fragmentation word and whose
/// **32-bit Identification is the IPv4 16-bit Identification zero-extended** (the
/// SAME extension the first fragment used), copies the payload verbatim, and
/// touches NO L4 checksum (there is no L4 header). `src_v6`/`dst_v6` come from
/// the first fragment's cached reverse association. TCP/UDP only — a fragmented
/// ICMP stays the #4617 fail-closed drop.
pub(crate) fn write_v4_to_v6_nonfirst_into(
    dst: &mut [u8],
    packet: &[u8],
    src_v6: Ipv6Addr,
    dst_v6: Ipv6Addr,
) -> Option<usize> {
    if packet.len() < 20 {
        return None;
    }
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    if ihl < 20 || packet.len() < ihl {
        return None;
    }
    let tos = packet[1];
    let ttl = packet[8];
    if ttl <= 1 {
        return None; // TTL expired
    }
    let protocol = packet[9];
    let ipv4_total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if ipv4_total_len < ihl || ipv4_total_len > packet.len() {
        return None;
    }
    let payload = packet.get(ihl..ipv4_total_len)?;
    let frag_word = u16::from_be_bytes([packet[6], packet[7]]);
    let more = (frag_word & 0x2000) != 0;
    let offset_units = frag_word & 0x1FFF;
    if offset_units == 0 {
        return None; // not a non-first fragment — caller must use the first path
    }
    // TCP/UDP only. ICMP fragments stay the #4617 fail-closed drop.
    let next_header = match protocol {
        PROTO_TCP | PROTO_UDP => protocol,
        _ => return None,
    };
    let v4_ident = u16::from_be_bytes([packet[4], packet[5]]);
    let ipv6_payload_len = 8usize.checked_add(payload.len())?;
    let total_len = 40usize.checked_add(ipv6_payload_len)?;
    let out = dst.get_mut(..total_len)?;
    out[0] = 0x60 | (tos >> 4); // version=6 | TC[7:4]
    out[1] = (tos & 0x0f) << 4; // TC[3:0] | flow-label high nibble (0)
    out[2] = 0; // flow label
    out[3] = 0; // flow label
    out[4..6].copy_from_slice(&(ipv6_payload_len as u16).to_be_bytes());
    out[6] = 44; // next header = Fragment
    out[7] = ttl - 1;
    out[8..24].copy_from_slice(&src_v6.octets());
    out[24..40].copy_from_slice(&dst_v6.octets());
    // 8-byte IPv6 Fragment Header (RFC 8200 §4.5).
    out[40] = next_header;
    out[41] = 0; // reserved
    let v6_frag_word = (offset_units << 3) | u16::from(more);
    out[42..44].copy_from_slice(&v6_frag_word.to_be_bytes());
    out[44..48].copy_from_slice(&u32::from(v4_ident).to_be_bytes());
    out[48..total_len].copy_from_slice(payload);
    Some(total_len)
}

/// #2562: Ethernet + IPv4 frame for a NON-first IPv6 fragment (forward NAT64).
/// Mirrors [`build_nat64_v6_to_v4_frame`] but calls the L3-only non-first
/// translator (no L4 header, no `no_v6_frag_header` policy — the fragmentation
/// fields come from the packet's Fragment Header).
pub(crate) fn build_nat64_v6_to_v4_nonfirst_frame(
    frame: &[u8],
    snat_v4: Ipv4Addr,
    dst_v4: Ipv4Addr,
    eth_dst: [u8; 6],
    eth_src: [u8; 6],
    vlan_id: u16,
) -> Option<Vec<u8>> {
    let l3 = frame_l3_offset(frame)?;
    let ipv6_packet = frame.get(l3..)?;
    let eth_len = if vlan_id > 0 { 18 } else { 14 };
    let mut out = vec![0u8; eth_len + ipv6_packet.len()];
    write_eth_header_slice(&mut out, eth_dst, eth_src, vlan_id, 0x0800)?;
    let written = write_v6_to_v4_nonfirst_into(&mut out[eth_len..], ipv6_packet, snat_v4, dst_v4)?;
    out.truncate(eth_len + written);
    Some(out)
}

/// #2562: Ethernet + IPv6 frame for a NON-first IPv4 fragment (reverse NAT64).
/// Mirrors [`build_nat64_v4_to_v6_frame`] but calls the L3-only non-first
/// translator. The IPv4->IPv6 non-first output grows by 28 bytes (40+8 IPv6
/// header vs 20 IPv4 header); the `2 * NAT64_HEADER_DELTA` over-allocation is a
/// safe upper bound (there is no ICMP-error embedded-packet growth on a
/// TCP/UDP fragment) and the result is truncated to the exact length.
pub(crate) fn build_nat64_v4_to_v6_nonfirst_frame(
    frame: &[u8],
    src_v6: Ipv6Addr,
    dst_v6: Ipv6Addr,
    eth_dst: [u8; 6],
    eth_src: [u8; 6],
    vlan_id: u16,
) -> Option<Vec<u8>> {
    let l3 = frame_l3_offset(frame)?;
    let ipv4_packet = frame.get(l3..)?;
    let eth_len = if vlan_id > 0 { 18 } else { 14 };
    let mut out =
        vec![0u8; eth_len + ipv4_packet.len().saturating_add(2 * NAT64_HEADER_DELTA as usize)];
    write_eth_header_slice(&mut out, eth_dst, eth_src, vlan_id, 0x86dd)?;
    let written = write_v4_to_v6_nonfirst_into(&mut out[eth_len..], ipv4_packet, src_v6, dst_v6)?;
    out.truncate(eth_len + written);
    Some(out)
}

/// Build a complete Ethernet + IPv4 frame from an Ethernet + IPv6 frame.
/// Used for forward NAT64 (IPv6→IPv4): frame shrinks by 20 bytes.
///
/// `eth_dst`, `eth_src` are the new L2 addresses for the forwarded frame.
/// `vlan_id` is inserted if > 0.
pub(crate) fn build_nat64_v6_to_v4_frame(
    frame: &[u8],
    snat_v4: Ipv4Addr,
    dst_v4: Ipv4Addr,
    eth_dst: [u8; 6],
    eth_src: [u8; 6],
    vlan_id: u16,
    no_v6_frag_header: bool,
) -> Option<Vec<u8>> {
    // Find L3 offset.
    let l3 = frame_l3_offset(frame)?;
    let ipv6_packet = frame.get(l3..)?;
    let eth_len = if vlan_id > 0 { 18 } else { 14 };
    // Single output allocation (the unavoidable `TxRequest.bytes`): IPv6→IPv4
    // shrinks the L3 by 20 bytes, so the IPv4 frame can never exceed
    // `eth_len + ipv6_packet.len()`. Allocate that upper bound, write the
    // translated IPv4 L3 directly into the tail with the allocation-free
    // `_into` core (no intermediate L3 `Vec`, no second copy — #2211), then
    // truncate to the exact length.
    let mut out = vec![0u8; eth_len + ipv6_packet.len()];
    // #2844: use the SSOT in-place Ethernet writer shared with gre.rs,
    // icmp.rs, and the TX segmentation path instead of a private copy,
    // so VLAN/TPID/PCP/ethertype changes propagate to NAT64 too.
    write_eth_header_slice(&mut out, eth_dst, eth_src, vlan_id, 0x0800)?;
    let written =
        write_v6_to_v4_into(&mut out[eth_len..], ipv6_packet, snat_v4, dst_v4, no_v6_frag_header)?;
    out.truncate(eth_len + written);
    Some(out)
}

/// Build a complete Ethernet + IPv6 frame from an Ethernet + IPv4 frame.
/// Used for reverse NAT64 (IPv4→IPv6): frame grows by 20 bytes.
///
/// `src_v6` and `dst_v6` are the restored IPv6 addresses.
pub(crate) fn build_nat64_v4_to_v6_frame(
    frame: &[u8],
    src_v6: Ipv6Addr,
    dst_v6: Ipv6Addr,
    eth_dst: [u8; 6],
    eth_src: [u8; 6],
    vlan_id: u16,
) -> Option<Vec<u8>> {
    let l3 = frame_l3_offset(frame)?;
    let ipv4_packet = frame.get(l3..)?;
    let eth_len = if vlan_id > 0 { 18 } else { 14 };
    // Single output allocation (the unavoidable `TxRequest.bytes`): IPv4→IPv6
    // grows the outer L3 header by 20 bytes (40-byte IPv6 header vs 20-byte IPv4
    // header). An ICMP-error message ALSO grows its embedded quoted packet by
    // another 20 bytes (#2219), so the worst-case IPv6 frame is
    // `eth_len + ipv4_packet.len() + 40`. Allocate that upper bound, write the
    // translated IPv6 L3 directly into the tail with the allocation-free `_into`
    // core (no intermediate L3 `Vec`, no second copy — #2211), then truncate to
    // the exact length.
    let mut out = vec![0u8; eth_len + ipv4_packet.len().saturating_add(2 * NAT64_HEADER_DELTA as usize)];
    // #2844: SSOT Ethernet writer (see build_nat64_v6_to_v4_frame).
    write_eth_header_slice(&mut out, eth_dst, eth_src, vlan_id, 0x86dd)?;
    let written = write_v4_to_v6_into(&mut out[eth_len..], ipv4_packet, src_v6, dst_v6)?;
    out.truncate(eth_len + written);
    Some(out)
}

/// #6472: Ethernet + IPv4 frame for a flowless NAT64 ICMPv6 error (an error
/// about the session's translated REPLY packet, v6→v4). Mirrors
/// [`build_nat64_v6_to_v4_frame`] but drives
/// [`write_v6_to_v4_icmp_error_into`] so the embedded quote's L4 destination
/// port / echo id is restored to the session's translated (pool) value —
/// the tuple the v4 server associates the error with.
pub(crate) fn build_nat64_v6_to_v4_icmp_error_frame(
    frame: &[u8],
    snat_v4: Ipv4Addr,
    dst_v4: Ipv4Addr,
    embedded_dst_port: Option<u16>,
    eth_dst: [u8; 6],
    eth_src: [u8; 6],
    vlan_id: u16,
    no_v6_frag_header: bool,
) -> Option<Vec<u8>> {
    let l3 = frame_l3_offset(frame)?;
    let ipv6_packet = frame.get(l3..)?;
    let eth_len = if vlan_id > 0 { 18 } else { 14 };
    // IPv6→IPv4 shrinks the L3 by 20 bytes, so `eth_len + ipv6_packet.len()`
    // is a safe upper bound even with the embedded-packet shrink.
    let mut out = vec![0u8; eth_len + ipv6_packet.len()];
    write_eth_header_slice(&mut out, eth_dst, eth_src, vlan_id, 0x0800)?;
    let written = write_v6_to_v4_icmp_error_into(
        &mut out[eth_len..],
        ipv6_packet,
        snat_v4,
        dst_v4,
        no_v6_frag_header,
        embedded_dst_port,
    )?;
    out.truncate(eth_len + written);
    Some(out)
}

/// #6472: Ethernet + IPv6 frame for a flowless NAT64 ICMPv4 error (an error
/// about the session's FORWARD wire packet, v4→v6). Mirrors
/// [`build_nat64_v4_to_v6_frame`] but drives
/// [`write_v4_to_v6_icmp_error_into`] so the embedded quote's L4 source
/// port / echo id is restored to the ORIGINAL v6 client value — the tuple
/// the client associates the error with.
pub(crate) fn build_nat64_v4_to_v6_icmp_error_frame(
    frame: &[u8],
    src_v6: Ipv6Addr,
    dst_v6: Ipv6Addr,
    embedded_src_port: Option<u16>,
    eth_dst: [u8; 6],
    eth_src: [u8; 6],
    vlan_id: u16,
) -> Option<Vec<u8>> {
    let l3 = frame_l3_offset(frame)?;
    let ipv4_packet = frame.get(l3..)?;
    let eth_len = if vlan_id > 0 { 18 } else { 14 };
    let mut out = vec![0u8; eth_len + ipv4_packet.len().saturating_add(2 * NAT64_HEADER_DELTA as usize)];
    write_eth_header_slice(&mut out, eth_dst, eth_src, vlan_id, 0x86dd)?;
    let written = write_v4_to_v6_icmp_error_into(
        &mut out[eth_len..],
        ipv4_packet,
        src_v6,
        dst_v6,
        embedded_src_port,
    )?;
    out.truncate(eth_len + written);
    Some(out)
}

/// Find the L3 offset by checking Ethernet type/VLAN.
///
/// #2150: a single 0x88a8 (802.1ad) tag carries the same 4-byte
/// TPID+TCI layout as 0x8100, so the L3 header sits at offset 18, not
/// 14. The previous `== 0x8100` check treated a 0x88a8-tagged frame as
/// untagged (l3=14) and read the IP header 4 bytes into the VLAN tag,
/// corrupting any NAT64 translation of a provider-tagged frame. This
/// now matches the canonical L2 contract
/// (`afxdp/frame/inspect.rs::frame_l3_offset`,
/// `afxdp/cos/ecn.rs::ethernet_l3`, `afxdp/parser.rs::parse_eth_offsets`).
fn frame_l3_offset(frame: &[u8]) -> Option<usize> {
    if frame.len() < 14 {
        return None;
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    if matches!(ethertype, 0x8100 | 0x88a8) {
        if frame.len() < 18 {
            return None;
        }
        Some(18)
    } else {
        Some(14)
    }
}

// #2844: NAT64's private `write_eth_header` (hardcoded 0x8100 TPID,
// bare-VID semantics) was deleted. The frame builders above now call
// the shared SSOT `crate::afxdp::write_eth_header_slice`, the same
// in-place writer used by gre.rs, icmp.rs, and the TX segmentation
// path. The SSOT writer's `From<u16>` VLAN semantics (tag present iff
// `vlan_id > 0`, TPID 0x8100, PCP/DEI 0) reproduce the deleted copy's
// behavior byte-for-byte, so output is identical for every NAT64
// frame the dataplane currently emits — while a future TPID/PCP/DEI/
// 802.1ad/ethertype change in the shared module now reaches NAT64.

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[path = "nat64_tests.rs"]
mod tests;
