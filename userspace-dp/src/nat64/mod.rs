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
//!   * **Complete v6→v4 UDP datagrams with a zero checksum** — the illegal
//!     IPv6 UDP checksum has no baseline, but all payload bytes are available,
//!     so the translated IPv4 checksum is recomputed. A real first fragment
//!     with that checksum is instead dropped before output writes (#13696):
//!     only part of the datagram is present, so recomputation is impossible.
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
//! [`reserve_synced_nat64_allocation`] applies the source-NAT synchronization
//! path to the standard round-robin NAT64 allocator: the standby reserves the
//! translated tuple through `reserve_nat64_pool_port` and joins the same
//! `AnyRemoteHost` persistent BIB lease as local allocations. Normal teardown
//! drops the active session reference but retains the BIB for 300 seconds, so
//! a new remote endpoint cannot receive a different mapping during that idle
//! interval. Deterministic NAPT64 remains a separate per-flow path; #14091
//! tracks bringing its block-constrained allocator into the same contract.
//!
//! Scope: this closes the port-COLLISION harm. Reverse-TRANSLATION of a
//! promoted synced NAT64 session (restoring the original client v6 address)
//! still needs `Nat64ReverseInfo` — `orig_src_v6` / `orig_dst_v6`, which are NOT
//! reconstructible from `NatDecision` — to ride the sync payload; that is a
//! separate wire-field follow-up (`ha.rs` sets `nat64_reverse: None`).

use crate::afxdp::frame::checksum::{adjust_zero_checksum_illegal, ChecksumFamily};
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
// Re-exported from `crate::afxdp` because NAT64 lives outside that module.
// #10860: Fragment Header Next-Header classification uses the canonical
// extension-header set, so newly traversable types cannot reopen the geometry
// corruption by being stripped after fragmentation.
use crate::afxdp::{ExtChainOutcome, ipv6_ext_header_is_traversable, walk_ipv6_ext_chain};
use crate::nat::{
    DeterministicV6, NatDecision, PortAllocator, SourceNatFailureReason, SourceNatFlowKey,
    TranslatedTuple, allocate_nat64_pool_port, allocate_nat64_pool_port_deterministic_v6,
    peer_owns_identity_in, release_nat64_pool_port, reserve_nat64_pool_port,
    static_owns_wire_identity,
};
use crate::prefix::PrefixV6;
use crate::session::SessionDecision;
use rustc_hash::{FxHashMap, FxHashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use crate::ip_proto::{PROTO_ICMP, PROTO_ICMPV6, PROTO_TCP, PROTO_UDP};
use std::sync::atomic::AtomicU32;

// ---------------------------------------------------------------------------
// #16188: nat64.rs split into the nat64/ module (motion-only).
//
// The previous single-file userspace-dp/src/nat64.rs (5,538 lines)
// mixed six independent concerns: prefix/state construction and
// matching, the allocation reserve/release facade, the stateless
// v6<->v4 translation cores, ICMP error + embedded-quote translation,
// the checksum helpers, and the Ethernet frame builders. The split
// localizes each concern; no behaviour, signature, or invariant
// changed, and the deliberate checksum16* one-line forwards (kept
// post-#13086) live untouched in nat64/checksum.rs.
//
// Submodules are intentionally private; this mod.rs is the curated
// public namespace and re-exports the pub(crate) symbols that
// external callers reach as crate::nat64::*. Cross-submodule internal
// items use pub(super): visible to this root (whose `use super::*`
// children and glob re-exports then carry them) and to the test
// modules below, never outside nat64/ -- exactly their pre-split
// reach, since every widened item was private in the flat file.
//
// Visibility bill (the ONLY non-motion edits; machine-checked by
// scripts/verify-nat64-split-16188.py, which reconstructs the
// pre-split file byte-for-byte after un-applying them):
//   state.rs:    NAT64_PORT_LOW, NAT64_PORT_HIGH, parse_pool_v4,
//                nat64_rule_identity, build_deterministic_v6,
//                prev_prefix_is_deterministic,
//                Nat64State::embedded_v4_is_non_global (associated fn)
//                private -> pub(super)
//   reserve.rs:  release_nat64_allocation_with_mode
//                private -> pub(super) (test-only reach via root)
//   translate.rs: ICMPV6_ECHO_REQUEST, ICMPV6_ECHO_REPLY,
//                ICMP_ECHO_REQUEST, ICMP_ECHO_REPLY,
//                ICMPV6_DEST_UNREACHABLE, ICMPV6_PACKET_TOO_BIG,
//                ICMPV6_TIME_EXCEEDED, ICMPV6_PARAMETER_PROBLEM,
//                ICMP_DEST_UNREACHABLE, ICMP_TIME_EXCEEDED,
//                ICMP_PARAMETER_PROBLEM, IPV6_MIN_MTU,
//                NAT64_HEADER_DELTA, MAX_EMBEDDED_LEN,
//                rfc1191_plateau_mtu, next_frag_id, map_frag_id,
//                ipv6_l4_offset_and_protocol,
//                nat64_v6_translation_ineligible,
//                ipv6_is_non_first_fragment, write_v6_to_v4_translate,
//                write_v4_to_v6_translate, checked_ipv6_payload_len
//                private -> pub(super)
//   icmp.rs:     EmbeddedV6ToV4, EmbeddedV6ToV4Layout, EmbeddedV4ToV6
//                (+ all their fields), embedded_v6_to_v4_layout,
//                translated_icmpv6_error_l4_len,
//                translate_icmpv6_message_to_icmpv4,
//                translate_icmpv4_message_to_icmpv6,
//                translate_embedded_v6_to_v4,
//                translate_embedded_v4_to_v6,
//                recompute_l4_checksum_after_nat64_v6_to_v4,
//                recompute_l4_checksum_after_nat64_v4_to_v6,
//                canonicalize_zero_checksum,
//                map_icmpv6_error_to_icmpv4, map_icmpv4_error_to_icmpv6,
//                embedded_icmpv6_type_to_icmpv4,
//                embedded_icmpv4_type_to_icmpv6, finalize_icmpv4_checksum,
//                write_icmpv4_error_with_embedded,
//                write_icmpv6_error_with_embedded
//                private -> pub(super)
//   checksum.rs: checksum16, checksum16_add, checksum16_fold,
//                checksum16_ipv4_pseudo, checksum16_ipv6_pseudo,
//                checksum16_incremental,
//                adjust_l4_checksum_v6_to_v4_incremental,
//                adjust_l4_checksum_v4_to_v6_incremental
//                private -> pub(super)
//   frames.rs:   write_v6_to_v4_nonfirst_translate,
//                write_v4_to_v6_nonfirst_translate, frame_l3_offset
//                private -> pub(super)
//
// Three doc-comment blocks moved WITH their item across a seam
// (a doc comment left dangling at a submodule EOF is a hard error):
// the release_nat64_allocation_with_mode doc (state tail -> reserve
// head), the map_icmpv6_error_to_icmpv4 doc (translate tail -> icmp
// head), and the write_v6_to_v4_nonfirst_translate doc (checksum tail
// -> frames head). Their text is verbatim; only their file changed.
// The two mid-file `use` lines that sat inside the translate seam
// (crate::ip_proto::* and AtomicU32, pre-split lines 2736-2737) now
// sit in this root's import block: a submodule's private `use` is
// NOT forwarded by a sibling's `use super::*` glob, so leaving them
// in translate.rs starved icmp/checksum/frames of PROTO_*.
//
// The tests module's #[path] is respelled ../nat64_tests.rs for the
// new depth, and its #2211 source scan now reads nat64/checksum.rs
// (where the pinned helpers live) instead of the deleted flat file.
//
// A CAUTION this split pays for (same as #1542/#6988): pub(super)
// means something different at each depth. Every widened item was
// private to the flat nat64 module, so pub(super) inside nat64/*
// (visible to nat64 and its descendants, i.e. the tests below)
// restores exactly the pre-split reach -- nothing widened here
// becomes crate-visible that was not already pub(crate).

mod checksum;
mod frames;
mod icmp;
mod reserve;
mod state;
mod translate;

pub(crate) use checksum::*;
pub(crate) use frames::*;
pub(crate) use icmp::*;
pub(crate) use reserve::*;
pub(crate) use state::*;
pub(crate) use translate::*;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[path = "../nat64_tests.rs"]
mod tests;

/// #9069: every NAT64 recompute arm applies the codebase's ONE zero-checksum
/// rule, and applies it only where that rule says to.
///
/// The `PROTO_ICMPV6` arm of the v4->v6 recompute wrote `sum` raw while its own
/// UDP sibling ten lines above canonicalised, and while
/// `adjust_zero_checksum_illegal` — this codebase's declared SSOT (#1839) — says
/// V6 zero is illegal for UDP *and ICMPv6*. The afxdp-side
/// `recompute_l4_checksum_ipv6` canonicalises its ICMPv6 arm; the NAT64
/// translator diverged from the rule its sibling path enforces.
///
/// SCOPE, stated because the originating report's stated consequence was
/// REFUTED: it cited RFC 4443 §2.3 and RFC 8200 §8.1 for a mandatory all-ones
/// substitution on ICMPv6, and that rule is UDP-specific in RFC 8200 §8.1 while
/// RFC 4443 §2.3 contains no such sentence. A 0x0000 ICMPv6 checksum verifies
/// correctly at a compliant receiver. This is an internal SSOT-consistency fix,
/// not a wire-correctness one, and these cells assert consistency accordingly.
#[cfg(test)]
mod nat64_zero_checksum_ssot_9069_tests {
    use super::*;

    /// A minimal IPv6 + ICMPv6 Echo Reply whose last two payload bytes are
    /// caller-chosen, so a cell can drive the checksum to a specific value.
    fn icmpv6_echo_reply_9069(tail: [u8; 2]) -> Vec<u8> {
        let mut p = vec![0u8; 40];
        p[0] = 0x60;
        p[6] = PROTO_ICMPV6;
        p[7] = 64;
        // src = 64:ff9b::/96 mapped, dst = a client address; the exact values
        // only matter in that both cells use the SAME ones.
        p[0..1].copy_from_slice(&[0x60]);
        p[8..24].copy_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ]);
        p[24..40].copy_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02,
        ]);
        // ICMPv6 Echo Reply: type 129, code 0, checksum (filled), id, seq, payload.
        let mut l4 = vec![129u8, 0, 0, 0, 0x12, 0x34, 0x00, 0x01];
        l4.extend_from_slice(&tail);
        p[4..6].copy_from_slice(&(l4.len() as u16).to_be_bytes());
        p.extend_from_slice(&l4);
        p
    }

    /// Brute-force the two-byte tail that makes the ICMPv6 checksum fold to
    /// zero, so the cell below cannot silently stop being about a zero.
    ///
    /// The issue reports (0xa1, 0x2a) for ITS packet; this one differs, so the
    /// value is DERIVED here rather than copied. A hard-coded tail from another
    /// fixture would be the shape where a cell passes while testing nothing —
    /// the checksum would simply be non-zero and the canonicalisation never
    /// exercised.
    fn tail_that_folds_to_zero_9069() -> [u8; 2] {
        for a in 0u16..=255 {
            for b in 0u16..=255 {
                let mut p = icmpv6_echo_reply_9069([a as u8, b as u8]);
                let src = Ipv6Addr::from(<[u8; 16]>::try_from(&p[8..24]).unwrap());
                let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&p[24..40]).unwrap());
                p[42..44].copy_from_slice(&[0, 0]);
                if checksum16_ipv6_pseudo(src, dst, PROTO_ICMPV6, &p[40..]) == 0 {
                    return [a as u8, b as u8];
                }
            }
        }
        panic!("no two-byte tail folds this packet's ICMPv6 checksum to zero — the \
                fixture changed and the cell below would assert nothing");
    }

    /// THE DEFECT: a translated ICMPv6 message whose checksum folds to zero must
    /// be emitted as 0xFFFF, matching the UDP sibling and the SSOT.
    #[test]
    fn a_zero_folding_icmpv6_checksum_is_canonicalised_9069() {
        let tail = tail_that_folds_to_zero_9069();
        let mut pkt = icmpv6_echo_reply_9069(tail);

        recompute_l4_checksum_after_nat64_v4_to_v6(&mut pkt, PROTO_ICMPV6)
            .expect("recompute must succeed on a well-formed packet");

        let written = u16::from_be_bytes([pkt[42], pkt[43]]);
        assert_ne!(
            written, 0x0000,
            "#9069: the ICMPv6 arm emitted 0x0000. Its own UDP sibling ten lines \
             above canonicalises, and adjust_zero_checksum_illegal — the declared \
             SSOT — says V6 zero is illegal for ICMPv6, which the afxdp-side \
             recompute_l4_checksum_ipv6 already honours. The translator diverged \
             from the rule its sibling path enforces"
        );
        assert_eq!(
            written, 0xFFFF,
            "#9069: a zero-folding checksum must become all-ones, not some other \
             value"
        );
    }

    /// MUST NOT OVER-APPLY — TCP. A computed TCP 0x0000 is LEGAL on the wire in
    /// both families (this is why the sibling finding GEMINI-050-009 was
    /// refuted), so the canonicalisation must leave it alone. Without this cell a
    /// "fix" that canonicalised unconditionally would satisfy the one above while
    /// corrupting every TCP checksum that legitimately computes to zero.
    #[test]
    fn a_zero_tcp_checksum_is_left_alone_9069() {
        assert_eq!(
            canonicalize_zero_checksum(0, PROTO_TCP, ChecksumFamily::V6),
            0,
            "#9069: a computed TCP 0x0000 is valid on the wire and must survive \
             the canonicalisation untouched"
        );
        assert_eq!(
            canonicalize_zero_checksum(0, PROTO_TCP, ChecksumFamily::V4),
            0,
            "#9069: same for v4 TCP"
        );
    }

    /// MUST NOT OVER-APPLY — v4 ICMP. It carries no pseudo-header and has no
    /// zero sentinel, so V4/ICMP is deliberately absent from the SSOT's matrix.
    /// A fix that keyed on "is it ICMP-ish" rather than on the (protocol, family)
    /// PAIR would corrupt it.
    #[test]
    fn a_zero_v4_icmp_checksum_is_left_alone_9069() {
        assert_eq!(
            canonicalize_zero_checksum(0, PROTO_ICMP, ChecksumFamily::V4),
            0,
            "#9069: v4 ICMP has no pseudo-header and no zero sentinel — the rule \
             is keyed on the (protocol, family) PAIR, not on the protocol alone"
        );
    }

    /// The pairs the SSOT DOES cover must canonicalise, in both families.
    #[test]
    fn the_ssot_pairs_canonicalise_9069() {
        for (proto, fam, name) in [
            (PROTO_UDP, ChecksumFamily::V4, "v4 UDP"),
            (PROTO_UDP, ChecksumFamily::V6, "v6 UDP"),
            (PROTO_ICMPV6, ChecksumFamily::V6, "v6 ICMPv6"),
        ] {
            assert_eq!(
                canonicalize_zero_checksum(0, proto, fam),
                0xFFFF,
                "#9069: {name} carries a zero sentinel and must canonicalise"
            );
        }
    }

    /// A NON-zero sum must pass through untouched for every pair — otherwise the
    /// cells above could be satisfied by a function that always returns 0xFFFF.
    #[test]
    fn a_nonzero_checksum_is_never_rewritten_9069() {
        for (proto, fam) in [
            (PROTO_UDP, ChecksumFamily::V6),
            (PROTO_ICMPV6, ChecksumFamily::V6),
            (PROTO_TCP, ChecksumFamily::V6),
            (PROTO_UDP, ChecksumFamily::V4),
        ] {
            assert_eq!(canonicalize_zero_checksum(0x1234, proto, fam), 0x1234);
        }
    }
}
