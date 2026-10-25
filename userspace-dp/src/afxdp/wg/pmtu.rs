//! #16711: per-peer WireGuard outer path-MTU soft state learned from
//! underlay ICMP Packet-Too-Big / Fragmentation-Needed errors.
//!
//! The AF_XDP transit encap (`frame::wg::wg_encap_frame`) sizes the
//! outer datagram against the local egress link MTU (or a static route
//! `mtu`). Nothing learned the underlay path MTU beyond the first hop:
//! a router past that hop with a smaller MTU drops the unfragmentable
//! IPv6 outer (RFC 8200 §4.5 — only the source fragments) and returns
//! an ICMPv6 Packet-Too-Big to the firewall's outer source. That PTB
//! reached only the kernel route cache, which the AF_XDP path never
//! reads, so large inner packets black-holed silently and permanently.
//!
//! This module is the soft-state store the acceptance requires:
//!   - keyed by PEER PUBKEY (the peer's endpoint may roam; the pubkey
//!     is the stable identity `WgEngine::peer_for_dest` returns);
//!   - an outer PMTU (the largest outer L3 datagram the underlay now
//!     admits), floored at the family's protocol minimum — 1280 for an
//!     IPv6 outer (RFC 8201), 68 for an IPv4 outer (RFC 791) — and
//!     never raised by a PTB (only a strictly smaller, floored value
//!     replaces the stored one, so a forged large PTB cannot inflate
//!     the budget);
//!   - aged: an entry is honoured for `WG_PMTU_AGE_NS` (10 min,
//!     RFC 8201 §4's suggested probe cadence) after its last accepted
//!     PTB, then expires so a path that widens again (failover onto a
//!     broader underlay) is re-probed at the full local MTU rather
//!     than pinned forever at the stale small value.
//!
//! Both writers and readers are lock-free per peer: the value and its
//! learn stamp live in packed `AtomicU64`s on `Peer` (mirroring the
//! `live_endpoint` slot's per-peer, `Arc`-survives-reconcile posture —
//! same pubkey reuses the same `Arc<Peer>`, so the learned PMTU
//! survives config commits that do not touch the peer's identity and
//! is reset exactly when the engine/peer is rebuilt).
//!
//! Validation of a PTB before it reaches [`WgEngine::note_peer_pmtu`]
//! lives in `frame::wg::consume_wg_outer_ptb`: the quote must be a live
//! WG outer (UDP, src port = the endpoint's `wg_listen_port`, dst =
//! the selected peer's configured-or-roamed endpoint). A forged quote
//! that names no live peer endpoint/port learns nothing.

/// How long a learned outer PMTU is honoured after the last accepted
/// PTB. RFC 8201 §4 suggests re-raising the probe after ~10 minutes;
/// on expiry the encap/PTB/MSS consumers fall back to the local
/// egress/route MTU and the next oversize outer draws a fresh PTB.
pub(crate) const WG_PMTU_AGE_NS: u64 = 600_000_000_000;

/// Floor for a learned outer PMTU by outer family: an IPv6 outer is
/// never sized below the 1280 link minimum (RFC 8201 §4 forbids
/// reducing below it); an IPv4 outer floors at the 68-byte RFC 791
/// minimum reassembly buffer. A PTB advertising less is clamped up to
/// the floor, never honoured literally — a sub-floor advertisement
/// would otherwise pin the tunnel at an unusable MTU.
#[inline]
pub(crate) fn wg_pmtu_floor(outer_v6: bool) -> usize {
    if outer_v6 {
        1280
    } else {
        68
    }
}

/// Pack (mtu, learned_ns) decision: the effective outer PMTU for a
/// peer, or `None` when no fresh entry exists. Pure so the aging rule
/// is unit-testable without an engine. `stored_mtu == 0` is the
/// never-learned sentinel.
#[inline]
pub(crate) fn effective_pmtu(stored_mtu: u64, learned_ns: u64, now_ns: u64) -> Option<usize> {
    if stored_mtu == 0 || learned_ns == 0 {
        return None;
    }
    // A stamp in the future (clock step / test seam) counts as fresh,
    // mirroring the monotonic-stamp convention elsewhere (#1792: a
    // step must not fence live state).
    if now_ns >= learned_ns && now_ns - learned_ns > WG_PMTU_AGE_NS {
        return None;
    }
    Some(stored_mtu as usize)
}

/// Decide the stored value after an offered PTB. Returns the value to
/// store, or `None` to leave the store untouched. Only a strictly
/// smaller (post-floor) offer replaces a fresh stored value; an equal
/// or larger offer still refreshes the aging stamp at the call site,
/// so a repeat PTB for the same path keeps the entry alive without
/// ever raising the budget.
#[inline]
pub(crate) fn pmtu_after_offer(
    current: Option<usize>,
    offered_mtu: usize,
    outer_v6: bool,
) -> Option<usize> {
    let offered = offered_mtu.max(wg_pmtu_floor(outer_v6));
    match current {
        Some(cur) if offered >= cur => None,
        _ => Some(offered),
    }
}
