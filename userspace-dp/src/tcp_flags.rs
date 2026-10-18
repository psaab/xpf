//! Canonical TCP control-flag bits + classification predicates shared
//! across the dataplane.
//!
//! #2151: consolidates the per-module TCP-flag duplicates. Before this
//! module the same six flag bits were redefined under three different
//! naming schemes (`TCP_FLAG_*` in `afxdp/mod.rs` and `frame/tcp.rs`,
//! `TCP_*` in `screen/packet.rs`, the partial `TCP_FIN`/`TCP_RST` pair in
//! `session/mod.rs`) plus raw hex literals on the hot path (e.g.
//! `(meta.tcp_flags & 0x17) == 0x10` for a pure-ACK admission test). A
//! flag-aware change could update one private set and leave a hot-path
//! literal stale — a latent correctness hazard, not only a style issue.
//!
//! These are load-bearing wire constants: the bit values are fixed by the
//! TCP header layout (RFC 9293 §3.1, control-bits octet at TCP offset 13)
//! and must match the on-wire byte exactly. The flags octet, low bit
//! first, is: FIN(0x01) SYN(0x02) RST(0x04) PSH(0x08) ACK(0x10)
//! URG(0x20) ECE(0x40) CWR(0x80).
//!
//! The predicates below encode the EXACT inline checks they replaced — no
//! semantic change. Each predicate carries the original expression it
//! consolidates so a reviewer can confirm bit-for-bit equivalence.

/// FIN — sender has finished sending data.
pub(crate) const TCP_FIN: u8 = 0x01;
/// SYN — synchronize sequence numbers (connection open).
pub(crate) const TCP_SYN: u8 = 0x02;
/// RST — reset the connection.
pub(crate) const TCP_RST: u8 = 0x04;
/// PSH — push buffered data to the receiving application.
pub(crate) const TCP_PSH: u8 = 0x08;
/// ACK — the acknowledgment field is significant.
pub(crate) const TCP_ACK: u8 = 0x10;
/// URG — the urgent pointer field is significant.
pub(crate) const TCP_URG: u8 = 0x20;
/// CWR — Congestion Window Reduced (RFC 3168 §6.1.2). Set by the data
/// sender on the FIRST new-data segment it emits after halving cwnd in
/// response to an ECN-Echo, and on that segment only: the receiver stops
/// echoing as soon as it sees one CWR, so a CWR replicated onto a later
/// segment retracts an ECE the receiver may have re-raised in between and
/// loses a congestion signal. #5191: software TCP segmentation therefore
/// keeps CWR on segment 0 and clears it on the rest, matching what a TSO
/// NIC and Linux's `tcp_gso_segment` do.
pub(crate) const TCP_CWR: u8 = 0x80;

/// Mask of the four flags that distinguish a pure ACK from a connection
/// control segment: FIN | SYN | RST | ACK (0x17). Used by the flow-cache
/// admission test below.
pub(crate) const TCP_FLAGS_CTRL_MASK: u8 = TCP_FIN | TCP_SYN | TCP_RST | TCP_ACK;

/// True iff the SYN bit is set.
#[inline]
#[allow(dead_code)]
pub(crate) fn has_syn(flags: u8) -> bool {
    (flags & TCP_SYN) != 0
}

/// True iff the ACK bit is set.
#[inline]
#[allow(dead_code)]
pub(crate) fn has_ack(flags: u8) -> bool {
    (flags & TCP_ACK) != 0
}

/// True iff the RST bit is set.
#[inline]
#[allow(dead_code)]
pub(crate) fn has_rst(flags: u8) -> bool {
    (flags & TCP_RST) != 0
}

/// True iff the FIN bit is set.
#[inline]
#[allow(dead_code)]
pub(crate) fn has_fin(flags: u8) -> bool {
    (flags & TCP_FIN) != 0
}

/// True iff the URG bit is set.
#[inline]
#[allow(dead_code)]
pub(crate) fn has_urg(flags: u8) -> bool {
    (flags & TCP_URG) != 0
}

/// True iff the PSH bit is set.
#[inline]
#[allow(dead_code)]
pub(crate) fn has_psh(flags: u8) -> bool {
    (flags & TCP_PSH) != 0
}

/// True iff the segment is a pure ACK — ACK set and FIN/SYN/RST all
/// clear. Equivalent to the inline `(flags & 0x17) == 0x10`. PSH and URG
/// are intentionally ignored (a PSH-ACK is still a pure ACK for cache
/// admission). Drives flow-cache eligibility on the hot path.
#[inline]
#[allow(dead_code)]
pub(crate) fn is_ack_only(flags: u8) -> bool {
    (flags & TCP_FLAGS_CTRL_MASK) == TCP_ACK
}

/// True iff the segment is an initial (bare) SYN — SYN set, ACK clear.
/// Equivalent to the inline `(flags & SYN) != 0 && (flags & ACK) == 0`.
/// Distinguishes a connection-opening SYN from a SYN+ACK.
#[inline]
#[allow(dead_code)]
pub(crate) fn is_initial_syn(flags: u8) -> bool {
    has_syn(flags) && !has_ack(flags)
}

/// True iff both SYN and ACK are set (a SYN+ACK handshake response).
/// Equivalent to the inline `(flags & 0x12) == 0x12`.
#[inline]
#[allow(dead_code)]
pub(crate) fn is_syn_ack(flags: u8) -> bool {
    (flags & (TCP_SYN | TCP_ACK)) == (TCP_SYN | TCP_ACK)
}

/// True iff the segment carries a connection-closing control bit —
/// FIN or RST. Equivalent to the inline `(flags & (FIN | RST)) != 0`.
/// Marks a session as closing on the conntrack path.
#[inline]
#[allow(dead_code)]
pub(crate) fn is_closing(flags: u8) -> bool {
    (flags & (TCP_FIN | TCP_RST)) != 0
}

/// True iff the segment carries TCP payload progress — i.e. it is a
/// data-bearing segment rather than a bare control/ACK segment.
///
/// `payload_len` is the caller-derived TCP payload length (IP-declared
/// datagram end minus the TCP header end; zero when unknown/truncated).
/// The session layer never parses frames, so callers that cannot derive
/// a payload length pass 0 and this predicate stays false — the
/// conservative direction (no spurious refresh). PSH is deliberately
/// NOT used: a zero-window probe or a retransmitted PSH segment carries
/// no new payload, while a data segment without PSH (bulk-transfer
/// middle segments routinely clear PSH) still advances the byte stream.
#[inline]
pub(crate) fn has_payload_progress(_tcp_flags: u8, payload_len: u32) -> bool {
    payload_len > 0
}

#[cfg(test)]
#[path = "tcp_flags_tests.rs"]
mod tests;
