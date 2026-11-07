// ECN CE-marking + Ethernet L3 parser. Threshold constants and the
// `apply_cos_admission_ecn_policy` gate live with admission in
// `cos/admission.rs` (a byte-mutation module shouldn't own
// admission tuning).

use crate::afxdp::ethernet::{ETH_HDR_LEN, VLAN_TAG_LEN};
use crate::afxdp::types::{PreparedTxRequest, TxRequest};
use crate::afxdp::umem::MmapArea;

/// ECN codepoint masks (low 2 bits of IPv4 TOS / IPv6 tclass).
///
/// `pub(in crate::afxdp)` because admission tests in
/// `cos/admission.rs::tests` reference these masks directly.
pub(in crate::afxdp) const ECN_MASK: u8 = 0b0000_0011;
pub(in crate::afxdp) const ECN_NOT_ECT: u8 = 0b0000_0000;
pub(in crate::afxdp) const ECN_ECT_0: u8 = 0b0000_0010;
pub(in crate::afxdp) const ECN_ECT_1: u8 = 0b0000_0001;
pub(in crate::afxdp) const ECN_CE: u8 = 0b0000_0011;

/// Parsed L3 discriminator + offset from a forwarded Ethernet frame.
/// Carries both pieces together so the ECN mark path dispatches off the
/// bytes it actually parsed, not the `expected_addr_family` sideband —
/// a malformed frame whose sideband says AF_INET but whose ethertype
/// says something else must not get its "TOS byte" stamped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::afxdp) enum EthernetL3 {
    Ipv4(usize),
    Ipv6(usize),
}

/// Parse the outer Ethernet header, transparently walk a single 802.1Q
/// / 802.1ad VLAN tag, and report the L3 family + header offset. The
/// CoS admission path sees frames post-forward-build, so VLAN tags
/// from tagged subinterfaces (e.g. `reth0 unit 80`) are already
/// present. Callers use the returned family to dispatch to the
/// matching ECN marker and the offset to locate the TOS / tclass byte.
///
/// Returns `None` for:
/// - buffers shorter than the parse requires (no slice-out-of-bounds
///   panic on the hot path),
/// - non-IP ethertypes (including ARP, MPLS, and the tail of a QinQ
///   stack) — we refuse to guess rather than stamp a byte that is not
///   a TOS / tclass byte,
/// - nested VLAN tags (QinQ / 802.1ad-over-Q) — not implemented yet;
///   adding support means one more 4-byte hop plus recursive inner-
///   ethertype inspection. The single-tag path covers the only lab
///   fixture we currently exercise.
///
/// Historically this helper just returned an offset, and dispatch was
/// based on `expected_addr_family`. The gap that exposed was: if the
/// sideband said AF_INET but the frame was ARP-inside-VLAN, we would
/// still compute offset = 18 and stamp byte 19 inside the ARP body.
/// Returning the parsed family here closes that drift permanently —
/// the marker cannot disagree with the wire bytes it is mutating.
#[inline]
pub(in crate::afxdp) fn ethernet_l3(bytes: &[u8]) -> Option<EthernetL3> {
    if bytes.len() < ETH_HDR_LEN {
        return None;
    }
    let outer = u16::from_be_bytes([bytes[12], bytes[13]]);
    match outer {
        0x0800 => Some(EthernetL3::Ipv4(ETH_HDR_LEN)),
        0x86DD => Some(EthernetL3::Ipv6(ETH_HDR_LEN)),
        // 802.1Q / 802.1ad single VLAN tag. The inner ethertype lives
        // 4 bytes after the outer one; if that inner ethertype is
        // *itself* a VLAN TPID we have a QinQ stack that we do not
        // support yet — reject it rather than stamping into an inner
        // tag.
        0x8100 | 0x88A8 => {
            let inner_off = ETH_HDR_LEN + VLAN_TAG_LEN;
            // Inner ethertype lives at bytes[inner_off-2..inner_off],
            // so we only need `bytes.len() >= inner_off`. The downstream
            // markers (`mark_ecn_ce_ipv4` / `_ipv6`) have their own
            // bounds checks for the IP header itself; the parser must
            // not over-reject frames that ARE long enough to identify
            // the L3 family (Copilot review on PR #976).
            if bytes.len() < inner_off {
                return None;
            }
            let inner = u16::from_be_bytes([bytes[inner_off - 2], bytes[inner_off - 1]]);
            match inner {
                0x0800 => Some(EthernetL3::Ipv4(inner_off)),
                0x86DD => Some(EthernetL3::Ipv6(inner_off)),
                // QinQ or unknown inner — refuse to guess.
                _ => None,
            }
        }
        _ => None,
    }
}

#[cfg(test)]
pub(crate) fn cos_l2_view_for_test(bytes: &[u8]) -> crate::afxdp::L2View {
    crate::afxdp::L2View {
        l3_offset: ethernet_l3(bytes).map(|view| match view {
            EthernetL3::Ipv4(offset) | EthernetL3::Ipv6(offset) => offset,
        }),
    }
}

/// Mark the IPv4 packet at `l3_offset` within `bytes` as ECN CE if it
/// is already ECT(0) or ECT(1). Updates the IP header checksum
/// incrementally (RFC 1624). Returns true iff the packet was marked.
/// Never modifies a NOT-ECT packet (protects non-ECN flows per RFC
/// 3168 section 6.1.1.1).
#[inline]
pub(in crate::afxdp) fn mark_ecn_ce_ipv4(bytes: &mut [u8], l3_offset: usize) -> bool {
    // Need the full 20-byte base IPv4 header (through the checksum field).
    // Short buffers are returned false rather than panicking — this path
    // runs per admission on the hot path and cannot trust upstream
    // length validation to have covered every corner.
    let end = l3_offset.saturating_add(20);
    if bytes.len() < end {
        return false;
    }
    // #4269 (R-8h): the ethertype-based dispatch is the primary guard, but
    // verify the IP version nibble too. A frame whose ethertype was
    // trusted but whose L3 header is not actually IPv4 (mislabeled tag,
    // NAT64/tunnel rewrite drift, injected frame) would otherwise have its
    // TOS byte flipped and its "IPv4 checksum" recomputed over a non-IPv4
    // header. Reject anything but version 4.
    if (bytes[l3_offset] >> 4) != 4 {
        return false;
    }
    let tos_idx = l3_offset + 1;
    let old_tos = bytes[tos_idx];
    let ecn = old_tos & ECN_MASK;
    // Branchless: only ECT(0) and ECT(1) cross to CE; NOT-ECT and CE
    // are left unchanged. A non-ECT packet returning false routes into
    // the existing admission drop path unchanged.
    if ecn != ECN_ECT_0 && ecn != ECN_ECT_1 {
        return false;
    }
    let new_tos = (old_tos & !ECN_MASK) | ECN_CE;
    bytes[tos_idx] = new_tos;

    // RFC 1624 incremental checksum update for a single byte change to
    // the TOS field (16-bit word = [version/IHL, TOS]). The header
    // checksum sits at l3_offset+10..l3_offset+12 in network byte order.
    //
    //   HC' = ~(~HC + ~m + m')
    //
    // where m and m' are the 16-bit words at the mutated position. The
    // version/IHL byte is unchanged so it cancels inside `old_word` /
    // `new_word` — but keeping it in the word avoids a conditional on
    // which half of the 16-bit word we touched.
    let ihl = bytes[l3_offset];
    let old_word = ((ihl as u32) << 8) | old_tos as u32;
    let new_word = ((ihl as u32) << 8) | new_tos as u32;
    let csum_idx = l3_offset + 10;
    let old_csum = ((bytes[csum_idx] as u32) << 8) | bytes[csum_idx + 1] as u32;
    // ~HC + ~m + m' in 32-bit arithmetic, then fold carries.
    let mut sum = (!old_csum & 0xffff) + (!old_word & 0xffff) + new_word;
    // Fold any carries out of the low 16 bits. Two folds are sufficient
    // for the three 16-bit addends above (max ~3 * 0xffff fits in 18
    // bits, one fold collapses to 17 bits, second to 16 bits).
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let new_csum = (!sum) & 0xffff;
    bytes[csum_idx] = (new_csum >> 8) as u8;
    bytes[csum_idx + 1] = (new_csum & 0xff) as u8;
    true
}

/// Mark the IPv6 packet at `l3_offset` within `bytes` as ECN CE if it
/// is already ECT(0) or ECT(1). IPv6 has no header checksum so no
/// incremental update is needed. Returns true iff the packet was marked.
#[inline]
pub(in crate::afxdp) fn mark_ecn_ce_ipv6(bytes: &mut [u8], l3_offset: usize) -> bool {
    // tclass spans the low nibble of byte[l3_offset] and the high
    // nibble of byte[l3_offset+1]. We need both bytes in range.
    let end = l3_offset.saturating_add(2);
    if bytes.len() < end {
        return false;
    }
    // #4269 (R-8h): defensive version-nibble check (mirror of the IPv4
    // marker). The ethertype dispatch is primary, but verify the header is
    // actually IPv6 before rewriting its traffic-class ECN bits.
    if (bytes[l3_offset] >> 4) != 6 {
        return false;
    }
    // Version/tclass-high byte: [vvvv tttt]. ECN bits are the low 2
    // bits of tclass, which sit in the high nibble of byte[l3_offset+1]
    // as bits 5..4. Extract with a simple shift-mask.
    let b1 = bytes[l3_offset + 1];
    let ecn = (b1 >> 4) & ECN_MASK;
    if ecn != ECN_ECT_0 && ecn != ECN_ECT_1 {
        return false;
    }
    // Clear the old ECN bits (bits 5..4 of byte[l3_offset+1]) and OR in
    // CE shifted into place.
    let cleared = b1 & !(ECN_MASK << 4);
    bytes[l3_offset + 1] = cleared | (ECN_CE << 4);
    true
}

/// Dispatch ECN marking based on the L3 protocol family parsed
/// from the TxRequest's bytes (NOT the `expected_addr_family`
/// sideband — see the dispatch body for the rationale). Returns
/// true iff the packet was marked.
#[inline]
pub(in crate::afxdp) fn maybe_mark_ecn_ce(req: &mut TxRequest) -> bool {
    // Dispatch off the parsed Ethernet header, not the sideband
    // `expected_addr_family`. The sideband is populated at RX time and
    // can drift for injected or re-queued frames whose wire bytes got
    // rewritten (e.g. NAT64, tunnel transit). Trusting the parse keeps
    // the marker from stamping the wrong protocol body on any frame
    // where the two disagree.
    match ethernet_l3(&req.bytes) {
        Some(EthernetL3::Ipv4(l3_offset)) => mark_ecn_ce_ipv4(&mut req.bytes, l3_offset),
        Some(EthernetL3::Ipv6(l3_offset)) => mark_ecn_ce_ipv6(&mut req.bytes, l3_offset),
        None => false,
    }
}

/// Mark a prepared (zero-copy) TX frame as ECN CE in place inside the
/// UMEM. Only fires on ECT(0)/ECT(1) per RFC 3168 §6.1.1.1. Returns
/// true iff the packet was marked. Out-of-range offset/len pairs
/// (e.g. a PreparedTxRequest that somehow escaped bounds checks)
/// return false without panicking — the caller falls through into
/// the existing admission path unchanged.
///
/// This is the Prepared-variant counterpart to `maybe_mark_ecn_ce`;
/// #718 / #722 originally only handled the Local variant, leaving
/// the XSK-RX→XSK-TX zero-copy hot path (iperf3, NAT'd flows) with
/// the marker dormant. See `docs/cos-validation-notes.md` for the
/// counter-reading methodology.
///
/// # Safety
///
/// The caller must hold exclusive access to the frame at
/// `[req.offset, req.offset + req.len)` within `umem`. On the CoS
/// admission path this is guaranteed: admission runs *before* the
/// frame is enqueued into the CoS queue, let alone submitted to the
/// XSK TX ring, so the worker that built the frame is still the sole
/// owner. Callers that invoke this outside of the admission gate
/// must provide the same guarantee.
#[inline]
pub(in crate::afxdp) fn maybe_mark_ecn_ce_prepared(
    req: &PreparedTxRequest,
    umem: &MmapArea,
) -> bool {
    let offset = req.offset as usize;
    let len = req.len as usize;
    // SAFETY: see function-level doc. The admission path owns the
    // frame until `cos_queue_push_back` takes it, which is strictly
    // after this call. Out-of-range slices return None (handled
    // below) rather than producing a dangling reference.
    let Some(bytes) = (unsafe { umem.slice_mut_unchecked(offset, len) }) else {
        return false;
    };
    // Same rationale as `maybe_mark_ecn_ce`: dispatch off the parsed
    // wire bytes, not `expected_addr_family`. See that helper's
    // comment for the drift scenarios this protects against.
    match ethernet_l3(bytes) {
        Some(EthernetL3::Ipv4(l3_offset)) => mark_ecn_ce_ipv4(bytes, l3_offset),
        Some(EthernetL3::Ipv6(l3_offset)) => mark_ecn_ce_ipv6(bytes, l3_offset),
        None => false,
    }
}

#[cfg(test)]
#[path = "ecn_tests.rs"]
mod tests;

