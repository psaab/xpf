//! #16512: link-specific fragmentation of tunnel OUTER datagrams below
//! IPv6 (RFC 8200 §5) for IPv6 inners up to the 1280 link minimum.
//!
//! When a GRE/WireGuard tunnel's derived inner budget is below 1280, a
//! PTB advertising the floored 1280 can never resolve the oversize
//! (RFC 8201 §4 forbids reducing below 1280), so the pre-#16512 path
//! blackholed every non-TCP IPv6 datagram in `(budget, 1280]` forever.
//! The tunnel link must instead provide fragmentation below IPv6: the
//! outer datagram (GRE proto-47 or WG UDP) is fragmented at the outer
//! MTU and the tunnel peer reassembles it before decap (#14645/#15102
//! bounded reassembly, 64 KiB cap). This module is the single writer of
//! outer fragments for both tunnel kinds.
//!
//! Eligibility is narrow, by construction at the call sites:
//!   - inner family is IPv6 and inner length is in `(inner_budget, 1280]`
//!     (larger inners keep the PTB path, which CAN resolve them);
//!   - outer family is IPv4 (IPv6 outers cannot be fragmented by a
//!     router, RFC 8200 §4.5 — those keep PTB+drop);
//!   - the built outer datagram exceeds the outer MTU but fits one
//!     UMEM frame as a whole (the encap builders already built it).
//!
//! Fragmentation follows RFC 791: every fragment except the last has an
//! 8-byte-multiple payload, all share one Identification (the tunnel
//! header writer's advancing ID, RFC 6864), DF is clear, and each
//! fragment's header checksum is recomputed. The Ethernet header
//! (including any VLAN tag) is replicated verbatim.

use std::sync::atomic::{AtomicU32, Ordering};

/// Advancing Identification for fragmented outer datagrams whose header
/// writer did not already mint one (WG outers use `write_ipv4_header`'s
/// atomic ID=0, which must never be reused across fragments of different
/// datagrams). GRE outers already carry the advancing tunnel ID.
static OUTER_FRAG_ID: AtomicU32 = AtomicU32::new(1);

/// Whether `outer_l3_len` needs fragmentation at `outer_mtu` for an
/// eligible #16512 packet: the whole outer does not fit, but the inner
/// is at most the IPv6 link minimum so delivery (not PTB) is owed.
#[inline]
pub(in crate::afxdp) fn outer_frag_eligible(
    inner_family: i32,
    inner_len: usize,
    inner_budget: usize,
    outer_family: i32,
    outer_l3_len: usize,
    outer_mtu: usize,
) -> bool {
    inner_family == libc::AF_INET6
        && outer_family == libc::AF_INET
        && outer_mtu > 20
        && inner_len > inner_budget
        && inner_len <= 1280
        && outer_l3_len > outer_mtu
}

/// Split one built outer Ethernet frame into IPv4 fragments at
/// `outer_mtu` (the L3 MTU; the Ethernet header is replicated on each).
/// `l3_offset` is the outer IP header offset in `frame`. Returns `None`
/// (fail-closed: caller drops + counts) when the frame is not a
/// fragmentable IPv4 datagram or the MTU cannot carry an 8-byte payload
/// chunk. A frame that already fits is returned as the single fragment.
pub(in crate::afxdp) fn fragment_outer_ipv4_frame(
    frame: &[u8],
    l3_offset: usize,
    outer_mtu: usize,
) -> Option<Vec<Vec<u8>>> {
    let ip = frame.get(l3_offset..)?;
    if ip.len() < 20 || ip[0] != 0x45 {
        return None;
    }
    let total_len = u16::from_be_bytes([ip[2], ip[3]]) as usize;
    if total_len < 20 || total_len > ip.len() {
        return None;
    }
    if total_len <= outer_mtu {
        return Some(vec![frame.to_vec()]);
    }
    // DF must be clear to fragment; tunnel outers that permit this path
    // are written DF-clear, but never override a DF the builder set.
    if ip[6] & 0x40 != 0 {
        return None;
    }
    // Already-fragmented outers are never produced by the encap
    // builders; refuse rather than re-fragment (offsets would splice).
    if ip[6] & 0x20 != 0 || u16::from_be_bytes([ip[6], ip[7]]) & 0x1fff != 0 {
        return None;
    }
    let max_payload = outer_mtu.checked_sub(20)? / 8 * 8;
    if max_payload == 0 {
        return None;
    }
    let payload = &ip[20..total_len];
    // One Identification for every fragment. An atomic ID=0 (WG's
    // `write_ipv4_header`) is replaced with an advancing value so
    // fragments of different datagrams can never splice at the peer.
    let mut ident = u16::from_be_bytes([ip[4], ip[5]]);
    if ident == 0 {
        ident = OUTER_FRAG_ID.fetch_add(1, Ordering::Relaxed) as u16;
        if ident == 0 {
            ident = OUTER_FRAG_ID.fetch_add(1, Ordering::Relaxed) as u16;
        }
    }
    let eth = &frame[..l3_offset];
    let mut fragments = Vec::new();
    let mut offset = 0usize;
    while offset < payload.len() {
        let chunk = (payload.len() - offset).min(max_payload);
        let offset_units = offset / 8;
        if offset % 8 != 0 || offset_units > 0x1fff {
            return None;
        }
        let more = offset + chunk < payload.len();
        let mut frag = Vec::with_capacity(l3_offset + 20 + chunk);
        frag.extend_from_slice(eth);
        frag.extend_from_slice(&ip[..20]);
        frag.extend_from_slice(&payload[offset..offset + chunk]);
        let start = l3_offset;
        frag[start + 2..start + 4].copy_from_slice(&u16::try_from(20 + chunk).ok()?.to_be_bytes());
        frag[start + 4..start + 6].copy_from_slice(&ident.to_be_bytes());
        let word: u16 = u16::try_from(offset_units).ok()? | if more { 0x2000 } else { 0 };
        frag[start + 6..start + 8].copy_from_slice(&word.to_be_bytes());
        frag[start + 10..start + 12].fill(0);
        let csum = super::frame::checksum16(&frag[start..start + 20]);
        frag[start + 10..start + 12].copy_from_slice(&csum.to_be_bytes());
        fragments.push(frag);
        offset += chunk;
    }
    if fragments.is_empty() {
        return None;
    }
    Some(fragments)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outer_frame(payload_len: usize, df: bool) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 9]);
        frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]);
        frame.extend_from_slice(&0x0800u16.to_be_bytes());
        let l3 = frame.len();
        let total = 20 + payload_len;
        frame.push(0x45);
        frame.push(0);
        frame.extend_from_slice(&(total as u16).to_be_bytes());
        frame.extend_from_slice(&7u16.to_be_bytes());
        frame.extend_from_slice(&(if df { 0x4000u16 } else { 0 }).to_be_bytes());
        frame.extend_from_slice(&[64, 47, 0, 0]);
        frame.extend_from_slice(&[10, 0, 0, 1]);
        frame.extend_from_slice(&[10, 0, 0, 2]);
        let csum = crate::afxdp::frame::checksum16(&frame[l3..l3 + 20]);
        frame[l3 + 10..l3 + 12].copy_from_slice(&csum.to_be_bytes());
        frame.extend((0..payload_len).map(|i| i as u8));
        frame
    }

    #[test]
    fn fragments_reassemble_to_original_payload() {
        let frame = outer_frame(100, false);
        let frags = fragment_outer_ipv4_frame(&frame, 14, 60).expect("fragmentable");
        assert!(frags.len() > 1);
        let mut payload = Vec::new();
        for (i, frag) in frags.iter().enumerate() {
            let ip = &frag[14..];
            assert!(ip.len() <= 60, "fragment exceeds outer MTU");
            assert_eq!(u16::from_be_bytes([ip[4], ip[5]]), 7, "shared ID");
            let word = u16::from_be_bytes([ip[6], ip[7]]);
            assert_eq!((word & 0x1fff) as usize * 8, payload.len(), "offset chain");
            assert_eq!(word & 0x2000 != 0, i + 1 < frags.len(), "MF chain");
            // Header checksum verifies (one's-complement sum == 0).
            assert_eq!(crate::afxdp::frame::checksum16(&ip[..20]), 0);
            payload.extend_from_slice(&ip[20..]);
        }
        assert_eq!(payload, &frame[14 + 20..]);
    }

    #[test]
    fn df_outer_refused_and_fitting_outer_untouched() {
        assert!(fragment_outer_ipv4_frame(&outer_frame(100, true), 14, 60).is_none());
        let fits = outer_frame(40, false);
        assert_eq!(
            fragment_outer_ipv4_frame(&fits, 14, 1500).expect("fits"),
            vec![fits]
        );
    }

    #[test]
    fn eligibility_band_is_exact() {
        // GRE-1300 shape: budget 1276, inner 1280, outer 1304 > 1300.
        assert!(outer_frag_eligible(
            libc::AF_INET6,
            1280,
            1276,
            libc::AF_INET,
            1304,
            1300
        ));
        // Larger inner keeps PTB; v6 outer cannot fragment; fitting outer no-op.
        assert!(!outer_frag_eligible(
            libc::AF_INET6,
            1281,
            1276,
            libc::AF_INET,
            1305,
            1300
        ));
        assert!(!outer_frag_eligible(
            libc::AF_INET6,
            1280,
            1276,
            libc::AF_INET6,
            1324,
            1300
        ));
        assert!(!outer_frag_eligible(
            libc::AF_INET6,
            1280,
            1276,
            libc::AF_INET,
            1300,
            1300
        ));
        assert!(!outer_frag_eligible(
            libc::AF_INET,
            1280,
            1276,
            libc::AF_INET,
            1304,
            1300
        ));
    }
}
