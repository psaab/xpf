// #14954: GRE inner fragment / declared-length / LAND guards, EXECUTED.
//
// `classify_native_gre_inner*` (userspace-xdp/src/lib.rs) builds a
// `UserspaceSessionKey` from the INNER packet and, on a session/DNAT/
// local hit, steers the OUTER GRE frame — to the kernel on
// `PASS_TO_KERNEL`, to the helper on `REDIRECT` — without the inner ever
// being adjudicated by the worker. Before this fix it:
//   * ignored inner IPv4 fragmentation (MF/offset) and (via the
//     terminal-only bail) moot-checked inner IPv6 fragments, so ports
//     were read from fragment payload bytes;
//   * never consulted the inner declared lengths (v4 Total Length /
//     v6 Payload Length), so L4 spans were read from slack past the
//     declared datagram end (Ethernet pad / outer trailer);
//   * never compared inner src/dst, so an inner LAND packet rode a
//     PASS hit to the kernel decapsulated with no screen seeing it.
//
// The verdict lives in the `core`-only `gre_classify` module
// (`gre_inner_classify_allowed`, delegating to the scalar
// `gre_inner_fragment_or_length_rejected` the shim calls); this file
// pulls that module (plus `land`, `ipv4_len_gate`, `ipv6_len_gate`,
// and the shared extension walk) in by source and runs the real
// functions on real byte buffers. The walk leg runs
// `walk_ipv6_ext_headers` itself on chained Fragment headers.
//
// Production-wiring note: the classifier functions live in the BPF
// crate root and cannot be linked here (map reads). What is executed
// is the decision they delegate to, with arguments composed exactly
// as the call sites compose them (fragment field mask 0x3fff,
// declared end from the same len-gate helpers, span = the arm's read
// length, inner-L3-relative offsets). The lib.rs call sites judge
// LAND by direct address comparison and the scalar verdict per arm,
// returning the miss (0) on rejection.
#[path = "../../../../userspace-xdp/src/gre_classify.rs"]
mod shim_gre;
#[path = "../../../../userspace-xdp/src/land.rs"]
mod shim_land;
#[path = "../../../../userspace-xdp/src/ipv4_len_gate.rs"]
mod shim_v4len;
#[path = "../../../../userspace-xdp/src/ipv6_len_gate.rs"]
mod shim_v6len;
#[path = "../../../../userspace-xdp/src/ipv6_ext_walk.rs"]
mod shim_walk;

use shim_gre::gre_inner_classify_allowed;

const V4_L3: usize = 38; // eth(14) + outer(20) + GRE(4): inner v4 starts here
const V6_L3: usize = 38;


fn v6_addr(last: u8) -> [u8; 16] {
    let mut buf = [0u8; 16];
    buf[0] = 0x20;
    buf[1] = 0x01;
    buf[15] = last;
    buf
}

/// Compose the v4 classifier verdict exactly as
/// `classify_native_gre_inner_ipv4` does: fragment from bytes 6..8,
/// declared end from Total Length via the len gate, span = arm length.
fn v4_allowed(iph: &[u8], l4_span_len: usize) -> bool {
    assert!(iph.len() >= 20);
    let ihl = ((iph[0] & 0x0f) as usize) * 4;
    let frag_field = u16::from_be_bytes([iph[6], iph[7]]);
    let inner_is_fragment = (frag_field & 0x3fff) != 0;
    let total_len = u16::from_be_bytes([iph[2], iph[3]]);
    if !shim_v4len::ipv4_declared_len_covers_header(total_len, ihl) {
        return false;
    }
    let declared_end = V4_L3 + total_len as usize;
    let mut src = [0u8; 16];
    src[..4].copy_from_slice(&iph[12..16]);
    let mut dst = [0u8; 16];
    dst[..4].copy_from_slice(&iph[16..20]);
    gre_inner_classify_allowed(
        inner_is_fragment,
        &src,
        &dst,
        V4_L3,
        declared_end,
        V4_L3 + ihl,
        l4_span_len,
    )
}

fn inner_v4(frag_field: u16, total_len: u16, src: [u8; 4], dst: [u8; 4], proto: u8) -> Vec<u8> {
    let mut h = vec![0u8; 20];
    h[0] = 0x45;
    h[2..4].copy_from_slice(&total_len.to_be_bytes());
    h[6..8].copy_from_slice(&frag_field.to_be_bytes());
    h[9] = proto;
    h[12..16].copy_from_slice(&src);
    h[16..20].copy_from_slice(&dst);
    h
}

#[test]
fn gre_inner_v4_fragment_rejected_14954() {
    let src = [10, 0, 0, 1];
    let dst = [192, 0, 2, 1];
    // Whole datagram (DF only): allowed — control.
    assert!(v4_allowed(&inner_v4(0x4000, 40, src, dst, 6), 14), "whole TCP inner must classify");
    // First fragment (MF set, offset 0): the L4 header may be partial;
    // a steering key from it is payload-derived. RED pre-fix (no check).
    assert!(!v4_allowed(&inner_v4(0x2000, 40, src, dst, 6), 14), "MF first fragment must miss");
    // Non-first fragment (offset != 0): no L4 header at all here.
    assert!(!v4_allowed(&inner_v4(0x0001, 40, src, dst, 6), 14), "non-first fragment must miss");
    assert!(!v4_allowed(&inner_v4(0x2001, 40, src, dst, 17), 8), "MF+offset UDP must miss");
    // Reserved flag alone (0x8000) is not fragmentation.
    assert!(v4_allowed(&inner_v4(0x8000, 40, src, dst, 6), 14), "reserved-only is not a fragment");
}

#[test]
fn gre_inner_v4_declared_length_enforced_14954() {
    let src = [10, 0, 0, 1];
    let dst = [192, 0, 2, 1];
    // Declared exactly header+TCP span (20+14=34): allowed.
    assert!(v4_allowed(&inner_v4(0, 34, src, dst, 6), 14), "span ending at declared end allowed");
    // Declared header+4 only: TCP ports live in slack past the datagram.
    assert!(!v4_allowed(&inner_v4(0, 24, src, dst, 6), 14), "TCP span past declared end must miss");
    // Declared less than the header itself: impossible on the wire.
    assert!(!v4_allowed(&inner_v4(0, 10, src, dst, 6), 14), "total_len < ihl must miss");
    // UDP span (8) fits where TCP span (14) does not.
    assert!(v4_allowed(&inner_v4(0, 28, src, dst, 17), 8), "UDP span at declared end allowed");
    assert!(!v4_allowed(&inner_v4(0, 27, src, dst, 17), 8), "UDP span one past declared end must miss");
    // No-L4 protocol (span 0): length gate vacuous for the span.
    assert!(v4_allowed(&inner_v4(0, 20, src, dst, 47), 0), "port-less protocol keeps classifying");
}

#[test]
fn gre_inner_land_rejected_14954() {
    // v4 LAND: src == dst.
    let same = [10, 0, 0, 9];
    assert!(!v4_allowed(&inner_v4(0, 40, same, same, 6), 14), "v4 inner LAND must miss");
    // v6 LAND via the shared predicate shape the classifier uses.
    let a = v6_addr(7);
    let b = v6_addr(7);
    assert!(shim_land::is_land(&a, &b));
    assert!(!gre_inner_classify_allowed(false, &a, &b, V6_L3, V6_L3 + 40 + 14, V6_L3 + 40, 14), "v6 inner LAND must miss");
    // Distinct v6 addresses: control stays allowed.
    assert!(gre_inner_classify_allowed(false, &v6_addr(1), &v6_addr(2), V6_L3, V6_L3 + 40 + 14, V6_L3 + 40, 14), "distinct v6 inner must classify");
}

#[test]
fn gre_inner_v6_declared_length_and_fragment_14954() {
    let src = v6_addr(1);
    let dst = v6_addr(2);
    let l4 = V6_L3 + 40;
    // payload_len covers exactly the TCP span: allowed.
    assert!(gre_inner_classify_allowed(false, &src, &dst, V6_L3, shim_v6len::ipv6_declared_end(V6_L3, 14), l4, 14), "v6 span at declared end allowed");
    // payload_len one short: span in slack.
    assert!(!gre_inner_classify_allowed(false, &src, &dst, V6_L3, shim_v6len::ipv6_declared_end(V6_L3, 13), l4, 14), "v6 span past declared end must miss");
    // Fragment flag from the walk rejects regardless of length.
    assert!(!gre_inner_classify_allowed(true, &src, &dst, V6_L3, shim_v6len::ipv6_declared_end(V6_L3, 14), l4, 14), "v6 fragmented inner must miss");
    // Span overflow cannot wrap into allowance.
    assert!(!gre_inner_classify_allowed(false, &src, &dst, V6_L3, usize::MAX, usize::MAX - 4, 14), "span overflow must miss");
}

/// Build an inner-IPv6 packet at l3=0: fixed header (next=`first`),
/// then `chain` extension bytes, then TCP-ish payload.
fn v6_packet(first: u8, chain: &[u8]) -> Vec<u8> {
    let mut p = vec![0u8; 40];
    p[0] = 0x60;
    let payload_len = (chain.len() + 20) as u16;
    p[4..6].copy_from_slice(&payload_len.to_be_bytes());
    p[6] = first;
    p[8] = 0x20;
    p[9] = 0x01;
    p[23] = 1;
    p[24] = 0x20;
    p[25] = 0x01;
    p[39] = 2;
    p.extend_from_slice(chain);
    p.extend_from_slice(&[0x04, 0xd2, 0x00, 0x50, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    p
}

fn frag_hdr(next: u8, word: u16) -> [u8; 8] {
    let mut h = [0u8; 8];
    h[0] = next;
    h[2..4].copy_from_slice(&word.to_be_bytes());
    h[7] = 1;
    h
}

fn shim_walk(buf: &[u8]) -> shim_walk::ExtWalk {
    let data = buf.as_ptr() as usize;
    shim_walk::walk_ipv6_ext_headers(data, data + buf.len(), 0, buf[6], 40).expect("walk resolves")
}

#[test]
fn chained_atomic_fragment_does_not_reset_fragment_seen_14954() {
    // [DestOpts -> Frag(non-atomic: offset 0, M=1) -> Frag(atomic) -> TCP]
    // The second, atomic header must NOT erase the first sighting.
    // RED pre-fix: `fragment_seen` resets to false on the atomic header.
    let mut chain = Vec::new();
    let mut dest = [0u8; 8];
    dest[0] = 44; // next = Fragment
    chain.extend_from_slice(&dest);
    chain.extend_from_slice(&frag_hdr(44, 0x0001)); // offset 0, M=1 (first, non-atomic)
    chain.extend_from_slice(&frag_hdr(6, 0x0000)); // atomic: offset 0, M=0
    let pkt = v6_packet(60, &chain);
    let w = shim_walk(&pkt);
    assert!(w.fragment_seen, "chained atomic header erased the non-atomic fragment sighting");
    assert!(!w.non_first_fragment, "offset-0 fragments are not non-first");

    // [atomic][atomic] alone: whole datagrams, stay non-fragment (control).
    let mut chain2 = Vec::new();
    chain2.extend_from_slice(&frag_hdr(44, 0x0000));
    chain2.extend_from_slice(&frag_hdr(6, 0x0000));
    let pkt2 = v6_packet(44, &chain2);
    let w2 = shim_walk(&pkt2);
    assert!(!w2.fragment_seen, "double-atomic chain is a whole datagram");
    assert_eq!(w2.protocol, 6, "atomic chain resolves to TCP");

    // Single atomic: control, non-fragment.
    let pkt3 = v6_packet(44, &frag_hdr(6, 0x0000));
    assert!(!shim_walk(&pkt3).fragment_seen, "single atomic is not a fragment");

    // Single first fragment (M=1): fragment (control).
    let pkt4 = v6_packet(44, &frag_hdr(6, 0x0001));
    assert!(shim_walk(&pkt4).fragment_seen, "first fragment (M set) is a fragment");

    // Non-first then atomic-shaped payload: walk stops at non-first.
    let pkt5 = v6_packet(44, &frag_hdr(6, 0x0008));
    let w5 = shim_walk(&pkt5);
    assert!(w5.fragment_seen && w5.non_first_fragment, "non-first sighting latched");
}
