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
// The verdicts live in the `core`-only `gre_classify` module: both
// classifiers call the scalar `gre_inner_fragment_or_length_rejected`
// and judge LAND via `gre_inner_land`. This file pulls that module
// (plus `land`, `ipv4_len_gate`, `ipv6_len_gate`, `ipv6_ext_walk`,
// and the shared extension walk) in by source and runs the real
// functions on real byte buffers. The walk leg runs
// `walk_ipv6_ext_headers` itself on chained Fragment headers — that
// leg guards the WORKER's walk, not the shim v6 classifier: shim v6
// never walks the inner chain, it bails on any non-terminal first
// header (see the v6 composition below).
//
// Production-wiring note: the classifier functions live in the BPF
// crate root and cannot be linked here (map reads). What is executed
// is the decision they delegate to, with arguments composed exactly
// as the call sites compose them:
//   * v4: fragment field mask 0x3fff, declared end from Total
//     Length via the len gate, span start = ihl, span = the arm's
//     read length, inner-L3-relative offsets; LAND via
//     `gre_inner_land` on the built key.
//   * v6 (#17238): fragment = `eh_class(first_header) !=
//     EH_CLASS_TERMINAL` (terminal-first-header bail, atomic
//     Fragment included), declared end = `40 + payload_len`, span
//     start = 40, span = the protocol's read length; LAND via
//     `gre_inner_land` on the built key. Before #17238 v6 hand-rolled
//     an inline length compare and its own LAND compare, and the v6
//     cells below executed a combined wrapper no production caller
//     used — a mutation of the v6 production checks could not red
//     any host cell.
// Both classifiers return the miss (0) on rejection.
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

use shim_gre::{gre_inner_fragment_or_length_rejected, gre_inner_land};

const V4_L3: usize = 38; // eth(14) + outer(20) + GRE(4): inner v4 starts here (v6 cells compose L3-relative)


fn v6_addr(last: u8) -> [u8; 16] {
    let mut buf = [0u8; 16];
    buf[0] = 0x20;
    buf[1] = 0x01;
    buf[15] = last;
    buf
}

/// Compose the v4 classifier verdict exactly as
/// `classify_native_gre_inner_ipv4` does (#17238): per arm it calls
/// the scalar verdict (fragment from bytes 6..8, declared end from
/// Total Length, span start = ihl, span = arm length), then judges
/// LAND via `gre_inner_land` on the built key. Allowed = scalar not
/// rejected AND not LAND, in production order (scalar per arm
/// first, LAND on the key after the L4 read — order is verdict-
/// identical, both must pass).
fn v4_allowed(iph: &[u8], l4_span_len: usize) -> bool {
    assert!(iph.len() >= 20);
    let ihl = ((iph[0] & 0x0f) as usize) * 4;
    let frag_field = u16::from_be_bytes([iph[6], iph[7]]);
    let inner_is_fragment = (frag_field & 0x3fff) != 0;
    let total_len = u16::from_be_bytes([iph[2], iph[3]]);
    if !shim_v4len::ipv4_declared_len_covers_header(total_len, ihl) {
        return false;
    }
    if gre_inner_fragment_or_length_rejected(
        inner_is_fragment,
        0,
        total_len as usize,
        ihl,
        l4_span_len,
    ) {
        return false;
    }
    let mut src = [0u8; 16];
    src[..4].copy_from_slice(&iph[12..16]);
    let mut dst = [0u8; 16];
    dst[..4].copy_from_slice(&iph[16..20]);
    !gre_inner_land(&src, &dst)
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

/// Compose the v6 classifier verdict exactly as
/// `classify_native_gre_inner_ipv6` does (#17238): one scalar call
/// with fragment = non-terminal first header, declared end =
/// `40 + payload_len` (inlined in production, not via the len-gate
/// helper — the helper call below reproduces that value from the
/// inner L3 start), span start = 40, span = the protocol's read
/// length; `payload_len == 0` (jumbogram) misses before the
/// verdict, as in production; LAND via `gre_inner_land` on the
/// built key. A mutation of the production v6 comparison
/// (e.g. `>` flipped, span or declared-end constants drifted) reds
/// these cells because they execute the same scalar function.
fn v6_allowed(first_header: u8, payload_len: u16, l4_span_len: usize, src: &[u8; 16], dst: &[u8; 16]) -> bool {
    if payload_len == 0 {
        return false;
    }
    // Mirror production: `eh_class(protocol) != EH_CLASS_TERMINAL`
    // on the first next-header. TCP (6) is terminal; Fragment (44)
    // and Hop-by-Hop (0) are not.
    let inner_is_fragment = shim_walk::eh_class(first_header) != shim_walk::EH_CLASS_TERMINAL;
    let declared_end = shim_v6len::ipv6_declared_end(0, payload_len);
    if gre_inner_fragment_or_length_rejected(inner_is_fragment, 0, declared_end, 40, l4_span_len) {
        return false;
    }
    !gre_inner_land(src, dst)
}

#[test]
fn gre_inner_land_rejected_14954() {
    // v4 LAND: src == dst.
    let same = [10, 0, 0, 9];
    assert!(!v4_allowed(&inner_v4(0, 40, same, same, 6), 14), "v4 inner LAND must miss");
    // v6 LAND via the production `gre_inner_land` on the built key.
    let a = v6_addr(7);
    let b = v6_addr(7);
    assert!(shim_land::is_land(&a, &b));
    assert!(gre_inner_land(&a, &b), "v6 inner LAND must be judged LAND");
    assert!(!v6_allowed(6, 14, 14, &a, &b), "v6 inner LAND must miss");
    // Distinct v6 addresses: control stays allowed.
    assert!(v6_allowed(6, 14, 14, &v6_addr(1), &v6_addr(2)), "distinct v6 inner must classify");
    assert!(!gre_inner_land(&v6_addr(1), &v6_addr(2)));
}

#[test]
fn gre_inner_v6_declared_length_and_fragment_14954() {
    let src = v6_addr(1);
    let dst = v6_addr(2);
    // payload_len covers exactly the TCP span (14): allowed.
    assert!(v6_allowed(6, 14, 14, &src, &dst), "v6 span at declared end allowed");
    // payload_len one short (13): span in slack past declared end.
    // RED if the production length compare flips or softens.
    assert!(!v6_allowed(6, 13, 14, &src, &dst), "v6 span past declared end must miss");
    // UDP span (8) fits where TCP span (14) does not.
    assert!(v6_allowed(17, 8, 8, &src, &dst), "v6 UDP span at declared end allowed");
    assert!(!v6_allowed(17, 7, 8, &src, &dst), "v6 UDP span one past declared end must miss");
    // Port-less terminal with span 0 (e.g. ESP 50, terminal with no
    // ports to read): length gate vacuous for the span.
    assert!(v6_allowed(50, 1, 0, &src, &dst), "v6 port-less terminal keeps classifying");
    // NoNext (59) is NONEXT, not TERMINAL: production's
    // `eh_class != TERMINAL` bail misses it before any span check.
    assert!(!v6_allowed(59, 1, 0, &src, &dst), "v6 NoNext first header must miss");
    // Non-terminal first header (Fragment 44, atomic or not — shim
    // v6 never walks, so even an atomic Fragment first header
    // misses, stricter than the worker walk) rejects regardless
    // of length. RED if production reverted to a walk verdict.
    assert!(!v6_allowed(44, 14, 14, &src, &dst), "v6 Fragment first header must miss");
    assert!(!v6_allowed(0, 14, 14, &src, &dst), "v6 Hop-by-Hop first header must miss");
    // Jumbogram escape: payload_len == 0 misses before the verdict.
    assert!(!v6_allowed(6, 0, 14, &src, &dst), "v6 jumbogram payload_len 0 must miss");
    // Span overflow cannot wrap into allowance (scalar verdict).
    assert!(gre_inner_fragment_or_length_rejected(false, 0, usize::MAX, usize::MAX - 4, 14), "span overflow must be rejected");
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
