// #989: targeted unit tests for the relocated TCP helpers. Per
// design doc rev-3 §2.3, these directly exercise the parser-edge
// cases for clamp_tcp_mss that integration tests don't cover:
// MSS-not-at-start, malformed option lengths, EOL before MSS,
// multiple MSS options, IPv6 pseudo-header recompute, non-SYN
// no-op, and the no-op-when-already-smaller path.
//
// `clamp_tcp_mss` checksum sanity: every "mutated checksum is still
// valid" claim is verified by independent recomputation (sum the
// pseudo-header + TCP segment, verify the folded value is 0xFFFF).
// The incremental update path inside clamp_tcp_mss is not trusted
// blindly — these tests provide an oracle via from-scratch sum.

use super::*;

// ---------- Frame builders (Ethernet + IPv4/IPv6 + TCP) ----------

const ETH_HDR_LEN: usize = 14;
const IPV4_HDR_LEN: usize = 20;
const IPV6_HDR_LEN: usize = 40;
const TCP_FLAG_SYN: u8 = 0x02;
const TCP_FLAG_ACK: u8 = 0x10;

/// Build an Ethernet header with given EtherType (0x0800 v4, 0x86dd v6).
fn eth_header(ethertype: u16) -> [u8; ETH_HDR_LEN] {
    let mut eth = [0u8; ETH_HDR_LEN];
    // dst+src MAC zero, ethertype at offset 12.
    eth[12..14].copy_from_slice(&ethertype.to_be_bytes());
    eth
}

/// Build IPv4 header (no options, fixed 20-byte). Caller supplies
/// `total_len` (full IPv4 datagram length including this header)
/// and `protocol` (e.g. 6 for TCP).
fn ipv4_header(total_len: u16, protocol: u8) -> [u8; IPV4_HDR_LEN] {
    let mut ip = [0u8; IPV4_HDR_LEN];
    ip[0] = 0x45; // version=4, IHL=5
    ip[2..4].copy_from_slice(&total_len.to_be_bytes());
    ip[8] = 64; // TTL
    ip[9] = protocol;
    ip[12..16].copy_from_slice(&[10, 0, 0, 1]); // src
    ip[16..20].copy_from_slice(&[10, 0, 0, 2]); // dst
    // header checksum computed by caller if needed
    ip
}

/// Build IPv6 header. `payload_len` is the L4+payload size.
fn ipv6_header(payload_len: u16, next_header: u8) -> [u8; IPV6_HDR_LEN] {
    let mut ip6 = [0u8; IPV6_HDR_LEN];
    ip6[0] = 0x60; // version=6
    ip6[4..6].copy_from_slice(&payload_len.to_be_bytes());
    ip6[6] = next_header;
    ip6[7] = 64; // hop limit
    // src = fe00::1, dst = fe00::2 — high byte 0xfe is just to
    // make the address recognizably non-zero in failure dumps.
    ip6[8] = 0xfe;
    ip6[8 + 15] = 0x01;
    ip6[24] = 0xfe;
    ip6[24 + 15] = 0x02;
    ip6
}

/// Build a 20-byte TCP header skeleton with the given flags.
/// `data_offset_dwords` is the data-offset field value (TCP header
/// length in 4-byte units, e.g. 5 for no options, 7 for 8 bytes
/// of options, etc.).
fn tcp_header_skeleton(flags: u8, data_offset_dwords: u8) -> [u8; 20] {
    let mut tcp = [0u8; 20];
    // src port 12345, dst port 80
    tcp[0..2].copy_from_slice(&12345u16.to_be_bytes());
    tcp[2..4].copy_from_slice(&80u16.to_be_bytes());
    // seq=1, ack=0
    tcp[4..8].copy_from_slice(&1u32.to_be_bytes());
    // data offset (high nibble of byte 12)
    tcp[12] = data_offset_dwords << 4;
    tcp[13] = flags;
    tcp[14..16].copy_from_slice(&65535u16.to_be_bytes()); // window
    // checksum at 16..18 set later
    tcp
}

/// Independent ones-complement TCP checksum: sums pseudo-header
/// (v4 or v6) + TCP segment bytes, returns the folded 16-bit value.
/// On a properly-checksummed segment this returns 0xFFFF.
fn checksum_tcp_v4(src: [u8; 4], dst: [u8; 4], tcp: &[u8]) -> u16 {
    let tcp_len = tcp.len() as u16;
    let mut sum: u32 = 0;
    // Pseudo-header: src(4) + dst(4) + zero(1) + protocol(1) + tcp_len(2)
    for chunk in src.chunks(2).chain(dst.chunks(2)) {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    sum += u32::from(6u16); // protocol
    sum += u32::from(tcp_len);
    // TCP segment
    let mut i = 0;
    while i + 1 < tcp.len() {
        sum += u32::from(u16::from_be_bytes([tcp[i], tcp[i + 1]]));
        i += 2;
    }
    if i < tcp.len() {
        sum += u32::from(u16::from_be_bytes([tcp[i], 0]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum as u16
}

/// IPv6 pseudo-header variant.
fn checksum_tcp_v6(src: [u8; 16], dst: [u8; 16], tcp: &[u8]) -> u16 {
    let tcp_len = tcp.len() as u32;
    let mut sum: u32 = 0;
    for chunk in src.chunks(2).chain(dst.chunks(2)) {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    sum += tcp_len; // 32-bit length
    sum += 6u32; // next header
    let mut i = 0;
    while i + 1 < tcp.len() {
        sum += u32::from(u16::from_be_bytes([tcp[i], tcp[i + 1]]));
        i += 2;
    }
    if i < tcp.len() {
        sum += u32::from(u16::from_be_bytes([tcp[i], 0]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum as u16
}

/// Set a v4 TCP segment's checksum so that
/// `checksum_tcp_v4(src, dst, tcp) == 0xFFFF`.
fn set_v4_tcp_checksum(tcp: &mut [u8], src: [u8; 4], dst: [u8; 4]) {
    tcp[16..18].copy_from_slice(&[0, 0]);
    let raw = checksum_tcp_v4(src, dst, tcp);
    let csum = !raw;
    tcp[16..18].copy_from_slice(&csum.to_be_bytes());
}

fn set_v6_tcp_checksum(tcp: &mut [u8], src: [u8; 16], dst: [u8; 16]) {
    tcp[16..18].copy_from_slice(&[0, 0]);
    let raw = checksum_tcp_v6(src, dst, tcp);
    let csum = !raw;
    tcp[16..18].copy_from_slice(&csum.to_be_bytes());
}

// ---------- frame_has_tcp_rst ----------

#[test]
fn frame_has_tcp_rst_true_when_rst_set() {
    let eth = eth_header(0x0800);
    let ip = ipv4_header(40, 6);
    let tcp = tcp_header_skeleton(0x04, 5); // RST
    let mut frame = Vec::with_capacity(54);
    frame.extend_from_slice(&eth);
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&tcp);
    assert!(frame_has_tcp_rst(&frame));
}

#[test]
fn frame_has_tcp_rst_false_when_rst_clear() {
    let eth = eth_header(0x0800);
    let ip = ipv4_header(40, 6);
    let tcp = tcp_header_skeleton(TCP_FLAG_SYN, 5);
    let mut frame = Vec::with_capacity(54);
    frame.extend_from_slice(&eth);
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&tcp);
    assert!(!frame_has_tcp_rst(&frame));
}

#[test]
fn frame_has_tcp_rst_false_for_non_tcp() {
    let eth = eth_header(0x0800);
    let ip = ipv4_header(28, 17); // UDP
    let mut frame = Vec::with_capacity(42);
    frame.extend_from_slice(&eth);
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&[0u8; 8]); // UDP header
    assert!(!frame_has_tcp_rst(&frame));
}

#[test]
fn frame_has_tcp_rst_false_for_truncated() {
    // Only Ethernet + 5 bytes — too short for an IP header.
    let mut frame = Vec::with_capacity(20);
    frame.extend_from_slice(&eth_header(0x0800));
    frame.extend_from_slice(&[0u8; 5]);
    assert!(!frame_has_tcp_rst(&frame));
}

// ---------- extract_tcp_flags_and_window ----------

#[test]
fn extract_tcp_flags_and_window_returns_syn_ack_window() {
    let eth = eth_header(0x0800);
    let ip = ipv4_header(40, 6);
    let mut tcp = tcp_header_skeleton(TCP_FLAG_SYN | TCP_FLAG_ACK, 5);
    tcp[14..16].copy_from_slice(&8192u16.to_be_bytes());
    let mut frame = Vec::with_capacity(54);
    frame.extend_from_slice(&eth);
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&tcp);
    let (flags, window) = extract_tcp_flags_and_window(&frame).expect("Some");
    assert_eq!(flags, TCP_FLAG_SYN | TCP_FLAG_ACK);
    assert_eq!(window, 8192);
}

#[test]
fn extract_tcp_flags_and_window_handles_fin_ack() {
    let eth = eth_header(0x0800);
    let ip = ipv4_header(40, 6);
    let tcp = tcp_header_skeleton(0x01 | TCP_FLAG_ACK, 5); // FIN+ACK
    let mut frame = Vec::with_capacity(54);
    frame.extend_from_slice(&eth);
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&tcp);
    let (flags, _window) = extract_tcp_flags_and_window(&frame).expect("Some");
    assert_eq!(flags, 0x01 | TCP_FLAG_ACK);
}

#[test]
fn extract_tcp_flags_and_window_returns_none_for_truncated() {
    let mut frame = Vec::with_capacity(28);
    frame.extend_from_slice(&eth_header(0x0800));
    frame.extend_from_slice(&ipv4_header(20, 6)); // claims TCP but no TCP bytes follow
    assert!(extract_tcp_flags_and_window(&frame).is_none());
}

// ---------- extract_tcp_window ----------

#[test]
fn extract_tcp_window_v4_v6() {
    // v4
    let mut frame4 = Vec::new();
    frame4.extend_from_slice(&eth_header(0x0800));
    frame4.extend_from_slice(&ipv4_header(40, 6));
    let mut tcp4 = tcp_header_skeleton(0, 5);
    tcp4[14..16].copy_from_slice(&4096u16.to_be_bytes());
    frame4.extend_from_slice(&tcp4);
    assert_eq!(
        extract_tcp_window(&frame4, libc::AF_INET as u8),
        Some(4096)
    );
    // v6
    let mut frame6 = Vec::new();
    frame6.extend_from_slice(&eth_header(0x86dd));
    frame6.extend_from_slice(&ipv6_header(20, 6));
    let mut tcp6 = tcp_header_skeleton(0, 5);
    tcp6[14..16].copy_from_slice(&2048u16.to_be_bytes());
    frame6.extend_from_slice(&tcp6);
    assert_eq!(
        extract_tcp_window(&frame6, libc::AF_INET6 as u8),
        Some(2048)
    );
}

#[test]
fn extract_tcp_window_returns_none_for_truncated() {
    let mut frame = Vec::new();
    frame.extend_from_slice(&eth_header(0x0800));
    frame.extend_from_slice(&ipv4_header(20, 6)); // no TCP bytes
    assert_eq!(extract_tcp_window(&frame, libc::AF_INET as u8), None);
}

// ---------- tcp_flags_str ----------

#[test]
fn tcp_flags_str_renders_zero_as_none() {
    assert_eq!(tcp_flags_str(0), "none");
}

#[test]
fn tcp_flags_str_renders_single_flag() {
    assert_eq!(tcp_flags_str(TCP_FLAG_SYN), "SYN");
    assert_eq!(tcp_flags_str(TCP_FLAG_ACK), "ACK");
    assert_eq!(tcp_flags_str(0x04), "RST");
}

#[test]
fn tcp_flags_str_renders_combinations() {
    assert_eq!(tcp_flags_str(TCP_FLAG_SYN | TCP_FLAG_ACK), "SYN ACK");
    assert_eq!(
        tcp_flags_str(TCP_FLAG_ACK | 0x08),
        "ACK PSH",
        "ACK+PSH ordering matches the in-source flag-iteration order"
    );
}

#[test]
fn tcp_flags_str_renders_all_flags() {
    let all = TCP_FLAG_SYN | TCP_FLAG_ACK | 0x01 | 0x04 | 0x08 | 0x20;
    assert_eq!(tcp_flags_str(all), "SYN ACK FIN RST PSH URG");
}

// ---------- clamp_tcp_mss: parser-edge cases ----------

/// Helper: build a v4 IP+TCP packet (no Ethernet header) with a
/// configurable TCP options trailer. `flags` controls the TCP
/// flags; `options` is appended after the 20-byte TCP header.
/// Returns the L3+L4 buffer plus the source/dst v4 addrs for
/// independent checksum verification.
fn build_v4_ip_tcp_with_options(flags: u8, options: &[u8]) -> (Vec<u8>, [u8; 4], [u8; 4]) {
    // TCP header is 20 bytes + options. data_offset = (20 + opts) / 4.
    let pad = (4 - (options.len() % 4)) % 4;
    let mut opts = options.to_vec();
    opts.resize(opts.len() + pad, 0); // pad with NOP-like zero bytes (EOL is fine)
    let tcp_total = 20 + opts.len();
    assert!(tcp_total % 4 == 0, "TCP header must be 4-byte aligned");
    let data_offset = (tcp_total / 4) as u8;

    let total_ip = (IPV4_HDR_LEN + tcp_total) as u16;
    let ip = ipv4_header(total_ip, 6);
    let mut tcp = vec![0u8; tcp_total];
    tcp[..20].copy_from_slice(&tcp_header_skeleton(flags, data_offset));
    tcp[20..].copy_from_slice(&opts);

    let src = [10, 0, 0, 1];
    let dst = [10, 0, 0, 2];
    set_v4_tcp_checksum(&mut tcp, src, dst);

    let mut packet = Vec::with_capacity(IPV4_HDR_LEN + tcp_total);
    packet.extend_from_slice(&ip);
    packet.extend_from_slice(&tcp);
    (packet, src, dst)
}

fn build_v6_ip_tcp_with_options(flags: u8, options: &[u8]) -> (Vec<u8>, [u8; 16], [u8; 16]) {
    let pad = (4 - (options.len() % 4)) % 4;
    let mut opts = options.to_vec();
    opts.resize(opts.len() + pad, 0);
    let tcp_total = 20 + opts.len();
    let data_offset = (tcp_total / 4) as u8;
    let ip6 = ipv6_header(tcp_total as u16, 6);
    let mut tcp = vec![0u8; tcp_total];
    tcp[..20].copy_from_slice(&tcp_header_skeleton(flags, data_offset));
    tcp[20..].copy_from_slice(&opts);

    let mut src = [0u8; 16];
    src[0] = 0xfe;
    src[15] = 0x01;
    let mut dst = [0u8; 16];
    dst[0] = 0xfe;
    dst[15] = 0x02;
    set_v6_tcp_checksum(&mut tcp, src, dst);

    let mut packet = Vec::with_capacity(IPV6_HDR_LEN + tcp_total);
    packet.extend_from_slice(&ip6);
    packet.extend_from_slice(&tcp);
    (packet, src, dst)
}

/// Strip the L3 header from a packet so the MSS-option assertions
/// can index into the TCP segment directly.
fn tcp_segment_v4(packet: &[u8]) -> &[u8] {
    &packet[IPV4_HDR_LEN..]
}

#[test]
fn clamp_tcp_mss_clamps_when_mss_at_start_of_options() {
    // MSS option (kind=2, len=4, value=1460) at TCP offset 20.
    let opts = [2, 4, 0x05, 0xb4]; // 1460 BE
    let (mut packet, src, dst) = build_v4_ip_tcp_with_options(TCP_FLAG_SYN, &opts);

    let clamped = clamp_tcp_mss(&mut packet, 1200);
    assert!(clamped, "MSS 1460 > 1200 → must clamp");

    // MSS bytes at TCP offset 22..24 are now 1200.
    let tcp = tcp_segment_v4(&packet);
    assert_eq!(u16::from_be_bytes([tcp[22], tcp[23]]), 1200);

    // Independent checksum recompute.
    let folded = checksum_tcp_v4(src, dst, tcp);
    assert_eq!(
        folded, 0xFFFF,
        "post-clamp TCP checksum must independently fold to 0xFFFF"
    );
}

#[test]
fn clamp_tcp_mss_walks_past_nop_and_timestamp_to_find_mss() {
    // NOP NOP TIMESTAMP(8) MSS(4) — MSS NOT at start.
    let opts = [
        1, 1, // 2x NOP
        8, 10, 0, 0, 0, 1, 0, 0, 0, 0, // TS option (kind=8, len=10)
        2, 4, 0x05, 0xb4, // MSS=1460
    ];
    let (mut packet, src, dst) = build_v4_ip_tcp_with_options(TCP_FLAG_SYN, &opts);

    assert!(clamp_tcp_mss(&mut packet, 1300));
    let tcp = tcp_segment_v4(&packet);
    // MSS option is at TCP offset 20 + 2 + 10 = 32; value at 34..36.
    assert_eq!(u16::from_be_bytes([tcp[34], tcp[35]]), 1300);
    assert_eq!(checksum_tcp_v4(src, dst, tcp), 0xFFFF);
}

#[test]
fn clamp_tcp_mss_eol_before_mss_is_no_op() {
    // EOL (kind=0) terminates options before MSS — clamp must skip.
    let opts = [
        0, 0, 0, 0, // EOL + padding
        2, 4, 0x05, 0xb4, // MSS option (unreachable due to EOL)
    ];
    let (mut packet, src, dst) = build_v4_ip_tcp_with_options(TCP_FLAG_SYN, &opts);
    let pre = packet.clone();

    let clamped = clamp_tcp_mss(&mut packet, 1200);
    assert!(!clamped, "EOL before MSS → clamp must be a no-op");
    assert_eq!(packet, pre, "no bytes mutated when MSS unreachable");
    let tcp = tcp_segment_v4(&packet);
    assert_eq!(
        checksum_tcp_v4(src, dst, tcp),
        0xFFFF,
        "checksum unchanged"
    );
}

#[test]
fn clamp_tcp_mss_first_mss_only_when_multiple_present() {
    // Two MSS options. clamp_tcp_mss returns after rewriting the
    // first match; second one stays untouched. (This documents
    // current behavior — the parser is not RFC-strict on multiples.)
    let opts = [
        2, 4, 0x05, 0xb4, // MSS=1460 (first)
        2, 4, 0x05, 0xb4, // MSS=1460 (second)
    ];
    let (mut packet, src, dst) = build_v4_ip_tcp_with_options(TCP_FLAG_SYN, &opts);

    assert!(clamp_tcp_mss(&mut packet, 1200));
    let tcp = tcp_segment_v4(&packet);
    assert_eq!(
        u16::from_be_bytes([tcp[22], tcp[23]]),
        1200,
        "first MSS clamped"
    );
    assert_eq!(
        u16::from_be_bytes([tcp[26], tcp[27]]),
        1460,
        "second MSS untouched (parser stops at first)"
    );
    // Checksum was incrementally adjusted only for the first
    // rewrite — but the second MSS field's bytes are unchanged, so
    // the segment as a whole still folds correctly when summed
    // against the new value.
    assert_eq!(checksum_tcp_v4(src, dst, tcp), 0xFFFF);
}

#[test]
fn clamp_tcp_mss_malformed_option_length_bails_safely() {
    // kind=42 (unknown) with len=0 → would loop infinitely if not
    // guarded; len=1 is also invalid (must be >= 2). Both must
    // cause the parser to break out without clamping or panicking.
    let opts_len0 = [42, 0, 0, 0];
    let (mut packet, _, _) = build_v4_ip_tcp_with_options(TCP_FLAG_SYN, &opts_len0);
    let pre = packet.clone();
    let clamped = clamp_tcp_mss(&mut packet, 100);
    assert!(!clamped);
    assert_eq!(packet, pre);

    let opts_len1 = [42, 1, 2, 4];
    let (mut packet, _, _) = build_v4_ip_tcp_with_options(TCP_FLAG_SYN, &opts_len1);
    let pre = packet.clone();
    let clamped = clamp_tcp_mss(&mut packet, 100);
    assert!(!clamped);
    assert_eq!(packet, pre);
}

#[test]
fn clamp_tcp_mss_opt_len_past_data_offset_bails() {
    // Gemini round-2 gap: a TCP option whose length field walks
    // PAST the end of the TCP-options region (pos + opt_len >
    // data_offset) must cause the parser to break out, not OOB.
    //
    // Construct: a single option at TCP offset 20 with kind=42 and
    // len=20. data_offset for a 24-byte TCP header = 6 dwords, so
    // the options region is exactly 4 bytes (20..24). An opt_len of
    // 20 takes pos=20+20=40, which is well past data_offset=24.
    // The parser must hit the `pos + opt_len > data_offset` branch
    // at the bounds check inside clamp_tcp_mss and break out
    // without rewriting anything or panicking.
    let opts = [42, 20, 0xaa, 0xbb]; // kind=42, malformed len=20
    let (mut packet, src, dst) = build_v4_ip_tcp_with_options(TCP_FLAG_SYN, &opts);
    let pre = packet.clone();
    let clamped = clamp_tcp_mss(&mut packet, 100);
    assert!(!clamped, "opt_len past data_offset → no rewrite");
    assert_eq!(
        packet, pre,
        "no bytes mutated when option length walks past options end"
    );
    assert_eq!(
        checksum_tcp_v4(src, dst, tcp_segment_v4(&packet)),
        0xFFFF,
        "checksum unchanged on parser bail-out"
    );
}

#[test]
fn clamp_tcp_mss_non_syn_is_no_op() {
    // ACK-only (no SYN bit) → clamp_tcp_mss must not touch.
    let opts = [2, 4, 0x05, 0xb4];
    let (mut packet, src, dst) = build_v4_ip_tcp_with_options(TCP_FLAG_ACK, &opts);
    let pre = packet.clone();
    let clamped = clamp_tcp_mss(&mut packet, 1200);
    assert!(!clamped, "non-SYN must be no-op");
    assert_eq!(packet, pre);
    assert_eq!(checksum_tcp_v4(src, dst, tcp_segment_v4(&packet)), 0xFFFF);
}

#[test]
fn clamp_tcp_mss_no_op_when_mss_already_smaller() {
    // current_mss = 1000, max_mss = 1200 → no rewrite.
    let opts = [2, 4, 0x03, 0xe8]; // MSS=1000
    let (mut packet, src, dst) = build_v4_ip_tcp_with_options(TCP_FLAG_SYN, &opts);
    let pre = packet.clone();
    let clamped = clamp_tcp_mss(&mut packet, 1200);
    assert!(!clamped, "MSS 1000 <= 1200 → no rewrite");
    assert_eq!(packet, pre, "bytes unchanged on no-op");
    assert_eq!(
        checksum_tcp_v4(src, dst, tcp_segment_v4(&packet)),
        0xFFFF,
        "checksum unchanged on no-op"
    );
}

#[test]
fn clamp_tcp_mss_v6_recomputes_with_pseudoheader() {
    let opts = [2, 4, 0x05, 0xb4];
    let (mut packet, src, dst) = build_v6_ip_tcp_with_options(TCP_FLAG_SYN, &opts);

    let clamped = clamp_tcp_mss(&mut packet, 1200);
    assert!(clamped, "IPv6 SYN with MSS=1460 → must clamp to 1200");

    let tcp = &packet[IPV6_HDR_LEN..];
    assert_eq!(u16::from_be_bytes([tcp[22], tcp[23]]), 1200);
    // IPv6 pseudo-header recompute: must still fold to 0xFFFF.
    assert_eq!(
        checksum_tcp_v6(src, dst, tcp),
        0xFFFF,
        "post-clamp v6 TCP checksum must fold to 0xFFFF with IPv6 pseudo-header"
    );
}

// ---------- clamp_tcp_mss_frame ----------

#[test]
fn clamp_tcp_mss_frame_clamps_full_ethernet_frame_v4() {
    let opts = [2, 4, 0x05, 0xb4];
    let (l3_packet, src, dst) = build_v4_ip_tcp_with_options(TCP_FLAG_SYN, &opts);
    let mut frame = Vec::with_capacity(ETH_HDR_LEN + l3_packet.len());
    frame.extend_from_slice(&eth_header(0x0800));
    frame.extend_from_slice(&l3_packet);

    let clamped = clamp_tcp_mss_frame(&mut frame, ETH_HDR_LEN, 1200);
    assert!(clamped);
    let tcp = &frame[ETH_HDR_LEN + IPV4_HDR_LEN..];
    assert_eq!(u16::from_be_bytes([tcp[22], tcp[23]]), 1200);
    assert_eq!(checksum_tcp_v4(src, dst, tcp), 0xFFFF);
}

#[test]
fn clamp_tcp_mss_frame_clamps_full_ethernet_frame_v6() {
    let opts = [2, 4, 0x05, 0xb4];
    let (l3_packet, src, dst) = build_v6_ip_tcp_with_options(TCP_FLAG_SYN, &opts);
    let mut frame = Vec::with_capacity(ETH_HDR_LEN + l3_packet.len());
    frame.extend_from_slice(&eth_header(0x86dd));
    frame.extend_from_slice(&l3_packet);

    let clamped = clamp_tcp_mss_frame(&mut frame, ETH_HDR_LEN, 1200);
    assert!(clamped);
    let tcp = &frame[ETH_HDR_LEN + IPV6_HDR_LEN..];
    assert_eq!(u16::from_be_bytes([tcp[22], tcp[23]]), 1200);
    assert_eq!(checksum_tcp_v6(src, dst, tcp), 0xFFFF);
}

// ---------- #2089 build_reject_rst_frame ----------

const TCP_FLAG_RST: u8 = 0x04;
const ETH_MIN_FRAME_LEN: usize = 60;

/// Full v4 TCP frame with explicit MACs, seq/ack, and flags.
fn reject_v4_tcp_frame(flags: u8, seq: u32, ack: u32) -> Vec<u8> {
    let mut eth = eth_header(0x0800);
    eth[0..6].copy_from_slice(&[0x02, 0, 0, 0, 0, 0xdd]); // dst (firewall)
    eth[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, 0xcc]); // src (client)
    let ip = ipv4_header(40, 6);
    let mut tcp = tcp_header_skeleton(flags, 5);
    tcp[4..8].copy_from_slice(&seq.to_be_bytes());
    tcp[8..12].copy_from_slice(&ack.to_be_bytes());
    let mut frame = Vec::with_capacity(54);
    frame.extend_from_slice(&eth);
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&tcp);
    frame
}

/// Full v6 TCP frame with explicit MACs, seq/ack, and flags.
fn reject_v6_tcp_frame(flags: u8, seq: u32, ack: u32) -> Vec<u8> {
    let mut eth = eth_header(0x86dd);
    eth[0..6].copy_from_slice(&[0x02, 0, 0, 0, 0, 0xdd]);
    eth[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, 0xcc]);
    let ip = ipv6_header(20, 6);
    let mut tcp = tcp_header_skeleton(flags, 5);
    tcp[4..8].copy_from_slice(&seq.to_be_bytes());
    tcp[8..12].copy_from_slice(&ack.to_be_bytes());
    let mut frame = Vec::with_capacity(74);
    frame.extend_from_slice(&eth);
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&tcp);
    frame
}

#[test]
fn reject_rst_v4_for_syn_acks_seq_plus_one_with_macs_and_ips_swapped() {
    let frame = reject_v4_tcp_frame(TCP_FLAG_SYN, 0x1111_2222, 0);
    let out = build_reject_rst_frame(&frame).expect("RST for SYN");
    // Ethernet padded to 60 bytes.
    assert_eq!(out.len(), ETH_MIN_FRAME_LEN);
    // MAC swap: reply dst = inbound src (client), reply src = inbound dst.
    assert_eq!(&out[0..6], &[0x02, 0, 0, 0, 0, 0xcc]);
    assert_eq!(&out[6..12], &[0x02, 0, 0, 0, 0, 0xdd]);
    // IP swap: reply src = inbound dst (10.0.0.2), reply dst = inbound src.
    assert_eq!(&out[ETH_HDR_LEN + 12..ETH_HDR_LEN + 16], &[10, 0, 0, 2]);
    assert_eq!(&out[ETH_HDR_LEN + 16..ETH_HDR_LEN + 20], &[10, 0, 0, 1]);
    let tcp = &out[ETH_HDR_LEN + IPV4_HDR_LEN..ETH_HDR_LEN + IPV4_HDR_LEN + 20];
    // Ports swapped.
    assert_eq!(u16::from_be_bytes([tcp[0], tcp[1]]), 80);
    assert_eq!(u16::from_be_bytes([tcp[2], tcp[3]]), 12345);
    // No-ACK inbound: seq=0, ack=inbound_seq+1, flags RST|ACK.
    assert_eq!(u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]), 0);
    assert_eq!(
        u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]),
        0x1111_2223
    );
    assert_eq!(tcp[13], TCP_FLAG_RST | TCP_FLAG_ACK);
    // RST window forced to 0.
    assert_eq!(u16::from_be_bytes([tcp[14], tcp[15]]), 0);
    // Checksum valid (independent recompute folds to 0xFFFF).
    assert_eq!(checksum_tcp_v4([10, 0, 0, 2], [10, 0, 0, 1], tcp), 0xFFFF);
}

/// #9499: a SYN at the top of the sequence space wraps the RST's ack to 0.
///
/// The ack is `seq.wrapping_add(consumed)`. An unchecked `+` there computes the
/// same wrapped value in a release build without overflow checks, so every
/// value assertion in this file stays green on the release leg; only a leg
/// with overflow checks turns it into a failure, and only if a test drives
/// the addition across `u32::MAX`. This is that test.
#[test]
fn reject_rst_v4_for_syn_at_seq_max_wraps_ack_to_zero_9499() {
    let frame = reject_v4_tcp_frame(TCP_FLAG_SYN, u32::MAX, 0);
    let out = build_reject_rst_frame(&frame).expect("RST for SYN");
    let tcp = &out[ETH_HDR_LEN + IPV4_HDR_LEN..ETH_HDR_LEN + IPV4_HDR_LEN + 20];
    assert_eq!(u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]), 0);
    assert_eq!(tcp[13], TCP_FLAG_RST | TCP_FLAG_ACK);
}

#[test]
fn reject_rst_v4_for_ack_uses_inbound_ack_no_ack_flag() {
    // ACK-bearing inbound (no SYN): RST seq=inbound_ack, flags RST only.
    let frame = reject_v4_tcp_frame(TCP_FLAG_ACK, 0x5555_0000, 0x9999_8888);
    let out = build_reject_rst_frame(&frame).expect("RST for ACK");
    let tcp = &out[ETH_HDR_LEN + IPV4_HDR_LEN..ETH_HDR_LEN + IPV4_HDR_LEN + 20];
    assert_eq!(
        u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]),
        0x9999_8888
    );
    assert_eq!(tcp[13], TCP_FLAG_RST);
    assert_eq!(tcp[13] & TCP_FLAG_ACK, 0, "ACK flag must be clear");
    assert_eq!(checksum_tcp_v4([10, 0, 0, 2], [10, 0, 0, 1], tcp), 0xFFFF);
}

#[test]
fn reject_rst_v6_for_syn_acks_seq_plus_one() {
    let frame = reject_v6_tcp_frame(TCP_FLAG_SYN, 7, 0);
    let out = build_reject_rst_frame(&frame).expect("v6 RST for SYN");
    // MAC swap.
    assert_eq!(&out[0..6], &[0x02, 0, 0, 0, 0, 0xcc]);
    let mut src = [0u8; 16];
    src.copy_from_slice(&out[ETH_HDR_LEN + 8..ETH_HDR_LEN + 24]);
    let mut dst = [0u8; 16];
    dst.copy_from_slice(&out[ETH_HDR_LEN + 24..ETH_HDR_LEN + 40]);
    let tcp = &out[ETH_HDR_LEN + IPV6_HDR_LEN..ETH_HDR_LEN + IPV6_HDR_LEN + 20];
    assert_eq!(u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]), 0);
    assert_eq!(u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]), 8);
    assert_eq!(tcp[13], TCP_FLAG_RST | TCP_FLAG_ACK);
    assert_eq!(checksum_tcp_v6(src, dst, tcp), 0xFFFF);
}

#[test]
fn reject_rst_never_answers_inbound_rst() {
    let frame = reject_v4_tcp_frame(TCP_FLAG_RST, 1, 0);
    assert!(
        build_reject_rst_frame(&frame).is_none(),
        "must not RST a RST"
    );
}

/// #3204: a TCP-RST reject triggered by a frame whose L2 destination is the
/// broadcast MAC MUST be suppressed (no RST). A reflected RST copies the
/// inbound destination MAC into its own source slot, so answering a broadcast
/// frame would egress a RST with a broadcast SOURCE MAC. Mirrors the ICMP
/// reject path's `l2_dst_is_group_or_broadcast` guard. Fail-on-revert: remove
/// the guard in `build_reject_rst_frame` and this returns `Some(..)` instead
/// of `None`.
#[test]
fn reject_rst_suppressed_for_l2_broadcast_dst() {
    let mut frame = reject_v4_tcp_frame(TCP_FLAG_SYN, 0x1111_2222, 0);
    frame[0..6].copy_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    assert!(
        build_reject_rst_frame(&frame).is_none(),
        "must not RST a broadcast-dst frame (would source a broadcast MAC)"
    );
}

/// #3204: same suppression for an L2 multicast destination (I/G group bit set
/// in the first MAC octet), e.g. an IPv4 multicast 01:00:5e:.. destination.
#[test]
fn reject_rst_suppressed_for_l2_multicast_dst() {
    let mut frame = reject_v6_tcp_frame(TCP_FLAG_SYN, 7, 0);
    frame[0..6].copy_from_slice(&[0x33, 0x33, 0x00, 0x00, 0x00, 0x01]);
    assert!(
        build_reject_rst_frame(&frame).is_none(),
        "must not RST a multicast-dst frame (would source a multicast MAC)"
    );
}

/// #3204 regression: a TCP-RST reject for a normal UNICAST L2 destination
/// still generates the RST (the guard only short-circuits group/broadcast).
#[test]
fn reject_rst_still_generated_for_l2_unicast_dst() {
    // reject_v4_tcp_frame's dst MAC is 02:..:dd — unicast (I/G bit clear).
    let frame = reject_v4_tcp_frame(TCP_FLAG_SYN, 0x1111_2222, 0);
    assert_eq!(frame[0] & 0x01, 0, "fixture dst MAC must be unicast");
    let out = build_reject_rst_frame(&frame).expect("RST for unicast SYN");
    // Reflected RST: reply src MAC = inbound dst (unicast), RST flag set.
    assert_eq!(&out[6..12], &[0x02, 0, 0, 0, 0, 0xdd]);
    let tcp = &out[ETH_HDR_LEN + IPV4_HDR_LEN..ETH_HDR_LEN + IPV4_HDR_LEN + 20];
    assert_ne!(tcp[13] & TCP_FLAG_RST, 0, "RST flag must be set");
}

/// Full v6 TCP frame with ONE Destination-Options extension header
/// (8 bytes) between the IPv6 base header and the TCP header. Exercises
/// the ext-header-aware seg_len path so a no-ACK RST acks exactly the
/// SYN (seq+1), not seq+1+ext_bytes.
fn reject_v6_tcp_frame_with_ext(flags: u8, seq: u32) -> Vec<u8> {
    let mut eth = eth_header(0x86dd);
    eth[0..6].copy_from_slice(&[0x02, 0, 0, 0, 0, 0xdd]);
    eth[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, 0xcc]);
    let mut ip = ipv6_header(8 + 20, 60); // next-header = Dest-Options (60)
    // payload_len covers ext header (8) + TCP (20).
    ip[4..6].copy_from_slice(&((8 + 20) as u16).to_be_bytes());
    let mut ext = [0u8; 8]; // Dest-Options: next-header=TCP(6), hdr-ext-len=0
    ext[0] = 6;
    ext[1] = 0;
    let mut tcp = tcp_header_skeleton(flags, 5);
    tcp[4..8].copy_from_slice(&seq.to_be_bytes());
    tcp[8..12].copy_from_slice(&0u32.to_be_bytes());
    let mut frame = Vec::with_capacity(14 + 40 + 8 + 20);
    frame.extend_from_slice(&eth);
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&ext);
    frame.extend_from_slice(&tcp);
    frame
}

#[test]
fn reject_rst_v6_ext_header_syn_acks_seq_plus_one_not_plus_ext() {
    // Regression guard: a no-ACK v6 SYN carrying an extension header must
    // get ack = seq + 1 (the SYN consumes one seq number), NOT
    // seq + 1 + ext_header_bytes. The latter is an unacceptable ack a
    // SYN-SENT client would discard, degrading the reject to a drop.
    let frame = reject_v6_tcp_frame_with_ext(TCP_FLAG_SYN, 100);
    let out = build_reject_rst_frame(&frame).expect("v6 ext-header RST for SYN");
    // Reply has no ext header (minimal 40+20); TCP at fixed offset.
    let tcp = &out[ETH_HDR_LEN + IPV6_HDR_LEN..ETH_HDR_LEN + IPV6_HDR_LEN + 20];
    assert_eq!(tcp[13], TCP_FLAG_RST | TCP_FLAG_ACK);
    assert_eq!(
        u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]),
        101,
        "ack must be seq+1, not inflated by the 8-byte ext header"
    );
}

#[test]
fn reject_rst_v4_syn_with_data_acks_seq_plus_one_plus_payload() {
    // A no-ACK segment carrying payload (rare for a SYN, but exercises
    // the seg_len payload math): ack = seq + 1(SYN) + payload_len.
    let mut eth = eth_header(0x0800);
    eth[0..6].copy_from_slice(&[0x02, 0, 0, 0, 0, 0xdd]);
    eth[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, 0xcc]);
    // total_len = 20 (IP) + 20 (TCP) + 4 (payload) = 44.
    let ip = ipv4_header(44, 6);
    let mut tcp = tcp_header_skeleton(TCP_FLAG_SYN, 5);
    tcp[4..8].copy_from_slice(&1000u32.to_be_bytes());
    let mut frame = Vec::new();
    frame.extend_from_slice(&eth);
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&tcp);
    frame.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]); // 4 payload bytes
    let out = build_reject_rst_frame(&frame).expect("RST for SYN+data");
    let tcp_out = &out[ETH_HDR_LEN + IPV4_HDR_LEN..ETH_HDR_LEN + IPV4_HDR_LEN + 20];
    assert_eq!(
        u32::from_be_bytes([tcp_out[8], tcp_out[9], tcp_out[10], tcp_out[11]]),
        1000 + 1 + 4,
        "ack = seq + SYN(1) + 4 payload bytes"
    );
}

#[test]
fn reject_rst_v4_inflated_total_len_clamped_to_frame_acks_seq_plus_one() {
    // #4484 L-3: a crafted/corrupted IPv4 packet advertises a total_len
    // far larger than the actual captured frame. `tcp_segment_consumed_len`
    // must clamp the derived datagram end to `frame.len()` so the no-ACK RST
    // acks exactly the SYN (seq + 1), NOT seq + 1 + phantom_payload. The
    // inflated value would produce an unacceptable ack the SYN-SENT peer
    // discards, degrading the reject to a silent drop (fail-closed self-DoS).
    //
    // Fail-on-revert: remove the `.min(frame.len())` clamp and the ack
    // becomes seq + 1 + (14 + 1200 - 54) = seq + 1161, so this FAILS.
    let mut eth = eth_header(0x0800);
    eth[0..6].copy_from_slice(&[0x02, 0, 0, 0, 0, 0xdd]);
    eth[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, 0xcc]);
    // Header claims a 1200-byte datagram, but the real frame is only
    // 14 (eth) + 20 (IP) + 20 (TCP) = 54 bytes — no payload present.
    let ip = ipv4_header(1200, 6);
    let mut tcp = tcp_header_skeleton(TCP_FLAG_SYN, 5);
    tcp[4..8].copy_from_slice(&100u32.to_be_bytes());
    let mut frame = Vec::new();
    frame.extend_from_slice(&eth);
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&tcp);
    assert_eq!(frame.len(), 54, "fixture frame must be 54 bytes");
    let out = build_reject_rst_frame(&frame).expect("RST for SYN with inflated total_len");
    let tcp_out = &out[ETH_HDR_LEN + IPV4_HDR_LEN..ETH_HDR_LEN + IPV4_HDR_LEN + 20];
    // No-ACK inbound: seq=0, RST|ACK, ack = seq + 1 (SYN only, no payload).
    assert_eq!(tcp_out[13], TCP_FLAG_RST | TCP_FLAG_ACK);
    assert_eq!(
        u32::from_be_bytes([tcp_out[8], tcp_out[9], tcp_out[10], tcp_out[11]]),
        101,
        "ack must be seq+1 (SYN); the phantom total_len payload must be clamped away"
    );
}

#[test]
fn reject_rst_v4_exact_total_len_unchanged_by_clamp() {
    // Guard: a well-formed packet whose total_len == the real datagram
    // length (no overshoot) is unaffected by the clamp — the SYN+data
    // payload math is preserved. total_len = 20 (IP) + 20 (TCP) + 6 = 46,
    // frame = 14 + 46 = 60 bytes; ack = seq + SYN(1) + 6 payload bytes.
    let mut eth = eth_header(0x0800);
    eth[0..6].copy_from_slice(&[0x02, 0, 0, 0, 0, 0xdd]);
    eth[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, 0xcc]);
    let ip = ipv4_header(46, 6);
    let mut tcp = tcp_header_skeleton(TCP_FLAG_SYN, 5);
    tcp[4..8].copy_from_slice(&200u32.to_be_bytes());
    let mut frame = Vec::new();
    frame.extend_from_slice(&eth);
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&tcp);
    frame.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]); // 6 payload bytes
    assert_eq!(frame.len(), 60, "fixture frame must be 60 bytes");
    let out = build_reject_rst_frame(&frame).expect("RST for well-formed SYN+data");
    let tcp_out = &out[ETH_HDR_LEN + IPV4_HDR_LEN..ETH_HDR_LEN + IPV4_HDR_LEN + 20];
    assert_eq!(
        u32::from_be_bytes([tcp_out[8], tcp_out[9], tcp_out[10], tcp_out[11]]),
        200 + 1 + 6,
        "ack = seq + SYN(1) + 6 payload bytes (clamp is a no-op for valid packets)"
    );
}

// ---------- #2148: IPv6 extension-header L4-offset correctness ----------
//
// The three stale helpers (frame_has_tcp_rst,
// extract_tcp_flags_and_window, extract_tcp_window) previously hard-coded
// the IPv6 TCP header at L3+40, ignoring extension headers. These tests
// craft IPv6 frames that carry one or more extension headers before the
// TCP header. They are written so that the byte sequence sitting at the
// OLD fixed offset (L3+40, i.e. the first byte of the extension header)
// is deliberately NOT a valid/RST TCP header — so the pre-fix code
// produces the wrong answer and these tests FAIL against it. The fix
// walks the ext-header chain to the true L4 offset.

/// Build an IPv6 extension header block: `[next_header, hdr_ext_len, ...]`
/// where `hdr_ext_len` is in 8-octet units NOT counting the first 8
/// octets (RFC 8200 §4.3 for hop-by-hop/dest-opts/routing). `units`
/// gives the number of additional 8-octet groups (0 → 8-byte header).
/// The body is filled with a recognizable sentinel (0xEE) so that any
/// reader landing inside the ext header (the pre-#2148 bug) sees
/// non-TCP-header bytes.
fn ipv6_ext_hbh_or_dstopt(next_header: u8, units: u8) -> Vec<u8> {
    let len = (units as usize + 1) * 8;
    let mut ext = vec![0xEEu8; len];
    ext[0] = next_header;
    ext[1] = units; // hdr_ext_len in 8-octet units beyond the first 8
    ext
}

/// Build an IPv6 fragment header (always 8 bytes): next_header, reserved,
/// fragment-offset+flags (2), identification (4). Offset 0, M=0 → first
/// (atomic) fragment, which DOES carry the L4 header.
fn ipv6_fragment_header(next_header: u8) -> [u8; 8] {
    let mut frag = [0u8; 8];
    frag[0] = next_header;
    // bytes 2-3 = frag offset (0) | res | M-flag (0): first fragment.
    frag[4..8].copy_from_slice(&0xABCDEF01u32.to_be_bytes());
    frag
}

/// Assemble an Ethernet+IPv6 frame whose IPv6 next-header chain is the
/// concatenation of `ext_blocks` (each a raw ext-header byte block whose
/// first byte already points at the following header) terminating in a
/// 20-byte TCP header carrying `flags`/`window`. `first_next_header` is
/// the IPv6 base-header next-header byte (the first ext-header type, or
/// PROTO_TCP if `ext_blocks` is empty).
fn build_v6_frame_with_ext_chain(
    first_next_header: u8,
    ext_blocks: &[Vec<u8>],
    flags: u8,
    window: u16,
) -> Vec<u8> {
    let mut tcp = tcp_header_skeleton(flags, 5);
    tcp[14..16].copy_from_slice(&window.to_be_bytes());

    let ext_total: usize = ext_blocks.iter().map(|b| b.len()).sum();
    let payload_len = (ext_total + tcp.len()) as u16;

    let mut frame = Vec::new();
    frame.extend_from_slice(&eth_header(0x86dd));
    frame.extend_from_slice(&ipv6_header(payload_len, first_next_header));
    for b in ext_blocks {
        frame.extend_from_slice(b);
    }
    frame.extend_from_slice(&tcp);
    frame
}

#[test]
fn frame_has_tcp_rst_v6_plain_unchanged() {
    // No ext headers: base IPv6 next-header = TCP (offset 40). RST set.
    let frame = build_v6_frame_with_ext_chain(PROTO_TCP, &[], 0x04, 65535);
    assert!(
        frame_has_tcp_rst(&frame),
        "plain IPv6 TCP RST still detected (offset-40 path unchanged)"
    );
}

#[test]
fn frame_has_tcp_rst_v6_hop_by_hop() {
    // 1 hop-by-hop ext header (8 bytes) → TCP at L3+40+8. RST set.
    // The byte at the OLD offset L3+40 is the ext-header next-header
    // (PROTO_TCP) followed by hdr_ext_len/sentinel — its "flags" byte at
    // +13 is the 0xEE sentinel, so the pre-fix code reads RST from the
    // wrong place. The fix walks to the true offset.
    let hbh = ipv6_ext_hbh_or_dstopt(PROTO_TCP, 0);
    let frame = build_v6_frame_with_ext_chain(0 /* HBH */, &[hbh], 0x04, 65535);
    assert!(
        frame_has_tcp_rst(&frame),
        "IPv6 + hop-by-hop: RST must be read at the post-ext-header offset"
    );
}

#[test]
fn frame_has_tcp_rst_v6_hop_by_hop_no_rst() {
    // Same chain but SYN (no RST). Must report false. The 0xEE sentinel
    // at the old offset HAS bit 0x04 set (0xEE & 0x04 == 0x04), so the
    // pre-fix code would FALSELY report RST here — this guards both
    // directions of the verdict.
    let hbh = ipv6_ext_hbh_or_dstopt(PROTO_TCP, 0);
    let frame = build_v6_frame_with_ext_chain(0, &[hbh], TCP_FLAG_SYN, 65535);
    assert!(
        !frame_has_tcp_rst(&frame),
        "IPv6 + hop-by-hop SYN: must NOT false-positive RST from the ext-header sentinel"
    );
}

#[test]
fn frame_has_tcp_rst_v6_two_ext_headers() {
    // hop-by-hop (next=dest-opts) → dest-opts (next=TCP) → TCP. RST set.
    let dstopt = ipv6_ext_hbh_or_dstopt(PROTO_TCP, 1); // 16-byte dest-opts
    let hbh = ipv6_ext_hbh_or_dstopt(60 /* dest-opts */, 0); // 8-byte HBH
    let frame = build_v6_frame_with_ext_chain(0 /* HBH */, &[hbh, dstopt], 0x04, 65535);
    assert!(
        frame_has_tcp_rst(&frame),
        "IPv6 + 2 ext headers: RST read at the post-chain offset"
    );
}

#[test]
fn frame_has_tcp_rst_v6_fragment_header() {
    // First fragment (offset 0) carries the TCP header after an 8-byte
    // fragment ext header. RST set.
    let frag = ipv6_fragment_header(PROTO_TCP);
    let frame = build_v6_frame_with_ext_chain(44 /* fragment */, &[frag.to_vec()], 0x04, 65535);
    assert!(
        frame_has_tcp_rst(&frame),
        "IPv6 + fragment header (first fragment): RST read at post-frag offset"
    );
}

#[test]
fn frame_has_tcp_rst_v6_malformed_chain_no_panic() {
    // A hop-by-hop header that claims a huge length running past the
    // frame end. Must not panic / read OOB; fail-safe to false.
    let mut frame = Vec::new();
    frame.extend_from_slice(&eth_header(0x86dd));
    frame.extend_from_slice(&ipv6_header(40, 0 /* HBH */));
    // ext header: next=TCP, hdr_ext_len=200 (8-octet units) → way past end.
    frame.extend_from_slice(&[PROTO_TCP, 200, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE]);
    assert!(
        !frame_has_tcp_rst(&frame),
        "malformed ext-header length must fail safe (no panic, no OOB)"
    );
}

#[test]
fn frame_has_tcp_rst_v6_looping_chain_bounded() {
    // A chain of >6 dest-opts headers (exceeds the 6-iteration bound).
    // The walker must give up safely rather than loop / read OOB.
    let mut blocks = Vec::new();
    for _ in 0..8 {
        blocks.push(ipv6_ext_hbh_or_dstopt(60 /* dest-opts (self-chain) */, 0));
    }
    let frame = build_v6_frame_with_ext_chain(60, &blocks, 0x04, 65535);
    // Whatever the bounded walker decides, it must not panic; with 8
    // ext headers it exceeds the bound and returns false.
    assert!(
        !frame_has_tcp_rst(&frame),
        "over-long ext-header chain is bounded and fails safe"
    );
}

#[test]
fn extract_tcp_flags_and_window_v6_hop_by_hop() {
    // SYN+ACK, window 8192, behind one hop-by-hop header.
    let hbh = ipv6_ext_hbh_or_dstopt(PROTO_TCP, 0);
    let frame = build_v6_frame_with_ext_chain(0, &[hbh], TCP_FLAG_SYN | TCP_FLAG_ACK, 8192);
    let (flags, window) =
        extract_tcp_flags_and_window(&frame).expect("flags/window past ext header");
    assert_eq!(flags, TCP_FLAG_SYN | TCP_FLAG_ACK);
    assert_eq!(window, 8192, "window read from the real TCP header");
}

#[test]
fn extract_tcp_flags_and_window_v6_two_ext_headers() {
    let dstopt = ipv6_ext_hbh_or_dstopt(PROTO_TCP, 1);
    let hbh = ipv6_ext_hbh_or_dstopt(60, 0);
    let frame = build_v6_frame_with_ext_chain(0, &[hbh, dstopt], TCP_FLAG_ACK, 4096);
    let (flags, window) = extract_tcp_flags_and_window(&frame).expect("Some");
    assert_eq!(flags, TCP_FLAG_ACK);
    assert_eq!(window, 4096);
}

#[test]
fn extract_tcp_flags_and_window_v6_plain_unchanged() {
    let frame = build_v6_frame_with_ext_chain(PROTO_TCP, &[], TCP_FLAG_SYN, 16384);
    let (flags, window) = extract_tcp_flags_and_window(&frame).expect("Some");
    assert_eq!(flags, TCP_FLAG_SYN);
    assert_eq!(window, 16384);
}

#[test]
fn extract_tcp_flags_and_window_v6_malformed_no_panic() {
    let mut frame = Vec::new();
    frame.extend_from_slice(&eth_header(0x86dd));
    frame.extend_from_slice(&ipv6_header(40, 0));
    frame.extend_from_slice(&[PROTO_TCP, 200, 0, 0, 0, 0, 0, 0]); // overlong
    assert!(extract_tcp_flags_and_window(&frame).is_none());
}

#[test]
fn extract_tcp_window_v6_hop_by_hop() {
    let hbh = ipv6_ext_hbh_or_dstopt(PROTO_TCP, 0);
    let frame = build_v6_frame_with_ext_chain(0, &[hbh], 0, 2048);
    assert_eq!(
        extract_tcp_window(&frame, libc::AF_INET6 as u8),
        Some(2048),
        "window read at the post-ext-header TCP offset"
    );
}

#[test]
fn extract_tcp_window_v6_fragment_header() {
    let frag = ipv6_fragment_header(PROTO_TCP);
    let frame = build_v6_frame_with_ext_chain(44, &[frag.to_vec()], 0, 1024);
    assert_eq!(
        extract_tcp_window(&frame, libc::AF_INET6 as u8),
        Some(1024)
    );
}

#[test]
fn extract_tcp_window_v6_plain_unchanged() {
    let frame = build_v6_frame_with_ext_chain(PROTO_TCP, &[], 0, 512);
    assert_eq!(
        extract_tcp_window(&frame, libc::AF_INET6 as u8),
        Some(512)
    );
}

#[test]
fn extract_tcp_window_v6_malformed_no_panic() {
    let mut frame = Vec::new();
    frame.extend_from_slice(&eth_header(0x86dd));
    frame.extend_from_slice(&ipv6_header(40, 0));
    frame.extend_from_slice(&[PROTO_TCP, 200, 0, 0, 0, 0, 0, 0]);
    assert_eq!(extract_tcp_window(&frame, libc::AF_INET6 as u8), None);
}

#[test]
fn frame_tcp_v6_non_tcp_after_ext_header() {
    // hop-by-hop → UDP (not TCP). All three helpers must report
    // "not TCP" (false / None), reading the protocol from the END of
    // the chain, not the base-header next-header.
    let hbh = ipv6_ext_hbh_or_dstopt(17 /* UDP */, 0);
    let frame = build_v6_frame_with_ext_chain(0, &[hbh], 0x04, 65535);
    assert!(!frame_has_tcp_rst(&frame));
    assert!(extract_tcp_flags_and_window(&frame).is_none());
    assert_eq!(extract_tcp_window(&frame, libc::AF_INET6 as u8), None);
}

// ---------- #5765: SYN-cookie length-field narrowing (defense-in-depth) ----------
//
// `build_syn_cookie_tcp_reply_v{4,6}` narrow a length (v4: the IPv4
// `total_length = 20 + tcp_len`; v6: the IPv6 `payload_length = tcp_len`) into
// the 16-bit wire field. The bare `as u16` at those sites is hardened to
// `saturate_len16` for idiom-consistency with the checksum sites, BUT the
// truncation is TRULY UNREACHABLE — even at this function boundary: the builder
// calls `write_syn_cookie_tcp_header`, which hard-REJECTS (returns None) any
// `tcp_len` that is not exactly `TCP_MIN_HEADER_LEN` (20) or
// `TCP_MIN_HEADER_LEN + TCP_MSS_OPTION_LEN` (24). So `total_len` is at most 44
// and the length narrowing can never observe a >64K value: an oversized reply
// is discarded (None), never emitted with a wrapped length. The two tests below
// GUARD that structural gate (a huge `tcp_len` yields None, not a bad reply);
// the fail-on-revert coverage for the `saturate_len16` primitive these sites now
// share lives in `checksum::len16_hardening_tests`.

#[test]
fn syn_cookie_reply_v4_rejects_oversized_tcp_len() {
    let frame = reject_v4_tcp_frame(TCP_FLAG_SYN, 0x1111_2222, 0);
    let parsed = parse_tcp_reply_source(&frame).expect("valid v4 SYN frame parses");
    // A >64K tcp_len (total_len = 20 + tcp_len overflows u16) is structurally
    // rejected by write_syn_cookie_tcp_header BEFORE any reply escapes — this
    // is exactly what makes the total_len narrowing unreachable-for-wrap.
    let out = build_syn_cookie_tcp_reply_v4(
        &frame,
        parsed,
        65_516usize,
        0xdead_beef,
        0x1111_2223,
        TCP_FLAG_SYN | TCP_FLAG_ACK,
        0,
    );
    assert!(out.is_none(), "oversized tcp_len must be rejected, never emitted with a wrapped total_length");
}

#[test]
fn syn_cookie_reply_v6_rejects_oversized_tcp_len() {
    let frame = reject_v6_tcp_frame(TCP_FLAG_SYN, 0x3333_4444, 0);
    let parsed = parse_tcp_reply_source(&frame).expect("valid v6 SYN frame parses");
    // A >64K tcp_len (= the IPv6 payload_length, overflows u16) is likewise
    // rejected before any reply escapes.
    let out = build_syn_cookie_tcp_reply_v6(
        &frame,
        parsed,
        65_536usize,
        0xdead_beef,
        0x3333_4445,
        TCP_FLAG_SYN | TCP_FLAG_ACK,
        0,
    );
    assert!(out.is_none(), "oversized tcp_len must be rejected, never emitted with a wrapped payload_length");
}

#[test]
fn syn_cookie_reply_v4_in_range_length_is_exact() {
    // Regression guard: a normal-sized reply must carry the exact
    // total_length, byte-identical to the pre-hardening cast.
    let frame = reject_v4_tcp_frame(TCP_FLAG_SYN, 0x1111_2222, 0);
    let parsed = parse_tcp_reply_source(&frame).expect("valid v4 SYN frame parses");
    let tcp_len = 24usize; // header + MSS option, the real production size
    let out = build_syn_cookie_tcp_reply_v4(
        &frame,
        parsed,
        tcp_len,
        0xdead_beef,
        0x1111_2223,
        TCP_FLAG_SYN | TCP_FLAG_ACK,
        1460,
    )
    .expect("v4 SYN-cookie reply builds");
    let total_len_field = u16::from_be_bytes([out[parsed.l3 + 2], out[parsed.l3 + 3]]);
    assert_eq!(total_len_field, (20 + tcp_len) as u16, "in-range total_length must be exact");
}

// ── #7699: tcp_payload_offset ────────────────────────────────────────────────
//
// The dispatch COPIES a TCP/1723 segment's payload off the hot path, and this
// is what locates it. Two properties are load-bearing rather than cosmetic:
// the offset must honour TCP OPTIONS (a fixed +20 silently copies the options
// as if they were the control message), and the declared data offset is
// ATTACKER-CONTROLLED, so it must be checked against the bytes present rather
// than trusted.

/// An Ethernet + IPv4 + TCP frame whose TCP header is `data_offset_dwords`
/// 32-bit words long, followed by `payload`.
fn tcp_v4_frame_with_options(data_offset_dwords: u8, payload: &[u8]) -> Vec<u8> {
    let opt_bytes = (data_offset_dwords as usize) * 4 - 20;
    let total_len = (IPV4_HDR_LEN + 20 + opt_bytes + payload.len()) as u16;
    let mut frame = Vec::new();
    frame.extend_from_slice(&eth_header(0x0800));
    frame.extend_from_slice(&ipv4_header(total_len, PROTO_TCP));
    frame.extend_from_slice(&tcp_header_skeleton(0x18, data_offset_dwords));
    // NOP-fill the option space so the bytes are well-formed rather than zeros
    // that could be read as End-of-Options.
    frame.extend(std::iter::repeat(1u8).take(opt_bytes));
    frame.extend_from_slice(payload);
    frame
}

#[test]
fn tcp_payload_offset_skips_tcp_options_7699() {
    // 10 dwords = 20 header + 20 option bytes. A fixed +20 implementation
    // returns 34 here and the "payload" it copies is the OPTIONS.
    let payload = b"PPTP-CONTROL";
    let frame = tcp_v4_frame_with_options(10, payload);
    let off = tcp_payload_offset(&frame).expect("a well-formed TCP frame has a payload offset");
    assert_eq!(off, ETH_HDR_LEN + IPV4_HDR_LEN + 40);
    assert_eq!(
        &frame[off..],
        payload,
        "the offset did not skip the TCP options"
    );
}

#[test]
fn tcp_payload_offset_handles_the_no_options_case_7699() {
    let payload = b"PPTP-CONTROL";
    let frame = tcp_v4_frame_with_options(5, payload);
    let off = tcp_payload_offset(&frame).expect("offset");
    assert_eq!(off, ETH_HDR_LEN + IPV4_HDR_LEN + 20);
    assert_eq!(&frame[off..], payload);
}

#[test]
fn tcp_payload_offset_refuses_a_data_offset_past_the_bytes_present_7699() {
    // A 5-dword header, then the declared offset is rewritten to 15 dwords (60
    // bytes) with only 20 + 12 present. Trusting it would slice out of range,
    // or — worse for a copy — hand back a start past the payload.
    let mut frame = tcp_v4_frame_with_options(5, b"PPTP-CONTROL");
    let tcp = ETH_HDR_LEN + IPV4_HDR_LEN;
    frame[tcp + 12] = 15 << 4;
    assert_eq!(
        tcp_payload_offset(&frame),
        None,
        "a lying data offset was trusted"
    );
}

#[test]
fn tcp_payload_offset_refuses_a_sub_minimum_data_offset_7699() {
    let mut frame = tcp_v4_frame_with_options(5, b"PPTP-CONTROL");
    let tcp = ETH_HDR_LEN + IPV4_HDR_LEN;
    frame[tcp + 12] = 4 << 4; // 16 bytes — below the 20-byte minimum header
    assert_eq!(tcp_payload_offset(&frame), None);
}

#[test]
fn tcp_payload_offset_refuses_a_non_tcp_frame_7699() {
    let mut frame = tcp_v4_frame_with_options(5, b"PPTP-CONTROL");
    frame[ETH_HDR_LEN + 9] = 17; // UDP
    assert_eq!(tcp_payload_offset(&frame), None);
}

// #8597 K37: `parse_tcp_reply_source` must DECLINE a non-first fragment.
//
// On a non-first fragment the bytes at the L4 offset are payload. Without the
// gate this function reads ports, seq, ack and flags out of attacker-chosen
// data and the three builders that call it reflect them into a SYN-ACK or an
// RST.
//
// WHY NO END-TO-END CELL. The packet path cannot currently deliver such a frame
// here: the shim substitutes `PROTO_FRAGMENT_NO_L4` for a non-first fragment's
// protocol before `parse_l4`, so `meta.protocol` is not TCP and `meta.tcp_flags`
// is 0 — which is what stops all three callers. That defence lives in another
// crate and is keyed on `meta`, while THIS function reads the frame. So the
// direct call is the only instrument that can distinguish a gated function from
// an ungated one, and a passing end-to-end test would be measuring the shim.
//
// Note what does NOT protect it: the `protocol != PROTO_TCP` check below the
// gate reads the protocol byte from the FRAME's IP header, and a fragmented TCP
// datagram says TCP (6) in EVERY fragment. Fragmentation does not touch that
// field.
fn frag_v4_tcp_frame_8597_k37() -> Vec<u8> {
    let mut frame = reject_v4_tcp_frame(TCP_FLAG_SYN, 0x1111_2222, 0);
    // IPv4 flags/fragment-offset is bytes 6..8 of the IP header, which starts at
    // frame offset 14. A non-zero offset makes this a NON-FIRST fragment.
    frame[20] = 0x00;
    frame[21] = 0x01;
    frame
}

fn frag_v6_tcp_frame_8597_k37() -> Vec<u8> {
    let mut eth = eth_header(0x86dd);
    eth[0..6].copy_from_slice(&[0x02, 0, 0, 0, 0, 0xdd]);
    eth[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, 0xcc]);
    // next-header = 44 (Fragment), payload = 8 (frag hdr) + 20 (TCP).
    let ip = ipv6_header(8 + 20, 44);
    // RFC 8200 §4.5: next-header, reserved, offset<<3 | flags, identification.
    // offset_units 1 -> the 0xFFF8 mask is non-zero, i.e. NOT the first fragment.
    let frag = [6u8, 0, 0x00, 0x08, 0xde, 0xad, 0xbe, 0xef];
    let tcp = tcp_header_skeleton(TCP_FLAG_SYN, 5);
    let mut frame = Vec::with_capacity(14 + 40 + 8 + 20);
    frame.extend_from_slice(&eth);
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&frag);
    frame.extend_from_slice(&tcp);
    frame
}

#[test]
fn parse_tcp_reply_source_declines_a_non_first_fragment_8597_k37() {
    assert!(
        parse_tcp_reply_source(&frag_v4_tcp_frame_8597_k37()).is_none(),
        "a v4 non-first fragment carries PAYLOAD at the L4 offset; parsing it as a \
         TCP header reflects attacker-chosen bytes into a SYN-ACK or RST"
    );
    assert!(
        parse_tcp_reply_source(&frag_v6_tcp_frame_8597_k37()).is_none(),
        "a v6 non-first fragment (Fragment Header, non-zero offset) must decline \
         for the same reason"
    );
}

// ANTI-OVER-REJECT, and it is what makes the pair meaningful: the gate must
// reject non-first fragments WITHOUT rejecting ordinary TCP, or the syn-cookie
// and reject-RST paths silently stop replying at all.
#[test]
fn parse_tcp_reply_source_still_accepts_unfragmented_tcp_8597_k37() {
    let v4 = reject_v4_tcp_frame(TCP_FLAG_SYN, 0x1111_2222, 0);
    let p4 = parse_tcp_reply_source(&v4).expect("an ordinary v4 TCP frame must still parse");
    assert_eq!(p4.seq, 0x1111_2222, "the parse must be intact, not merely non-None");

    let v6 = reject_v6_tcp_frame(TCP_FLAG_SYN, 0x3333_4444, 0);
    let p6 = parse_tcp_reply_source(&v6).expect("an ordinary v6 TCP frame must still parse");
    assert_eq!(p6.seq, 0x3333_4444);

    // A FIRST fragment (offset 0, More-Fragments set) still carries a real TCP
    // header and must be accepted — the gate keys on the OFFSET, not on the
    // presence of fragmentation.
    let mut first = reject_v4_tcp_frame(TCP_FLAG_SYN, 0x5555_6666, 0);
    first[20] = 0x20; // MF set, offset 0
    first[21] = 0x00;
    let pf = parse_tcp_reply_source(&first)
        .expect("a FIRST fragment has a real TCP header and must still parse");
    assert_eq!(pf.seq, 0x5555_6666);
}

// ---------------------------------------------------------------------------
// #9111: #3204's L2 group/broadcast refusal, on the two SYN-cookie reply legs
// it was never given.
// ---------------------------------------------------------------------------

/// #9111: the SYN-cookie SYN-ACK must be suppressed for an L2 broadcast
/// destination.
///
/// #3204 established that `write_reply_eth_header` copies the inbound L2
/// DESTINATION into the reply's own L2 SOURCE, so answering a group-addressed
/// frame egresses a group/broadcast SOURCE MAC — switches learn it against this
/// port or MAC-flap and err-disable it. #3204 guarded ONE of the three reply
/// builders. This is the leg an unauthenticated host on the segment can drive
/// at will, because it is armed exactly when SYN-flood cookies are active.
///
/// Fail-on-revert: remove the guard from `parse_tcp_reply_source` and this
/// returns `Some(..)`.
#[test]
fn syn_cookie_syn_ack_suppressed_for_l2_broadcast_dst_9111() {
    let mut frame = reject_v4_tcp_frame(TCP_FLAG_SYN, 0x1111_2222, 0);
    frame[0..6].copy_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    assert!(
        build_syn_cookie_syn_ack_frame(&frame, 0xdead_beef, 1460).is_none(),
        "must not answer a broadcast-dst SYN with a cookie SYN-ACK (would source \
         a broadcast MAC)"
    );
}

/// #9111: same for an L2 multicast destination on the SYN-ACK leg.
#[test]
fn syn_cookie_syn_ack_suppressed_for_l2_multicast_dst_9111() {
    let mut frame = reject_v6_tcp_frame(TCP_FLAG_SYN, 7, 0);
    frame[0..6].copy_from_slice(&[0x33, 0x33, 0x00, 0x00, 0x00, 0x01]);
    assert!(
        build_syn_cookie_syn_ack_frame(&frame, 0xdead_beef, 1460).is_none(),
        "must not answer a multicast-dst SYN with a cookie SYN-ACK"
    );
}

/// #9111: the SYN-cookie ACK-RST leg, the third builder.
#[test]
fn syn_cookie_ack_rst_suppressed_for_l2_group_dst_9111() {
    let mut frame = reject_v4_tcp_frame(TCP_FLAG_ACK, 0x1111_2222, 0x3333_4444);
    frame[0..6].copy_from_slice(&[0x01, 0x00, 0x5e, 0x00, 0x00, 0x01]);
    assert!(
        build_syn_cookie_ack_rst_frame(&frame).is_none(),
        "must not answer a multicast-dst ACK with a cookie RST"
    );
}

/// CONTROL: both SYN-cookie legs still build for an ordinary UNICAST
/// destination, and the reply's SOURCE MAC is that unicast address.
///
/// Without this row a guard that refused everything would satisfy all three
/// assertions above while disabling the SYN-cookie challenge entirely — which
/// is the feature the defect is reachable through, so breaking it is the worse
/// outcome.
#[test]
fn syn_cookie_legs_still_build_for_l2_unicast_dst_9111() {
    let syn = reject_v4_tcp_frame(TCP_FLAG_SYN, 0x1111_2222, 0);
    assert_eq!(syn[0] & 0x01, 0, "fixture dst MAC must be unicast");
    let sa = build_syn_cookie_syn_ack_frame(&syn, 0xdead_beef, 1460)
        .expect("cookie SYN-ACK for a unicast SYN");
    assert_eq!(
        &sa[6..12],
        &[0x02, 0, 0, 0, 0, 0xdd],
        "reply SOURCE MAC is the inbound unicast destination"
    );

    let ack = reject_v4_tcp_frame(TCP_FLAG_ACK, 0x1111_2222, 0x3333_4444);
    let rst = build_syn_cookie_ack_rst_frame(&ack).expect("cookie RST for a unicast ACK");
    assert_eq!(&rst[6..12], &[0x02, 0, 0, 0, 0, 0xdd]);
}
