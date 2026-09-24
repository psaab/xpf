//! #10662: host-side IPv6 declared-payload boundary cells.
//!
//! The shim keeps its capture-bound `parse_l4` path unchanged and performs
//! one scalar check against `l3 + 40 + payload_len` after parsing. These cells
//! exercise the shared end arithmetic at the TCP flags boundary; the Go shim
//! test executes the complete packet path against the generated object.

#[path = "../../../userspace-xdp/src/ipv6_len_gate.rs"]
mod shim_v6_len_gate;

use shim_v6_len_gate::{IPV6_FIXED_HDR_LEN, ipv6_declared_end};

const L3: usize = 14;
/// L4 offset with no extension headers (NextHdr = TCP straight off the base).
const L4: usize = L3 + 40;
const PROTO_TCP: u8 = 6;
const TCP_FLAG_SYN: u8 = 0x02;

/// A captured frame: eth + 40-byte IPv6 base (`payload_len`, NextHdr TCP) +
/// a 20-byte TCP header with SYN set + zero pad out to `caplen`.
fn v6_frame(payload_len: u16, caplen: usize) -> Vec<u8> {
    let mut frame = vec![0u8; caplen.max(L4 + 20)];
    frame[L3] = 0x60; // version 6
    frame[L3 + 4..L3 + 6].copy_from_slice(&payload_len.to_be_bytes());
    frame[L3 + 6] = PROTO_TCP;
    frame[L3 + 7] = 64; // hop limit
    frame[L3 + 8..L3 + 24].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    frame[L3 + 24..L3 + 40].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    // Ports + SYN at L4+13, exactly where the shim's TCP arm reads them.
    frame[L4..L4 + 4].copy_from_slice(&[0x30, 0x39, 0x00, 0x50]);
    frame[L4 + 12] = 0x50;
    frame[L4 + 13] = TCP_FLAG_SYN;
    frame.truncate(caplen);
    frame
}

/// The shim's read of the length field: bytes 4..6 of the held 40-byte slice.
fn frame_payload_len(frame: &[u8]) -> u16 {
    u16::from_be_bytes([frame[L3 + 4], frame[L3 + 5]])
}

#[test]
fn shim_v6_declared_end_tracks_payload_len_10662() {
    // The fixed header length is part of the wire contract, and L4 is exactly
    // that far into this no-extension-header fixture.
    assert_eq!(IPV6_FIXED_HDR_LEN, 40, "IPv6 base header is 40 bytes");
    assert_eq!(L4, L3 + IPV6_FIXED_HDR_LEN, "test L4 uses the shim constant");

    // Zero is a bare IPv6 header; 13/14/15 bracket the TCP flags span;
    // 39/40/41 bracket the base TCP header; u16::MAX exercises the largest
    // legal arithmetic input.
    let payloads: [u16; 19] = [
        0, 1, 13, 14, 15, 19, 20, 21, 39, 40, 41, 59, 60, 61, 100, 1400, 1460,
        1500, 65535,
    ];
    for payload in payloads {
        assert_eq!(
            ipv6_declared_end(L3, payload),
            L4 + payload as usize,
            "payload={payload}: end counts fixed header and declared payload",
        );
    }
}

#[test]
fn out_of_datagram_tcp_flags_are_past_declared_end_10662() {
    // A lying-SHORT payload_len (13) leaves a full SYN-bearing TCP header in
    // the capture. The flags byte at L4+13 is the first byte PAST declared_end.
    let frame = v6_frame(13, L4 + 20);
    assert_eq!(frame[L4 + 13], TCP_FLAG_SYN, "non-vacuity: SYN is captured");
    let payload = frame_payload_len(&frame);
    assert_eq!(payload, 13, "non-vacuity: the datagram declares 13");
    let declared_end = ipv6_declared_end(L3, payload);
    assert_eq!(
        declared_end,
        L4 + 13,
        "declared end is the first byte after the IPv6 payload",
    );
    assert!(
        L4 + 14 > declared_end,
        "#10662: flags are past declared_end={declared_end}",
    );

    // Boundary twins: 14 declares exactly the flags span; 0 is a bare header.
    for (payload, reachable) in [(14u16, true), (0u16, false)] {
        let frame = v6_frame(payload, L4 + 20);
        let declared_end = ipv6_declared_end(L3, frame_payload_len(&frame));
        assert_eq!(
            declared_end >= L4 + 14,
            reachable,
            "#10662: payload={payload} declared_end={declared_end} L4+14={}",
            L4 + 14,
        );
    }
}
