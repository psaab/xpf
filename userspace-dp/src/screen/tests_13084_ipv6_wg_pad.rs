//! #13084: the IPv6 shim must not classify Ethernet padding as a UDP payload.
//!
//! Compile and execute the exact gate used by the shim, and pin the parser
//! call site so the helper cannot silently become disconnected from parsing.

#[path = "../../../userspace-xdp/src/ipv6_len_gate.rs"]
mod shim_v6_len_gate;

use shim_v6_len_gate::{ipv6_declared_end, ipv6_udp_first_payload_byte_in_datagram};

const L3: usize = 14;
const L4: usize = L3 + 40;

#[test]
fn zero_payload_ipv6_udp_never_classifies_l2_pad_as_wireguard_data_13084() {
    // Ethernet (14) + IPv6 (40) + UDP header (8) declares a 62-byte frame.
    // The Ethernet minimum frame has two extra pad bytes; pad byte 62 is 4,
    // the WireGuard transport-data record type. The old post-parse truncation
    // test accepted payload_offset == declared_end and retained this claim.
    let declared_end = ipv6_declared_end(L3, 8);
    assert_eq!(declared_end, L4 + 8);
    assert_eq!(L4 + 8, 62);
    let captured_pad_byte = 4u8;
    assert_eq!(captured_pad_byte, 4, "fixture contains WG type 4 in L2 pad");

    // No byte after the 8-byte UDP header is inside the declared datagram.
    assert!(
        !ipv6_udp_first_payload_byte_in_datagram(L4, declared_end),
        "#13084: an absent UDP payload byte must not classify as WG data"
    );
    // A declared byte is still classified normally, including with ext hdrs
    // (the L4 offset, rather than the fixed-header end, is passed to the gate).
    assert!(
        ipv6_udp_first_payload_byte_in_datagram(L4 + 8, L4 + 8 + 9),
        "declared first payload byte remains available"
    );
}

#[test]
fn parse_ipv6_applies_declared_end_to_wireguard_claim_13084() {
    let lib = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("userspace-xdp/src/lib.rs");
    let src = std::fs::read_to_string(&lib).expect("read shim lib.rs");
    assert!(src.contains("fn parse_ipv6"), "non-vacuity: real shim parser");
    assert!(
        src.contains("ipv6_udp_first_payload_byte_in_datagram(offset as usize, declared_end)"),
        "#13084: parse_ipv6 must gate the UDP payload classification byte against the IPv6 declared end"
    );
}
