//! #16009: execute the shim's stateless-malformed screen verdict on
//! the host.
//!
//! The verdict lives in the `core`-only `host_screen` module the shim
//! calls before every kernel pass; this file pulls that file in by
//! source and runs it against the worker screen's own stateless
//! checks (`check_fragment_and_route` + `check_tcp_flag_screens`) over
//! the decisive shapes, so the parity executed here is the parity the
//! shim performs. FAIL-ON-REVERT: reverting any shim check (e.g.
//! dropping the teardrop MF gate) makes the corresponding row RED.

#[path = "../../../../userspace-xdp/src/host_screen.rs"]
mod shim_host_screen;

use shim_host_screen::{
    HOST_SCREEN_ICMP_FRAGMENT, HOST_SCREEN_PING_DEATH, HOST_SCREEN_SOURCE_ROUTE,
    HOST_SCREEN_SYN_FIN, HOST_SCREEN_SYN_FRAG, HOST_SCREEN_TCP_FLAGS, HOST_SCREEN_TEARDROP,
    HostMalformedDisposition, HostScreenPacket, host_malformed_disposition,
    host_malformed_verdict,
};

use crate::screen::{ScreenPacketInfo, ScreenProfile};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

fn worker_profile() -> ScreenProfile {
    ScreenProfile {
        ping_death: true,
        teardrop: true,
        icmp_fragment: true,
        syn_frag: true,
        source_route: true,
        syn_fin: true,
        no_flag: true,
        fin_no_ack: true,
        winnuke: true,
        ..ScreenProfile::default()
    }
}

/// Build the worker's ScreenPacketInfo and the shim verdict for the
/// same logical packet, then require agreement on every gated check.
#[allow(clippy::too_many_arguments)]
fn assert_parity(
    is_ipv4: bool,
    protocol: u8,
    tcp_flags: u8,
    tcp_flags_unknown: bool,
    dst_port: u16,
    is_fragment: bool,
    is_first_fragment: bool,
    ip_frag_off: u16,
    ip_total_len: u16,
    ip_ihl: u8,
    ip_payload_len: u16,
    frag_data_off: u16,
    saw_source_route: bool,
) {
    let info = ScreenPacketInfo {
        addr_family: if is_ipv4 { AF_INET } else { AF_INET6 },
        protocol,
        tcp_flags,
        tcp_flags_unknown,
        src_ip: if is_ipv4 {
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))
        } else {
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2))
        },
        dst_ip: if is_ipv4 {
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))
        } else {
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
        },
        src_port: 12345,
        dst_port,
        tcp_seq: 0,
        tcp_ack: 0,
        tcp_mss: 0,
        pkt_len: 0,
        is_fragment,
        is_first_fragment,
        ip_ihl,
        ip_frag_off,
        ip_total_len,
        ip_payload_len,
        frag_data_off,
        saw_ipv4_source_route: saw_source_route && is_ipv4,
        saw_ipv6_routing_header: saw_source_route && !is_ipv4,
    };
    let profile = worker_profile();
    let expected_mask = crate::screen::worker_malformed_mask_for_test(&profile, &info);
    let mask = host_malformed_verdict(&HostScreenPacket {
        is_ipv4,
        protocol,
        wire_protocol: protocol,
        tcp_flags,
        tcp_flags_unknown,
        dst_port,
        is_fragment,
        is_first_fragment,
        ip_frag_off,
        ip_total_len,
        ip_ihl,
        ip_payload_len,
        frag_data_off,
        saw_source_route,
    });
    assert_eq!(
        mask, expected_mask,
        "shim mask {mask:#x} != worker mask {expected_mask:#x} for \
         v4={is_ipv4} proto={protocol} flags={tcp_flags:#x} unknown={tcp_flags_unknown} \
         frag={is_fragment}/{is_first_fragment} off={ip_frag_off:#x} \
         total={ip_total_len} payload_len={ip_payload_len} \
         frag_data_off={frag_data_off} sr={saw_source_route}"
    );
}

#[test]
fn host_malformed_verdict_matches_worker_16009() {
    // Teardrop: non-last first fragment, payload 4 (not multiple of 8).
    assert_parity(true, 17, 0, false, 443, true, true, 0x2000, 24, 5, 0, 0, false);
    // Teardrop control: legal 8-byte first fragment passes.
    assert_parity(true, 17, 0, false, 443, true, true, 0x2000, 28, 5, 0, 0, false);
    // Teardrop control: legal short LAST fragment (MF=0) passes (#9426).
    assert_parity(true, 17, 0, false, 443, true, false, 0x0001, 24, 5, 0, 0, false);
    // Teardrop: zero-payload fragment.
    assert_parity(true, 17, 0, false, 443, true, false, 0x0001, 20, 5, 0, 0, false);
    // Ping-of-death: maximal offset + length overflows 65535.
    assert_parity(true, 17, 0, false, 443, true, false, 0x1FFF, 1500, 5, 0, 0, false);
    // Ping-of-death control: offset + length exactly at limit passes.
    assert_parity(true, 17, 0, false, 443, true, false, 0x0001, 28, 5, 0, 0, false);
    // ICMP fragment (v4 + v6).
    assert_parity(true, 1, 0, false, 443, true, false, 0x0001, 28, 5, 0, 0, false);
    assert_parity(false, 58, 0, false, 443, true, false, 0x0001, 0, 0, 16, 8, false);
    // ICMP non-fragment control passes.
    assert_parity(true, 1, 0, false, 443, false, false, 0, 28, 5, 0, 0, false);
    // SYN-frag: TCP SYN on a first fragment.
    assert_parity(true, 6, 0x02, false, 443, true, true, 0x2000, 48, 5, 0, 0, false);
    // SYN-frag control: SYN on a whole packet passes this gate.
    assert_parity(true, 6, 0x02, false, 443, false, false, 0, 40, 5, 0, 0, false);
    // Tiny first fragment with unknown flags fails closed as syn-frag.
    assert_parity(true, 6, 0, true, 443, true, true, 0x2000, 28, 5, 0, 0, false);
    // TCP SYN+FIN.
    assert_parity(true, 6, 0x03, false, 443, false, false, 0, 40, 5, 0, 0, false);
    // TCP no-flag.
    assert_parity(true, 6, 0x00, false, 443, false, false, 0, 40, 5, 0, 0, false);
    // TCP FIN without ACK.
    assert_parity(true, 6, 0x01, false, 443, false, false, 0, 40, 5, 0, 0, false);
    // TCP FIN with ACK control passes.
    assert_parity(true, 6, 0x11, false, 443, false, false, 0, 40, 5, 0, 0, false);
    // WinNuke: URG to port 139.
    assert_parity(true, 6, 0x20, false, 139, false, false, 0, 40, 5, 0, 0, false);
    // WinNuke control: URG to another port passes.
    assert_parity(true, 6, 0x20, false, 443, false, false, 0, 40, 5, 0, 0, false);
    // TCP flags on a non-first fragment are never tested (no L4 header).
    assert_parity(true, 6, 0x03, false, 443, true, false, 0x0001, 40, 5, 0, 0, false);
    // Source-route, IPv4 LSRR sighting.
    assert_parity(true, 6, 0x10, false, 443, false, false, 0, 40, 6, 0, 0, true);
    // Source-route, IPv6 Routing-header sighting.
    assert_parity(false, 6, 0x10, false, 443, false, false, 0, 0, 0, 48, 0, true);
    // IPv6 teardrop: non-last fragment with 4 data bytes.
    assert_parity(false, 17, 0, false, 443, true, true, 0x0001, 0, 0, 12, 8, false);
    // IPv6 ping-of-death: maximal offset fragment.
    assert_parity(false, 17, 0, false, 443, true, false, 0xFFF8, 0, 0, 100, 8, false);
    // Clean transit-shaped packet: no check trips.
    assert_parity(true, 6, 0x10, false, 443, false, false, 0, 100, 5, 0, 0, false);
    // Sanity: the masks used above are the published bits.
    assert_eq!(HOST_SCREEN_PING_DEATH, 1 << 0);
    assert_eq!(HOST_SCREEN_TEARDROP, 1 << 1);
    assert_eq!(HOST_SCREEN_ICMP_FRAGMENT, 1 << 2);
    assert_eq!(HOST_SCREEN_SYN_FRAG, 1 << 3);
    assert_eq!(HOST_SCREEN_SOURCE_ROUTE, 1 << 4);
    assert_eq!(HOST_SCREEN_SYN_FIN, 1 << 5);
    assert_eq!(HOST_SCREEN_TCP_FLAGS, 1 << 6);
}

#[test]
fn host_malformed_disposition_follows_published_byte_16009() {
    let trip = HOST_SCREEN_TEARDROP;
    // Resolved zone, check enabled, drop posture.
    assert_eq!(
        host_malformed_disposition(true, HOST_SCREEN_TEARDROP, trip),
        HostMalformedDisposition::Drop
    );
    // Resolved zone, check enabled under alarm-without-drop.
    assert_eq!(
        host_malformed_disposition(true, HOST_SCREEN_TEARDROP | 0x80, trip),
        HostMalformedDisposition::AlarmPass
    );
    // Resolved zone, check disabled: passes even though another trips.
    assert_eq!(
        host_malformed_disposition(true, HOST_SCREEN_PING_DEATH, trip),
        HostMalformedDisposition::Pass
    );
    // Resolved zone, absent row (byte 0): checks off.
    assert_eq!(
        host_malformed_disposition(true, 0, trip),
        HostMalformedDisposition::Pass
    );
    // Unresolved zone fails closed regardless of any byte.
    assert_eq!(
        host_malformed_disposition(false, 0, trip),
        HostMalformedDisposition::Drop
    );
    assert_eq!(
        host_malformed_disposition(false, 0x7f, trip),
        HostMalformedDisposition::Drop
    );
}
