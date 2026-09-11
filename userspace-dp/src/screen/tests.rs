// Tests for screen.rs — relocated from inline
// `#[cfg(test)] mod tests` to keep screen.rs under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "screen_tests.rs"]` from screen.rs.

use super::syncookie::syn_cookie_zone_tag;
use super::*;
// #7888: the two WARN texts live in the `unresolved` child module after the
// split; `use super::*` does not reach into a sibling module's namespace.
use super::unresolved::{inert_profile_warn_message, missing_profile_warn_message};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// #3607: nanoseconds per second. The `_opts` / `validate_*` screen entry
/// points now take a monotonic `now_ns` before `now_secs`; these tests pass
/// `<secs> * NS` so the token-bucket consumers see second-granular time
/// (equivalent to the pre-#3607 per-second semantics) except where a test
/// explicitly drives sub-second `now_ns` to exercise the refill / micro-burst
/// behaviour.
const NS: u64 = 1_000_000_000;

fn default_profile() -> ScreenProfile {
    ScreenProfile {
        land: true,
        syn_fin: true,
        no_flag: true,
        fin_no_ack: true,
        winnuke: true,
        ping_death: true,
        teardrop: true,
        icmp_fragment: true,
        syn_frag: true,
        source_route: true,
        icmp_flood_threshold: 0,
        udp_flood_threshold: 0,
        syn_flood_threshold: 0,
        syn_cookie: false,
        syn_flood_alarm_threshold: 0,
        syn_flood_dst_threshold: 0,
        syn_flood_src_threshold: 0,
        session_limit_src: 0,
        session_limit_dst: 0,
        port_scan_threshold: 0,
        ip_sweep_threshold: 0,
        alarm_without_drop: false,
    }
}

fn tcp_pkt(src: IpAddr, dst: IpAddr, src_port: u16, dst_port: u16, flags: u8) -> ScreenPacketInfo {
    ScreenPacketInfo {
        addr_family: match src {
            IpAddr::V4(_) => libc::AF_INET as u8,
            IpAddr::V6(_) => libc::AF_INET6 as u8,
        },
        protocol: PROTO_TCP,
        tcp_flags: flags,
        src_ip: src,
        dst_ip: dst,
        src_port,
        dst_port,
        tcp_seq: 1,
        tcp_ack: 0,
        tcp_mss: 1460,
        pkt_len: 60,
        is_fragment: false,
        is_first_fragment: false,
        ip_ihl: 5,
        ip_frag_off: 0,
        ip_total_len: 60,
        ip_payload_len: 0,
        frag_data_off: 0,
        saw_ipv4_source_route: false,
        saw_ipv6_routing_header: false,
    }
}

fn icmp_pkt(src: IpAddr, dst: IpAddr, pkt_len: u16) -> ScreenPacketInfo {
    let proto = match src {
        IpAddr::V4(_) => PROTO_ICMP,
        IpAddr::V6(_) => PROTO_ICMPV6,
    };
    ScreenPacketInfo {
        addr_family: match src {
            IpAddr::V4(_) => libc::AF_INET as u8,
            IpAddr::V6(_) => libc::AF_INET6 as u8,
        },
        protocol: proto,
        tcp_flags: 0,
        src_ip: src,
        dst_ip: dst,
        src_port: 0,
        dst_port: 0,
        tcp_seq: 0,
        tcp_ack: 0,
        tcp_mss: 0,
        pkt_len,
        is_fragment: false,
        is_first_fragment: false,
        ip_ihl: 5,
        ip_frag_off: 0,
        ip_total_len: pkt_len,
        ip_payload_len: 0,
        frag_data_off: 0,
        saw_ipv4_source_route: false,
        saw_ipv6_routing_header: false,
    }
}

fn udp_pkt(src: IpAddr, dst: IpAddr) -> ScreenPacketInfo {
    ScreenPacketInfo {
        addr_family: match src {
            IpAddr::V4(_) => libc::AF_INET as u8,
            IpAddr::V6(_) => libc::AF_INET6 as u8,
        },
        protocol: PROTO_UDP,
        tcp_flags: 0,
        src_ip: src,
        dst_ip: dst,
        src_port: 5000,
        dst_port: 5001,
        tcp_seq: 0,
        tcp_ack: 0,
        tcp_mss: 0,
        pkt_len: 100,
        is_fragment: false,
        is_first_fragment: false,
        ip_ihl: 5,
        ip_frag_off: 0,
        ip_total_len: 100,
        ip_payload_len: 0,
        frag_data_off: 0,
        saw_ipv4_source_route: false,
        saw_ipv6_routing_header: false,
    }
}

fn make_state(zone: &str, profile: ScreenProfile) -> ScreenState {
    let mut state = ScreenState::new();
    let mut profiles = FxHashMap::default();
    profiles.insert(zone.to_string(), profile);
    state.update_profiles(profiles);
    state
}

// ================================================================
// Land attack
// ================================================================

#[test]
fn land_attack_v4() {
    let mut state = make_state("trust", default_profile());
    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    let pkt = tcp_pkt(src, src, 80, 80, TCP_SYN);
    assert_eq!(
        state.check_packet("trust", &pkt, 1),
        ScreenVerdict::Drop("land-attack")
    );
}

#[test]
fn land_attack_v6() {
    let mut state = make_state("trust", default_profile());
    let src = IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap());
    let pkt = tcp_pkt(src, src, 443, 443, TCP_SYN);
    assert_eq!(
        state.check_packet("trust", &pkt, 1),
        ScreenVerdict::Drop("land-attack")
    );
}

#[test]
fn land_attack_different_ports_drops() {
    // #2215 fail-on-revert (sub-bug B): the LAND signature is
    // src_ip == dst_ip ALONE, matching the authoritative BPF screen
    // (`13fa1009e^:bpf/xdp/xdp_screen.c` ~715-723) — NO port equality.
    // Pre-#2215 the check additionally required src_port == dst_port,
    // so this same-IP/different-port frame PASSED. It must now DROP.
    let mut state = make_state("trust", default_profile());
    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    let pkt = tcp_pkt(src, src, 80, 443, TCP_SYN);
    assert_eq!(
        state.check_packet("trust", &pkt, 1),
        ScreenVerdict::Drop("land-attack")
    );
}

#[test]
fn land_attack_v6_different_ports_drops() {
    // #2215 (sub-bug B): the BPF reference drops src==dst for IPv6 too,
    // unconditionally. Different ports must still DROP.
    let mut state = make_state("trust", default_profile());
    let src = IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap());
    let pkt = tcp_pkt(src, src, 80, 443, TCP_SYN);
    assert_eq!(
        state.check_packet("trust", &pkt, 1),
        ScreenVerdict::Drop("land-attack")
    );
}

#[test]
fn land_attack_udp_different_ports_drops() {
    // #2215 (sub-bug B): the LAND/anti-spoofing invariant is not
    // TCP-specific. A UDP frame whose source IP equals its destination
    // IP (different ports) must DROP. Pre-#2215 it passed.
    let mut profile = default_profile();
    // Keep the rate-based screens disabled so only LAND can fire.
    profile.udp_flood_threshold = 0;
    let mut state = make_state("trust", profile);
    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    let mut pkt = udp_pkt(src, src);
    pkt.src_port = 5000;
    pkt.dst_port = 5001;
    assert_eq!(
        state.check_packet("trust", &pkt, 1),
        ScreenVerdict::Drop("land-attack")
    );
}

#[test]
fn land_attack_distinct_ips_passes() {
    // Control: a normal frame whose source != destination must NOT be
    // flagged as a LAND attack regardless of ports.
    let mut state = make_state("trust", default_profile());
    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1));
    let pkt = tcp_pkt(src, dst, 80, 80, TCP_SYN);
    assert_eq!(state.check_packet("trust", &pkt, 1), ScreenVerdict::Pass);
}

#[test]
fn land_attack_disabled() {
    let mut profile = default_profile();
    profile.land = false;
    let mut state = make_state("trust", profile);
    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    let pkt = tcp_pkt(src, src, 80, 80, TCP_SYN);
    assert_eq!(state.check_packet("trust", &pkt, 1), ScreenVerdict::Pass);
}

// ================================================================
// TCP SYN+FIN
// ================================================================

#[test]
fn syn_fin_drops() {
    let mut state = make_state("trust", default_profile());
    let pkt = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        1234,
        80,
        TCP_SYN | TCP_FIN,
    );
    assert_eq!(
        state.check_packet("trust", &pkt, 1),
        ScreenVerdict::Drop("tcp-syn-fin")
    );
}

#[test]
fn syn_fin_disabled_passes() {
    let mut profile = default_profile();
    profile.syn_fin = false;
    // SYN+FIN also has FIN set without ACK, so disable fin_no_ack too
    profile.fin_no_ack = false;
    let mut state = make_state("trust", profile);
    let pkt = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        1234,
        80,
        TCP_SYN | TCP_FIN,
    );
    assert_eq!(state.check_packet("trust", &pkt, 1), ScreenVerdict::Pass);
}

// ================================================================
// TCP no-flag (null scan)
// ================================================================

#[test]
fn no_flag_drops() {
    let mut state = make_state("trust", default_profile());
    let pkt = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        1234,
        80,
        0, // no flags
    );
    assert_eq!(
        state.check_packet("trust", &pkt, 1),
        ScreenVerdict::Drop("tcp-no-flag")
    );
}

#[test]
fn no_flag_disabled_passes() {
    let mut profile = default_profile();
    profile.no_flag = false;
    let mut state = make_state("trust", profile);
    let pkt = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        1234,
        80,
        0,
    );
    assert_eq!(state.check_packet("trust", &pkt, 1), ScreenVerdict::Pass);
}

// ================================================================
// TCP FIN without ACK
// ================================================================

#[test]
fn fin_no_ack_drops() {
    let mut state = make_state("trust", default_profile());
    let pkt = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        1234,
        80,
        TCP_FIN, // FIN without ACK
    );
    assert_eq!(
        state.check_packet("trust", &pkt, 1),
        ScreenVerdict::Drop("tcp-fin-no-ack")
    );
}

#[test]
fn fin_with_ack_passes() {
    let mut state = make_state("trust", default_profile());
    let pkt = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        1234,
        80,
        TCP_FIN | TCP_ACK, // FIN+ACK is normal
    );
    assert_eq!(state.check_packet("trust", &pkt, 1), ScreenVerdict::Pass);
}

// ================================================================
// WinNuke
// ================================================================

#[test]
fn winnuke_drops() {
    let mut state = make_state("trust", default_profile());
    let pkt = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        1234,
        139, // NetBIOS
        TCP_URG | TCP_ACK,
    );
    assert_eq!(
        state.check_packet("trust", &pkt, 1),
        ScreenVerdict::Drop("winnuke")
    );
}

#[test]
fn winnuke_wrong_port_passes() {
    let mut state = make_state("trust", default_profile());
    let pkt = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        1234,
        80, // not 139
        TCP_URG | TCP_ACK,
    );
    assert_eq!(state.check_packet("trust", &pkt, 1), ScreenVerdict::Pass);
}

#[test]
fn winnuke_disabled_passes() {
    let mut profile = default_profile();
    profile.winnuke = false;
    let mut state = make_state("trust", profile);
    let pkt = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        1234,
        139,
        TCP_URG | TCP_ACK,
    );
    assert_eq!(state.check_packet("trust", &pkt, 1), ScreenVerdict::Pass);
}

// ================================================================
// Ping of Death
// ================================================================

/// Build an IPv4 fragment with the given fragment-offset (in 8-byte
/// units, i.e. the raw 13-bit offset field) and IP total length.
/// `more_fragments` controls the MF bit. Used by the #2215
/// ping-of-death and teardrop regression tests.
fn ipv4_fragment(
    src: IpAddr,
    dst: IpAddr,
    protocol: u8,
    frag_units: u16,
    more_fragments: bool,
    ip_total_len: u16,
) -> ScreenPacketInfo {
    let mut frag_off = frag_units & 0x1FFF;
    if more_fragments {
        frag_off |= 0x2000;
    }
    let is_first = more_fragments && (frag_units & 0x1FFF) == 0;
    ScreenPacketInfo {
        addr_family: libc::AF_INET as u8,
        protocol,
        tcp_flags: 0,
        src_ip: src,
        dst_ip: dst,
        src_port: 0,
        dst_port: 0,
        tcp_seq: 0,
        tcp_ack: 0,
        tcp_mss: 0,
        pkt_len: ip_total_len,
        is_fragment: (frag_off & 0x3FFF) != 0,
        is_first_fragment: is_first,
        ip_ihl: 5,
        ip_frag_off: frag_off,
        ip_total_len,
        ip_payload_len: 0,
        frag_data_off: 0,
        saw_ipv4_source_route: false,
        saw_ipv6_routing_header: false,
    }
}

#[test]
fn ping_of_death_oversized_fragment_drops() {
    // #2215 fail-on-revert (sub-bug A): the classic ping-of-death is a
    // fragment whose reassembled contribution exceeds the 65535-byte IP
    // length limit. The dataplane does not reassemble, so it is detected
    // per-fragment: offset_bytes = (frag_off & 0x1FFF) << 3; if
    // offset_bytes + ip_total_len > 65535 -> drop (BPF #893 formula).
    //
    // Last fragment at offset 8191 units = 65528 bytes carrying a 60-byte
    // IP datagram: 65528 + 60 = 65588 > 65535 -> ping-of-death. Pre-#2215
    // the check was ICMP-only dead code (`pkt_len as u32 > 65535`,
    // unsatisfiable for a u16) so this PASSED.
    let mut state = make_state("trust", default_profile());
    let pkt = ipv4_fragment(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        PROTO_ICMP,
        8191, // 8191 * 8 = 65528 bytes
        false,
        60,
    );
    assert_eq!(
        state.check_packet("trust", &pkt, 1),
        ScreenVerdict::Drop("ping-of-death")
    );
}

#[test]
fn ping_of_death_oversized_fragment_any_proto_drops() {
    // #2215 (sub-bug A): the BPF reference fires for ANY IPv4 protocol,
    // not just ICMP. A UDP fragment that overflows the reassembly limit
    // must DROP. (Disable the UDP-flood screen so only ping-of-death can
    // fire.)
    let mut profile = default_profile();
    profile.udp_flood_threshold = 0;
    let mut state = make_state("trust", profile);
    let pkt = ipv4_fragment(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        PROTO_UDP,
        8190, // 8190 * 8 = 65520 bytes
        false,
        100, // 65520 + 100 = 65620 > 65535
    );
    assert_eq!(
        state.check_packet("trust", &pkt, 1),
        ScreenVerdict::Drop("ping-of-death")
    );
}

#[test]
fn ping_of_death_in_bounds_fragment_passes() {
    // Control: a fragment whose offset + total length stays within the
    // 65535-byte limit must NOT be flagged as ping-of-death. Use a UDP
    // fragment (with the udp-flood screen disabled) so neither the
    // icmp-fragment nor teardrop screens can mask the ping-of-death
    // outcome; payload (1500-20=1480) is well above the 8-byte teardrop
    // floor regardless.
    let mut profile = default_profile();
    profile.udp_flood_threshold = 0;
    let mut state = make_state("trust", profile);
    let pkt = ipv4_fragment(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        PROTO_UDP,
        100,   // 100 * 8 = 800 bytes
        false, // not the last fragment is irrelevant; a mid-chain fragment
        1500,  // 800 + 1500 = 2300 <= 65535
    );
    assert_eq!(state.check_packet("trust", &pkt, 1), ScreenVerdict::Pass);
}

#[test]
fn ping_of_death_non_fragment_passes() {
    // Control: a normal (unfragmented) ICMP echo must NOT be flagged —
    // the check only applies to fragments.
    let mut state = make_state("trust", default_profile());
    let pkt = icmp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        84,
    );
    assert_eq!(state.check_packet("trust", &pkt, 1), ScreenVerdict::Pass);
}

#[test]
fn normal_ping_passes() {
    let mut state = make_state("trust", default_profile());
    let pkt = icmp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        84,
    );
    assert_eq!(state.check_packet("trust", &pkt, 1), ScreenVerdict::Pass);
}

/// Build a `ScreenPacketInfo` for an IPv6 fragment the way `extract.rs`
/// would populate it: `frag_units` is the IPv6 fragment offset in 8-byte
/// units (top 13 bits of the fragment-header frag_off field), `more`
/// sets the M bit, `payload_len` is the IPv6 base-header payload-length
/// field (bytes after the 40-byte fixed header), and `frag_data_off` is
/// the payload-region bytes consumed by extension headers up to and
/// including the 8-byte fragment header (8 when the fragment header is
/// the only/first ext header). Used by the #2293 IPv6 ping-of-death
/// tests.
fn ipv6_fragment(
    src: IpAddr,
    dst: IpAddr,
    protocol: u8,
    frag_units: u16,
    more: bool,
    payload_len: u16,
    frag_data_off: u16,
) -> ScreenPacketInfo {
    // IPv6 fragment frag_off field: offset(13) | reserved(2) | M(1).
    let frag_off = ((frag_units & 0x1FFF) << 3) | (more as u16);
    let is_first = more && (frag_units & 0x1FFF) == 0;
    ScreenPacketInfo {
        addr_family: libc::AF_INET6 as u8,
        protocol,
        tcp_flags: 0,
        src_ip: src,
        dst_ip: dst,
        src_port: 0,
        dst_port: 0,
        tcp_seq: 0,
        tcp_ack: 0,
        tcp_mss: 0,
        pkt_len: payload_len.saturating_add(40),
        is_fragment: (frag_off & 0xFFF8) != 0 || more,
        is_first_fragment: is_first,
        ip_ihl: 5,
        ip_frag_off: frag_off,
        ip_total_len: 0,
        ip_payload_len: payload_len,
        frag_data_off,
        saw_ipv4_source_route: false,
        saw_ipv6_routing_header: false,
    }
}

#[test]
fn ping_of_death_v6_oversized_fragment_drops() {
    // #2293: IPv6 ping-of-death — a fragment whose reassembled
    // contribution exceeds the 65535-byte IPv6-payload limit must DROP,
    // mirroring the IPv4 per-fragment formula. Last fragment at offset
    // 8191 units = 65528 bytes, payload_len=68 with a single 8-byte
    // fragment header (frag_data_off=8) -> frag_data=60:
    // 65528 + 60 = 65588 > 65535 -> ping-of-death. Pre-#2293 the v6
    // family never reached the oversize check (IPv4-only gate).
    let mut state = make_state("trust", default_profile());
    let pkt = ipv6_fragment(
        IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()),
        IpAddr::V6("2001:db8::2".parse::<Ipv6Addr>().unwrap()),
        PROTO_ICMPV6,
        8191, // 8191 * 8 = 65528 bytes
        false,
        68, // payload_len; frag_data = 68 - 8 = 60
        8,
    );
    assert_eq!(
        state.check_packet("trust", &pkt, 1),
        ScreenVerdict::Drop("ping-of-death")
    );
}

#[test]
fn ping_of_death_v6_oversized_fragment_any_proto_drops() {
    // #2293: like the IPv4 path, the IPv6 check fires for ANY protocol,
    // not just ICMPv6. A UDP fragment that overflows the reassembly
    // ceiling must DROP. (Disable the UDP-flood screen so only
    // ping-of-death can fire.)
    let mut profile = default_profile();
    profile.udp_flood_threshold = 0;
    let mut state = make_state("trust", profile);
    let pkt = ipv6_fragment(
        IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()),
        IpAddr::V6("2001:db8::2".parse::<Ipv6Addr>().unwrap()),
        PROTO_UDP,
        8190, // 8190 * 8 = 65520 bytes
        false,
        108, // frag_data = 108 - 8 = 100; 65520 + 100 = 65620 > 65535
        8,
    );
    assert_eq!(
        state.check_packet("trust", &pkt, 1),
        ScreenVerdict::Drop("ping-of-death")
    );
}

#[test]
fn ping_of_death_v6_in_bounds_fragment_passes() {
    // Control: an IPv6 fragment whose offset + data stays within the
    // 65535 ceiling must NOT be flagged. UDP with udp-flood disabled so
    // neither icmp-fragment nor a flood screen masks the outcome.
    let mut profile = default_profile();
    profile.udp_flood_threshold = 0;
    let mut state = make_state("trust", profile);
    let pkt = ipv6_fragment(
        IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()),
        IpAddr::V6("2001:db8::2".parse::<Ipv6Addr>().unwrap()),
        PROTO_UDP,
        100,   // 100 * 8 = 800 bytes
        false, // mid-chain fragment
        1488,  // frag_data = 1488 - 8 = 1480; 800 + 1480 = 2280 <= 65535
        8,
    );
    assert_eq!(state.check_packet("trust", &pkt, 1), ScreenVerdict::Pass);
}

#[test]
fn ping_of_death_v6_non_fragment_passes() {
    // Control: a normal (unfragmented) ICMPv6 echo must NOT be flagged —
    // the check only applies to fragments.
    let mut state = make_state("trust", default_profile());
    let pkt = icmp_pkt(
        IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()),
        IpAddr::V6("2001:db8::2".parse::<Ipv6Addr>().unwrap()),
        84,
    );
    assert_eq!(state.check_packet("trust", &pkt, 1), ScreenVerdict::Pass);
}

#[test]
fn ping_of_death_v6_disabled_profile_passes() {
    // Fail-on-revert guard: with ping_death OFF, even an oversize v6
    // fragment must PASS (the check must be gated on the profile flag,
    // not always-on). Disable udp-flood so only ping-of-death could
    // possibly fire.
    let mut profile = default_profile();
    profile.ping_death = false;
    profile.udp_flood_threshold = 0;
    let mut state = make_state("trust", profile);
    let pkt = ipv6_fragment(
        IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()),
        IpAddr::V6("2001:db8::2".parse::<Ipv6Addr>().unwrap()),
        PROTO_UDP,
        8191,
        false,
        68,
        8,
    );
    assert_eq!(state.check_packet("trust", &pkt, 1), ScreenVerdict::Pass);
}

// ================================================================
// Teardrop
// ================================================================

#[test]
fn teardrop_drops() {
    let mut state = make_state("trust", default_profile());
    let pkt = ScreenPacketInfo {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        tcp_flags: TCP_ACK, // use ACK to avoid no-flag check
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        src_port: 1234,
        dst_port: 80,
        tcp_seq: 1,
        tcp_ack: 0,
        tcp_mss: 1460,
        pkt_len: 28,
        is_fragment: true,
        is_first_fragment: false,
        ip_ihl: 5,
        ip_frag_off: 0x0001 | 0x2000, // offset=1 (non-first frag), MF=1
        ip_total_len: 24,             // 20 byte header + 4 byte payload (< 8)
        ip_payload_len: 0,
        frag_data_off: 0,
        saw_ipv4_source_route: false,
        saw_ipv6_routing_header: false,
    };
    assert_eq!(
        state.check_packet("trust", &pkt, 1),
        ScreenVerdict::Drop("teardrop")
    );
}

#[test]
fn teardrop_first_fragment_passes() {
    let _state = make_state("trust", default_profile());
    let pkt = ScreenPacketInfo {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        tcp_flags: 0,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        src_port: 1234,
        dst_port: 80,
        tcp_seq: 1,
        tcp_ack: 0,
        tcp_mss: 1460,
        pkt_len: 24,
        is_fragment: true,
        // #1137 Copilot review: ip_frag_off=0x2000 means MF=1 &&
        // offset==0, which IS a first-fragment. Keep the fields
        // consistent with each other so future regressions don't
        // hide behind misleading metadata.
        is_first_fragment: true,
        ip_ihl: 5,
        ip_frag_off: 0x2000, // offset=0 (first frag), MF=1
        ip_total_len: 24,
        ip_payload_len: 0,
        frag_data_off: 0,
        saw_ipv4_source_route: false,
        saw_ipv6_routing_header: false,
    };
    // First fragment (offset=0) — teardrop only triggers on non-first
    // However no_flag check will trigger first since tcp_flags=0
    // Use a profile with only teardrop enabled
    let mut profile = ScreenProfile::default();
    profile.teardrop = true;
    let mut st = make_state("trust", profile);
    assert_eq!(st.check_packet("trust", &pkt, 1), ScreenVerdict::Pass);
}

#[test]
fn teardrop_zero_payload_non_first_fragment_drops() {
    // #3027 fail-on-revert: a non-first fragment whose ip_total_len is
    // EQUAL to the header length (zero payload) is malformed and must
    // DROP as teardrop. ip_ihl=5 → hdr_len=20, ip_total_len=20.
    //
    // The pre-#3027 code only entered the payload-size branch when
    // ip_total_len > hdr_len, so 20 > 20 is false and this packet
    // slipped through as a PASS. Reverting the fix makes this assert
    // fail (Pass instead of Drop). A teardrop-only profile isolates the
    // check from the no-flag / other screens.
    let mut profile = ScreenProfile::default();
    profile.teardrop = true;
    let mut state = make_state("trust", profile);
    let pkt = ipv4_fragment(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        PROTO_TCP,
        2,     // frag offset = 2 (non-first fragment)
        false, // no MORE_FRAGMENTS — a trailing fragment
        20,    // ip_total_len == hdr_len (ihl=5*4) → zero payload
    );
    assert_eq!(
        state.check_packet("trust", &pkt, 1),
        ScreenVerdict::Drop("teardrop")
    );
}

#[test]
fn teardrop_under_length_non_first_fragment_drops() {
    // #3027 fail-on-revert: a non-first fragment whose claimed
    // ip_total_len is LESS than the header length ("negative" payload)
    // is malformed and must DROP. ip_ihl=5 → hdr_len=20,
    // ip_total_len=18. Pre-#3027 (ip_total_len > hdr_len gate) PASSed
    // this; the subtraction would also have underflowed.
    let mut profile = ScreenProfile::default();
    profile.teardrop = true;
    let mut state = make_state("trust", profile);
    let pkt = ipv4_fragment(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        PROTO_TCP,
        2, // non-first fragment
        false,
        18, // ip_total_len < hdr_len (20) → under-length / "negative"
    );
    assert_eq!(
        state.check_packet("trust", &pkt, 1),
        ScreenVerdict::Drop("teardrop")
    );
}

#[test]
fn teardrop_v6_tiny_non_first_fragment_drops() {
    // #3119 fail-on-revert: an IPv6 non-first Fragment-header fragment
    // carrying a tiny data contribution (< 8 bytes) is the IPv6 teardrop
    // signature and must DROP. Pre-#3119 `check_teardrop` was gated on
    // AF_INET only, so this slipped through as a PASS even though the
    // sibling ping-of-death check already screened IPv6.
    //
    // #9426 RE-ANCHOR, not a rewrite. #3119's claim above is that the IPv6
    // ARM EXISTS AT ALL, and that half is still true and still fail-on-revert:
    // delete the AF_INET6 branch and this reds. What was wrong was the
    // FIXTURE's `more: false` — that builds an explicitly TRAILING (M=0)
    // fragment carrying 4 bytes, which is a LEGAL last fragment (every
    // fragment except the last must be an 8-byte multiple; the last may be any
    // size), not a teardrop. The cell's own justification said a tiny trailing
    // fragment "is the IPv6 teardrop signature" — a factual claim about IP,
    // and it is false. Junos specifies `tear-drop` as OVERLAP detection and
    // says nothing about tiny tails.
    //
    // So the shape is corrected to `more: true` — a NON-LAST fragment carrying
    // 4 bytes, which genuinely is malformed — and the claim, the reason and
    // the assertion are kept verbatim. The legal case the old fixture actually
    // described is now asserted, as a PASS, by
    // `teardrop_v6_last_fragment_tiny_payload_passes_9426`.
    //
    // offset 2 units = 16 bytes (non-first); payload_len=12 with a single
    // 8-byte fragment header (frag_data_off=8) → frag_data = 12 - 8 = 4
    // (< 8) → teardrop. Use UDP with udp-flood disabled and a
    // teardrop-only profile so no other screen masks the outcome.
    let mut profile = ScreenProfile::default();
    profile.teardrop = true;
    let mut state = make_state("trust", profile);
    let pkt = ipv6_fragment(
        IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()),
        IpAddr::V6("2001:db8::2".parse::<Ipv6Addr>().unwrap()),
        PROTO_UDP,
        2,    // offset = 2 units = 16 bytes (non-first fragment)
        true, // NON-LAST fragment (M=1) — #9426, see above
        12,   // payload_len; frag_data = 12 - 8 = 4 (< 8)
        8,
    );
    assert_eq!(
        state.check_packet("trust", &pkt, 1),
        ScreenVerdict::Drop("teardrop")
    );
}

#[test]
fn teardrop_v6_under_length_non_first_fragment_drops() {
    // #3119 fail-on-revert: an IPv6 non-first fragment whose declared
    // ip_payload_len is SMALLER than the ext-header bytes already walked
    // (frag_data_off) yields a 0-byte (saturating) data contribution —
    // malformed, the IPv6 analogue of the #3027 zero/negative-payload
    // case — and must DROP.
    let mut profile = ScreenProfile::default();
    profile.teardrop = true;
    let mut state = make_state("trust", profile);
    let pkt = ipv6_fragment(
        IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()),
        IpAddr::V6("2001:db8::2".parse::<Ipv6Addr>().unwrap()),
        PROTO_UDP,
        2, // non-first fragment
        false,
        4, // payload_len < frag_data_off (8) → saturating_sub → 0 (< 8)
        8,
    );
    assert_eq!(
        state.check_packet("trust", &pkt, 1),
        ScreenVerdict::Drop("teardrop")
    );
}

#[test]
fn teardrop_v6_normal_fragment_passes() {
    // Control: an IPv6 non-first fragment carrying a healthy data
    // contribution (>= 8 bytes) must NOT be flagged as teardrop. offset
    // 100 units = 800 bytes; payload_len=1488 with frag_data_off=8 →
    // frag_data = 1480 (>= 8). UDP with udp-flood disabled and a
    // teardrop-only profile so only teardrop could fire.
    let mut profile = ScreenProfile::default();
    profile.teardrop = true;
    profile.udp_flood_threshold = 0;
    let mut state = make_state("trust", profile);
    let pkt = ipv6_fragment(
        IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()),
        IpAddr::V6("2001:db8::2".parse::<Ipv6Addr>().unwrap()),
        PROTO_UDP,
        100,   // 800 bytes (non-first fragment)
        false, // mid-chain fragment
        1488,  // frag_data = 1488 - 8 = 1480 (>= 8)
        8,
    );
    assert_eq!(state.check_packet("trust", &pkt, 1), ScreenVerdict::Pass);
}

#[test]
fn teardrop_v6_first_fragment_passes() {
    // Control: an IPv6 FIRST fragment (offset 0) is never a teardrop even
    // with a tiny data contribution — teardrop only fires on non-first
    // fragments. M=1, offset=0.
    let mut profile = ScreenProfile::default();
    profile.teardrop = true;
    let mut state = make_state("trust", profile);
    let pkt = ipv6_fragment(
        IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()),
        IpAddr::V6("2001:db8::2".parse::<Ipv6Addr>().unwrap()),
        PROTO_UDP,
        0,    // offset 0 → first fragment
        true, // MORE_FRAGMENTS
        12,   // tiny data, but offset==0 so not a teardrop
        8,
    );
    assert_eq!(state.check_packet("trust", &pkt, 1), ScreenVerdict::Pass);
}

#[test]
fn teardrop_v6_disabled_profile_passes() {
    // Fail-on-revert guard: with teardrop OFF, even a tiny v6 non-first
    // fragment must PASS (the IPv6 arm must be gated on the profile flag,
    // not always-on).
    let mut profile = ScreenProfile::default();
    profile.teardrop = false;
    profile.udp_flood_threshold = 0;
    let mut state = make_state("trust", profile);
    let pkt = ipv6_fragment(
        IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()),
        IpAddr::V6("2001:db8::2".parse::<Ipv6Addr>().unwrap()),
        PROTO_UDP,
        2,
        false,
        12,
        8,
    );
    assert_eq!(state.check_packet("trust", &pkt, 1), ScreenVerdict::Pass);
}

// ================================================================
// ICMP fragment
// ================================================================

#[test]
fn icmp_fragment_drops() {
    let mut state = make_state("trust", default_profile());
    let mut pkt = icmp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        84,
    );
    pkt.is_fragment = true;
    assert_eq!(
        state.check_packet("trust", &pkt, 1),
        ScreenVerdict::Drop("icmp-fragment")
    );
}

#[test]
fn icmpv6_fragment_drops() {
    let mut state = make_state("trust", default_profile());
    let mut pkt = icmp_pkt(
        IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()),
        IpAddr::V6("2001:db8::2".parse::<Ipv6Addr>().unwrap()),
        84,
    );
    pkt.is_fragment = true;
    assert_eq!(
        state.check_packet("trust", &pkt, 1),
        ScreenVerdict::Drop("icmp-fragment")
    );
}

// ================================================================
// #1137 SCREEN_SYN_FRAG — TCP SYN on a first-fragment is the
// fragmentation-based attack pattern. Mirrors BPF SCREEN_SYN_FRAG
// (see #866 / docs/pr/bug-batch-866-867-916-925/design.md §1).
// ================================================================

#[test]
fn syn_frag_drops_on_first_fragment_with_syn() {
    let mut state = make_state("trust", default_profile());
    let mut pkt = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        12345,
        80,
        TCP_SYN,
    );
    pkt.is_fragment = true;
    pkt.is_first_fragment = true;
    assert_eq!(
        state.check_packet("trust", &pkt, 1),
        ScreenVerdict::Drop("syn-frag")
    );
}

#[test]
fn syn_frag_passes_when_first_fragment_without_syn() {
    let mut state = make_state("trust", default_profile());
    let mut pkt = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        12345,
        80,
        TCP_ACK, // ACK without SYN — not a SYN-fragment
    );
    pkt.is_fragment = true;
    pkt.is_first_fragment = true;
    assert_eq!(state.check_packet("trust", &pkt, 1), ScreenVerdict::Pass);
}

#[test]
fn syn_frag_passes_on_subsequent_fragment() {
    // Subsequent fragments don't carry the L4 header, so tcp_flags is
    // unreliable. is_first_fragment=0 keeps the check from firing on
    // them — even if SYN bit is somehow set in the meta (e.g. a
    // crafted attacker frame), is_first_fragment guards us.
    let mut state = make_state("trust", default_profile());
    let mut pkt = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        12345,
        80,
        TCP_SYN,
    );
    pkt.is_fragment = true;
    pkt.is_first_fragment = false;
    assert_eq!(state.check_packet("trust", &pkt, 1), ScreenVerdict::Pass);
}

#[test]
fn syn_frag_passes_on_non_fragmented_syn() {
    // Non-fragmented TCP SYN is normal connection setup, not the
    // syn-frag attack. Should pass regardless of profile.syn_frag.
    let mut profile = ScreenProfile::default();
    profile.syn_frag = true;
    let mut state = make_state("trust", profile);
    let pkt = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        12345,
        80,
        TCP_SYN,
    );
    // Defaults: is_fragment=false, is_first_fragment=false
    assert_eq!(state.check_packet("trust", &pkt, 1), ScreenVerdict::Pass);
}

#[test]
fn syn_frag_disabled_when_profile_off() {
    // Even a SYN-bearing first-fragment passes when the profile
    // doesn't enable syn_frag.
    let profile = ScreenProfile::default(); // all checks off
    let mut state = make_state("trust", profile);
    let mut pkt = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        12345,
        80,
        TCP_SYN,
    );
    pkt.is_fragment = true;
    pkt.is_first_fragment = true;
    assert_eq!(state.check_packet("trust", &pkt, 1), ScreenVerdict::Pass);
}

#[test]
fn extract_screen_info_ipv4_first_fragment() {
    // Build a synthetic IPv4 header at offset 14 (Ethernet) with
    // MF=1 and offset=0. version=4, ihl=5, tot_len=40 (20 IP + 20 TCP),
    // protocol=TCP, src=1.2.3.4 dst=5.6.7.8.
    let mut frame = vec![0u8; 14 + 40];
    // Ethernet: zeroed (we don't parse it here)
    let ip = 14;
    frame[ip] = 0x45; // version=4, ihl=5
    frame[ip + 2..ip + 4].copy_from_slice(&40u16.to_be_bytes());
    // frag_off: MF (0x2000) | offset 0 = 0x2000 BE
    frame[ip + 6..ip + 8].copy_from_slice(&0x2000u16.to_be_bytes());
    frame[ip + 9] = 6; // protocol = TCP
    frame[ip + 12..ip + 16].copy_from_slice(&[1, 2, 3, 4]);
    frame[ip + 16..ip + 20].copy_from_slice(&[5, 6, 7, 8]);

    let info = extract_screen_info(
        &frame,
        libc::AF_INET as u8,
        6,    // TCP
        0x02, // SYN
        40,
        IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
        12345,
        80,
        14,
    )
    .expect("valid IPv4 first fragment parses");
    assert!(info.is_fragment, "MF=1 → is_fragment");
    assert!(
        info.is_first_fragment,
        "MF=1 && offset==0 → is_first_fragment"
    );
}

#[test]
fn extract_screen_info_ipv4_subsequent_fragment() {
    // offset=8 octets (encoded as 0x0001 since offset is in 8-byte units),
    // MF=0 (last fragment).
    let mut frame = vec![0u8; 14 + 40];
    let ip = 14;
    frame[ip] = 0x45;
    frame[ip + 2..ip + 4].copy_from_slice(&40u16.to_be_bytes());
    frame[ip + 6..ip + 8].copy_from_slice(&0x0001u16.to_be_bytes());
    frame[ip + 9] = 6;

    let info = extract_screen_info(
        &frame,
        libc::AF_INET as u8,
        6,
        0,
        40,
        IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
        0,
        0,
        14,
    )
    .expect("valid IPv4 subsequent fragment parses");
    assert!(info.is_fragment, "offset>0 → is_fragment");
    assert!(
        !info.is_first_fragment,
        "offset>0 → is_first_fragment must be 0"
    );
}

#[test]
fn extract_screen_info_ipv6_first_fragment() {
    // IPv6 base header (40 bytes) at offset 14, with NextHdr=44 (FRAGMENT),
    // followed by an 8-byte fragment ext header. MF=1, offset=0.
    let mut frame = vec![0u8; 14 + 40 + 8];
    // IPv6 first byte: version=6 in top nibble
    frame[14] = 0x60;
    // NextHdr = FRAGMENT
    frame[14 + 6] = 44;
    // Fragment header at offset 14+40 = 54: nexthdr=6 (TCP), reserved=0,
    // frag_off (MF=1, offset=0) = 0x0001 in big-endian.
    let frag_off_pos = 14 + 40 + 2;
    frame[14 + 40] = 6; // inner nexthdr = TCP
    frame[frag_off_pos..frag_off_pos + 2].copy_from_slice(&0x0001u16.to_be_bytes());

    let info = extract_screen_info(
        &frame,
        libc::AF_INET6 as u8,
        6,
        0x02,
        48,
        IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()),
        IpAddr::V6("2001:db8::2".parse::<Ipv6Addr>().unwrap()),
        12345,
        80,
        14,
    )
    .expect("valid IPv6 first fragment parses");
    assert!(info.is_fragment, "IPv6 MF=1 → is_fragment");
    assert!(
        info.is_first_fragment,
        "IPv6 MF=1 && offset==0 → is_first_fragment"
    );
}

#[test]
fn extract_screen_info_ipv6_subsequent_fragment() {
    // IPv6 fragment with offset>0 (e.g. offset=1 in 8-byte units → 0x0008).
    let mut frame = vec![0u8; 14 + 40 + 8];
    frame[14] = 0x60;
    frame[14 + 6] = 44;
    let frag_off_pos = 14 + 40 + 2;
    frame[14 + 40] = 6;
    frame[frag_off_pos..frag_off_pos + 2].copy_from_slice(&0x0008u16.to_be_bytes());

    let info = extract_screen_info(
        &frame,
        libc::AF_INET6 as u8,
        6,
        0,
        48,
        IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()),
        IpAddr::V6("2001:db8::2".parse::<Ipv6Addr>().unwrap()),
        0,
        0,
        14,
    )
    .expect("valid IPv6 subsequent fragment parses");
    assert!(info.is_fragment, "IPv6 offset>0 → is_fragment");
    assert!(
        !info.is_first_fragment,
        "IPv6 offset>0 → is_first_fragment must be 0"
    );
}

#[test]
fn extract_screen_info_ipv6_first_fragment_extheader_after_fragment_extracts_tcp() {
    // #3120 ext-chain TCP-flag evasion: an IPv6 FIRST fragment whose
    // chain is `Fragment(offset 0) → Destination-Options → TCP(SYN)`.
    // RFC 8200 permits a destination-options header AFTER the fragment
    // header, so the L4 (TCP) header is present in this first fragment,
    // just one extension header further along. The pre-fix walk only
    // checked whether the header IMMEDIATELY after the fragment header was
    // TCP and then `break`d unconditionally, leaving `tcp_offset = None` —
    // so the TCP seq/ack/MSS were never extracted and the TCP-flag screens
    // / SYN-cookie flood challenge were bypassed. The fix continues the
    // walk past the fragment header for first fragments, so the trailing
    // dest-opts header is traversed and the real TCP header is found.
    //
    // Layout (l3_offset = 14):
    //   14            Ethernet
    //   14+0          IPv6 base (40), NextHdr = 44 (FRAGMENT)
    //   14+40 = 54    Fragment header (8): NextHdr = 60 (DEST), MF=1 off=0
    //   54+8  = 62    Dest-Options header (8): NextHdr = 6 (TCP), len=0
    //   62+8  = 70    TCP (20 + 4-byte MSS option)
    let mut frame = vec![0u8; 14 + 40 + 8 + 8 + 24];
    frame[14] = 0x60; // version=6
    frame[14 + 6] = 44; // base NextHdr = FRAGMENT
    // Fragment header at 54.
    frame[54] = 60; // NextHdr = DEST (an ext header, NOT TCP)
    let frag_off_pos = 54 + 2;
    frame[frag_off_pos..frag_off_pos + 2].copy_from_slice(&0x0001u16.to_be_bytes()); // MF=1, off=0
    // Destination-Options header at 62: NextHdr=TCP, HdrExtLen=0 → 8 bytes.
    frame[62] = 6; // NextHdr = TCP
    frame[63] = 0; // HdrExtLen = 0 → (0+1)*8 = 8 bytes
    // TCP header at 70.
    let tcp = 70;
    frame[tcp + 4..tcp + 8].copy_from_slice(&0x1122_3344u32.to_be_bytes()); // seq
    frame[tcp + 8..tcp + 12].copy_from_slice(&0x0000_0000u32.to_be_bytes()); // ack
    frame[tcp + 12] = 0x60; // data offset = 6 words = 24 bytes (room for MSS opt)
    frame[tcp + 20] = 2; // option kind = MSS
    frame[tcp + 21] = 4; // option len
    frame[tcp + 22..tcp + 24].copy_from_slice(&1400u16.to_be_bytes()); // MSS value

    let info = extract_screen_info(
        &frame,
        libc::AF_INET6 as u8,
        6,    // TCP
        0x02, // SYN — the attack-relevant flag the screens must see
        frame.len() as u16,
        IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()),
        IpAddr::V6("2001:db8::2".parse::<Ipv6Addr>().unwrap()),
        12345,
        80,
        14,
    )
    .expect("first fragment with ext header after fragment must parse");

    assert!(info.is_fragment, "MF=1 → is_fragment");
    assert!(
        info.is_first_fragment,
        "MF=1 && offset==0 → is_first_fragment"
    );
    // The walk must have continued past the fragment + dest-opts headers to
    // the real TCP header. If the FRAGMENT arm still `break`d (the #3120
    // bug), `tcp_offset` stays None and these fields are left at 0 — the TCP
    // flags/seq/MSS are hidden from the screens (the evasion). The SYN flag
    // (passed in `tcp_flags`) is still seen, but the SYN-cookie challenge
    // consumes `tcp_mss`, which is only populated when the L4 is reached.
    assert_eq!(
        info.tcp_seq, 0x1122_3344,
        "TCP seq must be extracted past the ext-header chain"
    );
    assert_eq!(
        info.tcp_mss, 1400,
        "TCP MSS option must be extracted past the ext-header chain"
    );
    assert_eq!(
        info.tcp_flags, 0x02,
        "SYN flag visible to the TCP-flag screens"
    );
}

#[test]
fn extract_screen_info_ipv6_mobility_before_fragment_extracts_tcp() {
    // #4517 ext-header IDS evasion: an IPv6 FIRST fragment whose chain is
    // `HOP → MOBILITY(135) → FRAGMENT(offset 0) → TCP(SYN)`. Mobility (135)
    // is a length-prefixed extension header (RFC 6275), but before #4517
    // the screen walk enumerated only {0,43,44,51,60} and STOPPED at type
    // 135 (`_ => break`) — leaving `is_fragment`/`is_first_fragment` false
    // and `tcp_offset` None, so the SYN behind the Mobility header was
    // hidden from the `syn-frag` (and teardrop/ping-of-death) screens. The
    // fix walks Mobility/HIP/Shim6/experimental as generic EHs, so the
    // FRAGMENT header and the real TCP header are reached.
    //
    // Layout (l3_offset = 14):
    //   14+0   = 14  IPv6 base (40), NextHdr = 0 (HOP)
    //   14+40  = 54  Hop-by-Hop (8): NextHdr = 135 (MOBILITY), len = 0
    //   54+8   = 62  Mobility (8):   NextHdr = 44  (FRAGMENT), len = 0
    //   62+8   = 70  Fragment (8):   NextHdr = 6   (TCP), MF=1 off=0
    //   70+8   = 78  TCP (20 + 4-byte MSS option)
    let mut frame = vec![0u8; 14 + 40 + 8 + 8 + 8 + 24];
    frame[14] = 0x60; // version 6
    frame[14 + 6] = 0; // base NextHdr = HOP-BY-HOP
    frame[54] = 135; // HOP NextHdr = MOBILITY, HdrExtLen(55)=0 → 8 bytes
    frame[62] = 44; // MOBILITY NextHdr = FRAGMENT, HdrExtLen(63)=0 → 8 bytes
    frame[70] = 6; // FRAGMENT NextHdr = TCP
    let frag_off_pos = 70 + 2;
    frame[frag_off_pos..frag_off_pos + 2].copy_from_slice(&0x0001u16.to_be_bytes()); // MF=1, off=0
    let tcp = 78;
    frame[tcp + 4..tcp + 8].copy_from_slice(&0x1122_3344u32.to_be_bytes()); // seq
    frame[tcp + 12] = 0x60; // data offset = 6 words = 24 bytes
    frame[tcp + 20] = 2; // MSS option kind
    frame[tcp + 21] = 4; // MSS option len
    frame[tcp + 22..tcp + 24].copy_from_slice(&1400u16.to_be_bytes());

    // The meta walker (inspect.rs, also fixed by #4517) resolves proto=TCP
    // and the SYN flag; pass those in as the production caller would.
    let info = extract_screen_info(
        &frame,
        libc::AF_INET6 as u8,
        6,    // TCP — what the fixed meta walker now reports (was 135)
        0x02, // SYN
        frame.len() as u16,
        IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()),
        IpAddr::V6("2001:db8::2".parse::<Ipv6Addr>().unwrap()),
        12345,
        22,
        14,
    )
    .expect("MOBILITY-before-fragment chain must parse");

    // On revert the walk stops at MOBILITY: is_first_fragment=false and
    // tcp_offset=None, so all three assertions flip.
    assert!(info.is_fragment, "Fragment header behind MOBILITY → is_fragment");
    assert!(
        info.is_first_fragment,
        "MF=1 && offset==0 behind MOBILITY → is_first_fragment"
    );
    assert_eq!(
        info.tcp_seq, 0x1122_3344,
        "TCP seq extracted past the MOBILITY + FRAGMENT chain"
    );
    assert_eq!(
        info.tcp_mss, 1400,
        "TCP MSS option extracted past the ext-header chain"
    );

    // End-to-end: the extracted info must now trigger the `syn-frag` screen
    // (a SYN on a first fragment). Before #4517 this MOBILITY-hidden SYN
    // was Passed unscreened.
    let mut state = make_state("trust", default_profile());
    assert_eq!(
        state.check_packet("trust", &info, 1),
        ScreenVerdict::Drop("syn-frag"),
        "the MOBILITY-hidden fragmented SYN must trip the syn-frag screen"
    );
}

#[test]
fn extract_screen_info_ipv6_nonfirst_fragment_extheader_stays_flowless() {
    // #3120 non-regression (#2344/#3064): a NON-FIRST fragment (offset>0)
    // with the same `Fragment → Dest-Options → TCP` chain shape carries no
    // L4 header in THIS packet (the TCP header is in the first fragment).
    // The walk must STOP at the fragment header and leave `tcp_offset`
    // unused — the continue-past-fragment fix is gated on offset==0 only.
    let mut frame = vec![0u8; 14 + 40 + 8 + 8 + 24];
    frame[14] = 0x60;
    frame[14 + 6] = 44; // FRAGMENT
    frame[54] = 60; // NextHdr = DEST
    let frag_off_pos = 54 + 2;
    // offset = 1 (8-byte unit), MF=1 → 0x0009: a non-first fragment.
    frame[frag_off_pos..frag_off_pos + 2].copy_from_slice(&0x0009u16.to_be_bytes());
    frame[62] = 6; // would be TCP if (wrongly) walked
    frame[63] = 0;
    let tcp = 70;
    frame[tcp + 4..tcp + 8].copy_from_slice(&0x1122_3344u32.to_be_bytes());
    frame[tcp + 12] = 0x60;
    frame[tcp + 20] = 2;
    frame[tcp + 21] = 4;
    frame[tcp + 22..tcp + 24].copy_from_slice(&1400u16.to_be_bytes());

    let info = extract_screen_info(
        &frame,
        libc::AF_INET6 as u8,
        6,
        0x02,
        frame.len() as u16,
        IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()),
        IpAddr::V6("2001:db8::2".parse::<Ipv6Addr>().unwrap()),
        12345,
        80,
        14,
    )
    .expect("non-first fragment parses");

    assert!(info.is_fragment, "offset>0 → is_fragment");
    assert!(!info.is_first_fragment, "offset>0 → not first fragment");
    // No L4 header in this packet: the downstream gate `(!is_fragment ||
    // is_first_fragment)` must skip extraction, so seq/MSS stay zero.
    assert_eq!(info.tcp_seq, 0, "non-first fragment has no L4 to extract");
    assert_eq!(info.tcp_mss, 0, "non-first fragment has no L4 to extract");
}

#[test]
fn extract_screen_info_ipv6_truncated_fragment_fails_closed() {
    // #2146 IDS-evasion: an IPv6 frame whose base header advertises
    // NextHdr=FRAGMENT (44) but whose captured bytes are TOO SHORT to
    // contain the 8-byte fragment header. The pre-fix extractor
    // `break`d out of the walk and returned defaults with
    // `is_first_fragment=false`, so a SYN-bearing truncated fragment
    // silently bypassed the `syn-frag` screen. The fix returns
    // `Err(TruncatedIpv6ExtChain)` so the caller drops it FAIL-CLOSED.
    //
    // Frame: 14 Ethernet + 40 IPv6 base + only 4 of the 8 fragment
    // bytes present (offset+8 > frame.len()).
    let mut frame = vec![0u8; 14 + 40 + 4];
    frame[14] = 0x60; // version=6
    frame[14 + 6] = 44; // NextHdr = FRAGMENT
    frame[14 + 40] = 6; // inner nexthdr = TCP (would have set syn-frag)

    let res = extract_screen_info(
        &frame,
        libc::AF_INET6 as u8,
        6,    // TCP
        0x02, // SYN — the attack-relevant flag
        48,
        IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()),
        IpAddr::V6("2001:db8::2".parse::<Ipv6Addr>().unwrap()),
        12345,
        80,
        14,
    );
    let err = res.expect_err("truncated IPv6 FRAGMENT header must FAIL CLOSED, not pass syn-frag");
    assert_eq!(err, ScreenParseError::TruncatedIpv6ExtChain);
    assert_eq!(
        err.screen_reason(),
        "ip-malformed",
        "fail-closed drop reason"
    );
}

#[test]
fn extract_screen_info_ipv6_truncated_base_header_fails_closed() {
    // AF_INET6 metadata but the captured frame is shorter than the
    // mandatory 40-byte IPv6 base header. Pre-fix this fell through the
    // `l3_offset + 40 <= frame.len()` guard to silent defaults; now it
    // is FAIL-CLOSED.
    let frame = vec![0u8; 14 + 30]; // 10 bytes short of the base header
    let res = extract_screen_info(
        &frame,
        libc::AF_INET6 as u8,
        6,
        0x02,
        44,
        IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()),
        IpAddr::V6("2001:db8::2".parse::<Ipv6Addr>().unwrap()),
        12345,
        80,
        14,
    );
    assert_eq!(
        res.expect_err("short IPv6 base header must fail closed"),
        ScreenParseError::TruncatedIpv6ExtChain
    );
}

#[test]
fn extract_screen_info_ipv4_truncated_base_header_fails_closed() {
    // #4167 (L-11): AF_INET metadata but the captured frame is shorter
    // than the mandatory 20-byte IPv4 base header at l3_offset 14. Pre-
    // fix, the `addr_family == AF_INET && l3_offset + 20 <= frame.len()`
    // gate fell through to `Ok(defaults)` (is_fragment=false, ip_ihl=5,
    // no source-route) and the frame passed UNSCREENED. Now it is FAIL-
    // CLOSED, symmetric with the IPv6 base-header case above. Goes RED
    // on revert (the Err becomes Ok → an unparseable frame is admitted).
    let frame = vec![0u8; 14 + 15]; // 5 bytes short of the 20-byte header
    let res = extract_screen_info(
        &frame,
        libc::AF_INET as u8,
        6,
        0x02,
        29,
        IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
        12345,
        80,
        14,
    );
    assert_eq!(
        res.expect_err("short IPv4 base header must fail closed"),
        ScreenParseError::TruncatedIpv4Header
    );
}

#[test]
fn extract_screen_info_ipv4_ihl_claims_past_frame_fails_closed() {
    // #4167 (L-11): the 20-byte base header IS captured, but the IHL
    // field claims 6 words = 24 bytes while only 20 are present. The
    // options region (bytes 20..24) cannot be read, so a source-route
    // option would be silently missed. FAIL-CLOSED rather than skip the
    // scan (the pre-fix `l3_offset + ihl_bytes <= frame.len()` guard let
    // this fall through with saw_ipv4_source_route=false). Goes RED on
    // revert.
    let mut frame = vec![0u8; 14 + 20]; // exactly 20 IPv4 bytes captured
    let ip = 14;
    frame[ip] = 0x46; // version=4, ihl=6 → claims 24 header bytes
    frame[ip + 9] = 6; // protocol = TCP
    let res = extract_screen_info(
        &frame,
        libc::AF_INET as u8,
        6,
        0x02,
        34,
        IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
        12345,
        80,
        14,
    );
    assert_eq!(
        res.expect_err("IHL claiming more than captured must fail closed"),
        ScreenParseError::TruncatedIpv4Header
    );
}

#[test]
fn extract_screen_info_ipv4_minimal_header_not_overdropped() {
    // #4167 (L-11) over-drop guard: a VALID minimal 20-byte IPv4 header
    // (IHL=5, no options) must still parse Ok — the fail-closed fix must
    // NOT drop a legitimate runt-but-complete IPv4 packet. Frame carries
    // exactly the 20-byte base header at l3_offset 14 and nothing more.
    let mut frame = vec![0u8; 14 + 20];
    let ip = 14;
    frame[ip] = 0x45; // version=4, ihl=5 → 20-byte header, no options
    frame[ip + 9] = 6; // protocol = TCP
    let info = extract_screen_info(
        &frame,
        libc::AF_INET as u8,
        6,
        0x02,
        34,
        IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
        12345,
        80,
        14,
    )
    .expect("valid minimal 20-byte IPv4 header must NOT be over-dropped");
    assert!(!info.is_fragment, "no MF/offset → not a fragment");
    assert!(!info.saw_ipv4_source_route, "no options → no source route");
    assert_eq!(info.ip_ihl, 5, "IHL=5 parsed from the minimal header");
}

#[test]
fn extract_screen_info_ipv6_truncated_hopbyhop_fails_closed() {
    // NextHdr=HOP-BY-HOP (0) at the base header, but the chain is cut
    // off before the hop-by-hop header's own 2 length bytes — the walk
    // runs out of bytes before reaching the FRAGMENT/upper header.
    let mut frame = vec![0u8; 14 + 40]; // exactly the base header, no ext bytes
    frame[14] = 0x60;
    frame[14 + 6] = 0; // NextHdr = HOP-BY-HOP, but offset(54)+2 > len(54)
    let res = extract_screen_info(
        &frame,
        libc::AF_INET6 as u8,
        6,
        0x02,
        40,
        IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()),
        IpAddr::V6("2001:db8::2".parse::<Ipv6Addr>().unwrap()),
        12345,
        80,
        14,
    );
    assert_eq!(
        res.expect_err("truncated hop-by-hop chain must fail closed"),
        ScreenParseError::TruncatedIpv6ExtChain
    );
}

#[test]
fn extract_screen_info_ipv6_exact_fragment_bytes_parses_ok() {
    // Boundary: the frame is EXACTLY long enough to hold the 8-byte
    // fragment header (offset + 8 == frame.len()). This must parse OK
    // (no off-by-one over-rejection) and yield is_first_fragment for a
    // MF=1, offset=0 first fragment carrying TCP.
    let mut frame = vec![0u8; 14 + 40 + 8];
    frame[14] = 0x60;
    frame[14 + 6] = 44; // FRAGMENT
    frame[14 + 40] = 6; // inner nexthdr = TCP
    let frag_off_pos = 14 + 40 + 2;
    frame[frag_off_pos..frag_off_pos + 2].copy_from_slice(&0x0001u16.to_be_bytes());
    assert_eq!(frame.len(), 14 + 40 + 8, "frame is exactly base + frag hdr");

    let info = extract_screen_info(
        &frame,
        libc::AF_INET6 as u8,
        6,
        0x02,
        48,
        IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()),
        IpAddr::V6("2001:db8::2".parse::<Ipv6Addr>().unwrap()),
        12345,
        80,
        14,
    )
    .expect("exactly-enough fragment bytes must parse OK, not over-reject");
    assert!(info.is_fragment, "MF=1 → is_fragment");
    assert!(
        info.is_first_fragment,
        "MF=1 && offset==0 → is_first_fragment"
    );
}

#[test]
fn extract_screen_info_ipv6_hopbyhop_overshoot_inner_tcp_fails_closed() {
    // #2189 MAJOR fail-open: the base NextHdr=HOP-BY-HOP (0) header's own
    // length bytes ARE present, but its DECLARED length (HdrExtLen=200)
    // advances `offset` far past the captured frame. The inner NextHdr is
    // TCP (6). Pre-fix, the walk advanced `offset` without re-validating
    // it, then the next iteration hit the `PROTO_TCP` arm, set
    // `tcp_offset=Some(offset)` and returned `Ok{is_first_fragment:false}`
    // — a SYN with NO captured FRAGMENT header bypassed `syn-frag`. The
    // fix re-validates `offset > frame.len()` at the top of the loop, so
    // this now FAILS CLOSED before the terminal arm runs.
    //
    // Frame: 14 Ethernet + 40 IPv6 base + 8 bytes of hop-by-hop header
    // (only the first 2 — NextHdr + HdrExtLen — are read).
    let mut frame = vec![0u8; 14 + 40 + 8];
    frame[14] = 0x60; // version=6
    frame[14 + 6] = 0; // base NextHdr = HOP-BY-HOP
    frame[14 + 40] = 6; // hop-by-hop NextHdr = TCP (the inner upper-layer)
    frame[14 + 40 + 1] = 200; // HdrExtLen=200 → offset jumps far past frame

    let res = extract_screen_info(
        &frame,
        libc::AF_INET6 as u8,
        6,    // TCP
        0x02, // SYN — the attack-relevant flag
        48,
        IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()),
        IpAddr::V6("2001:db8::2".parse::<Ipv6Addr>().unwrap()),
        12345,
        80,
        14,
    );
    assert_eq!(
        res.expect_err("hop-by-hop overshoot to inner TCP must FAIL CLOSED, not pass syn-frag"),
        ScreenParseError::TruncatedIpv6ExtChain
    );
}

#[test]
fn extract_screen_info_ipv6_routing_overshoot_unknown_inner_fails_closed() {
    // #2189 sibling: a ROUTING (43) header whose DECLARED length
    // overshoots the frame, with an UNKNOWN inner NextHdr that would hit
    // the `_` terminal arm and `break` with `Ok` pre-fix. The fix's
    // top-of-loop `offset > frame.len()` guard covers the `_` arm too.
    let mut frame = vec![0u8; 14 + 40 + 8];
    frame[14] = 0x60;
    frame[14 + 6] = 43; // base NextHdr = ROUTING
    frame[14 + 40] = 253; // routing NextHdr = unknown/experimental → `_` arm
    frame[14 + 40 + 1] = 200; // HdrExtLen=200 → offset overshoots

    let res = extract_screen_info(
        &frame,
        libc::AF_INET6 as u8,
        6,
        0x02,
        48,
        IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()),
        IpAddr::V6("2001:db8::2".parse::<Ipv6Addr>().unwrap()),
        12345,
        80,
        14,
    );
    assert_eq!(
        res.expect_err("routing overshoot to unknown inner must FAIL CLOSED"),
        ScreenParseError::TruncatedIpv6ExtChain
    );
}

#[test]
fn syn_frag_drops_truncated_ipv6_first_fragment_at_screen() {
    // End-to-end at the screen layer: a properly-parsed IPv6 SYN first
    // fragment is dropped by `syn-frag`. This pins the defense the
    // truncated-fragment evasion was bypassing: pre-#2146 the extractor
    // returned `is_first_fragment=false` for a truncated frame, so this
    // check never fired. With the extractor now FAIL-CLOSED, a truncated
    // frame is dropped before this check; a complete one is dropped HERE.
    let mut state = make_state("trust", default_profile());
    let mut pkt = tcp_pkt(
        IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()),
        IpAddr::V6("2001:db8::2".parse::<Ipv6Addr>().unwrap()),
        12345,
        80,
        TCP_SYN,
    );
    pkt.is_fragment = true;
    pkt.is_first_fragment = true;
    assert_eq!(
        state.check_packet("trust", &pkt, 1),
        ScreenVerdict::Drop("syn-frag"),
        "IPv6 SYN first-fragment must hit the syn-frag screen"
    );
}

#[test]
fn tcp_no_flag_passes_on_subsequent_fragment_with_zero_flags() {
    // #1137 Copilot review regression: subsequent fragments don't
    // carry the L4 header, so tcp_flags is meaningless. Without the
    // outer `!is_fragment || is_first_fragment` guard, a subsequent
    // fragment with tcp_flags=0 (because the meta wasn't filled)
    // would falsely trip SCREEN_TCP_NO_FLAG. Mirrors the BPF #853
    // defense.
    let mut profile = ScreenProfile::default();
    profile.no_flag = true;
    let mut state = make_state("trust", profile);
    let mut pkt = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        12345,
        80,
        0, // tcp_flags=0 on a subsequent fragment is normal — meta wasn't filled
    );
    pkt.is_fragment = true;
    pkt.is_first_fragment = false;
    assert_eq!(
        state.check_packet("trust", &pkt, 1),
        ScreenVerdict::Pass,
        "subsequent fragment must not trip TCP_NO_FLAG even with tf=0"
    );
}

#[test]
fn tcp_syn_fin_passes_on_subsequent_fragment_with_syn_fin_bytes() {
    // Adversarial: subsequent fragment whose payload bytes happen to
    // look like SYN+FIN. The outer guard must keep this from tripping
    // syn_fin (the bytes aren't real TCP flags).
    let mut profile = ScreenProfile::default();
    profile.syn_fin = true;
    let mut state = make_state("trust", profile);
    let mut pkt = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        12345,
        80,
        TCP_SYN | TCP_FIN,
    );
    pkt.is_fragment = true;
    pkt.is_first_fragment = false;
    assert_eq!(state.check_packet("trust", &pkt, 1), ScreenVerdict::Pass);
}

// ================================================================
// IP source route
// ================================================================

#[test]
fn source_route_actual_lsrr_drops() {
    // #2973: an actual LSRR (option 131) source-route packet must DROP.
    let mut state = make_state("trust", default_profile());
    let mut pkt = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        1234,
        80,
        TCP_SYN,
    );
    pkt.ip_ihl = 6;
    pkt.saw_ipv4_source_route = true; // extractor decoded LSRR/SSRR
    assert_eq!(
        state.check_packet("trust", &pkt, 1),
        ScreenVerdict::Drop("ip-source-route")
    );
}

#[test]
fn source_route_benign_options_pass() {
    // #2973 fail-on-revert: a packet with IPv4 options present (IHL>5)
    // but NO source-route option (e.g. router-alert/record-route/
    // timestamp) must PASS. The pre-#2973 check dropped on ANY IHL>5;
    // reverting to that makes this assertion fail.
    let mut state = make_state("trust", default_profile());
    let mut pkt = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        1234,
        80,
        TCP_SYN,
    );
    pkt.ip_ihl = 6; // options present, but not source route
    pkt.saw_ipv4_source_route = false;
    assert_eq!(state.check_packet("trust", &pkt, 1), ScreenVerdict::Pass);
}

#[test]
fn source_route_ipv6_routing_header_drops() {
    // #2973 fail-on-revert: an IPv6 Routing Header (source-route routing
    // type) must DROP for vSRX parity. The pre-#2973 check ignored IPv6
    // entirely; reverting makes this PASS instead of DROP.
    let mut state = make_state("trust", default_profile());
    let mut pkt = tcp_pkt(
        IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()),
        IpAddr::V6("2001:db8::2".parse::<Ipv6Addr>().unwrap()),
        1234,
        80,
        TCP_SYN,
    );
    pkt.saw_ipv6_routing_header = true; // extractor saw RH0/type-1
    assert_eq!(
        state.check_packet("trust", &pkt, 1),
        ScreenVerdict::Drop("ip-source-route")
    );
}

#[test]
fn extract_screen_info_ipv4_lsrr_detected() {
    // #2973: an IPv4 header carrying an LSRR (131) option sets
    // saw_ipv4_source_route. Header: version=4, ihl=7 (28 bytes = 20
    // base + 8 options), LSRR option {131, len=7, ptr=4, addr...} then
    // padding/EOOL.
    let ihl_words = 7u8;
    let hdr_len = (ihl_words as usize) * 4; // 28
    let mut frame = vec![0u8; 14 + hdr_len + 20];
    let ip = 14;
    frame[ip] = 0x40 | ihl_words; // version=4, ihl=7
    frame[ip + 2..ip + 4].copy_from_slice(&((hdr_len + 20) as u16).to_be_bytes());
    frame[ip + 9] = 6; // TCP
    // options begin at ip+20
    let opt = ip + 20;
    frame[opt] = 131; // LSRR
    frame[opt + 1] = 7; // option length
    frame[opt + 2] = 4; // pointer
    // bytes opt+3.. : route data (zeroed), then opt+7 = EOOL(0)

    let info = extract_screen_info(
        &frame,
        libc::AF_INET as u8,
        6,
        0x02,
        (hdr_len + 20) as u16,
        IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
        12345,
        80,
        14,
    )
    .expect("valid IPv4 LSRR packet parses");
    assert!(
        info.saw_ipv4_source_route,
        "LSRR (option 131) must set saw_ipv4_source_route"
    );
}

#[test]
fn extract_screen_info_ipv4_malformed_option_before_lsrr_fails_closed() {
    // #4543 (ps-027 S-03): a MALFORMED option placed BEFORE an LSRR must
    // NOT let the source-route option evade the screen. The kind==LSRR
    // test precedes the length check, so the pre-fix `break`-on-malformed
    // aborted the walk at the bad option, leaving saw_ipv4_source_route=
    // false → check_source_route passed the packet. The fix returns
    // Err(TruncatedIpv4Header) so the malformed frame is DROPPED (the
    // "ip-malformed" fail-closed path, mirroring #4167). Layout: version=4,
    // ihl=9 (36 bytes = 20 base + 16 options); options = a bad
    // length-prefixed option {type=0x44, len=0x01} (len < 2 → malformed),
    // then an LSRR {131, len=7, ...}. Goes RED on revert (the packet would
    // parse Ok with saw_ipv4_source_route=false).
    let ihl_words = 9u8;
    let hdr_len = (ihl_words as usize) * 4; // 36
    let mut frame = vec![0u8; 14 + hdr_len + 20];
    let ip = 14;
    frame[ip] = 0x40 | ihl_words; // version=4, ihl=9
    frame[ip + 2..ip + 4].copy_from_slice(&((hdr_len + 20) as u16).to_be_bytes());
    frame[ip + 9] = 6; // TCP
    let opt = ip + 20;
    // Malformed option: a length-prefixed type with a declared length of
    // 1 (< 2, impossible for a length-prefixed option).
    frame[opt] = 0x44; // type (not EOOL/NOP/LSRR/SSRR)
    frame[opt + 1] = 0x01; // malformed length
    // An LSRR placed AFTER the malformed option — the source-route the
    // operator's screen is meant to catch.
    frame[opt + 2] = 131; // LSRR
    frame[opt + 3] = 7; // option length
    frame[opt + 4] = 4; // pointer
    let res = extract_screen_info(
        &frame,
        libc::AF_INET as u8,
        6,
        0x02,
        (hdr_len + 20) as u16,
        IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
        12345,
        80,
        14,
    );
    assert_eq!(
        res.expect_err("malformed IPv4 option before LSRR must fail closed"),
        ScreenParseError::TruncatedIpv4Header
    );
}

#[test]
fn extract_screen_info_ipv4_option_length_overruns_region_fails_closed() {
    // #4543: a length-prefixed option whose declared length runs PAST the
    // options region is malformed and must fail closed (not `break`).
    // Layout: version=4, ihl=6 (24 bytes = 20 base + 4 options); a single
    // option {type=7 (record-route), len=8} — but only 4 option bytes
    // exist, so the length overruns opt_end. Goes RED on revert.
    let ihl_words = 6u8;
    let hdr_len = (ihl_words as usize) * 4; // 24
    let mut frame = vec![0u8; 14 + hdr_len + 20];
    let ip = 14;
    frame[ip] = 0x40 | ihl_words;
    frame[ip + 2..ip + 4].copy_from_slice(&((hdr_len + 20) as u16).to_be_bytes());
    frame[ip + 9] = 6;
    let opt = ip + 20;
    frame[opt] = 7; // record-route (length-prefixed)
    frame[opt + 1] = 8; // declares 8 bytes but only 4 remain → overruns
    let res = extract_screen_info(
        &frame,
        libc::AF_INET as u8,
        6,
        0x02,
        (hdr_len + 20) as u16,
        IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
        12345,
        80,
        14,
    );
    assert_eq!(
        res.expect_err("IPv4 option length overrunning region must fail closed"),
        ScreenParseError::TruncatedIpv4Header
    );
}

#[test]
fn extract_screen_info_ipv4_wellformed_lsrr_after_benign_option_trips() {
    // #4543 over-drop guard: a WELL-FORMED options list where an LSRR
    // follows a benign length-prefixed option (router-alert, type 148,
    // len 4) must STILL set saw_ipv4_source_route — the fail-closed fix
    // must not disturb valid multi-option walks. Layout: version=4, ihl=10
    // (40 bytes = 20 base + 20 options); router-alert {148, len=4}, then
    // LSRR {131, len=7, ptr=4, ...}, then EOOL/pad.
    let ihl_words = 10u8;
    let hdr_len = (ihl_words as usize) * 4; // 40
    let mut frame = vec![0u8; 14 + hdr_len + 20];
    let ip = 14;
    frame[ip] = 0x40 | ihl_words;
    frame[ip + 2..ip + 4].copy_from_slice(&((hdr_len + 20) as u16).to_be_bytes());
    frame[ip + 9] = 6; // TCP
    let opt = ip + 20;
    frame[opt] = 148; // router-alert (benign)
    frame[opt + 1] = 4; // length
    // LSRR follows at opt+4.
    frame[opt + 4] = 131; // LSRR
    frame[opt + 5] = 7; // option length
    frame[opt + 6] = 4; // pointer
    // remaining bytes zeroed (route data / EOOL padding)
    let info = extract_screen_info(
        &frame,
        libc::AF_INET as u8,
        6,
        0x02,
        (hdr_len + 20) as u16,
        IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
        12345,
        80,
        14,
    )
    .expect("well-formed router-alert + LSRR packet must parse Ok");
    assert!(
        info.saw_ipv4_source_route,
        "LSRR after a well-formed benign option must still trip the source-route screen"
    );
}

#[test]
fn extract_screen_info_ipv4_router_alert_not_source_route() {
    // #2973 fail-on-revert: an IPv4 header with a benign router-alert
    // option (148, length 4) must NOT set saw_ipv4_source_route.
    let ihl_words = 6u8;
    let hdr_len = (ihl_words as usize) * 4; // 24
    let mut frame = vec![0u8; 14 + hdr_len + 20];
    let ip = 14;
    frame[ip] = 0x40 | ihl_words;
    frame[ip + 2..ip + 4].copy_from_slice(&((hdr_len + 20) as u16).to_be_bytes());
    frame[ip + 9] = 6;
    let opt = ip + 20;
    frame[opt] = 148; // router alert
    frame[opt + 1] = 4; // length
    // opt+2,opt+3 = value (0); fills the 4-byte option exactly.

    let info = extract_screen_info(
        &frame,
        libc::AF_INET as u8,
        6,
        0x02,
        (hdr_len + 20) as u16,
        IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
        12345,
        80,
        14,
    )
    .expect("valid IPv4 router-alert packet parses");
    assert!(
        !info.saw_ipv4_source_route,
        "router-alert (option 148) must NOT set saw_ipv4_source_route"
    );
}

#[test]
fn extract_screen_info_ipv6_routing_header_detected() {
    // #2973: an IPv6 Routing Header (NextHdr=43) with routing type 0
    // (RH0, the deprecated source-route type) sets
    // saw_ipv6_routing_header. Routing ext header is 8 bytes:
    // {nexthdr, hdr_ext_len=0, routing_type=0, segs_left, ...}.
    let mut frame = vec![0u8; 14 + 40 + 8 + 20];
    frame[14] = 0x60; // version=6
    frame[14 + 6] = 43; // NextHdr = ROUTING
    let rh = 14 + 40;
    frame[rh] = 6; // inner nexthdr = TCP
    frame[rh + 1] = 0; // hdr_ext_len = 0 → 8 bytes
    frame[rh + 2] = 0; // routing type 0 = RH0 (source route)

    let info = extract_screen_info(
        &frame,
        libc::AF_INET6 as u8,
        6,
        0x02,
        28,
        IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()),
        IpAddr::V6("2001:db8::2".parse::<Ipv6Addr>().unwrap()),
        12345,
        80,
        14,
    )
    .expect("valid IPv6 routing-header packet parses");
    assert!(
        info.saw_ipv6_routing_header,
        "IPv6 RH0 (routing type 0) must set saw_ipv6_routing_header"
    );
}

#[test]
fn extract_screen_info_ipv6_routing_type2_not_source_route() {
    // #2973: routing type 2 is Mobile IPv6, NOT source routing — it must
    // NOT set saw_ipv6_routing_header.
    let mut frame = vec![0u8; 14 + 40 + 8 + 20];
    frame[14] = 0x60;
    frame[14 + 6] = 43;
    let rh = 14 + 40;
    frame[rh] = 6;
    frame[rh + 1] = 0;
    frame[rh + 2] = 2; // routing type 2 = Mobile IPv6 (not source route)

    let info = extract_screen_info(
        &frame,
        libc::AF_INET6 as u8,
        6,
        0x02,
        28,
        IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()),
        IpAddr::V6("2001:db8::2".parse::<Ipv6Addr>().unwrap()),
        12345,
        80,
        14,
    )
    .expect("valid IPv6 type-2 routing-header packet parses");
    assert!(
        !info.saw_ipv6_routing_header,
        "IPv6 routing type 2 (Mobile IPv6) must NOT set saw_ipv6_routing_header"
    );
}

// ================================================================
// Normal packets pass all checks
// ================================================================

#[test]
fn normal_tcp_syn_passes() {
    let mut state = make_state("trust", default_profile());
    let pkt = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        1234,
        80,
        TCP_SYN,
    );
    assert_eq!(state.check_packet("trust", &pkt, 1), ScreenVerdict::Pass);
}

#[test]
fn normal_tcp_established_passes() {
    let mut state = make_state("trust", default_profile());
    let pkt = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        1234,
        80,
        TCP_ACK, // normal established traffic
    );
    assert_eq!(state.check_packet("trust", &pkt, 1), ScreenVerdict::Pass);
}

#[test]
fn normal_udp_passes() {
    let mut state = make_state("trust", default_profile());
    let pkt = udp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
    );
    assert_eq!(state.check_packet("trust", &pkt, 1), ScreenVerdict::Pass);
}

#[test]
fn no_profile_passes() {
    let mut state = ScreenState::new();
    let pkt = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        80,
        80,
        TCP_SYN | TCP_FIN, // malicious but no profile
    );
    assert_eq!(state.check_packet("trust", &pkt, 1), ScreenVerdict::Pass);
}

// ================================================================
// Rate limiting: ICMP flood
// ================================================================

#[test]
fn icmp_flood_triggers() {
    let mut profile = ScreenProfile::default();
    profile.icmp_flood_threshold = 3;
    let mut state = make_state("trust", profile);
    let pkt = icmp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        84,
    );
    // First 3 pass
    assert_eq!(state.check_packet("trust", &pkt, 100), ScreenVerdict::Pass);
    assert_eq!(state.check_packet("trust", &pkt, 100), ScreenVerdict::Pass);
    assert_eq!(state.check_packet("trust", &pkt, 100), ScreenVerdict::Pass);
    // 4th exceeds threshold
    assert_eq!(
        state.check_packet("trust", &pkt, 100),
        ScreenVerdict::Drop("icmp-flood")
    );
}

/// #4969 fail-on-revert: a `ZoneScreenState` constructed from a `ScreenProfile`
/// with a configured limiter has ALL of that limiter's flood sub-state PRESENT
/// by construction, so a configured zone can NEVER present a fail-open (missing)
/// sub-state on the screened path.
///
/// This is the correctness win of the #4969 map consolidation. In the pre-#4969
/// parallel `FxHashMap<String, _>` shape the profile table and the sketch tables
/// could DISAGREE: a profile could carry `icmp_flood_threshold > 0` while its
/// `icmp_dst_sketch` entry was absent (a missed prepopulation step in
/// `update_profiles`), and the screened path's `if let Some(sketch) = ...` then
/// fell through to a fail-open Pass — the PRIMARY per-destination cap silently
/// disabled. Building every sub-state together in `from_profile` makes
/// `Some ⟺ configured` a construction invariant.
///
/// Part 1 asserts the construction invariant directly (RED on revert: if a
/// future edit stops constructing a configured limiter's sub-state, the
/// `is_some()` assertion fails by assertion, not a build break). Part 2 proves
/// the sub-state's presence is LOAD-BEARING for enforcement: nulling
/// `icmp_dst_sketch` (the parallel-map "configured-but-missing" shape) FAILS THE
/// SCREEN OPEN — the per-destination cap a correctly-constructed zone enforces
/// no longer trips.
#[test]
fn zone_screen_state_construction_has_no_fail_open_gap_4969() {
    // --- Part 1: construction invariant (Some ⟺ configured). ---
    let mut configured = ScreenProfile::default();
    configured.icmp_flood_threshold = 3;
    configured.udp_flood_threshold = 3;
    configured.syn_flood_dst_threshold = 3;
    configured.syn_flood_src_threshold = 3;
    configured.syn_flood_alarm_threshold = 2;
    configured.syn_flood_threshold = 10;

    let z = ZoneScreenState::from_profile("trust", configured.clone());
    assert!(
        z.icmp_dst_sketch.is_some(),
        "icmp_flood_threshold>0 must construct the icmp_dst_sketch"
    );
    assert!(
        z.udp_dst_sketch.is_some(),
        "udp_flood_threshold>0 must construct the udp_dst_sketch"
    );
    assert!(
        z.syn_dst_sketch.is_some(),
        "syn_flood_dst_threshold>0 must construct the syn_dst_sketch"
    );
    assert!(
        z.syn_src_sketch.is_some(),
        "syn_flood_src_threshold>0 must construct the syn_src_sketch"
    );

    // Symmetric negative: an unconfigured profile constructs NONE of the
    // sketches, so the Option is a faithful `Some ⟺ configured` flag (memory
    // still tracks live config), not a lazy "always Some".
    let bare = ZoneScreenState::from_profile("trust", ScreenProfile::default());
    assert!(bare.icmp_dst_sketch.is_none());
    assert!(bare.udp_dst_sketch.is_none());
    assert!(bare.syn_dst_sketch.is_none());
    assert!(bare.syn_src_sketch.is_none());

    // --- Part 2: the sub-state is load-bearing for enforcement. ---
    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    let victim = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1));

    // (a) Correctly-constructed zone: the PRIMARY per-destination ICMP cap
    // (threshold 3) enforces — 3 admitted, the 4th to the victim Drops.
    let mut enforced = make_state("trust", configured.clone());
    for _ in 0..3 {
        assert_eq!(
            enforced.check_packet("trust", &icmp_pkt(src, victim, 84), 100),
            ScreenVerdict::Pass
        );
    }
    assert_eq!(
        enforced.check_packet("trust", &icmp_pkt(src, victim, 84), 100),
        ScreenVerdict::Drop("icmp-flood"),
        "configured per-destination ICMP cap must enforce on the screened path"
    );

    // (b) Fail-open simulation: null the per-destination sketch (the pre-#4969
    // "configured-but-missing entry" shape). The PRIMARY cap can no longer trip;
    // only the SECONDARY aggregate ceiling (8× threshold = 24) gates, so the 4th
    // packet that Dropped in (a) now PASSES — the exact fail-open the #4969
    // construction invariant forecloses. (tests is a child module, so it may
    // reach the private `zones` map / `ZoneScreenState` fields to inject the gap.)
    let mut leaky = make_state("trust", configured);
    leaky
        .zones
        .get_mut("trust")
        .expect("zone present")
        .icmp_dst_sketch = None;
    for i in 0..8u8 {
        assert_eq!(
            leaky.check_packet("trust", &icmp_pkt(src, victim, 84), 100),
            ScreenVerdict::Pass,
            "with icmp_dst_sketch missing (pre-#4969 fail-open) the per-destination \
             cap does NOT trip (packet {i} of a would-be-dropped burst)"
        );
    }
}

#[test]
fn icmp_flood_per_dest_token_bucket_bounds_burst_and_refills() {
    // #5805: the per-destination ICMP flood cap is now a monotonic-ns TOKEN
    // BUCKET (was a count-all `RateCounter`). Two properties:
    //   (a) #2937 preserved — an instantaneous burst is bounded to `threshold`
    //       (the capacity), and a sub-millisecond straddle hands out no fresh
    //       budget; and
    //   (b) #5805 fixed — a FULL second later the bucket has refilled to
    //       capacity and admits the budget again, WITHOUT requiring a fully idle
    //       second. The reverted `RateCounter` kept the destination dropped in
    //       the second immediately following an at-threshold second (its
    //       previous-second tally weighed the whole current second) — this final
    //       assertion is RED on the reverted count-all cell.
    const THRESHOLD: u32 = 2;
    let mut profile = ScreenProfile::default();
    profile.icmp_flood_threshold = THRESHOLD;
    let mut state = make_state("trust", profile);
    let pkt = icmp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        84,
    );
    // Instantaneous burst at second 100: exactly `threshold` admitted, the rest
    // dropped (cold-start capacity bound).
    let now_ns = 100 * NS;
    let mut admitted = 0u32;
    for _ in 0..(THRESHOLD * 3) {
        if state.check_packet_with_zone_id_opts("trust", 3, &pkt, now_ns, 100, false)
            == ScreenVerdict::Pass
        {
            admitted += 1;
        }
    }
    assert_eq!(
        admitted, THRESHOLD,
        "instantaneous burst bounded to capacity (#2937)"
    );
    // A sub-millisecond straddle 100us later must NOT refill a fresh budget.
    let straddle_ns = now_ns + 100_000;
    assert_eq!(
        state.check_packet_with_zone_id_opts("trust", 3, &pkt, straddle_ns, 100, false),
        ScreenVerdict::Drop("icmp-flood"),
        "a sub-ms straddle must not hand out a second budget (#2937)"
    );
    // A FULL second later the bucket has refilled to capacity → the budget is
    // admitted again, WITHOUT needing a fully idle second (the #5805 fix; the
    // count-all RateCounter would still be dropping here).
    let next_secs_ns = now_ns + NS;
    let mut admitted2 = 0u32;
    for _ in 0..THRESHOLD {
        if state.check_packet_with_zone_id_opts("trust", 3, &pkt, next_secs_ns, 101, false)
            == ScreenVerdict::Pass
        {
            admitted2 += 1;
        }
    }
    assert_eq!(
        admitted2, THRESHOLD,
        "a full second later the per-destination budget refills (#5805 recovery)"
    );
}

// ================================================================
// Rate limiting: UDP flood
// ================================================================

#[test]
fn udp_flood_triggers() {
    let mut profile = ScreenProfile::default();
    profile.udp_flood_threshold = 2;
    let mut state = make_state("trust", profile);
    let pkt = udp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
    );
    assert_eq!(state.check_packet("trust", &pkt, 100), ScreenVerdict::Pass);
    assert_eq!(state.check_packet("trust", &pkt, 100), ScreenVerdict::Pass);
    assert_eq!(
        state.check_packet("trust", &pkt, 100),
        ScreenVerdict::Drop("udp-flood")
    );
}

/// #4112 F18: Junos measures ICMP flood PER DESTINATION IP, not per zone.
/// Traffic to two distinct destinations, each AT the per-destination threshold,
/// counts INDEPENDENTLY and is NOT summed into one zone counter. RED on revert
/// (single per-zone aggregate at `threshold`): the two destinations sum, so the
/// 4th packet overall crosses the zone counter and is false-dropped even though
/// no single destination is flooded.
#[test]
fn icmp_flood_per_destination_counts_independently() {
    let mut profile = ScreenProfile::default();
    profile.icmp_flood_threshold = 3;
    let mut state = make_state("trust", profile);
    let dst_a = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1));
    let dst_b = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 2));
    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    // 3 to A and 3 to B: each destination is AT its per-destination cap (3), so
    // none trip. The reverted single zone counter (threshold 3) would drop from
    // the 4th packet on.
    for _ in 0..3 {
        assert_eq!(
            state.check_packet("trust", &icmp_pkt(src, dst_a, 84), 100),
            ScreenVerdict::Pass,
            "destination A within its own per-destination cap"
        );
    }
    for _ in 0..3 {
        assert_eq!(
            state.check_packet("trust", &icmp_pkt(src, dst_b, 84), 100),
            ScreenVerdict::Pass,
            "destination B counts independently of A (not summed)"
        );
    }
    // A single-destination flood is STILL capped: the 4th packet to A trips the
    // per-destination cap.
    assert_eq!(
        state.check_packet("trust", &icmp_pkt(src, dst_a, 84), 100),
        ScreenVerdict::Drop("icmp-flood"),
        "a single flooded destination is still capped per-destination"
    );
}

/// #4112 F18: Junos measures UDP flood PER DESTINATION IP AND PORT. Two flows to
/// the SAME destination IP but DIFFERENT destination ports count independently.
/// RED on revert (single per-zone aggregate): the two ports sum and are
/// false-dropped.
#[test]
fn udp_flood_per_destination_port_counts_independently() {
    let mut profile = ScreenProfile::default();
    profile.udp_flood_threshold = 2;
    let mut state = make_state("trust", profile);
    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1));
    let to_port = |port: u16| {
        let mut p = udp_pkt(src, dst);
        p.dst_port = port;
        p
    };
    // 2 to (dst, 80) and 2 to (dst, 443): each destination-port is AT its cap.
    for _ in 0..2 {
        assert_eq!(
            state.check_packet("trust", &to_port(80), 100),
            ScreenVerdict::Pass
        );
    }
    for _ in 0..2 {
        assert_eq!(
            state.check_packet("trust", &to_port(443), 100),
            ScreenVerdict::Pass,
            "a different destination port counts independently (not summed)"
        );
    }
    // Same (dst, port) flood is STILL capped: the 3rd packet to (dst, 80) trips.
    assert_eq!(
        state.check_packet("trust", &to_port(80), 100),
        ScreenVerdict::Drop("udp-flood"),
        "a single flooded destination-port is still capped"
    );
}

/// #4112 F18: the per-zone aggregate is retained as a coarse SECONDARY
/// zone-saturation ceiling ABOVE the per-destination cap. A flood spread thin
/// across many destinations (each under the per-destination cap) is still
/// bounded zone-wide at `SECONDARY_FLOOD_CEILING_MULT × threshold` — an operator
/// relying on the zone-wide cap still gets it. With threshold 2 and the 8×
/// multiplier the ceiling is 16, so the 17th distinct-destination packet trips.
#[test]
fn icmp_flood_secondary_zone_ceiling_still_fires() {
    let mut profile = ScreenProfile::default();
    profile.icmp_flood_threshold = 2;
    let mut state = make_state("trust", profile);
    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    // 16 distinct destinations, one packet each — every per-destination cap is
    // far below threshold, but the zone aggregate climbs to the 8×2 = 16 ceiling.
    for i in 0..16u8 {
        let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 2, i + 1));
        assert_eq!(
            state.check_packet("trust", &icmp_pkt(src, dst, 84), 100),
            ScreenVerdict::Pass,
            "under the zone-saturation ceiling"
        );
    }
    // 17th distinct destination: still under its own per-destination cap, but the
    // zone aggregate (17) crosses the 16 ceiling → secondary drop.
    let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 200));
    assert_eq!(
        state.check_packet("trust", &icmp_pkt(src, dst, 84), 100),
        ScreenVerdict::Drop("icmp-flood"),
        "zone-wide saturation ceiling fires above the per-destination cap"
    );
}

/// #4112 F18: the per-destination cap also runs on the FLOWLESS path (non-first
/// fragment / non-query ICMP), so a fragment-based flood cannot evade it. Two
/// distinct destinations count independently there too.
#[test]
fn icmp_flood_flowless_per_destination_independent() {
    let mut profile = ScreenProfile::default();
    profile.icmp_flood_threshold = 2;
    let mut state = make_state("trust", profile);
    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    let dst_a = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1));
    let dst_b = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 2));
    for _ in 0..2 {
        assert_eq!(
            state.check_flowless_screens("trust", &flowless_icmp_pkt(src, dst_a), true, 100),
            ScreenVerdict::Pass
        );
    }
    for _ in 0..2 {
        assert_eq!(
            state.check_flowless_screens("trust", &flowless_icmp_pkt(src, dst_b), true, 100),
            ScreenVerdict::Pass,
            "flowless per-destination independence"
        );
    }
    assert_eq!(
        state.check_flowless_screens("trust", &flowless_icmp_pkt(src, dst_a), true, 100),
        ScreenVerdict::Drop("icmp-flood"),
        "flowless single-destination flood still capped"
    );
}

/// #5805 RED-ON-REVERT (headline): a single destination receiving ICMP at
/// EXACTLY the per-destination `icmp flood threshold` rate, SUSTAINED for 20
/// seconds (the clock advanced past every 1-second boundary), stays admitted.
/// The per-destination token bucket refills continuously at the configured
/// rate, so the destination is served steadily. Reverting the sketch cell to
/// the count-all `RateCounter` collapses admission to ~one window after the
/// first second (its whole-second boundary reset counts even the rejected
/// packets) → this assertion goes RED. Events are paced at the real monotonic
/// rate via `now_ns`, mirroring `syn_flood_cookie_off_sustained_at_threshold`.
#[test]
fn icmp_flood_per_dest_sustained_at_threshold_admitted() {
    const THRESHOLD: u32 = 100;
    let mut profile = ScreenProfile::default();
    profile.icmp_flood_threshold = THRESHOLD;
    let mut state = make_state("trust", profile);
    let pkt = icmp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        84,
    );
    let interval_ns = NS / THRESHOLD as u64; // exactly threshold events/second
    let mut now_ns = 9 * NS;
    let total = THRESHOLD * 20; // 20 seconds sustained at threshold
    let mut admitted = 0u32;
    for _ in 0..total {
        let now_secs = now_ns / NS;
        if state.check_packet_with_zone_id_opts("trust", 3, &pkt, now_ns, now_secs, false)
            == ScreenVerdict::Pass
        {
            admitted += 1;
        }
        now_ns += interval_ns;
    }
    assert!(
        admitted as f64 >= 0.99 * total as f64,
        "per-destination ICMP at threshold must stay admitted across 20s (#5805): {admitted}/{total}"
    );
}

/// #5805 RED-ON-REVERT: the UDP per-destination-PORT flood cap has the same
/// token-bucket behaviour — a `(dst_ip, dst_port)` parked at exactly `udp flood
/// threshold` pps for 20 seconds stays admitted. RED on the reverted
/// `RateCounter` cell.
#[test]
fn udp_flood_per_dest_port_sustained_at_threshold_admitted() {
    const THRESHOLD: u32 = 100;
    let mut profile = ScreenProfile::default();
    profile.udp_flood_threshold = THRESHOLD;
    let mut state = make_state("trust", profile);
    let mut pkt = udp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
    );
    pkt.dst_port = 443;
    let interval_ns = NS / THRESHOLD as u64;
    let mut now_ns = 9 * NS;
    let total = THRESHOLD * 20;
    let mut admitted = 0u32;
    for _ in 0..total {
        let now_secs = now_ns / NS;
        if state.check_packet_with_zone_id_opts("trust", 3, &pkt, now_ns, now_secs, false)
            == ScreenVerdict::Pass
        {
            admitted += 1;
        }
        now_ns += interval_ns;
    }
    assert!(
        admitted as f64 >= 0.99 * total as f64,
        "per-(dst,port) UDP at threshold must stay admitted across 20s (#5805): {admitted}/{total}"
    );
}

/// #5805 enforcement preserved (IPv6): an OVER-threshold destination (sending at
/// 2× the per-destination cap) is still LIMITED down to the configured rate —
/// the fix must not weaken enforcement. The token bucket admits ≈ `threshold`
/// per second plus the one-time cold-start capacity, so over 20 seconds a 2×
/// flood sees ≈ `threshold × 21` admitted: well below the `threshold × 40`
/// offered (a real flood is still dropped, enforcement holds) AND well above the
/// ~`threshold` a reverted count-all `RateCounter` would admit (no collapse —
/// the lower bound is RED on revert). Uses an IPv6 destination.
#[test]
fn icmp_flood_per_dest_over_threshold_still_limited() {
    const THRESHOLD: u32 = 100;
    const SECS: u32 = 20;
    let mut profile = ScreenProfile::default();
    profile.icmp_flood_threshold = THRESHOLD;
    let mut state = make_state("trust", profile);
    let pkt = icmp_pkt(
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x50)),
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x99)),
        84,
    );
    // Offer 2× the cap, evenly spaced.
    let interval_ns = NS / (2 * THRESHOLD) as u64;
    let mut now_ns = 9 * NS;
    let total = 2 * THRESHOLD * SECS;
    let mut admitted = 0u32;
    for _ in 0..total {
        let now_secs = now_ns / NS;
        if state.check_packet_with_zone_id_opts("trust", 3, &pkt, now_ns, now_secs, false)
            == ScreenVerdict::Pass
        {
            admitted += 1;
        }
        now_ns += interval_ns;
    }
    // Enforcement: a real 2× flood is limited, not passed wholesale.
    assert!(
        admitted < total,
        "an over-threshold destination must still be rate-limited: {admitted}/{total}"
    );
    assert!(
        admitted <= THRESHOLD * (SECS + 2),
        "admitted must be bounded to ~the configured rate (+cold-start burst): {admitted}"
    );
    // No collapse: the configured rate IS delivered every second (RED on the
    // reverted count-all cell, which admits ~one window total).
    assert!(
        admitted >= THRESHOLD * SECS,
        "the configured rate must be delivered steadily, not collapsed (#5805): {admitted}"
    );
}

/// #5805 RED-ON-REVERT (flowless fragment path): a UDP non-first fragment carries
/// no L4 port, so `udp_flood_drop` folds it into the per-destination-IP token
/// bucket (#4567). A sustained at-threshold fragment stream to one destination
/// IP stays admitted across seconds. RED on the reverted `RateCounter` cell.
#[test]
fn udp_flood_flowless_fragment_sustained_at_threshold_admitted() {
    const THRESHOLD: u32 = 100;
    let mut profile = ScreenProfile::default();
    profile.udp_flood_threshold = THRESHOLD;
    let mut state = make_state("trust", profile);
    let pkt = flowless_nonfirst_fragment(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        PROTO_UDP,
    );
    let interval_ns = NS / THRESHOLD as u64;
    let mut now_ns = 9 * NS;
    let total = THRESHOLD * 20;
    let mut admitted = 0u32;
    for _ in 0..total {
        let now_secs = now_ns / NS;
        if state.check_flowless_screens_opts("trust", &pkt, true, now_ns, now_secs, false)
            == ScreenVerdict::Pass
        {
            admitted += 1;
        }
        now_ns += interval_ns;
    }
    assert!(
        admitted as f64 >= 0.99 * total as f64,
        "flowless UDP fragment at threshold must stay admitted across 20s (#5805): {admitted}/{total}"
    );
}

// ================================================================
// Rate limiting: SYN flood
// ================================================================

#[test]
fn syn_flood_triggers() {
    let mut profile = ScreenProfile::default();
    profile.syn_flood_threshold = 2;
    let mut state = make_state("trust", profile);
    let pkt = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        1234,
        80,
        TCP_SYN,
    );
    assert_eq!(state.check_packet("trust", &pkt, 100), ScreenVerdict::Pass);
    assert_eq!(state.check_packet("trust", &pkt, 100), ScreenVerdict::Pass);
    assert_eq!(
        state.check_packet("trust", &pkt, 100),
        ScreenVerdict::Drop("syn-flood")
    );
}

#[test]
fn syn_flood_ignores_syn_ack() {
    let mut profile = ScreenProfile::default();
    profile.syn_flood_threshold = 1;
    let mut state = make_state("trust", profile);
    // SYN+ACK should not count toward SYN flood
    let pkt = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        1234,
        80,
        TCP_SYN | TCP_ACK,
    );
    assert_eq!(state.check_packet("trust", &pkt, 100), ScreenVerdict::Pass);
    assert_eq!(state.check_packet("trust", &pkt, 100), ScreenVerdict::Pass);
    assert_eq!(state.check_packet("trust", &pkt, 100), ScreenVerdict::Pass);
}

#[test]
fn syn_flood_disabled_passes() {
    let profile = ScreenProfile::default(); // threshold=0 means disabled
    let mut state = make_state("trust", profile);
    let pkt = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        1234,
        80,
        TCP_SYN,
    );
    for _ in 0..1000 {
        assert_eq!(state.check_packet("trust", &pkt, 100), ScreenVerdict::Pass);
    }
}

/// #3607 (M09) RED-ON-REVERT: with `syn-cookie` OFF, a legitimate SYN stream
/// parked at EXACTLY `syn_flood_threshold`/second stays ADMITTED — the
/// cookie-OFF token bucket refills at the configured rate. Reverting the
/// migration (the count-all `RateCounter` aggregate as the drop authority)
/// throttles the stream to ~0 after the first second, so this is RED on the
/// pre-#3607 code. Events are paced at the real monotonic rate via `now_ns`.
#[test]
fn syn_flood_cookie_off_sustained_at_threshold_admitted() {
    const THRESHOLD: u32 = 100;
    let mut profile = ScreenProfile::default();
    profile.syn_flood_threshold = THRESHOLD; // syn_cookie stays false (default)
    let mut state = make_state("trust", profile);
    let pkt = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        1234,
        80,
        TCP_SYN,
    );
    let interval_ns = NS / THRESHOLD as u64; // exactly threshold events/second
    let mut now_ns = 9 * NS;
    let total = THRESHOLD * 15; // 15 seconds sustained at threshold
    let mut admitted = 0u32;
    for _ in 0..total {
        let now_secs = now_ns / NS;
        if state.check_packet_with_zone_id_opts("trust", 3, &pkt, now_ns, now_secs, false)
            == ScreenVerdict::Pass
        {
            admitted += 1;
        }
        now_ns += interval_ns;
    }
    assert!(
        admitted as f64 >= 0.99 * total as f64,
        "cookie-OFF sustained-at-threshold must stay admitted (#3607): {admitted}/{total}"
    );
}

/// #3607 (Codex round-4) cookie-OFF single-gate micro-burst bound: on a fresh
/// zone an INSTANTANEOUS burst admits AT MOST `threshold` (the bucket
/// capacity), NOT ~2x. Proves the token bucket is the SOLE drop authority when
/// `syn-cookie` is OFF — there is no "aggregate admits T + full bucket admits
/// another T" double-quota, and #2937's anti-micro-burst property holds.
#[test]
fn syn_flood_cookie_off_microburst_bounded_to_threshold() {
    const THRESHOLD: u32 = 50;
    let mut profile = ScreenProfile::default();
    profile.syn_flood_threshold = THRESHOLD;
    let mut state = make_state("trust", profile);
    let pkt = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        1234,
        80,
        TCP_SYN,
    );
    let now_ns = 5 * NS;
    let mut admitted = 0u32;
    for _ in 0..(THRESHOLD * 3) {
        if state.check_packet_with_zone_id_opts("trust", 3, &pkt, now_ns, 5, false)
            == ScreenVerdict::Pass
        {
            admitted += 1;
        }
    }
    assert_eq!(
        admitted, THRESHOLD,
        "cookie-OFF instantaneous burst bounded to capacity (no double-quota)"
    );
}

// ================================================================
// SYN-flood sub-thresholds (#3315): source / destination / alarm
// ================================================================

/// per-DESTINATION threshold trips for a victim flooded from many (varied)
/// sources while the aggregate attack-threshold stays well under budget. This
/// is the PRIMARY #3315 control: a single hot destination is capped even though
/// no single source is hot and the zone aggregate never trips. RED on revert to
/// aggregate-only enforcement (the victim would never be dropped).
#[test]
fn syn_flood_dest_threshold_trips_under_aggregate() {
    let mut profile = ScreenProfile::default();
    profile.syn_flood_threshold = 100_000; // aggregate never trips in this test
    profile.syn_flood_dst_threshold = 3;
    let mut state = make_state("trust", profile);
    let victim = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 50));
    // 3 SYNs to the victim from 3 distinct sources are admitted.
    for i in 0..3u8 {
        let pkt = tcp_pkt(
            IpAddr::V4(Ipv4Addr::new(10, 0, 1, i + 1)),
            victim,
            1234,
            80,
            TCP_SYN,
        );
        assert_eq!(state.check_packet("trust", &pkt, 100), ScreenVerdict::Pass);
    }
    // The 4th SYN to the victim (from yet another source) trips per-dest.
    let pkt = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 99)),
        victim,
        1234,
        80,
        TCP_SYN,
    );
    assert_eq!(
        state.check_packet("trust", &pkt, 100),
        ScreenVerdict::Drop("syn-flood")
    );
    assert_eq!(
        state.syn_flood_dst_drops(),
        1,
        "per-dest sub-attribution counter increments"
    );
    assert_eq!(
        state.syn_flood_src_drops(),
        0,
        "no per-source drop occurred"
    );
    // A DIFFERENT, un-flooded destination is unaffected.
    let other_dst = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 51));
    let pkt = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 5)),
        other_dst,
        1234,
        80,
        TCP_SYN,
    );
    assert_eq!(state.check_packet("trust", &pkt, 100), ScreenVerdict::Pass);
}

/// per-SOURCE threshold trips one hot source while a second source under its cap
/// passes; the aggregate stays under budget throughout.
#[test]
fn syn_flood_source_threshold_trips_per_source() {
    let mut profile = ScreenProfile::default();
    profile.syn_flood_threshold = 100_000;
    profile.syn_flood_src_threshold = 2;
    let mut state = make_state("trust", profile);
    let src_a = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    let src_b = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 2));
    // src A: 2 admitted, 3rd trips (distinct dsts so per-dest is irrelevant).
    for i in 0..2u8 {
        let pkt = tcp_pkt(
            src_a,
            IpAddr::V4(Ipv4Addr::new(10, 0, 2, i + 1)),
            1234,
            80,
            TCP_SYN,
        );
        assert_eq!(state.check_packet("trust", &pkt, 100), ScreenVerdict::Pass);
    }
    let pkt = tcp_pkt(
        src_a,
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 9)),
        1234,
        80,
        TCP_SYN,
    );
    assert_eq!(
        state.check_packet("trust", &pkt, 100),
        ScreenVerdict::Drop("syn-flood")
    );
    assert_eq!(state.syn_flood_src_drops(), 1);
    // src B under its cap passes.
    let pkt = tcp_pkt(
        src_b,
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 20)),
        1234,
        80,
        TCP_SYN,
    );
    assert_eq!(state.check_packet("trust", &pkt, 100), ScreenVerdict::Pass);
}

/// alarm-threshold: crossing it (below attack-threshold) raises a single
/// out-of-band alarm event per second per zone WITHOUT dropping the packet.
#[test]
fn syn_flood_alarm_threshold_raises_event_without_drop() {
    let mut profile = ScreenProfile::default();
    profile.syn_flood_threshold = 10; // attack
    profile.syn_flood_alarm_threshold = 3; // alarm (below attack)
    let mut state = make_state("trust", profile);
    let pkt = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        1234,
        80,
        TCP_SYN,
    );
    // SYNs 1..3: under alarm (sum 3 > 3 is false). No alarm, all Pass.
    for _ in 0..3 {
        assert_eq!(state.check_packet("trust", &pkt, 100), ScreenVerdict::Pass);
        assert!(!state.take_syn_alarm_event());
    }
    // SYN 4: sum 4 > 3 alarm, < 10 attack → alarm pending, verdict Pass.
    assert_eq!(state.check_packet("trust", &pkt, 100), ScreenVerdict::Pass);
    assert!(
        state.take_syn_alarm_event(),
        "alarm-threshold crossing raises an event"
    );
    // SYN 5 in the SAME second: alarm still over but cadence suppresses a second
    // event (≤1/sec/zone).
    assert_eq!(state.check_packet("trust", &pkt, 100), ScreenVerdict::Pass);
    assert!(
        !state.take_syn_alarm_event(),
        "≤1 alarm per second per zone"
    );
    // Next second: a fresh alarm is allowed.
    assert_eq!(state.check_packet("trust", &pkt, 101), ScreenVerdict::Pass);
    assert!(
        state.take_syn_alarm_event(),
        "a new second admits a fresh alarm"
    );
    assert!(state.syn_flood_alarm_events() >= 2);
}

/// FAIL-ON-REVERT (SMR-F5): the aggregate counter ALWAYS increments before the
/// per-IP checks, so its cookie-activation side-effect can never be skipped.
/// With both attack and per-dest configured, driving the aggregate over
/// attack-threshold mints a cookie (cookie mode) rather than letting a per-dest
/// hard-drop pre-empt the aggregate. Reverting to "per-IP first, return early"
/// would make this a per-dest Drop instead of a cookie challenge.
#[test]
fn syn_flood_aggregate_authoritative_over_per_ip() {
    let mut profile = ScreenProfile::default();
    profile.syn_flood_threshold = 2; // low aggregate
    profile.syn_cookie = true;
    profile.syn_flood_dst_threshold = 100; // per-dest configured but high
    let mut state = make_state("trust", profile);
    state.update_syn_cookie_master_key(Some(syn_cookie_key()));
    let pkt = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        1234,
        80,
        TCP_SYN,
    );
    assert_eq!(
        state.check_packet_with_zone_id("trust", 3, &pkt, 100),
        ScreenVerdict::Pass
    );
    assert_eq!(
        state.check_packet_with_zone_id("trust", 3, &pkt, 100),
        ScreenVerdict::Pass
    );
    // 3rd SYN trips the aggregate → cookie challenge (aggregate authoritative),
    // NOT a per-dest drop.
    assert!(matches!(
        state.check_packet_with_zone_id("trust", 3, &pkt, 100),
        ScreenVerdict::SynCookieChallenge(_)
    ));
    assert_eq!(
        state.syn_flood_dst_drops(),
        0,
        "aggregate cookie path pre-empts per-dest"
    );
}

/// D3: per-DESTINATION runs even when the zone is SYN-cookie active (a cookie-
/// completing distributed flood must not evade destination-threshold). Force the
/// zone cookie-active and keep the aggregate high so only the per-dest cap can
/// trip.
#[test]
fn syn_flood_dest_runs_when_cookie_active() {
    let mut profile = ScreenProfile::default();
    profile.syn_flood_threshold = 100_000; // aggregate won't trip
    profile.syn_cookie = true;
    profile.syn_flood_dst_threshold = 2;
    let mut state = make_state("trust", profile);
    state.update_syn_cookie_master_key(Some(syn_cookie_key()));
    // Force the zone cookie-active for the test window.
    state.force_syn_cookie_active_for_test("trust", 100_000);
    let victim = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 7));
    for i in 0..2u8 {
        let pkt = tcp_pkt(
            IpAddr::V4(Ipv4Addr::new(10, 0, 1, i + 1)),
            victim,
            1234,
            80,
            TCP_SYN,
        );
        assert_eq!(
            state.check_packet_with_zone_id("trust", 3, &pkt, 100),
            ScreenVerdict::Pass
        );
    }
    let pkt = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 50)),
        victim,
        1234,
        80,
        TCP_SYN,
    );
    assert_eq!(
        state.check_packet_with_zone_id("trust", 3, &pkt, 100),
        ScreenVerdict::Drop("syn-flood"),
        "per-dest must still enforce while the zone is cookie-active"
    );
    assert_eq!(state.syn_flood_dst_drops(), 1);
}

/// #4112 F19: the per-DESTINATION SYN cap is evaluated BEFORE the aggregate
/// over-attack early-return, so a per-destination-over-threshold backend is
/// HARD-DROPPED even while the zone aggregate is over attack-threshold and
/// minting SYN cookies. A LOW `syn_flood_threshold` makes over_attack fire, and
/// the per-dest cap is also low, so the same SYN trips BOTH. On revert (per-dst
/// checked only AFTER the `if over_attack` return) the 3rd SYN is a
/// SynCookieChallenge, not a Drop, and `syn_flood_dst_drops` stays 0 — the
/// destination-threshold that exists to shield a single victim is defeated in
/// exactly the high-load regime it is configured for.
#[test]
fn syn_flood_dest_hard_drops_over_attack_with_cookie() {
    let mut profile = ScreenProfile::default();
    profile.syn_flood_threshold = 2; // LOW aggregate → over_attack fires fast
    profile.syn_cookie = true;
    profile.syn_flood_dst_threshold = 2; // per-dest also low
    let mut state = make_state("trust", profile);
    state.update_syn_cookie_master_key(Some(syn_cookie_key()));
    let victim = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 9));
    // SYNs 1,2 to the victim: aggregate 1,2 (not over 2) AND per-dest 1,2 (not
    // over 2) → Pass. These also feed both counters.
    for i in 0..2u8 {
        let pkt = tcp_pkt(
            IpAddr::V4(Ipv4Addr::new(10, 0, 1, i + 1)),
            victim,
            1234,
            80,
            TCP_SYN,
        );
        assert_eq!(
            state.check_packet_with_zone_id("trust", 3, &pkt, 100),
            ScreenVerdict::Pass
        );
    }
    // SYN 3: aggregate 3 > 2 → over_attack (WOULD mint a cookie), AND per-dest
    // 3 > 2. The per-destination cap is evaluated first and HARD-DROPS. On revert
    // this is a SynCookieChallenge (the flooded victim admits cookie-completing
    // clients) — the F19 bug.
    let pkt = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 50)),
        victim,
        1234,
        80,
        TCP_SYN,
    );
    assert_eq!(
        state.check_packet_with_zone_id("trust", 3, &pkt, 100),
        ScreenVerdict::Drop("syn-flood"),
        "per-dst must hard-drop before the aggregate mints a cookie"
    );
    assert_eq!(state.syn_flood_dst_drops(), 1);
}

/// D3: per-SOURCE is SKIPPED while the zone is SYN-cookie active. Even a source
/// well over its cap must NOT be per-source dropped once the cookie governs the
/// zone (the spoofed-flood regime where per-source is defeated and the sketch
/// would over-throttle). RED on revert if the cookie-active gate is dropped.
#[test]
fn syn_flood_source_skipped_when_cookie_active() {
    let mut profile = ScreenProfile::default();
    profile.syn_flood_threshold = 100_000; // aggregate won't trip
    profile.syn_cookie = true;
    profile.syn_flood_src_threshold = 2;
    let mut state = make_state("trust", profile);
    state.update_syn_cookie_master_key(Some(syn_cookie_key()));
    state.force_syn_cookie_active_for_test("trust", 100_000);
    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    // Many SYNs from one source, far over source-threshold, all Pass (per-source
    // skipped while cookie-active).
    for i in 0..10u8 {
        let pkt = tcp_pkt(
            src,
            IpAddr::V4(Ipv4Addr::new(10, 0, 2, i + 1)),
            1234,
            80,
            TCP_SYN,
        );
        assert_eq!(
            state.check_packet_with_zone_id("trust", 3, &pkt, 100),
            ScreenVerdict::Pass
        );
    }
    assert_eq!(
        state.syn_flood_src_drops(),
        0,
        "per-source must be skipped while cookie-active"
    );
}

/// per-SOURCE runs (NOT skipped) when the zone is NOT cookie-active — the
/// counterpart to the gate test above.
#[test]
fn syn_flood_source_runs_when_not_cookie_active() {
    let mut profile = ScreenProfile::default();
    profile.syn_flood_threshold = 100_000;
    profile.syn_cookie = true; // enabled but zone NOT active
    profile.syn_flood_src_threshold = 2;
    let mut state = make_state("trust", profile);
    state.update_syn_cookie_master_key(Some(syn_cookie_key()));
    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    for i in 0..2u8 {
        let pkt = tcp_pkt(
            src,
            IpAddr::V4(Ipv4Addr::new(10, 0, 2, i + 1)),
            1234,
            80,
            TCP_SYN,
        );
        assert_eq!(
            state.check_packet_with_zone_id("trust", 3, &pkt, 100),
            ScreenVerdict::Pass
        );
    }
    let pkt = tcp_pkt(
        src,
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 9)),
        1234,
        80,
        TCP_SYN,
    );
    assert_eq!(
        state.check_packet_with_zone_id("trust", 3, &pkt, 100),
        ScreenVerdict::Drop("syn-flood")
    );
    assert_eq!(state.syn_flood_src_drops(), 1);
}

/// Sub-threshold sketches are allocated only for zones that configure them and
/// dropped when the threshold is removed (memory tracks live config).
#[test]
fn syn_flood_sketches_allocated_only_when_configured() {
    let mut state = ScreenState::new();
    // No sub-thresholds → no sketches.
    let mut p = ScreenProfile::default();
    p.syn_flood_threshold = 10;
    state.update_profiles({
        let mut m = FxHashMap::default();
        m.insert("trust".to_string(), p.clone());
        m
    });
    assert!(!state.syn_dst_sketch_present("trust"));
    assert!(!state.syn_src_sketch_present("trust"));
    // Configure dst + src → sketches appear.
    let mut p2 = p.clone();
    p2.syn_flood_dst_threshold = 5;
    p2.syn_flood_src_threshold = 5;
    state.update_profiles({
        let mut m = FxHashMap::default();
        m.insert("trust".to_string(), p2);
        m
    });
    assert!(state.syn_dst_sketch_present("trust"));
    assert!(state.syn_src_sketch_present("trust"));
    // Remove them → sketches freed.
    state.update_profiles({
        let mut m = FxHashMap::default();
        m.insert("trust".to_string(), p);
        m
    });
    assert!(!state.syn_dst_sketch_present("trust"));
    assert!(!state.syn_src_sketch_present("trust"));
}

// ================================================================
// SYN cookie core (#1374)
// ================================================================

fn syn_cookie_codec() -> SynCookieCodec {
    SynCookieCodec::new(syn_cookie_key())
}

/// Zone tags for the codec and cache cells that predate #9740, in place of the
/// zone ids they passed. Any two distinct tags serve.
const Z7: [u64; 2] = [7, 0];
const Z8: [u64; 2] = [8, 0];

fn syn_cookie_key() -> [u8; 16] {
    [
        0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe,
        0x0f,
    ]
}

/// #9419 whitelist key for the same client the `syn_cookie_tuple()` 4-tuple
/// describes. Deliberately carries no ephemeral source port.
fn syn_cookie_client() -> SynCookieClientKey {
    SynCookieClientKey {
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        dst_port: 443,
    }
}

fn syn_cookie_tuple() -> SynCookieTuple {
    SynCookieTuple {
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        src_port: 49152,
        dst_port: 443,
    }
}

#[test]
fn siphash24_matches_reference_vectors() {
    // SipHash-2-4 reference vectors for key bytes 00..0f and message bytes
    // 00..len. These pin the private implementation used by the cookie MAC.
    let k0 = u64::from_le_bytes([0, 1, 2, 3, 4, 5, 6, 7]);
    let k1 = u64::from_le_bytes([8, 9, 10, 11, 12, 13, 14, 15]);
    let vectors = [
        (0usize, 0x726f_db47_dd0e_0e31u64),
        (1, 0x74f8_39c5_93dc_67fdu64),
        (8, 0x93f5_f579_9a93_2462u64),
        (15, 0xa129_ca61_49be_45e5u64),
    ];

    for (len, expected) in vectors {
        let mut sip = SipHash24::new(k0, k1);
        let bytes: Vec<u8> = (0..len as u8).collect();
        sip.write_bytes(&bytes);
        assert_eq!(sip.finish(), expected, "SipHash-2-4 vector length {len}");
    }
}

#[test]
fn syn_cookie_layout_fills_tcp_isn() {
    assert_eq!(SYN_COOKIE_LAYOUT_BITS, SYN_COOKIE_ISN_BITS);
    assert_eq!(SYN_COOKIE_EPOCH_SHIFT, 27);
    assert_eq!(SYN_COOKIE_MSS_SHIFT, 24);
}

#[test]
fn syn_cookie_tuple_from_packet_matches_packet_flow() {
    let pkt = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        49152,
        443,
        TCP_SYN,
    );

    assert_eq!(SynCookieTuple::from_packet(&pkt), syn_cookie_tuple());
}

#[test]
fn syn_cookie_mint_validate_roundtrip() {
    let codec = syn_cookie_codec();
    let tuple = syn_cookie_tuple();
    let cookie = codec.mint_isn(tuple, Z7, 42, 1460);
    let validation = codec
        .validate_isn(tuple, Z7, 42, cookie)
        .expect("fresh cookie should validate");

    assert_eq!(validation.full_epoch, 42);
    assert_eq!(validation.mss_index, 6);
    assert_eq!(validation.mss, 1460);
    assert_eq!(
        (cookie >> SYN_COOKIE_EPOCH_SHIFT) & SYN_COOKIE_EPOCH_MASK,
        10
    );
}

#[test]
fn syn_cookie_validate_rejects_modified_tuple() {
    let codec = syn_cookie_codec();
    let tuple = syn_cookie_tuple();
    let cookie = codec.mint_isn(tuple, Z7, 42, 1460);

    let mut mutated = tuple;
    mutated.src_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11));
    assert!(codec.validate_isn(mutated, Z7, 42, cookie).is_none());

    mutated = tuple;
    mutated.dst_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 21));
    assert!(codec.validate_isn(mutated, Z7, 42, cookie).is_none());

    mutated = tuple;
    mutated.src_port += 1;
    assert!(codec.validate_isn(mutated, Z7, 42, cookie).is_none());

    mutated = tuple;
    mutated.dst_port += 1;
    assert!(codec.validate_isn(mutated, Z7, 42, cookie).is_none());

    assert!(codec.validate_isn(tuple, Z8, 42, cookie).is_none());
}

#[test]
fn syn_cookie_validate_rejects_stale_secret() {
    let codec = syn_cookie_codec();
    let stale_codec = SynCookieCodec::new([
        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
        0x00,
    ]);
    let tuple = syn_cookie_tuple();
    let cookie = codec.mint_isn(tuple, Z7, 42, 1460);

    assert!(stale_codec.validate_isn(tuple, Z7, 42, cookie).is_none());
}

#[test]
fn syn_cookie_mss_index_encoding_parity() {
    let codec = syn_cookie_codec();
    let tuple = syn_cookie_tuple();

    for (idx, mss) in SYN_COOKIE_MSS_VALUES.iter().copied().enumerate() {
        assert_eq!(SynCookieCodec::mss_index(mss), idx as u8);
        let cookie = codec.mint_isn(tuple, Z7, 42, mss);
        assert_eq!(
            (cookie >> SYN_COOKIE_MSS_SHIFT) & SYN_COOKIE_MSS_MASK,
            idx as u32
        );
        assert_eq!(codec.validate_isn(tuple, Z7, 42, cookie).unwrap().mss, mss);
    }

    assert_eq!(SynCookieCodec::mss_index(535), 0);
    assert_eq!(SynCookieCodec::mss_index(1459), 5);
    assert_eq!(SynCookieCodec::mss_index(9000), 7);

    let cookie = codec.mint_isn(tuple, Z7, 42, 1460);
    let tampered_mss =
        (cookie & !(SYN_COOKIE_MSS_MASK << SYN_COOKIE_MSS_SHIFT)) | (5 << SYN_COOKIE_MSS_SHIFT);
    assert!(codec.validate_isn(tuple, Z7, 42, tampered_mss).is_none());
}

#[test]
fn syn_cookie_epoch_uses_unix_wall_clock_units() {
    assert_eq!(SynCookieCodec::full_epoch_from_unix_secs(0), 0);
    assert_eq!(SynCookieCodec::full_epoch_from_unix_secs(63), 0);
    assert_eq!(SynCookieCodec::full_epoch_from_unix_secs(64), 1);
    assert_eq!(SynCookieCodec::full_epoch_from_unix_secs(64 * 33 + 9), 33);
}

#[test]
fn syn_cookie_current_full_epoch_is_pure_wall_clock_passthrough() {
    // #3032: the epoch leaf must be a pure function of the supplied Unix
    // wall-clock seconds — it no longer reads the OS clock. Pinning it equal
    // to `full_epoch_from_unix_secs` for sample seconds catches any
    // off-by-one-epoch or clock-domain regression at the leaf.
    for secs in [0u64, 1, 63, 64, 127, 128, 64 * 33 + 9, 1_800_000_000] {
        assert_eq!(
            SynCookieCodec::current_full_epoch(secs),
            SynCookieCodec::full_epoch_from_unix_secs(secs),
            "current_full_epoch must equal full_epoch_from_unix_secs for {secs}s",
        );
    }
}

#[test]
fn syn_cookie_round_trip_with_cached_wall_secs() {
    // #3032: minting with an epoch derived from a cached wall-clock second
    // (as the hot path now does once per monotonic second) and validating
    // with the same cached domain must round-trip — and must keep the same
    // 60s+ window tolerance as before. T sits mid-epoch so the +/-1 epoch
    // window is exercised, not a boundary artifact.
    let codec = syn_cookie_codec();
    let tuple = syn_cookie_tuple();
    // 1_800_000_000 is an exact multiple of EPOCH_SECS (64), so the second
    // sits at offset 0 within its epoch and the +/- arithmetic below stays
    // inside / crosses epochs deterministically.
    let mint_unix_secs = 1_800_000_000u64;
    assert_eq!(mint_unix_secs % SynCookieCodec::EPOCH_SECS, 0);
    let mint_epoch = SynCookieCodec::current_full_epoch(mint_unix_secs);
    let cookie = codec.mint_isn(tuple, Z7, mint_epoch, 1460);

    // Validate at the same cached second.
    assert!(
        codec.validate_isn(tuple, Z7, mint_epoch, cookie).is_some(),
        "same-second validation must succeed",
    );
    // Validate from a second still inside the same epoch (cached value may be
    // up to ~1s stale under the once-per-second refresh, well within window).
    let same_epoch_later =
        SynCookieCodec::current_full_epoch(mint_unix_secs + (SynCookieCodec::EPOCH_SECS - 1));
    assert_eq!(same_epoch_later, mint_epoch);
    assert!(
        codec
            .validate_isn(tuple, Z7, same_epoch_later, cookie)
            .is_some(),
        "validation later in the same epoch must succeed",
    );
    // Validate one epoch ahead (next-second crossing into the next epoch) —
    // still inside the +/-1 epoch acceptance window.
    let next_epoch =
        SynCookieCodec::current_full_epoch(mint_unix_secs + SynCookieCodec::EPOCH_SECS);
    assert_eq!(next_epoch, mint_epoch + 1);
    assert!(
        codec.validate_isn(tuple, Z7, next_epoch, cookie).is_some(),
        "validation one epoch later must succeed (window tolerance)",
    );
    // Two epochs ahead is outside the window and must fail, exactly as
    // before the cached-now change.
    let two_epochs_ahead =
        SynCookieCodec::current_full_epoch(mint_unix_secs + 2 * SynCookieCodec::EPOCH_SECS);
    assert_eq!(two_epochs_ahead, mint_epoch + 2);
    assert!(
        codec
            .validate_isn(tuple, Z7, two_epochs_ahead, cookie)
            .is_none(),
        "validation two epochs later must fail as before",
    );
}

#[test]
fn syn_cookie_screen_state_epoch_uses_wall_clock_not_monotonic() {
    // #3032 (call-site clock-domain guard): `current_syn_cookie_full_epoch`
    // takes the batch-cached MONOTONIC second purely as a once-per-second
    // refresh throttle, but must derive the epoch from the cached Unix
    // wall-clock seconds — NOT from the monotonic argument. This is the exact
    // HA-breaking regression the issue feared: feeding `mono_now_secs` into
    // the epoch (`current_full_epoch(mono_now_secs)`) would compile and pass
    // every leaf/codec test. This test fails if that happens.
    //
    // No `set_syn_cookie_full_epoch_for_test` override here — that would
    // short-circuit the very selection under test.
    let mut state = make_state("trust", ScreenProfile::default());

    // A small monotonic second lands in a wildly different epoch bucket than
    // the live wall clock (~1.7e9s ⇒ epoch ~28M vs. epoch 0 for 5s), so the
    // two are always distinguishable regardless of when the test runs.
    let mono_now_secs = 5u64;
    let monotonic_epoch = SynCookieCodec::full_epoch_from_unix_secs(mono_now_secs);

    // Bracket the call with wall-clock samples from the SAME source the
    // implementation uses, so a 64s-boundary crossing during the call cannot
    // flake the assertion.
    let wall_epoch_before =
        SynCookieCodec::full_epoch_from_unix_secs(ScreenState::read_unix_wall_secs());
    let got = state.current_syn_cookie_full_epoch(mono_now_secs);
    let wall_epoch_after =
        SynCookieCodec::full_epoch_from_unix_secs(ScreenState::read_unix_wall_secs());

    assert!(
        got == wall_epoch_before || got == wall_epoch_after,
        "epoch must come from the live Unix wall clock ({wall_epoch_before}..={wall_epoch_after}), got {got}",
    );
    assert_ne!(
        got, monotonic_epoch,
        "epoch must NOT be derived from the monotonic argument ({mono_now_secs}s ⇒ epoch {monotonic_epoch})",
    );
    assert_ne!(got, 0, "a live wall-clock epoch is never 0 (1970)");
}

#[test]
fn syn_cookie_wall_clock_epoch_survives_peer_uptime_skew() {
    let codec = syn_cookie_codec();
    let tuple = syn_cookie_tuple();
    let shared_wall_epoch = SynCookieCodec::full_epoch_from_unix_secs(1_800_000_000);
    let peer_monotonic_epoch = 0;
    let cookie = codec.mint_isn(tuple, Z7, shared_wall_epoch, 1460);

    assert_ne!(
        shared_wall_epoch, peer_monotonic_epoch,
        "test must model peers with unrelated monotonic uptimes"
    );
    assert!(
        codec
            .validate_isn(tuple, Z7, shared_wall_epoch, cookie)
            .is_some(),
        "HA peers validate with the shared Unix wall-clock epoch"
    );
    assert!(
        codec
            .validate_isn(tuple, Z7, peer_monotonic_epoch, cookie)
            .is_none(),
        "local monotonic uptime would reject the peer-minted cookie"
    );
}

#[test]
fn syn_cookie_epoch_low_bits_wrap_rejects_32_epoch_old_cookie() {
    let codec = syn_cookie_codec();
    let tuple = syn_cookie_tuple();
    let old_epoch = 10;
    let current_epoch = old_epoch + 32;
    let cookie = codec.mint_isn(tuple, Z7, old_epoch, 1460);

    assert_eq!(old_epoch & 0x1f, current_epoch & 0x1f);
    assert!(
        codec
            .validate_isn(tuple, Z7, current_epoch, cookie)
            .is_none()
    );
}

#[test]
fn syn_cookie_validation_tries_next_current_and_previous_full_epoch() {
    let codec = syn_cookie_codec();
    let tuple = syn_cookie_tuple();
    let next_cookie = codec.mint_isn(tuple, Z7, 43, 1460);
    let current_cookie = codec.mint_isn(tuple, Z7, 42, 1460);
    let previous_cookie = codec.mint_isn(tuple, Z7, 41, 1460);
    let older_cookie = codec.mint_isn(tuple, Z7, 40, 1460);

    assert_eq!(
        codec
            .validate_isn(tuple, Z7, 42, next_cookie)
            .expect("next epoch")
            .full_epoch,
        43
    );
    assert_eq!(
        codec
            .validate_isn(tuple, Z7, 42, current_cookie)
            .expect("current epoch")
            .full_epoch,
        42
    );
    assert_eq!(
        codec
            .validate_isn(tuple, Z7, 42, previous_cookie)
            .expect("previous epoch")
            .full_epoch,
        41
    );
    assert!(codec.validate_isn(tuple, Z7, 42, older_cookie).is_none());
}

#[test]
fn syn_cookie_chosen_when_threshold_exceeded() {
    let mut profile = ScreenProfile::default();
    profile.syn_flood_threshold = 2;
    profile.syn_cookie = true;
    let mut state = make_state("trust", profile);
    state.update_syn_cookie_master_key(Some(syn_cookie_key()));
    state.set_syn_cookie_full_epoch_for_test(2);
    let pkt = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        49152,
        443,
        TCP_SYN,
    );

    assert_eq!(
        state.check_packet_with_zone_id("trust", 7, &pkt, 128),
        ScreenVerdict::Pass
    );
    assert_eq!(
        state.check_packet_with_zone_id("trust", 7, &pkt, 128),
        ScreenVerdict::Pass
    );
    let expected_isn = syn_cookie_codec().mint_isn(
        SynCookieTuple::from_packet(&pkt),
        syn_cookie_zone_tag("trust"),
        2,
        pkt.tcp_mss,
    );
    assert_eq!(
        state.check_packet_with_zone_id("trust", 7, &pkt, 128),
        ScreenVerdict::SynCookieChallenge(SynCookieChallenge {
            cookie_isn: expected_isn,
            peer_mss: 1460,
        })
    );
}

#[test]
fn syn_cookie_without_published_secret_fails_closed() {
    let mut profile = ScreenProfile::default();
    profile.syn_flood_threshold = 1;
    profile.syn_cookie = true;
    let mut state = make_state("trust", profile);
    let pkt = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        49152,
        443,
        TCP_SYN,
    );

    assert_eq!(
        state.check_packet_with_zone_id("trust", 7, &pkt, 128),
        ScreenVerdict::Pass
    );
    assert_eq!(
        state.check_packet_with_zone_id("trust", 7, &pkt, 128),
        ScreenVerdict::Drop("syn-cookie-unavailable")
    );
}

#[test]
fn syn_cookie_ack_validation_marks_next_syn_bypass_without_session_creation() {
    let mut profile = ScreenProfile::default();
    profile.syn_flood_threshold = 1;
    profile.syn_cookie = true;
    let mut state = make_state("trust", profile);
    state.update_syn_cookie_master_key(Some(syn_cookie_key()));
    state.set_syn_cookie_full_epoch_for_test(1);
    let syn = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        49152,
        443,
        TCP_SYN,
    );

    assert_eq!(
        state.check_packet_with_zone_id("trust", 7, &syn, 128),
        ScreenVerdict::Pass
    );
    let challenge = match state.check_packet_with_zone_id("trust", 7, &syn, 128) {
        ScreenVerdict::SynCookieChallenge(challenge) => challenge,
        other => panic!("expected SYN-cookie challenge, got {other:?}"),
    };

    let mut ack = syn.clone();
    ack.tcp_flags = TCP_ACK;
    ack.tcp_seq = 2;
    ack.tcp_ack = challenge.cookie_isn.wrapping_add(1);
    assert_eq!(
        state.validate_syn_cookie_ack_on_session_miss("trust", 7, &ack, 128 * NS, 128),
        SynCookieAckVerdict::Validated
    );
    assert_eq!(state.syn_cookie_validated_len(), 1);

    assert_eq!(
        state.check_packet_with_zone_id("trust", 7, &syn, 128),
        ScreenVerdict::SynCookieBypass
    );
    // #9419 re-anchor. This used to assert `len() == 0` with the note
    // "validated tuple is single-use". Single-use was the defect, not the
    // contract: the challenge path answers the valid cookie ACK with a RST,
    // so the retry this whitelist exists to admit arrives from a NEW
    // ephemeral port on a NEW connection — a single-use entry is already
    // gone by then even in the impossible case where the port matched. The
    // entry now survives its own hit and is bounded only by the TTL and the
    // #2446 generation.
    assert_eq!(
        state.syn_cookie_validated_len(),
        1,
        "a validated client stays whitelisted for the TTL, not for one packet"
    );
}

#[test]
fn syn_cookie_validated_syn_bypasses_flood_gate_and_passes() {
    // #2134: this test used to prove "a SYN-cookie-validated SYN still
    // runs the LATER screen checks" by asserting the session-limit drop
    // fires on the validated tuple. That check moved out of the screen
    // stage (it now enforces at the new-flow decision in
    // poll_descriptor), and the only remaining later stateful checks
    // (port-scan / ip-sweep) key on tuple-uniqueness — which conflicts
    // with the validated cache, that bypasses the flood gate only for the
    // validated CLIENT (src_ip, dst_ip, dst_port — #9419). So we prove the
    // load-bearing property
    // directly: a cookie-validated SYN bypasses the SYN-flood gate and
    // traverses the rest of `check_packet_with_zone_id` to a clean Pass,
    // whereas the identical un-validated SYN is challenged at the gate.
    let mut profile = ScreenProfile::default();
    profile.syn_flood_threshold = 1;
    profile.syn_cookie = true;
    let mut state = make_state("trust", profile);
    state.update_syn_cookie_master_key(Some(syn_cookie_key()));
    let syn = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        49152,
        443,
        TCP_SYN,
    );

    // First SYN passes (under the SYN-flood threshold of 1).
    assert_eq!(
        state.check_packet_with_zone_id("trust", 7, &syn, 128),
        ScreenVerdict::Pass
    );
    // Second SYN crosses the SYN-flood threshold -> cookie challenge.
    let challenge = match state.check_packet_with_zone_id("trust", 7, &syn, 128) {
        ScreenVerdict::SynCookieChallenge(challenge) => challenge,
        other => panic!("expected SYN-cookie challenge, got {other:?}"),
    };

    let mut ack = syn.clone();
    ack.tcp_flags = TCP_ACK;
    ack.tcp_ack = challenge.cookie_isn.wrapping_add(1);
    assert_eq!(
        state.validate_syn_cookie_ack_on_session_miss("trust", 7, &ack, 128 * NS, 128),
        SynCookieAckVerdict::Validated
    );

    // The client's next SYN, now cookie-validated, bypasses the SYN-flood
    // gate and runs to completion: SynCookieBypass (a Pass-equivalent that
    // records the bypass), NOT another challenge or drop. #9419: the entry
    // survives the hit (see `syn_cookie_retry_from_new_ephemeral_port_...`),
    // so the cache still holds it afterwards.
    assert_eq!(
        state.check_packet_with_zone_id("trust", 7, &syn, 128),
        ScreenVerdict::SynCookieBypass
    );
    assert_eq!(state.syn_cookie_validated_len(), 1);
}

// ===== #9419: the challenge-and-reset design's own recovery step =====
//
// `docs/syn-cookie-flood-protection.md` step 6 is "client retransmits SYN ->
// passes as validated". No TCP stack does that: step 5 RSTs the client, which
// aborts the just-ESTABLISHED socket with ECONNRESET, and the application
// calls `connect()` again — a NEW ephemeral source port. So the ONLY shape in
// which step 6 is observable is a retry from a DIFFERENT source port, and that
// is what these cells drive. The pre-#9419 whitelist key carried `src_port`
// and was consumed on hit, so both halves had to change; each cell below is
// red under either half alone.
//
// FAIL-ON-REVERT: re-add `src_port` to `SynCookieClientKey`, or restore the
// consume-on-hit in `contains_valid`, and these red as assertions.

/// Step 6, in the only shape it can occur in: the retry comes from a new
/// ephemeral port.
#[test]
fn syn_cookie_retry_from_new_ephemeral_port_bypasses_9419() {
    let mut profile = ScreenProfile::default();
    profile.syn_flood_threshold = 1;
    profile.syn_cookie = true;
    let mut state = make_state("trust", profile);
    state.update_syn_cookie_master_key(Some(syn_cookie_key()));
    state.set_syn_cookie_full_epoch_for_test(1);

    let syn = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        49152,
        443,
        TCP_SYN,
    );
    assert_eq!(
        state.check_packet_with_zone_id("trust", 7, &syn, 128),
        ScreenVerdict::Pass
    );
    let challenge = match state.check_packet_with_zone_id("trust", 7, &syn, 128) {
        ScreenVerdict::SynCookieChallenge(challenge) => challenge,
        other => panic!("expected SYN-cookie challenge, got {other:?}"),
    };

    let mut ack = syn.clone();
    ack.tcp_flags = TCP_ACK;
    ack.tcp_seq = 2;
    ack.tcp_ack = challenge.cookie_isn.wrapping_add(1);
    assert_eq!(
        state.validate_syn_cookie_ack_on_session_miss("trust", 7, &ack, 128 * NS, 128),
        SynCookieAckVerdict::Validated
    );

    // The RST landed; the application reconnects. Everything about the packet
    // is identical EXCEPT the ephemeral source port.
    let mut retry = syn.clone();
    retry.src_port = 49153;
    assert_eq!(
        state.check_packet_with_zone_id("trust", 7, &retry, 128),
        ScreenVerdict::SynCookieBypass,
        "a validated client's reconnect must be admitted; it cannot reuse the \
         ephemeral port the RST just tore down"
    );
}

/// Not single-use: several successive reconnects, each on its own new port,
/// are all admitted while the whitelist entry is inside its TTL.
#[test]
fn syn_cookie_repeated_reconnects_from_validated_client_bypass_9419() {
    let mut profile = ScreenProfile::default();
    profile.syn_flood_threshold = 1;
    profile.syn_cookie = true;
    let mut state = make_state("trust", profile);
    state.update_syn_cookie_master_key(Some(syn_cookie_key()));
    state.set_syn_cookie_full_epoch_for_test(1);

    let syn = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        49152,
        443,
        TCP_SYN,
    );
    assert_eq!(
        state.check_packet_with_zone_id("trust", 7, &syn, 128),
        ScreenVerdict::Pass
    );
    let challenge = match state.check_packet_with_zone_id("trust", 7, &syn, 128) {
        ScreenVerdict::SynCookieChallenge(challenge) => challenge,
        other => panic!("expected SYN-cookie challenge, got {other:?}"),
    };
    let mut ack = syn.clone();
    ack.tcp_flags = TCP_ACK;
    ack.tcp_seq = 2;
    ack.tcp_ack = challenge.cookie_isn.wrapping_add(1);
    assert_eq!(
        state.validate_syn_cookie_ack_on_session_miss("trust", 7, &ack, 128 * NS, 128),
        SynCookieAckVerdict::Validated
    );

    for port in 49153u16..49158 {
        let mut retry = syn.clone();
        retry.src_port = port;
        assert_eq!(
            state.check_packet_with_zone_id("trust", 7, &retry, 128),
            ScreenVerdict::SynCookieBypass,
            "reconnect {port} must still bypass: the whitelist is bounded by \
             its TTL, not by a single use"
        );
    }
    assert_eq!(state.syn_cookie_validated_len(), 1);
}

/// NEGATIVE CONTROL — the widening is source- and service-scoped, not blanket.
/// A different source address and a different destination service are both
/// still challenged, from the same state that just admitted the reconnect
/// above. Without this, "always return true" would pass the two cells above.
#[test]
fn syn_cookie_whitelist_does_not_widen_past_the_validated_client_9419() {
    let mut profile = ScreenProfile::default();
    profile.syn_flood_threshold = 1;
    profile.syn_cookie = true;
    let mut state = make_state("trust", profile);
    state.update_syn_cookie_master_key(Some(syn_cookie_key()));
    state.set_syn_cookie_full_epoch_for_test(1);

    let syn = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        49152,
        443,
        TCP_SYN,
    );
    assert_eq!(
        state.check_packet_with_zone_id("trust", 7, &syn, 128),
        ScreenVerdict::Pass
    );
    let challenge = match state.check_packet_with_zone_id("trust", 7, &syn, 128) {
        ScreenVerdict::SynCookieChallenge(challenge) => challenge,
        other => panic!("expected SYN-cookie challenge, got {other:?}"),
    };
    let mut ack = syn.clone();
    ack.tcp_flags = TCP_ACK;
    ack.tcp_seq = 2;
    ack.tcp_ack = challenge.cookie_isn.wrapping_add(1);
    assert_eq!(
        state.validate_syn_cookie_ack_on_session_miss("trust", 7, &ack, 128 * NS, 128),
        SynCookieAckVerdict::Validated
    );

    // POSITIVE control, same instant: the validated client's reconnect IS
    // admitted, so a challenge below is a real scope boundary rather than the
    // whitelist simply being empty or the zone not being cookie-active.
    let mut ok = syn.clone();
    ok.src_port = 49153;
    assert_eq!(
        state.check_packet_with_zone_id("trust", 7, &ok, 128),
        ScreenVerdict::SynCookieBypass
    );

    let mut other_source = syn.clone();
    other_source.src_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11));
    other_source.src_port = 49153;
    assert!(
        matches!(
            state.check_packet_with_zone_id("trust", 7, &other_source, 128),
            ScreenVerdict::SynCookieChallenge(_)
        ),
        "a DIFFERENT source must not inherit the whitelist"
    );

    let mut other_service = syn.clone();
    other_service.dst_port = 8443;
    other_service.src_port = 49154;
    assert!(
        matches!(
            state.check_packet_with_zone_id("trust", 7, &other_service, 128),
            ScreenVerdict::SynCookieChallenge(_)
        ),
        "a DIFFERENT destination service must not inherit the whitelist"
    );
}

/// The whitelist is bounded by the TTL: once the entry ages out, a reconnect
/// from the validated client is challenged again rather than admitted forever.
#[test]
fn syn_cookie_whitelist_stops_bypassing_after_ttl_9419() {
    let mut profile = ScreenProfile::default();
    profile.syn_flood_threshold = 1;
    profile.syn_cookie = true;
    let mut state = make_state("trust", profile);
    state.update_syn_cookie_master_key(Some(syn_cookie_key()));
    state.set_syn_cookie_full_epoch_for_test(1);

    let syn = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        49152,
        443,
        TCP_SYN,
    );
    assert_eq!(
        state.check_packet_with_zone_id("trust", 7, &syn, 128),
        ScreenVerdict::Pass
    );
    let challenge = match state.check_packet_with_zone_id("trust", 7, &syn, 128) {
        ScreenVerdict::SynCookieChallenge(challenge) => challenge,
        other => panic!("expected SYN-cookie challenge, got {other:?}"),
    };
    let mut ack = syn.clone();
    ack.tcp_flags = TCP_ACK;
    ack.tcp_seq = 2;
    ack.tcp_ack = challenge.cookie_isn.wrapping_add(1);
    assert_eq!(
        state.validate_syn_cookie_ack_on_session_miss("trust", 7, &ack, 128 * NS, 128),
        SynCookieAckVerdict::Validated
    );

    // Insert at 128 with a one-epoch (64s) TTL -> expires at 192.
    let mut late = syn.clone();
    late.src_port = 49153;
    assert_ne!(
        state.check_packet_with_zone_id("trust", 7, &late, 192),
        ScreenVerdict::SynCookieBypass,
        "the whitelist must expire; a 64s-old validation is not a standing pass"
    );
    assert_eq!(
        state.syn_cookie_validated_len(),
        0,
        "the expired entry is reclaimed rather than left occupying a way"
    );
}

#[test]
fn syn_cookie_invalid_ack_does_not_validate_client() {
    let mut profile = ScreenProfile::default();
    profile.syn_flood_threshold = 1;
    profile.syn_cookie = true;
    let mut state = make_state("trust", profile);
    state.update_syn_cookie_master_key(Some(syn_cookie_key()));
    state.set_syn_cookie_full_epoch_for_test(1);
    let syn = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        49152,
        443,
        TCP_SYN,
    );

    assert_eq!(
        state.check_packet_with_zone_id("trust", 7, &syn, 128),
        ScreenVerdict::Pass
    );
    assert!(matches!(
        state.check_packet_with_zone_id("trust", 7, &syn, 128),
        ScreenVerdict::SynCookieChallenge(_)
    ));

    let mut ack = syn.clone();
    ack.tcp_flags = TCP_ACK;
    ack.tcp_seq = 2;
    ack.tcp_ack = 0xdead_beefu32;
    assert_eq!(
        state.validate_syn_cookie_ack_on_session_miss("trust", 7, &ack, 128 * NS, 128),
        SynCookieAckVerdict::Invalid
    );
    assert_eq!(state.syn_cookie_validated_len(), 0);
}

// fable-review-164 L-10 fold: under `alarm-without-drop`, the SYN-cookie path
// must stay profile-wide -- FORWARD + alarm, never drop. A zone in syn-cookie
// mode that crosses attack-threshold marks itself cookie-active as a
// SIDE-EFFECT of `check_packet` (BEFORE the challenge verdict is converted to a
// log-only alarm + Pass by the consumer). Because audit mode never actually
// mints cookies on the wire, any returning session-miss ACK is unvalidatable;
// if the zone were marked cookie-active, `validate_syn_cookie_ack_on_session_miss`
// would DROP it as `Invalid`. Gating the cookie-active marking on
// `!alarm_without_drop` keeps `locally_active` false so the ACK is
// `NotApplicable` (forwards). The non-audit control proves the normal
// SYN-cookie flow is UNCHANGED (still Invalid -> drop).
//
// FAIL-ON-REVERT: remove the `!alarm_without_drop` gate on the
// `syn_cookie_active_until_secs` set and the audit assertion flips to Invalid.
#[test]
fn syn_cookie_alarm_without_drop_forwards_session_miss_ack_l10() {
    let syn = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        49152,
        443,
        TCP_SYN,
    );
    let mut ack = syn.clone();
    ack.tcp_flags = TCP_ACK;
    ack.tcp_seq = 2;
    ack.tcp_ack = 0xdead_beefu32; // not a valid cookie

    // Audit mode: crossing SYN still mints a challenge (the consumer converts
    // it to alarm + Pass), but the zone is NOT marked cookie-active, so the
    // returning invalid ACK is NotApplicable (forwards) rather than Invalid.
    let mut audit = ScreenProfile::default();
    audit.syn_flood_threshold = 1;
    audit.syn_cookie = true;
    audit.alarm_without_drop = true;
    let mut astate = make_state("trust", audit);
    astate.update_syn_cookie_master_key(Some(syn_cookie_key()));
    astate.set_syn_cookie_full_epoch_for_test(1);
    assert_eq!(
        astate.check_packet_with_zone_id("trust", 7, &syn, 128),
        ScreenVerdict::Pass
    );
    assert!(
        matches!(
            astate.check_packet_with_zone_id("trust", 7, &syn, 128),
            ScreenVerdict::SynCookieChallenge(_)
        ),
        "audit mode still mints the challenge verdict (converted to alarm+Pass \
         by the consumer)"
    );
    assert_eq!(
        astate.validate_syn_cookie_ack_on_session_miss("trust", 7, &ack, 128 * NS, 128),
        SynCookieAckVerdict::NotApplicable,
        "alarm-without-drop must FORWARD the returning session-miss ACK, not \
         drop it as Invalid"
    );

    // Non-audit control (identical inputs, alarm_without_drop = false): the
    // zone IS marked cookie-active and the invalid ACK is dropped as Invalid.
    // Proves the normal SYN-cookie flow is unchanged by the fold.
    let mut normal = ScreenProfile::default();
    normal.syn_flood_threshold = 1;
    normal.syn_cookie = true;
    let mut nstate = make_state("trust", normal);
    nstate.update_syn_cookie_master_key(Some(syn_cookie_key()));
    nstate.set_syn_cookie_full_epoch_for_test(1);
    assert_eq!(
        nstate.check_packet_with_zone_id("trust", 7, &syn, 128),
        ScreenVerdict::Pass
    );
    assert!(matches!(
        nstate.check_packet_with_zone_id("trust", 7, &syn, 128),
        ScreenVerdict::SynCookieChallenge(_)
    ));
    assert_eq!(
        nstate.validate_syn_cookie_ack_on_session_miss("trust", 7, &ack, 128 * NS, 128),
        SynCookieAckVerdict::Invalid,
        "non-audit syn-cookie flow must still drop the invalid ACK (unchanged)"
    );
}

#[test]
fn syn_cookie_ack_validates_on_peer_without_local_active_window() {
    let mut profile = ScreenProfile::default();
    profile.syn_flood_threshold = 1;
    profile.syn_cookie = true;

    let mut peer = make_state("trust", profile);
    peer.update_syn_cookie_master_key(Some(syn_cookie_key()));
    peer.set_syn_cookie_full_epoch_for_test(41);

    let syn = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        49152,
        443,
        TCP_SYN,
    );
    let cookie_isn = syn_cookie_codec().mint_isn(
        SynCookieTuple::from_packet(&syn),
        syn_cookie_zone_tag("trust"),
        41,
        syn.tcp_mss,
    );

    let mut ack = syn.clone();
    ack.tcp_flags = TCP_ACK;
    ack.tcp_seq = 2;
    ack.tcp_ack = cookie_isn.wrapping_add(1);

    assert_eq!(
        peer.validate_syn_cookie_ack_on_session_miss("trust", 7, &ack, 128 * NS, 128),
        SynCookieAckVerdict::Validated,
        "HA backup must accept a peer-minted cookie without a local flood window"
    );
    assert_eq!(peer.syn_cookie_validated_len(), 1);
}

#[test]
fn syn_cookie_ack_validates_on_peer_one_epoch_behind_active() {
    let mut profile = ScreenProfile::default();
    profile.syn_flood_threshold = 1;
    profile.syn_cookie = true;

    let mut standby = make_state("trust", profile);
    standby.update_syn_cookie_master_key(Some(syn_cookie_key()));
    standby.set_syn_cookie_full_epoch_for_test(40);

    let syn = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        49152,
        443,
        TCP_SYN,
    );
    let active_cookie = syn_cookie_codec().mint_isn(
        SynCookieTuple::from_packet(&syn),
        syn_cookie_zone_tag("trust"),
        41,
        syn.tcp_mss,
    );

    let mut ack = syn.clone();
    ack.tcp_flags = TCP_ACK;
    ack.tcp_seq = 2;
    ack.tcp_ack = active_cookie.wrapping_add(1);

    assert_eq!(
        standby.validate_syn_cookie_ack_on_session_miss("trust", 7, &ack, 128 * NS, 128),
        SynCookieAckVerdict::Validated,
        "standby one epoch behind must accept cookies minted by the former active"
    );
    assert_eq!(standby.syn_cookie_validated_len(), 1);
}

#[test]
fn syn_cookie_invalid_ack_without_active_window_remains_not_applicable() {
    let mut profile = ScreenProfile::default();
    profile.syn_flood_threshold = 1;
    profile.syn_cookie = true;

    let mut peer = make_state("trust", profile);
    peer.update_syn_cookie_master_key(Some(syn_cookie_key()));
    peer.set_syn_cookie_full_epoch_for_test(41);

    let mut ack = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        49152,
        443,
        TCP_ACK,
    );
    ack.tcp_seq = 2;
    ack.tcp_ack = 0xdead_beefu32;

    assert_eq!(
        peer.validate_syn_cookie_ack_on_session_miss("trust", 7, &ack, 128 * NS, 128),
        SynCookieAckVerdict::NotApplicable,
        "inactive peers only consume ACKs that validate against the shared key"
    );
    assert_eq!(peer.syn_cookie_validated_len(), 0);
}

#[test]
fn syn_cookie_standby_ack_prefilter_skips_implausible_epoch_bits() {
    let mut profile = ScreenProfile::default();
    profile.syn_flood_threshold = 1;
    profile.syn_cookie = true;

    let mut peer = make_state("trust", profile);
    peer.update_syn_cookie_master_key(Some(syn_cookie_key()));
    peer.set_syn_cookie_full_epoch_for_test(40);

    let mut ack = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        49152,
        443,
        TCP_ACK,
    );
    let implausible_cookie =
        ((45u32 & SYN_COOKIE_EPOCH_MASK) << SYN_COOKIE_EPOCH_SHIFT) | 0x00ff_eeaa;
    ack.tcp_ack = implausible_cookie.wrapping_add(1);

    assert_eq!(
        peer.validate_syn_cookie_ack_on_session_miss("trust", 7, &ack, 128 * NS, 128),
        SynCookieAckVerdict::NotApplicable,
        "inactive peers should reject ACKs outside the epoch window before MAC work"
    );
    assert!(
        peer.syn_cookie_standby_ack_untouched("trust"),
        "wire-epoch prefilter must not spend standby validation budget"
    );
}

#[test]
fn syn_cookie_standby_ack_validation_is_rate_limited() {
    let mut profile = ScreenProfile::default();
    profile.syn_flood_threshold = 1;
    profile.syn_cookie = true;

    let mut peer = make_state("trust", profile);
    peer.update_syn_cookie_master_key(Some(syn_cookie_key()));
    peer.set_syn_cookie_full_epoch_for_test(41);

    let syn = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        49152,
        443,
        TCP_SYN,
    );
    let mut bad_ack = syn.clone();
    bad_ack.tcp_flags = TCP_ACK;
    bad_ack.tcp_seq = 2;
    bad_ack.tcp_ack =
        (((41u32 & SYN_COOKIE_EPOCH_MASK) << SYN_COOKIE_EPOCH_SHIFT) | 0x1234).wrapping_add(1);

    // #3607: the standby budget is now a monotonic-ns TOKEN BUCKET. Drain the
    // whole budget at ONE instant — a bogus-but-plausible ACK still spends a
    // SipHash (then fails the crypto check → NotApplicable), so every event
    // consumes a token.
    let base_ns = 128 * NS;
    for _ in 0..SYN_COOKIE_STANDBY_ACK_VALIDATION_RATE_LIMIT_PER_SEC {
        assert_eq!(
            peer.validate_syn_cookie_ack_on_session_miss("trust", 7, &bad_ack, base_ns, 128),
            SynCookieAckVerdict::NotApplicable
        );
    }
    // The instantaneous budget is fully spent.
    assert_eq!(peer.syn_cookie_standby_ack_available("trust"), 0);

    let valid_cookie = syn_cookie_codec().mint_isn(
        SynCookieTuple::from_packet(&syn),
        syn_cookie_zone_tag("trust"),
        41,
        syn.tcp_mss,
    );
    let mut valid_ack = syn.clone();
    valid_ack.tcp_flags = TCP_ACK;
    valid_ack.tcp_seq = 3;
    valid_ack.tcp_ack = valid_cookie.wrapping_add(1);

    // A valid ACK at the same instant is still capped (budget exhausted): the
    // standby guard refuses to spend more SipHash beyond the per-second budget.
    assert_eq!(
        peer.validate_syn_cookie_ack_on_session_miss("trust", 7, &valid_ack, base_ns, 128),
        SynCookieAckVerdict::NotApplicable,
        "standby validation budget should cap SipHash work at this instant"
    );
    assert_eq!(peer.syn_cookie_validated_len(), 0);

    // #2937 RETAINED: a sub-millisecond straddle (+1us) accrues a negligible
    // refill, so the attacker cannot double its plausible-ACK allowance by
    // bursting across a boundary — the valid ACK stays capped.
    assert_eq!(
        peer.validate_syn_cookie_ack_on_session_miss("trust", 7, &valid_ack, base_ns + 1_000, 128),
        SynCookieAckVerdict::NotApplicable,
        "a sub-ms micro-burst must not refill the standby budget"
    );
    assert_eq!(peer.syn_cookie_validated_len(), 0);

    // #3607: after a full second the bucket refills at its configured rate, so
    // a legitimate returning client (e.g. right after a failover) is NO LONGER
    // suppressed — the old sliding window kept it capped until a fully idle
    // second. The valid ACK now validates.
    assert_eq!(
        peer.validate_syn_cookie_ack_on_session_miss("trust", 7, &valid_ack, base_ns + NS, 129),
        SynCookieAckVerdict::Validated,
        "the standby budget refills at its configured rate (#3607)"
    );
    assert_eq!(peer.syn_cookie_validated_len(), 1);
}

#[test]
fn syn_cookie_ack_fin_is_invalid_while_cookie_mode_is_active() {
    let mut profile = ScreenProfile::default();
    profile.syn_flood_threshold = 1;
    profile.syn_cookie = true;
    let mut state = make_state("trust", profile);
    state.update_syn_cookie_master_key(Some(syn_cookie_key()));
    let syn = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        49152,
        443,
        TCP_SYN,
    );

    assert_eq!(
        state.check_packet_with_zone_id("trust", 7, &syn, 128),
        ScreenVerdict::Pass
    );
    let challenge = match state.check_packet_with_zone_id("trust", 7, &syn, 128) {
        ScreenVerdict::SynCookieChallenge(challenge) => challenge,
        other => panic!("expected SYN-cookie challenge, got {other:?}"),
    };

    let mut ack_fin = syn.clone();
    ack_fin.tcp_flags = TCP_ACK | TCP_FIN;
    ack_fin.tcp_ack = challenge.cookie_isn.wrapping_add(1);
    assert_eq!(
        state.validate_syn_cookie_ack_on_session_miss("trust", 7, &ack_fin, 128 * NS, 128),
        SynCookieAckVerdict::Invalid
    );
    assert_eq!(state.syn_cookie_validated_len(), 0);
}

#[test]
fn syn_cookie_validated_cache_is_bounded() {
    let mut cache = SynCookieValidatedCache::new(4, 64);
    assert_eq!(cache.capacity(), 4);

    // #9419: distinctness now comes from the DESTINATION port — the key
    // carries no source port at all, so varying `src_port` would insert the
    // same entry 32 times and this cell would measure nothing.
    let mut client = syn_cookie_client();
    for port in 40000..40032 {
        client.dst_port = port;
        cache.insert(Z7, 0, client, 100);
    }

    assert_eq!(cache.len(), 4);
    let mut evicted = syn_cookie_client();
    evicted.dst_port = 40000;
    assert!(!cache.contains_valid(Z7, 0, evicted, 100));
    evicted.dst_port = 40027;
    assert!(!cache.contains_valid(Z7, 0, evicted, 100));

    let mut retained = syn_cookie_client();
    retained.dst_port = 40028;
    assert!(cache.contains_valid(Z7, 0, retained, 100));
    retained.dst_port = 40031;
    assert!(cache.contains_valid(Z7, 0, retained, 100));
}

#[test]
fn syn_cookie_validated_cache_index_is_keyed() {
    let mut left = SynCookieValidatedCache::new(64, 64);
    left.set_hash_keys([0x1111_2222_3333_4444, 0x5555_6666_7777_8888]);
    let mut right = SynCookieValidatedCache::new(64, 64);
    right.set_hash_keys([0x9999_aaaa_bbbb_cccc, 0xdddd_eeee_ffff_0000]);

    let mut client = syn_cookie_client();
    let differs = (0..1024).any(|offset| {
        client.dst_port = 30000 + offset;
        left.debug_set_index(Z7, 0, client) != right.debug_set_index(Z7, 0, client)
    });

    assert!(
        differs,
        "cache slot selection must be keyed rather than attacker-predictable"
    );
}

#[test]
fn syn_cookie_invalid_ack_flood_does_not_grow_validated_cache() {
    let mut profile = ScreenProfile::default();
    profile.syn_flood_threshold = 1;
    profile.syn_cookie = true;
    let mut state = make_state("trust", profile);
    state.update_syn_cookie_master_key(Some(syn_cookie_key()));
    let syn = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        49152,
        443,
        TCP_SYN,
    );

    assert_eq!(
        state.check_packet_with_zone_id("trust", 7, &syn, 128),
        ScreenVerdict::Pass
    );
    assert!(matches!(
        state.check_packet_with_zone_id("trust", 7, &syn, 128),
        ScreenVerdict::SynCookieChallenge(_)
    ));

    for offset in 0..1024 {
        let mut ack = syn.clone();
        ack.tcp_flags = TCP_ACK;
        ack.src_port = 30000 + offset;
        ack.tcp_ack = 0xdead_0000u32.wrapping_add(offset as u32);
        assert_eq!(
            state.validate_syn_cookie_ack_on_session_miss("trust", 7, &ack, 128 * NS, 128),
            SynCookieAckVerdict::Invalid
        );
    }

    assert_eq!(state.syn_cookie_validated_len(), 0);
}

#[test]
fn syn_cookie_master_key_rotation_clears_validated_cache() {
    let mut profile = ScreenProfile::default();
    profile.syn_flood_threshold = 1;
    profile.syn_cookie = true;
    let mut state = make_state("trust", profile);
    state.update_syn_cookie_master_key(Some(syn_cookie_key()));
    let syn = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        49152,
        443,
        TCP_SYN,
    );

    assert_eq!(
        state.check_packet_with_zone_id("trust", 7, &syn, 128),
        ScreenVerdict::Pass
    );
    let challenge = match state.check_packet_with_zone_id("trust", 7, &syn, 128) {
        ScreenVerdict::SynCookieChallenge(challenge) => challenge,
        other => panic!("expected SYN-cookie challenge, got {other:?}"),
    };
    let mut ack = syn.clone();
    ack.tcp_flags = TCP_ACK;
    ack.tcp_ack = challenge.cookie_isn.wrapping_add(1);
    assert_eq!(
        state.validate_syn_cookie_ack_on_session_miss("trust", 7, &ack, 128 * NS, 128),
        SynCookieAckVerdict::Validated
    );
    assert_eq!(state.syn_cookie_validated_len(), 1);

    state.update_syn_cookie_master_key(None);

    assert_eq!(state.syn_cookie_validated_len(), 0);
}

// #2446: helper — drive a zone through a SYN-flood crossing into cookie
// mode, then validate a returning ACK so a validated-cache entry is
// installed for `tuple`. Returns the validated SYN-cookie 4-tuple.
fn install_validated_syn_cookie_entry(state: &mut ScreenState, zone: &str, zone_id: u16) {
    let syn = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        49152,
        443,
        TCP_SYN,
    );
    // First SYN passes (counter at threshold-1), second crosses the
    // threshold and mints a challenge.
    assert_eq!(
        state.check_packet_with_zone_id(zone, zone_id, &syn, 128),
        ScreenVerdict::Pass
    );
    let challenge = match state.check_packet_with_zone_id(zone, zone_id, &syn, 128) {
        ScreenVerdict::SynCookieChallenge(challenge) => challenge,
        other => panic!("expected SYN-cookie challenge, got {other:?}"),
    };
    let mut ack = syn.clone();
    ack.tcp_flags = TCP_ACK;
    ack.tcp_ack = challenge.cookie_isn.wrapping_add(1);
    assert_eq!(
        state.validate_syn_cookie_ack_on_session_miss(zone, zone_id, &ack, 128 * NS, 128),
        SynCookieAckVerdict::Validated
    );
    assert_eq!(state.syn_cookie_validated_len(), 1);
}

// #2446 fail-on-revert: a tuple validated under one SYN-cookie profile
// generation must NOT be consumable as a hit after the zone's
// SYN-cookie-relevant profile changes (same master key). Without the
// per-zone profile generation in the cache key (or without the gen bump
// in `update_profiles`) the validated entry is consumed as a hit and
// bypasses the NEW profile's SYN-flood counter — RED.
#[test]
fn syn_cookie_validated_cache_invalidated_on_profile_change() {
    let mut profile = ScreenProfile::default();
    profile.syn_flood_threshold = 1;
    profile.syn_cookie = true;
    let mut state = make_state("trust", profile);
    state.update_syn_cookie_master_key(Some(syn_cookie_key()));

    install_validated_syn_cookie_entry(&mut state, "trust", 7);

    // Change a SYN-cookie-relevant field (the SYN-flood threshold) while
    // the master key stays stable. This bumps the zone's profile
    // generation, so the cached validation is from an older generation.
    let mut changed = ScreenProfile::default();
    changed.syn_flood_threshold = 5; // was 1
    changed.syn_cookie = true;
    let mut profiles = FxHashMap::default();
    profiles.insert("trust".to_string(), changed);
    state.update_profiles(profiles);

    // The same SYN that produced the validated ACK now arrives. Under the
    // bug it would be a validated-cache HIT (SynCookieBypass) and skip the
    // new profile's SYN-flood counter. With the fix it is a MISS, so the
    // packet is counted as a normal SYN under the new threshold (Pass at
    // count 1, below the new threshold of 5).
    let syn = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        49152,
        443,
        TCP_SYN,
    );
    // Within the entry's TTL (insert at 128, 64s TTL → expires 192) so the
    // only reason this is a MISS is the bumped generation, not expiry.
    assert_eq!(
        state.check_packet_with_zone_id("trust", 7, &syn, 150),
        ScreenVerdict::Pass,
        "validated entry from the old profile generation must NOT bypass \
         the new profile's SYN-flood counter"
    );
}

// #2446: disable then re-enable SYN-cookie on a zone (master key stable)
// invalidates a validation that occurred before the toggle.
#[test]
fn syn_cookie_validated_cache_invalidated_on_disable_reenable() {
    let mut profile = ScreenProfile::default();
    profile.syn_flood_threshold = 1;
    profile.syn_cookie = true;
    let mut state = make_state("trust", profile.clone());
    state.update_syn_cookie_master_key(Some(syn_cookie_key()));

    install_validated_syn_cookie_entry(&mut state, "trust", 7);

    // Disable syn_cookie (gen bump), then re-enable it (gen bump again):
    // two SYN-cookie-relevant changes, so the pre-toggle validation is
    // stale.
    let mut disabled = profile.clone();
    disabled.syn_cookie = false;
    let mut profiles = FxHashMap::default();
    profiles.insert("trust".to_string(), disabled);
    state.update_profiles(profiles);

    let mut profiles = FxHashMap::default();
    profiles.insert("trust".to_string(), profile);
    state.update_profiles(profiles);

    let syn = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        49152,
        443,
        TCP_SYN,
    );
    // Within the entry's TTL (insert at 128, 64s TTL → expires 192) so the
    // only reason this is not a HIT is the stale generation. A stale HIT
    // would return SynCookieBypass and skip the SYN-flood counter; with the
    // fix it is a MISS, counted as the first SYN under threshold 1 → Pass.
    assert_eq!(
        state.check_packet_with_zone_id("trust", 7, &syn, 150),
        ScreenVerdict::Pass,
        "re-enabled cookie mode must NOT honour a stale pre-disable \
         validation (a stale HIT would return SynCookieBypass)"
    );
}

// #2446 no-regression: within the SAME profile generation a validated
// tuple is still a hit (the cache works normally). An UNRELATED profile
// edit (a stateless screen toggle) does NOT bump the generation, so the
// validation survives.
#[test]
fn syn_cookie_validated_cache_hit_within_same_generation() {
    let mut profile = ScreenProfile::default();
    profile.syn_flood_threshold = 1;
    profile.syn_cookie = true;
    let mut state = make_state("trust", profile.clone());
    state.update_syn_cookie_master_key(Some(syn_cookie_key()));

    install_validated_syn_cookie_entry(&mut state, "trust", 7);

    // An unrelated profile change (enable the teardrop screen) leaves the
    // SYN-cookie signature unchanged, so the generation is stable and the
    // validation remains consumable.
    let mut unrelated = profile;
    unrelated.teardrop = true;
    let mut profiles = FxHashMap::default();
    profiles.insert("trust".to_string(), unrelated);
    state.update_profiles(profiles);

    // The matching SYN is a validated-cache HIT → SynCookieBypass (it does
    // NOT count toward the SYN-flood threshold), proving the cache still
    // works normally within a generation.
    let syn = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        49152,
        443,
        TCP_SYN,
    );
    // Within the entry's TTL (insert at 128, 64s TTL → expires 192).
    assert_eq!(
        state.check_packet_with_zone_id("trust", 7, &syn, 150),
        ScreenVerdict::SynCookieBypass,
        "an unrelated profile edit must not invalidate a validated entry"
    );
    // #9419: the hit does not consume the entry — it remains whitelisted
    // for the rest of its TTL under the same generation.
    assert_eq!(state.syn_cookie_validated_len(), 1);
}

// #2446 unit-level: the cache treats two generations as distinct keys —
// an entry inserted under gen N is a miss when consumed under gen N+1,
// and a hit when consumed under gen N.
#[test]
fn syn_cookie_validated_cache_generation_is_keyed() {
    let mut cache = SynCookieValidatedCache::new(64, 64);
    let client = syn_cookie_client();

    cache.insert(Z7, 1, client, 100);
    assert!(
        !cache.contains_valid(Z7, 2, client, 100),
        "an entry from a stale generation must be a miss under the new gen"
    );

    assert!(
        cache.contains_valid(Z7, 1, client, 100),
        "an entry looked up under its own generation must still be a hit"
    );
}

#[test]
fn update_profiles_prepopulates_syn_cookie_active_state() {
    let mut profile = ScreenProfile::default();
    profile.syn_flood_threshold = 1;
    profile.syn_cookie = true;
    let mut state = make_state("trust", profile.clone());
    assert_eq!(state.syn_cookie_active_zone_count(), 1);

    let mut profiles = FxHashMap::default();
    profiles.insert("trust".to_string(), profile.clone());
    profiles.insert("untrust".to_string(), profile);
    state.update_profiles(profiles);
    assert_eq!(state.syn_cookie_active_zone_count(), 2);

    state.update_profiles(FxHashMap::default());
    assert_eq!(state.syn_cookie_active_zone_count(), 0);
}

#[test]
fn syn_cookie_validated_cache_refresh_extends_ttl() {
    let mut cache = SynCookieValidatedCache::new(4, 10);
    let client_refreshed = syn_cookie_client();
    let mut client_old = syn_cookie_client();
    client_old.dst_port += 1;
    cache.insert(Z7, 0, client_refreshed, 100);
    cache.insert(Z7, 0, client_old, 100);
    cache.insert(Z7, 0, client_refreshed, 109);
    assert!(!cache.contains_valid(Z7, 0, client_old, 110));
    assert!(cache.contains_valid(Z7, 0, client_refreshed, 110));
}

#[test]
fn syn_cookie_validated_cache_expires_on_ttl_boundary() {
    let mut cache = SynCookieValidatedCache::new(4, SynCookieCodec::EPOCH_SECS);
    let client = syn_cookie_client();

    cache.insert(Z7, 0, client, 128);
    assert!(
        cache.contains_valid(Z7, 0, client, 191),
        "entry should remain valid until just before the 64s TTL boundary"
    );

    assert!(
        !cache.contains_valid(Z7, 0, client, 192),
        "entry expires at insertion time + one cookie epoch"
    );
    // #9419: the TTL is what BOUNDS the whitelist now that a hit no longer
    // consumes the entry — an expired lookup must also reclaim the way.
    assert_eq!(
        cache.len(),
        0,
        "an expired entry is reclaimed on the lookup that observes its expiry"
    );
}

#[test]
fn syn_cookie_ack_validation_accepts_previous_epoch_after_rotation() {
    let mut profile = ScreenProfile::default();
    profile.syn_flood_threshold = 1;
    profile.syn_cookie = true;
    let mut state = make_state("trust", profile);
    state.update_syn_cookie_master_key(Some(syn_cookie_key()));
    state.set_syn_cookie_full_epoch_for_test(1);
    let syn = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        49152,
        443,
        TCP_SYN,
    );

    assert_eq!(
        state.check_packet_with_zone_id("trust", 7, &syn, 127),
        ScreenVerdict::Pass
    );
    let challenge = match state.check_packet_with_zone_id("trust", 7, &syn, 127) {
        ScreenVerdict::SynCookieChallenge(challenge) => challenge,
        other => panic!("expected SYN-cookie challenge, got {other:?}"),
    };

    let mut ack = syn.clone();
    ack.tcp_flags = TCP_ACK;
    ack.tcp_ack = challenge.cookie_isn.wrapping_add(1);
    state.set_syn_cookie_full_epoch_for_test(2);
    assert_eq!(
        state.validate_syn_cookie_ack_on_session_miss("trust", 7, &ack, 128 * NS, 128),
        SynCookieAckVerdict::Validated,
        "ACK after the epoch tick must validate against the previous full epoch"
    );
    assert_eq!(
        state.check_packet_with_zone_id("trust", 7, &syn, 128),
        ScreenVerdict::SynCookieBypass
    );
}

// ================================================================
// Profile update
// ================================================================

#[test]
fn update_profiles_clears_stale_counters() {
    let mut profile = ScreenProfile::default();
    profile.icmp_flood_threshold = 2;
    let mut state = make_state("trust", profile);
    let pkt = icmp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        84,
    );
    // Fill up counter
    state.check_packet("trust", &pkt, 100);
    state.check_packet("trust", &pkt, 100);

    // Update profiles for a different zone — trust counter should be removed
    let mut new_profiles = FxHashMap::default();
    let mut new_profile = ScreenProfile::default();
    new_profile.icmp_flood_threshold = 2;
    new_profiles.insert("untrust".to_string(), new_profile);
    state.update_profiles(new_profiles);

    // trust zone no longer has a profile — all packets pass
    assert_eq!(state.check_packet("trust", &pkt, 100), ScreenVerdict::Pass);
}

// ================================================================
// extract_screen_info
// ================================================================

#[test]
fn extract_info_from_ipv4_frame() {
    // Build a minimal IPv4 frame: 14 bytes Ethernet + 20 bytes IP header
    let mut frame = vec![0u8; 34];
    // IP header at offset 14
    frame[14] = 0x45; // version=4, ihl=5
    frame[16] = 0x00; // total_len high
    frame[17] = 20; // total_len low = 20
    frame[20] = 0x20; // flags=MF, offset=0
    frame[21] = 0x00;

    let info = extract_screen_info(
        &frame,
        libc::AF_INET as u8,
        PROTO_TCP,
        TCP_SYN,
        34,
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        1234,
        80,
        14,
    )
    .expect("valid IPv4 frame parses");

    assert_eq!(info.ip_ihl, 5);
    assert_eq!(info.ip_total_len, 20);
    assert!(info.is_fragment); // MF bit set
    assert_eq!(info.protocol, PROTO_TCP);
}

// ================================================================
// Per-IP session limits — #2134: enforcement + lifecycle now live in
// `session::SessionTable` (count maintained at the install/remove sinks,
// checked at the new-flow decision in poll_descriptor). The screen stage
// no longer evaluates the per-IP count. End-to-end enforcement, the
// established-flow no-self-drop regression, evict-on-zero (#2128), the
// HA promote/demote count sites, the differential invariant, and
// clear-on-disable are covered by `session/tests.rs`
// (`session_limit_*`). The obsolete ScreenState-resident tests that
// drove the now-retired `session_created`/`session_expired` mutators
// were removed here.
// ================================================================

// ================================================================
// Port scan detection
// ================================================================

// NOTE (#2210): scan/sweep detection moved OFF the per-packet
// `check_packet` pre-session stage and onto the NEW-FLOW / session-MISS
// hook `scan_sweep_drop_on_new_flow`. These tests drive that hook (the
// caller in `poll_descriptor` only reaches it on a session miss, which is
// what gives established flows their immunity). `ZID` is an arbitrary but
// fixed zone id; the per-zone keying is exercised in
// `screen::scan::scan_tests` and `scan_sweep_per_zone_no_cross_count`.
const ZID: u16 = 7;

/// Junos default scan/sweep detection WINDOW (microseconds) for these tests
/// (#4114). The detection COUNT is the fixed `super::scan::SCAN_DETECT_COUNT`.
const SWEEP_W: u32 = 5_000;

/// #4379: the window-aware cleanup reap floor is the LONGEST configured
/// detection window across ALL live profiles, computed independently per check
/// (port-scan vs ip-sweep). This locks the wiring that feeds
/// `PortScanTracker::cleanup` / `IpSweepTracker::cleanup` their reap floor so a
/// slow scan within an operator window > 1s is not reaped early (the #4379
/// evasion). A disabled check (window 0) contributes nothing.
#[test]
fn scan_cleanup_floors_are_max_configured_window() {
    let mut state = ScreenState::new();
    let mut profiles = FxHashMap::default();
    // zone "a": port-scan 5s, ip-sweep 2s.
    let mut a = ScreenProfile::default();
    a.port_scan_threshold = 5_000_000;
    a.ip_sweep_threshold = 2_000_000;
    profiles.insert("a".to_string(), a);
    // zone "b": port-scan 1s, ip-sweep 9s. The floor must be the MAX across
    // zones per check: port=5s (from a), sweep=9s (from b).
    let mut b = ScreenProfile::default();
    b.port_scan_threshold = 1_000_000;
    b.ip_sweep_threshold = 9_000_000;
    profiles.insert("b".to_string(), b);
    // zone "c": both disabled — must not lower the max.
    profiles.insert("c".to_string(), ScreenProfile::default());
    state.update_profiles(profiles);

    let (port_floor, sweep_floor) = state.scan_cleanup_floors();
    assert_eq!(port_floor, 5_000_000, "port floor = max port_scan window");
    assert_eq!(sweep_floor, 9_000_000, "sweep floor = max ip_sweep window");

    // No profiles at all → both floors 0 (cleanup then reclaims idle state).
    state.update_profiles(FxHashMap::default());
    assert_eq!(state.scan_cleanup_floors(), (0, 0));
}

#[test]
fn port_scan_detected() {
    let mut profile = ScreenProfile::default();
    profile.port_scan_threshold = SWEEP_W; // microsecond window (#4114)
    let mut state = make_state("trust", profile);

    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1));
    let detect = super::scan::SCAN_DETECT_COUNT as u16;
    let now = 1_000_000u64;

    // The first SCAN_DETECT_COUNT-1 unique ports within the window pass.
    for p in 0..(detect - 1) {
        let pkt = tcp_pkt(src, dst, 1234, 8000 + p, TCP_SYN);
        assert_eq!(
            state.scan_sweep_drop_on_new_flow("trust", ZID, &pkt, now),
            None,
            "port {} should pass",
            8000 + p,
        );
    }

    // The SCAN_DETECT_COUNT-th unique port within the window triggers port scan.
    let pkt = tcp_pkt(src, dst, 1234, 8999, TCP_SYN);
    assert_eq!(
        state.scan_sweep_drop_on_new_flow("trust", ZID, &pkt, now),
        Some("port-scan")
    );
}

#[test]
fn port_scan_resets_on_window_expiry() {
    let mut profile = ScreenProfile::default();
    profile.port_scan_threshold = SWEEP_W;
    let mut state = make_state("trust", profile);

    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1));
    let detect = super::scan::SCAN_DETECT_COUNT as u16;
    let now = 1_000_000u64;

    // Fill the window: the first SCAN_DETECT_COUNT-1 ports pass, the next fires.
    for p in 0..(detect - 1) {
        let pkt = tcp_pkt(src, dst, 1234, 8000 + p, TCP_SYN);
        assert_eq!(
            state.scan_sweep_drop_on_new_flow("trust", ZID, &pkt, now),
            None
        );
    }
    let pkt_fire = tcp_pkt(src, dst, 1234, 8999, TCP_SYN);
    assert_eq!(
        state.scan_sweep_drop_on_new_flow("trust", ZID, &pkt_fire, now),
        Some("port-scan")
    );

    // After the microsecond window expires the count resets and a single new
    // port passes again.
    let pkt_after = tcp_pkt(src, dst, 1234, 7000, TCP_SYN);
    assert_eq!(
        state.scan_sweep_drop_on_new_flow("trust", ZID, &pkt_after, now + u64::from(SWEEP_W) + 1),
        None
    );
}

#[test]
fn port_scan_only_on_syn() {
    let mut profile = ScreenProfile::default();
    profile.port_scan_threshold = SWEEP_W;
    let mut state = make_state("trust", profile);

    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1));

    // ACK packets (a session-miss ACK still reaches the hook, but port-scan is
    // SYN-only) never trigger port scan, no matter how many distinct ports.
    // (IP-sweep on a miss ACK is a separate, intended count — its window is 0
    // here so it never fires.)
    for port in 1000..1000 + super::scan::SCAN_DETECT_COUNT as u16 + 2 {
        let pkt = tcp_pkt(src, dst, 1234, port, TCP_ACK);
        assert_eq!(
            state.scan_sweep_drop_on_new_flow("trust", ZID, &pkt, 1_000_000),
            None
        );
    }
}

// ================================================================
// IP sweep detection
// ================================================================

#[test]
fn ip_sweep_detected() {
    let mut profile = ScreenProfile::default();
    profile.ip_sweep_threshold = SWEEP_W;
    let mut state = make_state("trust", profile);

    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    let detect = super::scan::SCAN_DETECT_COUNT as u32;
    let now = 1_000_000u64;

    // The first SCAN_DETECT_COUNT-1 unique destinations within the window pass.
    for i in 0..(detect - 1) {
        let dst = IpAddr::V4(Ipv4Addr::from(0x0a00_0200u32 + i)); // 10.0.2.x
        let pkt = tcp_pkt(src, dst, 1234, 80, TCP_SYN);
        assert_eq!(
            state.scan_sweep_drop_on_new_flow("trust", ZID, &pkt, now),
            None
        );
    }

    // The SCAN_DETECT_COUNT-th unique destination triggers IP sweep.
    let dst = IpAddr::V4(Ipv4Addr::from(0x0a00_02ffu32));
    let pkt = tcp_pkt(src, dst, 1234, 80, TCP_SYN);
    assert_eq!(
        state.scan_sweep_drop_on_new_flow("trust", ZID, &pkt, now),
        Some("ip-sweep")
    );
}

#[test]
fn ip_sweep_resets_on_window_expiry() {
    let mut profile = ScreenProfile::default();
    profile.ip_sweep_threshold = SWEEP_W;
    let mut state = make_state("trust", profile);

    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    let detect = super::scan::SCAN_DETECT_COUNT as u32;
    let now = 1_000_000u64;

    // Fill the window: the first SCAN_DETECT_COUNT-1 destinations pass.
    for i in 0..(detect - 1) {
        let dst = IpAddr::V4(Ipv4Addr::from(0x0a00_0200u32 + i));
        let pkt = tcp_pkt(src, dst, 1234, 80, TCP_SYN);
        assert_eq!(
            state.scan_sweep_drop_on_new_flow("trust", ZID, &pkt, now),
            None
        );
    }

    // The SCAN_DETECT_COUNT-th triggers.
    let dst_fire = IpAddr::V4(Ipv4Addr::from(0x0a00_02ffu32));
    let pkt_fire = tcp_pkt(src, dst_fire, 1234, 80, TCP_SYN);
    assert_eq!(
        state.scan_sweep_drop_on_new_flow("trust", ZID, &pkt_fire, now),
        Some("ip-sweep")
    );

    // After the microsecond window expires the count resets and a single new
    // destination passes again.
    let dst_after = IpAddr::V4(Ipv4Addr::from(0x0a00_0300u32));
    let pkt_after = tcp_pkt(src, dst_after, 1234, 80, TCP_SYN);
    assert_eq!(
        state.scan_sweep_drop_on_new_flow("trust", ZID, &pkt_after, now + u64::from(SWEEP_W) + 1),
        None
    );
}

#[test]
fn ip_sweep_works_with_udp() {
    let mut profile = ScreenProfile::default();
    profile.ip_sweep_threshold = SWEEP_W;
    let mut state = make_state("trust", profile);

    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    let detect = super::scan::SCAN_DETECT_COUNT as u32;
    let now = 1_000_000u64;

    for i in 0..(detect - 1) {
        let dst = IpAddr::V4(Ipv4Addr::from(0x0a00_0200u32 + i));
        let mut pkt = udp_pkt(src, dst);
        pkt.dst_ip = dst;
        assert_eq!(
            state.scan_sweep_drop_on_new_flow("trust", ZID, &pkt, now),
            None
        );
    }

    // The SCAN_DETECT_COUNT-th triggers.
    let dst_fire = IpAddr::V4(Ipv4Addr::from(0x0a00_02ffu32));
    let mut pkt_fire = udp_pkt(src, dst_fire);
    pkt_fire.dst_ip = dst_fire;
    assert_eq!(
        state.scan_sweep_drop_on_new_flow("trust", ZID, &pkt_fire, now),
        Some("ip-sweep")
    );
}

// ================================================================
// #2210: established (session-hit) traffic must NOT count toward sweep.
// #2209: per-zone keying + bounded state + no per-packet profile clone.
// ================================================================

/// #2210 fail-on-revert: the per-packet `check_packet` pre-session stage
/// must NOT touch the sweep/scan trackers. If the scan/sweep mutation were
/// (re)added back to `check_packet` (the pre-#2210 bug), this would drop on
/// the 3rd packet. Established flows are session HITS in production and
/// never reach the miss hook, so the only way they could inflate the sweep
/// counter is via `check_packet` — which this asserts they do not.
#[test]
fn established_traffic_does_not_count_toward_sweep_via_check_packet() {
    let mut profile = ScreenProfile::default();
    profile.ip_sweep_threshold = SWEEP_W;
    profile.port_scan_threshold = SWEEP_W;
    let mut state = make_state("trust", profile);

    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    let detect = super::scan::SCAN_DETECT_COUNT as u32;
    let now = 1_000_000u64;
    // A high-fan-out established client: ACKs to many destinations on many
    // ports. None of these are SYNs; in production they would be session
    // hits. `check_packet` must pass every one — sweep is NOT evaluated
    // here anymore.
    for i in 1..=10u8 {
        let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 2, i));
        let pkt = tcp_pkt(src, dst, 1234, 1000 + i as u16, TCP_ACK);
        assert_eq!(
            state.check_packet("trust", &pkt, 100),
            ScreenVerdict::Pass,
            "established ACK to dst .{} must not count toward sweep on the pre-session stage",
            i
        );
    }
    // And a genuine new-flow sweep still fires on the miss hook: the first
    // SCAN_DETECT_COUNT-1 distinct destinations pass, the next fires.
    for i in 0..(detect - 1) {
        let dst = IpAddr::V4(Ipv4Addr::from(0x0a00_0300u32 + i)); // 10.0.3.x
        let pkt = tcp_pkt(src, dst, 1234, 80, TCP_SYN);
        assert_eq!(
            state.scan_sweep_drop_on_new_flow("trust", ZID, &pkt, now),
            None
        );
    }
    let dst = IpAddr::V4(Ipv4Addr::from(0x0a00_03ffu32));
    let pkt = tcp_pkt(src, dst, 1234, 80, TCP_SYN);
    assert_eq!(
        state.scan_sweep_drop_on_new_flow("trust", ZID, &pkt, now),
        Some("ip-sweep")
    );
}

/// #2209 fail-on-revert: scan/sweep state is per-zone. The SAME source
/// sweeping zone A must not push zone B over its threshold. A global
/// tracker (the pre-#2209 bug) would have zone B already at zone A's count.
#[test]
fn scan_sweep_per_zone_no_cross_count() {
    let mut state = ScreenState::new();
    let mut profiles = FxHashMap::default();
    let mut a = ScreenProfile::default();
    a.ip_sweep_threshold = SWEEP_W;
    let mut b = ScreenProfile::default();
    b.ip_sweep_threshold = SWEEP_W;
    profiles.insert("zoneA".to_string(), a);
    profiles.insert("zoneB".to_string(), b);
    state.update_profiles(profiles);

    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    let detect = super::scan::SCAN_DETECT_COUNT as u32;
    let now = 1_000_000u64;
    // Source sweeps zoneA: SCAN_DETECT_COUNT-1 unique dsts (no drop yet).
    for i in 0..(detect - 1) {
        let dst = IpAddr::V4(Ipv4Addr::from(0x0a00_0200u32 + i));
        let pkt = tcp_pkt(src, dst, 1234, 80, TCP_SYN);
        assert_eq!(
            state.scan_sweep_drop_on_new_flow("zoneA", 1, &pkt, now),
            None
        );
    }
    // Same source in zoneB starts fresh — the same count still passes.
    for i in 0..(detect - 1) {
        let dst = IpAddr::V4(Ipv4Addr::from(0x0a00_0900u32 + i));
        let pkt = tcp_pkt(src, dst, 1234, 80, TCP_SYN);
        assert_eq!(
            state.scan_sweep_drop_on_new_flow("zoneB", 2, &pkt, now),
            None,
            "zoneB must not inherit zoneA's sweep history for the same source",
        );
    }
    // zoneB's SCAN_DETECT_COUNT-th unique dst crosses zoneB's own count.
    let dst = IpAddr::V4(Ipv4Addr::from(0x0a00_09ffu32));
    let pkt = tcp_pkt(src, dst, 1234, 80, TCP_SYN);
    assert_eq!(
        state.scan_sweep_drop_on_new_flow("zoneB", 2, &pkt, now),
        Some("ip-sweep")
    );
}

/// #2209 fail-on-revert: a per-packet profile CLONE on the screen hot path
/// would defeat the perf fix. `ScreenProfile` is not `Copy` and the
/// production `check_packet_with_zone_id` borrows it. We assert the type is
/// NOT `Copy` (so an accidental `Clone`-by-value reintroduction is a visible
/// `.clone()` in review) and exercise the borrow-only path heavily to prove
/// it compiles and runs without a per-call clone. (A `Copy` profile would
/// silently hide a per-packet copy; keeping it non-Copy keeps the cost
/// auditable.)
#[test]
fn screen_profile_is_not_copy_so_per_packet_copies_stay_auditable() {
    // REAL negative-Copy guard (#2227 MINOR-3): autoref specialization.
    // `IsCopy::is_copy` (the inherent method on the `Witness<T>` wrapper) is
    // selected ONLY when `T: Copy`; otherwise method resolution autorefs to
    // the `NotCopy` trait's `is_copy(&self)`. So the returned flag is `true`
    // iff `ScreenProfile: Copy`. A test (not just a compile gate) lets this
    // FAIL-ON-REVERT loudly if someone makes `ScreenProfile` `Copy` — which
    // would silently hide a per-packet copy on the screen hot path.
    struct Witness<T>(core::marker::PhantomData<T>);
    trait NotCopy {
        fn is_copy(&self) -> bool {
            false
        }
    }
    impl<T> NotCopy for Witness<T> {}
    impl<T: Copy> Witness<T> {
        fn is_copy(&self) -> bool {
            true
        }
    }
    assert!(
        !Witness::<ScreenProfile>(core::marker::PhantomData).is_copy(),
        "ScreenProfile must NOT be Copy — a Copy profile silently hides a \
         per-packet copy on the screen hot path (#2209 perf invariant)"
    );
    // Sanity: the witness reports `true` for a genuinely-Copy type, proving
    // the negative assertion above is discriminating (not vacuously false).
    assert!(
        Witness::<u32>(core::marker::PhantomData).is_copy(),
        "witness must detect a Copy type"
    );

    // Drive the borrow-only hot path many times; this would not compile if
    // the body still required a `self.profiles.get(zone).clone()` and we had
    // removed Clone — and it documents the no-clone invariant.
    let mut profile = ScreenProfile::default();
    profile.land = true;
    let mut state = make_state("trust", profile);
    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1));
    for _ in 0..1000 {
        let pkt = tcp_pkt(src, dst, 1234, 80, TCP_SYN);
        assert_eq!(state.check_packet("trust", &pkt, 100), ScreenVerdict::Pass);
    }
}

/// #2209 fail-on-revert (bounded + not-fail-open at the `ScreenState`
/// level): a spoofed-source flood through the new-flow hook cannot grow the
/// tracker without bound and never fail-opens the drop.
#[test]
fn scan_sweep_state_bounded_and_records_pressure() {
    let mut profile = ScreenProfile::default();
    // A wide in-range window; each source touches one dst (count 1 < the fixed
    // detection count) so detection never trips — this exercises the memory
    // bound, not the verdict.
    profile.ip_sweep_threshold = 1_000_000;
    let mut state = make_state("trust", profile);

    assert_eq!(state.scan_sweep_skipped_pressure(), 0);
    assert_eq!(state.scan_sweep_evicted_pressure(), 0);
    let cap = super::scan::max_sources_per_zone_for_test();
    // Far more distinct sources than the per-zone cap.
    for i in 0..(cap + 200) {
        let src = IpAddr::V4(Ipv4Addr::from(0x0a00_0000u32 + i as u32));
        let dst = IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1));
        let pkt = tcp_pkt(src, dst, 1234, 80, TCP_SYN);
        // Must never return a drop reason from overflow (no fail-open).
        assert_eq!(
            state.scan_sweep_drop_on_new_flow("trust", ZID, &pkt, 100),
            None
        );
    }
    // #2234/#4418: over-cap sources are now ADMITTED by bounded
    // least-suspicious eviction (the table stays bounded but a fresh source is
    // no longer silently dropped on a full table), recorded as eviction
    // pressure — NOT skip pressure. The single-zone flood never falls back to
    // skip.
    assert!(
        state.scan_sweep_evicted_pressure() >= 200,
        "over-cap sources must record eviction pressure, got {}",
        state.scan_sweep_evicted_pressure()
    );
    assert_eq!(
        state.scan_sweep_skipped_pressure(),
        0,
        "a single-zone source flood must evict, never skip"
    );
}

/// #2234 fail-on-revert at the production `ScreenState` new-flow hook: a
/// genuine port-scanner arriving AFTER a high-cardinality spoofed flood has
/// saturated the per-zone source table must STILL be tracked and dropped.
/// Pre-#2234 the new source was skipped on a full table (returns None
/// forever), so the spoofed flood suppressed detection of the real scanner —
/// a detection-DoS. Reverting the bounded least-suspicious eviction breaks
/// this test.
#[test]
fn fresh_scanner_detected_after_source_flood_at_screen_state() {
    let mut profile = ScreenProfile::default();
    // A wide in-range window; a real fast scan of SCAN_DETECT_COUNT distinct
    // ports within it trips.
    profile.port_scan_threshold = 1_000_000;
    let mut state = make_state("trust", profile);
    let cap = super::scan::max_sources_per_zone_for_test();

    // Saturate the trust zone with a spoofed-source flood (one SYN each, so
    // none individually reaches the detection count).
    let flood_now = 1_000u64;
    let dst = IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1));
    for i in 0..cap {
        let src = IpAddr::V4(Ipv4Addr::from(0x0a00_0000u32 + i as u32));
        let pkt = tcp_pkt(src, dst, 1234, 80, TCP_SYN);
        assert_eq!(
            state.scan_sweep_drop_on_new_flow("trust", ZID, &pkt, flood_now),
            None
        );
    }

    // A real scanner shows up afterward, hitting SCAN_DETECT_COUNT+ ports on
    // one target within the window.
    let scanner = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
    let target = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10));
    let mut fired = false;
    for port in 1000u16..1000 + super::scan::SCAN_DETECT_COUNT as u16 + 2 {
        let pkt = tcp_pkt(scanner, target, 1234, port, TCP_SYN);
        if state.scan_sweep_drop_on_new_flow("trust", ZID, &pkt, flood_now + 1) == Some("port-scan")
        {
            fired = true;
            break;
        }
    }
    assert!(
        fired,
        "a real port-scanner arriving after a saturating flood MUST be \
         detected (pre-#2234 it was skipped on the full table → never \
         detected)"
    );
    assert!(
        state.scan_sweep_evicted_pressure() >= 1,
        "tracking the scanner required at least one eviction"
    );
}

/// #2234: the `scan-table-pressure` operator alarm transition fires at a
/// rare logarithmic rate under a sustained source flood — never per flow.
#[test]
fn scan_table_pressure_event_fires_rarely_under_flood() {
    let mut profile = ScreenProfile::default();
    // Wide in-range window, one dst per source → detection never trips; this
    // exercises the source-table eviction alarm, not the verdict.
    profile.ip_sweep_threshold = 1_000_000;
    let mut state = make_state("trust", profile);
    let cap = super::scan::max_sources_per_zone_for_test();

    // No evictions yet → no pressure-event transition.
    assert!(!state.take_scan_table_pressure_event());

    // Saturate, then churn many fresh sources to force sustained eviction.
    let dst = IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1));
    let mut events = 0u32;
    for i in 0..(cap + 2_000) {
        let src = IpAddr::V4(Ipv4Addr::from(0x0a00_0000u32 + i as u32));
        let pkt = tcp_pkt(src, dst, 1234, 80, TCP_SYN);
        let _ = state.scan_sweep_drop_on_new_flow("trust", ZID, &pkt, 100);
        if state.take_scan_table_pressure_event() {
            events += 1;
        }
    }
    // ~2000 evictions → log2(2000) ≈ 11 events, far fewer than the flood
    // size: the alarm is logarithmic, not per-flow.
    assert!(
        events >= 1 && events <= 20,
        "pressure-event must be rare/logarithmic, got {events} over {} flows",
        cap + 2_000
    );
    assert!(state.scan_sweep_evicted_pressure() >= 2_000);
}

// #4114: the pre-existing #2227 "over-cap threshold still fires (fail-closed
// clamp)" test was removed here — the configurable COUNT and its
// MAX_UNIQUE_PER_SOURCE clamp no longer exist. The detection count is now the
// fixed SCAN_DETECT_COUNT (10, well under the memory cap) and the configurable
// `threshold` is the microsecond detection WINDOW. The window vs count
// semantics are covered by `screen::scan::scan_tests::detects_fixed_count_within_window`
// and `no_detect_when_dests_spread_beyond_window`.

// ================================================================
// #3082 — lenient/HA-sync missing-screen-profile runtime signal
// ================================================================

// A zone that REFERENCES a screen profile undefined at snapshot-build time
// (no entry in `profiles`, but present in the references-missing set) must take
// the WARN path on the None branch, rate-limited to one per zone per second.
// FAIL-ON-REVERT: revert the references-missing threading (the None branch no
// longer calls `maybe_warn_missing_profile`, or the set is never populated) and
// `missing_profile_warn_count()` stays 0 → this test goes RED.
//
// #7168 narrowed what the Pass assertions here mean, so read them accordingly.
// The verdict for an unresolved reference is no longer unconditionally Pass —
// it is the substituted conservative default. These packets are plain SYNs,
// which that default does not drop, so the assertions are unchanged and still
// correct. What they no longer establish is "an unresolved reference always
// passes"; that claim is now false, and the #7168 cells own the drop side.
#[test]
fn missing_profile_reference_warns_and_is_rate_limited() {
    let mut state = ScreenState::new();
    let mut missing = FxHashMap::default();
    missing.insert("trust".to_string(), "ghost".to_string());
    state.update_missing_profiles(missing);

    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 2));
    let pkt = tcp_pkt(src, dst, 5000, 80, TCP_SYN);

    // First packet in second 1: WARN emitted, verdict Pass.
    assert_eq!(state.check_packet("trust", &pkt, 1), ScreenVerdict::Pass);
    assert_eq!(
        state.missing_profile_warn_count(),
        1,
        "first packet to a missing-profile zone must emit exactly one WARN"
    );

    // Flood within the same second: rate-limited to the single WARN, all Pass.
    for _ in 0..200 {
        assert_eq!(state.check_packet("trust", &pkt, 1), ScreenVerdict::Pass);
    }
    assert_eq!(
        state.missing_profile_warn_count(),
        1,
        "a per-packet flood within one second must be rate-limited to 1 WARN"
    );

    // A sustained flood crossing into the next second stays suppressed: the
    // sliding-window counter carries the prior second's tally, so a misconfig
    // under continuous traffic produces essentially one WARN, not 1/sec.
    assert_eq!(state.check_packet("trust", &pkt, 2), ScreenVerdict::Pass);
    assert_eq!(
        state.missing_profile_warn_count(),
        1,
        "sustained traffic into the next second must not re-WARN"
    );

    // After traffic subsides for a full window (a multi-second quiet gap), a new
    // packet re-emits exactly one WARN.
    assert_eq!(state.check_packet("trust", &pkt, 10), ScreenVerdict::Pass);
    assert_eq!(
        state.missing_profile_warn_count(),
        2,
        "a packet after a quiet gap must re-WARN"
    );
}

// A zone with NO screen configured (absent from BOTH `profiles` and the
// references-missing set) is the legit Pass case: it must NOT warn.
#[test]
fn no_screen_configured_zone_passes_without_warn() {
    let mut state = ScreenState::new();
    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 2));
    let pkt = tcp_pkt(src, dst, 5000, 80, TCP_SYN);
    for s in 1..6 {
        assert_eq!(state.check_packet("nozone", &pkt, s), ScreenVerdict::Pass);
    }
    assert_eq!(
        state.missing_profile_warn_count(),
        0,
        "a zone with no screen configured must never WARN"
    );
}

// A zone with a RESOLVED screen profile runs the real checks and never takes the
// missing-profile WARN path.
#[test]
fn resolved_profile_zone_never_warns_missing() {
    let mut state = make_state("trust", default_profile());
    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 2));
    let pkt = tcp_pkt(src, dst, 5000, 80, TCP_SYN);
    assert_eq!(state.check_packet("trust", &pkt, 1), ScreenVerdict::Pass);
    assert_eq!(
        state.missing_profile_warn_count(),
        0,
        "a resolved-profile zone must not take the missing-profile WARN path"
    );
}

// An old-helper snapshot WITHOUT the references-missing set (empty after
// `update_missing_profiles`) yields all-Pass and no warn — skew tolerance at
// the dataplane mirror of the serde default.
#[test]
fn empty_missing_set_passes_without_warn() {
    let mut state = ScreenState::new();
    state.update_missing_profiles(FxHashMap::default());
    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 2));
    let pkt = tcp_pkt(src, dst, 5000, 80, TCP_SYN);
    assert_eq!(state.check_packet("trust", &pkt, 1), ScreenVerdict::Pass);
    assert_eq!(state.missing_profile_warn_count(), 0);
}

// ================================================================
// #3908 — missing-screen-profile signal on the FLOWLESS path
// ================================================================
//
// The flow-present `check_packet_with_zone_id` None branch calls
// `maybe_warn_missing_profile` (#3082), but before #3908 the flowless
// `check_flowless_screens` None branch returned Pass SILENTLY — a flowless
// packet (non-first fragment / non-query ICMP) to a broken-profile zone
// produced no diagnostic. These tests assert the flowless path now mirrors the
// flow path: WARN-but-Pass for a referenced-missing profile, silent Pass for a
// zone with no screen, and no missing-warn for a resolved profile.

// A zone that REFERENCES a screen profile undefined at snapshot-build time
// must take the WARN path on the flowless None branch — yet still return Pass
// (watch-log-only, no verdict change). FAIL-ON-REVERT: drop the
// `maybe_warn_missing_profile` call from `check_flowless_screens` and
// `missing_profile_warn_count()` stays 0 → this test goes RED.
#[test]
fn missing_profile_reference_warns_on_flowless_path_but_passes() {
    let mut state = ScreenState::new();
    let mut missing = FxHashMap::default();
    missing.insert("trust".to_string(), "ghost".to_string());
    state.update_missing_profiles(missing);

    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 2));
    let pkt = flowless_icmp_pkt(src, dst);

    // First flowless packet in second 1: WARN emitted, verdict Pass.
    assert_eq!(
        state.check_flowless_screens("trust", &pkt, true, 1),
        ScreenVerdict::Pass
    );
    assert_eq!(
        state.missing_profile_warn_count(),
        1,
        "first flowless packet to a missing-profile zone must emit exactly one WARN"
    );

    // Flood within the same second: rate-limited to the single WARN, all Pass.
    for _ in 0..200 {
        assert_eq!(
            state.check_flowless_screens("trust", &pkt, true, 1),
            ScreenVerdict::Pass
        );
    }
    assert_eq!(
        state.missing_profile_warn_count(),
        1,
        "a flowless per-packet flood within one second must be rate-limited to 1 WARN"
    );

    // After a multi-second quiet gap a new flowless packet re-emits one WARN.
    assert_eq!(
        state.check_flowless_screens("trust", &pkt, true, 10),
        ScreenVerdict::Pass
    );
    assert_eq!(
        state.missing_profile_warn_count(),
        2,
        "a flowless packet after a quiet gap must re-WARN"
    );
}

// A zone with NO screen configured (absent from BOTH `profiles` and the
// references-missing set) is the legit Pass case on the flowless path: it must
// NOT warn. FAIL-SAFE: an over-broad flowless fix that warns on every None
// would make this go RED.
#[test]
fn no_screen_configured_zone_passes_flowless_without_warn() {
    let mut state = ScreenState::new();
    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 2));
    let pkt = flowless_icmp_pkt(src, dst);
    for s in 1..6 {
        assert_eq!(
            state.check_flowless_screens("nozone", &pkt, true, s),
            ScreenVerdict::Pass
        );
    }
    assert_eq!(
        state.missing_profile_warn_count(),
        0,
        "a zone with no screen configured must never WARN on the flowless path"
    );
}

// A zone with a RESOLVED screen profile runs the real flowless checks and never
// takes the missing-profile WARN path.
#[test]
fn resolved_profile_zone_flowless_never_warns_missing() {
    // icmp_flood_threshold high enough that a single ICMP packet passes; the
    // point is that the resolved-profile branch is taken (never the None WARN).
    let mut profile = default_profile();
    profile.icmp_flood_threshold = 1000;
    let mut state = make_state("trust", profile);
    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 2));
    let pkt = flowless_icmp_pkt(src, dst);
    assert_eq!(
        state.check_flowless_screens("trust", &pkt, true, 1),
        ScreenVerdict::Pass
    );
    assert_eq!(
        state.missing_profile_warn_count(),
        0,
        "a resolved-profile zone must not take the missing-profile WARN path on the flowless path"
    );
}

// ================================================================
// #3902: source-independent screens on the FLOWLESS path
// ================================================================
//
// A non-first IP fragment and a non-query ICMP/ICMPv6 control message are
// deliberately flowless (#2344 / #3290 — the dataplane never derives an L4
// tuple for them). Before #3902 the flowless branch ran ONLY the three L3
// fragment screens (ping-of-death / teardrop / icmp-fragment), so the
// SOURCE-INDEPENDENT screens — LAND anti-spoof, ip-source-route, ICMP flood,
// UDP flood — were BYPASSED for those packets (screen fail-open).
// `check_flowless_screens` now runs them. Each drop test below goes RED if
// the fix is reverted: the pre-#3902 `check_fragment_screens_l3` never
// evaluated LAND / source-route / the flood counters.

/// A flowless non-query ICMP/ICMPv6 packet (no fragment, no L4 flow).
fn flowless_icmp_pkt(src: IpAddr, dst: IpAddr) -> ScreenPacketInfo {
    let (proto, af) = match src {
        IpAddr::V4(_) => (PROTO_ICMP, libc::AF_INET as u8),
        IpAddr::V6(_) => (PROTO_ICMPV6, libc::AF_INET6 as u8),
    };
    ScreenPacketInfo {
        addr_family: af,
        protocol: proto,
        tcp_flags: 0,
        src_ip: src,
        dst_ip: dst,
        src_port: 0,
        dst_port: 0,
        tcp_seq: 0,
        tcp_ack: 0,
        tcp_mss: 0,
        pkt_len: 84,
        is_fragment: false,
        is_first_fragment: false,
        ip_ihl: 5,
        ip_frag_off: 0,
        ip_total_len: 84,
        ip_payload_len: 0,
        frag_data_off: 0,
        saw_ipv4_source_route: false,
        saw_ipv6_routing_header: false,
    }
}

/// A flowless non-first IPv4 fragment carrying `protocol` (no L4 flow). The
/// fragment offset field is 185 (→ 1480 bytes, non-first) with MF=0 (tail
/// fragment); the total length keeps the payload well above the teardrop
/// threshold and the reassembled end below the ping-of-death ceiling so those
/// two fragment screens do NOT fire — the source-independent screens under
/// test are the only ones that can drop.
fn flowless_nonfirst_fragment(src: IpAddr, dst: IpAddr, protocol: u8) -> ScreenPacketInfo {
    ScreenPacketInfo {
        addr_family: libc::AF_INET as u8,
        protocol,
        tcp_flags: 0,
        src_ip: src,
        dst_ip: dst,
        src_port: 0,
        dst_port: 0,
        tcp_seq: 0,
        tcp_ack: 0,
        tcp_mss: 0,
        pkt_len: 1400,
        is_fragment: true,
        is_first_fragment: false,
        ip_ihl: 5,
        ip_frag_off: 185, // offset field 185 (→ 1480 bytes), non-first, MF=0
        ip_total_len: 1400,
        ip_payload_len: 0,
        frag_data_off: 0,
        saw_ipv4_source_route: false,
        saw_ipv6_routing_header: false,
    }
}

#[test]
fn land_flowless_non_query_icmp_drops() {
    // RED-on-revert: a crafted non-query ICMP whose src_ip == dst_ip is
    // flowless (#3290) but LAND is source-independent and MUST drop it.
    let mut profile = ScreenProfile::default();
    profile.land = true;
    let mut state = make_state("trust", profile);
    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    let pkt = flowless_icmp_pkt(ip, ip);
    assert_eq!(
        state.check_flowless_screens("trust", &pkt, true, 1),
        ScreenVerdict::Drop("land-attack")
    );
}

#[test]
fn land_flowless_non_first_fragment_drops() {
    // RED-on-revert: a non-first fragment whose src_ip == dst_ip must trip
    // LAND on the flowless path.
    let mut profile = ScreenProfile::default();
    profile.land = true;
    let mut state = make_state("trust", profile);
    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 5, 5));
    let pkt = flowless_nonfirst_fragment(ip, ip, PROTO_UDP);
    assert_eq!(
        state.check_flowless_screens("trust", &pkt, true, 1),
        ScreenVerdict::Drop("land-attack")
    );
}

#[test]
fn land_flowless_addrs_unknown_skips() {
    // When the caller could not derive the real L3 addresses (frame too
    // short → addrs_known=false) LAND must be SKIPPED rather than fired on
    // the unspecified==unspecified placeholder. The same tuple WITH
    // addrs_known=true proves the guard is what suppresses it.
    let mut profile = ScreenProfile::default();
    profile.land = true;
    let mut state = make_state("trust", profile);
    let unspec = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
    let pkt = flowless_icmp_pkt(unspec, unspec);
    assert_eq!(
        state.check_flowless_screens("trust", &pkt, false, 1),
        ScreenVerdict::Pass
    );
    assert_eq!(
        state.check_flowless_screens("trust", &pkt, true, 1),
        ScreenVerdict::Drop("land-attack")
    );
}

#[test]
fn source_route_flowless_non_first_fragment_drops() {
    // RED-on-revert: ip-source-route is source-independent and must drop a
    // flowless non-first fragment carrying an LSRR/SSRR option.
    let mut profile = ScreenProfile::default();
    profile.source_route = true;
    let mut state = make_state("trust", profile);
    let mut pkt = flowless_nonfirst_fragment(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        PROTO_UDP,
    );
    pkt.saw_ipv4_source_route = true; // extractor decoded LSRR/SSRR
    assert_eq!(
        state.check_flowless_screens("trust", &pkt, true, 1),
        ScreenVerdict::Drop("ip-source-route")
    );
}

#[test]
fn icmp_flood_flowless_drops() {
    // RED-on-revert: the per-zone ICMP flood counter is source-independent
    // and must count flowless non-query ICMP packets.
    let mut profile = ScreenProfile::default();
    profile.icmp_flood_threshold = 2;
    let mut state = make_state("trust", profile);
    let pkt = flowless_icmp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
    );
    assert_eq!(
        state.check_flowless_screens("trust", &pkt, true, 100),
        ScreenVerdict::Pass
    );
    assert_eq!(
        state.check_flowless_screens("trust", &pkt, true, 100),
        ScreenVerdict::Pass
    );
    assert_eq!(
        state.check_flowless_screens("trust", &pkt, true, 100),
        ScreenVerdict::Drop("icmp-flood")
    );
}

#[test]
fn udp_flood_flowless_non_first_fragment_drops() {
    // RED-on-revert: the per-zone UDP flood counter is source-independent
    // and must count flowless non-first UDP fragments.
    let mut profile = ScreenProfile::default();
    profile.udp_flood_threshold = 2;
    let mut state = make_state("trust", profile);
    let pkt = flowless_nonfirst_fragment(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        PROTO_UDP,
    );
    assert_eq!(
        state.check_flowless_screens("trust", &pkt, true, 100),
        ScreenVerdict::Pass
    );
    assert_eq!(
        state.check_flowless_screens("trust", &pkt, true, 100),
        ScreenVerdict::Pass
    );
    assert_eq!(
        state.check_flowless_screens("trust", &pkt, true, 100),
        ScreenVerdict::Drop("udp-flood")
    );
}

#[test]
fn udp_flood_flowless_fragment_folds_into_per_ip_bucket_4567() {
    // RED-on-revert (#4567): a non-first UDP fragment (flowless, dst_port=0)
    // must fold its flood count into the per-DESTINATION-IP `increment(dst_ip)`
    // bucket — the SAME abstraction the ICMP flood path uses — NOT a distinct
    // `(dst_ip, port=0)` bucket.
    //
    // A single-IP fragment stream trips EITHER bucket, so it cannot tell the two
    // apart. This discriminator pre-saturates ONLY the per-DESTINATION-IP cells
    // for D and leaves the `(D, 0)` cells fresh, then sends ONE flowless UDP
    // fragment to D. After the fix `udp_flood_drop` reads the pre-saturated
    // per-IP cells and Drops on the FIRST fragment; on revert it counts into the
    // fresh `(D, 0)` cells (the per-IP cells are never consulted) and Passes. The
    // Drop⟷Pass flips.
    const T: u32 = 4;
    let mut profile = ScreenProfile::default();
    profile.udp_flood_threshold = T;
    let mut state = make_state("trust", profile);
    let d = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1));
    // Drive the per-DESTINATION-IP cells for D over threshold directly (test
    // seam), leaving the `(D, port=0)` cells untouched.
    let cells = state.udp_dst_sketch_mut_for_test("trust").cell_indices(&d);
    let sketch = state.udp_dst_sketch_mut_for_test("trust");
    for (row, &col) in cells.iter().enumerate() {
        // #5805: the flood sketch cells are token buckets keyed on `now_ns`; the
        // check below runs at `now_secs=100` (→ `now_ns = 100 * NANOS_PER_SEC`),
        // so saturate at the SAME instant or the bucket would "refill" across the
        // apparent elapsed second and un-saturate.
        sketch.saturate_cell(row, col, 100 * NS, T);
    }
    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    let pkt = flowless_nonfirst_fragment(src, d, PROTO_UDP);
    assert_eq!(
        state.check_flowless_screens("trust", &pkt, true, 100),
        ScreenVerdict::Drop("udp-flood"),
        "flowless UDP fragment must count into the pre-saturated per-IP bucket, \
         not a separate (ip,0) bucket"
    );
}

#[test]
fn udp_flood_first_fragment_still_counts_per_ip_port_4567() {
    // Guard (#4567): folding a trailing fragment into the per-IP bucket must NOT
    // change where a first/atomic fragment (flow path, real L4 port) counts.
    // Pre-saturate the per-DESTINATION-IP cells for D, then drive normal UDP
    // datagrams to `(D, 5001)` via the flow path: they count at `(D, 5001)`,
    // independent of the per-IP(D) cells, so the first T still Pass (the
    // pre-saturated per-IP cells are NOT consulted for a real port) and the
    // (T+1)th trips its OWN `(ip, port)` bucket.
    const T: u32 = 4;
    let mut profile = ScreenProfile::default();
    profile.udp_flood_threshold = T;
    let mut state = make_state("trust", profile);
    let d = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1));
    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    let cells = state.udp_dst_sketch_mut_for_test("trust").cell_indices(&d);
    let sketch = state.udp_dst_sketch_mut_for_test("trust");
    for (row, &col) in cells.iter().enumerate() {
        // #5805: the flood sketch cells are token buckets keyed on `now_ns`; the
        // check below runs at `now_secs=100` (→ `now_ns = 100 * NANOS_PER_SEC`),
        // so saturate at the SAME instant or the bucket would "refill" across the
        // apparent elapsed second and un-saturate.
        sketch.saturate_cell(row, col, 100 * NS, T);
    }
    let pkt = udp_pkt(src, d); // dst_port = 5001 (real L4 port, flow path)
    for i in 0..T {
        assert_eq!(
            state.check_packet_with_zone_id("trust", 3, &pkt, 100),
            ScreenVerdict::Pass,
            "flow-path UDP datagram #{i} must count at (ip,port), not per-IP(D)"
        );
    }
    assert_eq!(
        state.check_packet_with_zone_id("trust", 3, &pkt, 100),
        ScreenVerdict::Drop("udp-flood"),
        "the (T+1)th datagram trips its own (ip,port) bucket"
    );
}

#[test]
fn teardrop_still_screened_on_flowless_path() {
    // #3064 regression guard: the L3 fragment screens still fire on the
    // flowless path through check_flowless_screens.
    let mut profile = ScreenProfile::default();
    profile.teardrop = true;
    let mut state = make_state("trust", profile);
    let mut pkt = flowless_nonfirst_fragment(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        PROTO_UDP,
    );
    // #9426: MF=1 (0x2000). The fixture was `0x0001` — offset 1 with MF=0,
    // a LAST fragment carrying 4 bytes, which is legal IP and is no longer
    // dropped. This cell is about the flowless PATH (#3064), not about the
    // teardrop boundary, so the trigger is repaired and the claim is unchanged.
    pkt.ip_frag_off = 0x2001; // offset field 1 (non-first), MF=1 (non-last)
    pkt.ip_total_len = 24; // 20-byte header + 4-byte payload (< 8) → teardrop
    assert_eq!(
        state.check_flowless_screens("trust", &pkt, true, 1),
        ScreenVerdict::Drop("teardrop")
    );
}

#[test]
fn flowless_clean_non_first_fragment_passes() {
    // A benign flowless non-first fragment (no screen tripped) must PASS —
    // the fix must not over-drop. Uses the full default profile (LAND,
    // source-route, all fragment screens enabled) with distinct src/dst.
    let mut state = make_state("trust", default_profile());
    let pkt = flowless_nonfirst_fragment(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        PROTO_UDP,
    );
    assert_eq!(
        state.check_flowless_screens("trust", &pkt, true, 1),
        ScreenVerdict::Pass
    );
}

// ================================================================
// #4155: fabric-redirected traffic must NOT re-run the rate-based
// flood counters on the RG owner (already screened on ingress).
// The `_opts(..., skip_rate_flood = true)` entry points model the
// FABRIC_INGRESS_FLAG path; the stateless screens still run.
// ================================================================

#[test]
fn fabric_skip_does_not_count_icmp_flood_4155() {
    // RED-on-revert: with skip_rate_flood=true the per-zone/per-dst ICMP
    // flood counter must NOT tick, so an ICMP stream well past threshold 2
    // keeps passing. Reverting the skip lets the counter run and the 3rd
    // packet Drops → this Pass assertion goes RED.
    let mut profile = ScreenProfile::default();
    profile.icmp_flood_threshold = 2;
    let mut state = make_state("trust", profile);
    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1));
    for i in 0..8 {
        assert_eq!(
            state.check_packet_with_zone_id_opts("trust", 3, &icmp_pkt(src, dst, 84), 100 * NS, 100, true),
            ScreenVerdict::Pass,
            "fabric-redirected ICMP #{i} must not be re-counted on the owner"
        );
    }
}

#[test]
fn fabric_skip_does_not_count_udp_flood_4155() {
    let mut profile = ScreenProfile::default();
    profile.udp_flood_threshold = 2;
    let mut state = make_state("trust", profile);
    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1));
    for i in 0..8 {
        let mut pkt = udp_pkt(src, dst);
        pkt.dst_ip = dst;
        assert_eq!(
            state.check_packet_with_zone_id_opts("trust", 3, &pkt, 100 * NS, 100, true),
            ScreenVerdict::Pass,
            "fabric-redirected UDP #{i} must not be re-counted on the owner"
        );
    }
}

#[test]
fn fabric_skip_does_not_count_syn_flood_4155() {
    // A fabric-redirected SYN belongs to a session the peer already admitted:
    // the owner must neither count it toward syn-flood nor mint a cookie.
    let mut profile = ScreenProfile::default();
    profile.syn_flood_threshold = 2;
    let mut state = make_state("trust", profile);
    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1));
    for i in 0..8 {
        let pkt = tcp_pkt(src, dst, 1234 + i, 80, TCP_SYN);
        assert_eq!(
            state.check_packet_with_zone_id_opts("trust", 3, &pkt, 100 * NS, 100, true),
            ScreenVerdict::Pass,
            "fabric-redirected SYN #{i} must not be re-counted (no syn-flood, no cookie)"
        );
    }
}

#[test]
fn fabric_skip_still_runs_stateless_land_4155() {
    // Scope guard: the skip is RATE-only. A stateless LAND attack must still
    // Drop on a fabric-redirected packet (idempotent per-packet check).
    let mut state = make_state("trust", default_profile());
    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    let pkt = tcp_pkt(src, src, 80, 80, TCP_SYN);
    assert_eq!(
        state.check_packet_with_zone_id_opts("trust", 3, &pkt, NS, 1, true),
        ScreenVerdict::Drop("land-attack"),
        "stateless LAND must still fire on fabric traffic"
    );
}

#[test]
fn fabric_skip_flowless_does_not_count_icmp_flood_4155() {
    let mut profile = ScreenProfile::default();
    profile.icmp_flood_threshold = 2;
    let mut state = make_state("trust", profile);
    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1));
    for i in 0..8 {
        assert_eq!(
            state.check_flowless_screens_opts(
                "trust",
                &flowless_icmp_pkt(src, dst),
                true,
                100 * NS,
                100,
                true,
            ),
            ScreenVerdict::Pass,
            "fabric-redirected flowless ICMP #{i} must not be re-counted"
        );
    }
}

#[test]
fn fabric_skip_flowless_still_runs_teardrop_4155() {
    // Scope guard on the flowless path: stateless fragment screens still run.
    let mut profile = ScreenProfile::default();
    profile.teardrop = true;
    let mut state = make_state("trust", profile);
    let mut pkt = flowless_nonfirst_fragment(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        PROTO_UDP,
    );
    // #9426: MF=1, as in teardrop_still_screened_on_flowless_path. This cell
    // is about the #4155 fabric skip, not about the teardrop boundary.
    pkt.ip_frag_off = 0x2001; // offset 1 unit (non-first), MF=1 (non-last)
    pkt.ip_total_len = 24; // 20-byte header + 4-byte payload (< 8) → teardrop
    assert_eq!(
        state.check_flowless_screens_opts("trust", &pkt, true, NS, 1, true),
        ScreenVerdict::Drop("teardrop"),
        "stateless teardrop must still fire on fabric flowless traffic"
    );
}

#[test]
fn fabric_skip_leaves_direct_ingress_counting_intact_4155() {
    // The skip is scoped to fabric traffic: a burst of fabric-redirected ICMP
    // must NOT advance the counter, so a subsequent DIRECT-ingress stream
    // reaches the flood threshold at the CORRECT count (threshold + 1), not
    // halved by a phantom fabric double-count.
    let mut profile = ScreenProfile::default();
    profile.icmp_flood_threshold = 3;
    let mut state = make_state("trust", profile);
    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1));
    // 5 fabric packets — none may count.
    for _ in 0..5 {
        assert_eq!(
            state.check_packet_with_zone_id_opts("trust", 3, &icmp_pkt(src, dst, 84), 100 * NS, 100, true),
            ScreenVerdict::Pass
        );
    }
    // Direct ingress: 3 pass (threshold 3), 4th drops. If fabric packets had
    // polluted the counter the drop would come EARLY (RED-on-revert of scope).
    assert_eq!(
        state.check_packet_with_zone_id_opts("trust", 3, &icmp_pkt(src, dst, 84), 100 * NS, 100, false),
        ScreenVerdict::Pass
    );
    assert_eq!(
        state.check_packet_with_zone_id_opts("trust", 3, &icmp_pkt(src, dst, 84), 100 * NS, 100, false),
        ScreenVerdict::Pass
    );
    assert_eq!(
        state.check_packet_with_zone_id_opts("trust", 3, &icmp_pkt(src, dst, 84), 100 * NS, 100, false),
        ScreenVerdict::Pass
    );
    assert_eq!(
        state.check_packet_with_zone_id_opts("trust", 3, &icmp_pkt(src, dst, 84), 100 * NS, 100, false),
        ScreenVerdict::Drop("icmp-flood"),
        "direct ingress reaches the flood threshold at the correct count"
    );
}

// ================================================================
// #6238 — shared source-independent screen extraction
//
// Two helpers now single-source the previously hand-mirrored
// source-independent screen orchestration:
//   - `stateless::check_fragment_and_route` — the common stateless tail
//     (ping-of-death → teardrop → icmp-fragment → source-route), run at the
//     SAME precedence slot on the flow-present and flowless paths.
//   - `ZoneScreenState::enforce_common_rate_floods` — the common ICMP/UDP
//     flood block, run right after each path's fabric `skip_rate_flood` gate.
//
// LAND and the TCP-flag screens are DELIBERATELY excluded from the shared
// tail (LAND is `addrs_known`-gated on the flowless path and precedes the
// full-only TCP-flag screens; a contiguous LAND-through-source-route helper
// would flip drop precedence — the reason string selects the per-reason drop
// counter via `screen_reason_drop_index`). These tests pin the precedence a
// single-feature test cannot catch, and prove BOTH paths route through the
// shared helpers (fail-on-revert).
// ================================================================

#[test]
fn precedence_full_tcp_flag_screens_precede_fragment_route_tail_6238() {
    // Multi-trigger: a TCP packet carrying an LSRR/SSRR source-route option
    // that is ALSO SYN+FIN triggers BOTH the full-only TCP-flag screen
    // (`tcp-syn-fin`, ordinal 8) AND the shared fragment/route tail
    // (`ip-source-route`, ordinal 12). Because `check_tcp_flag_screens` runs
    // IMMEDIATELY BEFORE `check_fragment_and_route` on the full path, the
    // winning reason MUST be `tcp-syn-fin`. A single-feature test cannot catch
    // a reorder that moved the shared tail ahead of the TCP-flag screens; this
    // pins the precedence (and thus the per-reason drop-counter ordinal).
    let mut state = make_state("trust", default_profile());
    let mut pkt = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        1234,
        80,
        TCP_SYN | TCP_FIN,
    );
    pkt.saw_ipv4_source_route = true; // extractor decoded LSRR/SSRR
    assert_eq!(
        state.check_packet("trust", &pkt, 1),
        ScreenVerdict::Drop("tcp-syn-fin"),
        "TCP-flag screens must precede the shared fragment/route tail"
    );
}

#[test]
fn precedence_full_land_precedes_tcp_flag_screens_6238() {
    // Multi-trigger: a LAND packet (src == dst) that is ALSO SYN+FIN triggers
    // BOTH LAND (`land-attack`, ordinal 5) and the TCP-flag screen
    // (`tcp-syn-fin`, ordinal 8). LAND runs FIRST (unconditionally, before the
    // TCP-flag screens), so the winning reason MUST be `land-attack`. Guards
    // the LAND → TCP-flag ordering the shared-tail extraction must not disturb.
    let mut state = make_state("trust", default_profile());
    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    let pkt = tcp_pkt(ip, ip, 80, 80, TCP_SYN | TCP_FIN);
    assert_eq!(
        state.check_packet("trust", &pkt, 1),
        ScreenVerdict::Drop("land-attack"),
        "LAND must precede the TCP-flag screens"
    );
}

#[test]
fn precedence_flowless_addrs_unknown_skips_land_runs_tail_and_floods_6238() {
    // On the flowless path LAND is `addrs_known`-gated, but the shared
    // fragment/route tail and the rate floods are NOT. A flowless fragment
    // whose src == dst (would trip LAND) AND that carries a source-route
    // option, with addrs_known=false, must SKIP LAND and drop on the tail's
    // `ip-source-route` — proving the tail runs even when LAND is gated off.
    // The same tuple with addrs_known=true drops `land-attack`, proving LAND
    // precedes the tail when it is enabled.
    let profile = ScreenProfile {
        land: true,
        source_route: true,
        ..ScreenProfile::default()
    };
    let mut state = make_state("trust", profile);
    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 7, 7));
    let mut pkt = flowless_nonfirst_fragment(ip, ip, PROTO_UDP);
    pkt.saw_ipv4_source_route = true;
    assert_eq!(
        state.check_flowless_screens("trust", &pkt, false, 1),
        ScreenVerdict::Drop("ip-source-route"),
        "LAND gated off (addrs_known=false) but the shared tail must still run"
    );
    assert_eq!(
        state.check_flowless_screens("trust", &pkt, true, 1),
        ScreenVerdict::Drop("land-attack"),
        "LAND precedes the shared tail when addrs are known"
    );

    // The rate floods run regardless of addrs_known. A clean flowless ICMP
    // stream (no src==dst, no source-route) over threshold drops `icmp-flood`
    // with addrs_known=false — proving `enforce_common_rate_floods` is reached
    // on the flowless path independent of the LAND gate.
    let flood_profile = ScreenProfile {
        icmp_flood_threshold: 2,
        ..ScreenProfile::default()
    };
    let mut flood_state = make_state("trust", flood_profile);
    let fpkt = flowless_icmp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
    );
    assert_eq!(
        flood_state.check_flowless_screens("trust", &fpkt, false, 100),
        ScreenVerdict::Pass
    );
    assert_eq!(
        flood_state.check_flowless_screens("trust", &fpkt, false, 100),
        ScreenVerdict::Pass
    );
    assert_eq!(
        flood_state.check_flowless_screens("trust", &fpkt, false, 100),
        ScreenVerdict::Drop("icmp-flood"),
        "rate floods enforce regardless of addrs_known"
    );
}

#[test]
fn shared_fragment_route_helper_binds_flowless_path_6238() {
    // FAIL-ON-REVERT (flowless leg): the flowless path enforces the shared
    // fragment/route tail via `check_fragment_and_route`. Neutralizing the
    // flowless `check_fragment_and_route` call site turns this flowless binding
    // test RED (the packet would PASS) — together with the other flowless
    // source-route tests that traverse the same call site — while the
    // opposite-path (full) binding test below stays GREEN. That path-specific
    // asymmetry proves the flowless path is single-sourced through the shared
    // helper rather than an independent hand-mirrored copy.
    let profile = ScreenProfile {
        source_route: true,
        ..ScreenProfile::default()
    };
    let mut state = make_state("trust", profile);
    let mut pkt = flowless_nonfirst_fragment(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        PROTO_UDP,
    );
    pkt.saw_ipv4_source_route = true;
    assert_eq!(
        state.check_flowless_screens("trust", &pkt, true, 1),
        ScreenVerdict::Drop("ip-source-route")
    );
}

#[test]
fn shared_fragment_route_helper_binds_full_path_6238() {
    // FAIL-ON-REVERT (full leg): the flow-present path enforces the SAME shared
    // tail. Neutralizing the full-path `check_fragment_and_route` call site
    // turns this full binding test RED (with the other full-path source-route
    // tests through that call site), while the flowless binding test above
    // stays GREEN — the two paths route through ONE helper, so a future
    // source-independent addition to `check_fragment_and_route` is enforced on
    // both entry points by construction (the #3902 fail-open class).
    let profile = ScreenProfile {
        source_route: true,
        ..ScreenProfile::default()
    };
    let mut state = make_state("trust", profile);
    let mut pkt = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        1234,
        80,
        TCP_SYN,
    );
    pkt.saw_ipv4_source_route = true;
    assert_eq!(
        state.check_packet("trust", &pkt, 1),
        ScreenVerdict::Drop("ip-source-route")
    );
}

/// #6885: the screen extractor's ext-header walk resolves the SAME chain
/// depths as the forwarding walker — bound as an AGREEMENT, not as a number.
///
/// The comment this replaces asserted parity by stating a constant
/// (`MAX_EXT_HDRS=8`) and a peer (`the BPF parser`), and both were false: no
/// constant of that name has ever been 8, and the BPF parser bounded at 6.
/// The parity itself was real. That is the failure mode a hand-written number
/// has here — three walkers reach the same depth by different mechanisms and
/// therefore carry three different numbers (this extractor's `0..8`
/// iterations, `MAX_IPV6_EXT_HEADERS = 8`, the shim's `MAX_EXT_HDRS = 7`), so
/// any single number copied into a comment is wrong for two of them.
///
/// Pinning either side's literal would just re-create that. This asserts the
/// two walkers AGREE at every chain length, which stays true through a
/// mechanism change on either side and reds the moment their coverage
/// actually diverges.
///
/// The sweep spans the boundary deliberately: 0..=7 must resolve, 8..=10 must
/// refuse. A sweep that stopped at 7 would pass against a walk with no bound
/// at all.
#[test]
fn screen_ext_header_depth_agrees_with_the_forwarding_walker_6885() {
    let mut screen_resolved = Vec::new();
    let mut walker_resolved = Vec::new();

    for n in 0usize..=10 {
        // base -> n x Destination-Options(8B) -> TCP
        let base = 14 + 40;
        let mut frame = vec![0u8; base + n * 8 + 24];
        frame[14] = 0x60; // version = 6
        frame[14 + 6] = if n == 0 { 6 } else { 60 };
        for i in 0..n {
            let at = base + i * 8;
            frame[at] = if i + 1 == n { 6 } else { 60 }; // last one points at TCP
            frame[at + 1] = 0; // HdrExtLen = 0 -> 8 bytes
        }
        let tcp = base + n * 8;
        frame[tcp + 4..tcp + 8].copy_from_slice(&0x1122_3344u32.to_be_bytes());
        frame[tcp + 12] = 0x50; // data offset = 5 words

        let screen = extract_screen_info(
            &frame,
            libc::AF_INET6 as u8,
            6,
            0x02,
            frame.len() as u16,
            IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()),
            IpAddr::V6("2001:db8::2".parse::<Ipv6Addr>().unwrap()),
            12345,
            80,
            14,
        );
        // "Resolved" for the extractor means it actually REACHED the L4 and
        // pulled the TCP header out — not merely that it returned Ok. A walk
        // that gave up mid-chain still returns Ok with tcp_seq left at 0, and
        // that is precisely the ext-header evasion #3120/#4517 are about.
        screen_resolved.push(screen.map(|i| i.tcp_seq == 0x1122_3344).unwrap_or(false));

        let walk = crate::afxdp::walk_ipv6_ext_chain(&frame, 14);
        walker_resolved.push(matches!(
            walk.outcome,
            crate::afxdp::ExtChainOutcome::L4(_, _)
        ));
    }

    assert_eq!(
        screen_resolved, walker_resolved,
        "#6885: the screen extractor and the forwarding walker must resolve the same IPv6 \
         ext-header chain depths. Index n is a chain of n Destination-Options headers; a \
         divergence means a chain one plane screens is invisible to the other, or vice versa"
    );

    // Anchor the shared depth so the agreement above cannot be satisfied by
    // BOTH walkers regressing together (two all-false vectors are equal).
    let expected: Vec<bool> = (0usize..=10).map(|n| n <= 7).collect();
    assert_eq!(
        screen_resolved, expected,
        "#6885: both walkers must resolve 0..=7 extension headers and refuse 8 or more — the \
         depth the shim's MAX_EXT_HDRS = MAX_IPV6_EXT_HEADERS - 1 parity note names"
    );
}

// ---------------------------------------------------------------------------
// #7168: a zone whose screen reference does not resolve is enforced against the
// SUBSTITUTED conservative default, not passed outright.
//
// Before #7168 the None branch returned `ScreenVerdict::Pass`: the active
// config said a screen was attached to the zone and ZERO checks ran for it, on
// the three paths #5806 enumerates (tolerant load of an older/externally
// modified active.json, HA config-sync from a schema-skewed peer, rolling
// upgrade intervals). Failing CLOSED was rejected as the fix because it turns a
// config-reference typo into a per-zone outage on the one path whose reason to
// exist is #1960 no-brick.
//
// The two halves below must BOTH hold, and they pull in opposite directions —
// which is the point. Enforcing too little is the security hole; enforcing too
// much is the availability incident the fail-closed option was rejected for. A
// test suite that only asserted the drops would be satisfied by a substitution
// that turned everything on.
// ---------------------------------------------------------------------------

fn missing_ref_state(zone: &str, profile: &str) -> ScreenState {
    let mut state = ScreenState::new();
    let mut missing = FxHashMap::default();
    missing.insert(zone.to_string(), profile.to_string());
    state.update_missing_profiles(missing);
    state
}

// Acceptance: a LAND packet (src == dst) to a dangling-reference zone is
// DROPPED. Reverting `missing_profile_verdict` to `ScreenVerdict::Pass` reds
// this.
#[test]
fn substituted_default_drops_land_on_the_flow_path_7168() {
    let mut state = missing_ref_state("trust", "ghost");
    let same = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    let land = tcp_pkt(same, same, 5000, 5000, TCP_SYN);
    assert!(
        matches!(state.check_packet("trust", &land, 1), ScreenVerdict::Drop(_)),
        "a LAND packet to a zone whose screen reference did not resolve must be dropped by \
         the #7168 substituted conservative default, not passed"
    );
    assert_eq!(
        state.substituted_default_drops(),
        1,
        "a drop by the substituted default must be counted separately — it means a broken \
         screen reference is being masked, which the operator still has to fix"
    );
}

// The flowless path (non-first fragment / non-query ICMP) must substitute too.
// It is a SEPARATE None branch, so fixing one and not the other is live.
#[test]
fn substituted_default_drops_on_the_flowless_path_7168() {
    let mut state = missing_ref_state("trust", "ghost");
    let same = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    let land = flowless_icmp_pkt(same, same);
    assert!(
        matches!(
            state.check_flowless_screens("trust", &land, true, 1),
            ScreenVerdict::Drop(_)
        ),
        "the flowless None branch must substitute the conservative default too — it is a \
         separate branch from the flow-present one, so fixing only one leaves a live hole"
    );
}

// LAND compares source against destination, so it is only meaningful when the
// caller supplied real L3 addresses. With addrs_known=false the substitution
// must NOT invent a verdict from addresses it does not have.
#[test]
fn substituted_default_skips_land_when_addresses_are_unknown_7168() {
    let mut state = missing_ref_state("trust", "ghost");
    let same = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    let land = flowless_icmp_pkt(same, same);
    assert_eq!(
        state.check_flowless_screens("trust", &land, false, 1),
        ScreenVerdict::Pass,
        "with addrs_known=false the addresses are not the packet's real ones, so LAND must \
         not be evaluated against them"
    );
}

// Acceptance, and the half that stops this fix becoming the outage the
// fail-closed option was rejected for: the RATE checks must NOT be synthesised.
// A SYN burst far beyond any plausible syn-flood threshold still passes.
//
// WHAT THIS CELL CAN AND CANNOT SEE — measured, not assumed. Setting
// `syn_flood_threshold: 100` in conservative_default does NOT red this test.
// That is not a gap in the fixture, it is the structural guarantee showing
// through: the substituted path runs only STATELESS checks, because the rate
// checks need per-zone tracker and sketch state that does not exist for an
// unresolved zone, so a threshold set there is inert and unreachable. The cell
// that actually catches a synthesised threshold today is the field-level
// assertion in substituted_default_excludes_icmp_fragment_7168, which reds on
// exactly that mutation.
//
// This test is kept anyway, and the reason is worth stating: it guards the
// FUTURE change, not the current code. The day someone wires zone state into
// this path — giving the rate checks something to run against — the structural
// guarantee evaporates and this becomes the cell that notices. Presenting it as
// load-bearing against today's code would be overclaiming; deleting it would
// remove the only behavioural guard on the property that matters.
#[test]
fn substituted_default_does_not_synthesise_rate_checks_7168() {
    let mut state = missing_ref_state("trust", "ghost");
    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 2));
    let syn = tcp_pkt(src, dst, 5000, 80, TCP_SYN);
    for i in 0..5_000 {
        assert_eq!(
            state.check_packet("trust", &syn, 1),
            ScreenVerdict::Pass,
            "packet {i} of a 5000-SYN burst was dropped: the substitution synthesised a \
             rate threshold. It must not — a guessed flood threshold is site-specific and \
             would make this fix an availability incident, which is exactly why failing \
             CLOSED was rejected"
        );
    }
    assert_eq!(
        state.substituted_default_drops(),
        0,
        "no drops expected from a burst of well-formed SYNs"
    );
}

// Control: a zone with NO screen configured at all is a legitimate
// configuration, not a fault, and must still pass silently. Without this, a
// substitution that fired for every unresolved lookup — including zones that
// never referenced a screen — would pass every cell above while screening
// traffic the operator never asked to screen.
#[test]
fn zone_with_no_screen_configured_is_not_substituted_7168() {
    let mut state = ScreenState::new(); // no missing-refs entry at all
    let same = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    let land = tcp_pkt(same, same, 5000, 5000, TCP_SYN);
    assert_eq!(
        state.check_packet("trust", &land, 1),
        ScreenVerdict::Pass,
        "a zone with no screen configured must pass silently — substituting a default there \
         would enforce screens the operator never configured"
    );
    assert_eq!(state.substituted_default_drops(), 0);
    assert_eq!(
        state.missing_profile_warn_count(),
        0,
        "and it must not WARN either — there is no fault to report"
    );
}

// icmp-fragment is deliberately NOT in the substituted subset, even though it is
// a threshold-free bool that otherwise fits the rule. A fragmented ICMP packet
// is unusual but not malformed — a large ping legitimately fragments — so
// enabling it could black-hole traffic that is merely atypical. Pinned so the
// exclusion is a decision rather than an oversight someone "fixes" later.
#[test]
fn substituted_default_excludes_icmp_fragment_7168() {
    let p = ScreenProfile::conservative_default();
    assert!(!p.icmp_fragment, "icmp-fragment must stay disabled in the substituted default");
    assert!(p.land && p.teardrop && p.winnuke && p.syn_fin && p.no_flag);
    assert!(p.fin_no_ack && p.syn_frag && p.ping_death && p.source_route);
    // Every threshold disabled — the property the burst test exercises
    // behaviourally, stated here directly so a new threshold field added to the
    // struct is visibly off unless someone deliberately turns it on.
    assert_eq!(p.syn_flood_threshold, 0);
    assert_eq!(p.icmp_flood_threshold, 0);
    assert_eq!(p.udp_flood_threshold, 0);
    assert_eq!(p.port_scan_threshold, 0);
    assert_eq!(p.ip_sweep_threshold, 0);
    assert_eq!(p.session_limit_src, 0);
    assert_eq!(p.session_limit_dst, 0);
    assert!(!p.alarm_without_drop, "the substitute must DROP, not merely alarm");
}

// ---------------------------------------------------------------------------
// #7888 — the screen reference has THREE states, and the helper must tell all
// three apart.
//
// Before this change the helper held ONE map, `missing_profile_refs`, and it
// was doing the work of separating three states while carrying only one of
// them. An inert zone — profile defined, no check enabled — was in neither
// `zones` nor that map, so it fell out of `missing_profile_verdict` as a bare
// `Pass`: no substitution, no WARN, indistinguishable from a zone with no
// screen configured at all. The state that looks MORE correct to an operator
// had LESS protection than the one that looks broken.
//
// Each cell below asserts the verdict AND which warn counter moved. The counter
// is what makes "the right branch ran" falsifiable: a single shared counter
// would be satisfied by either branch, which is the merge this issue exists to
// prevent.
// ---------------------------------------------------------------------------

fn inert_ref_state(zone: &str, profile: &str) -> ScreenState {
    inert_ref_state_with_audit(zone, profile, false)
}

/// #9425: the same helper, with the profile's `alarm-without-drop` modifier
/// under the caller's control. `inert_ref_state` keeps the pre-#9425 shape
/// (audit OFF) so every #7888 cell built on it still asserts the hard-drop
/// posture verbatim.
fn inert_ref_state_with_audit(zone: &str, profile: &str, audit: bool) -> ScreenState {
    let mut state = ScreenState::new();
    let mut inert = FxHashMap::default();
    inert.insert(
        zone.to_string(),
        InertProfileRef {
            profile: profile.to_string(),
            alarm_without_drop: audit,
        },
    );
    state.update_inert_profiles(inert);
    state
}

// THE MIDDLE ROW. A LAND packet to an inert zone must be DROPPED by the same
// #7168 substituted conservative default an undefined reference gets.
//
// RED on revert: drop the `UnresolvedScreen::Inert` arm (or let
// `unresolved_screen_kind` consult only `missing_profile_refs`) and this
// returns `Pass`, which is exactly the pre-#7888 behaviour.
#[test]
fn inert_profile_gets_the_substituted_default_7888() {
    let mut state = inert_ref_state("trust", "p");
    let same = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    let land = tcp_pkt(same, same, 5000, 5000, TCP_SYN);
    assert!(
        matches!(
            state.check_packet("trust", &land, 1),
            ScreenVerdict::Drop(_)
        ),
        "a LAND packet to a zone whose screen profile is DEFINED but enables no check must \
         be dropped by the substituted conservative default — the consequence is identical \
         to an undefined reference, so the protection must be too"
    );
    assert_eq!(
        state.substituted_default_drops(),
        1,
        "an inert-zone drop is still the substitute doing the work, and must be counted as \
         such — the operator has a real configuration to fix either way"
    );
    assert_eq!(
        state.inert_profile_warn_count(),
        1,
        "the INERT warn must fire"
    );
    assert_eq!(
        state.missing_profile_warn_count(),
        0,
        "the undefined-profile warn must NOT fire for a defined profile — emitting it here \
         is the exact defect #7888 was filed for: its text is word-for-word the strict \
         commit-time error for a genuinely missing profile"
    );
}

// The flowless None branch is a SEPARATE call site. Fixing only the flow-present
// one leaves half the packets unprotected.
#[test]
fn inert_profile_substitutes_on_the_flowless_path_7888() {
    let mut state = inert_ref_state("trust", "p");
    let same = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    let land = flowless_icmp_pkt(same, same);
    assert!(
        matches!(
            state.check_flowless_screens("trust", &land, true, 1),
            ScreenVerdict::Drop(_)
        ),
        "the flowless branch must substitute for an inert zone too"
    );
}

// The third state, and the one that must NOT change: a zone with no `screen`
// statement is a legitimate configuration and passes silently. Without this cell
// the two maps could be replaced by "anything not in `zones`" and every other
// cell here would still pass — while every unscreened zone started dropping.
#[test]
fn zone_with_no_screen_still_passes_silently_7888() {
    let mut state = ScreenState::new();
    let same = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    let land = tcp_pkt(same, same, 5000, 5000, TCP_SYN);
    assert_eq!(
        state.check_packet("trust", &land, 1),
        ScreenVerdict::Pass,
        "a zone with NO screen configured must still pass — 'nothing enforced because \
         nothing was asked for' is a legitimate configuration, not a fault, and it is the \
         only arm that may pass without a signal"
    );
    assert_eq!(state.substituted_default_drops(), 0);
    assert_eq!(
        state.missing_profile_warn_count(),
        0,
        "no signal for a legit zone"
    );
    assert_eq!(
        state.inert_profile_warn_count(),
        0,
        "no signal for a legit zone"
    );
}

// The undefined state keeps its own warn and must not be re-routed through the
// inert branch. Together with the cell above this pins all three arms, so a
// change that COLLAPSES two of them cannot pass by satisfying only the ends.
#[test]
fn undefined_profile_keeps_its_own_warn_7888() {
    let mut state = missing_ref_state("trust", "ghost");
    let same = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    let land = tcp_pkt(same, same, 5000, 5000, TCP_SYN);
    assert!(matches!(
        state.check_packet("trust", &land, 1),
        ScreenVerdict::Drop(_)
    ));
    assert_eq!(state.missing_profile_warn_count(), 1);
    assert_eq!(
        state.inert_profile_warn_count(),
        0,
        "an undefined profile must not report itself as defined-but-inert"
    );
}

// The two WARN texts must be tellable apart by an OPERATOR, which is a property
// of the wording and not of the branch. The undefined text is word-for-word the
// strict commit-time validation error in
// `pkg/config/compiler_validate_strict_screen.go`; if the inert text also said
// "undefined" (or if the two were merely reworded versions of each other) the
// operator would still be sent to look for an `ids-option` stanza that is
// present, with no commit-time evidence to reconcile against — the same
// confusion in a new form.
#[test]
fn the_two_warn_texts_are_distinguishable_7888() {
    let undefined = missing_profile_warn_message("trust", "ghost");
    let inert = inert_profile_warn_message("trust", "p");

    assert_ne!(
        undefined, inert,
        "the two states must not render identically"
    );
    assert!(
        undefined.contains("references undefined"),
        "the undefined text is shipped and documented; this fix must not reword it: {undefined}"
    );
    assert!(
        !inert.contains("undefined"),
        "the inert text must NOT call a DEFINED profile undefined — that is the factual \
         error #7888 was filed about: {inert}"
    );
    assert!(
        inert.contains("IS DEFINED"),
        "the inert text must lead with the fact that contradicts the operator's likely \
         first guess: {inert}"
    );
    // Naming the cause is what makes the message actionable: the canonical way
    // into this state is configuring a MODIFIER and believing it enabled a check.
    assert!(
        inert.contains("modifier"),
        "the inert text must name the actual cause, not just the symptom: {inert}"
    );
    // Different remedy, not just different prose. "Upgrade the HA peer" is wrong
    // advice for a profile that is present and committed.
    assert!(
        !inert.contains("upgrade the HA peer"),
        "the inert remedy is to add a check or remove the screen statement, not to upgrade \
         a peer — the config is already what the operator intended to write: {inert}"
    );
    // Both must still name the zone and the profile, or the operator has nowhere
    // to go.
    for (label, msg) in [("undefined", &undefined), ("inert", &inert)] {
        assert!(
            msg.contains("trust"),
            "{label} text must name the zone: {msg}"
        );
    }
}

// #6860 closed an all-or-nothing hole: with NO resolved profiles the screen
// stage was skipped entirely, so the missing-profile WARN never fired. An
// inert-only config has the same shape — no `zones` entry and no missing ref —
// so `has_screen_state` has to see the inert map too, or the substituted default
// never runs for the very config this issue is about.
#[test]
fn has_screen_state_sees_an_inert_only_config_7888() {
    let state = inert_ref_state("trust", "p");
    assert!(
        state.has_screen_state(),
        "a config whose ONLY screen reference is inert must still activate the screen \
         stage — otherwise the stage is skipped and the substitution is unreachable, the \
         same all-or-nothing hole #6860 closed for undefined references"
    );
}

// ---------------------------------------------------------------------------
// #9114: the shim's non-first-fragment protocol sentinel must be recovered, or
// every protocol-keyed screen is evaluated against a protocol that is not the
// packet's.
// ---------------------------------------------------------------------------

/// #9114 (IPv4): a NON-FIRST fragment arrives with `protocol` = the shim's
/// `PROTO_FRAGMENT_NO_L4` sentinel (255), and `extract_screen_info` must
/// recover the datagram's real protocol from the IP header.
///
/// `userspace-xdp` substitutes the sentinel before `parse_l4`, and it rides
/// `meta.protocol` into the screens unchanged. `check_icmp_fragment`,
/// `icmp-flood` and `udp-flood` are all keyed on `protocol == PROTO_ICMP /
/// PROTO_ICMPV6 / PROTO_UDP`, so they never fired on the exact packets they
/// exist to police.
///
/// THE EXISTING FRAGMENT FIXTURES CANNOT CATCH THIS: they pass the REAL
/// protocol as the caller argument, which is a packet shape the shim never
/// emits for a non-first fragment. This cell passes the sentinel, as the shim
/// does.
#[test]
fn extract_recovers_real_protocol_for_v4_non_first_fragment_9114() {
    let mut frame = vec![0u8; 14 + 40];
    let ip = 14;
    frame[ip] = 0x45;
    frame[ip + 2..ip + 4].copy_from_slice(&40u16.to_be_bytes());
    // NON-first fragment: offset != 0 (185 * 8 bytes in), MF clear.
    frame[ip + 6..ip + 8].copy_from_slice(&185u16.to_be_bytes());
    frame[ip + 9] = 1; // real protocol = ICMP
    frame[ip + 12..ip + 16].copy_from_slice(&[1, 2, 3, 4]);
    frame[ip + 16..ip + 20].copy_from_slice(&[5, 6, 7, 8]);

    let info = extract_screen_info(
        &frame,
        libc::AF_INET as u8,
        255, // the shim's PROTO_FRAGMENT_NO_L4 sentinel
        0,
        40,
        IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
        0,
        0,
        14,
    )
    .expect("a non-first IPv4 fragment must still parse");

    assert!(info.is_fragment, "fixture precondition: offset != 0 is a fragment");
    assert!(
        !info.is_first_fragment,
        "fixture precondition: this must be a NON-first fragment, or the sentinel \
         would never have been substituted"
    );
    assert_eq!(
        info.protocol, 1,
        "the screens must see the datagram's REAL protocol (ICMP), not the shim's \
         255 sentinel — icmp-fragment and icmp-flood are keyed on it (#9114)"
    );
}

/// #9114 (IPv6): same recovery, from the FRAGMENT HEADER's own NextHdr field.
///
/// The v6 walk `break`s out on a non-first fragment before it would read
/// `nexthdr`, so the real protocol has to be taken from the fragment header
/// itself — a field present on every fragment, which is its purpose.
#[test]
fn extract_recovers_real_protocol_for_v6_non_first_fragment_9114() {
    // eth(14) + IPv6 base(40) + fragment header(8)
    let mut frame = vec![0u8; 14 + 40 + 8];
    let ip = 14;
    frame[ip] = 0x60; // version 6
    frame[ip + 4..ip + 6].copy_from_slice(&8u16.to_be_bytes()); // payload len
    frame[ip + 6] = 44; // next header = Fragment
    frame[ip + 7] = 64; // hop limit
    let fh = ip + 40;
    frame[fh] = 17; // fragment header NextHdr = UDP (the real protocol)
    // frag offset field: non-first (offset != 0), M bit clear.
    frame[fh + 2..fh + 4].copy_from_slice(&(185u16 << 3).to_be_bytes());

    let info = extract_screen_info(
        &frame,
        libc::AF_INET6 as u8,
        255, // the shim's sentinel
        0,
        48,
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)),
        0,
        0,
        14,
    )
    .expect("a non-first IPv6 fragment must still parse");

    assert!(info.is_fragment, "fixture precondition: a fragment");
    assert!(
        !info.is_first_fragment,
        "fixture precondition: NON-first fragment"
    );
    assert_eq!(
        info.protocol, 17,
        "the screens must see the datagram's REAL protocol (UDP) recovered from the \
         fragment header's NextHdr, not the shim's 255 sentinel — udp-flood is keyed \
         on it (#9114)"
    );
}

/// CONTROL: an ordinary packet's protocol is passed through UNTOUCHED.
///
/// The recovery is gated on the sentinel. Without this row a change that always
/// re-derived the protocol from the frame would satisfy both cells above while
/// overriding a caller that legitimately knew better (a decapsulated inner
/// packet, for one).
#[test]
fn extract_leaves_a_real_caller_protocol_untouched_9114() {
    let mut frame = vec![0u8; 14 + 40];
    let ip = 14;
    frame[ip] = 0x45;
    frame[ip + 2..ip + 4].copy_from_slice(&40u16.to_be_bytes());
    frame[ip + 6..ip + 8].copy_from_slice(&0u16.to_be_bytes()); // not a fragment
    frame[ip + 9] = 1; // header says ICMP
    frame[ip + 12..ip + 16].copy_from_slice(&[1, 2, 3, 4]);
    frame[ip + 16..ip + 20].copy_from_slice(&[5, 6, 7, 8]);

    let info = extract_screen_info(
        &frame,
        libc::AF_INET as u8,
        6, // caller says TCP, and the caller wins
        0x02,
        40,
        IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
        12345,
        80,
        14,
    )
    .expect("ordinary packet parses");
    assert_eq!(
        info.protocol, 6,
        "a non-sentinel caller protocol must be passed through unchanged — the \
         #9114 recovery is gated on the sentinel, not unconditional"
    );
}

// ===================== #9425 member 1 =====================
//
// An INERT zone (screen profile DEFINED, no check enabled) has no `zones`
// entry, so `alarm_without_drop`'s resolved lookup missed and every #7888
// substituted-default drop was ENFORCED — including for the operator who wrote
// `set security screen ids-option p alarm-without-drop` and nothing else, which
// is both the canonical route into the inert state and an explicit request for
// audit mode. The box did the exact inverse of what was configured, on a commit
// that reported success with zero warnings.
//
// #7888's decision is NOT being contested here: it chose drop over PASS for an
// inert zone, and that stands — the substituted checks still run, still count,
// and still warn. This changes only drop vs ALARM, and only for a zone that
// explicitly asked.

/// The fix. Same inert zone, same LAND packet, but the profile carries
/// `alarm-without-drop`: the verdict consumers must be told to suppress.
#[test]
fn inert_profile_honours_alarm_without_drop_9425() {
    let mut state = inert_ref_state_with_audit("trust", "p", true);
    let same = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    let land = tcp_pkt(same, same, 5000, 5000, TCP_SYN);

    // The check still RUNS and still produces a Drop verdict — that is what
    // carries the reason string into the alarm event and what keeps the
    // substituted-default counter honest. Only the consumer's disposition
    // changes, and `alarm_without_drop` is the switch it reads.
    assert!(
        matches!(
            state.check_packet("trust", &land, 1),
            ScreenVerdict::Drop(_)
        ),
        "the substituted check must still run and trip — #9425 changes the terminal \
         disposition, not whether the check happens"
    );
    assert_eq!(
        state.substituted_default_drops(),
        1,
        "the substitute is still doing the work and must still be counted"
    );
    assert!(
        state.alarm_without_drop("trust"),
        "an INERT zone whose DEFINED profile carries alarm-without-drop must report \
         audit mode; the consumers read exactly this to turn the Drop into a log-only \
         alarm plus a forward. Before #9425 the `zones` lookup missed and this was \
         false, so the operator's audit request produced hard drops"
    );
}

/// NEGATIVE CONTROL — the same inert zone WITHOUT the modifier must keep
/// #7888's hard-drop posture. Without this, "always return true" passes the
/// cell above and silently reverts #7888.
#[test]
fn inert_profile_without_the_modifier_still_hard_drops_9425() {
    let mut state = inert_ref_state("trust", "p");
    let same = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    let land = tcp_pkt(same, same, 5000, 5000, TCP_SYN);
    assert!(matches!(
        state.check_packet("trust", &land, 1),
        ScreenVerdict::Drop(_)
    ));
    assert!(
        !state.alarm_without_drop("trust"),
        "an inert zone that did NOT ask for audit mode must keep #7888's hard-drop \
         posture — this is the control that stops the fix from becoming a blanket \
         revert of #7888"
    );
}

/// SECOND NEGATIVE CONTROL — the UNDEFINED set must not inherit the meaning.
/// `ScreenMissingProfileRef` is shared by both wire sets; on the undefined set
/// there is no profile to have carried the modifier, so there is no operator
/// statement to honour and the zone must keep hard-dropping. A shared marshal
/// that leaked its meaning across the two sets would show up here.
#[test]
fn undefined_profile_never_reports_audit_mode_9425() {
    let mut state = ScreenState::new();
    let mut missing = FxHashMap::default();
    missing.insert("trust".to_string(), "ghost".to_string());
    state.update_missing_profiles(missing);
    // Also seed the INERT map for a DIFFERENT zone in audit mode, so the cell
    // fails if the lookup ever answers from the wrong set or ignores the key.
    let mut inert = FxHashMap::default();
    inert.insert(
        "dmz".to_string(),
        InertProfileRef {
            profile: "p".to_string(),
            alarm_without_drop: true,
        },
    );
    state.update_inert_profiles(inert);

    assert!(
        !state.alarm_without_drop("trust"),
        "a zone referencing an UNDEFINED profile has no operator audit statement to \
         honour and must keep hard-dropping the substituted default"
    );
    assert!(
        state.alarm_without_drop("dmz"),
        "POSITIVE CONTROL at the same instant: the inert audit zone IS in audit mode, \
         so the assertion above is a real scope boundary and not an empty map"
    );
}

/// A RESOLVED zone must be answered from its `zones` entry, not from a stale
/// inert reference. This is the precedence a two-source lookup can get wrong:
/// if a zone appears in both (a malformed or mid-transition snapshot), the
/// live profile is the authority.
#[test]
fn resolved_zone_profile_outranks_a_stale_inert_ref_9425() {
    let mut profile = ScreenProfile::default();
    profile.land = true;
    profile.alarm_without_drop = false;
    let mut state = make_state("trust", profile);
    let mut inert = FxHashMap::default();
    inert.insert(
        "trust".to_string(),
        InertProfileRef {
            profile: "p".to_string(),
            alarm_without_drop: true,
        },
    );
    state.update_inert_profiles(inert);
    assert!(
        !state.alarm_without_drop("trust"),
        "a zone with a published profile must be answered from that profile; the inert \
         map is the fallback for zones that have NO entry, not an override"
    );
}

// ===================== #9425 member 2 =====================
//
// `syn_cookie_active_until_secs` was inherited across `update_profiles`
// (#4969 preserves per-zone state; #2446 invalidates only the cookie
// GENERATION). So a zone that latched cookie-active under a live flood kept
// `locally_active` true after the operator committed `alarm-without-drop` TO
// STOP THE DROPS, and `validate_syn_cookie_ack_on_session_miss` — which checks
// syn_cookie, the threshold, the protocol and locally_active, but never
// alarm_without_drop — kept taking the `Invalid` arm for up to 64 s.
//
// The FRESHLY-configured audit case was already guarded and is untouched
// (`syn_cookie_alarm_without_drop_forwards_session_miss_ack_l10`). This is the
// ENFORCE -> AUDIT transition, which that guard cannot reach because the latch
// was set before the transition.

fn audit_transition_profile(alarm_without_drop: bool) -> ScreenProfile {
    let mut p = ScreenProfile::default();
    p.syn_flood_threshold = 1;
    p.syn_cookie = true;
    p.alarm_without_drop = alarm_without_drop;
    p
}

#[test]
fn enforce_to_audit_transition_clears_the_cookie_latch_9425() {
    let mut state = make_state("trust", audit_transition_profile(false));
    state.update_syn_cookie_master_key(Some(syn_cookie_key()));
    state.set_syn_cookie_full_epoch_for_test(1);

    let syn = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        49152,
        443,
        TCP_SYN,
    );
    // Drive the zone over its attack threshold so it LATCHES cookie-active.
    assert_eq!(
        state.check_packet_with_zone_id("trust", 7, &syn, 128),
        ScreenVerdict::Pass
    );
    assert!(matches!(
        state.check_packet_with_zone_id("trust", 7, &syn, 128),
        ScreenVerdict::SynCookieChallenge(_)
    ));

    // POSITIVE CONTROL, before the commit: the latch really is armed, so a
    // parse-invalid session-miss ACK is dropped as Invalid. Without this the
    // assertion after the commit is satisfied by a zone that was never latched.
    let mut bogus = syn.clone();
    bogus.tcp_flags = TCP_ACK;
    bogus.tcp_seq = 2;
    bogus.tcp_ack = 0xdead_beefu32;
    assert_eq!(
        state.validate_syn_cookie_ack_on_session_miss("trust", 7, &bogus, 128 * NS, 128),
        SynCookieAckVerdict::Invalid,
        "control: the zone must be latched cookie-active before the commit"
    );

    // The operator commits `alarm-without-drop` on this zone to stop the drops.
    let mut profiles = FxHashMap::default();
    profiles.insert("trust".to_string(), audit_transition_profile(true));
    state.update_profiles(profiles);

    // Same packet, same second. Under the defect the inherited latch kept
    // `locally_active` true and this stayed `Invalid` — a hard drop — for up to
    // EPOCH_SECS after the commit that was supposed to stop exactly that.
    assert_eq!(
        state.validate_syn_cookie_ack_on_session_miss("trust", 7, &bogus, 128 * NS, 128),
        SynCookieAckVerdict::NotApplicable,
        "after an ENFORCE -> AUDIT commit the inherited cookie-active latch must not \
         keep dropping session-miss ACKs (#9425 member 2)"
    );
}

/// NEGATIVE CONTROL for member 2 — an ordinary profile edit that does NOT turn
/// on audit mode must still inherit the latch (#4969). Without this, "clear the
/// latch on every update_profiles" passes the cell above while destroying the
/// per-zone state preservation #4969 exists for.
#[test]
fn a_non_audit_profile_edit_still_inherits_the_cookie_latch_9425() {
    let mut state = make_state("trust", audit_transition_profile(false));
    state.update_syn_cookie_master_key(Some(syn_cookie_key()));
    state.set_syn_cookie_full_epoch_for_test(1);

    let syn = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        49152,
        443,
        TCP_SYN,
    );
    assert_eq!(
        state.check_packet_with_zone_id("trust", 7, &syn, 128),
        ScreenVerdict::Pass
    );
    assert!(matches!(
        state.check_packet_with_zone_id("trust", 7, &syn, 128),
        ScreenVerdict::SynCookieChallenge(_)
    ));

    // An UNRELATED edit (enable teardrop): not a SYN-cookie-relevant field, so
    // neither the generation nor the latch may move.
    let mut edited = audit_transition_profile(false);
    edited.teardrop = true;
    let mut profiles = FxHashMap::default();
    profiles.insert("trust".to_string(), edited);
    state.update_profiles(profiles);

    let mut bogus = syn.clone();
    bogus.tcp_flags = TCP_ACK;
    bogus.tcp_seq = 2;
    bogus.tcp_ack = 0xdead_beefu32;
    assert_eq!(
        state.validate_syn_cookie_ack_on_session_miss("trust", 7, &bogus, 128 * NS, 128),
        SynCookieAckVerdict::Invalid,
        "a non-audit profile edit must still inherit the cookie-active latch (#4969); \
         clearing it on every update would silently disarm cookie mode mid-flood"
    );
}

// ===================== #9426: the legal last fragment =====================
//
// Every IP fragment except the LAST must be a multiple of 8 bytes; the last one
// may be any size. `check_teardrop` dropped ANY non-first fragment carrying 1-7
// bytes, so an IPv4 datagram whose length mod 1480 lands in 1-7 produced a legal
// last fragment the firewall dropped — and the receiver's reassembly then times
// out, so the WHOLE datagram is lost. No attacker is required.
//
// The discriminator was already in the struct and unused: `ip_frag_off` is the
// raw field, so MF (v4 0x2000, v6 the Fragment header's low bit) is in hand at
// this check. MF=0 is the last fragment.
//
// FAIL-ON-REVERT: remove the `more_fragments &&` gate from either arm of
// `check_teardrop` and every PASS cell below reds as an assertion.

/// A LEGAL last fragment (MF=0) at every size in the 1-7 band must PASS, on
/// both families. Swept rather than sampled: a fix that only admitted one size
/// would pass a single-value cell.
#[test]
fn teardrop_last_fragment_tiny_payload_passes_9426() {
    for payload in 1u16..8 {
        let mut profile = ScreenProfile::default();
        profile.teardrop = true;
        let mut state = make_state("trust", profile);
        let pkt = ipv4_fragment(
            IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
            PROTO_UDP,
            2,     // non-first fragment (offset 2 units = 16 bytes)
            false, // MF=0 — the LAST fragment, which may legally be any size
            20 + payload,
        );
        assert_eq!(
            state.check_packet("trust", &pkt, 1),
            ScreenVerdict::Pass,
            "a LAST IPv4 fragment carrying {payload} byte(s) is legal RFC 791 and must \
             not be dropped; dropping it loses the whole datagram when reassembly \
             times out"
        );
    }
}

#[test]
fn teardrop_v6_last_fragment_tiny_payload_passes_9426() {
    for payload in 1u16..8 {
        let mut profile = ScreenProfile::default();
        profile.teardrop = true;
        profile.udp_flood_threshold = 0;
        let mut state = make_state("trust", profile);
        let pkt = ipv6_fragment(
            IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()),
            IpAddr::V6("2001:db8::2".parse::<Ipv6Addr>().unwrap()),
            PROTO_UDP,
            2,     // non-first fragment (offset 2 units = 16 bytes)
            false, // M=0 — the LAST fragment
            8 + payload,
            8,
        );
        assert_eq!(
            state.check_packet("trust", &pkt, 1),
            ScreenVerdict::Pass,
            "a LAST IPv6 fragment carrying {payload} byte(s) is legal and must not be \
             dropped. This is the shape the pre-#9426 fixture of \
             teardrop_v6_tiny_non_first_fragment_drops actually described"
        );
    }
}

/// COMPANION: a NON-LAST fragment (MF=1) at the same sizes must STILL DROP.
/// Without this pair the fix is indistinguishable from deleting the `< 8` check
/// outright, which would lose a real malformed-fragment defence.
#[test]
fn teardrop_non_last_fragment_tiny_payload_still_drops_9426() {
    for payload in 1u16..8 {
        let mut profile = ScreenProfile::default();
        profile.teardrop = true;
        let mut state = make_state("trust", profile);
        let pkt = ipv4_fragment(
            IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
            PROTO_UDP,
            2,    // non-first fragment
            true, // MF=1 — a NON-LAST fragment must be an 8-byte multiple
            20 + payload,
        );
        assert_eq!(
            state.check_packet("trust", &pkt, 1),
            ScreenVerdict::Drop("teardrop"),
            "a NON-LAST IPv4 fragment carrying {payload} byte(s) violates the 8-byte \
             multiple rule and must still drop"
        );
    }
}

#[test]
fn teardrop_v6_non_last_fragment_tiny_payload_still_drops_9426() {
    for payload in 1u16..8 {
        let mut profile = ScreenProfile::default();
        profile.teardrop = true;
        profile.udp_flood_threshold = 0;
        let mut state = make_state("trust", profile);
        let pkt = ipv6_fragment(
            IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()),
            IpAddr::V6("2001:db8::2".parse::<Ipv6Addr>().unwrap()),
            PROTO_UDP,
            2,
            true, // M=1 — NON-LAST
            8 + payload,
            8,
        );
        assert_eq!(
            state.check_packet("trust", &pkt, 1),
            ScreenVerdict::Drop("teardrop"),
            "a NON-LAST IPv6 fragment carrying {payload} byte(s) must still drop"
        );
    }
}

/// The #3027 arm is UNGATED and must stay so: a non-first fragment contributing
/// ZERO (or under-length) data is malformed whatever MF says — a last fragment
/// with nothing in it is not a legal tail. Gating this arm on MF too would be
/// the over-correction, and this is the cell that catches it.
#[test]
fn teardrop_zero_payload_last_fragment_still_drops_9426() {
    for (label, total_len) in [("zero payload", 20u16), ("under-length", 18u16)] {
        let mut profile = ScreenProfile::default();
        profile.teardrop = true;
        let mut state = make_state("trust", profile);
        let pkt = ipv4_fragment(
            IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
            PROTO_UDP,
            2,
            false, // MF=0 — a LAST fragment, and still malformed
            total_len,
        );
        assert_eq!(
            state.check_packet("trust", &pkt, 1),
            ScreenVerdict::Drop("teardrop"),
            "{label}: the #3027 arm must NOT be gated on MF — a last fragment that \
             contributes no data is not a legal tail"
        );
    }
}

#[test]
fn teardrop_v6_zero_payload_last_fragment_still_drops_9426() {
    let mut profile = ScreenProfile::default();
    profile.teardrop = true;
    profile.udp_flood_threshold = 0;
    let mut state = make_state("trust", profile);
    let pkt = ipv6_fragment(
        IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()),
        IpAddr::V6("2001:db8::2".parse::<Ipv6Addr>().unwrap()),
        PROTO_UDP,
        2,
        false, // M=0 — a LAST fragment
        4,     // payload_len < frag_data_off (8) → saturating_sub → 0
        8,
    );
    assert_eq!(
        state.check_packet("trust", &pkt, 1),
        ScreenVerdict::Drop("teardrop"),
        "the IPv6 analogue of the #3027 arm must NOT be gated on M either"
    );
}

/// POSITIVE CONTROL retained from the boundary: exactly 8 bytes passes on BOTH
/// MF values. Keeps the pre-#9426 boundary cell's claim alive in the shape that
/// survives, and proves the sweeps above are not measuring a check that stopped
/// firing altogether.
#[test]
fn teardrop_eight_byte_fragment_passes_either_way_9426() {
    for more in [false, true] {
        let mut profile = ScreenProfile::default();
        profile.teardrop = true;
        let mut state = make_state("trust", profile);
        let pkt = ipv4_fragment(
            IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
            PROTO_UDP,
            2,
            more,
            28, // 20-byte header + exactly 8 payload bytes
        );
        assert_eq!(
            state.check_packet("trust", &pkt, 1),
            ScreenVerdict::Pass,
            "8 bytes is the first legal size for a NON-LAST fragment and is legal for a \
             last one too (more_fragments={more})"
        );
    }
}

// ---------------------------------------------------------------------------
// #9173: the SYN-cookie key ring. The helper derives each period's key from a
// published base and picks a key by each cookie's own epoch.
// ---------------------------------------------------------------------------

const RING_PERIOD_EPOCHS_9173: u64 = 56;
const RING_PERIOD_SECS_9173: u64 = RING_PERIOD_EPOCHS_9173 * SynCookieCodec::EPOCH_SECS;
/// The rotation epoch the cells run in, and its first cookie epoch.
const RING_ROTATION_9173: u64 = 1000;
const RING_FIRST_EPOCH_9173: u64 = RING_ROTATION_9173 * RING_PERIOD_EPOCHS_9173;
const LEGACY_KEY_9173: [u8; 16] = [0xee; 16];
const RING_BASE_9173: [u8; 32] = [0x5a; 32];

/// The key the published base derives for `rotation_epoch`.
fn ring_key_9173(rotation_epoch: u64) -> [u8; 16] {
    SynCookieKeyRing::derive_epoch_key(&RING_BASE_9173, rotation_epoch)
}

/// What a control plane publishes: one primary base, whatever the period.
fn published_ring_9173() -> SynCookieKeyRing {
    SynCookieKeyRing::new(RING_PERIOD_SECS_9173, [(RING_BASE_9173, false)])
}

fn ring_state_9173(ring: SynCookieKeyRing, full_epoch: u64) -> ScreenState {
    let mut profile = ScreenProfile::default();
    profile.syn_flood_threshold = 1;
    profile.syn_cookie = true;
    let mut state = make_state("trust", profile);
    state.update_syn_cookie_keys(Some(LEGACY_KEY_9173), ring);
    state.set_syn_cookie_full_epoch_for_test(full_epoch);
    state
}

fn ring_syn_9173() -> ScreenPacketInfo {
    tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        49152,
        443,
        TCP_SYN,
    )
}

/// The ACK completing a handshake whose cookie `key` minted in `full_epoch`.
fn ring_ack_9173(key: [u8; 16], full_epoch: u64) -> ScreenPacketInfo {
    let syn = ring_syn_9173();
    let cookie_isn = SynCookieCodec::new(key).mint_isn(
        SynCookieTuple::from_packet(&syn),
        syn_cookie_zone_tag("trust"),
        full_epoch,
        syn.tcp_mss,
    );
    let mut ack = syn.clone();
    ack.tcp_flags = TCP_ACK;
    ack.tcp_seq = 2;
    ack.tcp_ack = cookie_isn.wrapping_add(1);
    ack
}

fn ring_verdict_9173(state: &mut ScreenState, ack: &ScreenPacketInfo) -> SynCookieAckVerdict {
    state.validate_syn_cookie_ack_on_session_miss("trust", 7, ack, 128 * NS, 128)
}

/// Drive SYNs through the flood gate until it answers with a cookie challenge.
fn mint_challenge_isn_9173(state: &mut ScreenState) -> u32 {
    mint_challenge_isn_at_step_9173(state, "")
}

/// As `mint_challenge_isn_9173`, naming `step` in the panic, so a cell that mints
/// more than once says which mint failed.
fn mint_challenge_isn_at_step_9173(state: &mut ScreenState, step: &str) -> u32 {
    let syn = ring_syn_9173();
    for _ in 0..8 {
        if let ScreenVerdict::SynCookieChallenge(challenge) =
            state.check_packet_with_zone_id("trust", 7, &syn, 100)
        {
            return challenge.cookie_isn;
        }
    }
    panic!("the SYN-flood gate never minted a cookie challenge{step}");
}

fn minted_by_9173(key: [u8; 16], full_epoch: u64, cookie_isn: u32) -> bool {
    SynCookieCodec::new(key)
        .validate_isn_at_epoch(
            SynCookieTuple::from_packet(&ring_syn_9173()),
            syn_cookie_zone_tag("trust"),
            full_epoch,
            cookie_isn,
        )
        .is_some()
}

#[test]
fn syn_cookie_ring_accepts_the_previous_periods_key_across_the_boundary_9173() {
    // Minted in the LAST cookie epoch of the previous period ...
    let ack = ring_ack_9173(
        ring_key_9173(RING_ROTATION_9173 - 1),
        RING_FIRST_EPOCH_9173 - 1,
    );
    // ... and validated in the FIRST cookie epoch of the current one.
    let mut state = ring_state_9173(published_ring_9173(), RING_FIRST_EPOCH_9173);
    assert_eq!(
        ring_verdict_9173(&mut state, &ack),
        SynCookieAckVerdict::Validated,
        "key(e-1) must still validate a cookie minted in its own period"
    );
}

#[test]
fn syn_cookie_ring_accepts_a_cookie_from_the_next_period_9173() {
    // A peer whose clock is just ahead minted in the FIRST cookie epoch of the
    // next period, while this node is still in the LAST cookie epoch of this one.
    let next_first = RING_FIRST_EPOCH_9173 + RING_PERIOD_EPOCHS_9173;
    let ack = ring_ack_9173(ring_key_9173(RING_ROTATION_9173 + 1), next_first);
    let mut state = ring_state_9173(published_ring_9173(), next_first - 1);
    assert_eq!(
        ring_verdict_9173(&mut state, &ack),
        SynCookieAckVerdict::Validated,
        "key(e+1) must validate a cookie a peer just across the boundary minted in its own period"
    );
}

#[test]
fn syn_cookie_ring_refuses_a_key_two_periods_old_9173() {
    let epoch = RING_FIRST_EPOCH_9173 + 3;
    let mut control = ring_state_9173(published_ring_9173(), epoch);
    assert_eq!(
        ring_verdict_9173(
            &mut control,
            &ring_ack_9173(ring_key_9173(RING_ROTATION_9173), epoch)
        ),
        SynCookieAckVerdict::Validated,
        "premise: the current period's key validates in this state"
    );
    let mut state = ring_state_9173(published_ring_9173(), epoch);
    assert_ne!(
        ring_verdict_9173(
            &mut state,
            &ring_ack_9173(ring_key_9173(RING_ROTATION_9173 - 2), epoch)
        ),
        SynCookieAckVerdict::Validated,
        "key(e-2) must be refused"
    );
    // That refusal holds by epoch selection alone: a cookie's epoch stays within
    // one cookie epoch of the clock, so no accepted cookie names period e-2. The
    // doc also says key(e-2) is never DERIVED, which only this pins.
    assert_eq!(
        state.syn_cookie_key_ring.derived_rotation_epochs(),
        vec![
            RING_ROTATION_9173 - 1,
            RING_ROTATION_9173,
            RING_ROTATION_9173 + 1
        ],
        "refresh must derive only the adjacent periods: key(e-2) is never derived"
    );
}

#[test]
fn syn_cookie_ring_key_validates_only_its_own_period_9173() {
    let epoch = RING_FIRST_EPOCH_9173 + 3;
    for (key, what) in [
        (ring_key_9173(RING_ROTATION_9173 - 1), "the previous period's key"),
        (ring_key_9173(RING_ROTATION_9173 + 1), "the next period's key"),
        (LEGACY_KEY_9173, "the legacy key, in a period the ring covers"),
    ] {
        let mut state = ring_state_9173(published_ring_9173(), epoch);
        assert_ne!(
            ring_verdict_9173(&mut state, &ring_ack_9173(key, epoch)),
            SynCookieAckVerdict::Validated,
            "{what} must not validate a cookie minted in the current period: one key \
             per period keeps a forger at one MAC per ACK"
        );
    }
}

#[test]
fn syn_cookie_ring_mints_with_the_current_periods_key_9173() {
    let epoch = RING_FIRST_EPOCH_9173 + 3;
    let mut state = ring_state_9173(published_ring_9173(), epoch);
    let isn = mint_challenge_isn_9173(&mut state);
    assert!(
        minted_by_9173(ring_key_9173(RING_ROTATION_9173), epoch, isn),
        "a ring covering this period must mint with that period's key"
    );
    assert!(
        !minted_by_9173(LEGACY_KEY_9173, epoch, isn),
        "a ring covering this period must not mint with the legacy key"
    );
}

#[test]
fn syn_cookie_ring_psk_window_accepts_the_old_key_but_never_mints_with_it_9173() {
    let epoch = RING_FIRST_EPOCH_9173 + 3;
    let old_base = [0x0d; 32];
    let old_key = SynCookieKeyRing::derive_epoch_key(&old_base, RING_ROTATION_9173);
    let new_key = ring_key_9173(RING_ROTATION_9173);
    // The accept-only base comes FIRST, so minting must skip its key, not take it.
    let window_ring = || {
        SynCookieKeyRing::new(
            RING_PERIOD_SECS_9173,
            [(old_base, true), (RING_BASE_9173, false)],
        )
    };
    let mut state = ring_state_9173(window_ring(), epoch);
    assert_eq!(
        ring_verdict_9173(&mut state, &ring_ack_9173(old_key, epoch)),
        SynCookieAckVerdict::Validated,
        "an additional-authentication-key cookie must validate during a #6630 rotation window"
    );
    let mut minting = ring_state_9173(window_ring(), epoch);
    let isn = mint_challenge_isn_9173(&mut minting);
    assert!(
        minted_by_9173(new_key, epoch, isn),
        "mint must use the primary key"
    );
    assert!(
        !minted_by_9173(old_key, epoch, isn),
        "an accept-only key must never mint"
    );
}

/// Drive SYNs through the flood gate and return every verdict.
fn mint_verdicts_9173(state: &mut ScreenState) -> Vec<ScreenVerdict> {
    let syn = ring_syn_9173();
    (0..8)
        .map(|_| state.check_packet_with_zone_id("trust", 7, &syn, 100))
        .collect()
}

#[test]
fn syn_cookie_ring_rotates_without_a_republish_9173() {
    // One ring, published three periods ago and never republished.
    let early = RING_FIRST_EPOCH_9173 - 3 * RING_PERIOD_EPOCHS_9173;
    let mut state = ring_state_9173(published_ring_9173(), early);
    let isn = mint_challenge_isn_at_step_9173(
        &mut state,
        ": premise, in the period the ring was published in",
    );
    assert!(
        minted_by_9173(ring_key_9173(RING_ROTATION_9173 - 3), early, isn),
        "premise: the ring mints with the key of the period it was published in"
    );
    let epoch = RING_FIRST_EPOCH_9173 + 3;
    state.set_syn_cookie_full_epoch_for_test(epoch);
    let isn = mint_challenge_isn_at_step_9173(
        &mut state,
        ": after rotating three periods without a republish",
    );
    assert!(
        minted_by_9173(ring_key_9173(RING_ROTATION_9173), epoch, isn),
        "the same ring must derive and mint with the current period's key: rotation needs no republish"
    );
    assert!(
        !minted_by_9173(ring_key_9173(RING_ROTATION_9173 - 3), epoch, isn),
        "it must not keep minting with the key it derived three periods ago"
    );
}

#[test]
fn syn_cookie_present_ring_without_a_base_fails_closed_9173() {
    let empty = || SynCookieKeyRing::new(RING_PERIOD_SECS_9173, std::iter::empty::<([u8; 32], bool)>());
    let epoch = RING_FIRST_EPOCH_9173 + 3;
    let mut minting = ring_state_9173(empty(), epoch);
    let verdicts = mint_verdicts_9173(&mut minting);
    assert!(
        verdicts.contains(&ScreenVerdict::Drop("syn-cookie-unavailable"))
            && !verdicts
                .iter()
                .any(|v| matches!(v, ScreenVerdict::SynCookieChallenge(_))),
        "a published ring with no base must fail closed, not mint with the legacy key: {verdicts:?}"
    );
    let mut state = ring_state_9173(empty(), epoch);
    assert_ne!(
        ring_verdict_9173(&mut state, &ring_ack_9173(LEGACY_KEY_9173, epoch)),
        SynCookieAckVerdict::Validated,
        "the legacy key must not validate through a present ring with no base"
    );
}

#[test]
fn syn_cookie_absent_ring_uses_the_legacy_key_9173() {
    // An older control plane sends no ring at all.
    let epoch = RING_FIRST_EPOCH_9173 + 3;
    let mut minting = ring_state_9173(SynCookieKeyRing::default(), epoch);
    let isn = mint_challenge_isn_9173(&mut minting);
    assert!(
        minted_by_9173(LEGACY_KEY_9173, epoch, isn),
        "an absent ring must mint with the legacy key"
    );
    let mut state = ring_state_9173(SynCookieKeyRing::default(), epoch);
    assert_eq!(
        ring_verdict_9173(&mut state, &ring_ack_9173(LEGACY_KEY_9173, epoch)),
        SynCookieAckVerdict::Validated,
        "an absent ring must validate with the legacy key"
    );
}

#[test]
fn syn_cookie_ring_with_a_period_off_the_cookie_epoch_fails_closed_9173() {
    for period_secs in [0, 100, SynCookieCodec::EPOCH_SECS + 1] {
        let mut ring = SynCookieKeyRing::new(period_secs, [([1; 32], false)]);
        ring.refresh(0);
        assert!(
            ring.is_present() && ring.mint_codec(0).is_none(),
            "a {period_secs}s period is not a whole number of cookie epochs: the ring must stay present with no usable key"
        );
        let mut state = ring_state_9173(ring, 0);
        let verdicts = mint_verdicts_9173(&mut state);
        assert!(
            !verdicts
                .iter()
                .any(|v| matches!(v, ScreenVerdict::SynCookieChallenge(_))),
            "a malformed ring must fail closed, not fall back to the legacy key: {verdicts:?}"
        );
    }
}

#[test]
fn syn_cookie_cleared_legacy_key_fails_closed_even_with_a_ring_9173() {
    let epoch = RING_FIRST_EPOCH_9173 + 3;
    let mut profile = ScreenProfile::default();
    profile.syn_flood_threshold = 1;
    profile.syn_cookie = true;
    let mut state = make_state("trust", profile);
    state.update_syn_cookie_keys(None, published_ring_9173());
    state.set_syn_cookie_full_epoch_for_test(epoch);
    let syn = ring_syn_9173();
    let verdicts: Vec<_> = (0..4)
        .map(|_| state.check_packet_with_zone_id("trust", 7, &syn, 100))
        .collect();
    assert!(
        !verdicts
            .iter()
            .any(|v| matches!(v, ScreenVerdict::SynCookieChallenge(_))),
        "no legacy key must mean no cookie, ring or not: {verdicts:?}"
    );
    assert_ne!(
        ring_verdict_9173(
            &mut state,
            &ring_ack_9173(ring_key_9173(RING_ROTATION_9173), epoch)
        ),
        SynCookieAckVerdict::Validated
    );
}

#[test]
fn syn_cookie_ring_debug_never_renders_a_key_9173() {
    let mut ring = SynCookieKeyRing::new(RING_PERIOD_SECS_9173, [([0xab; 32], false)]);
    ring.refresh(RING_FIRST_EPOCH_9173);
    let rendered = format!("{ring:?}");
    assert!(
        rendered.contains("<redacted>") && !rendered.contains("171"),
        "{rendered}"
    );
}

#[test]
fn syn_cookie_epoch_key_matches_the_control_plane_derivation_9173() {
    // TestSYNCookieEpochKeyMatchesTheHelper9173 asserts the same vector in Go.
    let mut base = [0u8; 32];
    for (i, byte) in base.iter_mut().enumerate() {
        *byte = i as u8;
    }
    let hex: String = SynCookieKeyRing::derive_epoch_key(&base, 502_232)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(
        hex, "a028081b51656faa6cd12471864df2c5",
        "the helper must derive the control plane's period key"
    );
}

/// A state whose cookie epoch comes from the latch and a test-set wall clock,
/// not from the epoch override.
fn latched_ring_state_9173(ring: SynCookieKeyRing, latched_epoch: u64, wall_epoch: u64) -> ScreenState {
    let mut profile = ScreenProfile::default();
    profile.syn_flood_threshold = 1;
    profile.syn_cookie = true;
    let mut state = make_state("trust", profile);
    state.update_syn_cookie_keys(Some(LEGACY_KEY_9173), ring);
    state.syn_cookie_last_full_epoch = latched_epoch;
    state.syn_cookie_epoch_wall_secs = wall_epoch * SynCookieCodec::EPOCH_SECS + 1;
    // The mints below pass now_secs = 100, so the wall clock is not re-read.
    state.syn_cookie_epoch_clock_mono_secs = 100;
    state
}

/// The ACK completing a handshake whose challenge minted `cookie_isn`.
fn ack_for_isn_9173(cookie_isn: u32) -> ScreenPacketInfo {
    let mut ack = ring_syn_9173();
    ack.tcp_flags = TCP_ACK;
    ack.tcp_seq = 2;
    ack.tcp_ack = cookie_isn.wrapping_add(1);
    ack
}

#[test]
fn syn_cookie_latch_never_steps_back_9173() {
    // Derived keys cover every epoch, so the latch holds through any backward
    // step and mints with its own latched period's key.
    let wall = RING_FIRST_EPOCH_9173 + 3;
    for step in [1, 2, 3 * RING_PERIOD_EPOCHS_9173] {
        let latched = wall + step;
        let mut state = latched_ring_state_9173(published_ring_9173(), latched, wall);
        let isn = mint_challenge_isn_9173(&mut state);
        assert!(
            minted_by_9173(ring_key_9173(latched / RING_PERIOD_EPOCHS_9173), latched, isn),
            "after a {step}-epoch backward step the latch must hold and mint with its own period's key"
        );
    }
}

#[test]
fn syn_cookie_backward_step_does_not_resurrect_a_past_cookie_9173() {
    // A cookie minted at `wall`; the node's clock then advanced to `latched` and
    // stepped back to `wall`. Re-accepting the cookie would let a recorded ACK
    // validate again and re-install its source's whitelist entry.
    let wall = RING_FIRST_EPOCH_9173 + 3;
    for ring in [published_ring_9173(), SynCookieKeyRing::default()] {
        let key = if ring.is_present() {
            ring_key_9173(RING_ROTATION_9173)
        } else {
            LEGACY_KEY_9173
        };
        let ack = ring_ack_9173(key, wall);
        let mut control = ring_state_9173(ring.clone(), wall);
        assert_eq!(
            ring_verdict_9173(&mut control, &ack),
            SynCookieAckVerdict::Validated,
            "premise: the cookie validates in the epoch it was minted in"
        );
        let mut state = latched_ring_state_9173(ring, wall + 5, wall);
        // ring_verdict_9173 passes now_secs = 128: pin the clock gate to it so the
        // validation reads the stepped-back `wall`, not the host's real clock.
        state.syn_cookie_epoch_clock_mono_secs = 128;
        assert_ne!(
            ring_verdict_9173(&mut state, &ack),
            SynCookieAckVerdict::Validated,
            "after a backward clock step, a cookie from an epoch this node already left must not validate again"
        );
    }
}

/// #9740: a state screening `zones`, all with a syn-flood threshold of 1 and SYN
/// cookies on, keyed from the published #9173 ring and pinned to `epoch`.
fn zones_state_9740(zones: &[&str], epoch: u64) -> ScreenState {
    let mut state = ScreenState::new();
    let mut profiles = FxHashMap::default();
    for zone in zones {
        let mut profile = ScreenProfile::default();
        profile.syn_flood_threshold = 1;
        profile.syn_cookie = true;
        profiles.insert((*zone).to_string(), profile);
    }
    state.update_profiles(profiles);
    state.update_syn_cookie_keys(Some(LEGACY_KEY_9173), published_ring_9173());
    state.set_syn_cookie_full_epoch_for_test(epoch);
    state
}

/// Drive `ring_syn_9173()` through `zone`'s flood gate until it mints a cookie.
fn mint_in_zone_9740(state: &mut ScreenState, zone: &str) -> u32 {
    let syn = ring_syn_9173();
    for _ in 0..8 {
        if let ScreenVerdict::SynCookieChallenge(challenge) =
            state.check_packet_with_zone_id(zone, 7, &syn, 100)
        {
            return challenge.cookie_isn;
        }
    }
    panic!("the SYN-flood gate in zone {zone} never minted a cookie challenge");
}

#[test]
fn syn_cookie_zone_tag_matches_its_known_answers_9740() {
    // Computed independently of this crate, by Python's hashlib (SHA-256 over the
    // label, the big-endian u64 name length and the name). Every node must derive
    // the same tag from the same zone name, or a cookie fails on its peer.
    let vectors: [(&str, [u64; 2]); 4] = [
        ("trust", [0x1aba_0b6c_d3d9_e26c, 0x4f25_84ec_784a_79df]),
        ("z174", [0x59b7_3d0d_4599_c856, 0xecb2_8035_0e17_a855]),
        ("z214", [0x3203_9774_5ec7_fc64, 0x0ce5_66c2_ac63_46ff]),
        ("", [0xe554_9b85_9775_a4da, 0xe61f_c3af_b059_d1e5]),
    ];
    for (zone, want) in vectors {
        assert_eq!(syn_cookie_zone_tag(zone), want, "zone tag of {zone:?}");
    }
}

#[test]
fn syn_cookie_zones_whose_ids_collide_share_neither_cookies_nor_whitelist_9740() {
    // z174 and z214 fold to the same StableZoneID (the premise of
    // pkg/cli/apply_syslog_zonemap_3704_test.go); here both carry zone_id 7.
    // #9740 dropped the screened-zone set from the key base, so what keeps a
    // cookie minted in one from validating, or whitelisting its client, in the
    // other is the cookie's binding to the zone NAME.
    let epoch = RING_FIRST_EPOCH_9173 + 3;
    let mut node = zones_state_9740(&["z174", "z214"], epoch);
    let ack = ack_for_isn_9173(mint_in_zone_9740(&mut node, "z174"));

    assert_ne!(
        node.validate_syn_cookie_ack_on_session_miss("z214", 7, &ack, 128 * NS, 128),
        SynCookieAckVerdict::Validated,
        "a cookie minted in z174 must not validate in z214, whose zone ID collides"
    );
    let mut peer_other = zones_state_9740(&["z214"], epoch);
    assert_ne!(
        peer_other.validate_syn_cookie_ack_on_session_miss("z214", 7, &ack, 128 * NS, 128),
        SynCookieAckVerdict::Validated,
        "a peer screening only z214 must not validate a z174 cookie"
    );
    let mut peer_same = zones_state_9740(&["z174"], epoch);
    assert_eq!(
        peer_same.validate_syn_cookie_ack_on_session_miss("z174", 7, &ack, 128 * NS, 128),
        SynCookieAckVerdict::Validated,
        "control: a peer that has the same zone validates the cookie"
    );

    assert_eq!(
        node.validate_syn_cookie_ack_on_session_miss("z174", 7, &ack, 128 * NS, 128),
        SynCookieAckVerdict::Validated,
        "premise: the cookie validates in the zone it was minted in"
    );
    let mut retry = ring_syn_9173();
    retry.src_port = retry.src_port.wrapping_add(1);
    assert_eq!(
        node.check_packet_with_zone_id("z174", 7, &retry, 128),
        ScreenVerdict::SynCookieBypass,
        "control: the whitelisted client bypasses the gate in its own zone"
    );
    assert_ne!(
        node.check_packet_with_zone_id("z214", 7, &retry, 128),
        ScreenVerdict::SynCookieBypass,
        "a client whitelisted in z174 must not bypass the SYN-flood gate in z214"
    );
}

#[test]
fn syn_cookie_a_removed_and_recreated_zone_does_not_inherit_its_whitelist_9740() {
    // The validated cache outlives a removed zone for up to one cookie epoch, and
    // a re-created zone used to start at generation 1 again, so a client
    // whitelisted in the old zone bypassed the new zone's gate.
    let epoch = RING_FIRST_EPOCH_9173 + 3;
    let mut node = zones_state_9740(&["trust", "dmz"], epoch);
    let ack = ack_for_isn_9173(mint_in_zone_9740(&mut node, "trust"));
    assert_eq!(
        node.validate_syn_cookie_ack_on_session_miss("trust", 7, &ack, 128 * NS, 128),
        SynCookieAckVerdict::Validated,
        "premise: the cookie validates in the zone it was minted in"
    );
    let mut retry = ring_syn_9173();
    retry.src_port = retry.src_port.wrapping_add(1);
    assert_eq!(
        node.check_packet_with_zone_id("trust", 7, &retry, 128),
        ScreenVerdict::SynCookieBypass,
        "control: the whitelisted client bypasses the gate while its zone exists"
    );

    let profiles = |zones: &[&str]| {
        zones
            .iter()
            .map(|zone| {
                let mut profile = ScreenProfile::default();
                profile.syn_flood_threshold = 1;
                profile.syn_cookie = true;
                ((*zone).to_string(), profile)
            })
            .collect::<FxHashMap<_, _>>()
    };
    node.update_profiles(profiles(&["dmz"]));
    node.update_profiles(profiles(&["trust", "dmz"]));
    assert_ne!(
        node.check_packet_with_zone_id("trust", 7, &retry, 128),
        ScreenVerdict::SynCookieBypass,
        "a client whitelisted before its zone was removed must not bypass the re-created zone's gate"
    );
}

/// #9740: a cookie ISN rebuilt from its documented parts, independently of
/// `SynCookieCodec`. `identity` absorbs the zone into both the per-epoch secret
/// and the MAC. With the zone tag it must reproduce `mint_isn`; with the 16-bit
/// zone id it is a cookie from a helper that predates #9740.
fn documented_cookie_isn_9740(
    master_key: [u8; 16],
    tuple: SynCookieTuple,
    identity: &dyn Fn(&mut SipHash24),
    full_epoch: u64,
    peer_mss: u16,
) -> u32 {
    let k0 = u64::from_le_bytes(master_key[0..8].try_into().expect("fixed slice"));
    let k1 = u64::from_le_bytes(master_key[8..16].try_into().expect("fixed slice"));
    let secret = |domain: &[u8; 8]| {
        let mut sip = SipHash24::new(k0, k1);
        sip.write_u64(u64::from_be_bytes(*domain));
        identity(&mut sip);
        sip.write_u64(full_epoch);
        sip.finish()
    };
    let mss_index = SynCookieCodec::mss_index(peer_mss);
    let mut sip = SipHash24::new(secret(b"xpf-sck0"), secret(b"xpf-sck1"));
    sip.write_u64(u64::from_be_bytes(*b"xpf-sync"));
    identity(&mut sip);
    sip.write_u64(full_epoch);
    sip.write_u8(mss_index);
    sip.write_ip(tuple.src_ip);
    sip.write_ip(tuple.dst_ip);
    sip.write_u16(tuple.src_port);
    sip.write_u16(tuple.dst_port);
    let mac = (sip.finish() as u32) & ((1u32 << SYN_COOKIE_MSS_SHIFT) - 1);
    ((full_epoch as u32 & SYN_COOKIE_EPOCH_MASK) << SYN_COOKIE_EPOCH_SHIFT)
        | ((mss_index as u32 & SYN_COOKIE_MSS_MASK) << SYN_COOKIE_MSS_SHIFT)
        | mac
}

#[test]
fn syn_cookie_mint_binds_the_zone_tag_twice_and_refuses_a_pre_9740_cookie_9740() {
    // The per-epoch secret and the MAC each absorb the zone, so dropping either
    // binding alone leaves every behavioural cell green. Requiring mint_isn to
    // equal the ISN rebuilt from its documented parts pins both bindings.
    let key = *b"xpf-9740-mac-key";
    let codec = SynCookieCodec::new(key);
    let tuple = SynCookieTuple {
        src_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
        src_port: 40_000,
        dst_port: 443,
    };
    let full_epoch = 0x0000_0001_2345_6789u64;
    for zone in ["trust", "z174", "z214"] {
        let tag = syn_cookie_zone_tag(zone);
        let with_tag = |sip: &mut SipHash24| {
            sip.write_u64(tag[0]);
            sip.write_u64(tag[1]);
        };
        for peer_mss in [536u16, 1460, 9000] {
            assert_eq!(
                codec.mint_isn(tuple, tag, full_epoch, peer_mss),
                documented_cookie_isn_9740(key, tuple, &with_tag, full_epoch, peer_mss),
                "mint_isn in {zone} (mss {peer_mss}) must bind the zone tag in the secret and in the MAC"
            );
        }
    }

    // A helper from before #9740 absorbed the 16-bit zone id instead, so the two
    // refuse each other's cookies from the first one, whatever key they share.
    let tag = syn_cookie_zone_tag("trust");
    let validates = |isn: u32| codec.validate_isn(tuple, tag, full_epoch, isn).is_some();
    let new_isn = codec.mint_isn(tuple, tag, full_epoch, 1460);
    assert!(
        validates(new_isn),
        "control: this helper validates its own cookie"
    );
    let with_id = |sip: &mut SipHash24| sip.write_u16(7);
    let old_isn = documented_cookie_isn_9740(key, tuple, &with_id, full_epoch, 1460);
    assert!(
        !validates(old_isn),
        "a cookie minted by a pre-#9740 helper must not validate on this one"
    );
    assert_ne!(
        new_isn, old_isn,
        "a pre-#9740 helper computes a different MAC for this helper's cookie, so it refuses it"
    );
}

#[test]
fn syn_cookie_mixed_version_pair_disagrees_from_the_first_boundary_9173() {
    // An older helper ignores the ring and keeps the key of the period its last
    // full snapshot was built in, here key(R). A newer helper picks a key by the
    // cookie's own epoch, so the two agree inside period R and disagree from the
    // first epoch of R + 1, in both directions.
    //
    // No real pair has this shape: every helper that ignores the ring predates
    // #9740 and absorbs the zone id, so it disagrees from the first cookie (see
    // syn_cookie_mint_binds_the_zone_tag_twice_and_refuses_a_pre_9740_cookie_9740).
    // The cell still pins what the legacy key alone gives a ring-ignoring helper.
    let old_key = ring_key_9173(RING_ROTATION_9173);
    let state = |legacy: [u8; 16], ring: SynCookieKeyRing, epoch: u64| {
        let mut profile = ScreenProfile::default();
        profile.syn_flood_threshold = 1;
        profile.syn_cookie = true;
        let mut state = make_state("trust", profile);
        state.update_syn_cookie_keys(Some(legacy), ring);
        state.set_syn_cookie_full_epoch_for_test(epoch);
        state
    };
    let old = |epoch: u64| state(old_key, SynCookieKeyRing::default(), epoch);
    let new = |epoch: u64| state(LEGACY_KEY_9173, published_ring_9173(), epoch);
    let crosses = |mut minter: ScreenState, mut validator: ScreenState| {
        let isn = mint_challenge_isn_9173(&mut minter);
        ring_verdict_9173(&mut validator, &ack_for_isn_9173(isn)) == SynCookieAckVerdict::Validated
    };

    let inside = RING_FIRST_EPOCH_9173 + 3;
    assert!(
        crosses(old(inside), new(inside)) && crosses(new(inside), old(inside)),
        "premise: inside the older helper's period the pair agrees both ways"
    );
    let boundary = RING_FIRST_EPOCH_9173 + RING_PERIOD_EPOCHS_9173;
    assert!(
        !crosses(old(boundary), new(boundary)),
        "from the first boundary a newer helper refuses the older helper's cookie: the documented mixed-version window"
    );
    assert!(
        !crosses(new(boundary), old(boundary)),
        "from the first boundary an older helper refuses the newer helper's cookie: the documented mixed-version window"
    );
    // A later full snapshot hands the older helper the then-current period's key,
    // which restores the pair until the NEXT boundary, and the window repeats.
    let refreshed = |epoch: u64| state(ring_key_9173(RING_ROTATION_9173 + 1), SynCookieKeyRing::default(), epoch);
    assert!(
        crosses(refreshed(boundary), new(boundary)) && crosses(new(boundary), refreshed(boundary)),
        "after a full snapshot in period R + 1 the pair must agree again"
    );
    let next_boundary = boundary + RING_PERIOD_EPOCHS_9173;
    assert!(
        !crosses(refreshed(next_boundary), new(next_boundary))
            && !crosses(new(next_boundary), refreshed(next_boundary)),
        "the refreshed pair must disagree again from the next boundary, until the next full snapshot"
    );
}
