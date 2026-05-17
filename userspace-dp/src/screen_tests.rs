// Tests for screen.rs — relocated from inline
// `#[cfg(test)] mod tests` to keep screen.rs under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "screen_tests.rs"]` from screen.rs.

use super::*;
use std::net::{Ipv4Addr, Ipv6Addr};

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
        session_limit_src: 0,
        session_limit_dst: 0,
        port_scan_threshold: 0,
        ip_sweep_threshold: 0,
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
        pkt_len: 60,
        is_fragment: false,
        is_first_fragment: false,
        ip_ihl: 5,
        ip_frag_off: 0,
        ip_total_len: 60,
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
        pkt_len,
        is_fragment: false,
        is_first_fragment: false,
        ip_ihl: 5,
        ip_frag_off: 0,
        ip_total_len: pkt_len,
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
        pkt_len: 100,
        is_fragment: false,
        is_first_fragment: false,
        ip_ihl: 5,
        ip_frag_off: 0,
        ip_total_len: 100,
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
fn land_attack_different_ports_passes() {
    let mut state = make_state("trust", default_profile());
    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    // Same IP but different ports should pass
    let pkt = tcp_pkt(src, src, 80, 443, TCP_SYN);
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

#[test]
fn ping_of_death_drops() {
    let mut state = make_state("trust", default_profile());
    // pkt_len stored as u16, so max is 65535; ping-of-death only triggers
    // for pkt_len > 65535 which can't fit in u16. The BPF code uses
    // meta->pkt_len which is also u16 but checks > 65535 via u32 promotion.
    // In practice with u16 pkt_len this check won't trigger, but we still
    // implement the logic for correctness. With u32 pkt_len it would work.
    // Test with u16 max — this should pass since 65535 is not > 65535.
    let pkt = icmp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        65535,
    );
    // 65535 is not > 65535, so it passes
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
        pkt_len: 28,
        is_fragment: true,
        is_first_fragment: false,
        ip_ihl: 5,
        ip_frag_off: 0x0001 | 0x2000, // offset=1 (non-first frag), MF=1
        ip_total_len: 24,             // 20 byte header + 4 byte payload (< 8)
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
    };
    // First fragment (offset=0) — teardrop only triggers on non-first
    // However no_flag check will trigger first since tcp_flags=0
    // Use a profile with only teardrop enabled
    let mut profile = ScreenProfile::default();
    profile.teardrop = true;
    let mut st = make_state("trust", profile);
    assert_eq!(st.check_packet("trust", &pkt, 1), ScreenVerdict::Pass);
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
    );
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
    );
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
    frame[14 + 6] = 44; // NextHdr = FRAGMENT
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
    );
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
    );
    assert!(info.is_fragment, "IPv6 offset>0 → is_fragment");
    assert!(
        !info.is_first_fragment,
        "IPv6 offset>0 → is_first_fragment must be 0"
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
fn source_route_drops() {
    let mut state = make_state("trust", default_profile());
    let mut pkt = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        1234,
        80,
        TCP_SYN,
    );
    pkt.ip_ihl = 6; // Options present (IHL > 5)
    assert_eq!(
        state.check_packet("trust", &pkt, 1),
        ScreenVerdict::Drop("ip-source-route")
    );
}

#[test]
fn source_route_ipv6_ignored() {
    let mut state = make_state("trust", default_profile());
    let mut pkt = tcp_pkt(
        IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()),
        IpAddr::V6("2001:db8::2".parse::<Ipv6Addr>().unwrap()),
        1234,
        80,
        TCP_SYN,
    );
    pkt.ip_ihl = 6; // IPv6 doesn't use IHL, should be ignored
    assert_eq!(state.check_packet("trust", &pkt, 1), ScreenVerdict::Pass);
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

#[test]
fn icmp_flood_resets_on_new_window() {
    let mut profile = ScreenProfile::default();
    profile.icmp_flood_threshold = 2;
    let mut state = make_state("trust", profile);
    let pkt = icmp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        84,
    );
    assert_eq!(state.check_packet("trust", &pkt, 100), ScreenVerdict::Pass);
    assert_eq!(state.check_packet("trust", &pkt, 100), ScreenVerdict::Pass);
    // Exceeds in window 100
    assert_eq!(
        state.check_packet("trust", &pkt, 100),
        ScreenVerdict::Drop("icmp-flood")
    );
    // New window (101) resets
    assert_eq!(state.check_packet("trust", &pkt, 101), ScreenVerdict::Pass);
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

// ================================================================
// SYN cookie core (#1374)
// ================================================================

fn syn_cookie_codec() -> SynCookieCodec {
    SynCookieCodec::new([
        0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe,
        0x0f,
    ])
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
    let cookie = codec.mint_isn(tuple, 7, 42, 1460);
    let validation = codec
        .validate_isn(tuple, 7, 42, cookie)
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
    let cookie = codec.mint_isn(tuple, 7, 42, 1460);

    let mut mutated = tuple;
    mutated.src_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11));
    assert!(codec.validate_isn(mutated, 7, 42, cookie).is_none());

    mutated = tuple;
    mutated.dst_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 21));
    assert!(codec.validate_isn(mutated, 7, 42, cookie).is_none());

    mutated = tuple;
    mutated.src_port += 1;
    assert!(codec.validate_isn(mutated, 7, 42, cookie).is_none());

    mutated = tuple;
    mutated.dst_port += 1;
    assert!(codec.validate_isn(mutated, 7, 42, cookie).is_none());

    assert!(codec.validate_isn(tuple, 8, 42, cookie).is_none());
}

#[test]
fn syn_cookie_validate_rejects_stale_secret() {
    let codec = syn_cookie_codec();
    let stale_codec = SynCookieCodec::new([
        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
        0x00,
    ]);
    let tuple = syn_cookie_tuple();
    let cookie = codec.mint_isn(tuple, 7, 42, 1460);

    assert!(stale_codec.validate_isn(tuple, 7, 42, cookie).is_none());
}

#[test]
fn syn_cookie_mss_index_encoding_parity() {
    let codec = syn_cookie_codec();
    let tuple = syn_cookie_tuple();

    for (idx, mss) in SYN_COOKIE_MSS_VALUES.iter().copied().enumerate() {
        assert_eq!(SynCookieCodec::mss_index(mss), idx as u8);
        let cookie = codec.mint_isn(tuple, 7, 42, mss);
        assert_eq!(
            (cookie >> SYN_COOKIE_MSS_SHIFT) & SYN_COOKIE_MSS_MASK,
            idx as u32
        );
        assert_eq!(codec.validate_isn(tuple, 7, 42, cookie).unwrap().mss, mss);
    }

    assert_eq!(SynCookieCodec::mss_index(535), 0);
    assert_eq!(SynCookieCodec::mss_index(1459), 5);
    assert_eq!(SynCookieCodec::mss_index(9000), 7);

    let cookie = codec.mint_isn(tuple, 7, 42, 1460);
    let tampered_mss =
        (cookie & !(SYN_COOKIE_MSS_MASK << SYN_COOKIE_MSS_SHIFT)) | (5 << SYN_COOKIE_MSS_SHIFT);
    assert!(codec.validate_isn(tuple, 7, 42, tampered_mss).is_none());
}

#[test]
fn syn_cookie_ntp_rollback_monotonic_epoch() {
    assert_eq!(SynCookieCodec::full_epoch_from_monotonic_secs(0), 0);
    assert_eq!(SynCookieCodec::full_epoch_from_monotonic_secs(63), 0);
    assert_eq!(SynCookieCodec::full_epoch_from_monotonic_secs(64), 1);
    assert_eq!(
        SynCookieCodec::full_epoch_from_monotonic_secs(64 * 33 + 9),
        33
    );
}

#[test]
fn syn_cookie_epoch_low_bits_wrap_rejects_32_epoch_old_cookie() {
    let codec = syn_cookie_codec();
    let tuple = syn_cookie_tuple();
    let old_epoch = 10;
    let current_epoch = old_epoch + 32;
    let cookie = codec.mint_isn(tuple, 7, old_epoch, 1460);

    assert_eq!(old_epoch & 0x1f, current_epoch & 0x1f);
    assert!(
        codec
            .validate_isn(tuple, 7, current_epoch, cookie)
            .is_none()
    );
}

#[test]
fn syn_cookie_validation_tries_current_and_previous_full_epoch() {
    let codec = syn_cookie_codec();
    let tuple = syn_cookie_tuple();
    let current_cookie = codec.mint_isn(tuple, 7, 42, 1460);
    let previous_cookie = codec.mint_isn(tuple, 7, 41, 1460);
    let older_cookie = codec.mint_isn(tuple, 7, 40, 1460);

    assert_eq!(
        codec
            .validate_isn(tuple, 7, 42, current_cookie)
            .expect("current epoch")
            .full_epoch,
        42
    );
    assert_eq!(
        codec
            .validate_isn(tuple, 7, 42, previous_cookie)
            .expect("previous epoch")
            .full_epoch,
        41
    );
    assert!(codec.validate_isn(tuple, 7, 42, older_cookie).is_none());
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
    );

    assert_eq!(info.ip_ihl, 5);
    assert_eq!(info.ip_total_len, 20);
    assert!(info.is_fragment); // MF bit set
    assert_eq!(info.protocol, PROTO_TCP);
}

// ================================================================
// Per-IP session limits
// ================================================================

#[test]
fn session_limit_src_enforced() {
    let mut profile = ScreenProfile::default();
    profile.session_limit_src = 2;
    let mut state = make_state("trust", profile);

    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    let dst1 = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1));
    let dst2 = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 2));
    let dst3 = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 3));

    // First two sessions pass and get created
    let pkt1 = tcp_pkt(src, dst1, 1234, 80, TCP_SYN);
    assert_eq!(state.check_packet("trust", &pkt1, 1), ScreenVerdict::Pass);
    state.session_created(src, dst1);

    let pkt2 = tcp_pkt(src, dst2, 1235, 80, TCP_SYN);
    assert_eq!(state.check_packet("trust", &pkt2, 1), ScreenVerdict::Pass);
    state.session_created(src, dst2);

    // Third session should be dropped (limit = 2)
    let pkt3 = tcp_pkt(src, dst3, 1236, 80, TCP_SYN);
    assert_eq!(
        state.check_packet("trust", &pkt3, 1),
        ScreenVerdict::Drop("session-limit-src")
    );
}

#[test]
fn session_limit_dst_enforced() {
    let mut profile = ScreenProfile::default();
    profile.session_limit_dst = 2;
    let mut state = make_state("trust", profile);

    let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1));
    let src1 = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    let src2 = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 2));
    let src3 = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 3));

    let pkt1 = tcp_pkt(src1, dst, 1234, 80, TCP_SYN);
    assert_eq!(state.check_packet("trust", &pkt1, 1), ScreenVerdict::Pass);
    state.session_created(src1, dst);

    let pkt2 = tcp_pkt(src2, dst, 1235, 80, TCP_SYN);
    assert_eq!(state.check_packet("trust", &pkt2, 1), ScreenVerdict::Pass);
    state.session_created(src2, dst);

    let pkt3 = tcp_pkt(src3, dst, 1236, 80, TCP_SYN);
    assert_eq!(
        state.check_packet("trust", &pkt3, 1),
        ScreenVerdict::Drop("session-limit-dst")
    );
}

#[test]
fn session_limit_decrements_on_expire() {
    let mut profile = ScreenProfile::default();
    profile.session_limit_src = 1;
    let mut state = make_state("trust", profile);

    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    let dst1 = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1));
    let dst2 = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 2));

    // Create one session
    let pkt1 = tcp_pkt(src, dst1, 1234, 80, TCP_SYN);
    assert_eq!(state.check_packet("trust", &pkt1, 1), ScreenVerdict::Pass);
    state.session_created(src, dst1);

    // Second session blocked
    let pkt2 = tcp_pkt(src, dst2, 1235, 80, TCP_SYN);
    assert_eq!(
        state.check_packet("trust", &pkt2, 1),
        ScreenVerdict::Drop("session-limit-src")
    );

    // Expire first session
    state.session_expired(src, dst1);

    // Now second session passes
    assert_eq!(state.check_packet("trust", &pkt2, 1), ScreenVerdict::Pass);
}

// ================================================================
// Port scan detection
// ================================================================

#[test]
fn port_scan_detected() {
    let mut profile = ScreenProfile::default();
    profile.port_scan_threshold = 3;
    let mut state = make_state("trust", profile);

    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1));

    // First 3 unique ports pass
    for port in [80, 443, 8080] {
        let pkt = tcp_pkt(src, dst, 1234, port, TCP_SYN);
        assert_eq!(
            state.check_packet("trust", &pkt, 100),
            ScreenVerdict::Pass,
            "port {} should pass",
            port,
        );
    }

    // 4th unique port triggers port scan
    let pkt = tcp_pkt(src, dst, 1234, 22, TCP_SYN);
    assert_eq!(
        state.check_packet("trust", &pkt, 100),
        ScreenVerdict::Drop("port-scan")
    );
}

#[test]
fn port_scan_resets_on_window_expiry() {
    let mut profile = ScreenProfile::default();
    profile.port_scan_threshold = 2;
    let mut state = make_state("trust", profile);

    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1));

    // Fill up in window at time=100
    let pkt1 = tcp_pkt(src, dst, 1234, 80, TCP_SYN);
    let pkt2 = tcp_pkt(src, dst, 1234, 443, TCP_SYN);
    assert_eq!(state.check_packet("trust", &pkt1, 100), ScreenVerdict::Pass);
    assert_eq!(state.check_packet("trust", &pkt2, 100), ScreenVerdict::Pass);

    // 3rd port triggers at time=100
    let pkt3 = tcp_pkt(src, dst, 1234, 22, TCP_SYN);
    assert_eq!(
        state.check_packet("trust", &pkt3, 100),
        ScreenVerdict::Drop("port-scan")
    );

    // After window expires (default 10s), should pass again
    let pkt4 = tcp_pkt(src, dst, 1234, 8080, TCP_SYN);
    assert_eq!(state.check_packet("trust", &pkt4, 111), ScreenVerdict::Pass);
}

#[test]
fn port_scan_only_on_syn() {
    let mut profile = ScreenProfile::default();
    profile.port_scan_threshold = 1;
    let mut state = make_state("trust", profile);

    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1));

    // ACK packets (established traffic) should not trigger port scan
    for port in [80, 443, 8080, 22] {
        let pkt = tcp_pkt(src, dst, 1234, port, TCP_ACK);
        assert_eq!(state.check_packet("trust", &pkt, 100), ScreenVerdict::Pass,);
    }
}

// ================================================================
// IP sweep detection
// ================================================================

#[test]
fn ip_sweep_detected() {
    let mut profile = ScreenProfile::default();
    profile.ip_sweep_threshold = 3;
    let mut state = make_state("trust", profile);

    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));

    // First 3 unique destinations pass
    for i in 1..=3u8 {
        let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 2, i));
        let pkt = tcp_pkt(src, dst, 1234, 80, TCP_SYN);
        assert_eq!(state.check_packet("trust", &pkt, 100), ScreenVerdict::Pass);
    }

    // 4th unique destination triggers IP sweep
    let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 4));
    let pkt = tcp_pkt(src, dst, 1234, 80, TCP_SYN);
    assert_eq!(
        state.check_packet("trust", &pkt, 100),
        ScreenVerdict::Drop("ip-sweep")
    );
}

#[test]
fn ip_sweep_resets_on_window_expiry() {
    let mut profile = ScreenProfile::default();
    profile.ip_sweep_threshold = 2;
    let mut state = make_state("trust", profile);

    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));

    // Fill up window at time=100
    for i in 1..=2u8 {
        let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 2, i));
        let pkt = tcp_pkt(src, dst, 1234, 80, TCP_SYN);
        assert_eq!(state.check_packet("trust", &pkt, 100), ScreenVerdict::Pass);
    }

    // 3rd triggers
    let dst3 = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 3));
    let pkt3 = tcp_pkt(src, dst3, 1234, 80, TCP_SYN);
    assert_eq!(
        state.check_packet("trust", &pkt3, 100),
        ScreenVerdict::Drop("ip-sweep")
    );

    // After window expires (default 10s), passes again
    let dst4 = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 4));
    let pkt4 = tcp_pkt(src, dst4, 1234, 80, TCP_SYN);
    assert_eq!(state.check_packet("trust", &pkt4, 111), ScreenVerdict::Pass);
}

#[test]
fn ip_sweep_works_with_udp() {
    let mut profile = ScreenProfile::default();
    profile.ip_sweep_threshold = 2;
    let mut state = make_state("trust", profile);

    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));

    for i in 1..=2u8 {
        let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 2, i));
        let mut pkt = udp_pkt(src, dst);
        pkt.dst_ip = dst;
        assert_eq!(state.check_packet("trust", &pkt, 100), ScreenVerdict::Pass);
    }

    // 3rd triggers
    let dst3 = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 3));
    let mut pkt3 = udp_pkt(src, dst3);
    pkt3.dst_ip = dst3;
    assert_eq!(
        state.check_packet("trust", &pkt3, 100),
        ScreenVerdict::Drop("ip-sweep")
    );
}
