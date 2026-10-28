//! Stateless malformed-screen parity for the XDP shim's kernel-pass
//! arms (#16009).
//!
//! The worker's screen stage 10 (`userspace-dp/src/screen/mod.rs`
//! `check_packet_with_zone_id_opts`) runs, in order, LAND, the TCP-flag
//! screens, then ping-of-death -> teardrop -> icmp-fragment ->
//! source-route on transit traffic, but every shim arm that hands a
//! packet to the kernel (session PASS_TO_KERNEL, session-miss local,
//! WG steer, early filter, degraded local/control, ctrl-disabled local)
//! is terminal — those packets never reach the worker. Only LAND was
//! replicated at the shim (#15789, `land_gate`). This module replicates
//! the remaining STATELESS malformed family so host-bound traffic is
//! screened to the same verdicts: ping-of-death, teardrop (stateless
//! parts), icmp-fragment, source-route (IPv4 LSRR/SSRR and IPv6
//! Routing type 0/1), and the TCP-flag malformed screens (syn-fin,
//! no-flag, fin-no-ack, winnuke, syn-frag).
//!
//! Deliberately NOT replicated here (stateful / counter-fidelity
//! residue recorded on #16009):
//!   - true fragment-overlap detection: needs offset/length state
//!     across fragments (`fragment_overlap`); the stateless teardrop
//!     check explicitly is not an overlap detector.
//!   - port-scan / ip-sweep: stateful per-source trackers gated on the
//!     worker's new-flow decision.
//!   - SYN-cookie challenge semantics and the rate-based flood
//!     counters: flood meters are already replicated in the kernel by
//!     `pkg/nftables/host_inbound_screens.go`; SYN-cookie minting is a
//!     worker crypto operation, not a drop verdict. Per-reason worker
//!     screen counters likewise stay worker-side; the shim counts one
//!     `host_screen_drop` / `host_screen_alarm` per packet.
//!   - LAND: already at the shim as `land_gate`, ordered before this
//!     gate so it keeps its own counter.
//!
//! The mask bits below mirror the Go constants of the same name in
//! `pkg/dataplane/userspace/host_screen.go`. Bit 7 is the profile-wide
//! alarm-without-drop audit flag (the worker's `alarm_without_drop`).

/// Ping-of-death enabled for the zone.
pub const HOST_SCREEN_PING_DEATH: u8 = 1 << 0;
/// Teardrop enabled for the zone.
pub const HOST_SCREEN_TEARDROP: u8 = 1 << 1;
/// ICMP-fragment enabled for the zone.
pub const HOST_SCREEN_ICMP_FRAGMENT: u8 = 1 << 2;
/// SYN-fragment enabled for the zone.
pub const HOST_SCREEN_SYN_FRAG: u8 = 1 << 3;
/// IP source-route enabled for the zone.
pub const HOST_SCREEN_SOURCE_ROUTE: u8 = 1 << 4;
/// TCP SYN+FIN enabled for the zone.
pub const HOST_SCREEN_SYN_FIN: u8 = 1 << 5;
/// TCP no-flag / fin-no-ack / winnuke family enabled for the zone.
/// One shared bit: the worker carries the three as separate bools,
/// but the shim byte dedicates one bit to the family (see
/// `host_malformed_verdict`); the Go sync sets it when any of the
/// three is enabled, mirroring the verdict exactly because the
/// verdict only tests the family bit against the same three flags.
pub const HOST_SCREEN_TCP_FLAGS: u8 = 1 << 6;
/// Profile-wide alarm-without-drop: count and pass instead of dropping.
pub const HOST_SCREEN_ALARM_WITHOUT_DROP: u8 = 1 << 7;

/// Every stateless malformed check this gate replicates. A tripped bit
/// outside the zone's mask is not a screen hit for that zone.
pub const HOST_SCREEN_ALL_CHECKS: u8 = HOST_SCREEN_PING_DEATH
    | HOST_SCREEN_TEARDROP
    | HOST_SCREEN_ICMP_FRAGMENT
    | HOST_SCREEN_SYN_FRAG
    | HOST_SCREEN_SOURCE_ROUTE
    | HOST_SCREEN_SYN_FIN
    | HOST_SCREEN_TCP_FLAGS;

const PROTO_ICMP: u8 = 1;
const PROTO_TCP: u8 = 6;
const PROTO_ICMPV6: u8 = 58;
const TCP_FLAG_FIN: u8 = 0x01;
const TCP_FLAG_SYN: u8 = 0x02;
const TCP_FLAG_ACK: u8 = 0x10;
const TCP_FLAG_URG: u8 = 0x20;


/// What the shim does with a malformed-screen hit for one ingress zone.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HostMalformedDisposition {
    /// No enabled check tripped (or checks disabled for this zone).
    Pass,
    /// Drop at the shim (`host_screen_drop` counter).
    Drop,
    /// Count `host_screen_alarm` and pass to the kernel.
    AlarmPass,
}

/// Resolve a verdict mask against one zone's published byte.
///
/// Only a RESOLVED zone's byte decides. An unresolved zone (no WG
/// ingress-zone row, or zone 0) fails closed to Drop for any tripped
/// packet, so a stale host_screen row for another zone can never admit
/// a packet whose own zone is unknown, and a pre-#16009 control plane
/// (no rows at all) drops malformed host-bound packets instead of
/// passing them unscreened. A resolved zone with an absent row reads
/// byte 0 — checks off — because the Go sync publishes an explicit row
/// for every screened zone; absence under a resolved zone is the
/// checks-off shape (the #15789 LAND precedent).
#[inline(always)]
pub fn host_malformed_disposition(
    zone_known: bool,
    screen_byte: u8,
    verdict_mask: u8,
) -> HostMalformedDisposition {
    if !zone_known {
        return HostMalformedDisposition::Drop;
    }
    if verdict_mask & screen_byte & HOST_SCREEN_ALL_CHECKS == 0 {
        return HostMalformedDisposition::Pass;
    }
    if screen_byte & HOST_SCREEN_ALARM_WITHOUT_DROP != 0 {
        return HostMalformedDisposition::AlarmPass;
    }
    HostMalformedDisposition::Drop
}

/// Packed screen inputs for one packet (BPF subprograms take at most
/// five arguments, so the verdict's scalars travel as one by-value
/// struct — the `record_trace_packed` precedent).
#[derive(Clone, Copy)]
pub struct HostScreenPacket {
    pub is_ipv4: bool,
    pub protocol: u8,
    pub wire_protocol: u8,
    pub tcp_flags: u8,
    /// TCP flags byte is UNKNOWN (tiny first fragment, #16007). The
    /// worker fails closed with `syn-frag` for this shape; the shim
    /// mirrors it (see `host_malformed_verdict`).
    pub tcp_flags_unknown: bool,
    pub dst_port: u16,
    pub is_fragment: bool,
    pub is_first_fragment: bool,
    pub ip_frag_off: u16,
    pub ip_total_len: u16,
    pub ip_ihl: u8,
    pub ip_payload_len: u16,
    pub frag_data_off: u16,
    pub saw_source_route: bool,
}

/// The stateless malformed verdict for one packet, as a mask of the
/// checks that trip UNCONDITIONALLY (before the zone mask is applied).
///
/// Mirrors `userspace-dp/src/screen/stateless.rs` exactly:
/// `check_fragment_and_route`'s tail (ping-of-death -> teardrop ->
/// icmp-fragment -> source-route) plus `check_tcp_flag_screens`
/// collapse to a mask here because the shim counts one
/// `host_screen_drop` per packet, not per reason. The ICMP-fragment
/// arm keys on the WIRE protocol: a non-first fragment's `protocol`
/// is the shim's no-L4 sentinel, and the worker recovers the real
/// protocol from the IP / Fragment header (`extract.rs` #9114) before
/// testing. The TCP-flag arms mirror the worker's outer guard
/// (`!is_fragment || is_first_fragment`): subsequent fragments carry
/// no L4 header, so their flags byte is never tested. The
/// `tcp_flags_unknown` arm mirrors the worker's #16007 fail-closed
/// `syn-frag` for a tiny first fragment whose flags were never seen.
#[inline(always)]
pub fn host_malformed_verdict(pkt: &HostScreenPacket) -> u8 {
    let is_ipv4 = pkt.is_ipv4;
    let protocol = pkt.protocol;
    let wire_protocol = pkt.wire_protocol;
    let tcp_flags = pkt.tcp_flags;
    let tcp_flags_unknown = pkt.tcp_flags_unknown;
    let dst_port = pkt.dst_port;
    let is_fragment = pkt.is_fragment;
    let is_first_fragment = pkt.is_first_fragment;
    let ip_frag_off = pkt.ip_frag_off;
    let ip_total_len = pkt.ip_total_len;
    let ip_ihl = pkt.ip_ihl;
    let ip_payload_len = pkt.ip_payload_len;
    let frag_data_off = pkt.frag_data_off;
    let saw_source_route = pkt.saw_source_route;
    let mut mask = 0u8;
    if is_fragment {
        // check_ping_of_death
        if is_ipv4 {
            let offset_bytes = ((ip_frag_off & 0x1FFF) as u32) << 3;
            if offset_bytes + ip_total_len as u32 > 65535 {
                mask |= HOST_SCREEN_PING_DEATH;
            }
        } else {
            let offset_bytes = (ip_frag_off & 0xFFF8) as u32;
            let frag_data = ip_payload_len.saturating_sub(frag_data_off) as u32;
            if offset_bytes + frag_data > 65535 {
                mask |= HOST_SCREEN_PING_DEATH;
            }
        }
        // check_teardrop
        if is_ipv4 {
            let hdr_len = (ip_ihl as u16) * 4;
            if ip_total_len <= hdr_len {
                mask |= HOST_SCREEN_TEARDROP;
            } else {
                let payload = ip_total_len - hdr_len;
                let more_fragments = (ip_frag_off & 0x2000) != 0;
                if more_fragments && payload % 8 != 0 {
                    mask |= HOST_SCREEN_TEARDROP;
                }
            }
        } else {
            let frag_data = ip_payload_len.saturating_sub(frag_data_off);
            if frag_data == 0 {
                mask |= HOST_SCREEN_TEARDROP;
            } else {
                let more_fragments = (ip_frag_off & 0x1) != 0;
                if more_fragments && frag_data % 8 != 0 {
                    mask |= HOST_SCREEN_TEARDROP;
                }
            }
        }
        // check_icmp_fragment (wire protocol, see above)
        if wire_protocol == PROTO_ICMP || wire_protocol == PROTO_ICMPV6 {
            mask |= HOST_SCREEN_ICMP_FRAGMENT;
        }
    }
    // check_tcp_flag_screens (worker order: syn-fin, no-flag,
    // fin-no-ack, winnuke, syn-frag). The mask collapses precedence:
    // any tripped arm sets its bit and the zone byte decides.
    if protocol == PROTO_TCP && (!is_fragment || is_first_fragment) {
        if tcp_flags_unknown && is_first_fragment {
            // #16007: flags UNKNOWN on a first fragment fails closed
            // as syn-frag, never read as a proven flag set.
            mask |= HOST_SCREEN_SYN_FRAG;
        } else {
            if (tcp_flags & TCP_FLAG_SYN) != 0 && (tcp_flags & TCP_FLAG_FIN) != 0 {
                mask |= HOST_SCREEN_SYN_FIN;
            }
            if tcp_flags == 0 {
                mask |= HOST_SCREEN_TCP_FLAGS;
            }
            if (tcp_flags & TCP_FLAG_FIN) != 0 && (tcp_flags & TCP_FLAG_ACK) == 0 {
                mask |= HOST_SCREEN_TCP_FLAGS;
            }
            if (tcp_flags & TCP_FLAG_URG) != 0 && dst_port == 139 {
                mask |= HOST_SCREEN_TCP_FLAGS;
            }
            if (tcp_flags & TCP_FLAG_SYN) != 0 && is_first_fragment {
                mask |= HOST_SCREEN_SYN_FRAG;
            }
        }
    }
    // check_source_route
    if saw_source_route {
        mask |= HOST_SCREEN_SOURCE_ROUTE;
    }
    mask
}
