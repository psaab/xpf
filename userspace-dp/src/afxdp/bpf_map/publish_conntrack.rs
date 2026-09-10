// Per-address-family publish helpers for `publish_bpf_conntrack_entry`.
//
// Pure code motion out of `bpf_map/mod.rs`: the v4 and v6 arms of the
// original 204-LOC orchestrator now live in `publish_v4_session` and
// `publish_v6_session`. The orchestrator (`publish_bpf_conntrack_entry`)
// stays in the parent module and dispatches by address family.
//
// Both helpers preserve the original side-effect contract:
//   - construct `BpfSessionKey*` from the forward 5-tuple
//   - construct a reverse key via `reverse_session_key()`; on a
//     cross-family reverse-key result, the helper returns early and
//     skips the BPF write entirely (same observable effect as the
//     pre-refactor early returns at the orchestrator level)
//   - populate `BpfSessionValue*` with state, flags, zones, NAT IPs/ports,
//     and the reverse key
//   - `bpf_map_update_elem` with `BPF_ANY`
//   - on failure, `eprintln!("xpf-ha: conntrack vN map update failed: …")`
//
// See #1356.

use super::{
    BpfSessionKeyV4, BpfSessionKeyV6, BpfSessionValueV4, BpfSessionValueV6, SESS_STATE_ESTABLISHED,
    SessionDecision, SessionKey, SessionMetadata, bpf_session_key_v4, bpf_session_key_v6,
    reverse_session_key,
};
use crate::ip_proto::{PROTO_TCP, PROTO_UDP};
use core::ffi::{c_int, c_void};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// `security alg <proto> disable` bitfield (#2008 H3/H4). Mirrors the Go
// `algDisableFlags` encoding and the legacy flow_config_map ALGFlags layout.
const ALG_DISABLE_DNS: u8 = 0x01;
const ALG_DISABLE_FTP: u8 = 0x02;
const ALG_DISABLE_SIP: u8 = 0x04;
// TFTP's disable bit is carried on the wire for layout parity with the Go
// `algDisableFlags` packer (DNS 0x01 / FTP 0x02 / SIP 0x04 / TFTP 0x08), but
// it has no consumer here: the dataplane has no TFTP conntrack alg_type to
// suppress (`alg_type` is one of none/FTP/SIP/DNS — see xpf_conntrack.h), so
// `alg_type_for_session` never reads this bit. Defined to document the full
// bit layout consistently across Go and Rust; intentionally unused.
#[allow(dead_code)]
const ALG_DISABLE_TFTP: u8 = 0x08;

// alg_type codes written into the conntrack session value, matching
// bpf/headers/xpf_conntrack.h: 0=none, 1=FTP, 2=SIP, 3=DNS.
const ALG_TYPE_NONE: u8 = 0;
const ALG_TYPE_FTP: u8 = 1;
const ALG_TYPE_SIP: u8 = 2;
const ALG_TYPE_DNS: u8 = 3;

/// Derive the conntrack `alg_type` for a session from its forward 5-tuple,
/// honouring the `security alg <proto> disable` bitfield (#2008 H3/H4).
///
/// Previously `alg_type` was hardcoded to 0, so the `alg disable` knob had
/// zero runtime effect: it parsed and compiled into `flow_config_map` but no
/// reader consumed it. This derives the ALG type from the well-known service
/// port (FTP TCP/21, SIP UDP+TCP/5060, DNS UDP/53) UNLESS the matching ALG is
/// disabled, in which case the session is tagged `none` (0) — exactly the
/// Junos semantics of `alg disable` (the ALG is turned off; traffic is NOT
/// dropped). The service port is the destination port for a forward session;
/// the reverse direction's source port mirrors it, so both directions of an
/// ALG session resolve to the same type.
pub(super) fn alg_type_for_session(protocol: u8, src_port: u16, dst_port: u16, disable: u8) -> u8 {
    // The well-known ALG service port can appear as either the forward dst
    // (client -> server) or, for a session keyed in the reverse direction,
    // the src. Treat a match on either port slot as the same ALG.
    let on_port = |p: u16| src_port == p || dst_port == p;
    match protocol {
        PROTO_UDP if on_port(53) => {
            if disable & ALG_DISABLE_DNS != 0 {
                ALG_TYPE_NONE
            } else {
                ALG_TYPE_DNS
            }
        }
        PROTO_TCP if on_port(21) => {
            if disable & ALG_DISABLE_FTP != 0 {
                ALG_TYPE_NONE
            } else {
                ALG_TYPE_FTP
            }
        }
        PROTO_UDP | PROTO_TCP if on_port(5060) => {
            if disable & ALG_DISABLE_SIP != 0 {
                ALG_TYPE_NONE
            } else {
                ALG_TYPE_SIP
            }
        }
        _ => ALG_TYPE_NONE,
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn publish_v4_session(
    conntrack_v4_fd: c_int,
    key: &SessionKey,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    decision: SessionDecision,
    metadata: &SessionMetadata,
    flags: u16,
    ingress_zone_id: u16,
    egress_zone_id: u16,
    now_secs: u64,
    alg_disable_flags: u8,
    app_id: u16,
    // #5213: the STABLE dataplane session id (`SessionEntry.session_id`, #4915)
    // resolved by the caller from the session table. Stamped into the conntrack
    // value so `show security flow session` reports the SAME id RT_FLOW emits for
    // the session (SESSION_CREATE/CLOSE). `0` = unknown/absent (the caller had no
    // live entry), preserving the legacy ordinal fallback on the Go render side.
    session_id: u64,
    // #8125: see build_conntrack_value_v4.
    timeout_secs: u32,
) {
    let bpf_key = bpf_session_key_v4(src.octets(), dst.octets(), key.src_port, key.dst_port, key.protocol);

    // A cross-family reverse key means the session cannot be mirrored to the v4
    // conntrack map — skip the write entirely (pre-#5213 behaviour).
    let Some(value) = build_conntrack_value_v4(
        key,
        decision,
        metadata,
        flags,
        ingress_zone_id,
        egress_zone_id,
        now_secs,
        alg_disable_flags,
        app_id,
        session_id,
        timeout_secs,
    ) else {
        return;
    };

    let rc = unsafe {
        libbpf_sys::bpf_map_update_elem(
            conntrack_v4_fd,
            (&bpf_key as *const BpfSessionKeyV4).cast::<c_void>(),
            (&value as *const BpfSessionValueV4).cast::<c_void>(),
            libbpf_sys::BPF_ANY as u64,
        )
    };
    if rc < 0 {
        eprintln!(
            "xpf-ha: conntrack v4 map update failed: {}",
            io::Error::last_os_error()
        );
    }
}

/// #9546: the routing domain stamped into a conntrack mirror row.
///
/// FORWARD rows state the session key's domain in the #7239 wire encoding --
/// the SAME encoding the event stream puts on the session delta
/// (`event_stream/codec/session_sync.rs`), so a Go delete that reads it back
/// names exactly what the install named. The default instance encodes as the
/// non-zero `WIRE_DEFAULT_INSTANCE` marker, never 0.
///
/// REVERSE rows state NOTHING (`WIRE_ABSENT`). Their key is the reverse-match
/// key, which `reverse_wire_key` / `reverse_canonical_key` deliberately build
/// with `routing_domain: 0` because a reply may legitimately arrive in another
/// domain (#7160). Encoding that 0 would yield `WIRE_DEFAULT_INSTANCE` -- a
/// confident claim that a tenant flow's reply half lives in the default
/// instance, which is false. Absence is the truthful value, and no delete path
/// needs more: the #9146 singular and #9364 batch deletes both scope the
/// reverse companion with the FORWARD row's domain.
pub(super) fn conntrack_row_routing_domain(key: &SessionKey, metadata: &SessionMetadata) -> u32 {
    if metadata.is_reverse {
        crate::session::ROUTING_DOMAIN_WIRE_ABSENT
    } else {
        crate::session::routing_domain_to_wire(key.routing_domain)
    }
}

/// #5213: build the v4 conntrack `BpfSessionValueV4` mirrored for `show security
/// flow session`. Pure (no map I/O) so the `session_id` stamping is unit-testable
/// without a BPF map fd. Returns `None` when the reverse key resolves cross-family
/// (the session is not v4-mappable), mirroring the pre-refactor early return.
#[allow(clippy::too_many_arguments)]
pub(super) fn build_conntrack_value_v4(
    key: &SessionKey,
    decision: SessionDecision,
    metadata: &SessionMetadata,
    flags: u16,
    ingress_zone_id: u16,
    egress_zone_id: u16,
    now_secs: u64,
    alg_disable_flags: u8,
    app_id: u16,
    session_id: u64,
    // #8125: the session's own inactivity window in whole seconds, from
    // SessionTable::timeout_secs_for. 0 = no live entry, which keeps the
    // documented default below rather than stamping a zero window.
    timeout_secs: u32,
) -> Option<BpfSessionValueV4> {
    let alg_type =
        alg_type_for_session(key.protocol, key.src_port, key.dst_port, alg_disable_flags);

    // Build reverse key
    let rev = reverse_session_key(key, decision.nat);
    let rev_key = match rev.src_ip {
        IpAddr::V4(rsrc) => {
            let rdst = match rev.dst_ip {
                IpAddr::V4(d) => d,
                _ => return None,
            };
            bpf_session_key_v4(rsrc.octets(), rdst.octets(), rev.src_port, rev.dst_port, rev.protocol)
        }
        _ => return None,
    };

    // NAT IPs: use native endian u32 (IP bytes already in network order,
    // interpret as NativeEndian per CLAUDE.md)
    let nat_src_ip = match decision.nat.rewrite_src {
        Some(IpAddr::V4(ip)) => u32::from_ne_bytes(ip.octets()),
        _ => 0,
    };
    let nat_dst_ip = match decision.nat.rewrite_dst {
        Some(IpAddr::V4(ip)) => u32::from_ne_bytes(ip.octets()),
        _ => 0,
    };
    let nat_src_port = decision.nat.rewrite_src_port.unwrap_or(0).to_be();
    let nat_dst_port = decision.nat.rewrite_dst_port.unwrap_or(0).to_be();

    Some(BpfSessionValueV4 {
        state: SESS_STATE_ESTABLISHED,
        flags,
        tcp_state: 0,
        is_reverse: if metadata.is_reverse { 1 } else { 0 },
        app_timeout: 0,
        // #5213: the stable session id from the session table (was hardcoded 0).
        session_id,
        created: now_secs,
        last_seen: now_secs,
        // #8125: the session's OWN window, not a constant. This column read
        // 1800 for every session — the Junos `established-timeout` default —
        // whatever window was actually in force, so a half-closed session on a
        // 30 s (or configured 3 s) closing window and an ESTABLISHED session on
        // its 300 s default both reported the same number. The reap behaviour
        // proved they differed by an order of magnitude; the column did not.
        //
        // 1800 remains the fallback for a publish with NO live table entry
        // (`timeout_secs == 0`), which is the pre-#8125 behaviour for exactly
        // the case that has no window to report. It is a default, not a
        // measurement, and the refresh loop corrects it within one cycle once
        // an entry exists. Go GC is SkipSweep'd and the helper owns lifetime
        // (#333), so nothing downstream acts on this value — it is an operator
        // display.
        timeout: if timeout_secs > 0 { timeout_secs } else { 1800 },
        // #3056: the admitting policy's ID, stamped on the session at install.
        // The Go session-row surfaces (`show security flow session`, REST,
        // gRPC) read this slot as `val.PolicyID` and resolve a policy name from
        // it; it was hardcoded `0`, which the Go side renders as the FIRST
        // configured policy (a wrong attribution). `0` stays the value for
        // non-policy-forwarded sessions (their metadata carries `policy_id: 0`).
        policy_id: metadata.policy_id,
        ingress_zone: ingress_zone_id,
        egress_zone: egress_zone_id,
        nat_src_ip,
        nat_dst_ip,
        nat_src_port,
        nat_dst_port,
        fwd_packets: 0,
        fwd_bytes: 0,
        rev_packets: 0,
        rev_bytes: 0,
        reverse_key: rev_key,
        alg_type,
        log_flags: 0,
        app_id,
        fib_ifindex: 0,
        fib_vlan_id: 0,
        fib_dmac: [0; 6],
        fib_smac: [0; 6],
        fib_gen: 0,
        // #4983: the session's TRUE ingress-interface identity, taken from the
        // metadata stamped at install (the binding the FIRST packet arrived
        // on) — deliberately NOT re-derived from `ingress_zone_id` here, which
        // is the very zone approximation the field replaces. `0` when the
        // session carries no ingress identity (reverse companion / peer-synced
        // import); the Go filter falls back to the zone approximation for it.
        ingress_ifindex: metadata.ingress_ifindex,
        ingress_vlan_id: metadata.ingress_vlan_id,
        // #9546: see conntrack_row_routing_domain.
        routing_domain: conntrack_row_routing_domain(key, metadata),
    })
}

#[allow(clippy::too_many_arguments)]
/// #6923: may a v6 session key with this protocol become visible to the shim?
///
/// False for exactly the next-header values the shim's extension-header walk
/// TRAVERSES. Those are the values the walk can emit by EXHAUSTING its loop —
/// it returns the last declared next-header, so an over-limit chain surfaces as
/// a key whose "protocol" is an extension header. Such a key must never exist
/// in the map, because the shim probes it and a hit means the over-limit chain
/// takes the fast path on an identity nothing parsed.
///
/// Derived from `ipv6_ext_header_is_traversable` rather than a second list of
/// protocol numbers. A duplicated set drifts, and it drifts in the direction
/// that reopens the hole: the walker learns a new traversable type, this copy
/// does not, and the refusal silently stops covering it — which is exactly how
/// the #4517 types came to be missing from the GRE-inner classify in #6886.
fn v6_session_key_is_publishable(protocol: u8) -> bool {
    !crate::afxdp::ipv6_ext_header_is_traversable(protocol)
}

pub(super) fn publish_v6_session(
    conntrack_v6_fd: c_int,
    key: &SessionKey,
    src: Ipv6Addr,
    dst: Ipv6Addr,
    decision: SessionDecision,
    metadata: &SessionMetadata,
    flags: u16,
    ingress_zone_id: u16,
    egress_zone_id: u16,
    now_secs: u64,
    alg_disable_flags: u8,
    app_id: u16,
    // #5213: stable dataplane session id — see publish_v4_session.
    session_id: u64,
    // #8125: see build_conntrack_value_v4.
    timeout_secs: u32,
) {
    // #6923: THE CHOKEPOINT. Refuse to make a key the shim would probe visible
    // when its protocol is an IPv6 extension-header type rather than an L4.
    //
    // The shim's over-limit refusal was never a property of the shim. Its walk
    // exhausts and returns the LAST DECLARED next-header — an extension-header
    // value, not a real protocol — and `parse_l4`'s catch-all then yields ports
    // 0/0. The intended consequence is that the session lookup MISSES and the
    // packet is redirected to userspace. But the lookup only misses while
    // nothing has published `(AF_INET6, <a traversable next-header>, src, dst,
    // 0, 0)`. Publish that tuple and the next packet of the same over-limit
    // chain HITS and takes the fast path, silently, with no code change
    // anywhere near the shim.
    //
    // That was previously held by an ENUMERATION — two writers that both
    // declined the tuple (`metadata_tuple_complete` on the packet path,
    // `build_synced_session_key` on the HA import path) and a doc comment
    // asking that a third not be added. A comment is not a gate, and an
    // enumeration is only as good as its completeness.
    //
    // Here it is expressed ONCE, at the point where a key becomes shim-visible,
    // so a third writer inherits it instead of having to remember it. This is
    // the sole path by which a v6 key can enter the map the shim probes:
    //   - `publish_bpf_conntrack_entry` -> here, `BPF_ANY` (creates)
    //   - `refresh_bpf_conntrack_last_seen`, `BPF_EXIST` — CANNOT create; that
    //     is demonstrated against a real map, not inferred from the flag's
    //     name, by `test/mutation/selftest-bpf-exist-cannot-create_6923.sh`
    //   - `delete_bpf_conntrack_entry` — a delete, which cannot mint a key
    //
    // DELIBERATELY UNREACHABLE TODAY. Both existing writers already decline, so
    // this refuses nothing that currently happens — it is a backstop, and its
    // value is that it stays true when a third writer appears. It is exercised
    // by its own tests rather than by production traffic, which is the intended
    // state for a backstop and not the "ships and does nothing" shape: the
    // guard IS the deliverable, and it is directly testable at its own entry.
    if !v6_session_key_is_publishable(key.protocol) {
        return;
    }
    let bpf_key = bpf_session_key_v6(
        src.octets(),
        dst.octets(),
        key.src_port,
        key.dst_port,
        key.protocol,
    );

    let Some(value) = build_conntrack_value_v6(
        key,
        decision,
        metadata,
        flags,
        ingress_zone_id,
        egress_zone_id,
        now_secs,
        alg_disable_flags,
        app_id,
        session_id,
        timeout_secs,
    ) else {
        return;
    };

    let rc = unsafe {
        libbpf_sys::bpf_map_update_elem(
            conntrack_v6_fd,
            (&bpf_key as *const BpfSessionKeyV6).cast::<c_void>(),
            (&value as *const BpfSessionValueV6).cast::<c_void>(),
            libbpf_sys::BPF_ANY as u64,
        )
    };
    if rc < 0 {
        eprintln!(
            "xpf-ha: conntrack v6 map update failed: {}",
            io::Error::last_os_error()
        );
    }
}

/// #5213: v6 sibling of [`build_conntrack_value_v4`] — pure builder for the v6
/// conntrack mirror value, stamping the stable `session_id`. Returns `None` on a
/// cross-family reverse key (not v6-mappable).
#[allow(clippy::too_many_arguments)]
pub(super) fn build_conntrack_value_v6(
    key: &SessionKey,
    decision: SessionDecision,
    metadata: &SessionMetadata,
    flags: u16,
    ingress_zone_id: u16,
    egress_zone_id: u16,
    now_secs: u64,
    alg_disable_flags: u8,
    app_id: u16,
    session_id: u64,
    // #8125: the session's own inactivity window in whole seconds, from
    // SessionTable::timeout_secs_for. 0 = no live entry, which keeps the
    // documented default below rather than stamping a zero window.
    timeout_secs: u32,
) -> Option<BpfSessionValueV6> {
    let alg_type =
        alg_type_for_session(key.protocol, key.src_port, key.dst_port, alg_disable_flags);

    let rev = reverse_session_key(key, decision.nat);
    let rev_key = match rev.src_ip {
        IpAddr::V6(rsrc) => {
            let rdst = match rev.dst_ip {
                IpAddr::V6(d) => d,
                _ => return None,
            };
            bpf_session_key_v6(rsrc.octets(), rdst.octets(), rev.src_port, rev.dst_port, rev.protocol)
        }
        _ => return None,
    };

    let nat_src_ip = match decision.nat.rewrite_src {
        Some(IpAddr::V6(ip)) => ip.octets(),
        _ => [0; 16],
    };
    let nat_dst_ip = match decision.nat.rewrite_dst {
        Some(IpAddr::V6(ip)) => ip.octets(),
        _ => [0; 16],
    };
    let nat_src_port = decision.nat.rewrite_src_port.unwrap_or(0).to_be();
    let nat_dst_port = decision.nat.rewrite_dst_port.unwrap_or(0).to_be();

    Some(BpfSessionValueV6 {
        state: SESS_STATE_ESTABLISHED,
        flags,
        tcp_state: 0,
        is_reverse: if metadata.is_reverse { 1 } else { 0 },
        app_timeout: 0,
        // #5213: the stable session id from the session table (was hardcoded 0).
        session_id,
        created: now_secs,
        last_seen: now_secs,
        // #8125: see the v4 arm.
        timeout: if timeout_secs > 0 { timeout_secs } else { 1800 },
        // #3056: see publish_v4_session — stamp the admitting policy ID so the
        // IPv6 live-session rows attribute the policy that admitted the flow.
        policy_id: metadata.policy_id,
        ingress_zone: ingress_zone_id,
        egress_zone: egress_zone_id,
        nat_src_ip,
        nat_dst_ip,
        nat_src_port,
        nat_dst_port,
        fwd_packets: 0,
        fwd_bytes: 0,
        rev_packets: 0,
        rev_bytes: 0,
        reverse_key: rev_key,
        alg_type,
        log_flags: 0,
        app_id,
        fib_ifindex: 0,
        fib_vlan_id: 0,
        fib_dmac: [0; 6],
        fib_smac: [0; 6],
        fib_gen: 0,
        // #4983: the session's TRUE ingress-interface identity, taken from the
        // metadata stamped at install (the binding the FIRST packet arrived
        // on) — deliberately NOT re-derived from `ingress_zone_id` here, which
        // is the very zone approximation the field replaces. `0` when the
        // session carries no ingress identity (reverse companion / peer-synced
        // import); the Go filter falls back to the zone approximation for it.
        ingress_ifindex: metadata.ingress_ifindex,
        ingress_vlan_id: metadata.ingress_vlan_id,
        // #9546: see conntrack_row_routing_domain.
        routing_domain: conntrack_row_routing_domain(key, metadata),
    })
}

#[cfg(test)]
mod alg_type_tests {
    use super::{
        ALG_DISABLE_DNS, ALG_DISABLE_FTP, ALG_DISABLE_SIP, ALG_TYPE_DNS, ALG_TYPE_FTP,
        ALG_TYPE_NONE, ALG_TYPE_SIP, PROTO_TCP, PROTO_UDP, alg_type_for_session,
    };

    // #2008 H3/H4: with no ALG disabled, a session on a well-known ALG
    // service port is tagged with its ALG type. The service port is the
    // forward destination port (client -> server).
    #[test]
    fn dns_session_tagged_when_alg_enabled() {
        // UDP/53 client (ephemeral src) -> server.
        assert_eq!(
            alg_type_for_session(PROTO_UDP, 41234, 53, 0),
            ALG_TYPE_DNS,
            "DNS session must be tagged DNS when the DNS ALG is enabled"
        );
    }

    #[test]
    fn ftp_session_tagged_when_alg_enabled() {
        assert_eq!(
            alg_type_for_session(PROTO_TCP, 51000, 21, 0),
            ALG_TYPE_FTP,
            "FTP session must be tagged FTP when the FTP ALG is enabled"
        );
    }

    #[test]
    fn sip_session_tagged_when_alg_enabled() {
        assert_eq!(alg_type_for_session(PROTO_UDP, 5060, 5060, 0), ALG_TYPE_SIP);
        assert_eq!(alg_type_for_session(PROTO_TCP, 40000, 5060, 0), ALG_TYPE_SIP);
    }

    // The enforcement under test (#2008 H3): when `security alg dns disable`
    // is set, the DNS-disable bit (0x01) MUST suppress the DNS ALG type — the
    // session is tagged `none`. This is the bit the audit found was written to
    // flow_config_map but never read. If the flag read is removed from
    // alg_type_for_session, this assertion regresses to ALG_TYPE_DNS.
    #[test]
    fn dns_session_not_tagged_when_alg_disabled() {
        assert_eq!(
            alg_type_for_session(PROTO_UDP, 41234, 53, ALG_DISABLE_DNS),
            ALG_TYPE_NONE,
            "`security alg dns disable` must turn the DNS ALG off (alg_type=none)"
        );
    }

    // #2008 H4: `security alg ftp disable` -> FTP-disable bit (0x02) suppresses
    // the FTP ALG type for TCP/21 sessions.
    #[test]
    fn ftp_session_not_tagged_when_alg_disabled() {
        assert_eq!(
            alg_type_for_session(PROTO_TCP, 51000, 21, ALG_DISABLE_FTP),
            ALG_TYPE_NONE,
            "`security alg ftp disable` must turn the FTP ALG off (alg_type=none)"
        );
    }

    #[test]
    fn sip_session_not_tagged_when_alg_disabled() {
        assert_eq!(
            alg_type_for_session(PROTO_UDP, 5060, 5060, ALG_DISABLE_SIP),
            ALG_TYPE_NONE,
            "`security alg sip disable` must turn the SIP ALG off (alg_type=none)"
        );
    }

    // Disabling one ALG must NOT affect another: with only DNS disabled, an
    // FTP session is still tagged FTP (proves the bits are read independently,
    // not as an all-or-nothing gate).
    #[test]
    fn disabling_dns_does_not_affect_ftp() {
        assert_eq!(
            alg_type_for_session(PROTO_TCP, 51000, 21, ALG_DISABLE_DNS),
            ALG_TYPE_FTP
        );
        assert_eq!(
            alg_type_for_session(PROTO_UDP, 41234, 53, ALG_DISABLE_FTP),
            ALG_TYPE_DNS
        );
    }

    // A session keyed in the REVERSE direction carries the well-known ALG
    // service port in the SRC slot (server -> client), not the dst. The
    // `on_port` helper checks `src_port == p || dst_port == p`, so the ALG
    // type must still resolve. Both directions of one ALG session map to the
    // same alg_type, which is required for the reverse conntrack entry the
    // publisher installs alongside the forward entry.
    #[test]
    fn dns_reverse_keyed_session_tagged_on_src_port() {
        // UDP 53 (server) -> ephemeral (client): well-known port in src slot.
        assert_eq!(
            alg_type_for_session(PROTO_UDP, 53, 41234, 0),
            ALG_TYPE_DNS,
            "reverse-keyed DNS session must match the well-known port on the src slot"
        );
        // The disable bit still suppresses it in the reverse direction.
        assert_eq!(
            alg_type_for_session(PROTO_UDP, 53, 41234, ALG_DISABLE_DNS),
            ALG_TYPE_NONE,
            "`security alg dns disable` must apply to reverse-keyed sessions too"
        );
    }

    #[test]
    fn ftp_reverse_keyed_session_tagged_on_src_port() {
        // TCP 21 (server) -> ephemeral (client): well-known port in src slot.
        assert_eq!(
            alg_type_for_session(PROTO_TCP, 21, 51000, 0),
            ALG_TYPE_FTP,
            "reverse-keyed FTP session must match the well-known port on the src slot"
        );
        assert_eq!(
            alg_type_for_session(PROTO_TCP, 21, 51000, ALG_DISABLE_FTP),
            ALG_TYPE_NONE,
            "`security alg ftp disable` must apply to reverse-keyed sessions too"
        );
    }

    // Junos `alg disable` turns the ALG OFF; it never drops traffic. The
    // dataplane has no DNS/FTP ALG transform, so a disabled ALG is simply not
    // tagged — non-ALG ports are always `none` regardless of the flags.
    #[test]
    fn non_alg_port_is_always_none() {
        assert_eq!(alg_type_for_session(PROTO_TCP, 12345, 443, 0), ALG_TYPE_NONE);
        assert_eq!(
            alg_type_for_session(PROTO_TCP, 12345, 443, 0xff),
            ALG_TYPE_NONE
        );
        // Wrong protocol on an ALG port (e.g. TCP/53) is not the DNS ALG.
        assert_eq!(alg_type_for_session(PROTO_TCP, 41234, 53, 0), ALG_TYPE_NONE);
    }
}

#[cfg(test)]
mod publish_chokepoint_6923_tests {
    use super::*;

    /// #6923: the refusal covers exactly the traversable set — and no more.
    ///
    /// The second half is the part that needs saying. A refusal that is too
    /// WIDE is not a safe direction here: it would stop publishing sessions
    /// that are legitimate today, turning a backstop into an outage. So this
    /// sweeps all 256 values and asserts both directions.
    #[test]
    fn refusal_covers_exactly_the_traversable_set_6923() {
        let mut refused = Vec::new();
        for protocol in 0u8..=255 {
            let publishable = v6_session_key_is_publishable(protocol);
            let traversable = crate::afxdp::ipv6_ext_header_is_traversable(protocol);
            assert_eq!(
                publishable, !traversable,
                "#6923: protocol {protocol}: publishable={publishable} but traversable={traversable}. \
                 The refusal must be exactly the set the shim's walk can emit by exhausting its \
                 loop — narrower reopens the hole, wider drops legitimate sessions"
            );
            if !publishable {
                refused.push(protocol);
            }
        }
        assert_eq!(
            refused,
            vec![0, 43, 44, 51, 60, 135, 139, 140, 253, 254],
            "#6923: the refused set changed. If the walker legitimately learned a new traversable \
             type this is the expected red — update it deliberately. If it SHRANK, the refusal \
             just stopped covering a value the shim can still emit"
        );
    }

    /// THE POSITIVE CONTROL: the refusal must not reject a key that is
    /// legitimate today.
    ///
    /// Without this the sweep above is satisfiable by refusing everything, and
    /// "refuse everything" is a total outage of v6 session publication that
    /// would look, from the shim's side, exactly like the fix working — every
    /// probe misses and every packet goes to userspace. Slower, correct-looking,
    /// and catastrophic.
    #[test]
    fn refusal_does_not_reject_a_currently_legitimate_key_6923() {
        for (protocol, name) in [
            (PROTO_TCP, "TCP"),
            (PROTO_UDP, "UDP"),
            (crate::ip_proto::PROTO_ICMPV6, "ICMPv6"),
            (crate::ip_proto::PROTO_ESP, "ESP"),
            (crate::ip_proto::PROTO_SCTP, "SCTP"),
            (crate::ip_proto::PROTO_GRE, "GRE"),
        ] {
            assert!(
                v6_session_key_is_publishable(protocol),
                "#6923: {name} ({protocol}) is a real L4/terminal protocol whose v6 sessions must \
                 still publish. Refusing it would take the fast path away from live traffic, and \
                 from the shim's side that is indistinguishable from the backstop working"
            );
        }
    }

    /// #6923 WIRING: `publish_v6_session` must CALL the refusal, before it
    /// builds the key.
    ///
    /// Added because deleting the call red nothing: every other test here
    /// exercises the predicate directly, and the predicate was never the part
    /// at risk. A refusal that is perfectly correct and never invoked is the
    /// defect this whole change is about, one layer in — and this codebase has
    /// hit that shape repeatedly (#6888, #7713, and #7734's own detector).
    ///
    /// A behavioural test would be better, but publishing needs a real BPF map
    /// fd and CAP_BPF, which unit tests do not have. So this binds the call
    /// site structurally, and the ORDER with it: the refusal must precede the
    /// `BpfSessionKeyV6` construction, because a check after the map update
    /// would let the key exist for the window that matters.
    #[test]
    fn publish_v6_session_calls_the_refusal_before_building_the_key_6923() {
        let src = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("src/afxdp/bpf_map/publish_conntrack.rs"),
        )
        .expect("read publish_conntrack.rs");
        let code: String = src
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        let start = code
            .find("pub(super) fn publish_v6_session(")
            .expect("#6923: publish_v6_session is gone — fix this bind, do not delete it");
        let body = &code[start..];
        let end = body.find("\n}").expect("#6923: could not bound publish_v6_session");
        let body = &body[..end];

        let guard_at = body.find("v6_session_key_is_publishable").expect(
            "#6923: publish_v6_session does not call the refusal. The predicate can be entirely \
             correct and never invoked — that is the same defect this change exists to close, one \
             layer in",
        );
        // #7743: the key construction was single-sourced into
        // `bpf_session_key_v6`, so this anchor accepts EITHER spelling and
        // takes whichever appears first. Pinning only the struct literal made
        // this guard fail the moment the builder replaced it — a pinned literal
        // must become an alias, not a decommissioned test. If NEITHER spelling
        // is present the key is no longer built here at all, and the expect
        // below fails loudly rather than passing vacuously.
        let key_at = [
            body.find("bpf_session_key_v6("),
            body.find("BpfSessionKeyV6 {"),
        ]
        .into_iter()
        .flatten()
        .min()
        .expect(
            "#6923/#7743: publish_v6_session no longer builds a v6 key by any known spelling \
             (neither `bpf_session_key_v6(` nor `BpfSessionKeyV6 {`) — re-anchor this bind, do \
             not delete it",
        );
        assert!(
            guard_at < key_at,
            "#6923: the refusal must run BEFORE the key is built and published. A check placed \
             after the map update leaves the key visible to the shim for exactly the window that \
             matters"
        );
    }

    /// #6923 anti-drift: the refusal must DERIVE from the walker's own set.
    ///
    /// Comments stripped first — this module's prose names both identifiers, so
    /// an unstripped scan would be satisfied by the documentation rather than
    /// the code (the #6885 lesson).
    #[test]
    fn refusal_derives_from_the_walker_set_not_a_second_list_6923() {
        let src = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("src/afxdp/bpf_map/publish_conntrack.rs"),
        )
        .expect("read publish_conntrack.rs");
        let code: String = src
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        let start = code
            .find("fn v6_session_key_is_publishable(")
            .expect("#6923: the predicate is gone — this bind has rotted, fix it, do not delete it");
        let body = &code[start..];
        let end = body.find("\n}").expect("#6923: could not bound the predicate");
        let body = &body[..end];
        assert!(
            body.contains("ipv6_ext_header_is_traversable"),
            "#6923: the refusal must derive from `ipv6_ext_header_is_traversable`, not restate a \
             list of protocol numbers. A second copy drifts, and it drifts toward reopening the \
             hole: the walker learns a type, the copy does not, and the refusal silently stops \
             covering it"
        );
    }
}

#[cfg(test)]
mod routing_domain_row_9546_tests {
    //! #9546 — a conntrack mirror row must state the session's routing domain,
    //! and state it TRUTHFULLY.
    //!
    //! The Go delete paths read `routing_domain` back out of this row to name the
    //! domain on the helper delete (#9146 singular, #9364 batch). The unprivileged
    //! Go round-trip cells and the privileged Go mirror cells cover rows the GO
    //! writer produces; these cover the rows the HELPER produces, which is the
    //! writer for every helper-owned local session and therefore the dominant
    //! source of the rows the conntrack GC deletes.
    //!
    //! They drive the BUILDERS, not just the pure helper. A cell on
    //! `conntrack_row_routing_domain` alone stays green if a builder stops calling
    //! it and writes `routing_domain: 0` in its literal — which would restore the
    //! exact inertness this issue removes.
    use super::{build_conntrack_value_v4, build_conntrack_value_v6, conntrack_row_routing_domain};
    use crate::afxdp::{ForwardingDisposition, ForwardingResolution};
    use crate::ip_proto::PROTO_TCP;
    use crate::nat::NatDecision;
    use crate::session::{
        routing_domain_from_wire, routing_domain_to_wire, SessionDecision, SessionKey,
        SessionMetadata, WireRoutingDomain, ROUTING_DOMAIN_WIRE_ABSENT,
    };
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    const TENANT: u32 = 100_007;

    fn decision() -> SessionDecision {
        SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 0,
                tx_ifindex: 0,
                tunnel_endpoint_id: 0,
                next_hop: None,
                neighbor_mac: None,
                src_mac: None,
                tx_vlan_id: 0,
            },
            nat: NatDecision::default(),
        }
    }

    fn metadata(is_reverse: bool) -> SessionMetadata {
        SessionMetadata {
            ingress_zone: 1,
            egress_zone: 2,
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            owner_rg_id: 1,
            fabric_ingress: false,
            is_reverse,
            nat64_reverse: None,
            log_session_init: false,
            log_session_close: false,
            policy_id: 0,
            inactivity_timeout_ns: None,
            policy_counter_idx: 0,
            policy_counter: None,
        }
    }

    fn key_v4(domain: u32) -> SessionKey {
        SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 55068,
            dst_port: 5201,
            discriminator: Default::default(),
            routing_domain: domain,
        }
    }

    fn key_v6(domain: u32) -> SessionKey {
        SessionKey {
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 0x102)),
            dst_ip: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 80, 0, 0, 0, 0x200)),
            src_port: 55068,
            dst_port: 5201,
            discriminator: Default::default(),
            routing_domain: domain,
        }
    }

    #[test]
    fn forward_row_states_the_tenant_domain_9546() {
        let got = conntrack_row_routing_domain(&key_v4(TENANT), &metadata(false));
        assert!(
            matches!(routing_domain_from_wire(got), WireRoutingDomain::Present(d) if d == TENANT),
            "a forward row must state its tenant domain in the #7239 wire encoding; got {got}"
        );
    }

    /// The default instance is a STATEMENT, not an absence. A forward row whose
    /// key is in the default instance must carry the non-zero default marker, so
    /// the Go delete names it and the helper does an exact lookup instead of the
    /// probe #8636 refuses when ambiguous.
    #[test]
    fn forward_default_instance_row_states_the_default_marker_not_absence_9546() {
        let got = conntrack_row_routing_domain(&key_v4(0), &metadata(false));
        assert_eq!(got, routing_domain_to_wire(0));
        assert_ne!(
            got, ROUTING_DOMAIN_WIRE_ABSENT,
            "a default-instance forward row must not read as 'not stated'"
        );
        assert!(matches!(routing_domain_from_wire(got), WireRoutingDomain::Present(0)));
    }

    /// LOAD-BEARING CONTROL, both directions. A reverse row's key is the
    /// reverse-match key, deliberately domain-agnostic (#7160). Encoding its 0
    /// would claim the default instance for a tenant flow's reply half — false.
    /// It must state ABSENCE, and must do so even if a key somehow carried a
    /// tenant, because the row's direction, not the key's field, is the truth.
    #[test]
    fn reverse_row_states_absence_not_a_guessed_domain_9546() {
        for key_domain in [0, TENANT] {
            let got = conntrack_row_routing_domain(&key_v4(key_domain), &metadata(true));
            assert_eq!(
                got, ROUTING_DOMAIN_WIRE_ABSENT,
                "a reverse row (key domain {key_domain}) must state absence, got {got}"
            );
            assert!(matches!(routing_domain_from_wire(got), WireRoutingDomain::Absent));
        }
    }

    #[test]
    fn built_v4_forward_row_carries_the_domain_9546() {
        let row = build_conntrack_value_v4(
            &key_v4(TENANT), decision(), &metadata(false), 0, 1, 2, 0, 0, 0, 0, 0,
        )
        .expect("a same-family v4 key must build a row");
        assert_eq!(
            row.routing_domain, TENANT,
            "build_conntrack_value_v4 wrote routing_domain={}, want {TENANT} — the Go GC reads \
             this back to scope its delete; 0 here restores the #9546 inertness",
            row.routing_domain
        );
    }

    #[test]
    fn built_v6_forward_row_carries_the_domain_9546() {
        let row = build_conntrack_value_v6(
            &key_v6(TENANT), decision(), &metadata(false), 0, 1, 2, 0, 0, 0, 0, 0,
        )
        .expect("a same-family v6 key must build a row");
        assert_eq!(
            row.routing_domain, TENANT,
            "build_conntrack_value_v6 wrote routing_domain={}, want {TENANT} — V6 has its own \
             builder and can regress on its own",
            row.routing_domain
        );
    }

    #[test]
    fn built_reverse_row_states_absence_9546() {
        let row = build_conntrack_value_v4(
            &key_v4(0), decision(), &metadata(true), 0, 1, 2, 0, 0, 0, 0, 0,
        )
        .expect("a same-family v4 key must build a row");
        assert_eq!(row.routing_domain, ROUTING_DOMAIN_WIRE_ABSENT);
    }
}
