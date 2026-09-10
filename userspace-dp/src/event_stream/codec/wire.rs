//! Wire-format constants and low-level frame-serialization primitives.
//!
//! Split out of the former single-file `codec.rs` (#4651): the message-type
//! and flag constants, the RT_FLOW event/action/disposition byte values, the
//! header/address write helpers, and the header-only stream-control frame
//! encoders. All frame construction happens on a stack-allocated `[u8; 256]`
//! buffer.

use crate::afxdp::ForwardingDisposition;
use std::net::IpAddr;

use super::EventFrame;

// ---------------------------------------------------------------------------
// Wire format constants
// ---------------------------------------------------------------------------

pub(crate) const FRAME_HEADER_SIZE: usize = 16;

pub(crate) const MSG_SESSION_OPEN: u8 = 1;
pub(crate) const MSG_SESSION_CLOSE: u8 = 2;
pub(crate) const MSG_SESSION_UPDATE: u8 = 3;
pub(crate) const MSG_ACK: u8 = 4;
pub(crate) const MSG_PAUSE: u8 = 5;
pub(crate) const MSG_RESUME: u8 = 6;
pub(crate) const MSG_DRAIN_REQUEST: u8 = 7;
pub(crate) const MSG_DRAIN_COMPLETE: u8 = 8;
pub(crate) const MSG_FULL_RESYNC: u8 = 9;
pub(crate) const MSG_KEEPALIVE: u8 = 10;

// #1379 codec-only security event foundation. Producer wiring must add
// fixed-size non-blocking emission, rate limiting, and loss accounting.
#[allow(dead_code)]
pub(crate) const MSG_POLICY_DENY: u8 = 11;
#[allow(dead_code)]
pub(crate) const MSG_SCREEN_DROP: u8 = 12;
#[allow(dead_code)]
pub(crate) const MSG_FILTER_LOG: u8 = 13;

// #2460: RT_FLOW SESSION_CLOSE on the raw dataplane-event channel. This
// frame carries the canonical 144-byte `dataplane.Event` payload (the same
// shape the Go `logging.DecodeRawEventRecord` / `ProcessRawEvent` parser
// consumes for the deny/screen/filter frames above) with the event-type
// byte set to RT_FLOW SESSION_CLOSE (2). It is what drives the Go
// NetFlow/IPFIX session-close exporters in userspace mode. It is ADDITIVE
// to — and entirely separate from — the minimal `MSG_SESSION_CLOSE` (type
// 2) HA session-sync delta below; the two are emitted as a pair from one
// close, never substituting for each other.
pub(crate) const MSG_SESSION_CLOSE_RT_FLOW: u8 = 14;

// #2508: RT_FLOW SESSION_CREATE on the raw dataplane-event channel. Same
// 144-byte payload shape as the close frame but with the event-type byte set
// to RT_FLOW SESSION_CREATE (1). Emitted ONLY for sessions admitted by a
// policy with `then log session-init`; there is no flowexport consumer of
// session opens, so this frame is gated at the producer (the caller checks
// metadata.log_session_init). The Go logEvent path formats it as an
// RT_FLOW_SESSION_CREATE syslog record.
pub(crate) const MSG_SESSION_CREATE_RT_FLOW: u8 = 15;

// #2749: 152 bytes (was 144). The trailing [144:152] block carries the
// class-of-service / interface-attribution fields the NetFlow v9 + IPFIX
// SESSION_CLOSE exporters re-introduce: [144] src ToS byte (DSCP<<2),
// [145] accumulated TCP control bits, [146] flow direction (reserved, 0 —
// deferred follow-up), [147] reserved, [148:152] egress ifindex (LE u32).
// Only the SESSION_CLOSE frame populates these; every other frame leaves
// [144:152] zero. The growth is purely ADDITIVE: the Go side keeps its
// minimum-frame acceptance at the legacy 144 bytes (`rawEventWireSize`) and
// reads [144:152] only when the frame actually carries them
// (`len(data) >= 152`), so a new daemon still accepts an old (144-byte)
// helper's frames and an old daemon ignores the trailing 8 bytes — both
// rolling-upgrade directions are safe (#1961 both-sides wire discipline).
//
// #3056: [136:140] carries the admitting policy ID on the SESSION_CLOSE
// frame, whose [44:48] policy_id slot is occupied by the #2853
// created-subsec-nanos remainder and so cannot hold the policy ID the way the
// SESSION_CREATE / deny / screen / filter frames do. [140:144] stays reserved
// padding. All frame encoders emit this length; non-close frames leave
// [136:152] zero.
//
// #4915: 160 bytes (was 152). The trailing [152:160] u64 carries the
// dataplane's STABLE session id (LE) on the SESSION_CREATE and SESSION_CLOSE
// frames so a SIEM/operator can join a session's open and close records — the
// per-event ordinal the Go side stamped before could never match across the
// two events, nor disambiguate a reused 5-tuple. Only the two RT_FLOW session
// frames populate this slot (`encode_session_create_rt_flow` /
// `encode_session_close_rt_flow`); deny/screen/filter frames have no session
// and leave it zero. The growth is ADDITIVE with the same discipline as the
// #2749 [144:152] block: the Go side keeps its minimum-frame acceptance at the
// legacy 144 bytes (`rawEventWireSize`) and reads [152:160] only when the frame
// carries it (`len(data) >= 160`) AND only on a session frame, so both
// rolling-upgrade directions stay safe (#1961 both-sides wire discipline).
#[allow(dead_code)]
pub(crate) const SECURITY_EVENT_PAYLOAD_SIZE: usize = 160;

pub(super) const RT_FLOW_AF_INET: u8 = 2;
pub(super) const RT_FLOW_AF_INET6: u8 = 10;
// #2460: SESSION_CLOSE event-type byte. Must equal the Go
// `eventTypeSessionClose` (pkg/logging/ringbuf.go) and
// `dataplane.EventTypeSessionClose` (pkg/dataplane/types.go) value of 2,
// so `eventTypeName(data[52])` resolves to the literal "SESSION_CLOSE" the
// flowexport callbacks gate on.
pub(super) const RT_FLOW_EVENT_SESSION_CLOSE: u8 = 2;
// #2508: SESSION_CREATE event-type byte. Must equal the Go
// `eventTypeSessionOpen` (pkg/logging/ringbuf.go) and
// `dataplane.EventTypeSessionOpen` value of 1 so `eventTypeName(data[52])`
// resolves to "SESSION_OPEN", which the Go formatter renders as the
// RT_FLOW_SESSION_CREATE syslog tag.
pub(super) const RT_FLOW_EVENT_SESSION_OPEN: u8 = 1;
// #2508: per-policy SYSLOG log gate, written to the final payload byte
// (offset 135). 1 == emit the per-policy RT_FLOW SYSLOG record on the Go
// side; 0 == suppress it (the global flowexport close exporter is
// unaffected).
pub(super) const RT_FLOW_LOG_SYSLOG: u8 = 1;
pub(super) const RT_FLOW_EVENT_POLICY_DENY: u8 = 3;
pub(super) const RT_FLOW_EVENT_SCREEN_DROP: u8 = 4;
pub(super) const RT_FLOW_EVENT_FILTER_LOG: u8 = 6;
// #2460: SESSION_CLOSE reason byte. The HA close delta carries no
// idle/FIN/RST/age discriminator, so the RT_FLOW close reports "none" (0).
// A real close-reason (and the byte/packet counters + session duration this
// frame currently reports as 0) is the per-session accounting work tracked
// in #2501.
pub(super) const RT_FLOW_CLOSE_REASON_NONE: u8 = 0;
// DENY/PERMIT are wire-format documentation pinned by codec_tests;
// like REJECT below they have no non-test reader (#1826: exposed when
// the stale module-level allow was removed).
#[allow(dead_code)]
pub(super) const RT_FLOW_ACTION_DENY: u8 = 0;
#[allow(dead_code)]
pub(super) const RT_FLOW_ACTION_PERMIT: u8 = 1;
#[allow(dead_code)]
pub(super) const RT_FLOW_ACTION_REJECT: u8 = 2;

/// Disposition encoding for the wire format.
pub(super) const DISP_FORWARD_CANDIDATE: u8 = 0;
pub(super) const DISP_LOCAL_DELIVERY: u8 = 1;
pub(super) const DISP_FABRIC_REDIRECT: u8 = 2;
pub(super) const DISP_POLICY_DENIED: u8 = 3;
pub(super) const DISP_NO_ROUTE: u8 = 4;
pub(super) const DISP_MISSING_NEIGHBOR: u8 = 5;
pub(super) const DISP_HA_INACTIVE: u8 = 6;
pub(super) const DISP_DISCARD_ROUTE: u8 = 7;
pub(super) const DISP_NEXT_TABLE_UNSUPPORTED: u8 = 8;

// Flag bits for SessionOpen/Close
pub(crate) const FLAG_FABRIC_REDIRECT: u8 = 1 << 0;
pub(crate) const FLAG_FABRIC_INGRESS: u8 = 1 << 1;
pub(crate) const FLAG_IS_REVERSE: u8 = 1 << 2;
// #2785: carry the admitting policy's per-policy `then log` selection on
// the HA session-sync open frame so a session that fails over to the peer
// keeps emitting the same RT_FLOW SESSION_CREATE/CLOSE syslog records after
// takeover. Additive bits on the existing flags byte: an old peer leaves
// them clear (0), which decodes to "no per-policy log" — bit-identical to
// pre-#2785 behavior (rolling-upgrade safe).
pub(crate) const FLAG_LOG_SESSION_INIT: u8 = 1 << 3;
pub(crate) const FLAG_LOG_SESSION_CLOSE: u8 = 1 << 4;
// #4565: mark a NAT64 cross-address-family session so a peer-PROMOTED session
// can rebuild its RFC 6146 reverse BIB after failover. A NAT64 forward flow is
// keyed on the ORIGINAL IPv6 5-tuple, but its NAT decision rewrites to an IPv4
// pool source (`snat_v4`) + IPv4 destination, and the reverse (v4->v6) reply is
// keyed on `(server_v4 -> snat_v4, translated port)`. The synced generic NAT
// address fields cannot carry a v4 source in a v6 session's 16-byte slot
// unambiguously, so this flag tells the standby: (a) set `nat.nat64`, (b) read
// the trailing `snat_v4` (below), (c) reconstruct the original v6 src/dst from
// the forward KEY (they ARE `key.src_ip`/`key.dst_ip` for a NAT64 forward
// session) and `dst_v4` from the /96-embedded low 32 bits of `key.dst_ip`.
// Additive bit: an old peer leaves it clear (0) -> decodes to "not NAT64",
// bit-identical to pre-#4565 (rolling-upgrade safe).
pub(crate) const FLAG_NAT64: u8 = 1 << 5;

// ---------------------------------------------------------------------------
// Header / address write helpers
// ---------------------------------------------------------------------------

pub(super) fn write_header(buf: &mut [u8; 256], payload_len: u32, msg_type: u8, seq: u64) {
    buf[0..4].copy_from_slice(&payload_len.to_le_bytes());
    buf[4] = msg_type;
    // buf[5..8] reserved (already zeroed)
    buf[8..16].copy_from_slice(&seq.to_le_bytes());
}

pub(super) fn write_ip(buf: &mut [u8; 256], pos: usize, ip: IpAddr, is_v6: bool) -> usize {
    match ip {
        IpAddr::V4(v4) => {
            buf[pos..pos + 4].copy_from_slice(&v4.octets());
            if is_v6 {
                // pad to 16 bytes if frame is v6 but this particular IP is v4
                // (shouldn't normally happen, but be safe)
                pos + 16
            } else {
                pos + 4
            }
        }
        IpAddr::V6(v6) => {
            buf[pos..pos + 16].copy_from_slice(&v6.octets());
            pos + 16
        }
    }
}

pub(super) fn write_ip_opt(
    buf: &mut [u8; 256],
    pos: usize,
    ip: Option<IpAddr>,
    is_v6: bool,
) -> usize {
    match ip {
        Some(addr) => write_ip(buf, pos, addr, is_v6),
        None => {
            let size = if is_v6 { 16 } else { 4 };
            // already zeroed
            pos + size
        }
    }
}

#[allow(dead_code)]
pub(super) fn write_ip_16(buf: &mut [u8; 256], pos: usize, ip: IpAddr) -> usize {
    match ip {
        IpAddr::V4(v4) => buf[pos..pos + 4].copy_from_slice(&v4.octets()),
        IpAddr::V6(v6) => buf[pos..pos + 16].copy_from_slice(&v6.octets()),
    }
    pos + 16
}

#[allow(dead_code)]
pub(super) fn write_ip_opt_16(buf: &mut [u8; 256], pos: usize, ip: Option<IpAddr>) -> usize {
    if let Some(addr) = ip {
        write_ip_16(buf, pos, addr)
    } else {
        pos + 16
    }
}

#[allow(dead_code)]
pub(super) fn rt_flow_addr_family(addr_family: u8, src_ip: IpAddr) -> u8 {
    if addr_family == libc::AF_INET6 as u8 || matches!(src_ip, IpAddr::V6(_)) {
        RT_FLOW_AF_INET6
    } else {
        RT_FLOW_AF_INET
    }
}

pub(super) fn encode_disposition(d: ForwardingDisposition) -> u8 {
    match d {
        ForwardingDisposition::ForwardCandidate => DISP_FORWARD_CANDIDATE,
        ForwardingDisposition::LocalDelivery => DISP_LOCAL_DELIVERY,
        ForwardingDisposition::FabricRedirect => DISP_FABRIC_REDIRECT,
        ForwardingDisposition::PolicyDenied => DISP_POLICY_DENIED,
        ForwardingDisposition::NoRoute => DISP_NO_ROUTE,
        ForwardingDisposition::MissingNeighbor => DISP_MISSING_NEIGHBOR,
        ForwardingDisposition::HAInactive => DISP_HA_INACTIVE,
        ForwardingDisposition::DiscardRoute => DISP_DISCARD_ROUTE,
        ForwardingDisposition::NextTableUnsupported => DISP_NEXT_TABLE_UNSUPPORTED,
    }
}

// ---------------------------------------------------------------------------
// Header-only stream-control frames
// ---------------------------------------------------------------------------

impl EventFrame {
    /// Encode a DrainComplete (type 8) frame -- header only, no payload.
    pub(crate) fn encode_drain_complete(seq: u64) -> Self {
        let mut buf = [0u8; 256];
        write_header(&mut buf, 0, MSG_DRAIN_COMPLETE, seq);
        EventFrame {
            data: buf,
            len: FRAME_HEADER_SIZE as u16,
            seq,
        }
    }

    /// Encode a FullResync (type 9) frame -- header only, no payload.
    pub(crate) fn encode_full_resync(seq: u64) -> Self {
        let mut buf = [0u8; 256];
        write_header(&mut buf, 0, MSG_FULL_RESYNC, seq);
        EventFrame {
            data: buf,
            len: FRAME_HEADER_SIZE as u16,
            seq,
        }
    }
}
