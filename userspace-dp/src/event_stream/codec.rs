//! Wire codec for the event stream binary protocol.
//!
//! Pure encoding/decoding functions with zero I/O — all frame construction
//! happens on a stack-allocated `[u8; 256]` buffer.

use crate::afxdp::ForwardingDisposition;
use crate::session::{SessionDecision, SessionDelta, SessionKey, SessionMetadata};
use rustc_hash::FxHashMap;
use std::net::IpAddr;

// ---------------------------------------------------------------------------
// Wire format constants
// ---------------------------------------------------------------------------

pub(crate) const FRAME_HEADER_SIZE: usize = 16;

pub(crate) const MSG_SESSION_OPEN: u8 = 1;
pub(crate) const MSG_SESSION_CLOSE: u8 = 2;
#[allow(dead_code)]
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

#[allow(dead_code)]
pub(crate) const SECURITY_EVENT_PAYLOAD_SIZE: usize = 136;

const RT_FLOW_AF_INET: u8 = 2;
const RT_FLOW_AF_INET6: u8 = 10;
const RT_FLOW_EVENT_POLICY_DENY: u8 = 3;
const RT_FLOW_EVENT_SCREEN_DROP: u8 = 4;
const RT_FLOW_EVENT_FILTER_LOG: u8 = 6;
const RT_FLOW_ACTION_DENY: u8 = 0;
const RT_FLOW_ACTION_PERMIT: u8 = 1;

/// Disposition encoding for the wire format.
const DISP_FORWARD_CANDIDATE: u8 = 0;
const DISP_LOCAL_DELIVERY: u8 = 1;
const DISP_FABRIC_REDIRECT: u8 = 2;
const DISP_POLICY_DENIED: u8 = 3;
const DISP_NO_ROUTE: u8 = 4;
const DISP_MISSING_NEIGHBOR: u8 = 5;
const DISP_HA_INACTIVE: u8 = 6;
const DISP_DISCARD_ROUTE: u8 = 7;
const DISP_NEXT_TABLE_UNSUPPORTED: u8 = 8;

// Flag bits for SessionOpen/Close
pub(crate) const FLAG_FABRIC_REDIRECT: u8 = 1 << 0;
pub(crate) const FLAG_FABRIC_INGRESS: u8 = 1 << 1;
pub(crate) const FLAG_IS_REVERSE: u8 = 1 << 2;

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DataplaneEventKind {
    PolicyDeny,
    ScreenDrop,
    FilterLog,
}

#[allow(dead_code)]
impl DataplaneEventKind {
    fn msg_type(self) -> u8 {
        match self {
            Self::PolicyDeny => MSG_POLICY_DENY,
            Self::ScreenDrop => MSG_SCREEN_DROP,
            Self::FilterLog => MSG_FILTER_LOG,
        }
    }

    fn from_msg_type(msg_type: u8) -> Option<Self> {
        match msg_type {
            MSG_POLICY_DENY => Some(Self::PolicyDeny),
            MSG_SCREEN_DROP => Some(Self::ScreenDrop),
            MSG_FILTER_LOG => Some(Self::FilterLog),
            _ => None,
        }
    }

    fn rt_flow_event_type(self) -> u8 {
        match self {
            Self::PolicyDeny => RT_FLOW_EVENT_POLICY_DENY,
            Self::ScreenDrop => RT_FLOW_EVENT_SCREEN_DROP,
            Self::FilterLog => RT_FLOW_EVENT_FILTER_LOG,
        }
    }

    fn from_rt_flow_event_type(event_type: u8) -> Option<Self> {
        match event_type {
            RT_FLOW_EVENT_POLICY_DENY => Some(Self::PolicyDeny),
            RT_FLOW_EVENT_SCREEN_DROP => Some(Self::ScreenDrop),
            RT_FLOW_EVENT_FILTER_LOG => Some(Self::FilterLog),
            _ => None,
        }
    }
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DataplaneEventPayload {
    pub(crate) kind: DataplaneEventKind,
    pub(crate) addr_family: u8,
    pub(crate) protocol: u8,
    pub(crate) action: u8,
    pub(crate) src_ip: IpAddr,
    pub(crate) dst_ip: IpAddr,
    pub(crate) src_port: u16,
    pub(crate) dst_port: u16,
    pub(crate) nat_src_ip: Option<IpAddr>,
    pub(crate) nat_dst_ip: Option<IpAddr>,
    pub(crate) nat_src_port: u16,
    pub(crate) nat_dst_port: u16,
    pub(crate) ingress_zone_id: u16,
    pub(crate) egress_zone_id: u16,
    pub(crate) ingress_ifindex: i32,
    pub(crate) policy_id: u32,
    pub(crate) rule_id: u32,
    pub(crate) term_id: u32,
    pub(crate) reason: u8,
    pub(crate) owner_rg_id: i16,
    pub(crate) application_id: u16,
    pub(crate) filter_id: u32,
    pub(crate) screen_id: u32,
    pub(crate) timestamp_ns: u64,
}

// ---------------------------------------------------------------------------
// EventFrame -- zero-allocation stack-buffered wire frame
// ---------------------------------------------------------------------------

/// Pre-serialized event frame ready for socket write.
#[derive(Clone)]
pub(crate) struct EventFrame {
    pub(super) data: [u8; 256],
    pub(super) len: u16,
    pub(crate) seq: u64,
}

impl EventFrame {
    /// Encode a SessionOpen (type 1) or SessionUpdate (type 3) frame.
    pub(crate) fn encode_session_open(
        seq: u64,
        key: &SessionKey,
        decision: &SessionDecision,
        metadata: &SessionMetadata,
        _zone_name_to_id: &FxHashMap<String, u16>,
        fabric_redirect_sync: bool,
    ) -> Self {
        let mut buf = [0u8; 256];
        let mut pos = FRAME_HEADER_SIZE; // skip header, fill later

        // [0] AddrFamily
        let is_v6 = key.addr_family == libc::AF_INET6 as u8;
        buf[pos] = if is_v6 { 6 } else { 4 };
        pos += 1;

        // [1] Protocol
        buf[pos] = key.protocol;
        pos += 1;

        // [2:4] SrcPort LE
        buf[pos..pos + 2].copy_from_slice(&key.src_port.to_le_bytes());
        pos += 2;

        // [4:6] DstPort LE
        buf[pos..pos + 2].copy_from_slice(&key.dst_port.to_le_bytes());
        pos += 2;

        // [6:8] NATSrcPort LE
        let nat = &decision.nat;
        buf[pos..pos + 2].copy_from_slice(&nat.rewrite_src_port.unwrap_or(0).to_le_bytes());
        pos += 2;

        // [8:10] NATDstPort LE
        buf[pos..pos + 2].copy_from_slice(&nat.rewrite_dst_port.unwrap_or(0).to_le_bytes());
        pos += 2;

        // [10:12] OwnerRGID i16 LE
        buf[pos..pos + 2].copy_from_slice(&(metadata.owner_rg_id as i16).to_le_bytes());
        pos += 2;

        // [12:14] EgressIfindex i16 LE
        buf[pos..pos + 2]
            .copy_from_slice(&(decision.resolution.egress_ifindex as i16).to_le_bytes());
        pos += 2;

        // [14:16] TXIfindex i16 LE
        buf[pos..pos + 2].copy_from_slice(&(decision.resolution.tx_ifindex as i16).to_le_bytes());
        pos += 2;

        // [16:18] TunnelEndpointID u16 LE
        buf[pos..pos + 2].copy_from_slice(&decision.resolution.tunnel_endpoint_id.to_le_bytes());
        pos += 2;

        // [18:20] TXVLANID u16 LE
        buf[pos..pos + 2].copy_from_slice(&decision.resolution.tx_vlan_id.to_le_bytes());
        pos += 2;

        // [20] Flags
        let mut flags: u8 = 0;
        if fabric_redirect_sync
            || decision.resolution.disposition == ForwardingDisposition::FabricRedirect
        {
            flags |= FLAG_FABRIC_REDIRECT;
        }
        if metadata.fabric_ingress {
            flags |= FLAG_FABRIC_INGRESS;
        }
        if metadata.is_reverse {
            flags |= FLAG_IS_REVERSE;
        }
        buf[pos] = flags;
        pos += 1;

        // [21] IngressZoneID u8
        // #919/#922: SessionMetadata.ingress_zone is now u16 directly;
        // no name→id round-trip. Wire format remains u8 — assert this
        // at debug time. forwarding_build.rs:80 enforces zone IDs
        // ≤ ZONE_ID_RESERVED_MIN-1 ≪ 256 by construction (Go assigns
        // i+1 capped at MAX_ZONES=64).
        debug_assert!(
            metadata.ingress_zone < 256,
            "zone id {} exceeds wire u8 capacity",
            metadata.ingress_zone
        );
        let ingress_id = metadata.ingress_zone as u8;
        buf[pos] = ingress_id;
        pos += 1;

        // [22] EgressZoneID u8
        debug_assert!(
            metadata.egress_zone < 256,
            "zone id {} exceeds wire u8 capacity",
            metadata.egress_zone
        );
        let egress_id = metadata.egress_zone as u8;
        buf[pos] = egress_id;
        pos += 1;

        // [23] Disposition u8
        buf[pos] = encode_disposition(decision.resolution.disposition);
        pos += 1;

        // Addresses: 4 bytes each for v4, 16 bytes each for v6
        pos = write_ip(&mut buf, pos, key.src_ip, is_v6);
        pos = write_ip(&mut buf, pos, key.dst_ip, is_v6);
        pos = write_ip_opt(&mut buf, pos, nat.rewrite_src, is_v6);
        pos = write_ip_opt(&mut buf, pos, nat.rewrite_dst, is_v6);

        // NeighborMAC [6 bytes]
        if let Some(mac) = decision.resolution.neighbor_mac {
            buf[pos..pos + 6].copy_from_slice(&mac);
        }
        pos += 6;

        // SrcMAC [6 bytes]
        if let Some(mac) = decision.resolution.src_mac {
            buf[pos..pos + 6].copy_from_slice(&mac);
        }
        pos += 6;

        // NextHop (4 or 16 bytes)
        pos = write_ip_opt(&mut buf, pos, decision.resolution.next_hop, is_v6);

        // Write header
        let payload_len = (pos - FRAME_HEADER_SIZE) as u32;
        write_header(&mut buf, payload_len, MSG_SESSION_OPEN, seq);

        EventFrame {
            data: buf,
            len: pos as u16,
            seq,
        }
    }

    /// Encode a SessionClose (type 2) frame -- minimal payload.
    /// #919/#922: extended with u8 ingress_zone_id + u8 egress_zone_id
    /// after the flags byte. Old daemons that don't read those bytes
    /// see them as trailing payload (the frame length lets them
    /// length-skip), so this is wire-additive within the same MSG type.
    pub(crate) fn encode_session_close(
        seq: u64,
        key: &SessionKey,
        owner_rg_id: i32,
        close_flags: u8,
        ingress_zone_id: u16,
        egress_zone_id: u16,
    ) -> Self {
        let mut buf = [0u8; 256];
        let mut pos = FRAME_HEADER_SIZE;

        let is_v6 = key.addr_family == libc::AF_INET6 as u8;

        // [0] AddrFamily
        buf[pos] = if is_v6 { 6 } else { 4 };
        pos += 1;

        // [1] Protocol
        buf[pos] = key.protocol;
        pos += 1;

        // [2:4] SrcPort
        buf[pos..pos + 2].copy_from_slice(&key.src_port.to_le_bytes());
        pos += 2;

        // [4:6] DstPort
        buf[pos..pos + 2].copy_from_slice(&key.dst_port.to_le_bytes());
        pos += 2;

        // SrcIP, DstIP
        pos = write_ip(&mut buf, pos, key.src_ip, is_v6);
        pos = write_ip(&mut buf, pos, key.dst_ip, is_v6);

        // OwnerRGID i16 LE
        buf[pos..pos + 2].copy_from_slice(&(owner_rg_id as i16).to_le_bytes());
        pos += 2;

        // Flags
        buf[pos] = close_flags;
        pos += 1;

        // #919/#922: IngressZoneID u8, EgressZoneID u8.
        debug_assert!(ingress_zone_id < 256, "zone id {ingress_zone_id} > u8");
        debug_assert!(egress_zone_id < 256, "zone id {egress_zone_id} > u8");
        buf[pos] = ingress_zone_id as u8;
        pos += 1;
        buf[pos] = egress_zone_id as u8;
        pos += 1;

        let payload_len = (pos - FRAME_HEADER_SIZE) as u32;
        write_header(&mut buf, payload_len, MSG_SESSION_CLOSE, seq);

        EventFrame {
            data: buf,
            len: pos as u16,
            seq,
        }
    }

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

    /// Encode a fixed-size security telemetry event using the existing
    /// RT_FLOW dataplane.Event wire shape consumed by the Go ringbuf parser.
    ///
    /// Payload layout (136 bytes) matches `pkg/dataplane.Event`: timestamp,
    /// 16-byte src/dst IP slots, big-endian ports, little-endian identities
    /// and zones, event/protocol/action/address-family bytes, NAT slots, and
    /// extended ingress-ifindex/application fields.
    #[allow(dead_code)]
    pub(crate) fn encode_dataplane_event(seq: u64, event: &DataplaneEventPayload) -> Self {
        let mut buf = [0u8; 256];
        let base = FRAME_HEADER_SIZE;
        let wire_af = rt_flow_addr_family(event.addr_family, event.src_ip);
        let policy_or_reason_id = match event.kind {
            DataplaneEventKind::PolicyDeny => event.policy_id,
            DataplaneEventKind::ScreenDrop => event.screen_id,
            DataplaneEventKind::FilterLog => event.filter_id,
        };

        buf[base..base + 8].copy_from_slice(&event.timestamp_ns.to_le_bytes());
        write_ip_16(&mut buf, base + 8, event.src_ip);
        write_ip_16(&mut buf, base + 24, event.dst_ip);
        buf[base + 40..base + 42].copy_from_slice(&event.src_port.to_be_bytes());
        buf[base + 42..base + 44].copy_from_slice(&event.dst_port.to_be_bytes());
        buf[base + 44..base + 48].copy_from_slice(&policy_or_reason_id.to_le_bytes());
        buf[base + 48..base + 50].copy_from_slice(&event.ingress_zone_id.to_le_bytes());
        buf[base + 50..base + 52].copy_from_slice(&event.egress_zone_id.to_le_bytes());
        buf[base + 52] = event.kind.rt_flow_event_type();
        buf[base + 53] = event.protocol;
        buf[base + 54] = event.action;
        buf[base + 55] = wire_af;
        buf[base + 56..base + 60].copy_from_slice(&event.rule_id.to_le_bytes());
        buf[base + 60..base + 64].copy_from_slice(&event.term_id.to_le_bytes());
        buf[base + 64..base + 66].copy_from_slice(&event.owner_rg_id.to_le_bytes());
        write_ip_opt_16(&mut buf, base + 72, event.nat_src_ip);
        write_ip_opt_16(&mut buf, base + 88, event.nat_dst_ip);
        buf[base + 104..base + 106].copy_from_slice(&event.nat_src_port.to_be_bytes());
        buf[base + 106..base + 108].copy_from_slice(&event.nat_dst_port.to_be_bytes());
        buf[base + 128..base + 132].copy_from_slice(&event.ingress_ifindex.to_le_bytes());
        buf[base + 132..base + 134].copy_from_slice(&event.application_id.to_le_bytes());
        buf[base + 134] = event.reason;

        write_header(
            &mut buf,
            SECURITY_EVENT_PAYLOAD_SIZE as u32,
            event.kind.msg_type(),
            seq,
        );

        EventFrame {
            data: buf,
            len: (FRAME_HEADER_SIZE + SECURITY_EVENT_PAYLOAD_SIZE) as u16,
            seq,
        }
    }

    /// The raw bytes of this frame (header + payload).
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.data[..self.len as usize]
    }

    #[allow(dead_code)]
    pub(crate) fn dataplane_event_payload(&self) -> Option<&[u8]> {
        DataplaneEventKind::from_msg_type(self.data[4])?;
        let payload_len = u32::from_le_bytes(self.data[0..4].try_into().ok()?) as usize;
        if payload_len != SECURITY_EVENT_PAYLOAD_SIZE {
            return None;
        }
        let end = FRAME_HEADER_SIZE + payload_len;
        if (self.len as usize) < end {
            return None;
        }
        Some(&self.data[FRAME_HEADER_SIZE..end])
    }

    #[allow(dead_code)]
    pub(crate) fn decode_dataplane_event(&self) -> Option<DataplaneEventPayload> {
        decode_dataplane_event(self.data[4], self.dataplane_event_payload()?)
    }
}

// ---------------------------------------------------------------------------
// Header / address helpers
// ---------------------------------------------------------------------------

fn write_header(buf: &mut [u8; 256], payload_len: u32, msg_type: u8, seq: u64) {
    buf[0..4].copy_from_slice(&payload_len.to_le_bytes());
    buf[4] = msg_type;
    // buf[5..8] reserved (already zeroed)
    buf[8..16].copy_from_slice(&seq.to_le_bytes());
}

fn write_ip(buf: &mut [u8; 256], pos: usize, ip: IpAddr, is_v6: bool) -> usize {
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

fn write_ip_opt(buf: &mut [u8; 256], pos: usize, ip: Option<IpAddr>, is_v6: bool) -> usize {
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
fn write_ip_16(buf: &mut [u8; 256], pos: usize, ip: IpAddr) -> usize {
    match ip {
        IpAddr::V4(v4) => buf[pos..pos + 4].copy_from_slice(&v4.octets()),
        IpAddr::V6(v6) => buf[pos..pos + 16].copy_from_slice(&v6.octets()),
    }
    pos + 16
}

#[allow(dead_code)]
fn write_ip_opt_16(buf: &mut [u8; 256], pos: usize, ip: Option<IpAddr>) -> usize {
    if let Some(addr) = ip {
        write_ip_16(buf, pos, addr)
    } else {
        pos + 16
    }
}

#[allow(dead_code)]
pub(crate) fn decode_dataplane_event(
    msg_type: u8,
    payload: &[u8],
) -> Option<DataplaneEventPayload> {
    let frame_kind = DataplaneEventKind::from_msg_type(msg_type)?;
    if payload.len() != SECURITY_EVENT_PAYLOAD_SIZE {
        return None;
    }

    let event_kind = DataplaneEventKind::from_rt_flow_event_type(payload[52])?;
    if event_kind != frame_kind {
        return None;
    }
    let wire_af = payload[55];
    if wire_af != RT_FLOW_AF_INET && wire_af != RT_FLOW_AF_INET6 {
        return None;
    }
    let policy_or_reason_id = u32::from_le_bytes(payload[44..48].try_into().ok()?);

    Some(DataplaneEventPayload {
        kind: event_kind,
        addr_family: if wire_af == RT_FLOW_AF_INET6 {
            libc::AF_INET6 as u8
        } else {
            libc::AF_INET as u8
        },
        protocol: payload[53],
        action: payload[54],
        src_port: u16::from_be_bytes(payload[40..42].try_into().ok()?),
        dst_port: u16::from_be_bytes(payload[42..44].try_into().ok()?),
        nat_src_port: u16::from_be_bytes(payload[104..106].try_into().ok()?),
        nat_dst_port: u16::from_be_bytes(payload[106..108].try_into().ok()?),
        ingress_zone_id: u16::from_le_bytes(payload[48..50].try_into().ok()?),
        egress_zone_id: u16::from_le_bytes(payload[50..52].try_into().ok()?),
        ingress_ifindex: i32::from_le_bytes(payload[128..132].try_into().ok()?),
        rule_id: u32::from_le_bytes(payload[56..60].try_into().ok()?),
        term_id: u32::from_le_bytes(payload[60..64].try_into().ok()?),
        owner_rg_id: i16::from_le_bytes(payload[64..66].try_into().ok()?),
        policy_id: if event_kind == DataplaneEventKind::PolicyDeny {
            policy_or_reason_id
        } else {
            0
        },
        reason: payload[134],
        application_id: u16::from_le_bytes(payload[132..134].try_into().ok()?),
        filter_id: if event_kind == DataplaneEventKind::FilterLog {
            policy_or_reason_id
        } else {
            0
        },
        screen_id: if event_kind == DataplaneEventKind::ScreenDrop {
            policy_or_reason_id
        } else {
            0
        },
        timestamp_ns: u64::from_le_bytes(payload[0..8].try_into().ok()?),
        src_ip: read_ip_16(&payload[8..24], wire_af)?,
        dst_ip: read_ip_16(&payload[24..40], wire_af)?,
        nat_src_ip: read_nonzero_ip_16(&payload[72..88], wire_af),
        nat_dst_ip: read_nonzero_ip_16(&payload[88..104], wire_af),
    })
}

#[allow(dead_code)]
fn read_ip_16(bytes: &[u8], wire_af: u8) -> Option<IpAddr> {
    match wire_af {
        RT_FLOW_AF_INET => Some(IpAddr::from(<[u8; 4]>::try_from(&bytes[..4]).ok()?)),
        RT_FLOW_AF_INET6 => Some(IpAddr::from(<[u8; 16]>::try_from(&bytes[..16]).ok()?)),
        _ => None,
    }
}

#[allow(dead_code)]
fn read_nonzero_ip_16(bytes: &[u8], wire_af: u8) -> Option<IpAddr> {
    if bytes.iter().all(|b| *b == 0) {
        return None;
    }
    read_ip_16(bytes, wire_af)
}

#[allow(dead_code)]
fn rt_flow_addr_family(addr_family: u8, src_ip: IpAddr) -> u8 {
    if addr_family == libc::AF_INET6 as u8 || matches!(src_ip, IpAddr::V6(_)) {
        RT_FLOW_AF_INET6
    } else {
        RT_FLOW_AF_INET
    }
}

fn encode_disposition(d: ForwardingDisposition) -> u8 {
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

/// Compute the close flags byte from a SessionDelta.
pub(crate) fn close_flags(delta: &SessionDelta) -> u8 {
    let mut flags: u8 = 0;
    if delta.fabric_redirect_sync
        || delta.decision.resolution.disposition == ForwardingDisposition::FabricRedirect
    {
        flags |= FLAG_FABRIC_REDIRECT;
    }
    if delta.metadata.fabric_ingress {
        flags |= FLAG_FABRIC_INGRESS;
    }
    flags
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[path = "codec_tests.rs"]
mod tests;
