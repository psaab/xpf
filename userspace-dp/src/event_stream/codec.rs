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
pub(crate) const SECURITY_EVENT_PAYLOAD_SIZE: usize = 120;

#[allow(dead_code)]
const SECURITY_EVENT_FLAG_NAT_SRC: u8 = 1 << 0;
#[allow(dead_code)]
const SECURITY_EVENT_FLAG_NAT_DST: u8 = 1 << 1;

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
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DataplaneEventPayload {
    pub(crate) kind: DataplaneEventKind,
    pub(crate) addr_family: u8,
    pub(crate) protocol: u8,
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
    pub(crate) owner_rg_id: i16,
    pub(crate) reason: u16,
    pub(crate) policy_id: u32,
    pub(crate) rule_id: u32,
    pub(crate) application_id: u32,
    pub(crate) filter_id: u32,
    pub(crate) term_id: u32,
    pub(crate) screen_id: u32,
    pub(crate) timestamp_ns: u64,
}

#[allow(dead_code)]
impl DataplaneEventPayload {
    pub(crate) fn from_session_key(kind: DataplaneEventKind, key: &SessionKey) -> Self {
        Self {
            kind,
            addr_family: key.addr_family,
            protocol: key.protocol,
            src_ip: key.src_ip,
            dst_ip: key.dst_ip,
            src_port: key.src_port,
            dst_port: key.dst_port,
            nat_src_ip: None,
            nat_dst_ip: None,
            nat_src_port: 0,
            nat_dst_port: 0,
            ingress_zone_id: 0,
            egress_zone_id: 0,
            ingress_ifindex: 0,
            owner_rg_id: 0,
            reason: 0,
            policy_id: 0,
            rule_id: 0,
            application_id: 0,
            filter_id: 0,
            term_id: 0,
            screen_id: 0,
            timestamp_ns: 0,
        }
    }
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

    /// Encode a fixed-size security telemetry event.
    ///
    /// Payload layout (120 bytes):
    /// [0] AF wire value, [1] protocol, [2] flags, [3] reserved,
    /// [4..56] scalar tuple/identity/reason fields, then four 16-byte IP slots:
    /// original src/dst and optional NAT src/dst.
    #[allow(dead_code)]
    pub(crate) fn encode_dataplane_event(seq: u64, event: &DataplaneEventPayload) -> Self {
        let mut buf = [0u8; 256];
        let mut pos = FRAME_HEADER_SIZE;

        let wire_af = wire_addr_family(event.addr_family, event.src_ip);
        let mut flags = 0u8;
        if event.nat_src_ip.is_some() {
            flags |= SECURITY_EVENT_FLAG_NAT_SRC;
        }
        if event.nat_dst_ip.is_some() {
            flags |= SECURITY_EVENT_FLAG_NAT_DST;
        }

        buf[pos] = wire_af;
        pos += 1;
        buf[pos] = event.protocol;
        pos += 1;
        buf[pos] = flags;
        pos += 1;
        pos += 1; // reserved
        buf[pos..pos + 2].copy_from_slice(&event.src_port.to_le_bytes());
        pos += 2;
        buf[pos..pos + 2].copy_from_slice(&event.dst_port.to_le_bytes());
        pos += 2;
        buf[pos..pos + 2].copy_from_slice(&event.nat_src_port.to_le_bytes());
        pos += 2;
        buf[pos..pos + 2].copy_from_slice(&event.nat_dst_port.to_le_bytes());
        pos += 2;
        buf[pos..pos + 2].copy_from_slice(&event.ingress_zone_id.to_le_bytes());
        pos += 2;
        buf[pos..pos + 2].copy_from_slice(&event.egress_zone_id.to_le_bytes());
        pos += 2;
        buf[pos..pos + 4].copy_from_slice(&event.ingress_ifindex.to_le_bytes());
        pos += 4;
        buf[pos..pos + 2].copy_from_slice(&event.owner_rg_id.to_le_bytes());
        pos += 2;
        buf[pos..pos + 2].copy_from_slice(&event.reason.to_le_bytes());
        pos += 2;
        buf[pos..pos + 4].copy_from_slice(&event.policy_id.to_le_bytes());
        pos += 4;
        buf[pos..pos + 4].copy_from_slice(&event.rule_id.to_le_bytes());
        pos += 4;
        buf[pos..pos + 4].copy_from_slice(&event.application_id.to_le_bytes());
        pos += 4;
        buf[pos..pos + 4].copy_from_slice(&event.filter_id.to_le_bytes());
        pos += 4;
        buf[pos..pos + 4].copy_from_slice(&event.term_id.to_le_bytes());
        pos += 4;
        buf[pos..pos + 4].copy_from_slice(&event.screen_id.to_le_bytes());
        pos += 4;
        buf[pos..pos + 8].copy_from_slice(&event.timestamp_ns.to_le_bytes());
        pos += 8;

        pos = write_ip_16(&mut buf, pos, event.src_ip);
        pos = write_ip_16(&mut buf, pos, event.dst_ip);
        pos = write_ip_opt_16(&mut buf, pos, event.nat_src_ip);
        pos = write_ip_opt_16(&mut buf, pos, event.nat_dst_ip);

        debug_assert_eq!(pos - FRAME_HEADER_SIZE, SECURITY_EVENT_PAYLOAD_SIZE);
        write_header(
            &mut buf,
            SECURITY_EVENT_PAYLOAD_SIZE as u32,
            event.kind.msg_type(),
            seq,
        );

        EventFrame {
            data: buf,
            len: pos as u16,
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
    let kind = DataplaneEventKind::from_msg_type(msg_type)?;
    if payload.len() != SECURITY_EVENT_PAYLOAD_SIZE {
        return None;
    }

    let wire_af = payload[0];
    if wire_af != 4 && wire_af != 6 {
        return None;
    }
    let flags = payload[2];

    Some(DataplaneEventPayload {
        kind,
        addr_family: if wire_af == 6 {
            libc::AF_INET6 as u8
        } else {
            libc::AF_INET as u8
        },
        protocol: payload[1],
        src_port: u16::from_le_bytes(payload[4..6].try_into().ok()?),
        dst_port: u16::from_le_bytes(payload[6..8].try_into().ok()?),
        nat_src_port: u16::from_le_bytes(payload[8..10].try_into().ok()?),
        nat_dst_port: u16::from_le_bytes(payload[10..12].try_into().ok()?),
        ingress_zone_id: u16::from_le_bytes(payload[12..14].try_into().ok()?),
        egress_zone_id: u16::from_le_bytes(payload[14..16].try_into().ok()?),
        ingress_ifindex: i32::from_le_bytes(payload[16..20].try_into().ok()?),
        owner_rg_id: i16::from_le_bytes(payload[20..22].try_into().ok()?),
        reason: u16::from_le_bytes(payload[22..24].try_into().ok()?),
        policy_id: u32::from_le_bytes(payload[24..28].try_into().ok()?),
        rule_id: u32::from_le_bytes(payload[28..32].try_into().ok()?),
        application_id: u32::from_le_bytes(payload[32..36].try_into().ok()?),
        filter_id: u32::from_le_bytes(payload[36..40].try_into().ok()?),
        term_id: u32::from_le_bytes(payload[40..44].try_into().ok()?),
        screen_id: u32::from_le_bytes(payload[44..48].try_into().ok()?),
        timestamp_ns: u64::from_le_bytes(payload[48..56].try_into().ok()?),
        src_ip: read_ip_16(&payload[56..72], wire_af)?,
        dst_ip: read_ip_16(&payload[72..88], wire_af)?,
        nat_src_ip: if flags & SECURITY_EVENT_FLAG_NAT_SRC != 0 {
            read_ip_16(&payload[88..104], wire_af)
        } else {
            None
        },
        nat_dst_ip: if flags & SECURITY_EVENT_FLAG_NAT_DST != 0 {
            read_ip_16(&payload[104..120], wire_af)
        } else {
            None
        },
    })
}

#[allow(dead_code)]
fn read_ip_16(bytes: &[u8], wire_af: u8) -> Option<IpAddr> {
    match wire_af {
        4 => Some(IpAddr::from(<[u8; 4]>::try_from(&bytes[..4]).ok()?)),
        6 => Some(IpAddr::from(<[u8; 16]>::try_from(&bytes[..16]).ok()?)),
        _ => None,
    }
}

#[allow(dead_code)]
fn wire_addr_family(addr_family: u8, src_ip: IpAddr) -> u8 {
    if addr_family == libc::AF_INET6 as u8 || matches!(src_ip, IpAddr::V6(_)) {
        6
    } else {
        4
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
