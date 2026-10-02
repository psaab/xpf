//! RT_FLOW payload decode (the Go-parity round-trip decoder used by tests and
//! the afxdp event-emit paths).
//!
//! Split out of the former single-file `codec.rs` (#4651).

use std::net::IpAddr;

use super::rt_flow::{DataplaneEventKind, DataplaneEventPayload, POLICY_CONFIG_GENERATION_MARKER};
use super::wire::*;

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
    let policy_generation_stamped = event_kind == DataplaneEventKind::PolicyDeny
        && u32::from_le_bytes(payload[140..144].try_into().ok()?) == POLICY_CONFIG_GENERATION_MARKER;
    let config_generation = if policy_generation_stamped {
        u64::from_le_bytes(payload[56..64].try_into().ok()?)
    } else {
        0
    };

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
        rule_id: if policy_generation_stamped {
            policy_or_reason_id
        } else {
            u32::from_le_bytes(payload[56..60].try_into().ok()?)
        },
        term_id: if policy_generation_stamped {
            0
        } else {
            u32::from_le_bytes(payload[60..64].try_into().ok()?)
        },
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
        config_generation,
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
