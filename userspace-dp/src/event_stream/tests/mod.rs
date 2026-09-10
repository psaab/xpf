// Tests for event_stream/mod.rs. Split from a single 2313-line tests.rs
// into per-concern sibling submodules (#4664) to keep each file under the
// modularity-discipline LOC threshold. Pure test-code motion: no production
// code and no test logic changed. The shared imports and the cross-concern
// fixtures (`build_raw_ack_frame`, `test_dataplane_event`, `test_close_delta`)
// live here and reach every submodule via `use super::*`.
//
// Submodules by concern (see each file's tests):
//   rt_flow  replay_budget  backpressure  control_frames  drain

use super::codec::{
    DataplaneEventKind, DataplaneEventPayload, MSG_DRAIN_COMPLETE, MSG_FULL_RESYNC,
    MSG_SESSION_CREATE_RT_FLOW,
};
use super::*;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr};


fn build_raw_ack_frame(seq: u64) -> [u8; FRAME_HEADER_SIZE] {
    let mut buf = [0u8; FRAME_HEADER_SIZE];
    // payload_len = 0 (header-only)
    buf[0..4].copy_from_slice(&0u32.to_le_bytes());
    buf[4] = MSG_ACK;
    // reserved bytes 5..8 stay zero
    buf[8..16].copy_from_slice(&seq.to_le_bytes());
    buf
}


fn test_dataplane_event(kind: DataplaneEventKind, ingress_zone_id: u16) -> DataplaneEventPayload {
    DataplaneEventPayload {
        kind,
        addr_family: libc::AF_INET as u8,
        protocol: 6,
        action: 0,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        src_port: 12345,
        dst_port: 443,
        nat_src_ip: None,
        nat_dst_ip: None,
        nat_src_port: 0,
        nat_dst_port: 0,
        ingress_zone_id,
        egress_zone_id: 9,
        ingress_ifindex: 42,
        policy_id: 101,
        rule_id: 202,
        term_id: 303,
        reason: 5,
        owner_rg_id: 1,
        application_id: 404,
        filter_id: 505,
        screen_id: 606,
        timestamp_ns: 123_456_789,
    }
}


// #2460: build a forward Close SessionDelta for the RT_FLOW close-emit
// pairing tests.
#[cfg(test)]
fn test_close_delta(kind: crate::session::SessionDeltaKind) -> crate::session::SessionDelta {
    use crate::afxdp::{ForwardingDisposition, ForwardingResolution};
    use crate::nat::NatDecision;
    use crate::session::{
        SessionCounters, SessionDecision, SessionDelta, SessionKey, SessionMetadata,
        SessionOrigin,
    };
    SessionDelta {
        kind,
        key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: 6,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 1, 102)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 12345,
            dst_port: 443,
                    discriminator: Default::default(),
                    routing_domain: 0,
        },
        decision: SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 2,
                egress_ifindex: 3,
                tx_ifindex: 3,
                tunnel_endpoint_id: 0,
                next_hop: None,
                neighbor_mac: None,
                src_mac: None,
                tx_vlan_id: 0,
            },
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                rewrite_dst: None,
                rewrite_src_port: Some(40000),
                rewrite_dst_port: None,
                nat64: false,
                nptv6: false,
            },
        },
        metadata: SessionMetadata {
            ingress_zone: 1,
            egress_zone: 2,
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            owner_rg_id: 0,
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
            log_session_init: false,
            log_session_close: false,
            policy_id: 0,
            inactivity_timeout_ns: None,
            policy_counter_idx: 0,
            policy_counter: None,
        },
        origin: SessionOrigin::ForwardFlow,
        fabric_redirect_sync: false,
        created_ns: 0,
        last_seen_ns: 0,
        counters: SessionCounters::default(),
        // #2749: ToS byte 0xB8 (DSCP EF=46 << 2) and TCP flags SYN|FIN|ACK so
        // the close-emit / round-trip tests can assert real wire values.
        observed_tos: 0xB8,
        observed_tcp_flags: 0x13,
        session_id: 0,
        bulk_resync: false,
        tcp_close_class: 0,
    }
}

mod rt_flow;
mod replay_budget;
mod backpressure;
mod control_frames;
mod drain;
mod write_backlog;
// #9169: the producer-seq lock instrumentation (#4800 site 4).
mod producer_seq_lock_9169;
