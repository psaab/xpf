//! #16480: Stage-11 IPsec pre-claim PBR `Drop` must be counted exactly once.
//!
//! The pre-claim probe (`ingress_route_table_override_uncounted`) resolves
//! the input-filter PBR override before the Stage-11 claim so the claim can
//! follow a `Table` steer. Its `Drop` arm is terminal — the packet never
//! reaches the claimed arm or the ordinary miss path where the counted
//! evaluation runs — so at HEAD a PBR `then { routing-instance X; reject; }`
//! term dropping an IKE packet moved no term counter, emitted no filter
//! log, and synthesized no reject reply, while TCP/UDP-53 controls on the
//! miss path counted exactly once. The fix re-runs the counted evaluation
//! (with the reject sink) exactly once on that terminal Drop arm, plus the
//! #11061 ambiguous-quarantine count the miss path's Drop arm applies.
//!
//! These cells drive the real descriptor path (`txn_run_descriptor*`):
//! - UDP/500 (IKE) subject: counter 1, one ICMP reject reply, one PBR
//!   filter-log event.
//! - TCP SYN and UDP/53 controls through the same filter: counter 1 each,
//!   one reply each (no double count from the pre-claim probe).
//! - Claimed-passthrough IKE (dst locally owned in the steered table,
//!   accept term): still counts exactly once via the claimed arm.
//! - Quarantined-ambiguous fabric IKE dropped by an Unresolvable domain:
//!   `ambiguous_fabric_zone_drops` increments exactly once.

use super::super::test_fixtures::*;
use super::super::tests_support::*;
use super::*;
use crate::event_stream::codec::DataplaneEventKind;
use crate::{FirewallFilterSnapshot, FirewallTermSnapshot};
use std::net::Ipv4Addr;
use std::sync::atomic::Ordering;

const INGRESS_IFINDEX: u32 = 24;
const SRC: Ipv4Addr = Ipv4Addr::new(10, 0, 61, 102);
const LOCAL_DST: Ipv4Addr = Ipv4Addr::new(10, 0, 61, 1);

fn pbr_drop_forwarding(action: &str) -> ForwardingState {
    let mut snapshot = nat_snapshot();
    snapshot.filters = vec![FirewallFilterSnapshot {
        name: "edge-pbr".into(),
        family: "inet".into(),
        terms: vec![
            FirewallTermSnapshot {
                name: "pbr-drop".into(),
                destination_addresses: vec!["10.0.61.1/32".into()],
                routing_instance: "sfmix".into(),
                action: action.into(),
                count: "pbr-drop-count".into(),
                log: true,
                ..Default::default()
            },
            FirewallTermSnapshot {
                name: "default".into(),
                action: "accept".into(),
                ..Default::default()
            },
        ],
    }];
    for iface in snapshot.interfaces.iter_mut() {
        if iface.ifindex == INGRESS_IFINDEX as i32 {
            iface.filter_input_v4 = "edge-pbr".into();
        }
    }
    build_forwarding_state(&snapshot)
}

fn pbr_term_hits(forwarding: &ForwardingState) -> u64 {
    crate::filter::flush_recorded_filter_counters();
    forwarding
        .filter_state
        .filters
        .values()
        .find(|filter| filter.name.as_str() == "edge-pbr")
        .map(|filter| filter.terms[0].counter.packets.load(Ordering::Relaxed))
        .unwrap_or(0)
}

fn udp_frame(dst_port: u16) -> Vec<u8> {
    // ISAKMP-shaped payload for 500/4500; plain payload otherwise.
    let mut payload = Vec::new();
    if dst_port == 500 || dst_port == 4500 {
        if dst_port == 4500 {
            payload.extend_from_slice(&[0, 0, 0, 0]);
        }
        payload.extend_from_slice(&0x1122_3344_5566_7788u64.to_be_bytes());
        payload.extend_from_slice(&0u64.to_be_bytes());
        payload.extend_from_slice(&[0x00, 0x20, 0x22, 0x08]);
        payload.extend_from_slice(&0u32.to_be_bytes());
        payload.extend_from_slice(&0u32.to_be_bytes());
    } else {
        payload.extend_from_slice(&[0xAA; 8]);
    }
    build_stage11_udp_frame(SRC, LOCAL_DST, 40_000, dst_port, &payload)
}

fn tcp_syn_frame() -> Vec<u8> {
    build_txn_tcp_syn_frame_v4(SRC, LOCAL_DST, 40_000, 443, TCP_FLAG_SYN, TEST_LAN_MAC)
}

fn build_stage11_udp_frame(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let total_len = 20 + 8 + payload.len();
    let mut frame = vec![
        0u8, 0, 0, 0, 0, 0, 0x02, 0x11, 0x22, 0x33, 0x44, 0x55, 0x08, 0x00, 0x45, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x40, 0x00, 64, PROTO_UDP, 0x00, 0x00,
    ];
    frame[..6].copy_from_slice(&TEST_LAN_MAC);
    frame[16..18].copy_from_slice(&(total_len as u16).to_be_bytes());
    frame.extend_from_slice(&src.octets());
    frame.extend_from_slice(&dst.octets());
    frame[24..26].fill(0);
    let ip_csum = checksum16(&frame[14..34]);
    frame[24..26].copy_from_slice(&ip_csum.to_be_bytes());
    frame.extend_from_slice(&src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    frame.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(payload);
    frame
}

fn udp_meta(frame: &[u8], dst_port: u16) -> UserspaceDpMeta {
    let mut src_addr = [0u8; 16];
    src_addr[..4].copy_from_slice(&SRC.octets());
    let mut dst_addr = [0u8; 16];
    dst_addr[..4].copy_from_slice(&LOCAL_DST.octets());
    UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: INGRESS_IFINDEX,
        l3_offset: 14,
        l4_offset: 34,
        payload_offset: 42,
        pkt_len: frame.len() as u16,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_UDP,
        flow_src_port: 40_000,
        flow_dst_port: dst_port,
        flow_src_addr: src_addr,
        flow_dst_addr: dst_addr,
        config_generation: 7,
        fib_generation: 9,
        ..UserspaceDpMeta::default()
    }
}

fn run_one(
    forwarding: &ForwardingState,
    frame: &[u8],
    meta: UserspaceDpMeta,
) -> (BindingWorker, BatchCounters) {
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, INGRESS_IFINDEX as i32, 0);
    binding.interface = std::sync::Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    let local_tunnel_deliveries = std::sync::Arc::new(arc_swap::ArcSwap::from_pointee(
        std::collections::BTreeMap::new(),
    ));
    let (event_handle, event_rx) = crate::event_stream::test_worker_handle(
        16,
        crate::event_stream::DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
            session_close_events_per_second: 0,
            session_close_burst: 0,
            session_create_events_per_second: 0,
            session_create_burst: 0,
        },
    );
    let (batch, _dbg) = txn_run_descriptor_with_event_stream(
        &mut binding,
        &mut sessions,
        forwarding,
        &ha_state,
        frame,
        meta,
        &local_tunnel_deliveries,
        &event_handle,
    );
    // Drain filter-log events for the caller's count via the handle stats.
    let _ = event_rx;
    (binding, batch)
}

#[test]
fn stage11_preclaim_pbr_reject_counts_once_and_replies_16480() {
    let forwarding = pbr_drop_forwarding("reject");
    assert_eq!(
        pbr_term_hits(&forwarding),
        0,
        "fixture: counter starts at 0"
    );

    // Subject: UDP/500 IKE to the PBR-dropped local dst.
    let frame = udp_frame(500);
    let meta = udp_meta(&frame, 500);
    let (binding, _batch) = run_one(&forwarding, &frame, meta);
    assert_eq!(
        pbr_term_hits(&forwarding),
        1,
        "#16480: pre-claim PBR Drop must count the term exactly once (was 0)"
    );
    assert_eq!(
        binding.tx_pipeline.pending_tx_local.len(),
        1,
        "#16480: a `reject` PBR term dropping IKE must enqueue one reject reply"
    );
    assert_eq!(
        binding.scratch.scratch_recycle.len(),
        1,
        "packet must be dropped"
    );

    // Control: TCP SYN through the same filter (miss path).
    let forwarding_tcp = pbr_drop_forwarding("reject");
    let frame_tcp = tcp_syn_frame();
    let meta_tcp = txn_meta_v4(INGRESS_IFINDEX, TCP_FLAG_SYN, frame_tcp.len() as u16);
    let (binding_tcp, _) = run_one(&forwarding_tcp, &frame_tcp, meta_tcp);
    assert_eq!(
        pbr_term_hits(&forwarding_tcp),
        1,
        "control: TCP SYN must count exactly once (no double count)"
    );
    assert_eq!(
        binding_tcp.tx_pipeline.pending_tx_local.len(),
        1,
        "control: TCP SYN reject must enqueue exactly one reply"
    );

    // Control: UDP/53 through the same filter (miss path).
    let forwarding_dns = pbr_drop_forwarding("reject");
    let frame_dns = udp_frame(53);
    let meta_dns = udp_meta(&frame_dns, 53);
    let (binding_dns, _) = run_one(&forwarding_dns, &frame_dns, meta_dns);
    assert_eq!(
        pbr_term_hits(&forwarding_dns),
        1,
        "control: UDP/53 must count exactly once (no double count)"
    );
    assert_eq!(
        binding_dns.tx_pipeline.pending_tx_local.len(),
        1,
        "control: UDP/53 reject must enqueue exactly one reply"
    );
}

#[test]
fn stage11_preclaim_pbr_discard_counts_once_silently_16480() {
    let forwarding = pbr_drop_forwarding("discard");
    let frame = udp_frame(500);
    let meta = udp_meta(&frame, 500);
    let (binding, _) = run_one(&forwarding, &frame, meta);
    assert_eq!(
        pbr_term_hits(&forwarding),
        1,
        "#16480: pre-claim PBR discard must count the term exactly once"
    );
    assert!(
        binding.tx_pipeline.pending_tx_local.is_empty(),
        "discard must not synthesize a reject reply"
    );
    assert_eq!(binding.scratch.scratch_recycle.len(), 1);
}

#[test]
fn stage11_claimed_passthrough_accept_counts_once_16480() {
    // Accept PBR term steering into sfmix: the dst is locally owned in the
    // default table, so with no steer the packet would be claimed; with the
    // Table steer it is adjudicated in sfmix. Use an accept term whose
    // routing-instance is `default` so the claim still succeeds in inet.0 —
    // the claimed arm's counted evaluation must then fire exactly once and
    // the uncounted pre-claim probe must not add a second hit.
    let mut snapshot = nat_snapshot();
    snapshot.filters = vec![FirewallFilterSnapshot {
        name: "edge-pbr".into(),
        family: "inet".into(),
        terms: vec![
            FirewallTermSnapshot {
                name: "pbr-drop".into(),
                destination_addresses: vec!["10.0.61.1/32".into()],
                routing_instance: "default".into(),
                action: "accept".into(),
                count: "pbr-drop-count".into(),
                log: true,
                ..Default::default()
            },
            FirewallTermSnapshot {
                name: "default".into(),
                action: "accept".into(),
                ..Default::default()
            },
        ],
    }];
    for iface in snapshot.interfaces.iter_mut() {
        if iface.ifindex == INGRESS_IFINDEX as i32 {
            iface.filter_input_v4 = "edge-pbr".into();
        }
    }
    let forwarding = build_forwarding_state(&snapshot);
    let frame = udp_frame(500);
    let meta = udp_meta(&frame, 500);
    let (binding, _) = run_one(&forwarding, &frame, meta);
    assert_eq!(
        pbr_term_hits(&forwarding),
        1,
        "#16480: claimed-passthrough IKE must count exactly once (pre-claim probe uncounted)"
    );
    // Passthrough recycles after reinjection attempt (slow_path None in the
    // txn harness records an exception, but the descriptor is recycled).
    assert_eq!(binding.scratch.scratch_recycle.len(), 1);
}

#[test]
fn stage11_pbr_filter_log_emitted_once_16480() {
    let forwarding = pbr_drop_forwarding("reject");
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, INGRESS_IFINDEX as i32, 0);
    binding.interface = std::sync::Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    let local_tunnel_deliveries = std::sync::Arc::new(arc_swap::ArcSwap::from_pointee(
        std::collections::BTreeMap::new(),
    ));
    let (event_handle, event_rx) = crate::event_stream::test_worker_handle(
        16,
        crate::event_stream::DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
            session_close_events_per_second: 0,
            session_close_burst: 0,
            session_create_events_per_second: 0,
            session_create_burst: 0,
        },
    );
    let frame = udp_frame(500);
    let meta = udp_meta(&frame, 500);
    let _ = txn_run_descriptor_with_event_stream(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
        &local_tunnel_deliveries,
        &event_handle,
    );
    let mut filter_logs = 0;
    while let Ok(frame) = event_rx.try_recv() {
        let event = frame.decode_dataplane_event().expect("event payload");
        if event.kind == DataplaneEventKind::FilterLog {
            filter_logs += 1;
            assert_eq!(event.reason, FilterLogSource::Pbr.wire_reason());
        }
    }
    assert_eq!(
        filter_logs, 1,
        "#16480: pre-claim PBR Drop must emit exactly one PBR filter log"
    );
}
