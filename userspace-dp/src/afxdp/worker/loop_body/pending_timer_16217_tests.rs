//! #16217 (FZDiag28, part b): timer-driven pending-neighbor retry tests.
//!
//! The production timer arm (`run_pending_neigh_timer` in ct_slice.rs)
//! drives the SAME `retry_pending_neigh` sweep `poll_binding` drives,
//! but packet-independently at the 100 ms ct-slice cadence. These cells
//! drive that production timer function (not `retry_pending_neigh`
//! directly, and not the cadence predicate alone): deleting the timer
//! call, the cadence gate, or the per-binding sweep turns them RED.

use super::ct_slice::{run_pending_neigh_timer, PendingNeighTimer};
use super::*;
use crate::afxdp::tx::test_support::build_ipv4_test_packet;
use std::sync::atomic::Ordering;

const EGRESS_IFINDEX: i32 = 80;
const TARGET_IFINDEX: i32 = 22;
const NEXT_HOP: std::net::Ipv4Addr = std::net::Ipv4Addr::new(10, 0, 0, 2);
const QUEUED_NS: u64 = 1_000_000_000;
const MAC: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

fn pending_meta(frame_len: usize) -> UserspaceDpMeta {
    let mut meta = UserspaceDpMeta {
        ingress_ifindex: 11,
        l3_offset: 14,
        l4_offset: 34,
        pkt_len: frame_len as u16,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        ..UserspaceDpMeta::default()
    };
    meta.flow_src_addr[..4].copy_from_slice(&[10, 0, 0, 1]);
    meta.flow_dst_addr[..4].copy_from_slice(&[10, 0, 0, 2]);
    meta
}

fn parked_packet(frame_len: usize) -> PendingNeighPacket {
    PendingNeighPacket {
        addr: 0,
        desc: XdpDesc {
            addr: 0,
            len: frame_len as u32,
            options: 0,
        },
        meta: pending_meta(frame_len),
        fabric_ingress_zone: None,
        decision: SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::MissingNeighbor,
                local_ifindex: 0,
                egress_ifindex: EGRESS_IFINDEX,
                tx_ifindex: TARGET_IFINDEX,
                tunnel_endpoint_id: 0,
                next_hop: Some(std::net::IpAddr::V4(NEXT_HOP)),
                neighbor_mac: None,
                src_mac: Some([0x02, 0xbf, 0x72, 0x16, 0x00, 0x01]),
                tx_vlan_id: 0,
                source_ifindex: 0,
                route_mtu: 0,
                transport_route_mtu: 0,
            },
            nat: crate::nat::NatDecision::default(),
            install_table_domain: 0,
            install_table_check: 0,
        },
        flow_key: None,
        queued_ns: QUEUED_NS,
        probe_attempts: 0,
    }
}

fn timer_fixture() -> Vec<BindingWorker> {
    let mut bindings = vec![
        BindingWorker::new_for_mirror_test(0, 0, 11, 0),
        BindingWorker::new_for_mirror_test(1, 0, TARGET_IFINDEX, 0),
    ];
    // Same-UMEM forward target so the resolved dispatch lands on the
    // prepared queue (the cross-UMEM copy fallback is covered elsewhere).
    bindings[1].umem = bindings[0].umem.clone();
    let frame = build_ipv4_test_packet(0);
    // SAFETY: single-threaded test; the test UMEM was just created and
    // no other borrow into [0, len) exists.
    unsafe {
        bindings[0]
            .umem
            .area()
            .slice_mut_unchecked(0, frame.len())
    }
    .expect("ingress frame")
    .copy_from_slice(&frame);
    let pkt = parked_packet(frame.len());
    let key = (EGRESS_IFINDEX, std::net::IpAddr::V4(NEXT_HOP));
    let due = crate::afxdp::neigh_schedule::next_due_for_pending(
        QUEUED_NS,
        QUEUED_NS,
        0,
        crate::afxdp::PENDING_NEIGH_TIMEOUT_NS,
        crate::afxdp::neighbor_dispatch::PROBE_SCHEDULE_NS,
    );
    bindings[0].pending_neigh.insert(key, pkt);
    bindings[0].pending_neigh_schedule.arm(key, due);
    bindings
}

fn run_timer(
    timer: &mut PendingNeighTimer,
    bindings: &mut [BindingWorker],
    forwarding: &ForwardingState,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    now_ns: u64,
) -> bool {
    let lookup = WorkerBindingLookup::from_bindings(bindings);
    let mirror_targets = MirrorTargetMap::default();
    let recent_exceptions = Arc::new(Mutex::new(ExceptionEventRing::new()));
    run_pending_neigh_timer(
        timer,
        bindings,
        &lookup,
        &mirror_targets,
        forwarding,
        dynamic_neighbors,
        None,
        now_ns,
        None,
        &recent_exceptions,
    )
}

/// Part (b) arm 1: a parked representative whose hop lands ONLY in the
/// node neighbor map must dispatch from the TIMER with zero RX, but
/// only once the 100 ms cadence fires.
///
/// FAIL-ON-REVERT: drop the timer sweep (or its loop callsite) and the
/// parked entry survives the +100 ms pass; drop the cadence gate and
/// the +99 ms pass dispatches early.
#[test]
fn timer_retry_dispatches_parked_frame_on_cadence_16217() {
    let mut bindings = timer_fixture();
    let forwarding = ForwardingState::default();
    // The hop exists ONLY in the node (dynamic) neighbor map: no
    // static `forwarding.neighbors` entry, exactly the warm-pass shape.
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    dynamic_neighbors.insert(
        (EGRESS_IFINDEX, std::net::IpAddr::V4(NEXT_HOP)),
        NeighborEntry { mac: MAC },
    );
    let mut timer = PendingNeighTimer::new();
    timer.prime_for_test(QUEUED_NS);

    // +99 ms: cadence not yet due — the timer must not fire and the
    // parked frame must stay parked despite the resolved neighbor.
    let fired = run_timer(
        &mut timer,
        &mut bindings,
        &forwarding,
        &dynamic_neighbors,
        QUEUED_NS + 99_000_000,
    );
    assert!(!fired, "timer must not fire before the 100 ms cadence");
    assert_eq!(
        bindings[0].pending_neigh.len(),
        1,
        "parked frame must survive a sub-cadence timer pass"
    );
    assert_eq!(
        bindings[0]
            .live
            .pending_neigh_visits
            .load(Ordering::Relaxed),
        0,
        "a gated-off timer pass must not visit any pending key"
    );

    // +100 ms: cadence fires with zero RX — the parked representative
    // is visited once and consumed (dispatched to the egress binding).
    let fired = run_timer(
        &mut timer,
        &mut bindings,
        &forwarding,
        &dynamic_neighbors,
        QUEUED_NS + 100_000_000,
    );
    assert!(fired, "timer must fire at the 100 ms cadence");
    assert_eq!(
        bindings[0]
            .live
            .pending_neigh_visits
            .load(Ordering::Relaxed),
        1,
        "the timer pass must visit the parked key exactly once"
    );
    assert!(
        bindings[0].pending_neigh.is_empty(),
        "resolved parked frame must be consumed by the timer dispatch"
    );
    assert!(
        !bindings[1].tx_pipeline.pending_tx_prepared.is_empty()
            || !bindings[1].tx_pipeline.pending_tx_local.is_empty(),
        "the timer dispatch must enqueue the frame on the egress binding"
    );
}

/// Part (b) arm 2 (fail-closed control): with the hop absent from the
/// node map, the timer pass at cadence must NOT dispatch — the frame
/// stays parked for its probe schedule / retransmit recovery.
///
/// FAIL-ON-REVERT: a timer that dispatches (or recycles) unresolved
/// parked frames turns this RED.
#[test]
fn timer_retry_keeps_unresolved_frame_parked_16217() {
    let mut bindings = timer_fixture();
    let forwarding = ForwardingState::default();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let mut timer = PendingNeighTimer::new();
    timer.prime_for_test(QUEUED_NS);

    let fired = run_timer(
        &mut timer,
        &mut bindings,
        &forwarding,
        &dynamic_neighbors,
        QUEUED_NS + 100_000_000,
    );
    assert!(fired, "timer must fire at the 100 ms cadence");
    assert_eq!(
        bindings[0].pending_neigh.len(),
        1,
        "unresolved parked frame must stay parked (fail-closed)"
    );
    assert!(
        bindings[1].tx_pipeline.pending_tx_prepared.is_empty()
            && bindings[1].tx_pipeline.pending_tx_local.is_empty(),
        "no frame may be enqueued while the neighbor is unresolved"
    );
}
