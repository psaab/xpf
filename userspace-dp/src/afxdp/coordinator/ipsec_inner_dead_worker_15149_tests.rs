//! #15149 (B12-01): the 1 Hz dead-worker sweep must retire the dead worker
//! from the D11 IPsec-inner transport.
//!
//! The sweep (`retire_dead_worker_holders`, driven from `refresh_status`)
//! reclaimed NAT holder bits, steering claims, and CoS V_min slots for a
//! panicked worker but never called
//! `IpsecInnerWorkerTransport::retire_worker`. The router therefore kept
//! hashing flows to the dead worker; its 128-deep queue accepted admits
//! nothing drains, then refused them as WORKER_QUEUE_FULL, and requests
//! already admitted completed only by Go ack timeout.
//!
//! FAIL-ON-REVERT: remove the `retire_worker` /
//! `join_worker_after_termination` pair (or the verdict delivery) from the
//! dead branch of `retire_selected_worker_holders` in `status.rs` and this
//! test fails: the survivor is never the sole route and the reaped requests
//! never reach the completion core as Denied.

use super::*;
use crate::afxdp::ipsec_inner_queue::{
    IpsecInnerDescriptor, IPSEC_INNER_STN_MAX,
};
use crate::slowpath_reinject_9506::{
    CaptureOrigin, ReinjectLease, SubmitFrame, PMECH_DEADLINE_CLOCK_MONOTONIC,
};
use std::sync::atomic::Ordering;

const PERMIT_15149: u64 = 7;
const QEPOCH_15149: u64 = 11;

fn frame_15149(id: u64, flow_tag: u64) -> SubmitFrame {
    SubmitFrame {
        lease: ReinjectLease {
            permit_epoch: PERMIT_15149,
            queue_epoch: QEPOCH_15149,
            queue_number: 1,
            request_id: id,
        },
        flow_tag,
        flags: 0,
        origin: CaptureOrigin::inet_forward(42, "owner", "stn"),
        bytes: vec![0x45u8; 64],
        snapshot_generation: 1,
        config_generation: 2,
        fib_generation: 3,
        zone_id: 4,
        if_id: 5,
        pmech_inventory_generation: 0,
        pmech_inventory_fib_generation: 0,
        pmech_policy_identity: [0; 32],
        deadline_mono_ns: crate::afxdp::monotonic_nanos() + 500_000_000,
        deadline_clock_id: PMECH_DEADLINE_CLOCK_MONOTONIC,
    }
}

fn desc_15149(
    request_id: u64,
    slab_id: u32,
    flow_tag: u64,
    generation: u64,
) -> IpsecInnerDescriptor {
    IpsecInnerDescriptor {
        slab_id,
        len: 64,
        tunnel_if_id: 1,
        stn_ifindex: 42,
        stn: [0; IPSEC_INNER_STN_MAX],
        stn_len: 0,
        inner_family: 2,
        inner_eth_proto: 0x0800,
        protocol: 6,
        rel_l4_offset: 20,
        payload_offset: 20,
        logical_ifindex: 42,
        rx_queue_index: 0,
        flow_tag,
        advisory_zone_id: 2,
        advisory_if_id: 1,
        expected_routing_domain: 0,
        expected_fib_table: 254,
        permit_epoch: PERMIT_15149,
        queue_number: 1,
        queue_epoch: QEPOCH_15149,
        snapshot_generation: 3,
        config_generation: 3,
        fib_generation: 3,
        pmech_inventory_generation: 4,
        pmech_inventory_fib_generation: 3,
        pmech_policy_identity: [0x6a; 32],
        phase_epoch: 1,
        worker_set_generation: generation,
        request_id,
        connection_id: 0,
        deadline_mono_ns: 0,
        enqueue_ns: 0,
        flags: 0,
    }
}

#[test]
fn dead_worker_sweep_retires_ipsec_inner_worker_15149() {
    let core = crate::slowpath_reinject_9506::ReinjectCore::new_shared();
    core.publish_epochs(PERMIT_15149, &[(1, QEPOCH_15149), (2, 13)]);
    let slow = Arc::new(crate::slowpath::SlowPathReinjector::new_without_worker_with_core(
        1500,
        core.clone(),
    ));
    let transport = slow.ipsec_inner_transport();
    transport.publish_workers([0, 1]);
    let generation = transport.authority().generation();
    let pool = transport.pool().clone();

    // Two requests admitted; both route to a worker (flow_tag % 2).
    for (request_id, flow_tag) in [(151_491u64, 0u64), (151_492, 1)] {
        assert!(core.admit(&frame_15149(request_id, flow_tag)).admitted);
        let slab_id = pool.acquire().expect("admission slab");
        let routed = transport
            .admit_descriptor(desc_15149(request_id, slab_id, flow_tag, generation))
            .expect("admit routes to a live worker");
        assert!(routed == 0 || routed == 1);
    }

    // Local copy of the tests.rs fake handle (that helper is private to the
    // sibling tests module).
    let fake_handle = || WorkerHandle {
        stop: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        heartbeat: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        commands: Arc::new(std::sync::Mutex::new(std::collections::VecDeque::new())),
        session_export_ack: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        cos_status: Arc::new(arc_swap::ArcSwap::from_pointee(Vec::new())),
        runtime_atomics: Arc::new(crate::afxdp::worker_runtime::WorkerRuntimeAtomics::new()),
        cold_path_atomics: Arc::new(crate::afxdp::cold_path_hist::WorkerColdPathAtomics::new()),
    };

    let mut coordinator = Coordinator::new();
    let dead_rec = WorkerRuntimeRecord::for_test(fake_handle());
    let dead_atomics = dead_rec.handle.runtime_atomics.clone();
    coordinator.workers.register(0, dead_rec, None);
    coordinator.workers.register(
        1,
        WorkerRuntimeRecord::for_test(fake_handle()),
        None,
    );
    coordinator.slow_path = Some(slow.clone());

    // Control: worker 0 still alive -> sweep must not touch D11 routing.
    coordinator.retire_dead_worker_holders();
    assert_eq!(
        transport.authority().live_count(),
        2,
        "a LIVE worker must stay in the IPsec-inner live set"
    );

    // Worker 0 panics: supervisor sets `dead`, thread exits, no respawn.
    dead_atomics.dead.store(true, Ordering::Relaxed);
    coordinator.retire_dead_worker_holders();

    // The survivor is now the sole route for every flow.
    assert_eq!(transport.authority().live_count(), 1);
    for flow_tag in 0..16u64 {
        assert_eq!(
            transport.authority().route(flow_tag),
            Some(1),
            "after the sweep alone, flow {flow_tag} must route to survivor 1, \
             never the dead worker 0 (#15149)"
        );
    }

    // The dead worker's reaped request completes as Denied; the survivor's
    // request stays pending (its worker is alive and may still adjudicate
    // it) — a sweep that terminalized survivors would fail this.
    let ready = core.drain_ready(16);
    assert_eq!(
        ready.len(),
        1,
        "only the dead worker's request must complete, got {ready:?}"
    );
    assert_eq!(ready[0].request_id, 151_491);
    assert_eq!(
        ready[0].outcome,
        crate::slowpath_reinject_9506::ReinjectOutcome::Denied,
        "reaped request must complete as Denied, not by ack timeout (#15149)"
    );
    // The dead worker's slab is reclaimed; the survivor's is still held.
    assert_eq!(
        pool.free_count(),
        crate::afxdp::ipsec_inner_queue::IPSEC_INNER_SLAB_CAP - 1
    );
}
