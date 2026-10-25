// #16504: the RST teardown drain must return both scratch buffers to
// the binding with their pre-sized capacities intact, and must keep
// the #15947 (H29-01) batch cross-cancel behaviour: two accepted RSTs
// for one session in the same batch must not cancel each other's
// pending forward.
//
// Pre-fix, `poll_binding` took `scratch_rst_teardowns`, built
// `rst_trigger_keeps` with a per-batch `collect`, drained, and dropped
// both Vecs — so every later RST batch reallocated both from zero.

use super::*;
use crate::nat::NatDecision;
use crate::session::SessionKey;
use std::net::{IpAddr, Ipv4Addr};

fn key(src_port: u16) -> SessionKey {
    SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: crate::ip_proto::PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        src_port,
        dst_port: 5201,
        discriminator: Default::default(),
        routing_domain: 0,
    }
}

fn pending(key: &SessionKey, addr: u64, decision: SessionDecision) -> PendingForwardRequest {
    PendingForwardRequest {
        target_ifindex: 22,
        target_binding_index: None,
        ingress_queue_id: 0,
        desc: crate::xsk_ffi::xdp::XdpDesc {
            addr,
            len: 64,
            options: 0,
        },
        frame: PendingForwardFrame::Live,
        meta: ForwardPacketMeta::default(),
        decision,
        apply_nat_on_fabric: false,
        expected_ports: None,
        flow_key: Some(key.clone()),
        nat64_reverse: None,
        overlap_admissions: None,
        cos_queue_id: None,
        dscp_rewrite: None,
        cos_tx_selection_resolved: true,
    }
}

fn decision() -> SessionDecision {
    SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 12,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 1))),
            neighbor_mac: Some([0, 1, 2, 3, 4, 5]),
            src_mac: Some([6, 7, 8, 9, 10, 11]),
            tx_vlan_id: 0,
            source_ifindex: 0,
            route_mtu: 0,
            transport_route_mtu: 0,
        },
        nat: NatDecision::default(),
        install_table_domain: 0,
        install_table_check: 0,
    }
}

// The exact state the descriptor loop leaves behind for one RST batch:
// both scratch buffers taken by the production drain, both returned.
struct DrainFixture {
    current: BindingWorker,
    sessions: SessionTable,
    forwarding: ForwardingState,
    shared_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: SharedSessionOwnerRgIndexes,
    peer_worker_commands: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>>,
    worker_commands_by_id: &'static WorkerCommandQueues,
    pending_forwards: Vec<PendingForwardRequest>,
    shared_recycles: Vec<(u32, u64)>,
}

impl DrainFixture {
    fn new() -> Self {
        Self {
            current: BindingWorker::new_for_mirror_test(0, 0, 24, 0),
            sessions: SessionTable::new(),
            forwarding: ForwardingState::default(),
            shared_sessions: Arc::new(Mutex::new(FastMap::default())),
            shared_nat_sessions: Arc::new(Mutex::new(FastMap::default())),
            shared_forward_wire_sessions: Arc::new(Mutex::new(FastMap::default())),
            shared_owner_rg_indexes: SharedSessionOwnerRgIndexes::default(),
            peer_worker_commands: Vec::new(),
            worker_commands_by_id: crate::afxdp::empty_worker_commands_by_id(),
            pending_forwards: Vec::new(),
            shared_recycles: Vec::new(),
        }
    }

    fn drain(&mut self) {
        drain_rst_teardowns(
            &mut [],
            &mut self.current,
            &mut [],
            &mut self.sessions,
            &self.shared_sessions,
            &self.shared_nat_sessions,
            &self.shared_forward_wire_sessions,
            &self.shared_owner_rg_indexes,
            &self.peer_worker_commands,
            &mut self.pending_forwards,
            &mut self.shared_recycles,
            &self.forwarding,
            &self.worker_commands_by_id,
            0,
            2,
        );
    }
}

#[test]
fn rst_drain_restores_scratch_capacities_16504() {
    // #16504 acceptance cell: after a batch carrying an accepted RST,
    // both scratch buffers are back on the binding, emptied, with the
    // capacity they had before the take. Pre-fix both were dropped, so
    // the binding's next push grew from capacity 0 (an allocation).
    let mut fx = DrainFixture::new();
    let flow = key(12345);
    let teardowns_cap = fx.current.scratch.scratch_rst_teardowns.capacity();
    let keeps_cap = fx.current.scratch.scratch_rst_trigger_keeps.capacity();
    assert!(
        teardowns_cap >= 16 && keeps_cap >= 16,
        "precondition: both RST scratch buffers are pre-sized \
         (teardowns={teardowns_cap}, keeps={keeps_cap})"
    );
    fx.current.scratch.scratch_rst_teardowns.push((
        flow.clone(),
        NatDecision::default(),
        Some((flow.clone(), 0x1000)),
    ));

    fx.drain();

    assert!(
        fx.current.scratch.scratch_rst_teardowns.is_empty(),
        "the teardowns scratch must be drained, or it replays next batch"
    );
    // The keeps buffer is left populated for the drain's callers and is
    // emptied by the NEXT batch's clear, beside its sibling clears in
    // poll_descriptor (its Vec::clear at fill time covers it too). What
    // this cell pins is that the drain UNDERSTOOD the trigger: exactly
    // this batch's trigger, not nothing and not a stale superset.
    assert_eq!(
        fx.current.scratch.scratch_rst_trigger_keeps,
        vec![(flow.clone(), 0x1000)],
        "the keeps scratch must carry exactly this batch's trigger set"
    );
    assert_eq!(
        fx.current.scratch.scratch_rst_teardowns.capacity(),
        teardowns_cap,
        "#16504: the teardowns Vec must be handed back with its capacity, \
         not dropped (dropping forced the next RST batch to reallocate)"
    );
    assert_eq!(
        fx.current.scratch.scratch_rst_trigger_keeps.capacity(),
        keeps_cap,
        "#16504: the keeps Vec must be handed back with its capacity, \
         not built by a per-batch collect and dropped"
    );
}

#[test]
fn rst_drain_keeps_batch_triggers_and_recycles_siblings_16504() {
    // #15947 (H29-01) through the production drain: two accepted RSTs
    // for one session in one batch must not cross-cancel — both
    // triggers' pending forwards survive; a non-trigger sibling for
    // the same flow is recycled.
    let mut fx = DrainFixture::new();
    let flow = key(12345);
    let dec = decision();
    fx.pending_forwards = vec![
        pending(&flow, 0x1000, dec),
        pending(&flow, 0x2000, dec),
        pending(&flow, 0x3000, dec),
    ];
    fx.current.scratch.scratch_rst_teardowns.push((
        flow.clone(),
        NatDecision::default(),
        Some((flow.clone(), 0x1000)),
    ));
    fx.current.scratch.scratch_rst_teardowns.push((
        flow.clone(),
        NatDecision::default(),
        Some((flow.clone(), 0x2000)),
    ));

    fx.drain();

    let kept: Vec<u64> = fx.pending_forwards.iter().map(|r| r.desc.addr).collect();
    assert_eq!(
        kept,
        vec![0x1000, 0x2000],
        "both batch RST triggers must survive the teardown drain"
    );
    let recycled: Vec<u64> = fx
        .current
        .tx_pipeline
        .pending_fill_frames
        .iter()
        .copied()
        .collect();
    assert_eq!(
        recycled,
        vec![0x3000],
        "the non-trigger sibling for the torn-down flow must be recycled"
    );
}
