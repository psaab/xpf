//! #18560: matched-view grace. A packet the shim stamped with a forwarding
//! view this worker has left is parked and processed under THAT view's tables
//! and validation, never dropped and never processed under the newer tables.
//!
//! The poll-level cells drive the real descriptor loop
//! (`poll_binding_process_descriptor_in_view`) with the GRE-to-self fixture
//! from `tests_support` (outer packet stamped config 7 / FIB 9; the decapped
//! inner packet is delivered to the gr- channel), so "processed" is observable
//! as exactly one delivery.
#![allow(unused_imports)]

use super::test_fixtures::*;
use super::tests_support::*;
use super::*;
use std::sync::mpsc;

const STAMPED: ValidationState = ValidationState {
    snapshot_installed: true,
    config_generation: 7,
    fib_generation: 9,
    neighbor_generation: 0,
};
const NEWER: ValidationState = ValidationState {
    snapshot_installed: true,
    config_generation: 8,
    fib_generation: 9,
    neighbor_generation: 0,
};
const NOW_NS: u64 = 123_000_000_000;

fn views_with(prev: ValidationState, forwarding: &Arc<ForwardingState>, next: ValidationState) -> PrevViews {
    let mut views = PrevViews::default();
    views.retain(prev, forwarding, next, NOW_NS);
    views
}

#[test]
fn retain_keeps_only_forward_moves_18560() {
    let fwd = Arc::new(ForwardingState::default());
    assert_eq!(views_with(STAMPED, &fwd, NEWER).find(7, 9, NOW_NS), Some(0), "route/config publish");
    let fib_bump = ValidationState { fib_generation: 10, ..STAMPED };
    assert_eq!(views_with(STAMPED, &fwd, fib_bump).find(7, 9, NOW_NS), Some(0), "FIB bump");
    let neighbor_only = ValidationState { neighbor_generation: 4, ..STAMPED };
    assert!(views_with(STAMPED, &fwd, neighbor_only).is_empty(), "neighbor-only republish changes no stamp");
    let first = ValidationState { snapshot_installed: false, ..STAMPED };
    assert!(views_with(first, &fwd, NEWER).is_empty(), "first install has no stamp to match");
    // A reset to a lower generation keeps the strict fence and forgets
    // everything retained before it.
    let mut views = views_with(STAMPED, &fwd, NEWER);
    let reset = ValidationState { config_generation: 2, ..NEWER };
    views.retain(NEWER, &fwd, reset, NOW_NS);
    assert!(views.is_empty(), "a generation that went down must clear the retained views");
}

#[test]
fn find_is_exact_pair_newest_first_and_expires_18560() {
    let fwd = Arc::new(ForwardingState::default());
    let mut views = PrevViews::default();
    let v1 = STAMPED;
    let v2 = ValidationState { fib_generation: 10, ..v1 };
    let v3 = ValidationState { config_generation: 8, ..v2 };
    let v4 = ValidationState { fib_generation: 11, ..v3 };
    let v5 = ValidationState { config_generation: 9, ..v4 };
    views.retain(v1, &fwd, v2, NOW_NS);
    views.retain(v2, &fwd, v3, NOW_NS);
    views.retain(v3, &fwd, v4, NOW_NS);
    assert_eq!(views.find(8, 10, NOW_NS), Some(0));
    assert_eq!(views.find(7, 10, NOW_NS), Some(1));
    assert_eq!(views.find(7, 9, NOW_NS), Some(2));
    assert_eq!(views.find(8, 9, NOW_NS), None, "a mixed pair matches no published view");
    views.retain(v4, &fwd, v5, NOW_NS);
    assert_eq!(views.find(7, 9, NOW_NS), None, "only MATCHED_VIEW_SLOTS views are kept");
    assert_eq!(views.find(8, 11, NOW_NS), Some(0));
    let late = NOW_NS + MATCHED_VIEW_GRACE_NS;
    assert_eq!(views.find(8, 11, late), None, "a view past its deadline matches nothing");
    views.expire(late);
    assert!(views.is_empty());
}

fn meta_stamped(config: u64, fib: u32) -> UserspaceDpMeta {
    UserspaceDpMeta {
        config_generation: config,
        fib_generation: fib,
        ..UserspaceDpMeta::default()
    }
}

#[test]
fn parks_only_mismatches_of_another_retained_view_18560() {
    let fwd = Arc::new(ForwardingState::default());
    let views = views_with(STAMPED, &fwd, NEWER);
    let normal = PassView { prev_views: Some(&views), held_pass: false, view: None };
    let cfg = PacketDisposition::ConfigGenerationMismatch;
    assert!(normal.parks(&meta_stamped(7, 9), cfg, NOW_NS), "stamped with the left view");
    assert!(
        !normal.parks(&meta_stamped(9, 9), cfg, NOW_NS),
        "#6592: a stamp ahead of the worker is never parked"
    );
    assert!(!normal.parks(&meta_stamped(6, 9), cfg, NOW_NS), "older than every retained view");
    assert!(
        !normal.parks(&meta_stamped(7, 9), PacketDisposition::UnsupportedPacket, NOW_NS),
        "only generation mismatches park"
    );
    let own = PassView { prev_views: Some(&views), held_pass: true, view: Some(0) };
    assert!(!own.parks(&meta_stamped(7, 9), cfg, NOW_NS), "a held pass does not re-park its own view");
    assert!(!PassView::current().parks(&meta_stamped(7, 9), cfg, NOW_NS));
}

struct GreFixture {
    binding: BindingWorker,
    sessions: SessionTable,
    forwarding: Arc<ForwardingState>,
    rx: mpsc::Receiver<Vec<u8>>,
    deliveries: Arc<ArcSwap<BTreeMap<i32, LocalTunnelDelivery>>>,
    frame: Vec<u8>,
    meta: UserspaceDpMeta,
}

fn gre_fixture() -> GreFixture {
    let forwarding = Arc::new(build_forwarding_state(&gre_to_self_snapshot()));
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 11, 0);
    binding.interface = Arc::<str>::from("ge-0-0-0");
    let inner = build_gre_inner_icmp_packet_v4();
    let frame = build_gre_to_self_outer_frame_v4(80, &inner);
    let meta = gre_to_self_outer_meta(80, frame.len());
    assert_eq!(
        (meta.config_generation, meta.fib_generation),
        (STAMPED.config_generation, STAMPED.fib_generation),
        "premise: the fixture stamps 7/9"
    );
    let (tx, rx) = mpsc::sync_channel(8);
    let wake = Arc::new(TunnelWake::new().expect("eventfd"));
    let deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::from([(77, LocalTunnelDelivery { tx, wake })])));
    GreFixture {
        binding,
        sessions: SessionTable::new(),
        forwarding,
        rx,
        deliveries,
        frame,
        meta,
    }
}

/// One descriptor pass. `push` puts the fixture frame on the RX ring first.
fn run_pass(fx: &mut GreFixture, forwarding: &ForwardingState, validation: ValidationState, pass: PassView<'_>, push: bool) -> BatchCounters {
    let meta_len = std::mem::size_of::<UserspaceDpMeta>();
    let frame_offset = 128;
    if push {
        let meta_bytes = unsafe { std::slice::from_raw_parts((&fx.meta as *const UserspaceDpMeta).cast::<u8>(), meta_len) };
        unsafe {
            fx.binding.umem.area().slice_mut_unchecked(frame_offset - meta_len, meta_len).expect("meta slice").copy_from_slice(meta_bytes);
            fx.binding.umem.area().slice_mut_unchecked(frame_offset, fx.frame.len()).expect("frame slice").copy_from_slice(&fx.frame);
        }
        fx.binding.xsk.rx.push_for_test(XdpDesc { addr: frame_offset as u64, len: fx.frame.len() as u32, options: 0 });
    }
    let ha_state = txn_ha_state();
    let ident = fx.binding.identity();
    let binding_lookup = WorkerBindingLookup::from_bindings(std::slice::from_ref(&fx.binding));
    let mirror_targets = MirrorTargetMap::default();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::default());
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let ike_exchanges = Arc::new(crate::afxdp::forwarding::IkeExchangeTable::new());
    let recent_exceptions = Arc::new(Mutex::new(ExceptionEventRing::new()));
    let last_resolution = Arc::new(Mutex::new(None));
    let peer_worker_commands = Vec::new();
    let rg_epochs = std::array::from_fn(|_| AtomicU32::new(0));
    let pptp = Arc::new(crate::session::pptp_control::PptpControlInbox::default());
    let worker_ctx = WorkerContext {
        pptp_control: &pptp,
        ident: &ident,
        binding_lookup: &binding_lookup,
        mirror_targets: &mirror_targets,
        forwarding,
        ha_state: &ha_state,
        forwarding_active_rgs: &*EMPTY_FWD_ACTIVE_RGS_16217,
        dynamic_neighbors: &dynamic_neighbors,
        neighbor_resolver: None,
        shared_sessions: &shared_sessions,
        shared_nat_sessions: &shared_nat_sessions,
        shared_forward_wire_sessions: &shared_forward_wire_sessions,
        shared_owner_rg_indexes: &shared_owner_rg_indexes,
        ike_exchanges: &ike_exchanges,
        slow_path: None,
        event_stream: None,
        local_tunnel_deliveries: &fx.deliveries,
        recent_exceptions: &recent_exceptions,
        last_resolution: &last_resolution,
        peer_worker_commands: &peer_worker_commands,
        worker_commands_by_id: crate::afxdp::empty_worker_commands_by_id(),
        rg_epochs: &rg_epochs,
        cold_path_sample_mask: 0xff,
    };
    let mut screen = ScreenState::new();
    let mut batch = BatchCounters::default();
    let mut dbg = DebugPollCounters::default();
    let mut telemetry = TelemetryContext { dbg: &mut dbg, counters: &mut batch };
    let area = UmemAreaHandle::from_umem(&fx.binding.umem);
    super::poll_descriptor::poll_binding_process_descriptor_in_view(
        &mut fx.binding,
        0,
        &mut [],
        &mut [],
        &area,
        u32::from(push),
        None,
        &mut fx.sessions,
        &mut screen,
        validation,
        NOW_NS,
        NOW_NS / 1_000_000_000,
        0,
        0,
        -1,
        -1,
        &worker_ctx,
        &mut telemetry,
        pass,
    );
    batch
}

/// The defect cell. A flow's flow-cache entry was seeded under 7/9; the
/// worker then moves to 8/9 while the shim still stamps 7/9. The ordinary
/// pass must park the flow's next packet (not drop it as a config generation
/// mismatch, not recycle it), and the held pass must serve it from the flow
/// cache under the 7/9 view. RED on revert of the park.
#[test]
fn packet_stamped_with_left_view_is_processed_under_it_18560() {
    let mut fx = transit_syn_fixture();
    let fwd = Arc::clone(&fx.forwarding);
    let batch = run_pass(&mut fx, &fwd, STAMPED, PassView::current(), true);
    assert_eq!(batch.session_creates, 1, "premise: the SYN establishes the flow under 7/9");
    let source = Ipv4Addr::new(10, 0, 61, 102);
    let destination = Ipv4Addr::new(172, 16, 80, 200);
    fx.frame = build_txn_tcp_syn_frame_v4(source, destination, 35790, 5211, crate::tcp_flags::TCP_ACK, TEST_LAN_MAC);
    fx.meta.tcp_flags = crate::tcp_flags::TCP_ACK;
    run_pass(&mut fx, &fwd, STAMPED, PassView::current(), true);
    assert!(txn_flow_cache_entries(&fx.binding) > 0, "premise: the flow's next packet seeds the flow cache under 7/9");
    let views = views_with(STAMPED, &fwd, NEWER);

    let normal = PassView { prev_views: Some(&views), held_pass: false, view: None };
    run_pass(&mut fx, &fwd, NEWER, normal, true);
    assert_eq!(fx.binding.live.config_gen_mismatches.load(Ordering::Relaxed), 0, "the left-view packet was dropped as a generation mismatch");
    assert_eq!(fx.binding.view_held.len(), 1, "the left-view packet must be parked for a held pass");
    assert!(fx.binding.scratch.scratch_recycle.is_empty(), "a parked descriptor must not be recycled");

    let hits_before = fx.binding.flow.flow_cache.hits;
    let view = views.find(7, 9, NOW_NS);
    let held = PassView { prev_views: Some(&views), held_pass: true, view };
    let prev = views.get(view.expect("retained")).expect("retained view");
    let batch = run_pass(&mut fx, &prev.forwarding, prev.validation, held, false);
    assert!(fx.binding.view_held.is_empty(), "the held pass must consume what it ran");
    assert_eq!(fx.binding.flow.flow_cache.hits, hits_before + 1, "the parked packet must be served from the 7/9 flow cache");
    assert_eq!(batch.session_misses, 0);
    assert_eq!(fx.binding.live.config_gen_mismatches.load(Ordering::Relaxed), 0);
}

/// A held packet that misses the flow cache is dropped as a generation
/// mismatch: the held pass never reaches the session slow path, whose
/// side effects (re-resolution, synced-session purge/promotion) left
/// established flows without a session on a demoting node.
#[test]
fn held_pass_serves_only_flow_cache_hits_18560() {
    let mut fx = transit_syn_fixture();
    let fwd = Arc::clone(&fx.forwarding);
    run_pass(&mut fx, &fwd, STAMPED, PassView::current(), true);
    let source = Ipv4Addr::new(10, 0, 61, 102);
    let destination = Ipv4Addr::new(172, 16, 80, 200);
    fx.frame = build_txn_tcp_syn_frame_v4(source, destination, 35790, 5211, crate::tcp_flags::TCP_ACK, TEST_LAN_MAC);
    fx.meta.tcp_flags = crate::tcp_flags::TCP_ACK;
    // No 7/9 flow-cache entry exists for this packet: the session exists,
    // but the cache was never seeded.
    let views = views_with(STAMPED, &fwd, NEWER);
    run_pass(&mut fx, &fwd, NEWER, PassView { prev_views: Some(&views), held_pass: false, view: None }, true);
    assert_eq!(fx.binding.view_held.len(), 1, "premise: parked");
    let sessions_before = fx.sessions.len();
    let prev = views.get(0).expect("retained view");
    let batch = run_pass(&mut fx, &prev.forwarding, prev.validation, PassView { prev_views: Some(&views), held_pass: true, view: Some(0) }, false);
    assert_eq!(batch.session_hits + batch.session_misses, 0, "a held packet must not reach the session slow path");
    assert_eq!(fx.sessions.len(), sessions_before, "the held pass must not touch the session table");
    assert_eq!(fx.binding.live.config_gen_mismatches.load(Ordering::Relaxed), 1, "dropped as the generation mismatch it is");
}

/// #6592 orientation and the expiry path: a stamp AHEAD of the worker, or a
/// left view whose deadline passed, is still dropped (counted, recycled,
/// nothing delivered).
#[test]
fn stamp_ahead_or_expired_view_is_dropped_18560() {
    let mut fx = gre_fixture();
    let fwd = Arc::clone(&fx.forwarding);
    let older = ValidationState { config_generation: 6, ..STAMPED };
    let views = views_with(older, &fwd, STAMPED);
    let normal = PassView { prev_views: Some(&views), held_pass: false, view: None };
    // The worker is at 6/9 -> the 7/9 stamp is ahead.
    run_pass(&mut fx, &fwd, older, normal, true);
    assert!(fx.binding.view_held.is_empty(), "#6592: a stamp ahead of the worker must not be parked");
    assert_eq!(fx.binding.live.config_gen_mismatches.load(Ordering::Relaxed), 1);
    assert!(fx.rx.try_recv().is_err());

    // A parked packet whose view expired before its held pass is judged
    // against the current view and dropped.
    let mut fx = gre_fixture();
    let views = views_with(STAMPED, &fwd, NEWER);
    run_pass(&mut fx, &fwd, NEWER, PassView { prev_views: Some(&views), held_pass: false, view: None }, true);
    assert_eq!(fx.binding.view_held.len(), 1);
    let mut expired = views.clone();
    expired.expire(NOW_NS + MATCHED_VIEW_GRACE_NS);
    run_pass(&mut fx, &fwd, NEWER, PassView { prev_views: None, held_pass: true, view: None }, false);
    assert!(fx.binding.view_held.is_empty());
    assert_eq!(fx.binding.live.config_gen_mismatches.load(Ordering::Relaxed), 1, "an expired view's packet is dropped as before");
    assert_eq!(fx.binding.scratch.scratch_recycle.len(), 1, "and its descriptor is recycled");
    assert!(fx.rx.try_recv().is_err());
}

/// The batch view `poll_binding` builds its WorkerContext from: the retained
/// view of the first parked stamp (its own tables, not the current ones),
/// else the current pair. RED if a held pass runs under the current view.
#[test]
fn held_pass_runs_under_the_retained_tables_18560() {
    let left = Arc::new(ForwardingState::default());
    let current = ForwardingState::default();
    let views = views_with(STAMPED, &left, NEWER);
    let parked = [(XdpDesc::default(), meta_stamped(7, 9))];
    let (view, fwd, validation) =
        super::worker::held_pass_view(&parked, &views, NOW_NS, &current, NEWER);
    assert_eq!(view, Some(0));
    assert!(std::ptr::eq(fwd, left.as_ref()), "a held pass must use the left view's tables");
    assert_eq!(validation, STAMPED, "and its validation");

    let (view, fwd, validation) = super::worker::held_pass_view(&[], &views, NOW_NS, &current, NEWER);
    assert_eq!((view, validation), (None, NEWER));
    assert!(std::ptr::eq(fwd, &current), "an ordinary batch uses the current tables");

    let late = NOW_NS + MATCHED_VIEW_GRACE_NS;
    let (view, fwd, validation) = super::worker::held_pass_view(&parked, &views, late, &current, NEWER);
    assert_eq!((view, validation), (None, NEWER), "an expired view falls back to the current pair");
    assert!(std::ptr::eq(fwd, &current));
}

/// A held pass must not move the session table's revalidation stamps back to
/// the left view: the table is single-versioned, and an old stamp made every
/// session stale for the pass, so held packets re-derived routes/policy under
/// the old tables with the current HA state and fell to the session-miss path
/// on a demoting node (loss test-failover: +12.2k session misses). RED on
/// revert of the prologue guard.
#[test]
fn held_pass_keeps_session_stamps_current_18560() {
    let mut fx = gre_fixture();
    let fwd = Arc::clone(&fx.forwarding);
    let views = views_with(STAMPED, &fwd, NEWER);
    run_pass(&mut fx, &fwd, NEWER, PassView { prev_views: Some(&views), held_pass: false, view: None }, true);
    assert_eq!(fx.sessions.filter_revalidation_gen(), NEWER.config_generation);
    let prev = views.get(0).expect("retained view");
    run_pass(&mut fx, &prev.forwarding, prev.validation, PassView { prev_views: Some(&views), held_pass: true, view: Some(0) }, false);
    assert_eq!(
        fx.sessions.filter_revalidation_gen(),
        NEWER.config_generation,
        "a held pass must leave the session table on the current view's stamps"
    );
}

fn transit_syn_fixture() -> GreFixture {
    let forwarding = Arc::new(build_forwarding_state(&nat_snapshot_with_fabric()));
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let source = Ipv4Addr::new(10, 0, 61, 102);
    let destination = Ipv4Addr::new(172, 16, 80, 200);
    let frame = build_txn_tcp_syn_frame_v4(source, destination, 35790, 5211, TCP_FLAG_SYN, TEST_LAN_MAC);
    let mut meta = txn_meta_v4(24, TCP_FLAG_SYN, frame.len() as u16);
    meta.flow_src_addr[..4].copy_from_slice(&source.octets());
    meta.flow_dst_addr[..4].copy_from_slice(&destination.octets());
    meta.flow_src_port = 35790;
    meta.flow_dst_port = 5211;
    let (_tx, rx) = mpsc::sync_channel(1);
    GreFixture {
        binding,
        sessions: SessionTable::new(),
        forwarding,
        rx,
        deliveries: Arc::new(ArcSwap::from_pointee(BTreeMap::new())),
        frame,
        meta,
    }
}

/// A held pass creates no session: a new flow admitted under a left view's
/// tables would carry the current stamps and never be re-judged. It is
/// dropped as a generation mismatch, as before the grace. The positive
/// control shows the same SYN installs a session under its own (current)
/// view. RED on revert of the held-pass miss guard.
#[test]
fn held_pass_creates_no_session_18560() {
    let mut control = transit_syn_fixture();
    let fwd = Arc::clone(&control.forwarding);
    let batch = run_pass(&mut control, &fwd, STAMPED, PassView::current(), true);
    assert_eq!(batch.session_creates, 1, "premise: the SYN installs a session under its own view");

    let mut fx = transit_syn_fixture();
    let fwd = Arc::clone(&fx.forwarding);
    let views = views_with(STAMPED, &fwd, NEWER);
    run_pass(&mut fx, &fwd, NEWER, PassView { prev_views: Some(&views), held_pass: false, view: None }, true);
    assert_eq!(fx.binding.view_held.len(), 1, "premise: the SYN is parked");
    let prev = views.get(0).expect("retained view");
    let batch = run_pass(&mut fx, &prev.forwarding, prev.validation, PassView { prev_views: Some(&views), held_pass: true, view: Some(0) }, false);
    assert_eq!(batch.session_creates, 0, "a held pass must not install a session");
    assert_eq!(fx.sessions.len(), 0);
    assert_eq!(fx.binding.live.config_gen_mismatches.load(Ordering::Relaxed), 1, "dropped as the generation mismatch it is");
    assert_eq!(fx.binding.scratch.scratch_recycle.len(), 1, "and recycled");
}
