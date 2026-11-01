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

fn views_with(
    prev: ValidationState,
    forwarding: &Arc<ForwardingState>,
    next: ValidationState,
) -> PrevViews {
    let mut views = PrevViews::default();
    views.retain(prev, forwarding, next, NOW_NS);
    views
}

#[test]
fn retain_keeps_only_forward_moves_18560() {
    let fwd = Arc::new(ForwardingState::default());
    assert_eq!(
        views_with(STAMPED, &fwd, NEWER).find(7, 9, NOW_NS),
        Some(0),
        "route/config publish"
    );
    let fib_bump = ValidationState {
        fib_generation: 10,
        ..STAMPED
    };
    assert_eq!(
        views_with(STAMPED, &fwd, fib_bump).find(7, 9, NOW_NS),
        Some(0),
        "FIB bump"
    );
    let neighbor_only = ValidationState {
        neighbor_generation: 4,
        ..STAMPED
    };
    assert!(
        views_with(STAMPED, &fwd, neighbor_only).is_empty(),
        "neighbor-only republish changes no stamp"
    );
    let first = ValidationState {
        snapshot_installed: false,
        ..STAMPED
    };
    assert!(
        views_with(first, &fwd, NEWER).is_empty(),
        "first install has no stamp to match"
    );
    // A reset to a lower generation keeps the strict fence and forgets
    // everything retained before it.
    let mut views = views_with(STAMPED, &fwd, NEWER);
    let reset = ValidationState {
        config_generation: 2,
        ..NEWER
    };
    views.retain(NEWER, &fwd, reset, NOW_NS);
    assert!(
        views.is_empty(),
        "a generation that went down must clear the retained views"
    );
}

#[test]
fn find_is_exact_pair_newest_first_and_expires_18560() {
    let fwd = Arc::new(ForwardingState::default());
    let mut views = PrevViews::default();
    let v1 = STAMPED;
    let v2 = ValidationState {
        fib_generation: 10,
        ..v1
    };
    let v3 = ValidationState {
        config_generation: 8,
        ..v2
    };
    let v4 = ValidationState {
        fib_generation: 11,
        ..v3
    };
    let v5 = ValidationState {
        config_generation: 9,
        ..v4
    };
    let v6 = ValidationState {
        fib_generation: 12,
        ..v5
    };
    views.retain(v1, &fwd, v2, NOW_NS);
    views.retain(v2, &fwd, v3, NOW_NS);
    assert_eq!(views.find(7, 10, NOW_NS), Some(0));
    assert_eq!(
        views.find(7, 9, NOW_NS),
        Some(1),
        "two slots: the view two publishes back is still held"
    );
    assert_eq!(
        views.find(8, 9, NOW_NS),
        None,
        "a mixed pair matches no published view"
    );
    views.retain(v3, &fwd, v4, NOW_NS);
    assert_eq!(
        views.find(7, 9, NOW_NS),
        None,
        "only MATCHED_VIEW_SLOTS views are kept"
    );
    assert_eq!(views.find(8, 10, NOW_NS), Some(0));
    views.retain(v4, &fwd, v5, NOW_NS);
    views.retain(v5, &fwd, v6, NOW_NS);
    assert_eq!(views.find(9, 11, NOW_NS), Some(0));
    let late = NOW_NS + MATCHED_VIEW_GRACE_NS;
    assert_eq!(
        views.find(9, 11, late - 1),
        Some(0),
        "the view lives for the whole grace"
    );
    assert_eq!(
        views.find(9, 11, late),
        None,
        "a view past its deadline matches nothing"
    );
    views.expire(late);
    assert!(views.is_empty());
    assert_eq!(
        MATCHED_VIEW_SLOTS, 2,
        "#18560 probe: one publish behind, plus the one before"
    );
    assert_eq!(
        MATCHED_VIEW_GRACE_NS, 200_000_000,
        "#18560 probe: about 12x the slowest adoption (15.7 ms)"
    );
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
    let normal = PassView {
        prev_views: Some(&views),
        held_pass: false,
        view: None,
    };
    let cfg = PacketDisposition::ConfigGenerationMismatch;
    assert!(
        normal.parks(&meta_stamped(7, 9), cfg, NOW_NS),
        "stamped with the left view"
    );
    assert!(
        !normal.parks(&meta_stamped(9, 9), cfg, NOW_NS),
        "#6592: a stamp ahead of the worker is never parked"
    );
    assert!(
        !normal.parks(&meta_stamped(6, 9), cfg, NOW_NS),
        "older than every retained view"
    );
    assert!(
        !normal.parks(
            &meta_stamped(7, 9),
            PacketDisposition::UnsupportedPacket,
            NOW_NS
        ),
        "only generation mismatches park"
    );
    let own = PassView {
        prev_views: Some(&views),
        held_pass: true,
        view: Some(0),
    };
    assert!(
        !own.parks(&meta_stamped(7, 9), cfg, NOW_NS),
        "a held pass does not re-park its own view"
    );
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
    let deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::from([(
        77,
        LocalTunnelDelivery { tx, wake },
    )])));
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
fn run_pass(
    fx: &mut GreFixture,
    forwarding: &ForwardingState,
    validation: ValidationState,
    pass: PassView<'_>,
    push: bool,
) -> BatchCounters {
    run_pass_ha(fx, forwarding, validation, pass, push, &txn_ha_state())
}

/// `run_pass` under an explicit live HA snapshot.
fn run_pass_ha(
    fx: &mut GreFixture,
    forwarding: &ForwardingState,
    validation: ValidationState,
    pass: PassView<'_>,
    push: bool,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
) -> BatchCounters {
    let meta_len = std::mem::size_of::<UserspaceDpMeta>();
    let frame_offset = 128;
    if push {
        let meta_bytes = unsafe {
            std::slice::from_raw_parts((&fx.meta as *const UserspaceDpMeta).cast::<u8>(), meta_len)
        };
        unsafe {
            fx.binding
                .umem
                .area()
                .slice_mut_unchecked(frame_offset - meta_len, meta_len)
                .expect("meta slice")
                .copy_from_slice(meta_bytes);
            fx.binding
                .umem
                .area()
                .slice_mut_unchecked(frame_offset, fx.frame.len())
                .expect("frame slice")
                .copy_from_slice(&fx.frame);
        }
        fx.binding.xsk.rx.push_for_test(XdpDesc {
            addr: frame_offset as u64,
            len: fx.frame.len() as u32,
            options: 0,
        });
    }
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
        ha_state,
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
    let mut telemetry = TelemetryContext {
        dbg: &mut dbg,
        counters: &mut batch,
    };
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

/// A UDP flow from the LAN host to the WAN gateway (which has a static
/// neighbor in `nat_snapshot`), so its second packet seeds the flow cache.
fn udp_flow_fixture() -> GreFixture {
    let mut fx = transit_syn_fixture();
    let source = Ipv4Addr::new(10, 0, 61, 102);
    let destination = Ipv4Addr::new(172, 16, 80, 1);
    let mut frame = build_udp_frame_v4_full(TEST_LAN_MAC, source, destination, 64);
    frame[34..36].copy_from_slice(&40001u16.to_be_bytes());
    frame[36..38].copy_from_slice(&5000u16.to_be_bytes());
    let mut meta = txn_meta_v4(24, 0, frame.len() as u16);
    meta.protocol = PROTO_UDP;
    meta.payload_offset = 42;
    meta.flow_src_addr[..4].copy_from_slice(&source.octets());
    meta.flow_dst_addr[..4].copy_from_slice(&destination.octets());
    meta.flow_src_port = 40001;
    meta.flow_dst_port = 5000;
    fx.frame = frame;
    fx.meta = meta;
    fx
}

/// The defect cell. A flow's flow-cache entry was seeded under 7/9; the
/// worker then moves to 8/9 while the shim still stamps 7/9. The ordinary
/// pass must park the flow's next packet (not drop it as a config generation
/// mismatch, not recycle it), and the held pass must serve it from the flow
/// cache under the 7/9 view. RED on revert of the park.
#[test]
fn packet_stamped_with_left_view_is_processed_under_it_18560() {
    let mut fx = udp_flow_fixture();
    let fwd = Arc::clone(&fx.forwarding);
    let batch = run_pass(&mut fx, &fwd, STAMPED, PassView::current(), true);
    assert!(
        batch.session_creates >= 1,
        "premise: the first packet establishes the flow under 7/9"
    );
    run_pass(&mut fx, &fwd, STAMPED, PassView::current(), true);
    assert!(
        txn_flow_cache_entries(&fx.binding) > 0,
        "premise: the flow's next packet seeds the flow cache under 7/9"
    );
    let views = views_with(STAMPED, &fwd, NEWER);

    let normal = PassView {
        prev_views: Some(&views),
        held_pass: false,
        view: None,
    };
    run_pass(&mut fx, &fwd, NEWER, normal, true);
    assert_eq!(
        fx.binding
            .live
            .config_gen_mismatches
            .load(Ordering::Relaxed),
        0,
        "the left-view packet was dropped as a generation mismatch"
    );
    assert_eq!(
        fx.binding.view_held.len(),
        1,
        "the left-view packet must be parked for a held pass"
    );

    let hits_before = fx.binding.flow.flow_cache.hits;
    let view = views.find(7, 9, NOW_NS);
    let held = PassView {
        prev_views: Some(&views),
        held_pass: true,
        view,
    };
    let prev = views.get(view.expect("retained")).expect("retained view");
    let batch = run_pass(&mut fx, &prev.forwarding, prev.validation, held, false);
    assert!(
        fx.binding.view_held.is_empty(),
        "the held pass must consume what it ran"
    );
    assert_eq!(
        fx.binding.flow.flow_cache.hits,
        hits_before + 1,
        "the parked packet must be served from the 7/9 flow cache"
    );
    assert_eq!(batch.session_misses, 0);
    assert_eq!(
        fx.binding
            .live
            .config_gen_mismatches
            .load(Ordering::Relaxed),
        0
    );
    assert_eq!(
        fx.binding.live.generation_held_hits.load(Ordering::Relaxed),
        1,
        "the saved packet is witnessed as a held hit"
    );
    assert_eq!(
        fx.binding
            .live
            .generation_held_misses
            .load(Ordering::Relaxed),
        0
    );
    assert_eq!(
        fx.binding
            .live
            .generation_mismatch_behind
            .load(Ordering::Relaxed),
        0,
        "nothing was dropped"
    );
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
    fx.frame = build_txn_tcp_syn_frame_v4(
        source,
        destination,
        35790,
        5211,
        crate::tcp_flags::TCP_ACK,
        TEST_LAN_MAC,
    );
    fx.meta.tcp_flags = crate::tcp_flags::TCP_ACK;
    // No 7/9 flow-cache entry exists for this packet: the session exists,
    // but the cache was never seeded.
    let views = views_with(STAMPED, &fwd, NEWER);
    run_pass(
        &mut fx,
        &fwd,
        NEWER,
        PassView {
            prev_views: Some(&views),
            held_pass: false,
            view: None,
        },
        true,
    );
    assert_eq!(fx.binding.view_held.len(), 1, "premise: parked");
    let sessions_before = fx.sessions.len();
    let prev = views.get(0).expect("retained view");
    let batch = run_pass(
        &mut fx,
        &prev.forwarding,
        prev.validation,
        PassView {
            prev_views: Some(&views),
            held_pass: true,
            view: Some(0),
        },
        false,
    );
    assert_eq!(
        batch.session_hits + batch.session_misses,
        0,
        "a held packet must not reach the session slow path"
    );
    assert_eq!(
        fx.sessions.len(),
        sessions_before,
        "the held pass must not touch the session table"
    );
    assert_eq!(
        fx.binding
            .live
            .config_gen_mismatches
            .load(Ordering::Relaxed),
        1,
        "dropped as the generation mismatch it is"
    );
    assert_eq!(
        fx.binding
            .live
            .generation_held_misses
            .load(Ordering::Relaxed),
        1,
        "witnessed as a held miss"
    );
    assert_eq!(
        fx.binding.live.generation_held_hits.load(Ordering::Relaxed),
        0
    );
}

/// #6592 orientation and the expiry path: a stamp AHEAD of the worker, or a
/// left view whose deadline passed, is still dropped (counted, recycled,
/// nothing delivered).
#[test]
fn stamp_ahead_or_expired_view_is_dropped_18560() {
    let mut fx = gre_fixture();
    let fwd = Arc::clone(&fx.forwarding);
    let older = ValidationState {
        config_generation: 6,
        ..STAMPED
    };
    let views = views_with(older, &fwd, STAMPED);
    let normal = PassView {
        prev_views: Some(&views),
        held_pass: false,
        view: None,
    };
    // The worker is at 6/9 -> the 7/9 stamp is ahead.
    run_pass(&mut fx, &fwd, older, normal, true);
    assert!(
        fx.binding.view_held.is_empty(),
        "#6592: a stamp ahead of the worker must not be parked"
    );
    assert_eq!(
        fx.binding
            .live
            .config_gen_mismatches
            .load(Ordering::Relaxed),
        1
    );
    assert_eq!(
        fx.binding
            .live
            .generation_mismatch_ahead
            .load(Ordering::Relaxed),
        1,
        "counted as AHEAD"
    );
    assert_eq!(
        fx.binding
            .live
            .generation_mismatch_behind
            .load(Ordering::Relaxed),
        0
    );
    assert!(fx.rx.try_recv().is_err());

    // A parked packet whose view expired before its held pass is judged
    // against the current view and dropped.
    let mut fx = gre_fixture();
    let views = views_with(STAMPED, &fwd, NEWER);
    run_pass(
        &mut fx,
        &fwd,
        NEWER,
        PassView {
            prev_views: Some(&views),
            held_pass: false,
            view: None,
        },
        true,
    );
    assert_eq!(fx.binding.view_held.len(), 1);
    let mut expired = views.clone();
    expired.expire(NOW_NS + MATCHED_VIEW_GRACE_NS);
    assert!(expired.is_empty(), "premise: the view expired");
    let (view, held_fwd, held_validation) =
        super::worker::held_pass_view(&fx.binding.view_held, &expired, NOW_NS, &fwd, NEWER);
    assert_eq!(view, None, "an expired view selects nothing");
    run_pass(
        &mut fx,
        held_fwd,
        held_validation,
        PassView {
            prev_views: Some(&expired),
            held_pass: true,
            view,
        },
        false,
    );
    assert!(fx.binding.view_held.is_empty());
    assert_eq!(
        fx.binding
            .live
            .config_gen_mismatches
            .load(Ordering::Relaxed),
        1,
        "an expired view's packet is dropped as before"
    );
    assert_eq!(
        fx.binding
            .live
            .generation_mismatch_behind
            .load(Ordering::Relaxed),
        1,
        "counted as BEHIND"
    );
    assert_eq!(
        fx.binding.live.generation_held_hits.load(Ordering::Relaxed),
        0
    );
    assert_eq!(
        fx.binding.scratch.scratch_recycle.len(),
        1,
        "and its descriptor is recycled"
    );
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
    assert!(
        std::ptr::eq(fwd, left.as_ref()),
        "a held pass must use the left view's tables"
    );
    assert_eq!(validation, STAMPED, "and its validation");

    let (view, fwd, validation) =
        super::worker::held_pass_view(&[], &views, NOW_NS, &current, NEWER);
    assert_eq!((view, validation), (None, NEWER));
    assert!(
        std::ptr::eq(fwd, &current),
        "an ordinary batch uses the current tables"
    );

    let late = NOW_NS + MATCHED_VIEW_GRACE_NS;
    let (view, fwd, validation) =
        super::worker::held_pass_view(&parked, &views, late, &current, NEWER);
    assert_eq!(
        (view, validation),
        (None, NEWER),
        "an expired view falls back to the current pair"
    );
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
    run_pass(
        &mut fx,
        &fwd,
        NEWER,
        PassView {
            prev_views: Some(&views),
            held_pass: false,
            view: None,
        },
        true,
    );
    assert_eq!(
        fx.sessions.filter_revalidation_gen(),
        NEWER.config_generation
    );
    let prev = views.get(0).expect("retained view");
    run_pass(
        &mut fx,
        &prev.forwarding,
        prev.validation,
        PassView {
            prev_views: Some(&views),
            held_pass: true,
            view: Some(0),
        },
        false,
    );
    assert_eq!(
        fx.sessions.filter_revalidation_gen(),
        NEWER.config_generation,
        "a held pass must leave the session table on the current view's stamps"
    );
    // Seat W (#18572 M1): `refresh_for_ha_transition`'s #10507 A2 reset runs
    // in `apply_worker_commands` BEFORE the next ordinary pass (RG2's
    // RefreshOwnerRGS lands inside the grace) and compares each row against
    // the table's live `policy_revalidation_gen`. A held pass that left it on
    // the old view would void that fence until the next ordinary pass.
    assert_eq!(
        fx.sessions.policy_revalidation_gen(),
        NEWER.config_generation,
        "the A2 fence's comparand must stay on the current view after a held pass"
    );
}

fn transit_syn_fixture() -> GreFixture {
    let forwarding = Arc::new(build_forwarding_state(&nat_snapshot_with_fabric()));
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let source = Ipv4Addr::new(10, 0, 61, 102);
    let destination = Ipv4Addr::new(172, 16, 80, 200);
    let frame =
        build_txn_tcp_syn_frame_v4(source, destination, 35790, 5211, TCP_FLAG_SYN, TEST_LAN_MAC);
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
    assert_eq!(
        batch.session_creates, 1,
        "premise: the SYN installs a session under its own view"
    );

    let mut fx = transit_syn_fixture();
    let fwd = Arc::clone(&fx.forwarding);
    let views = views_with(STAMPED, &fwd, NEWER);
    run_pass(
        &mut fx,
        &fwd,
        NEWER,
        PassView {
            prev_views: Some(&views),
            held_pass: false,
            view: None,
        },
        true,
    );
    assert_eq!(fx.binding.view_held.len(), 1, "premise: the SYN is parked");
    let prev = views.get(0).expect("retained view");
    let batch = run_pass(
        &mut fx,
        &prev.forwarding,
        prev.validation,
        PassView {
            prev_views: Some(&views),
            held_pass: true,
            view: Some(0),
        },
        false,
    );
    assert_eq!(
        batch.session_creates, 0,
        "a held pass must not install a session"
    );
    assert_eq!(fx.sessions.len(), 0);
    assert_eq!(
        fx.binding
            .live
            .config_gen_mismatches
            .load(Ordering::Relaxed),
        1,
        "dropped as the generation mismatch it is"
    );
    assert_eq!(
        fx.binding
            .live
            .generation_held_misses
            .load(Ordering::Relaxed),
        1,
        "witnessed as a held miss"
    );
    assert_eq!(fx.binding.scratch.scratch_recycle.len(), 1, "and recycled");
}

/// Seat W: the flow cache keeps one entry per key and a lookup with other
/// generations evicts it. In the batch that straddles a publish, the flow's
/// current-stamped packet re-seeds the entry under the current view before
/// the parked packet's held pass runs. That held lookup must compare only:
/// it misses (and drops) without evicting the CURRENT entry, so the flow's
/// next current packet is still a cache hit. RED if the held lookup evicts.
#[test]
fn held_lookup_never_evicts_the_current_entry_18560() {
    let mut fx = udp_flow_fixture();
    let fwd = Arc::clone(&fx.forwarding);
    run_pass(&mut fx, &fwd, STAMPED, PassView::current(), true);
    run_pass(&mut fx, &fwd, STAMPED, PassView::current(), true);
    let views = views_with(STAMPED, &fwd, NEWER);
    let normal = PassView {
        prev_views: Some(&views),
        held_pass: false,
        view: None,
    };
    // A current-stamped packet of the same flow: evicts the 7/9 entry and
    // re-seeds the flow under 8/9 (two passes: resolve, then seed).
    let left_stamp = fx.meta;
    fx.meta.config_generation = NEWER.config_generation;
    run_pass(&mut fx, &fwd, NEWER, normal, true);
    run_pass(&mut fx, &fwd, NEWER, normal, true);
    let hits_before = fx.binding.flow.flow_cache.hits;
    run_pass(&mut fx, &fwd, NEWER, normal, true);
    assert_eq!(
        fx.binding.flow.flow_cache.hits,
        hits_before + 1,
        "premise: the flow hits its 8/9 entry"
    );
    // The parked 7/9 packet, then its held pass.
    fx.meta = left_stamp;
    run_pass(&mut fx, &fwd, NEWER, normal, true);
    assert_eq!(fx.binding.view_held.len(), 1, "premise: parked");
    let evictions_before = fx.binding.flow.flow_cache.evictions;
    let prev = views.get(0).expect("retained view");
    run_pass(
        &mut fx,
        &prev.forwarding,
        prev.validation,
        PassView {
            prev_views: Some(&views),
            held_pass: true,
            view: Some(0),
        },
        false,
    );
    assert_eq!(
        fx.binding
            .live
            .generation_held_misses
            .load(Ordering::Relaxed),
        1,
        "the held packet misses: its entry is gone"
    );
    assert_eq!(
        fx.binding.flow.flow_cache.evictions, evictions_before,
        "a held lookup must not evict the current entry"
    );
    assert!(
        !fx.binding.flow.flow_cache.held_compare_only,
        "the compare-only mode ends with the held pass"
    );
    // The flow's next current packet still hits.
    fx.meta.config_generation = NEWER.config_generation;
    let hits_before = fx.binding.flow.flow_cache.hits;
    let batch = run_pass(&mut fx, &fwd, NEWER, normal, true);
    assert_eq!(
        fx.binding.flow.flow_cache.hits,
        hits_before + 1,
        "the current entry survived the held lookup"
    );
    assert_eq!(
        batch.session_hits + batch.session_misses,
        0,
        "no slow-path trip for the current packet"
    );
}

/// BEHIND with no matching held view: the worker left 6/9 (not 7/9), so a
/// 7/9 stamp is older than the worker but matches no view it ever held. It is
/// dropped and counted BEHIND, never parked. RED if `find` matches anything
/// but the exact pair.
#[test]
fn behind_stamp_without_a_held_view_is_dropped_18560() {
    let mut fx = gre_fixture();
    let fwd = Arc::clone(&fx.forwarding);
    let older = ValidationState {
        config_generation: 6,
        ..STAMPED
    };
    let views = views_with(older, &fwd, NEWER);
    run_pass(
        &mut fx,
        &fwd,
        NEWER,
        PassView {
            prev_views: Some(&views),
            held_pass: false,
            view: None,
        },
        true,
    );
    assert!(
        fx.binding.view_held.is_empty(),
        "a stamp no held view carries must not be parked"
    );
    assert_eq!(
        fx.binding
            .live
            .config_gen_mismatches
            .load(Ordering::Relaxed),
        1
    );
    assert_eq!(
        fx.binding
            .live
            .generation_mismatch_behind
            .load(Ordering::Relaxed),
        1,
        "counted as BEHIND"
    );
    assert_eq!(
        fx.binding
            .live
            .generation_mismatch_ahead
            .load(Ordering::Relaxed),
        0
    );
    assert_eq!(fx.binding.scratch.scratch_recycle.len(), 1, "and recycled");
    assert!(fx.rx.try_recv().is_err(), "nothing delivered");
}

/// A held packet whose flow-cache entry was seeded under its own view, but
/// whose egress RG the CURRENT HA state has demoted, is dropped: the hit path
/// judges the entry against the live HA snapshot (`worker_ctx.ha_state`), not
/// the left view. So a held pass cannot forward for, or emit an HA session
/// delta about, a session the current state has demoted. The positive control
/// is `packet_stamped_with_left_view_is_processed_under_it_18560` (same flow,
/// live HA active: a held hit).
#[test]
fn held_hit_on_a_session_the_current_state_demoted_is_dropped_18560() {
    let mut fx = udp_flow_fixture();
    let fwd = Arc::clone(&fx.forwarding);
    run_pass(&mut fx, &fwd, STAMPED, PassView::current(), true);
    run_pass(&mut fx, &fwd, STAMPED, PassView::current(), true);
    assert!(
        txn_flow_cache_entries(&fx.binding) > 0,
        "premise: the flow cache was seeded under 7/9"
    );
    let views = views_with(STAMPED, &fwd, NEWER);
    run_pass(
        &mut fx,
        &fwd,
        NEWER,
        PassView {
            prev_views: Some(&views),
            held_pass: false,
            view: None,
        },
        true,
    );
    assert_eq!(fx.binding.view_held.len(), 1, "premise: parked");
    let _ = fx.sessions.drain_deltas(usize::MAX);
    let demoted: BTreeMap<i32, HAGroupRuntime> = txn_ha_state()
        .into_keys()
        .map(|rg| {
            (
                rg,
                HAGroupRuntime {
                    active: false,
                    watchdog_timestamp: 123,
                    lease: HAForwardingLease::Inactive,
                },
            )
        })
        .collect();
    let hits_before = fx.binding.flow.flow_cache.hits;
    let departed_before = fx.binding.flow.flow_cache.evictions_by_arm
        [crate::afxdp::flow_cache::FlowCacheEvictionArm::PostHitForwardCandidateEgressDeparted
            as usize];
    let prev = views.get(0).expect("retained view");
    let batch = run_pass_ha(
        &mut fx,
        &prev.forwarding,
        prev.validation,
        PassView {
            prev_views: Some(&views),
            held_pass: true,
            view: Some(0),
        },
        false,
        &demoted,
    );
    assert!(fx.binding.view_held.is_empty());
    // Seat W: a HIT-STAGE evicting arm (not a lookup fence) fired, i.e. the
    // entry reached the hit stage's decision revalidation, was superseded, and
    // fell through. In an ordinary pass that fall-through re-resolves on the
    // slow path; in a held pass it must end as a counted drop.
    assert_eq!(
        fx.binding.flow.flow_cache.evictions_by_arm
            [crate::afxdp::flow_cache::FlowCacheEvictionArm::PostHitForwardCandidateEgressDeparted
                as usize],
        departed_before + 1,
        "premise: the hit stage's egress-departed arm evicted the entry"
    );
    assert_eq!(
        fx.binding.flow.flow_cache.hits, hits_before,
        "a demoted session's entry must not serve the held packet"
    );
    assert_eq!(
        fx.binding.live.generation_held_hits.load(Ordering::Relaxed),
        0
    );
    assert_eq!(
        fx.binding
            .live
            .generation_held_misses
            .load(Ordering::Relaxed),
        1,
        "dropped as a held miss"
    );
    assert_eq!(
        batch.session_hits + batch.session_misses + batch.session_creates,
        0,
        "and never reaches the session slow path"
    );
    assert!(
        fx.sessions.drain_deltas(usize::MAX).is_empty(),
        "no HA session delta for a held packet the current state rejects"
    );
    assert_eq!(fx.binding.scratch.scratch_recycle.len(), 1, "and recycled");
}

/// poll_binding's batch shape (seat V): a held batch reads no RX (current
/// stamps would be judged against the left view and dropped) and takes no
/// injected packet, and it does not end the poll's batch loop.
#[test]
fn held_batch_shape_18560() {
    let held = BatchShape::for_binding(1, 64);
    assert_eq!(
        held,
        BatchShape {
            held_pass: true,
            available: 0,
            take_injected: false
        }
    );
    assert!(
        held.loop_continues(),
        "a held pass must not end the poll's batch loop"
    );
    let normal = BatchShape::for_binding(0, 64);
    assert_eq!(
        normal,
        BatchShape {
            held_pass: false,
            available: 64,
            take_injected: true
        }
    );
    assert!(normal.loop_continues());
    assert!(
        !BatchShape::for_binding(0, 0).loop_continues(),
        "an empty ring ends the loop"
    );
}

/// The worker loop's per-tick view step and its CoS-change clear.
#[test]
fn worker_loop_view_steps_18560() {
    let fwd = Arc::new(ForwardingState::default());
    let mut views = PrevViews::default();
    views.on_tick(STAMPED, &fwd, NEWER, NOW_NS);
    assert_eq!(
        views.find(7, 9, NOW_NS),
        Some(0),
        "an adoption must retain the view being left"
    );
    views.on_tick(NEWER, &fwd, NEWER, NOW_NS);
    assert!(
        !views.is_empty(),
        "a tick without adoption keeps live views"
    );
    views.on_tick(NEWER, &fwd, NEWER, NOW_NS + MATCHED_VIEW_GRACE_NS);
    assert!(
        views.is_empty(),
        "a tick past the deadline must release the view"
    );
    views.on_tick(STAMPED, &fwd, NEWER, NOW_NS);
    views.on_forwarding_swap(false);
    assert!(!views.is_empty());
    views.on_forwarding_swap(true);
    assert!(
        views.is_empty(),
        "a CoS change must clear the retained views"
    );
}

/// The production loops must call the helpers the two cells above pin.
#[test]
fn held_pass_wiring_is_present_18560() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/afxdp/worker");
    let loop_body = std::fs::read_to_string(root.join("loop_body/mod.rs")).expect("read loop body");
    assert_eq!(
        loop_body.matches("prev_views.on_tick(").count(),
        1,
        "worker loop must step the retained views every tick"
    );
    assert_eq!(
        loop_body
            .matches("prev_views.on_forwarding_swap(cos_changed)")
            .count(),
        1,
        "worker loop must clear views on a CoS change"
    );
    let lifecycle = std::fs::read_to_string(root.join("lifecycle.rs")).expect("read lifecycle");
    for needle in [
        "BatchShape::for_binding(binding.view_held.len(), available)",
        "let available = shape.available;",
        "if shape.take_injected { injected_packet.take() } else { None }",
        "if !shape.loop_continues() {",
    ] {
        assert_eq!(
            lifecycle.matches(needle).count(),
            1,
            "poll_binding must use `{needle}`"
        );
    }
}
