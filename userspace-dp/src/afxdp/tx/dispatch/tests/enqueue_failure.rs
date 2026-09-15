// `enqueue_pending_forwards` dispatch-behaviour tests: mirror clone accounting,
// the #1946 Prebuilt fabric-redirect fail-closed drop, the #2208 cp2 copy-path
// ingress-descriptor recycle/reinject trio, and the #4041 direct-TX
// tuple-mismatch single-recycle. Local fixtures `ForceFaultGuard` (resets the
// #2208/#4041 fault-injection thread-locals) and `cp2_copy_fallback_harness`.

use super::*;

#[test]
fn enqueue_pending_forwards_mirrors_live_frame_and_records_counter() {
    let mut bindings = vec![
        BindingWorker::new_for_mirror_test(0, 0, 11, 0),
        BindingWorker::new_for_mirror_test(1, 0, 22, 0),
        BindingWorker::new_for_mirror_test(2, 0, 33, 0),
    ];
    let original_frame = build_ipv4_test_packet(0);
    unsafe {
        bindings[0]
            .umem
            .area()
            .slice_mut_unchecked(0, original_frame.len())
    }
    .expect("ingress frame")
    .copy_from_slice(&original_frame);

    let mut forwarding = test_forwarding_with_egress_mtu(1500);
    forwarding.mirror_configs.insert(
        11,
        MirrorRuntimeConfig {
            output_ifindex: 33,
            rate: 0,
        },
    );
    let lookup = WorkerBindingLookup::from_bindings(&bindings);
    let mirror_targets = MirrorTargetMap::default();
    let mut pending = vec![test_live_forward_request_for_frame(
        original_frame.len(),
        test_forwarding_decision_to_bound_ifindex(22),
    )];
    let mut post_recycles = Vec::new();
    let ingress_ident = bindings[0].identity();
    let ingress_live = &*bindings[0].live as *const BindingLiveState;
    let local_tunnel_deliveries: Arc<ArcSwap<BTreeMap<i32, LocalTunnelDelivery>>> =
        Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let recent_exceptions = Arc::new(Mutex::new(ExceptionEventRing::new()));
    let worker_commands_by_id: BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>> = BTreeMap::new();
    let mut dbg = DebugPollCounters::default();
    let (left, rest) = bindings.split_at_mut(0);
    let (ingress, right) = rest.split_first_mut().expect("ingress binding");

    enqueue_pending_forwards(
        left,
        0,
        ingress,
        right,
        &lookup,
        &mirror_targets,
        &mut pending,
        &mut post_recycles,
        1,
        &forwarding,
        &ingress_ident,
        unsafe { &*ingress_live },
        None,
        &local_tunnel_deliveries,
        &recent_exceptions,
        &mut dbg,
        &mut BatchCounters::default(),
        0,
        &worker_commands_by_id,
    );

    assert_eq!(bindings[0].live.mirrored_packets.load(Ordering::Relaxed), 1);
    assert_eq!(
        bindings[0].live.mirrored_bytes.load(Ordering::Relaxed),
        original_frame.len() as u64
    );
    let mirror_req = bindings[2]
        .tx_pipeline
        .pending_tx_prepared
        .front()
        .expect("mirror prepared request");
    assert!(mirror_req.mirror_clone);
    assert_eq!(mirror_req.egress_ifindex, 33);
    assert_eq!(
        bindings[2]
            .umem
            .area()
            .slice(mirror_req.offset as usize, mirror_req.len as usize)
            .expect("mirrored frame"),
        original_frame.as_slice(),
    );
    let forwarded_req = bindings[1]
        .tx_pipeline
        .pending_tx_prepared
        .front()
        .expect("forwarded prepared request");
    assert!(!forwarded_req.mirror_clone);
}

/// #1946: a Prebuilt FabricRedirect frame (e.g. an embedded-ICMP
/// NAT-reversed error whose resolution turned into a fabric redirect)
/// that is unsendable to the peer because the fabric parent has no XSK
/// binding must be dropped fail-closed AND counted on
/// `fabric_redirect_unsendable_drops` — not silently recycled. Drives the
/// Prebuilt no-binding arm of `enqueue_pending_forwards`.
#[test]
fn enqueue_pending_forwards_counts_prebuilt_fabric_redirect_no_binding() {
    let mut bindings = vec![BindingWorker::new_for_mirror_test(0, 0, 11, 0)];
    let mut forwarding = test_forwarding_with_egress_mtu(1500);
    forwarding.fabrics.clear();
    let lookup = WorkerBindingLookup::from_bindings(&bindings);
    let mirror_targets = MirrorTargetMap::default();

    // Target ifindex 4242 has no binding in `lookup`, so
    // resolve_pending_forward_target_binding returns None.
    let mut decision = test_forwarding_decision_to_bound_ifindex(4242);
    decision.resolution.disposition = ForwardingDisposition::FabricRedirect;
    let mut request = test_live_forward_request_for_frame(64, decision);
    request.frame = PendingForwardFrame::Prebuilt(vec![0u8; 64]);
    let mut pending = vec![request];

    let mut post_recycles = Vec::new();
    let ingress_ident = bindings[0].identity();
    let ingress_live = &*bindings[0].live as *const BindingLiveState;
    let local_tunnel_deliveries: Arc<ArcSwap<BTreeMap<i32, LocalTunnelDelivery>>> =
        Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let recent_exceptions = Arc::new(Mutex::new(ExceptionEventRing::new()));
    let worker_commands_by_id: BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>> = BTreeMap::new();
    let mut dbg = DebugPollCounters::default();
    let (left, rest) = bindings.split_at_mut(0);
    let (ingress, right) = rest.split_first_mut().expect("ingress binding");

    enqueue_pending_forwards(
        left,
        0,
        ingress,
        right,
        &lookup,
        &mirror_targets,
        &mut pending,
        &mut post_recycles,
        1,
        &forwarding,
        &ingress_ident,
        unsafe { &*ingress_live },
        None,
        &local_tunnel_deliveries,
        &recent_exceptions,
        &mut dbg,
        &mut BatchCounters::default(),
        0,
        &worker_commands_by_id,
    );

    assert_eq!(
        bindings[0]
            .live
            .fabric_redirect_unsendable_drops
            .load(Ordering::Relaxed),
        1
    );
    let reasons: Vec<String> = recent_exceptions
        .lock()
        .expect("exceptions")
        .iter()
        .map(|entry| entry.reason().to_string())
        .collect();
    assert_eq!(reasons, vec!["fabric_redirect_no_binding"]);
}

// ---------------------------------------------------------------------------
// #2208: the dispatch copy paths must recycle the ingress UMEM descriptor on
// EVERY exit. Four bare `continue;` statements (cp1/cp2 oversized + cp1/cp2
// enqueue-failure) jumped to the next loop iteration before the finalizer,
// permanently leaking the ingress descriptor (it never reached the fill ring)
// and — for the enqueue-failure sites — also skipping the slow-path reinject
// the `build_failed=true; fallback_to_slow_path=true` flags requested.
//
// These tests drive `enqueue_pending_forwards` through the cp2 copy fallback
// (target on a separate UMEM with an empty free_tx_frames pool forces the
// NoFreeTxFrame → Vec-copy branch) and assert:
//   (a) the ingress descriptor IS returned to circulation exactly once
//       (fill-ring pending + pending_fill_frames == 1, never 0 or 2);
//   (b) the enqueue-failure path runs handle_forward_build_failure
//       (dbg.build_fail bumped) AND its slow-path reinject
//       (slow_path_drops bumped, since the test passes slow_path=None so the
//        reinject lands on `slow_path_unavailable`);
//   (c) the oversized path recycles but does NOT reinject (the frame is
//       undeliverable) — build_fail bumped, slow_path_drops untouched.
//
// Against the pre-fix bare `continue;` (a) is 0 (leak) and (b)/(c) never fire.

/// RAII guard that resets the #2208 fault-injection thread-locals so a
/// panicking assertion cannot leak state into the next test on the same
/// thread.
struct ForceFaultGuard;
impl Drop for ForceFaultGuard {
    fn drop(&mut self) {
        super::cos::FORCE_ENQUEUE_ERR.with(|c| c.set(false));
        super::FORCE_OVERSIZED.with(|c| c.set(false));
        // #4041: reset the direct-TX tuple-mismatch injection so a panicking
        // assertion cannot leak it into the next test on the same thread.
        super::FORCE_TUPLE_MISMATCH.with(|c| c.set(false));
    }
}

/// Build a two-binding harness (ingress slot 0 / ifindex 11, egress slot 1 /
/// ifindex 22) with a valid IPv4 frame in the ingress UMEM at offset 0 and the
/// egress binding's `free_tx_frames` drained so dispatch is forced down the
/// cp2 Vec-copy fallback. Returns everything `enqueue_pending_forwards` needs.
fn cp2_copy_fallback_harness() -> (Vec<BindingWorker>, Vec<u8>) {
    let mut bindings = vec![
        BindingWorker::new_for_mirror_test(0, 0, 11, 0),
        BindingWorker::new_for_mirror_test(1, 0, 22, 0),
    ];
    let original_frame = build_ipv4_test_packet(0);
    unsafe {
        bindings[0]
            .umem
            .area()
            .slice_mut_unchecked(0, original_frame.len())
    }
    .expect("ingress frame")
    .copy_from_slice(&original_frame);
    // Drain the egress free-TX pool: with no direct-TX frame available the
    // dispatcher falls back to the Vec copy path (cp2), which is where the
    // enqueue/oversized #2208 sites live.
    bindings[1].tx_pipeline.free_tx_frames.clear();
    (bindings, original_frame)
}

#[test]
fn enqueue_failure_recycles_ingress_descriptor_and_reinjects_slow_path() {
    let _guard = ForceFaultGuard;
    let (mut bindings, original_frame) = cp2_copy_fallback_harness();
    let forwarding = test_forwarding_with_egress_mtu(1500);
    let lookup = WorkerBindingLookup::from_bindings(&bindings);
    let mirror_targets = MirrorTargetMap::default();
    let mut pending = vec![test_live_forward_request_for_frame(
        original_frame.len(),
        test_forwarding_decision_to_bound_ifindex(22),
    )];
    let mut post_recycles = Vec::new();
    let ingress_ident = bindings[0].identity();
    let ingress_live = &*bindings[0].live as *const BindingLiveState;
    let local_tunnel_deliveries: Arc<ArcSwap<BTreeMap<i32, LocalTunnelDelivery>>> =
        Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let recent_exceptions = Arc::new(Mutex::new(ExceptionEventRing::new()));
    let worker_commands_by_id: BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>> = BTreeMap::new();
    let mut dbg = DebugPollCounters::default();

    // Force the cp2 enqueue to fail (owner queue full / TX congestion).
    super::cos::FORCE_ENQUEUE_ERR.with(|c| c.set(true));

    let (left, rest) = bindings.split_at_mut(0);
    let (ingress, right) = rest.split_first_mut().expect("ingress binding");
    enqueue_pending_forwards(
        left,
        0,
        ingress,
        right,
        &lookup,
        &mirror_targets,
        &mut pending,
        &mut post_recycles,
        1,
        &forwarding,
        &ingress_ident,
        unsafe { &*ingress_live },
        None, // slow_path: None → reinject lands on slow_path_unavailable
        &local_tunnel_deliveries,
        &recent_exceptions,
        &mut dbg,
        &mut BatchCounters::default(),
        0,
        &worker_commands_by_id,
    );

    // (a) ingress descriptor recycled exactly once — the pre-fix `continue;`
    // leaked it (would be 0).
    assert_eq!(
        ingress_recycled_count(&bindings[0]),
        1,
        "ingress descriptor must be recycled exactly once on enqueue failure"
    );
    // (b) handle_forward_build_failure ran (build_fail) AND it reinjected to
    // the slow path (slow_path_drops, since slow_path=None). The pre-fix
    // `continue;` skipped both even though it set the build-failure flags.
    assert_eq!(dbg.build_fail, 1, "build-failure handler must run");
    assert_eq!(
        bindings[0].live.slow_path_drops.load(Ordering::Relaxed),
        1,
        "fallback_to_slow_path must reach the slow-path reinject"
    );
    // No successful TX was counted.
    assert_eq!(dbg.enqueue_ok, 0, "no TX enqueue succeeded");
    let reasons: Vec<String> = recent_exceptions
        .lock()
        .expect("exceptions")
        .iter()
        .map(|e| e.reason().to_string())
        .collect();
    assert!(
        reasons.iter().any(|r| r == "forward_build_failed"),
        "build-failure exception recorded: {reasons:?}"
    );
    assert!(
        reasons.iter().any(|r| r == "slow_path_unavailable"),
        "slow-path reinject attempted (unavailable here): {reasons:?}"
    );
}

#[test]
fn oversized_forward_frame_recycles_ingress_descriptor_without_reinject() {
    let _guard = ForceFaultGuard;
    let (mut bindings, original_frame) = cp2_copy_fallback_harness();
    let forwarding = test_forwarding_with_egress_mtu(1500);
    let lookup = WorkerBindingLookup::from_bindings(&bindings);
    let mirror_targets = MirrorTargetMap::default();
    let mut pending = vec![test_live_forward_request_for_frame(
        original_frame.len(),
        test_forwarding_decision_to_bound_ifindex(22),
    )];
    let mut post_recycles = Vec::new();
    let ingress_ident = bindings[0].identity();
    let ingress_live = &*bindings[0].live as *const BindingLiveState;
    let local_tunnel_deliveries: Arc<ArcSwap<BTreeMap<i32, LocalTunnelDelivery>>> =
        Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let recent_exceptions = Arc::new(Mutex::new(ExceptionEventRing::new()));
    let worker_commands_by_id: BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>> = BTreeMap::new();
    let mut dbg = DebugPollCounters::default();

    // Force the built cp2 frame to be treated as oversized (undeliverable).
    super::FORCE_OVERSIZED.with(|c| c.set(true));

    let (left, rest) = bindings.split_at_mut(0);
    let (ingress, right) = rest.split_first_mut().expect("ingress binding");
    enqueue_pending_forwards(
        left,
        0,
        ingress,
        right,
        &lookup,
        &mirror_targets,
        &mut pending,
        &mut post_recycles,
        1,
        &forwarding,
        &ingress_ident,
        unsafe { &*ingress_live },
        None,
        &local_tunnel_deliveries,
        &recent_exceptions,
        &mut dbg,
        &mut BatchCounters::default(),
        0,
        &worker_commands_by_id,
    );

    // (a) recycled exactly once — the pre-fix `continue;` leaked it.
    assert_eq!(
        ingress_recycled_count(&bindings[0]),
        1,
        "ingress descriptor must be recycled exactly once on oversized frame"
    );
    // (c) build-failure handler ran but did NOT reinject — an oversized frame
    // is undeliverable, so slow_path_drops stays 0.
    assert_eq!(dbg.build_fail, 1, "build-failure handler must run");
    assert_eq!(
        bindings[0].live.slow_path_drops.load(Ordering::Relaxed),
        0,
        "oversized frame must NOT be reinjected to the slow path"
    );
    assert_eq!(dbg.enqueue_ok, 0, "no TX enqueue succeeded");
    let reasons: Vec<String> = recent_exceptions
        .lock()
        .expect("exceptions")
        .iter()
        .map(|e| e.reason().to_string())
        .collect();
    assert!(
        reasons.iter().any(|r| r == "oversized_forward_frame"),
        "oversized exception recorded: {reasons:?}"
    );
    assert!(
        !reasons.iter().any(|r| r == "slow_path_unavailable"),
        "no slow-path reinject for an oversized frame: {reasons:?}"
    );
}

#[test]
fn enqueue_failure_conserves_free_frames_across_many_forwards() {
    // Descriptor-conservation check: under sustained enqueue failure (TX
    // congestion) every ingress descriptor must return to circulation. The
    // pre-fix `continue;` leaked one per failed forward → pool exhaustion.
    let _guard = ForceFaultGuard;
    let mut bindings = vec![
        BindingWorker::new_for_mirror_test(0, 0, 11, 0),
        BindingWorker::new_for_mirror_test(1, 0, 22, 0),
    ];
    let original_frame = build_ipv4_test_packet(0);
    // Lay the same frame down at N distinct ingress UMEM offsets and drive N
    // requests, each referencing its own descriptor.
    const N: usize = 16;
    let mut pending = Vec::with_capacity(N);
    for i in 0..N {
        let offset = (i as u64) << super::UMEM_FRAME_SHIFT;
        unsafe {
            bindings[0]
                .umem
                .area()
                .slice_mut_unchecked(offset as usize, original_frame.len())
        }
        .expect("ingress frame")
        .copy_from_slice(&original_frame);
        let mut req = test_live_forward_request_for_frame(
            original_frame.len(),
            test_forwarding_decision_to_bound_ifindex(22),
        );
        req.desc.addr = offset;
        pending.push(req);
    }
    bindings[1].tx_pipeline.free_tx_frames.clear();

    let forwarding = test_forwarding_with_egress_mtu(1500);
    let lookup = WorkerBindingLookup::from_bindings(&bindings);
    let mirror_targets = MirrorTargetMap::default();
    let mut post_recycles = Vec::new();
    let ingress_ident = bindings[0].identity();
    let ingress_live = &*bindings[0].live as *const BindingLiveState;
    let local_tunnel_deliveries: Arc<ArcSwap<BTreeMap<i32, LocalTunnelDelivery>>> =
        Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let recent_exceptions = Arc::new(Mutex::new(ExceptionEventRing::new()));
    let worker_commands_by_id: BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>> = BTreeMap::new();
    let mut dbg = DebugPollCounters::default();

    super::cos::FORCE_ENQUEUE_ERR.with(|c| c.set(true));

    let (left, rest) = bindings.split_at_mut(0);
    let (ingress, right) = rest.split_first_mut().expect("ingress binding");
    enqueue_pending_forwards(
        left,
        0,
        ingress,
        right,
        &lookup,
        &mirror_targets,
        &mut pending,
        &mut post_recycles,
        1,
        &forwarding,
        &ingress_ident,
        unsafe { &*ingress_live },
        None,
        &local_tunnel_deliveries,
        &recent_exceptions,
        &mut dbg,
        &mut BatchCounters::default(),
        0,
        &worker_commands_by_id,
    );

    assert_eq!(
        ingress_recycled_count(&bindings[0]),
        N,
        "every ingress descriptor must be recycled exactly once — no leak, \
         no double-recycle"
    );
    assert_eq!(
        dbg.build_fail as usize, N,
        "every forward hit build failure"
    );
    assert_eq!(
        bindings[0].live.slow_path_drops.load(Ordering::Relaxed) as usize,
        N,
        "every failed forward reinjected to the slow path"
    );
}

// #4041: the direct-TX diagnostic tuple-mismatch branch (debug-log build) must
// recycle the frame's `tx_offset` onto `free_tx_frames` EXACTLY once. Before
// the fix the mismatch branch pushed the offset AND the shared `if build_failed`
// handler pushed it again — the same UMEM offset landed on the free-list twice,
// so it was handed out for two later TX descriptors that then aliased one
// in-flight frame (on-wire corruption / double-free on the debug-log build).
//
// A correct builder never trips the mismatch (call sites compare against
// the POST-NAT expectation via `post_nat_expected_ports` since #9782 moved
// enforcement pre-NAT), so the branch is reached via the
// `#[cfg(test)] FORCE_TUPLE_MISMATCH` hook. The branch itself only exists under
// the `debug-log` feature (`if cfg!(feature = "debug-log")`), so the
// single-recycle assertions are gated on that feature; the non-debug-log build
// exercises the normal direct-TX forward (offset consumed by the TX pipeline).
//
// RED-on-revert (run with `--features debug-log`): reinstating the duplicate
// `push_front` makes the popped offset appear twice in `free_tx_frames` and the
// pool length grow by one — both assertions below fail.
#[test]
fn direct_tx_tuple_mismatch_recycles_frame_exactly_once() {
    let _guard = ForceFaultGuard;
    // Two bindings on SEPARATE UMEMs so `can_rewrite_in_place` is false and
    // dispatch takes the cross-binding direct-TX path. Unlike the cp2 harness
    // the egress pool is left populated so a direct-TX frame is available.
    let mut bindings = vec![
        BindingWorker::new_for_mirror_test(0, 0, 11, 0),
        BindingWorker::new_for_mirror_test(1, 0, 22, 0),
    ];
    let original_frame = build_ipv4_test_packet(0);
    unsafe {
        bindings[0]
            .umem
            .area()
            .slice_mut_unchecked(0, original_frame.len())
    }
    .expect("ingress frame")
    .copy_from_slice(&original_frame);

    let egress_free_before = bindings[1].tx_pipeline.free_tx_frames.len();
    let front_offset = *bindings[1]
        .tx_pipeline
        .free_tx_frames
        .front()
        .expect("egress pool populated");

    let forwarding = test_forwarding_with_egress_mtu(1500);
    let lookup = WorkerBindingLookup::from_bindings(&bindings);
    let mirror_targets = MirrorTargetMap::default();
    let mut pending = vec![test_live_forward_request_for_frame(
        original_frame.len(),
        test_forwarding_decision_to_bound_ifindex(22),
    )];
    let mut post_recycles = Vec::new();
    let ingress_ident = bindings[0].identity();
    let ingress_live = &*bindings[0].live as *const BindingLiveState;
    let local_tunnel_deliveries: Arc<ArcSwap<BTreeMap<i32, LocalTunnelDelivery>>> =
        Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let recent_exceptions = Arc::new(Mutex::new(ExceptionEventRing::new()));
    let worker_commands_by_id: BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>> = BTreeMap::new();
    let mut dbg = DebugPollCounters::default();

    // Force the direct-TX tuple-mismatch diagnostic branch to fire.
    super::FORCE_TUPLE_MISMATCH.with(|c| c.set(true));

    let (left, rest) = bindings.split_at_mut(0);
    let (ingress, right) = rest.split_first_mut().expect("ingress binding");
    enqueue_pending_forwards(
        left,
        0,
        ingress,
        right,
        &lookup,
        &mirror_targets,
        &mut pending,
        &mut post_recycles,
        1,
        &forwarding,
        &ingress_ident,
        unsafe { &*ingress_live },
        None,
        &local_tunnel_deliveries,
        &recent_exceptions,
        &mut dbg,
        &mut BatchCounters::default(),
        0,
        &worker_commands_by_id,
    );

    let free = &bindings[1].tx_pipeline.free_tx_frames;
    // Regardless of build: the popped offset must never appear twice on the
    // free-list — a duplicate is the aliasing bug.
    let dup = free.iter().filter(|&&o| o == front_offset).count();
    assert!(
        dup <= 1,
        "#4041: tx_offset {front_offset} recycled {dup} times — a duplicate \
         free-list entry aliases an in-flight TX frame"
    );

    if cfg!(feature = "debug-log") {
        // The mismatch fired: the frame was dropped and its offset returned to
        // the pool exactly once, so the pool length is unchanged.
        assert_eq!(
            free.len(),
            egress_free_before,
            "#4041: a mismatch drop must recycle the offset exactly once \
             (pool conserved); a second push grows the pool by one"
        );
        assert_eq!(
            dup, 1,
            "the recycled offset must be present exactly once after a mismatch drop"
        );
        let reasons: Vec<String> = recent_exceptions
            .lock()
            .expect("exceptions")
            .iter()
            .map(|e| e.reason().to_string())
            .collect();
        assert!(
            reasons
                .iter()
                .any(|r| r.starts_with("forward_tuple_mismatch")),
            "the mismatch must still be recorded for operators: {reasons:?}"
        );
        assert_eq!(
            dbg.enqueue_ok, 0,
            "a dropped mismatch frame is not a successful TX"
        );
    } else {
        // Without the debug-log feature the mismatch branch is compiled out; the
        // direct-TX forward succeeds and the offset is consumed by the TX
        // pipeline (one fewer free frame), never duplicated.
        assert_eq!(
            free.len(),
            egress_free_before - 1,
            "the direct-TX forward consumes exactly one free frame"
        );
        assert_eq!(dbg.enqueue_ok, 1, "the direct-TX forward is enqueued");
    }
}
// #9782 F2a: a correctly PAT-translated direct-TX forward must NOT trip the
// debug-log tuple-mismatch diagnostic (which compares against the POST-NAT
// expectation) and must NOT be dropped. RED-on-revert: comparing against
// the pre-NAT tuple fires the mismatch on every PAT build and recycles the
// frame under --features debug-log.
#[test]
fn direct_tx_pat_translation_is_not_a_tuple_mismatch_9782() {
    let _guard = ForceFaultGuard;
    let mut bindings = vec![
        BindingWorker::new_for_mirror_test(0, 0, 11, 0),
        BindingWorker::new_for_mirror_test(1, 0, 22, 0),
    ];
    // Hand-rolled TCP frame (arrival tuple 45678 -> 5201).
    let mut frame = vec![0u8; 14 + 20 + 20];
    frame[12] = 0x08;
    frame[13] = 0x00;
    frame[14] = 0x45;
    frame[16] = 0x00;
    frame[17] = 40;
    frame[22] = 64;
    frame[23] = PROTO_TCP;
    frame[26..30].copy_from_slice(&[10, 0, 61, 102]);
    frame[30..34].copy_from_slice(&[172, 16, 80, 200]);
    frame[34..36].copy_from_slice(&45678u16.to_be_bytes());
    frame[36..38].copy_from_slice(&5201u16.to_be_bytes());
    frame[46] = 0x50;
    frame[47] = 0x10;
    unsafe {
        bindings[0]
            .umem
            .area()
            .slice_mut_unchecked(0, frame.len())
    }
    .expect("ingress frame")
    .copy_from_slice(&frame);

    let egress_free_before = bindings[1].tx_pipeline.free_tx_frames.len();
    let forwarding = test_forwarding_with_egress_mtu(1500);
    let lookup = WorkerBindingLookup::from_bindings(&bindings);
    let mirror_targets = MirrorTargetMap::default();
    let mut decision = test_forwarding_decision_to_bound_ifindex(22);
    decision.nat = NatDecision {
        rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 7))),
        rewrite_src_port: Some(30001),
        ..Default::default()
    };
    let mut req = test_live_forward_request_for_frame(frame.len(), decision);
    req.expected_ports = Some((45678, 5201));
    let mut pending = vec![req];
    let mut post_recycles = Vec::new();
    let ingress_ident = bindings[0].identity();
    let ingress_live = &*bindings[0].live as *const BindingLiveState;
    let local_tunnel_deliveries: Arc<ArcSwap<BTreeMap<i32, LocalTunnelDelivery>>> =
        Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let recent_exceptions = Arc::new(Mutex::new(ExceptionEventRing::new()));
    let worker_commands_by_id: BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>> = BTreeMap::new();
    let mut dbg = DebugPollCounters::default();

    let (left, rest) = bindings.split_at_mut(0);
    let (ingress, right) = rest.split_first_mut().expect("ingress binding");
    enqueue_pending_forwards(
        left,
        0,
        ingress,
        right,
        &lookup,
        &mirror_targets,
        &mut pending,
        &mut post_recycles,
        1,
        &forwarding,
        &ingress_ident,
        unsafe { &*ingress_live },
        None,
        &local_tunnel_deliveries,
        &recent_exceptions,
        &mut dbg,
        &mut BatchCounters::default(),
        0,
        &worker_commands_by_id,
    );

    let free = &bindings[1].tx_pipeline.free_tx_frames;
    assert_eq!(
        free.len(),
        egress_free_before - 1,
        "#9782: a correctly translated PAT forward consumes its TX frame"
    );
    assert_eq!(dbg.enqueue_ok, 1, "the PAT forward is enqueued");
    if cfg!(feature = "debug-log") {
        let reasons: Vec<String> = recent_exceptions
            .lock()
            .expect("exceptions")
            .iter()
            .map(|e| e.reason().to_string())
            .collect();
        assert!(
            !reasons.iter().any(|r| r.starts_with("forward_tuple_mismatch")),
            "#9782: no false mismatch on a correct PAT build: {reasons:?}"
        );
    }
}
