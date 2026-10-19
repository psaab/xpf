use super::*;

/// #940: demote_prepared_cos_queue_to_local must not publish to
/// V_min during drain_all. Reframed per Gemini review: assert slot
/// value before demote == slot value after demote completes the
/// internal save/restore but BEFORE the new explicit post-restore
/// publish call... well actually the publish happens at the end of
/// demote_prepared_cos_queue_to_local now, so we observe:
///
///   1. Pre-demote: slot at SOME_PRE_VTIME (set explicitly).
///   2. Build a queue with prepared items.
///   3. Run demote (which drains internally with no-snapshot
///      pops, advances queue_vtime by drained bytes,
///      converts items to Local, then RESTORES queue_vtime
///      from the saved value, then publishes).
///   4. Post-demote: slot at SOME_PRE_VTIME (== restored value
///      since demote saves+restores symmetrically).
///
/// The test cannot observe the transient drain-time queue_vtime
/// from a single thread; the assertion is "slot value at start ==
/// slot value at end" which proves no transient leaked.
#[test]
fn vmin_demote_no_drain_all_leak() {
    // demote_prepared_cos_queue_to_local takes &MmapArea and
    // operates on Prepared items. We need a real MmapArea and
    // a queue with Prepared items. Start with a small UMEM.
    let area = MmapArea::new(2 * 1024 * 1024).expect("mmap umem");

    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "iperf-b".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000 / 8,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: 4 * 1024 * 1024,
            dscp_rewrite: None,
            codel_target_ns: 0,
        }],
    );
    let queue = &mut root.queues[0];
    let floor = attach_test_vtime_floor(queue, 4, 0);
    // Set a non-zero "prior committed" vtime so we can detect
    // accidental publishes-of-zero from drain_all.
    test_flow_fair_state_mut(queue).queue_vtime = 7777;
    floor.slots[0].publish(7777);
    let pre_slot = floor.slots[0].read();
    assert_eq!(pre_slot, Some(7777), "fixture sanity");

    // Push a Prepared item.
    let prep = PreparedTxRequest {
        offset: 0,
        len: 1500,
        recycle: PreparedTxRecycle::FreeTxFrame,
        dscp_rewrite: None,
        mirror_clone: false,
        overlap_admissions: None,
        cos_queue_id: Some(0),
        flow_key: None,
        expected_ports: None,
        expected_addr_family: libc::AF_INET as u8,
        expected_protocol: PROTO_TCP,
        egress_ifindex: 80,
        enqueue_ns: 0,
    };
    cos_queue_push_back(queue, CoSPendingTxItem::Prepared(prep));

    let mut free_tx = VecDeque::new();
    let mut pending_fill = VecDeque::new();
    let _ok = demote_prepared_cos_queue_to_local(
        &area,
        &mut free_tx,
        &mut pending_fill,
        0,
        &mut root,
        Some(0),
        None,
    );

    // Re-borrow queue and floor (root was reborrowed by demote).
    let queue = &root.queues[0];
    let post_slot = queue
        .v_min
        .vtime_floor
        .as_ref()
        .and_then(|f| f.slots.get(0))
        .and_then(|s| s.read());

    // Slot at end MUST equal slot at start: demote saves+restores
    // queue_vtime (#926) and the new post-restore publish writes
    // the SAME (saved) value back. drain_all's internal vtime
    // inflation never reaches the slot because the pop-time
    // publish has been removed (#940).
    assert_eq!(
        post_slot, pre_slot,
        "demote must not leak drain_all vtime to V_min slot — \
         the saved+restored vtime must round-trip cleanly (#940)",
    );
}

/// #941 Work item A: when the worker's last active bucket on a
/// shared_exact queue empties, the V_min slot is vacated to
/// NOT_PARTICIPATING. Without vacate, the slot would hold the
/// stale-low queue_vtime — phantom-participating — and peers would
/// throttle against it indefinitely.
#[test]
fn vmin_vacate_on_bucket_empty() {
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "iperf-c".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000 / 8,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
            codel_target_ns: 0,
        }],
    );
    let queue = &mut root.queues[0];
    let floor = attach_test_vtime_floor(queue, 4, 1);

    // Establish participation while a bucket is active, then drain it.
    // Commit-boundary publish must not reintroduce an empty worker.
    let item = test_flow_cos_item(1234, 1500);
    cos_queue_push_back(queue, item);
    publish_committed_queue_vtime(Some(&*queue));
    assert!(
        floor.slots[1].read().is_some(),
        "active bucket should participate after publish",
    );
    let _ = cos_queue_pop_front(queue);
    assert!(
        floor.slots[1].read().is_none(),
        "draining the last bucket must vacate the slot",
    );

    // active_flow_buckets is now 0 because pop drained the only bucket.
    // Enqueue + dequeue another item with the SAME flow_key to retrigger
    // the bucket-empty vacate path. Must use account_cos_queue_flow_*
    // helpers explicitly — push_back/pop_front delegate to them but
    // we want to exercise the dequeue accounting that holds the
    // vacate hook.
    let key = test_session_key(1234, 5201);
    account_cos_queue_flow_enqueue(queue, Some(&key), 1500);
    // Now dequeue: should fire the bucket-empty path AND vacate.
    account_cos_queue_flow_dequeue(queue, Some(&key), 1500);
    assert_eq!(
        test_flow_fair_state(queue).active_flow_buckets,
        0,
        "bucket count drained to 0"
    );
    assert!(
        floor.slots[1].read().is_none(),
        "Work item A: slot must be vacated to NOT_PARTICIPATING when the last bucket empties",
    );
}

/// #941 Work item A: the vacate fires ONLY when active_flow_buckets
/// transitions to 0. If two flows hash to two buckets, dequeueing
/// the first bucket should NOT vacate (the second is still active).
#[test]
fn vmin_vacate_only_when_last_bucket_empties() {
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "iperf-c".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000 / 8,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
            codel_target_ns: 0,
        }],
    );
    let queue = &mut root.queues[0];
    let floor = attach_test_vtime_floor(queue, 4, 1);
    // Pick keys that map to different buckets — try several until
    // we find two with distinct hashes.
    let mut keys: Vec<SessionKey> = Vec::new();
    let mut buckets = std::collections::HashSet::new();
    for src in 1000u16..2000 {
        let k = test_session_key(src, 5201);
        let bkt = cos_flow_bucket_index(test_flow_fair_state(queue).flow_hash_seed, Some(&k));
        if buckets.insert(bkt) {
            keys.push(k);
            if keys.len() == 2 {
                break;
            }
        }
    }
    assert_eq!(keys.len(), 2, "need two distinct buckets");
    // Enqueue both flows; active_flow_buckets becomes 2.
    account_cos_queue_flow_enqueue(queue, Some(&keys[0]), 1500);
    account_cos_queue_flow_enqueue(queue, Some(&keys[1]), 1500);
    assert_eq!(test_flow_fair_state(queue).active_flow_buckets, 2);
    // Establish participation by publishing.
    publish_committed_queue_vtime(Some(&*queue));
    assert!(floor.slots[1].read().is_some());
    // Dequeue first flow's bucket. active_flow_buckets goes 2→1; no vacate.
    account_cos_queue_flow_dequeue(queue, Some(&keys[0]), 1500);
    assert_eq!(test_flow_fair_state(queue).active_flow_buckets, 1);
    assert!(
        floor.slots[1].read().is_some(),
        "vacate must NOT fire when other buckets are still active",
    );
    // Dequeue second flow's bucket. active_flow_buckets goes 1→0 → vacate.
    account_cos_queue_flow_dequeue(queue, Some(&keys[1]), 1500);
    assert_eq!(test_flow_fair_state(queue).active_flow_buckets, 0);
    assert!(
        floor.slots[1].read().is_none(),
        "vacate must fire when the last bucket empties",
    );
}
/// #13657 (D8-04): a post-settle publish after the last bucket
/// drained must NOT resurrect the slot. The pop-time vacate in
/// `account_cos_queue_flow_dequeue` emptied the slot during drain;
/// an unconditional `slot.publish(ff.queue_vtime)` at the commit
/// boundary would overwrite NOT_PARTICIPATING with the frozen
/// queue_vtime and leave this idle worker phantom-participating
/// in peers' V_min reduction. The commit-boundary publish must
/// re-vacate when `active_flow_buckets == 0`.
#[test]
fn vmin_publish_after_settle_keeps_vacated_slot_empty() {
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "iperf-c".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000 / 8,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
            codel_target_ns: 0,
        }],
    );
    let queue = &mut root.queues[0];
    let floor = attach_test_vtime_floor(queue, 4, 1);

    // Drain the only bucket (pop vacates the slot via #941 A), then
    // run the exact post-settle publish the service sites call.
    let item = test_flow_cos_item(1234, 1500);
    cos_queue_push_back(queue, item);
    let _ = cos_queue_pop_front(queue);
    assert_eq!(test_flow_fair_state(queue).active_flow_buckets, 0);
    // Give queue_vtime a non-zero frozen value so a clobbering
    // publish is observable as Some(stale), not Some(0).
    test_flow_fair_state_mut(queue).queue_vtime = 42_424;
    publish_committed_queue_vtime(Some(&*queue));
    assert!(
        floor.slots[1].read().is_none(),
        "publish after drain-to-empty must keep slot NOT_PARTICIPATING (D8-04)",
    );

    // Positive control: with an active bucket, the same publish
    // must broadcast the committed queue_vtime (no over-vacate on
    // the non-empty path).
    account_cos_queue_flow_enqueue(queue, Some(&test_session_key(1234, 5201)), 1500);
    assert_eq!(test_flow_fair_state(queue).active_flow_buckets, 1);
    publish_committed_queue_vtime(Some(&*queue));
    assert_eq!(
        floor.slots[1].read(),
        Some(42_424),
        "publish with active buckets must broadcast queue_vtime",
    );
}

fn b14_exact_queue() -> CoSQueueConfig {
    CoSQueueConfig {
        queue_id: 0,
        forwarding_class: "iperf-c".into(),
        priority: 5,
        transmit_rate_bytes: 10_000_000_000 / 8,
        guarantee_enabled: true,
        exact: true,
        surplus_sharing: false,
        equal_flow_enforcement: false,
        equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
        surplus_weight: 1,
        buffer_bytes: 4 * 1024 * 1024,
        dscp_rewrite: None,
        codel_target_ns: 0,
    }
}

/// #15154 (B14-01): a worker that vacated (last bucket drained) and then
/// re-enters must reseed its frozen `queue_vtime` to the peer frontier
/// BEFORE the bucket anchor is computed. Without the reseed the re-entrant
/// keeps its stale-low vtime, and its first post-settle publish becomes
/// the cross-worker V_min, trapping busy peers in the throttle duty cycle.
///
/// RED pre-fix: re-entrant `queue_vtime` stays at the frozen value, not
/// `FRONTIER`, and the survivor gate throttles.
#[test]
fn v42_b14_vacate_reentry_traps_survivor() {
    const FRONTIER: u64 = 100 * 1024 * 1024 * 1024;
    const FROZEN: u64 = 42_424;
    let floor = Arc::new(SharedCoSQueueVtimeFloor::new(2));
    floor.slots[0].publish(FRONTIER);
    let mut root = test_cos_runtime_with_queues(10_000_000_000 / 8, vec![b14_exact_queue()]);
    let queue = &mut root.queues[0];
    queue.v_min.vtime_floor = Some(Arc::clone(&floor));
    queue.v_min.worker_id = 1;
    queue.config.shared_exact = true;
    enable_test_flow_fair(queue);
    assert!(queue.shared_exact());
    assert!(
        floor.slots[1].read().is_none(),
        "vacated slot must be NOT_PARTICIPATING"
    );
    test_flow_fair_state_mut(queue).queue_vtime = FROZEN;
    assert_eq!(test_flow_fair_state(queue).active_flow_buckets, 0);
    account_cos_queue_flow_enqueue(queue, Some(&test_session_key(1234, 5201)), 1500);
    assert_eq!(
        test_flow_fair_state(queue).queue_vtime,
        FRONTIER,
        "B14-01: re-entry after vacate must reseed queue_vtime to the peer frontier",
    );
    assert!(
        floor.slots[1].read().is_none(),
        "re-entry reseed must not publish on enqueue",
    );
    publish_committed_queue_vtime(Some(&*queue));
    assert_eq!(floor.slots[1].read(), Some(FRONTIER));
    let mut survivor = test_cos_runtime_with_queues(10_000_000_000 / 8, vec![b14_exact_queue()]);
    {
        let q = &mut survivor.queues[0];
        enable_test_flow_fair(q);
        q.v_min.vtime_floor = Some(Arc::clone(&floor));
        q.v_min.worker_id = 0;
        q.config.shared_exact = true;
        test_flow_fair_state_mut(q).queue_vtime = FRONTIER;
    }
    assert!(
        cos_queue_v_min_continue(&mut survivor.queues[0], 1),
        "B14-01: busy survivor must not be trapped by a vacate re-entrant",
    );
    assert_eq!(survivor.queues[0].v_min.v_min_throttles_scratch, 0);
}

/// #15154 (B14-01) control: a re-entrant already ahead of every peer
/// (`queue_vtime > frontier`) must keep its own vtime (max semantics),
/// and a re-entry with no participating peer keeps the frozen value.
#[test]
fn v42_b14_vacate_reentry_max_and_no_peer_controls() {
    const FRONTIER: u64 = 100 * 1024 * 1024 * 1024;
    let floor = Arc::new(SharedCoSQueueVtimeFloor::new(2));
    floor.slots[0].publish(FRONTIER);
    let mut root = test_cos_runtime_with_queues(10_000_000_000 / 8, vec![b14_exact_queue()]);
    let queue = &mut root.queues[0];
    queue.v_min.vtime_floor = Some(Arc::clone(&floor));
    queue.v_min.worker_id = 1;
    queue.config.shared_exact = true;
    enable_test_flow_fair(queue);
    test_flow_fair_state_mut(queue).queue_vtime = FRONTIER + 777;
    account_cos_queue_flow_enqueue(queue, Some(&test_session_key(1234, 5201)), 1500);
    assert_eq!(
        test_flow_fair_state(queue).queue_vtime,
        FRONTIER + 777,
        "reseed is a max: an ahead re-entrant must not be pulled down",
    );
    let cold_floor = Arc::new(SharedCoSQueueVtimeFloor::new(2));
    let mut cold = test_cos_runtime_with_queues(10_000_000_000 / 8, vec![b14_exact_queue()]);
    let cq = &mut cold.queues[0];
    cq.v_min.vtime_floor = Some(Arc::clone(&cold_floor));
    cq.v_min.worker_id = 1;
    cq.config.shared_exact = true;
    enable_test_flow_fair(cq);
    test_flow_fair_state_mut(cq).queue_vtime = 42_424;
    account_cos_queue_flow_enqueue(cq, Some(&test_session_key(1234, 5201)), 1500);
    assert_eq!(
        test_flow_fair_state(cq).queue_vtime,
        42_424,
        "no participating peer -> no reseed (cold / sole-worker re-entry)",
    );
}
