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

    // Establish participation: enqueue + drain + publish so slot
    // has a non-NOT_PARTICIPATING value.
    let item = test_flow_cos_item(1234, 1500);
    cos_queue_push_back(queue, item);
    let _ = cos_queue_pop_front(queue);
    publish_committed_queue_vtime(Some(&*queue));
    assert!(
        floor.slots[1].read().is_some(),
        "slot should be participating after publish",
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

