// #9365: the exact-demand queue mask past queue index 64.
//
// The mask reserves best-effort surplus for exact guarantee queues that are
// serviceable (#hb166 T-6(b)). It is keyed by the index into `root.queues`,
// which counts ALL of the interface's queues. As a `u64` it could not name
// index 64: a serviceable queue there saturated the mask, and the consumers
// counted every exact queue at index >= 64, so idle exact classes kept their
// rate reserved and a pure best-effort class lost its only service path.
//
// The issue's fixture: one interface shaped at 1 Gbit/s with 65 queues.
// Indices 0..=62 are residual-only best-effort, 63 is a 100 Mbit/s exact
// guarantee and 64 a 900 Mbit/s exact guarantee. There are only TWO exact
// queues, so the `builders.rs` >64-exact-queue warning never fires.

use super::*;
use crate::afxdp::cos::queue_ops::cos_exact_queue_serviceable;

const SHAPING_BYTES: u64 = 1_000_000_000 / 8;
const EXACT_63_BYTES: u64 = 100_000_000 / 8;
const EXACT_64_BYTES: u64 = 900_000_000 / 8;

fn demand_queue(queue_id: u8, transmit_rate_bytes: u64, exact: bool) -> CoSQueueConfig {
    CoSQueueConfig {
        queue_id,
        forwarding_class: format!("fc-{queue_id}").into(),
        priority: 5,
        transmit_rate_bytes,
        guarantee_enabled: exact,
        exact,
        surplus_sharing: false,
        equal_flow_enforcement: false,
        equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
        surplus_weight: 1,
        buffer_bytes: COS_MIN_BURST_BYTES,
        dscp_rewrite: None,
        codel_target_ns: 0,
    }
}

fn sixty_five_queue_root() -> CoSInterfaceRuntime {
    let mut queues: Vec<CoSQueueConfig> = (0..=62u8)
        .map(|queue_id| demand_queue(queue_id, SHAPING_BYTES, false))
        .collect();
    queues.push(demand_queue(63, EXACT_63_BYTES, true));
    queues.push(demand_queue(64, EXACT_64_BYTES, true));
    let mut root = test_cos_runtime_with_queues(SHAPING_BYTES, queues);
    root.tokens = 100_000;
    root
}

/// Runnable, non-empty, and holding tokens for its head: what
/// `cos_exact_queue_serviceable` requires.
fn make_serviceable(root: &mut CoSInterfaceRuntime, queue_idx: usize) {
    let queue = &mut root.queues[queue_idx];
    queue.hot.runnable = true;
    queue.hot.tokens = 10_000;
    queue.hot.items.push_back(test_cos_item(1500));
    queue.hot.queued_bytes = 1500;
}

#[test]
fn local_demand_mask_names_each_exact_queue_past_index_63() {
    for (serviceable, idle, want_rate) in
        [(64usize, 63usize, EXACT_64_BYTES), (63, 64, EXACT_63_BYTES)]
    {
        let mut root = sixty_five_queue_root();
        make_serviceable(&mut root, serviceable);

        let mask = serviceable_exact_demand_mask(&root);
        assert!(
            mask.counts(serviceable),
            "serviceable exact queue {serviceable} must count as demand"
        );
        assert!(
            !mask.counts(idle),
            "idle exact queue {idle} must not reserve best-effort surplus"
        );

        let rate = exact_demand_rate_bytes_for_mask(&root, mask);
        assert_eq!(
            rate, want_rate,
            "the reservation must be the backlogged exact queue's rate, not every exact queue's"
        );
        assert_eq!(
            residual_rate_and_burst(&root, rate).map(|(residual, _)| residual),
            Some(SHAPING_BYTES - want_rate),
            "best-effort residual must be shaping minus the backlogged exact rate"
        );
    }
}

#[test]
fn published_peer_demand_mask_names_each_exact_queue_past_index_63() {
    for (serviceable, want_rate) in [(64usize, EXACT_64_BYTES), (63, EXACT_63_BYTES)] {
        let mut peer_root = sixty_five_queue_root();
        make_serviceable(&mut peer_root, serviceable);
        let backlog = SharedCoSExactBacklog::new(1);
        backlog.publish_with_serviceable(1, 1500, 1500, serviceable_exact_demand_mask(&peer_root));

        // The local worker has no exact backlog of its own; all demand is the peer's.
        let local_root = sixty_five_queue_root();
        let mask =
            serviceable_exact_demand_mask(&local_root) | backlog.peer_exact_demand_queue_mask(0);
        let rate = exact_demand_rate_bytes_for_mask(&local_root, mask);
        assert_eq!(
            rate, want_rate,
            "through the published mask the reservation must still be only the backlogged exact queue's rate"
        );
        assert_eq!(
            residual_rate_and_burst(&local_root, rate).map(|(residual, _)| residual),
            Some(SHAPING_BYTES - want_rate)
        );
    }
}

#[test]
fn best_effort_surplus_drains_while_only_a_high_index_exact_queue_is_backlogged() {
    let mut root = sixty_five_queue_root();
    make_serviceable(&mut root, 64);
    // Best-effort queue 0 has work and no guarantee, so the surplus pass is its
    // only service path.
    root.queues[0].hot.runnable = true;
    root.queues[0].hot.items.push_back(test_cos_item(1500));
    root.queues[0].hot.queued_bytes = 1500;
    root.nonempty_queues = 2;
    root.runnable_queues = 2;
    let fast_interfaces = test_cos_fast_interfaces(
        42,
        42,
        0,
        (0..=64u8)
            .map(|queue_id| (queue_id, test_queue_fast_path(false, 0, None, None)))
            .collect(),
        None,
        None,
    );
    let fast_path = fast_interfaces.get(&42).expect("test fast path").clone();
    let mut binding = BindingWorker::new_for_cos_drain_test(0, 0, 42, root, fast_path);

    let batch = build_nonexact_cos_batch(&mut binding, 42, 2_000_000).expect(
        "a 100 Mbit/s residual must let best-effort drain; a saturated mask reserved the whole shaping rate",
    );
    assert!(matches!(
        batch,
        CoSBatch::Local {
            queue_idx: 0,
            phase: CoSServicePhase::Surplus,
            ..
        }
    ));
}

#[test]
fn exact_demand_mask_has_a_bit_for_every_u8_queue_id() {
    let mut mask = ExactDemandQueueMask::EMPTY;
    for queue_idx in [0usize, 63, 64, 127, 128, 255] {
        assert!(!mask.counts(queue_idx));
        mask = mask.with_queue(queue_idx);
        assert!(
            mask.counts(queue_idx),
            "index {queue_idx} must have its own bit"
        );
    }
    for queue_idx in [1usize, 62, 65, 200, 254] {
        assert!(!mask.counts(queue_idx), "index {queue_idx} was never set");
    }
    assert_eq!(
        ExactDemandQueueMask::EMPTY.with_queue(1) | ExactDemandQueueMask::EMPTY.with_queue(200),
        ExactDemandQueueMask::EMPTY.with_queue(1).with_queue(200)
    );

    // Past the u8 id domain there is one policy, and it over-reserves.
    let past = ExactDemandQueueMask::BITS;
    assert_eq!(
        ExactDemandQueueMask::EMPTY.with_queue(past),
        ExactDemandQueueMask::ALL
    );
    assert!(ExactDemandQueueMask::EMPTY.with_queue(3).counts(past + 5));
    assert!(!ExactDemandQueueMask::EMPTY.counts(past + 5));
}

#[test]
fn shared_backlog_carries_every_mask_word() {
    let backlog = SharedCoSExactBacklog::new(2);
    backlog.publish_with_serviceable(
        1,
        1500,
        1500,
        ExactDemandQueueMask::EMPTY.with_queue(64).with_queue(255),
    );
    backlog.publish_with_serviceable(2, 1500, 1500, ExactDemandQueueMask::EMPTY.with_queue(130));

    let seen_by_0 = backlog.peer_exact_demand_queue_mask(0);
    assert!(seen_by_0.counts(64) && seen_by_0.counts(255) && seen_by_0.counts(130));
    assert!(!seen_by_0.counts(63));
    let seen_by_1 = backlog.peer_exact_demand_queue_mask(1);
    assert!(
        !seen_by_1.counts(64),
        "a worker must not read its own slot as peer demand"
    );
    assert!(seen_by_1.counts(130));

    backlog.publish(2, 0);
    assert!(
        !backlog.peer_exact_demand_queue_mask(1).counts(130),
        "a zero publish clears the slot"
    );
    backlog.publish(2, 1);
    assert_eq!(
        backlog.peer_exact_demand_queue_mask(1),
        ExactDemandQueueMask::ALL,
        "the byte-only publish keeps its every-queue meaning"
    );
}

/// The pre-#9365 producer and consumer, apart from names, as the reference for
/// every interface a `u64` could represent.
fn reference_u64_mask(root: &CoSInterfaceRuntime) -> u64 {
    let root_tokens = root.tokens;
    root.queues
        .iter()
        .enumerate()
        .filter(|(_, queue)| {
            queue.config.exact
                && queue.config.guarantee_enabled
                && cos_exact_queue_serviceable(root_tokens, queue)
        })
        .fold(0u64, |acc, (queue_idx, _)| {
            if queue_idx < u64::BITS as usize {
                acc | (1u64 << queue_idx)
            } else {
                u64::MAX
            }
        })
}

fn reference_u64_rate(root: &CoSInterfaceRuntime, mask: u64) -> u64 {
    if mask == 0 {
        return 0;
    }
    root.queues
        .iter()
        .enumerate()
        .filter(|(queue_idx, queue)| {
            queue.config.exact
                && queue.config.guarantee_enabled
                && (*queue_idx >= u64::BITS as usize || (mask & (1u64 << *queue_idx)) != 0)
        })
        .fold(0u64, |acc, (_, queue)| {
            acc.saturating_add(queue.transmit_rate_bytes())
        })
}

#[test]
fn up_to_64_queues_the_wide_mask_reserves_exactly_what_the_u64_mask_did() {
    let mut seed: u64 = 0x9365_0000_9365_0001;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let mut compared_nonzero = 0;
    for _ in 0..400 {
        let queue_count = (next() % 64 + 1) as usize;
        let queues: Vec<CoSQueueConfig> = (0..queue_count)
            .map(|queue_idx| {
                let exact = next() % 2 == 0;
                let mut queue = demand_queue(queue_idx as u8, 1 + next() % SHAPING_BYTES, exact);
                queue.guarantee_enabled = exact || next() % 2 == 0;
                queue
            })
            .collect();
        let mut root = test_cos_runtime_with_queues(SHAPING_BYTES, queues);
        root.tokens = 100_000;
        for queue_idx in 0..queue_count {
            if next() % 2 == 0 {
                make_serviceable(&mut root, queue_idx);
            }
        }
        let peer_bits = next()
            & if queue_count == 64 {
                u64::MAX
            } else {
                (1u64 << queue_count) - 1
            };
        let peer_mask = (0..queue_count)
            .filter(|queue_idx| peer_bits & (1u64 << queue_idx) != 0)
            .fold(ExactDemandQueueMask::EMPTY, |mask, queue_idx| {
                mask.with_queue(queue_idx)
            });

        let want_local = reference_u64_rate(&root, reference_u64_mask(&root));
        let got_local =
            exact_demand_rate_bytes_for_mask(&root, serviceable_exact_demand_mask(&root));
        assert_eq!(
            got_local, want_local,
            "local reservation changed for a {queue_count}-queue interface"
        );

        let want = reference_u64_rate(&root, reference_u64_mask(&root) | peer_bits);
        let got = exact_demand_rate_bytes_for_mask(
            &root,
            serviceable_exact_demand_mask(&root) | peer_mask,
        );
        assert_eq!(
            got, want,
            "local+peer reservation changed for a {queue_count}-queue interface"
        );
        if want > 0 {
            compared_nonzero += 1;
        }
    }
    assert!(
        compared_nonzero > 100,
        "the sample must exercise real reservations, got {compared_nonzero}"
    );
}

/// `publish_cos_exact_backlog` is the only producer of the peer-visible mask.
/// It must publish the serviceable set, not every queue: a peer reading ALL
/// would reserve every exact class's rate and starve best-effort, which is the
/// defect this issue fixed for the local side.
#[test]
fn publish_cos_exact_backlog_publishes_only_the_serviceable_queue() {
    let mut root = sixty_five_queue_root();
    make_serviceable(&mut root, 64);
    let backlog = Arc::new(SharedCoSExactBacklog::new(1));
    let mut fast_interfaces = test_cos_fast_interfaces(
        42,
        42,
        0,
        (0..=64u8)
            .map(|queue_id| (queue_id, test_queue_fast_path(false, 0, None, None)))
            .collect(),
        None,
        None,
    );
    fast_interfaces
        .get_mut(&42)
        .expect("test fast path")
        .shared_exact_backlog = Some(backlog.clone());
    let fast_path = fast_interfaces.get(&42).expect("test fast path").clone();
    let binding = BindingWorker::new_for_cos_drain_test(0, 0, 42, root, fast_path);

    crate::afxdp::cos::publish_cos_exact_backlog(&binding, 42);

    let seen = backlog.peer_exact_demand_queue_mask(1);
    assert!(
        seen.counts(64),
        "the serviceable exact queue must be published"
    );
    assert!(
        !seen.counts(63),
        "an idle exact queue must not be published as demand"
    );
    assert_ne!(
        seen,
        ExactDemandQueueMask::ALL,
        "the publish must not saturate the mask"
    );
}
