use super::*;

// ---------------------------------------------------------------------
// #698 — per-worker exact-drain micro-bench
//
// Home: this file (`cos/queue_ops.rs`) rather than
// `cos/queue_service.rs`. The benches DO call drain_exact_local_*
// / settle_exact_local_* (which live in `cos/queue_service.rs`),
// but the steady-state cost they measure is dominated by the
// queue-side machinery owned here: V-min publish/consume slot
// bookkeeping, MQFQ pop snapshot/rollback, queue-vtime updates.
// Colocated with the queue_ops V-min + MQFQ unit-test suite so a
// future microarch tweak to either subsystem can be validated
// against the perf signal in the same file.
//
// Purpose: establish an in-tree, reproducible measurement of the
// userspace drain-path cost per packet. The value of
// `COS_SHARED_EXACT_MIN_RATE_BYTES` (2.5 Gbps) is cited in commit
// history as "the single-worker sustained exact throughput ceiling";
// before this harness existed there was no checked-in data supporting
// that number.
//
// Scope (what this measures):
//   - `drain_exact_local_fifo_items_to_scratch`
//       VecDeque indexed read, pattern match, free-frame pop, UMEM
//       `slice_mut_unchecked` + `copy_from_slice` (the 1500-byte
//       memcpy that dominates `memmove` in the live profile),
//       scratch Vec push, running root/secondary budget decrement.
//   - `settle_exact_local_fifo_submission`
//       queue.hot.items.pop_front per sent packet, scratch Vec pop.
//   - Re-prime between iterations — simulates a steady inflow of
//       new items from the upstream CoS enqueue path.
//
// Scope (what this does NOT measure):
//   - TX ring insert + commit (no XDP socket in unit tests; this
//     is a ring-buffer write + release store on the producer index,
//     ~20 ns combined on x86-64, amortized away at TX_BATCH_SIZE).
//   - The `sendto()` syscall used for kernel TX wakeup (amortized
//     over TX_BATCH_SIZE packets — ~2–4 ns per packet at the
//     pre-#920 batch of 256; ~10–15 ns per packet at the new
//     batch of 64).
//   - Completion ring reap (`reap_tx_completions`) — ~20–50 ns per
//     completion, mostly ring-buffer read + VecDeque push-back.
//   - All non-drain per-worker cost: RX, forwarding, NAT, session
//     lookup, conntrack. Measured in the live cluster profile, not
//     here. Those costs dominate in production and are the real
//     gate on per-worker aggregate throughput.
//
// What this tells us about the MIN constant:
//   - If drain-path Gbps is >> 2.5 Gbps, the constant is NOT gated
//     by drain speed. MIN reflects "what's left after RX + forward
//     + NAT consume 80%+ of the per-worker budget" — consistent
//     with the PR #680 collapse shape where the drain loop couldn't
//     absorb aggregate line-rate because of *other* per-packet work.
//   - If drain-path Gbps is < 2.5 Gbps, MIN is provably too high
//     and must drop. (Unlikely — drain is tightly bounded by a
//     1500-byte memcpy and a few VecDeque ops.)
//
// Running (release is mandatory — debug build numbers are not
// meaningful for this baseline):
//   cargo test --release --manifest-path userspace-dp/Cargo.toml \
//       cos_exact_drain_throughput_micro_bench -- --ignored --nocapture
//
// The bench reports two separate timings:
//   - "drain+settle (measured)" — the inner loop only. Setup work
//     (VecDeque priming, packet cloning, free-frame pool rebuild)
//     is excluded.
//   - "setup (per batch, unmeasured)" — setup cost printed for
//     reference so future changes to the setup path are visible.
//
// Hardware and noise: numbers depend on the box's core frequency
// and L1/L2 cache state. Run on quiet hardware; the published
// baseline in this commit's message was captured under those
// conditions. A repeat run after a refactor should stay within
// ~15% of the baseline on the same host — larger deltas warrant
// investigation. A single development-host measurement does NOT
// validate the MIN constant on other deployment hardware; it only
// rules out the inner drain loop as the limiter on this host.
// ---------------------------------------------------------------------
#[test]
#[ignore = "MEASUREMENT: micro-benchmark, not an assertion — it prints a rate and rules the inner drain loop in or out as the limiter ON THIS HOST; run with --release --ignored --nocapture"]
fn cos_exact_drain_throughput_micro_bench() {
    use std::time::Instant;

    // Single source of truth — `worker::COS_SHARED_EXACT_MIN_RATE_BYTES`
    // is `pub(super)` so the bench asserts against the production
    // constant directly rather than carrying a mirror that could drift.
    use crate::afxdp::worker::COS_SHARED_EXACT_MIN_RATE_BYTES;
    const PACKET_LEN: usize = 1500;
    const BATCHES: usize = 10_000;
    // Each drain call takes TX_BATCH_SIZE items. Prime enough items
    // for one batch; after each iteration we repopulate the queue
    // and free-frame pool so the measurement reflects steady state,
    // not a cold-start transient.
    const ITEMS_PER_BATCH: usize = TX_BATCH_SIZE;

    // UMEM: 2 MB is the hugepage-aligned minimum in MmapArea. That
    // fits TX_BATCH_SIZE * 4096 = 1 MB of frame slots with headroom.
    let area = MmapArea::new(2 * 1024 * 1024).expect("mmap umem");

    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 5,
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
    root.tokens = u64::MAX;
    root.queues[0].hot.tokens = u64::MAX;
    root.queues[0].hot.runnable = true;

    let packet_bytes = vec![0xABu8; PACKET_LEN];
    let mut scratch = Vec::with_capacity(ITEMS_PER_BATCH);
    let mut free_frames: VecDeque<u64> = (0..ITEMS_PER_BATCH as u64).map(|i| i * 4096).collect();
    let mut in_flight_untracked_tx = crate::afxdp::FastSet::default();

    // Prime: one full batch of items. Each iteration below drains
    // them all and then re-primes both the items and the free frames
    // to the same initial state.
    let prime_queue = |queue: &mut CoSQueueRuntime, packet: &[u8]| {
        queue.hot.items.clear();
        queue.hot.queued_bytes = 0;
        for _ in 0..ITEMS_PER_BATCH {
            queue
                .hot
                .items
                .push_back(CoSPendingTxItem::Local(TxRequest {
                    bytes: packet.to_vec(),
                    expected_ports: None,
                    expected_addr_family: libc::AF_INET as u8,
                    expected_protocol: PROTO_TCP,
                    flow_key: None,
                    egress_ifindex: 80,
                    cos_queue_id: Some(5),
                    dscp_rewrite: None,
                    mirror_clone: false,
                    overlap_admissions: None,
                    enqueue_ns: 0,
                }));
            queue.hot.queued_bytes += packet.len() as u64;
        }
    };

    // Warmup: 1000 batches to settle caches and branch predictors.
    for _ in 0..1000 {
        prime_queue(&mut root.queues[0], &packet_bytes);
        scratch.clear();
        free_frames = (0..ITEMS_PER_BATCH as u64).map(|i| i * 4096).collect();
        let build = drain_exact_local_fifo_items_to_scratch(
            &mut root.queues[0],
            &mut free_frames,
            &mut scratch,
            &area,
            u64::MAX,
            u64::MAX,
            None,
        );
        assert!(matches!(build, ExactCoSScratchBuild::Ready));
        let inserted = scratch.len();
        settle_exact_local_fifo_submission(
            Some(&mut root.queues[0]),
            &mut free_frames,
            &mut scratch,
            &mut in_flight_untracked_tx,
            inserted,
        );
    }

    // Measurement. Setup (priming, packet cloning, free-frame pool
    // rebuild) happens outside the `iter_start.elapsed()` window so
    // the reported ns/packet reflects only drain+settle. Setup cost
    // is separately accumulated and printed for reference.
    use std::time::Duration;
    let mut measured = Duration::ZERO;
    let mut setup_time = Duration::ZERO;
    let mut total_packets = 0u64;
    let mut total_bytes = 0u64;
    for _ in 0..BATCHES {
        let setup_start = Instant::now();
        prime_queue(&mut root.queues[0], &packet_bytes);
        scratch.clear();
        free_frames.clear();
        free_frames.extend((0..ITEMS_PER_BATCH as u64).map(|i| i * 4096));
        setup_time += setup_start.elapsed();

        let iter_start = Instant::now();
        let build = drain_exact_local_fifo_items_to_scratch(
            &mut root.queues[0],
            &mut free_frames,
            &mut scratch,
            &area,
            u64::MAX,
            u64::MAX,
            None,
        );
        let inserted = scratch.len();
        let (sent_pkts, sent_bytes) = settle_exact_local_fifo_submission(
            Some(&mut root.queues[0]),
            &mut free_frames,
            &mut scratch,
            &mut in_flight_untracked_tx,
            inserted,
        );
        measured += iter_start.elapsed();

        assert!(matches!(build, ExactCoSScratchBuild::Ready));
        total_packets += sent_pkts;
        total_bytes += sent_bytes;
    }

    let ns_per_packet = measured.as_nanos() as f64 / total_packets as f64;
    let mpps = total_packets as f64 / measured.as_secs_f64() / 1.0e6;
    let gbps = (total_bytes as f64 * 8.0) / measured.as_secs_f64() / 1.0e9;
    let setup_ns_per_packet = setup_time.as_nanos() as f64 / total_packets as f64;

    eprintln!(
        "\n=== #698 exact-drain userspace micro-bench ===\n\
         packet len              : {} B\n\
         batches                 : {}\n\
         packets per batch       : {}\n\
         total packets           : {}\n\
         total bytes             : {} ({:.2} MB)\n\
         drain+settle (measured) : {:?}\n\
         setup (per batch, unmeasured): {:?}\n\
         ns/packet (drain+settle): {:.2}\n\
         ns/packet (setup only)  : {:.2}\n\
         throughput (pps)        : {:.3} Mpps\n\
         throughput (line rate)  : {:.3} Gbps\n\
         min-constant gate       : {:.3} Gbps (COS_SHARED_EXACT_MIN_RATE_BYTES)\n\
         verdict (this host)     : {}\n\
         scope note              : userspace drain path only; excludes TX\n\
                                   ring insert/commit, kernel wakeup, and\n\
                                   completion ring reap. Single-host number\n\
                                   only — does not validate MIN on other\n\
                                   deployment hardware.\n\
         ================================================\n",
        PACKET_LEN,
        BATCHES,
        ITEMS_PER_BATCH,
        total_packets,
        total_bytes,
        total_bytes as f64 / (1024.0 * 1024.0),
        measured,
        setup_time,
        ns_per_packet,
        setup_ns_per_packet,
        mpps,
        gbps,
        (COS_SHARED_EXACT_MIN_RATE_BYTES * 8) as f64 / 1.0e9,
        if gbps > (COS_SHARED_EXACT_MIN_RATE_BYTES * 8) as f64 / 1.0e9 {
            "drain alone exceeds MIN on this host — rules out drain as \
             the immediate limiter here"
        } else {
            "drain alone below MIN on this host — constant is TOO HIGH, \
             lower it and re-validate live"
        },
    );

    assert!(
        total_packets as usize == BATCHES * ITEMS_PER_BATCH,
        "every batch must fully drain: {} != {}",
        total_packets,
        BATCHES * ITEMS_PER_BATCH
    );
}

// ---------------------------------------------------------------------
// #940 microbenchmark: pop + commit + settle + publish
//
// Per Gemini adversarial review: measure the FULL pop+commit+settle
// cycle so we capture the publish cost relocation (publish moved
// from pop time to post-settle).
//
// Run: cargo test --release -p xpf-userspace-dp -- bench_pop_commit_settle_publish --nocapture --ignored
// ---------------------------------------------------------------------
#[test]
#[ignore = "MEASUREMENT: micro-benchmark, not an assertion — it times the pop/commit/settle/publish cycle to locate the publish cost; run with --release --ignored --nocapture"]
fn bench_pop_commit_settle_publish() {
    use std::time::Instant;
    const PACKET_LEN: usize = 1500;
    const BATCHES: usize = 10_000;
    const ITEMS_PER_BATCH: usize = TX_BATCH_SIZE;

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
            buffer_bytes: 4 * 1024 * 1024,
            dscp_rewrite: None,
        codel_target_ns: 0,
        }],
    );
    root.tokens = u64::MAX;
    // Promote to flow_fair + shared_exact + attach floor to
    // exercise the V_min publish path.
    let queue = &mut root.queues[0];
    queue.hot.tokens = u64::MAX;
    enable_test_flow_fair(queue);
    queue.config.exact = true;
    queue.config.shared_exact = true;
    let _floor = attach_test_vtime_floor(queue, 4, 0);
    queue.hot.runnable = true;

    let area = MmapArea::new(2 * 1024 * 1024).expect("mmap umem");
    let packet_bytes = vec![0xABu8; PACKET_LEN];
    let mut scratch: Vec<(u64, TxRequest)> = Vec::with_capacity(ITEMS_PER_BATCH);
    let mut free_frames: VecDeque<u64> = (0..ITEMS_PER_BATCH as u64).map(|i| i * 4096).collect();
    let mut in_flight_untracked_tx = crate::afxdp::FastSet::default();

    let prime_queue = |queue: &mut CoSQueueRuntime, packet: &[u8]| {
        queue.hot.items.clear();
        queue.hot.queued_bytes = 0;
        test_flow_fair_state_mut(queue).queue_vtime = 0;
        test_flow_fair_state_mut(queue).flow_bucket_bytes = [0; COS_FLOW_FAIR_BUCKETS];
        test_flow_fair_state_mut(queue).flow_bucket_head_finish_bytes = [0; COS_FLOW_FAIR_BUCKETS];
        test_flow_fair_state_mut(queue).flow_bucket_tail_finish_bytes = [0; COS_FLOW_FAIR_BUCKETS];
        test_flow_fair_state_mut(queue).flow_rr_buckets = FlowRrRing::default();
        test_flow_fair_state_mut(queue).flow_bucket_items =
            std::array::from_fn(|_| VecDeque::new());
        test_flow_fair_state_mut(queue).active_flow_buckets = 0;
        queue.hot.local_item_count = 0;
        test_flow_fair_state_mut(queue).pop_snapshot_stack.clear();
        for i in 0..ITEMS_PER_BATCH {
            let mut req = TxRequest {
                bytes: packet.to_vec(),
                expected_ports: None,
                expected_addr_family: libc::AF_INET as u8,
                expected_protocol: PROTO_TCP,
                flow_key: Some(test_session_key((1000 + i) as u16, 5201)),
                egress_ifindex: 80,
                cos_queue_id: Some(0),
                dscp_rewrite: None,
                mirror_clone: false,
                overlap_admissions: None,
                enqueue_ns: 0,
            };
            let _ = req.bytes.len();
            cos_queue_push_back(queue, CoSPendingTxItem::Local(req));
        }
    };

    // Warmup.
    for _ in 0..1000 {
        prime_queue(&mut root.queues[0], &packet_bytes);
        scratch.clear();
        free_frames = (0..ITEMS_PER_BATCH as u64).map(|i| i * 4096).collect();
        let _ = drain_exact_local_items_to_scratch_flow_fair(
            &mut root.queues[0],
            &mut free_frames,
            &mut scratch,
            &area,
            u64::MAX,
            u64::MAX,
            None,
        );
        let inserted = scratch.len();
        settle_exact_local_scratch_submission_flow_fair(
            Some(&mut root.queues[0]),
            &mut free_frames,
            &mut scratch,
            &mut in_flight_untracked_tx,
            inserted,
            0, // now_ns: tests don't depend on EWMA accounting
        );
        publish_committed_queue_vtime(Some(&root.queues[0]));
    }

    let mut measured = std::time::Duration::ZERO;
    let mut total_packets = 0u64;
    for _ in 0..BATCHES {
        prime_queue(&mut root.queues[0], &packet_bytes);
        scratch.clear();
        free_frames.clear();
        free_frames.extend((0..ITEMS_PER_BATCH as u64).map(|i| i * 4096));

        let iter_start = Instant::now();
        let _ = drain_exact_local_items_to_scratch_flow_fair(
            &mut root.queues[0],
            &mut free_frames,
            &mut scratch,
            &area,
            u64::MAX,
            u64::MAX,
            None,
        );
        let inserted = scratch.len();
        settle_exact_local_scratch_submission_flow_fair(
            Some(&mut root.queues[0]),
            &mut free_frames,
            &mut scratch,
            &mut in_flight_untracked_tx,
            inserted,
            0, // now_ns: tests don't depend on EWMA accounting
        );
        publish_committed_queue_vtime(Some(&root.queues[0]));
        measured += iter_start.elapsed();
        total_packets += inserted as u64;
    }

    let ns_per_pkt = measured.as_nanos() as f64 / total_packets as f64;
    eprintln!(
        "bench_pop_commit_settle_publish: {} packets in {:?} = {:.1} ns/pkt",
        total_packets, measured, ns_per_pkt
    );
}

// ===================================================================
// #1735: lazy MQFQ generalization to non-exact shaped queues.
//
// These pin the four pieces of the design: (1) flow_fair() == is_some();
// (2) eligibility; (3) the hash-free front-key contention probe with
// single-flow-stays-FIFO + promote-on-first-differing-flow + correct
// migration; (4) lazy demotion with hysteresis. Plus a best-effort
// elephant-vs-mice per-flow fairness acceptance test (the headline gate
// proxy at unit scale).
// ===================================================================

