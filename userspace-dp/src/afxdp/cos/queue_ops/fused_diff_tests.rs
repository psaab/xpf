// #1763 — fused select+pop fairness-neutrality differential test.
//
// THE HARD GATE for Path 1. The MQFQ min-finish-bucket scan used to run
// TWICE per dequeue (peek then pop). #1763 fuses it: the peek selects
// the bucket, the pop reuses it with no re-scan, plus a no-cap fast path
// that skips the dead `flow_bucket_observed_bps` load. This test proves
// the fused path is BYTE-IDENTICAL in selection behavior to the original
// double-scan — same dequeue order AND same FlowFairState after every op.
//
// Method (mirrors the #1753 differential approach): build two
// independent, identically-configured flow-fair queues. Apply the SAME
// enqueue / pop / push_front / drain sequence to both, popping from the
// REFERENCE queue via the original double-scan API
// (`cos_queue_front*` peek + `cos_queue_pop_front*` re-scan) and from the
// FUSED queue via `cos_queue_peek_min_bucket` + `cos_queue_pop_known_bucket`.
// After every op assert the popped item identity and the full observable
// FlowFairState match. If the fused path EVER selects a different bucket,
// the assert trips. A randomized sequence test exercises the same
// invariant over thousands of mixed ops.

use super::*;
use crate::afxdp::types::EqualFlowTargetPolicy;
use crate::afxdp::cos::flow_hash::{cos_flow_bucket_index, cos_item_flow_key};
use crate::afxdp::cos::queue_ops::{
    cos_queue_drain_all, cos_queue_front, cos_queue_front_with_cap, cos_queue_peek_min_bucket,
    cos_queue_pop_front, cos_queue_pop_front_no_snapshot, cos_queue_pop_front_with_cap,
    cos_queue_pop_known_bucket, cos_queue_push_back, cos_queue_push_front,
};
use crate::afxdp::tx::test_support::{
    enable_test_flow_fair, test_cos_runtime_with_queues, test_flow_fair_state,
    test_flow_fair_state_mut, test_session_key,
};
use crate::afxdp::types::{CoSPendingTxItem, CoSQueueConfig, CoSQueueRuntime, TxRequest};
use crate::afxdp::{PROTO_TCP, TX_BATCH_SIZE};

// ---- helpers --------------------------------------------------------

/// Build a single-queue exact flow-fair runtime and return the promoted
/// queue. Exact queues stay promoted for life (the regime the lever
/// targets).
fn make_flow_fair_queue() -> CoSQueueRuntime {
    let mut root = test_cos_runtime_with_queues(
        25_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 4,
            forwarding_class: "iperf-a".into(),
            priority: 5,
            transmit_rate_bytes: 1_000_000_000 / 8,
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
    let mut queue = root.queues.remove(0);
    enable_test_flow_fair(&mut queue);
    queue
}

/// A flow-fair item carrying a unique `(src_port, len)` identity so two
/// independent queues can be compared item-for-item. `seq` is folded
/// into the payload length's low bits is avoided — instead identity is
/// `(src_port, len)` and we keep len distinct per logical packet.
fn flow_item(src_port: u16, len: usize) -> CoSPendingTxItem {
    CoSPendingTxItem::Local(TxRequest {
        bytes: vec![0u8; len],
        expected_ports: None,
        expected_addr_family: libc::AF_INET as u8,
        expected_protocol: PROTO_TCP,
        flow_key: Some(test_session_key(src_port, 5201)),
        egress_ifindex: 42,
        cos_queue_id: Some(4),
        dscp_rewrite: None,
        mirror_clone: false,
        overlap_admissions: None,
        enqueue_ns: 0,
    })
}

/// Identity tuple for cross-queue item comparison: (flow src_port, len).
fn item_identity(item: &CoSPendingTxItem) -> (Option<u16>, u64) {
    let port = cos_item_flow_key(item).map(|k| k.src_port);
    (port, cos_item_len(item))
}

/// Capture the full observable FlowFairState for equality comparison.
/// Includes everything the selection scan reads or the pop mutates:
/// queue_vtime, active_flow_buckets, the active ring order, per-bucket
/// head/tail finish, per-bucket item lengths, and the snapshot stack.
#[derive(Debug, PartialEq)]
struct FfSnapshot {
    queue_vtime: u64,
    active_flow_buckets: u16,
    active_flow_buckets_peak: u16,
    rr_order: Vec<u16>,
    bucket_head_finish: Vec<(u16, u64)>,
    bucket_tail_finish: Vec<(u16, u64)>,
    bucket_item_lens: Vec<(u16, Vec<u64>)>,
    // #1763 Codex review: the per-bucket accounting + selection-input
    // arrays MUST also match. `observed_bps` is a selection INPUT (the
    // cap-aware eligibility key), and `bytes`/`tx_bytes`/`pending_bytes`/
    // `last_tx_ns` are mutated by the shared pop accounting body — a
    // divergence here would be a real fairness or accounting regression
    // even if the dequeue order matched. Captured per active bucket.
    bucket_observed_bps: Vec<(u16, u64)>,
    bucket_bytes: Vec<(u16, u64)>,
    bucket_tx_bytes: Vec<(u16, u64)>,
    bucket_last_tx_ns: Vec<(u16, u64)>,
    bucket_pending_bytes: Vec<(u16, u32)>,
    snapshot_stack: Vec<crate::afxdp::types::CoSQueuePopSnapshot>,
    queued_bytes: u64,
    local_item_count: u32,
}

fn snapshot_ff(queue: &CoSQueueRuntime) -> FfSnapshot {
    let ff = test_flow_fair_state(queue);
    let rr_order: Vec<u16> = ff.flow_rr_buckets.iter().collect();
    // For every active bucket record the head/tail finish, item lengths
    // (FIFO order), and the per-bucket accounting + selection-input
    // arrays, keyed by bucket id (ring order).
    let mut bucket_head_finish = Vec::new();
    let mut bucket_tail_finish = Vec::new();
    let mut bucket_item_lens = Vec::new();
    let mut bucket_observed_bps = Vec::new();
    let mut bucket_bytes = Vec::new();
    let mut bucket_tx_bytes = Vec::new();
    let mut bucket_last_tx_ns = Vec::new();
    let mut bucket_pending_bytes = Vec::new();
    for b in rr_order.iter().copied() {
        let bi = usize::from(b);
        bucket_head_finish.push((b, ff.flow_bucket_head_finish_bytes[bi]));
        bucket_tail_finish.push((b, ff.flow_bucket_tail_finish_bytes[bi]));
        let lens: Vec<u64> = ff.flow_bucket_items[bi]
            .iter()
            .map(cos_item_len)
            .collect();
        bucket_item_lens.push((b, lens));
        bucket_observed_bps.push((b, ff.flow_bucket_observed_bps[bi]));
        bucket_bytes.push((b, ff.flow_bucket_bytes[bi]));
        bucket_tx_bytes.push((b, ff.flow_bucket_tx_bytes[bi]));
        bucket_last_tx_ns.push((b, ff.flow_bucket_last_tx_ns[bi]));
        bucket_pending_bytes.push((b, ff.flow_bucket_pending_bytes[bi]));
    }
    FfSnapshot {
        queue_vtime: ff.queue_vtime,
        active_flow_buckets: ff.active_flow_buckets,
        active_flow_buckets_peak: ff.active_flow_buckets_peak,
        rr_order,
        bucket_head_finish,
        bucket_tail_finish,
        bucket_item_lens,
        bucket_observed_bps,
        bucket_bytes,
        bucket_tx_bytes,
        bucket_last_tx_ns,
        bucket_pending_bytes,
        snapshot_stack: ff.pop_snapshot_stack.clone(),
        queued_bytes: queue.hot.queued_bytes,
        local_item_count: queue.hot.local_item_count,
    }
}

/// Reference popper (the original DOUBLE-scan): peek via `cos_queue_front`
/// (one scan), then `cos_queue_pop_front` (a second scan that re-derives
/// the same bucket). This is exactly what production did before #1763.
fn reference_pop_nocap(queue: &mut CoSQueueRuntime) -> Option<CoSPendingTxItem> {
    // Mirror the build_cos_batch_from_queue peek-then-pop shape: the peek
    // result is inspected then discarded, the pop re-scans.
    let _ = cos_queue_front(queue)?;
    cos_queue_pop_front(queue)
}

fn reference_pop_cap(queue: &mut CoSQueueRuntime, target_bps: u64) -> Option<CoSPendingTxItem> {
    let _ = cos_queue_front_with_cap(queue, target_bps)?;
    cos_queue_pop_front_with_cap(queue, target_bps)
}

/// Fused popper (the #1763 SINGLE-scan): peek returns the bucket id, the
/// pop reuses it with no re-scan.
fn fused_pop_nocap(queue: &mut CoSQueueRuntime) -> Option<CoSPendingTxItem> {
    let bucket = {
        let (b, _front) = cos_queue_peek_min_bucket(queue, u64::MAX)?;
        b
    };
    cos_queue_pop_known_bucket(queue, bucket, u64::MAX)
}

fn fused_pop_cap(queue: &mut CoSQueueRuntime, target_bps: u64) -> Option<CoSPendingTxItem> {
    let bucket = {
        let (b, _front) = cos_queue_peek_min_bucket(queue, target_bps)?;
        b
    };
    cos_queue_pop_known_bucket(queue, bucket, target_bps)
}

/// Assert two queues are in byte-identical observable state.
fn assert_states_equal(reference: &CoSQueueRuntime, fused: &CoSQueueRuntime, ctx: &str) {
    assert_eq!(
        snapshot_ff(reference),
        snapshot_ff(fused),
        "fused vs reference FlowFairState diverged: {ctx}"
    );
}

// ---- scripted differential scenarios --------------------------------

/// Step kinds applied identically to both the reference and fused queues.
#[derive(Clone, Debug)]
enum Step {
    Enqueue { src_port: u16, len: usize },
    PopNoCap,
    PopCap(u64),
    /// push_front the most-recently-popped item back (rollback). Carried
    /// per-queue because the items differ by identity but are equal by
    /// shape.
    PushFrontLast,
}

/// Drive `steps` through both queues and assert identical pops + state.
fn run_diff(steps: &[Step], scenario: &str) {
    let mut reference = make_flow_fair_queue();
    let mut fused = make_flow_fair_queue();
    // Per-queue stash of the last popped item for PushFrontLast rollback.
    let mut ref_last: Option<CoSPendingTxItem> = None;
    let mut fused_last: Option<CoSPendingTxItem> = None;

    for (i, step) in steps.iter().enumerate() {
        let ctx = format!("{scenario} step {i}: {step:?}");
        match step {
            Step::Enqueue { src_port, len } => {
                cos_queue_push_back(&mut reference, flow_item(*src_port, *len));
                cos_queue_push_back(&mut fused, flow_item(*src_port, *len));
            }
            Step::PopNoCap => {
                let r = reference_pop_nocap(&mut reference);
                let f = fused_pop_nocap(&mut fused);
                assert_eq!(
                    r.as_ref().map(item_identity),
                    f.as_ref().map(item_identity),
                    "no-cap pop identity diverged: {ctx}"
                );
                ref_last = r;
                fused_last = f;
            }
            Step::PopCap(target_bps) => {
                let r = reference_pop_cap(&mut reference, *target_bps);
                let f = fused_pop_cap(&mut fused, *target_bps);
                assert_eq!(
                    r.as_ref().map(item_identity),
                    f.as_ref().map(item_identity),
                    "cap pop identity diverged: {ctx}"
                );
                ref_last = r;
                fused_last = f;
            }
            Step::PushFrontLast => {
                if let Some(item) = ref_last.take() {
                    cos_queue_push_front(&mut reference, item);
                }
                if let Some(item) = fused_last.take() {
                    cos_queue_push_front(&mut fused, item);
                }
            }
        }
        assert_states_equal(&reference, &fused, &ctx);
    }
}

#[test]
fn diff_single_active_bucket() {
    let steps = vec![
        Step::Enqueue { src_port: 1111, len: 1500 },
        Step::Enqueue { src_port: 1111, len: 1500 },
        Step::Enqueue { src_port: 1111, len: 700 },
        Step::PopNoCap,
        Step::PopNoCap,
        Step::PopNoCap,
        Step::PopNoCap, // drains empty
    ];
    run_diff(&steps, "single_active_bucket");
}

#[test]
fn diff_n_buckets_equal_finish() {
    // Several flows, all equal-byte packets — every head finish ties, so
    // selection falls to ring insertion order. A re-scan that broke ties
    // differently would diverge here.
    let mut steps = Vec::new();
    for port in [2001u16, 2002, 2003, 2004, 2005] {
        steps.push(Step::Enqueue { src_port: port, len: 1500 });
        steps.push(Step::Enqueue { src_port: port, len: 1500 });
    }
    for _ in 0..10 {
        steps.push(Step::PopNoCap);
    }
    run_diff(&steps, "n_buckets_equal_finish");
}

#[test]
fn diff_skewed_finish() {
    // Mixed packet sizes → distinct head finish times → MQFQ orders by
    // byte-finish, not arrival. The single min-finish winner must match.
    let steps = vec![
        Step::Enqueue { src_port: 3001, len: 1500 },
        Step::Enqueue { src_port: 3002, len: 200 },
        Step::Enqueue { src_port: 3003, len: 800 },
        Step::Enqueue { src_port: 3001, len: 1500 },
        Step::Enqueue { src_port: 3002, len: 200 },
        Step::Enqueue { src_port: 3003, len: 800 },
        Step::PopNoCap,
        Step::PopNoCap,
        Step::PopNoCap,
        Step::PopNoCap,
        Step::PopNoCap,
        Step::PopNoCap,
    ];
    run_diff(&steps, "skewed_finish");
}

#[test]
fn diff_idle_bucket_reanchor() {
    // Drain a bucket to empty, advance vtime via other flows, then
    // re-enqueue the drained flow — it must re-anchor at queue_vtime.
    // The fused and reference paths must compute the identical re-anchor.
    let steps = vec![
        Step::Enqueue { src_port: 4001, len: 1500 },
        Step::Enqueue { src_port: 4002, len: 1500 },
        Step::Enqueue { src_port: 4002, len: 1500 },
        Step::PopNoCap, // drains one of them
        Step::PopNoCap,
        Step::Enqueue { src_port: 4001, len: 1500 }, // re-anchor at vtime
        Step::Enqueue { src_port: 4003, len: 300 },
        Step::PopNoCap,
        Step::PopNoCap,
        Step::PopNoCap,
    ];
    run_diff(&steps, "idle_bucket_reanchor");
}

#[test]
fn diff_snapshot_push_front_rollback() {
    // pop (records snapshot) then push_front (consumes snapshot, restores
    // pre-pop bucket state). The snapshot stack must match between fused
    // and reference after each rollback.
    let steps = vec![
        Step::Enqueue { src_port: 5001, len: 1500 },
        Step::Enqueue { src_port: 5002, len: 900 },
        Step::Enqueue { src_port: 5001, len: 1500 },
        Step::PopNoCap,
        Step::PushFrontLast,
        Step::PopNoCap,
        Step::PopNoCap,
        Step::PushFrontLast,
        Step::PopNoCap,
        Step::PopNoCap,
    ];
    run_diff(&steps, "snapshot_push_front_rollback");
}

#[test]
fn diff_cap_aware_over_cap_mix() {
    // Cap-aware pops with a finite target. Some buckets are "over cap"
    // (observed_bps starts at 0 in the test, so all are eligible) but the
    // finite target_bps still drives the eligible/fallback two-pass in the
    // reference, while the fused path runs the SAME cap-aware scan. They
    // must agree.
    let steps = vec![
        Step::Enqueue { src_port: 6001, len: 1500 },
        Step::Enqueue { src_port: 6002, len: 400 },
        Step::Enqueue { src_port: 6003, len: 1200 },
        Step::Enqueue { src_port: 6001, len: 1500 },
        Step::PopCap(100_000_000),
        Step::PopCap(100_000_000),
        Step::PopCap(50_000),
        Step::PopCap(50_000),
    ];
    run_diff(&steps, "cap_aware_over_cap_mix");
}

#[test]
fn diff_mixed_cap_and_nocap() {
    // Interleave cap-aware and no-cap pops on the same backlog — the
    // no-cap fast path (Lever B) and the cap-aware path must each match
    // their reference.
    let steps = vec![
        Step::Enqueue { src_port: 7001, len: 1500 },
        Step::Enqueue { src_port: 7002, len: 600 },
        Step::Enqueue { src_port: 7003, len: 1000 },
        Step::Enqueue { src_port: 7001, len: 1500 },
        Step::Enqueue { src_port: 7002, len: 600 },
        Step::PopNoCap,
        Step::PopCap(200_000_000),
        Step::PopNoCap,
        Step::PopCap(200_000_000),
        Step::PopNoCap,
    ];
    run_diff(&steps, "mixed_cap_and_nocap");
}

#[test]
fn diff_drain_all_after_fused_pops() {
    // After a run of fused pops on both queues, drain_all (which uses the
    // no-snapshot pop) must produce the identical residual order on both.
    let mut reference = make_flow_fair_queue();
    let mut fused = make_flow_fair_queue();
    for port in [8001u16, 8002, 8003] {
        for len in [1500usize, 1500, 300] {
            cos_queue_push_back(&mut reference, flow_item(port, len));
            cos_queue_push_back(&mut fused, flow_item(port, len));
        }
    }
    // Pop a few via the divergent paths.
    for _ in 0..4 {
        let r = reference_pop_nocap(&mut reference);
        let f = fused_pop_nocap(&mut fused);
        assert_eq!(r.as_ref().map(item_identity), f.as_ref().map(item_identity));
    }
    assert_states_equal(&reference, &fused, "drain_all pre-drain");
    let ref_rest = cos_queue_drain_all(&mut reference);
    let fused_rest = cos_queue_drain_all(&mut fused);
    let ref_ids: Vec<_> = ref_rest.iter().map(item_identity).collect();
    let fused_ids: Vec<_> = fused_rest.iter().map(item_identity).collect();
    assert_eq!(ref_ids, fused_ids, "drain_all residual order diverged");
}

#[test]
fn diff_no_snapshot_pop_parity() {
    // The no-snapshot pop path (used by drain_all) shares the fused
    // post-scan body via the FIFO/known-bucket inner. Pop both ways from
    // identical state and confirm parity through the no_snapshot variant.
    let mut reference = make_flow_fair_queue();
    let mut fused = make_flow_fair_queue();
    for port in [9001u16, 9002] {
        cos_queue_push_back(&mut reference, flow_item(port, 1500));
        cos_queue_push_back(&mut fused, flow_item(port, 1500));
    }
    // reference: front peek + no_snapshot pop; fused: peek_min_bucket +
    // pop_known_bucket(no_snapshot path is internal to drain_all, so here
    // we just confirm the no_snapshot reference path itself matches a
    // fused snapshotting pop is NOT valid — instead compare two
    // no_snapshot pops driven by the same selection).
    let r = {
        let _ = cos_queue_front(&reference);
        cos_queue_pop_front_no_snapshot(&mut reference)
    };
    let f = {
        let _ = cos_queue_peek_min_bucket(&fused, u64::MAX);
        cos_queue_pop_front_no_snapshot(&mut fused)
    };
    assert_eq!(r.as_ref().map(item_identity), f.as_ref().map(item_identity));
    assert_states_equal(&reference, &fused, "no_snapshot parity");
}

// ---- randomized differential ----------------------------------------

/// Tiny deterministic xorshift PRNG — no external dep, reproducible.
struct Rng(u64);
impl Rng {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }
}

#[test]
fn diff_randomized_sequences() {
    // Many randomized mixed sequences: enqueue across a small flow set,
    // no-cap pops, cap-aware pops, and push_front rollbacks. Each seed is
    // an independent backlog evolution; any selection divergence trips an
    // assert. Flow count kept around the measured N=14 regime.
    let ports: [u16; 14] = [
        10001, 10002, 10003, 10004, 10005, 10006, 10007, 10008, 10009, 10010, 10011, 10012,
        10013, 10014,
    ];
    let lens = [64usize, 200, 512, 800, 1200, 1500];
    let caps = [u64::MAX, 500_000_000, 100_000_000, 25_000, u64::MAX];

    for seed in 1u64..=40 {
        let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
        let mut steps: Vec<Step> = Vec::new();
        // Build up an initial backlog so the active set is populated.
        for _ in 0..(20 + rng.below(20)) {
            let port = ports[rng.below(ports.len() as u64) as usize];
            let len = lens[rng.below(lens.len() as u64) as usize];
            steps.push(Step::Enqueue { src_port: port, len });
        }
        // Then a long mixed op stream.
        for _ in 0..200 {
            match rng.below(10) {
                0 | 1 | 2 => {
                    let port = ports[rng.below(ports.len() as u64) as usize];
                    let len = lens[rng.below(lens.len() as u64) as usize];
                    steps.push(Step::Enqueue { src_port: port, len });
                }
                3 | 4 | 5 | 6 => steps.push(Step::PopNoCap),
                7 | 8 => {
                    let cap = caps[rng.below(caps.len() as u64) as usize];
                    steps.push(Step::PopCap(cap));
                }
                _ => steps.push(Step::PushFrontLast),
            }
        }
        run_diff(&steps, &format!("randomized seed={seed}"));
    }
}

/// #1763 Codex review — INDEPENDENT no-cap-vs-two-pass oracle. The
/// scripted/randomized diff tests above route BOTH the reference and the
/// fused popper through `cos_queue_min_finish_bucket`, so they prove
/// peek-vs-pop equivalence but NOT that the no-cap fast path (Lever B)
/// equals the ORIGINAL eligible/fallback two-pass at `target_bps ==
/// u64::MAX`. This test closes that gap with a self-contained reference:
/// it builds randomized active-ring states (varied head-finish + nonzero
/// observed_bps) and asserts `cos_queue_min_finish_bucket(ff, u64::MAX)`
/// (which dispatches to `cos_queue_min_finish_bucket_no_cap`) selects the
/// IDENTICAL bucket as a hand-rolled replay of the pre-#1763 two-pass
/// loop evaluated at `target_bps == u64::MAX`. Because every bucket is
/// eligible at u64::MAX, the two-pass collapses to "lowest head-finish,
/// first-wins on strict <" — exactly what the no-cap path must produce.
#[test]
fn no_cap_fast_path_equals_two_pass_at_max() {
    use crate::afxdp::tx::test_support::test_flow_fair_state_mut;

    // Reference: replay the ORIGINAL eligible/fallback two-pass loop
    // (verbatim semantics from the pre-#1763 cos_queue_min_finish_bucket)
    // at target_bps == u64::MAX. NOT routed through the new dispatch.
    fn two_pass_ref_at_max(ff: &crate::afxdp::types::FlowFairState) -> Option<u16> {
        let target_bps = u64::MAX;
        let mut eligible: Option<u16> = None;
        let mut eligible_finish = u64::MAX;
        let mut fallback: Option<u16> = None;
        let mut fallback_finish = u64::MAX;
        for bucket in ff.flow_rr_buckets.iter() {
            let b = usize::from(bucket);
            let finish = ff.flow_bucket_head_finish_bytes[b];
            if finish < fallback_finish {
                fallback_finish = finish;
                fallback = Some(bucket);
            }
            let observed = ff.flow_bucket_observed_bps[b];
            if observed <= target_bps && finish < eligible_finish {
                eligible_finish = finish;
                eligible = Some(bucket);
            }
        }
        eligible.or(fallback)
    }

    let mut rng = Rng(0xC0FF_EE12_3456_789A);
    for _iter in 0..2000 {
        let mut queue = make_flow_fair_queue();
        let ff = test_flow_fair_state_mut(&mut queue);
        // Populate a random set of active buckets with varied head-finish
        // and observed_bps directly (bypassing enqueue so we can hit
        // equal-finish ties and large observed values exhaustively).
        let n = 1 + rng.below(20) as usize; // up to 20 active buckets
        for _ in 0..n {
            let bucket = (1 + rng.below(4000)) as u16; // avoid bucket 0 sentinel-ish
            let bi = usize::from(bucket);
            // Skip duplicates (ring invariant: no dup bucket ids).
            if ff.flow_bucket_head_finish_bytes[bi] != 0 {
                continue;
            }
            // Head finish drawn from a small set to force frequent ties.
            let finish = 1 + rng.below(6) * 500;
            ff.flow_bucket_head_finish_bytes[bi] = finish;
            ff.flow_bucket_tail_finish_bytes[bi] = finish;
            // Observed bps: mix of 0, small, and near-u64::MAX values to
            // confirm the no-cap path ignores observed entirely.
            ff.flow_bucket_observed_bps[bi] = match rng.below(4) {
                0 => 0,
                1 => rng.below(1_000_000_000),
                2 => u64::MAX - 1,
                _ => u64::MAX,
            };
            ff.flow_rr_buckets.push_back(bucket);
        }
        let want = two_pass_ref_at_max(ff);
        let got = cos_queue_min_finish_bucket(ff, u64::MAX);
        assert_eq!(
            got, want,
            "no-cap fast path diverged from two-pass@u64::MAX: ring={:?}",
            ff.flow_rr_buckets.iter().collect::<Vec<_>>()
        );
        // Also confirm the no_cap specialization directly matches.
        assert_eq!(cos_queue_min_finish_bucket_no_cap(ff), want);
    }
}

#[test]
fn min_finish_bucket_selects_a_saturated_head_finish_bucket() {
    // #hb166 T-7: a bucket whose head-finish has SATURATED to u64::MAX
    // (the same value seeded as the "no bucket found" sentinel) must still
    // be selectable — otherwise it becomes a permanently unselectable
    // active bucket whose packets never drain. Pre-fix, the bare
    // `finish < *_finish` compare skipped it (both scans returned None);
    // the fix gates on `is_none()` so the first active bucket is always
    // chosen. Mirrors the R-8(b)/#4271 vtime-sentinel guard for the
    // head-finish domain #4271 did NOT cover.
    let mut queue = make_flow_fair_queue();
    let ff = test_flow_fair_state_mut(&mut queue);
    let bucket: u16 = 7;
    let bi = usize::from(bucket);
    ff.flow_bucket_head_finish_bytes[bi] = u64::MAX;
    ff.flow_bucket_tail_finish_bytes[bi] = u64::MAX;
    ff.flow_bucket_observed_bps[bi] = 0;
    ff.flow_rr_buckets.push_back(bucket);

    assert_eq!(
        cos_queue_min_finish_bucket_no_cap(ff),
        Some(bucket),
        "no-cap scan must select the sole active bucket even at u64::MAX head-finish"
    );
    assert_eq!(
        cos_queue_min_finish_bucket(ff, u64::MAX),
        Some(bucket),
        "dispatch must select the sole active bucket even at u64::MAX head-finish"
    );
    // Cap-aware path (finite target, observed under cap) must also fall
    // back to a saturated-finish bucket rather than returning None.
    assert_eq!(
        cos_queue_min_finish_bucket(ff, 1_000),
        Some(bucket),
        "cap-aware fallback must select a u64::MAX head-finish bucket"
    );
}

#[test]
fn pop_known_bucket_on_empty_selected_bucket_leaves_no_orphan_snapshot() {
    // #hb166 T-7: a desync where the selected min-finish bucket is in the
    // active ring but its item deque is empty must NOT leave an orphaned
    // rollback snapshot on the per-queue LIFO stack — a later push_front
    // would match against it and `assert!(false)`-panic the worker in
    // release. Pre-fix, the snapshot was pushed BEFORE the fallible pop, so
    // the `None` return orphaned it; the fix pops first and only pushes the
    // snapshot on success. RED-on-revert: the pre-fix ordering grows the
    // stack by 1.
    let mut queue = make_flow_fair_queue();
    let bucket: u16 = 3;
    {
        let ff = test_flow_fair_state_mut(&mut queue);
        // Active bucket with the smallest finish so the min-finish scan
        // selects it, but with an EMPTY item deque (the desync).
        ff.flow_bucket_head_finish_bytes[usize::from(bucket)] = 1;
        ff.flow_bucket_tail_finish_bytes[usize::from(bucket)] = 1;
        ff.flow_rr_buckets.push_back(bucket);
        assert!(ff.pop_snapshot_stack.is_empty());
    }
    let popped = cos_queue_pop_known_bucket(&mut queue, bucket, u64::MAX);
    assert!(popped.is_none(), "empty selected bucket must yield None");
    let ff = test_flow_fair_state_mut(&mut queue);
    assert!(
        ff.pop_snapshot_stack.is_empty(),
        "a None pop must not leave an orphaned rollback snapshot ({} entries)",
        ff.pop_snapshot_stack.len()
    );
}

#[test]
fn diff_full_batch_drain_parity() {
    // Drain a full TX_BATCH_SIZE worth interleaved across many flows, the
    // realistic hot-path batch shape, and confirm parity across the whole
    // batch.
    let mut steps = Vec::new();
    let ports: Vec<u16> = (12001u16..12001 + 14).collect();
    for round in 0..(TX_BATCH_SIZE / ports.len() + 2) {
        for (i, &port) in ports.iter().enumerate() {
            let len = 200 + (i * 91 + round * 37) % 1300;
            steps.push(Step::Enqueue { src_port: port, len });
        }
    }
    for _ in 0..TX_BATCH_SIZE {
        steps.push(Step::PopNoCap);
    }
    run_diff(&steps, "full_batch_drain_parity");
}
