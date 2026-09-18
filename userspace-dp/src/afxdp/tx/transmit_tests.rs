// Tests for afxdp/tx/transmit.rs — relocated from inline
// `#[cfg(test)] mod tests` to keep transmit.rs under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "transmit_tests.rs"]` from transmit.rs.

use super::*;
use crate::afxdp::PROTO_TCP;

#[test]
fn remember_prepared_recycle_tracks_only_shared_fill_recycles() {
    let mut in_flight_prepared_recycles = FastMap::default();
    let mut in_flight_untracked_tx = FastSet::default();

    remember_prepared_recycle(
        &mut in_flight_prepared_recycles,
        &mut in_flight_untracked_tx,
        &PreparedTxRequest {
            offset: 41,
            len: 64,
            recycle: PreparedTxRecycle::FreeTxFrame,
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 0,
            cos_queue_id: None,
            dscp_rewrite: None,
            mirror_clone: false,
            overlap_admissions: None,
            enqueue_ns: 0,
        },
    );
    remember_prepared_recycle(
        &mut in_flight_prepared_recycles,
        &mut in_flight_untracked_tx,
        &PreparedTxRequest {
            offset: 42,
            len: 64,
            recycle: PreparedTxRecycle::FillOnSlot(7),
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 0,
            cos_queue_id: None,
            dscp_rewrite: None,
            mirror_clone: false,
            overlap_admissions: None,
            enqueue_ns: 0,
        },
    );
    remember_prepared_recycle(
        &mut in_flight_prepared_recycles,
        &mut in_flight_untracked_tx,
        &PreparedTxRequest {
            offset: 43,
            len: 64,
            recycle: PreparedTxRecycle::FillOnSlotWithOffset {
                slot: 8,
                offset: 1234,
            },
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 0,
            cos_queue_id: None,
            dscp_rewrite: None,
            mirror_clone: false,
            overlap_admissions: None,
            enqueue_ns: 0,
        },
    );
    assert_eq!(in_flight_prepared_recycles.len(), 2);
    assert_eq!(
        in_flight_prepared_recycles.get(&42),
        Some(&PreparedTxRecycle::FillOnSlot(7))
    );
    assert_eq!(
        in_flight_prepared_recycles.get(&43),
        Some(&PreparedTxRecycle::FillOnSlotWithOffset {
            slot: 8,
            offset: 1234,
        })
    );
    assert!(!in_flight_prepared_recycles.contains_key(&41));
    // #9900 F-092 (GPT-2): the FreeTxFrame submit lands in the untracked
    // ownership set instead — same split, both sides exact.
    assert_eq!(in_flight_untracked_tx.len(), 1);
    assert!(in_flight_untracked_tx.contains(&41));
    assert!(!in_flight_untracked_tx.contains(&42));
    assert!(!in_flight_untracked_tx.contains(&43));
}

#[test]
fn cancelled_prepared_foreign_fill_routes_to_shared_recycles() {
    let mut free_tx_frames = VecDeque::new();
    let mut pending_fill_frames = VecDeque::new();
    let mut shared_recycles = Vec::new();

    recycle_cancelled_prepared_offset_with_shared(
        &mut free_tx_frames,
        &mut pending_fill_frames,
        Some(&mut shared_recycles),
        7,
        PreparedTxRecycle::FillOnSlotWithOffset {
            slot: 8,
            offset: 1234,
        },
        42,
    );

    assert!(free_tx_frames.is_empty());
    assert!(pending_fill_frames.is_empty());
    assert_eq!(shared_recycles, vec![(8, 1234)]);
}

#[test]
fn cancelled_prepared_local_fill_stays_on_pending_fill() {
    let mut free_tx_frames = VecDeque::new();
    let mut pending_fill_frames = VecDeque::new();
    let mut shared_recycles = Vec::new();

    recycle_cancelled_prepared_offset_with_shared(
        &mut free_tx_frames,
        &mut pending_fill_frames,
        Some(&mut shared_recycles),
        7,
        PreparedTxRecycle::FillOnSlot(7),
        42,
    );

    assert!(free_tx_frames.is_empty());
    assert_eq!(pending_fill_frames, VecDeque::from([42]));
    assert!(shared_recycles.is_empty());
}

// #hb166 T-6(d): when `transmit_batch` hits an oversized frame mid-batch it
// unwinds the already-staged prefix back onto the head of `pending`. The
// unwind MUST preserve the original front-to-back order so same-flow (in-
// order TCP) segments are not reordered on the error path.
//
// FAIL-ON-REVERT: dropping the `.rev()` from the unwind drain reverses the
// restored prefix, flipping the recovered enqueue_ns order from [1, 2, 4]
// to [2, 1, 4].
#[test]
fn transmit_batch_oversized_unwind_preserves_pending_order() {
    use crate::afxdp::tx::test_support::{
        test_cos_fast_interfaces, test_cos_runtime_with_queues, test_queue_fast_path,
    };
    use crate::afxdp::types::TxRequest;

    let mk = |len: usize, id: u64| TxRequest {
        bytes: vec![0u8; len],
        expected_ports: None,
        expected_addr_family: 0,
        expected_protocol: 0,
        flow_key: None,
        egress_ifindex: 42,
        cos_queue_id: None,
        dscp_rewrite: None,
        mirror_clone: false,
        overlap_admissions: None,
        // enqueue_ns doubles as an identity marker for order assertions.
        enqueue_ns: id,
    };

    let root = test_cos_runtime_with_queues(10_000_000, vec![]);
    let fast_interfaces = test_cos_fast_interfaces(
        42,
        42,
        0,
        vec![(0, test_queue_fast_path(false, 0, None, None))],
        None,
        None,
    );
    let fast_path = fast_interfaces.get(&42).expect("test fast path").clone();
    let mut binding = BindingWorker::new_for_cos_drain_test(0, 0, 42, root, fast_path);

    // A(128), B(128) stage; the oversized item (> tx_frame_capacity()) trips
    // the Drop-unwind; D(128) is never reached (loop returns on the Err).
    let mut pending = VecDeque::from([
        mk(128, 1),
        mk(128, 2),
        mk(tx_frame_capacity() + 1, 3),
        mk(128, 4),
    ]);
    let mut shared_recycles = Vec::new();

    let result = transmit_batch(&mut binding, &mut pending, 0, &mut shared_recycles);
    assert!(matches!(result, Err(TxError::Drop(_))));

    let order: Vec<u64> = pending.iter().map(|r| r.enqueue_ns).collect();
    assert_eq!(
        order,
        vec![1, 2, 4],
        "oversized-unwind must keep the staged prefix in original order (A before B)",
    );
}

// #4971: the expected TX-retry tail (the un-inserted suffix pushed
// back to `pending` after a partial ring insert) must not allocate per
// drain pass, and must preserve FIFO order. Driven through the real
// `finalise_prepared` with 2 of 4 staged frames accepted.
//
// FAIL-ON-REVERT (assertion, NOT a build break): reverting the tail
// drain to `let mut retry_tail = Vec::new();` + `retry_tail.push(req)`
// reintroduces a per-pass heap allocation for the pushed-back tail, so
// the measured allocation count becomes > 0 → assertion RED.
#[test]
fn tx_retry_tail_is_allocation_free_4971() {
    use crate::afxdp::tx::test_support::{
        test_cos_fast_interfaces, test_cos_runtime_with_queues, test_queue_fast_path,
    };

    let root = test_cos_runtime_with_queues(10_000_000, vec![]);
    let fast_interfaces = test_cos_fast_interfaces(
        42,
        42,
        0,
        vec![(0, test_queue_fast_path(false, 0, None, None))],
        None,
        None,
    );
    let fast_path = fast_interfaces.get(&42).expect("test fast path").clone();
    let mut binding = BindingWorker::new_for_cos_drain_test(0, 0, 42, root, fast_path);
    // maybe_wake_tx does a sendto(-1) on the test fd; suppress its
    // first-N error eprintln so it does not perturb the alloc count.
    binding.telemetry.dbg_sendto_err = 100;

    let mk = |off: u64, id: u64| PreparedTxRequest {
        offset: off,
        len: 64,
        recycle: PreparedTxRecycle::FreeTxFrame,
        expected_ports: None,
        expected_addr_family: libc::AF_INET as u8,
        expected_protocol: PROTO_TCP,
        flow_key: None,
        egress_ifindex: 0,
        cos_queue_id: None,
        dscp_rewrite: None,
        overlap_admissions: None,
        mirror_clone: false,
        // enqueue_ns doubles as an identity marker for FIFO assertions.
        enqueue_ns: id,
    };
    let stage = |binding: &mut BindingWorker| {
        binding.scratch.scratch_prepared_tx.clear();
        for i in 0..4u64 {
            binding.scratch.scratch_prepared_tx.push(mk(i * 2048, i + 1));
        }
    };

    // Pre-reserve so `push_front` never reallocates the deque during the
    // measured pass, then warm once to pay any one-time lazy init.
    let mut pending: VecDeque<PreparedTxRequest> = VecDeque::with_capacity(256);
    stage(&mut binding);
    let _ = finalise::finalise_prepared(&mut binding, &mut pending, 0, 2);

    pending.clear();
    stage(&mut binding);
    let (res, allocs) = crate::test_alloc::count_allocs(|| {
        finalise::finalise_prepared(&mut binding, &mut pending, 0, 2)
    });
    let (sent_packets, sent_bytes) = res.expect("finalise_prepared Ok");
    assert_eq!(sent_packets, 2, "2 of 4 staged frames were accepted");
    assert_eq!(sent_bytes, 128, "2 × 64-byte frames sent");
    assert_eq!(
        allocs, 0,
        "#4971: the TX retry tail must be allocation-free per drain pass \
         (revert to `retry_tail = Vec::new()` makes this > 0)"
    );
    // FIFO contract: staged idx 2,3 (enqueue_ns 3,4) are restored to the
    // FRONT of `pending` in ORIGINAL order, not reversed.
    let order: Vec<u64> = pending.iter().map(|r| r.enqueue_ns).collect();
    assert_eq!(order, vec![3, 4], "retry tail must preserve FIFO order");
}

// #4971: constructing an expected TX backpressure retry OUTCOME must
// not allocate — the reason is a `Copy` code, not a heap `String`.
// Driven through the real `transmit_batch` with an empty free-frame
// pool (the `no free TX frame available` retry), which recurs every
// drain pass under ring pressure.
//
// FAIL-ON-REVERT (assertion, NOT a build break — the test matches only
// `TxError::Retry(_)`, which compiles against both the `String` and the
// reason-code payload): reverting to `TxError::Retry("no free TX frame
// available".to_string())` heap-allocates the message on every pass, so
// the measured allocation count becomes > 0 → assertion RED.
#[test]
fn tx_retry_outcome_codes_4971() {
    use crate::afxdp::tx::test_support::{
        test_cos_fast_interfaces, test_cos_runtime_with_queues, test_queue_fast_path,
    };
    use crate::afxdp::types::TxRequest;

    let root = test_cos_runtime_with_queues(10_000_000, vec![]);
    let fast_interfaces = test_cos_fast_interfaces(
        42,
        42,
        0,
        vec![(0, test_queue_fast_path(false, 0, None, None))],
        None,
        None,
    );
    let fast_path = fast_interfaces.get(&42).expect("test fast path").clone();
    let mut binding = BindingWorker::new_for_cos_drain_test(0, 0, 42, root, fast_path);
    binding.telemetry.dbg_sendto_err = 100; // suppress wake eprintln

    // Force the NoFreeTxFrame retry: no free frames, one pending req.
    binding.tx_pipeline.free_tx_frames.clear();
    let mut pending = VecDeque::from([TxRequest {
        bytes: vec![0u8; 128],
        expected_ports: None,
        expected_addr_family: 0,
        expected_protocol: 0,
        flow_key: None,
        egress_ifindex: 42,
        cos_queue_id: None,
        dscp_rewrite: None,
        mirror_clone: false,
        overlap_admissions: None,
        enqueue_ns: 1,
    }]);
    let mut shared_recycles = Vec::with_capacity(8);

    // batch_size == 0 returns BEFORE consuming `pending`, so the same
    // input drives both the warm and the measured pass verbatim.
    let _ = transmit_batch(&mut binding, &mut pending, 0, &mut shared_recycles);
    let (res, allocs) = crate::test_alloc::count_allocs(|| {
        transmit_batch(&mut binding, &mut pending, 0, &mut shared_recycles)
    });
    assert!(
        matches!(res, Err(TxError::Retry(_))),
        "empty free_tx_frames must yield an expected TX retry outcome"
    );
    assert_eq!(
        allocs, 0,
        "#4971: constructing an expected TX retry outcome must not \
         allocate (revert to `Retry(String)` makes this > 0)"
    );
}

#[test]
fn cancelled_prepared_foreign_fill_without_sink_parks_masked_base_9900() {
    // #9900 F-092: a cross-slot Fill recycle with no shared sink parks in
    // the local free pool masked to its frame BASE — the stored recycle
    // offset is an RX addr (base + headroom), and planting it verbatim
    // would submit unaligned TX descs that the completion path must drop.
    let mut free_tx_frames = VecDeque::new();
    let mut pending_fill_frames = VecDeque::new();

    recycle_cancelled_prepared_offset_with_shared(
        &mut free_tx_frames,
        &mut pending_fill_frames,
        None,
        7,
        PreparedTxRecycle::FillOnSlotWithOffset {
            slot: 8,
            offset: 4096 + 256,
        },
        4096 + 252,
    );
    assert!(pending_fill_frames.is_empty());
    assert_eq!(free_tx_frames, VecDeque::from([4096]));

    // An already-aligned offset is unchanged (the mask is idempotent).
    recycle_cancelled_prepared_offset_with_shared(
        &mut free_tx_frames,
        &mut pending_fill_frames,
        None,
        7,
        PreparedTxRecycle::FillOnSlotWithOffset {
            slot: 8,
            offset: 8192,
        },
        8192,
    );
    assert_eq!(free_tx_frames, VecDeque::from([4096, 8192]));
}
