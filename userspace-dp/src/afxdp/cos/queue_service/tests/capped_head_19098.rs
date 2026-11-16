//! #19098 (Codex 1 on the #19075 design): the surplus selector budgets a flow-fair
//! queue's UNCAPPED head (`cos_queue_front`, the lowest-finish bucket) while
//! the builder takes the CAPPED head (`cos_queue_peek_min_bucket` with the
//! #1229 per-bucket target). When they differ and the capped head is the
//! larger, the visit's surplus deficit and root grant cover the head the
//! builder will not take, the build returns nothing, and the next drain
//! finds the same state. Pre-existing and independent of #19075's credit
//! fix: it binds through the surplus deficit, not root credit.

use super::cos_drain_sim::*;
use super::*;
use crate::afxdp::cos::builders::build_cos_interface_runtime;
use crate::afxdp::types::CoSInterfaceConfig;

/// A shaped root at `shaping_bytes` with no exact class and one best-effort
/// queue whose transmit rate is the shaping rate (the builder's fallback for
/// a class with no transmit rate), one worker, its own root lease.
fn one_worker_best_effort_root(shaping_bytes: u64, burst: u64) -> BindingWorker {
    let root_lease = Arc::new(SharedCoSRootLease::new(shaping_bytes, burst, 1));
    let mut fast = test_cos_fast_interfaces(
        IFX,
        IFX,
        NONEXACT_QUEUE,
        vec![(NONEXACT_QUEUE, test_queue_fast_path(true, 0, None, None))],
        None,
        Some(root_lease.clone()),
    );
    let fast = fast.remove(&IFX).expect("fast path");
    let mut root = build_cos_interface_runtime(
        &CoSInterfaceConfig {
            queue_id_bitmap: [0; 4],
            shaping_rate_bytes: shaping_bytes,
            burst_bytes: burst,
            default_queue: NONEXACT_QUEUE,
            dscp_classifier: String::new(),
            ieee8021_classifier: String::new(),
            inet_precedence_classifier: String::new(),
            dscp_queue_by_dscp: [u8::MAX; 64],
            ieee8021_queue_by_pcp: [u8::MAX; 8],
            inet_precedence_queue_by_prec: [u8::MAX; 8],
            queue_by_forwarding_class: FastMap::default(),
            queues: vec![queue_config(NONEXACT_QUEUE, shaping_bytes, false)],
            oversubscription_policy: CoSOversubscriptionPolicy::GuaranteeRate,
            oversubscription_guarantee_fraction: 0.7,
            priority_low_min_share_bytes: 0,
        },
        0,
    );
    root.shared_root_lease = Some(root_lease);
    apply_cos_queue_flow_fair_promotion(&mut root, &fast.queue_fast_path, 0);
    BindingWorker::new_for_cos_drain_test(0, 0, IFX, root, fast)
}

/// Codex 1: mixed head sizes and mixed observed rates, through the
/// production enqueue and drain. One worker on a 1 Gb/s root (96 KB burst)
/// with no exact class. Flow C promotes the best-effort queue to flow-fair
/// (a second flow) and drains away. Flow A (1,500-byte packets) then runs
/// alone for 20 ms, so its bucket's observed rate reaches about the root's
/// 1 Gb/s. Flow B (3,000-byte packets) joins: with two active buckets the
/// per-bucket target is 0.5 Gb/s, A is over it and B (observed 0) is under
/// it, so the builder's capped selection takes B. A's head finishes first
/// (A's head was queued before B arrived), so the selector reads A's
/// 1,500-byte head: it banks surplus deficit only until it covers 1,500
/// bytes and budgets at most 2,999. B never fits, nothing is sent, A's
/// observed rate never decays (it moves only on TX), and the next drain
/// finds the same state.
///
/// Property: after B joins, the queue keeps sending (no gap over 10 ms) and
/// B is served.
#[test]

fn a_capped_head_larger_than_the_selected_head_still_drains_19098() {
    const SHAPING: u64 = GBIT;
    const A_LEN: usize = 1_500;
    const B_LEN: usize = 3_000;
    const C_LEN: usize = 1_500;
    let mut binding = one_worker_best_effort_root(SHAPING, 96_000);
    let mut descs: Vec<crate::xsk_ffi::XdpDesc> = Vec::new();
    let mut recycles = Vec::new();
    let start = 2_000_000_000u64;
    let b_joins = start + 25_000_000;
    let end = b_joins + 30_000_000;
    let (port_a, port_b, port_c) = (40_001u16, 40_002u16, 40_003u16);
    let mut c_left = 4usize;
    let mut a_bytes_before_b = 0u64;
    let mut b_sent = 0u64;
    let mut a_sent_after = 0u64;
    let mut last_send = b_joins;
    let mut longest_gap = 0u64;
    let mut premise: Option<(u16, u64, u64)> = None;
    let mut now = start;
    while now < end {
        // Keep A (and B once it has joined) backlogged; C sends 4 packets.
        while queued_bytes(&binding, 0) < 24 * B_LEN as u64 {
            let item = if c_left > 0 {
                c_left -= 1;
                sim_item_len(NONEXACT_QUEUE, port_c, now, C_LEN)
            } else {
                sim_item_len(NONEXACT_QUEUE, port_a, now, A_LEN)
            };
            if !sim_enqueue(&mut binding, NONEXACT_QUEUE, item) {
                break;
            }
        }
        if now >= b_joins {
            if premise.is_none() {
                for _ in 0..8 {
                    let item = sim_item_len(NONEXACT_QUEUE, port_b, now, B_LEN);
                    if !sim_enqueue(&mut binding, NONEXACT_QUEUE, item) {
                        break;
                    }
                }
                let queue = &binding.cos.cos_interfaces[&IFX].queues[0];
                let ff = queue
                    .flow_fair_state
                    .as_ref()
                    .expect("premise: promoted to flow-fair");
                let max_observed = ff
                    .flow_bucket_observed_bps
                    .iter()
                    .copied()
                    .max()
                    .unwrap_or(0);
                premise = Some((
                    ff.active_flow_buckets,
                    max_observed,
                    super::super::drain::compute_drain_target_bps(queue),
                ));
            }
        }
        for _ in 0..8 {
            let _ = drain_shaped_tx(&mut binding, now, &mut recycles);
            descs.clear();
            binding.xsk.tx.take_submitted_for_test(&mut descs);
            let sent_now: u64 = descs.iter().map(|d| u64::from(d.len)).sum();
            for desc in &descs {
                if now >= b_joins {
                    if desc.len as usize == B_LEN {
                        b_sent += u64::from(desc.len);
                    } else {
                        a_sent_after += u64::from(desc.len);
                    }
                } else if desc.len as usize == A_LEN {
                    a_bytes_before_b += u64::from(desc.len);
                }
                binding.xsk.device.push_comp_for_test(desc.addr);
            }
            let _ = crate::afxdp::tx::reap_tx_completions(&mut binding, &mut recycles);
            recycles.clear();
            if sent_now == 0 {
                break;
            }
            if now >= b_joins {
                last_send = now;
            }
        }
        if now >= b_joins {
            longest_gap = longest_gap.max(now - last_send);
        }
        now += 1_000;
    }
    let (buckets, observed, target) = premise.expect("B joined");
    let summary = format!(
        "A before B joined {:.2} Gb/s; after: A {:.2} Gb/s, B {:.2} Gb/s, longest gap {} us; \
         at B's arrival: {buckets} active buckets, max observed {observed} b/s, target {target} b/s",
        a_bytes_before_b as f64 * 8.0 / 25_000_000.0,
        a_sent_after as f64 * 8.0 / 30_000_000.0,
        b_sent as f64 * 8.0 / 30_000_000.0,
        longest_gap / 1_000,
    );
    eprintln!("CAPPED-HEAD | {summary}");
    assert!(
        buckets >= 2,
        "premise: A and B in separate buckets; {summary}"
    );
    assert!(
        observed > target,
        "premise: A's bucket over the per-bucket target; {summary}"
    );
    assert!(
        longest_gap <= MAX_UNSERVED_NS,
        "the queue went {} ms without a send after B joined; {summary}",
        longest_gap / 1_000_000
    );
    assert!(b_sent > 0, "B was never served; {summary}");
}
