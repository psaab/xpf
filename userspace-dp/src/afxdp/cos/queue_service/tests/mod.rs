// Tests for afxdp/cos/queue_service/mod.rs. Split from a single 4384-line
// tests.rs into per-concern sibling submodules (#4665) to keep each file
// under the modularity-discipline LOC threshold. Pure test-code motion: no
// production code and no test logic changed. Shared imports, the epoch
// constant, and the cross-concern `waterfill_guarantee_rate_root` fixture
// live here and reach every submodule via `use super::*`.
//
// Submodules by concern (see each file's header):
//   selector  drain  wakeup  waterfill  sojourn  refund  submit
//   demand_mask_9365 (the exact-demand mask past queue index 64)

use super::*;
use crate::afxdp::types::EqualFlowTargetPolicy;
use crate::afxdp::FastMap;
use crate::afxdp::cos::admission::apply_cos_queue_flow_fair_promotion;
use crate::afxdp::cos::queue_ops::cos_queue_push_back;
use crate::afxdp::cos::tx_completion::COS_TIMER_WHEEL_TICK_NS;
use crate::afxdp::tx::test_support::*;
use crate::afxdp::types::{
    CoSQueueWaterfillCounters, ExactDemandQueueMask, SharedCoSExactBacklog, SharedCoSQueueLease,
    SharedCoSRootLease, V8RateMode, WorkerCoSInterfaceFastPath,
};
use crate::afxdp::worker::BindingWorker;
use crate::afxdp::{PROTO_TCP, UMEM_FRAME_SHIFT};
use std::sync::Arc;
// Relocated from a mid-file `use` that sat beside the drain TX-progress
// tests in the pre-split tests.rs (verbatim).
use crate::afxdp::types::{
    COS_FLOW_FAIR_BUCKETS, CoSQueueConfig, CoSQueueDropCounters, CoSQueueOwnerProfile, FlowRrRing,
};

const TEST_EPOCH_DURATION_NS: u64 = 200_000;

fn test_overlap_admissions_10285(
    tracker: &crate::fragment_overlap::OverlapTracker,
    ident: u32,
) -> crate::fragment_overlap::OverlapAdmissionTokens {
    let key = crate::fragment_overlap::OverlapKey {
        addr_family: libc::AF_INET as u8,
        src: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 61, 100)),
        dst: std::net::IpAddr::V4(std::net::Ipv4Addr::new(172, 16, 80, 200)),
        ident,
        protocol: PROTO_TCP,
        routing_domain: 0,
        ingress_zone: 0,
        fairness_origin: None,
    };
    let mut result = tracker.check_and_record_fragment_detailed(
        key,
        0,
        8,
        true,
        1_000 + ident as u64,
        &crate::fragment_overlap::FRAG_OVERLAP_DROPPED,
    );
    let admission = result.admission.take().expect("test overlap admission");
    crate::fragment_overlap::OverlapAdmissionTokens::new(
        tracker.clone(),
        Some(admission),
        None,
    )
}

fn attach_test_overlap_admission_10285(
    item: &mut crate::afxdp::types::CoSPendingTxItem,
    tracker: &crate::fragment_overlap::OverlapTracker,
    ident: u32,
) {
    let admissions = test_overlap_admissions_10285(tracker, ident);
    match item {
        crate::afxdp::types::CoSPendingTxItem::Local(req) => {
            req.overlap_admissions = Some(admissions);
        }
        crate::afxdp::types::CoSPendingTxItem::Prepared(req) => {
            req.overlap_admissions = Some(admissions);
        }
    }
}

/// Build a GuaranteeRate root with the ascending-by-rate vec populated
/// and every exact queue given abundant per-queue tokens so the only
/// gate is the Phase-1 byte budget.
fn waterfill_guarantee_rate_root(frac: f64) -> CoSInterfaceRuntime {
    let mut root = test_mixed_class_root_with_primed_queues();
    root.oversubscription_policy = CoSOversubscriptionPolicy::GuaranteeRate;
    root.oversubscription_guarantee_fraction = frac;
    root.exact_queues_by_rate_ascending = (0..root.queues.len())
        .filter(|&idx| root.queues[idx].config.exact && root.queues[idx].config.guarantee_enabled)
        .collect();
    root.exact_queues_by_rate_ascending
        .sort_by_key(|&idx| root.queues[idx].config.transmit_rate_bytes);
    for queue in &mut root.queues {
        if queue.config.exact {
            queue.hot.tokens = 128 * 1024;
        }
    }
    root
}

mod selector;
mod drain;
mod wakeup;
mod waterfill;
mod sojourn;
mod refund;
mod submit;
mod v_min_skip;
mod demand_mask_9365;
mod fairness;

// #13065 (source finding D1-14) FAIL-ON-REVERT modularity guard: every
// production .rs file at the top level of cos/queue_service/ must stay
// below the 800-LOC split ceiling the #13065 extraction established.
// The pre-split monolith was a single 2,249-LOC queue_service/mod.rs
// combining selection, waterfill, and settlement subsystems, which is
// where six of the CoS fairness defects in the source review were
// masked; re-growth past the ceiling must fail the suite instead of
// waiting for the repo-global heatmap refresh (whose lag fails nothing
// by design). Test files under tests/ are out of scope: the ceiling
// governs production code (docs/engineering-style.md, modularity
// discipline).
#[test]
fn queue_service_production_files_below_800_loc_13065() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/afxdp/cos/queue_service");
    let mut paths: Vec<std::path::PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .filter_map(|entry| {
            let path = entry.expect("queue_service dir entry").path();
            (path.is_file() && path.extension().is_some_and(|ext| ext == "rs")).then_some(path)
        })
        .collect();
    paths.sort();
    assert!(
        !paths.is_empty(),
        "fixture sanity: cos/queue_service/ must contain .rs files"
    );
    for path in paths {
        let loc = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
            .lines()
            .count();
        assert!(
            loc < 800,
            "{} is {} LOC — exceeds the 800-LOC queue_service split ceiling \
             (#13065); extract a sibling module instead of growing this file",
            path.display(),
            loc
        );
    }
}

// #17173 FAIL-ON-REVERT layering guard: the four CoS scheduler
// constants must live ONLY in cos/queue_service/settle.rs (next to
// cos_guarantee_quantum_bytes / cos_surplus_quantum_bytes) and must
// never reappear anywhere under tx/, where no code consumes them.
// Pre-fix they were defined in tx/drain/mod.rs, re-exported via
// tx/mod.rs, and imported back through the queue_service tx
// back-edge, contradicting its ring/binding/prepared-frame-only
// rationale. Also pin the exact values so a re-homing cannot
// silently retune the scheduler, and pin the tx import list so the
// constants cannot ride back in.
#[test]
fn cos_scheduler_constants_not_in_tx_17173() {
    // Value pins (bit-identical to the pre-move tx/drain definitions).
    assert_eq!(COS_GUARANTEE_VISIT_NS, 200_000);
    assert_eq!(COS_GUARANTEE_QUANTUM_MIN_BYTES, 1500);
    assert_eq!(COS_GUARANTEE_QUANTUM_MAX_BYTES, 512 * 1024);
    assert_eq!(COS_SURPLUS_ROUND_QUANTUM_BYTES, 1500);
    const NAMES: [&str; 4] = [
        "COS_GUARANTEE_VISIT_NS",
        "COS_GUARANTEE_QUANTUM_MIN_BYTES",
        "COS_GUARANTEE_QUANTUM_MAX_BYTES",
        "COS_SURPLUS_ROUND_QUANTUM_BYTES",
    ];
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    // (a) No token anywhere under tx/ (definition, re-export, use,
    // doc comment). The tx/README line is docs, handled in the PR;
    // only .rs sources are scanned here.
    let tx_dir = manifest.join("src/afxdp/tx");
    let mut stack = vec![tx_dir];
    let mut scanned = 0usize;
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()))
        {
            let path = entry.expect("tx dir entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                scanned += 1;
                let src = std::fs::read_to_string(&path)
                    .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
                for name in NAMES {
                    assert!(
                        !src.contains(name),
                        "{} reappeared in {} (#17173: constants belong in \
                         cos/queue_service/settle.rs, not tx/)",
                        name,
                        path.display()
                    );
                }
            }
        }
    }
    assert!(
        scanned > 10,
        "fixture sanity: tx/ scan must cover production sources, got {scanned}"
    );
    // (b) Single definition site: exactly one `const NAME` per name
    // in settle.rs, and no other queue_service production file
    // defines one (uses via `use super::*` are not definitions).
    let qs_dir = manifest.join("src/afxdp/cos/queue_service");
    let settle = std::fs::read_to_string(qs_dir.join("settle.rs"))
        .expect("read cos/queue_service/settle.rs");
    for name in NAMES {
        assert_eq!(
            settle.matches(&format!("const {name}")).count(),
            1,
            "{name} must be defined exactly once in settle.rs (#17173)"
        );
    }
    // (c) The queue_service tx back-edge import must not carry the
    // constants again: extract the `use crate::afxdp::tx::{...};`
    // block from mod.rs and reject any scheduler constant inside.
    let mod_rs = std::fs::read_to_string(qs_dir.join("mod.rs"))
        .expect("read cos/queue_service/mod.rs");
    let tx_import = mod_rs
        .split("use crate::afxdp::tx::{")
        .nth(1)
        .expect("queue_service must keep its tx back-edge import (#17173 guard anchor)")
        .split("};")
        .next()
        .expect("tx import block must terminate");
    for name in NAMES {
        assert!(
            !tx_import.contains(name),
            "{name} is back on the crate::afxdp::tx import in \
             cos/queue_service/mod.rs (#17173)"
        );
    }
}
