// Tests for afxdp/cos/builders.rs — relocated from inline
// `#[cfg(test)] mod tests` to keep builders.rs under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "builders_tests.rs"]` from builders.rs.

use super::*;
use crate::afxdp::tx::test_support::*;
use crate::afxdp::types::{CoSQueueConfig, FastMap};

// #915: build_cos_interface_runtime must propagate the
// surplus_sharing flag from CoSQueueConfig to the runtime.
// Test both true and false to catch a copy-by-default regression.
#[test]
fn build_cos_interface_runtime_propagates_surplus_sharing() {
    let runtime = build_cos_interface_runtime(
        &CoSInterfaceConfig {
            shaping_rate_bytes: 10_000_000_000 / 8,
            burst_bytes: 256 * 1024,
            default_queue: 4,
            dscp_classifier: String::new(),
            ieee8021_classifier: String::new(),
            dscp_queue_by_dscp: [u8::MAX; 64],
            ieee8021_queue_by_pcp: [u8::MAX; 8],
            queue_by_forwarding_class: FastMap::default(),
            queues: vec![
                CoSQueueConfig {
                    queue_id: 4,
                    forwarding_class: "iperf-a".into(),
                    priority: 5,
                    transmit_rate_bytes: 1_000_000_000 / 8,
                    exact: true,
                    surplus_sharing: true, // opt-in
                    surplus_weight: 1,
                    buffer_bytes: COS_MIN_BURST_BYTES,
                    dscp_rewrite: None,
                },
                CoSQueueConfig {
                    queue_id: 5,
                    forwarding_class: "iperf-b".into(),
                    priority: 5,
                    transmit_rate_bytes: 10_000_000_000 / 8,
                    exact: true,
                    surplus_sharing: false, // explicit hard-cap, no opt-in
                    surplus_weight: 1,
                    buffer_bytes: COS_MIN_BURST_BYTES,
                    dscp_rewrite: None,
                },
            ],
        },
        1_000_000_000,
    );
    let q4 = runtime.queues.iter().find(|q| q.queue_id == 4).unwrap();
    let q5 = runtime.queues.iter().find(|q| q.queue_id == 5).unwrap();
    assert!(q4.surplus_sharing,
        "queue_id=4 expected surplus_sharing=true after copy");
    assert!(!q5.surplus_sharing,
        "queue_id=5 expected surplus_sharing=false (default) after copy");
    // Both queues remain exact so #1183 useful-state gate doesn't strip them.
    assert!(q4.exact && q5.exact);
}

#[test]
fn build_cos_interface_runtime_starts_exact_queue_with_zero_local_tokens() {
    let runtime = build_cos_interface_runtime(
        &CoSInterfaceConfig {
            shaping_rate_bytes: 25_000_000,
            burst_bytes: 256 * 1024,
            default_queue: 5,
            dscp_classifier: String::new(),
            ieee8021_classifier: String::new(),
            dscp_queue_by_dscp: [u8::MAX; 64],
            ieee8021_queue_by_pcp: [u8::MAX; 8],
            queue_by_forwarding_class: FastMap::default(),
            queues: vec![CoSQueueConfig {
                queue_id: 5,
                forwarding_class: "iperf-b".into(),
                priority: 5,
                transmit_rate_bytes: 10_000_000,
                exact: true,
                surplus_sharing: false,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            }],
        },
        1_000_000_000,
    );

    assert_eq!(runtime.queues[0].tokens, 0);
    assert_eq!(runtime.queues[0].last_refill_ns, 0);
}

#[test]
fn build_cos_interface_runtime_leaves_flow_hash_seed_zero_until_promotion() {
    // The seed is drawn in `ensure_cos_interface_runtime`, not in
    // `build_cos_interface_runtime`. Pin this so a refactor that
    // accidentally moves the getrandom call into the builder is
    // caught: builder-time seeding would burn a syscall per non-
    // flow-fair queue and would also drift the struct doc invariant
    // that non-flow-fair queues keep seed=0.
    let root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![
            CoSQueueConfig {
                queue_id: 4,
                forwarding_class: "iperf-a".into(),
                priority: 5,
                transmit_rate_bytes: 1_000_000_000 / 8,
                exact: true,
                surplus_sharing: false,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            },
            CoSQueueConfig {
                queue_id: 5,
                forwarding_class: "iperf-b".into(),
                priority: 5,
                transmit_rate_bytes: 10_000_000_000 / 8,
                exact: true,
                surplus_sharing: false,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            },
        ],
    );
    for queue in &root.queues {
        assert!(!queue.flow_fair);
        assert_eq!(queue.flow_hash_seed, 0);
    }
}

#[test]
fn build_cos_interface_runtime_zero_shaping_rate_starts_with_full_root_tokens() {
    // #916: transparent root. When the interface has no shaping-rate
    // configured, root.tokens MUST start at the burst cap (not 0)
    // so the very first packet doesn't see an empty root bucket
    // before the first top-up call.
    let runtime = build_cos_interface_runtime(
        &CoSInterfaceConfig {
            shaping_rate_bytes: 0, // <- transparent root
            burst_bytes: 256 * 1024,
            default_queue: 0,
            dscp_classifier: String::new(),
            ieee8021_classifier: String::new(),
            dscp_queue_by_dscp: [u8::MAX; 64],
            ieee8021_queue_by_pcp: [u8::MAX; 8],
            queue_by_forwarding_class: FastMap::default(),
            queues: vec![CoSQueueConfig {
                queue_id: 0,
                forwarding_class: "best-effort".into(),
                priority: 5,
                transmit_rate_bytes: 1_000_000,
                exact: false,
                surplus_sharing: false,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            }],
        },
        1_000_000_000,
    );
    assert!(
        runtime.tokens >= 64 * 1500,
        "transparent root must start with full bucket (>= COS_MIN_BURST_BYTES), got {}",
        runtime.tokens,
    );
    assert_eq!(runtime.shaping_rate_bytes, 0);
}

#[test]
fn build_cos_interface_runtime_zero_queue_rate_starts_with_full_queue_tokens() {
    // #916: transparent queue. When transmit_rate_bytes == 0
    // (scheduler had no rate AND parent root has no shaping rate),
    // queue.tokens MUST start at the buffer cap so the queue
    // can drain immediately. Otherwise an exact queue with rate=0
    // starts at 0 and waits forever for a refill that never arrives.
    let runtime = build_cos_interface_runtime(
        &CoSInterfaceConfig {
            shaping_rate_bytes: 0,
            burst_bytes: 256 * 1024,
            default_queue: 0,
            dscp_classifier: String::new(),
            ieee8021_classifier: String::new(),
            dscp_queue_by_dscp: [u8::MAX; 64],
            ieee8021_queue_by_pcp: [u8::MAX; 8],
            queue_by_forwarding_class: FastMap::default(),
            queues: vec![CoSQueueConfig {
                queue_id: 0,
                forwarding_class: "best-effort".into(),
                priority: 5,
                transmit_rate_bytes: 0, // <- transparent queue
                exact: false,
                surplus_sharing: false,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            }],
        },
        1_000_000_000,
    );
    let queue = &runtime.queues[0];
    assert!(
        queue.tokens >= 64 * 1500,
        "transparent queue must start with full bucket (>= COS_MIN_BURST_BYTES), got {}",
        queue.tokens,
    );
    assert_eq!(queue.transmit_rate_bytes, 0);
}
