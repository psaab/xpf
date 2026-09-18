// Tests for afxdp/binding_state/. Split from a single ~1765-line
// tests.rs into per-concern sibling submodules (#4667) to keep each
// file under the modularity-discipline LOC threshold; relocated from
// `umem/tests/` to `binding_state/tests/` in #6436 when the
// binding-state cluster moved out of the UMEM module. Pure test-code
// motion: no production code and no test logic changed. The shared
// `use` header and the cross-concern `test_tx_request_for_inbox`
// fixture live here and reach every submodule via `use super::*`.
//
// Submodules by concern (see each file):
//   tx_inbox  latency_buckets  snapshot_propagation
//   tx_submit_latency  tx_kick_latency  debug_state

use super::super::flow_cache::ACTIVE_WINDOW_EPOCHS;
use crate::afxdp::types::EqualFlowTargetPolicy;
use super::*;

fn test_tx_request_for_inbox(payload: u8) -> TxRequest {
    TxRequest {
        bytes: vec![payload; 16],
        expected_ports: None,
        expected_addr_family: libc::AF_INET as u8,
        expected_protocol: 6,
        flow_key: None,
        egress_ifindex: 0,
        cos_queue_id: None,
        dscp_rewrite: None,
        mirror_clone: false,
        overlap_admissions: None,
        enqueue_ns: 0,
    }
}

mod tx_inbox;
mod latency_buckets;
mod snapshot_propagation;
mod tx_submit_latency;
mod tx_kick_latency;
mod debug_state;
