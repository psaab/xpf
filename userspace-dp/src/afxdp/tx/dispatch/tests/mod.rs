// Tests for afxdp/tx/dispatch/mod.rs. Split from a single ~1565-line
// dispatch_tests.rs into per-concern sibling submodules (#4670) to keep each
// file under the modularity-discipline LOC threshold. Pure test-code motion:
// no production code and no test logic changed. The shared `use` header and
// the fixtures used by more than one concern live here and reach every
// submodule via `use super::*`.
//
// Submodules by concern (see each file's header):
//   segmentation  shared_recycle  enqueue_failure  ptb  cos_shared_exact
//
// Shared fixtures kept here (each used by 2+ concern submodules):
//   test_forwarding_with_egress_mtu  test_forwarding_decision_to_bound_ifindex
//   test_live_forward_request_for_frame  ingress_recycled_count

use super::*;
use crate::afxdp::tx::test_support::{build_ipv4_test_packet, test_session_key};
use crate::test_zone_ids::*;
use arc_swap::ArcSwap;
use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::Ordering;
use std::sync::mpsc::SyncSender;
use std::sync::{Arc, Mutex};

fn test_forwarding_with_egress_mtu(mtu: usize) -> ForwardingState {
    let mut forwarding = ForwardingState::default();
    forwarding.egress.insert(
        80,
        EgressInterface {
            bind_ifindex: 11,
            vlan_id: 80,
            mtu,
            src_mac: [0; 6],
            zone_id: TEST_WAN_ZONE_ID,
            redundancy_group: 0,
            primary_v4: None,
            primary_v6: None,
        },
    );
    forwarding
}

fn test_forwarding_decision_to_bound_ifindex(tx_ifindex: i32) -> SessionDecision {
    SessionDecision { resolution: ForwardingResolution {
        disposition: ForwardingDisposition::ForwardCandidate,
        local_ifindex: 0,
        egress_ifindex: 80,
        tx_ifindex,
        tunnel_endpoint_id: 0,
        next_hop: None,
        neighbor_mac: Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
        src_mac: Some([0x02, 0xbf, 0x72, 0x16, 0x00, 0x01]),
        tx_vlan_id: 0,
    }, nat: NatDecision::default(), install_table_domain: 0, install_table_check: 0 }
}

fn test_live_forward_request_for_frame(
    frame_len: usize,
    decision: SessionDecision,
) -> PendingForwardRequest {
    PendingForwardRequest {
        target_ifindex: decision.resolution.tx_ifindex,
        target_binding_index: None,
        ingress_queue_id: 0,
        desc: XdpDesc {
            addr: 0,
            len: frame_len as u32,
            options: 0,
        },
        frame: PendingForwardFrame::Live,
        meta: ForwardPacketMeta {
            ingress_ifindex: 11,
            l3_offset: 14,
            l4_offset: 34,
            pkt_len: frame_len as u16,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            ..ForwardPacketMeta::default()
        },
        decision,
        apply_nat_on_fabric: false,
        expected_ports: None,
        flow_key: Some(test_session_key(12345, 443)),
        nat64_reverse: None,
        overlap_admissions: None,
        cos_queue_id: None,
        dscp_rewrite: None,
        cos_tx_selection_resolved: true,
    }
}

/// Count ingress descriptors returned to circulation: those submitted to the
/// fill ring plus any still queued in `pending_fill_frames`. Each forwarded
/// request must contribute exactly one — 0 is a leak, 2 is a double-recycle.
fn ingress_recycled_count(ingress: &BindingWorker) -> usize {
    ingress.xsk.device.pending() as usize + ingress.tx_pipeline.pending_fill_frames.len()
}

mod segmentation;
mod shared_recycle;
mod enqueue_failure;
mod ptb;
mod cos_shared_exact;
mod nat64_attribution_6922;
mod ipsec_selector_fence_10683;
