//! #18534 fold: the ct-slice fabric swap derives a worker-local forwarding
//! snapshot (the published tables with `fabrics` replaced). Per-flow memos
//! key on `ForwardingState::publish_epoch`, so the derived copy must not
//! keep the published snapshot's identity — and must not drop to 0 either,
//! which would disable every memo until the next coordinator publish. These
//! cells drive the production `run_ct_slice` and turn RED if the swap stops
//! restamping the copy.

use super::ct_slice::run_ct_slice;
use super::*;
use crate::afxdp::types::LOCAL_DERIVATION_EPOCH_BIT;

const PUBLISHED_EPOCH_18534: u64 = 7;

fn live_fabric_18534(peer_last_octet: u8) -> FabricLink {
    FabricLink {
        parent_ifindex: 41,
        overlay_ifindex: 42,
        peer_addr: IpAddr::V4(std::net::Ipv4Addr::new(10, 99, 0, peer_last_octet)),
        peer_mac: [0x02, 0xbf, 0x72, 0x00, 0x00, peer_last_octet],
        local_mac: [0x02, 0xbf, 0x72, 0x00, 0x00, 0x01],
        up: true,
        link_authenticated: false,
    }
}

/// Runs one production ct slice at t=0 (no conntrack refresh is due, so
/// the BPF fds are never touched) against `forwarding` with `live` as the
/// coordinator-published fabric set.
fn run_fabric_swap_18534(forwarding: &mut Arc<ForwardingState>, live: Vec<FabricLink>) {
    let mut sessions = crate::session::SessionTable::new();
    let shared_fabrics = Arc::new(ArcSwap::from_pointee(live));
    let wg_queues = Arc::new(ArcSwap::from_pointee(std::collections::BTreeMap::new()));
    let mut wg_batch = crate::afxdp::wg_uncovered_forward::WgUncoveredInjectedBatch::new();
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let (mut cursor, mut cycle_start, mut last_slice, mut high_water, mut est_cursor) =
        (0usize, 0u64, 0u64, 0u64, 0usize);
    run_ct_slice(
        &mut sessions,
        forwarding,
        0,
        -1,
        -1,
        &mut cursor,
        &mut cycle_start,
        &mut last_slice,
        &mut high_water,
        &shared_fabrics,
        &wg_queues,
        &mut wg_batch,
        0,
        &shared_sessions,
        &shared_forward_wire_sessions,
        &mut est_cursor,
    );
}

fn published_forwarding_18534() -> Arc<ForwardingState> {
    let mut state = ForwardingState::default();
    state.publish_epoch = PUBLISHED_EPOCH_18534;
    Arc::new(state)
}

#[test]
fn fabric_swap_restamps_the_derived_snapshot_18534() {
    let mut forwarding = published_forwarding_18534();
    let live = vec![live_fabric_18534(2)];
    run_fabric_swap_18534(&mut forwarding, live.clone());
    assert_eq!(forwarding.fabrics, live, "precondition: the swap ran");
    let epoch = forwarding.publish_epoch;
    assert_ne!(
        epoch, PUBLISHED_EPOCH_18534,
        "a derived snapshot kept the published identity; memos computed \
         against the published contents would be read against these"
    );
    assert_ne!(epoch, 0, "a derived snapshot must keep memos enabled");
    assert_ne!(
        epoch & LOCAL_DERIVATION_EPOCH_BIT,
        0,
        "local epochs live in the range the coordinator never reaches"
    );
}

#[test]
fn successive_fabric_swaps_never_share_an_epoch_18534() {
    let mut forwarding = published_forwarding_18534();
    run_fabric_swap_18534(&mut forwarding, vec![live_fabric_18534(2)]);
    let first = forwarding.publish_epoch;
    run_fabric_swap_18534(&mut forwarding, vec![live_fabric_18534(3)]);
    assert_eq!(forwarding.fabrics, vec![live_fabric_18534(3)]);
    assert_ne!(forwarding.publish_epoch, first);
    assert_ne!(forwarding.publish_epoch & LOCAL_DERIVATION_EPOCH_BIT, 0);
}

#[test]
fn unchanged_fabrics_keep_the_published_snapshot_18534() {
    let mut state = ForwardingState::default();
    state.publish_epoch = PUBLISHED_EPOCH_18534;
    state.fabrics = vec![live_fabric_18534(2)];
    let mut forwarding = Arc::new(state);
    let before = Arc::as_ptr(&forwarding);
    run_fabric_swap_18534(&mut forwarding, vec![live_fabric_18534(2)]);
    assert_eq!(Arc::as_ptr(&forwarding), before, "no derivation, no restamp");
    assert_eq!(forwarding.publish_epoch, PUBLISHED_EPOCH_18534);
}
