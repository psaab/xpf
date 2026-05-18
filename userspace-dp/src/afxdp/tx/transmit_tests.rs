// Tests for afxdp/tx/transmit.rs — relocated from inline
// `#[cfg(test)] mod tests` to keep transmit.rs under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "transmit_tests.rs"]` from transmit.rs.

use super::*;
use crate::afxdp::PROTO_TCP;

#[test]
fn remember_prepared_recycle_tracks_only_shared_fill_recycles() {
    let mut in_flight_prepared_recycles = FastMap::default();

    remember_prepared_recycle(
        &mut in_flight_prepared_recycles,
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
        },
    );
    remember_prepared_recycle(
        &mut in_flight_prepared_recycles,
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
        },
    );
    remember_prepared_recycle(
        &mut in_flight_prepared_recycles,
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
