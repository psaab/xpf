// Tests for afxdp/tx/drain.rs — relocated from inline
// `#[cfg(test)] mod tests` to keep drain.rs under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "drain_tests.rs"]` from drain.rs.

use super::*;

/// #784 Codex review regression pin: mixed-head deque scan.
///
/// The first revision of `drop_cos_bound_local_leftovers` did
/// a head-peek fast-exit: if the deque's front item had
/// `cos_queue_id.is_none()`, the function returned before
/// scanning. That let CoS-bound items LATER in the deque
/// escape to the unshaped `transmit_batch` backup path,
/// bypassing the CoS cap — the exact #760 bypass this filter
/// was designed to close.
///
/// This test constructs a mixed-head deque
/// `[non-cos, cos-bound, non-cos, cos-bound]` and verifies
/// every cos-bound item is either rescued or dropped (NEVER
/// left in the deque), while non-cos items are preserved for
/// the downstream backup transmit path.
///
/// If this test ever relaxes to allow cos-bound items in the
/// survivor set, the #760 cap bypass returns. Adversarial
/// reviewers MUST reject PRs that weaken this.
#[test]
fn partition_cos_bound_local_scans_mixed_head_deque() {
    // Build a pending deque with a NON-CoS head followed by
    // a mix of CoS-bound and non-CoS items. Codex flagged
    // the pre-refactor head-peek as HIGH severity — this is
    // the regression pin.
    let non_cos = |payload: u8| TxRequest {
        bytes: vec![payload; 64],
        expected_ports: None,
        expected_addr_family: libc::AF_INET as u8,
        expected_protocol: PROTO_TCP,
        flow_key: None,
        egress_ifindex: 99,
        cos_queue_id: None,
        dscp_rewrite: None,
    };
    let cos_bound = |payload: u8| TxRequest {
        bytes: vec![payload; 64],
        expected_ports: None,
        expected_addr_family: libc::AF_INET as u8,
        expected_protocol: PROTO_TCP,
        flow_key: None,
        egress_ifindex: 14,
        cos_queue_id: Some(4),
        dscp_rewrite: None,
    };
    let mut pending: VecDeque<TxRequest> = VecDeque::from([
        non_cos(1),
        cos_bound(2),
        non_cos(3),
        cos_bound(4),
        non_cos(5),
    ]);
    // Rescue stub: always fails (returns Err) so every
    // cos-bound item falls through to drop. Verifies the
    // scan covers the WHOLE deque, not just the head.
    let (dropped, dropped_bytes) = partition_cos_bound_local_with_rescue(&mut pending, Err);
    assert_eq!(
        dropped, 2,
        "both cos-bound items must be dropped (scan covers tail)"
    );
    assert_eq!(dropped_bytes, 128, "2 × 64 bytes dropped");
    // Survivors: only the 3 non-CoS items, in original order.
    let survivors: Vec<u8> = pending.iter().map(|r| r.bytes[0]).collect();
    assert_eq!(survivors, vec![1, 3, 5]);
}

/// #784 companion: rescue path pins. When `try_rescue` returns
/// Ok, items are consumed (rescued) — they must NOT remain in
/// the survivor set. Only items that actually fail rescue
/// count toward the drop.
#[test]
fn partition_cos_bound_local_rescues_when_try_rescue_ok() {
    let non_cos = TxRequest {
        bytes: vec![0xAA; 64],
        expected_ports: None,
        expected_addr_family: libc::AF_INET as u8,
        expected_protocol: PROTO_TCP,
        flow_key: None,
        egress_ifindex: 99,
        cos_queue_id: None,
        dscp_rewrite: None,
    };
    let cos_bound = TxRequest {
        bytes: vec![0xBB; 64],
        expected_ports: None,
        expected_addr_family: libc::AF_INET as u8,
        expected_protocol: PROTO_TCP,
        flow_key: None,
        egress_ifindex: 14,
        cos_queue_id: Some(4),
        dscp_rewrite: None,
    };
    let mut pending: VecDeque<TxRequest> = VecDeque::from([non_cos, cos_bound]);
    // Rescue always succeeds — CoS items must NOT count as drops.
    let (dropped, dropped_bytes) = partition_cos_bound_local_with_rescue(&mut pending, |_| Ok(()));
    assert_eq!(dropped, 0);
    assert_eq!(dropped_bytes, 0);
    // Survivor set: only the non-CoS item (rescued CoS item
    // was consumed by try_rescue closure).
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].bytes[0], 0xAA);
}

#[test]
fn process_pending_queue_in_place_preserves_failed_item_order() {
    let mut pending = VecDeque::from([1u8, 2, 3, 4]);

    process_pending_queue_in_place(&mut pending, |item| match item {
        1 | 3 => Ok(()),
        other => Err(other),
    });

    assert_eq!(pending.into_iter().collect::<Vec<_>>(), vec![2, 4]);
}

#[test]
fn shaped_drain_entry_guard_skips_configured_idle_binding() {
    assert!(
        !has_queued_cos_work(0, 4),
        "configured-but-idle bindings must not enter drain_shaped_tx"
    );
}

#[test]
fn shaped_drain_entry_guard_preserves_nonempty_service_path() {
    assert!(
        has_queued_cos_work(1, 4),
        "queued CoS work must still enter drain_shaped_tx for service and lease progress"
    );
}

#[test]
fn shaped_drain_entry_guard_requires_interface_order() {
    assert!(
        !has_queued_cos_work(1, 0),
        "bindings without an interface order cannot make shaped-drain progress"
    );
}
