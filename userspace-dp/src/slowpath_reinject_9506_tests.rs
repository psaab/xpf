//! #9506 S5: hermetic tests for the q0 REINJECT ACK/commit primitive.
//!
//! RED-then-GREEN: written before the implementation; every test failed
//! (unresolved items) until it landed. Hermetic: no TUN devices, no threads,
//! no filesystem sockets (socket-loopback tests live in
//! `server/reinject_9506_tests.rs` and use `UnixStream::pair`).
//!
//! Frozen contract under test (parent steer + r6 §3.2):
//! - `ReinjectLease { permit_epoch, queue_epoch, request_id }`, request_id
//!   nonzero, Go-monotonic per pipeline.
//! - Binary wire: u32 BE len (1 + payload) + u8 type + payload;
//!   SUBMIT_BATCH=1, CANCEL=2, ADMIT=11, COMPLETE=12; caps n<=64,
//!   data_len<=65535, msg<=1MB.
//! - Outcomes: written/stale/cancelled/refused/uncertain; uncertain never
//!   retried; ACK/completion only after a definitive write outcome.
//! - N_live=16384 aggregate (queued + write-started + unacked); reserve at
//!   submit-admission, release at terminal drain (NOT per-state).
//! - Per-flow FIFO drain on submitter-provided u64 flow_tag; other flows
//!   progress behind a stuck head.
//! - Cancel: by ids and/or permit/queue scope; permit-scope closes permit
//!   authority monotonically (no reopen); empty scope is a no-op.
//! - Legacy lease-None path unchanged, no completion tracking.

use super::*;
use crate::afxdp::ipsec_inner_queue::{
    reason as ipsec_reason, IpsecInnerVerdict, IPSEC_INNER_SLAB_CAP,
};
use std::sync::Arc;

const PERMIT: u64 = 7;
const QEPOCH: u64 = 11;

fn open_core() -> Arc<ReinjectCore> {
    let core = ReinjectCore::new_shared();
    core.publish_epochs(PERMIT, &[(1, QEPOCH), (2, 13)]);
    core
}

fn lease(id: u64) -> ReinjectLease {
    ReinjectLease {
        permit_epoch: PERMIT,
        queue_epoch: QEPOCH,
        queue_number: 1,
        request_id: id,
    }
}

fn frame(id: u64, flow_tag: u64, len: usize) -> SubmitFrame {
    SubmitFrame {
        lease: lease(id),
        flow_tag,
        flags: 0,
        origin: CaptureOrigin::inet_forward(42, "owner", "stn"),
        bytes: vec![0x45u8; len],
        snapshot_generation: 1,
        config_generation: 2,
        fib_generation: 3,
        zone_id: 4,
        if_id: 5,
    }
}

fn written(bytes: u32) -> TransferVerdict {
    TransferVerdict::Written { bytes }
}
fn refused() -> TransferVerdict {
    TransferVerdict::Refused {
        reason: "test-refused".to_string(),
    }
}
fn uncertain() -> TransferVerdict {
    TransferVerdict::Uncertain {
        reason: "test-uncertain".to_string(),
    }
}

#[test]
fn ipsec_inner_verdict_bridge_terminalizes_deny_and_would_permit() {
    let core = open_core();
    assert!(core.admit(&frame(901, 17, 64)).admitted);
    assert!(core.resolve_ipsec_inner_verdict(IpsecInnerVerdict::Deny {
        request_id: 901,
        stage: "d14",
        reason: 32,
        policy_id: 0,
    }));
    assert_eq!(
        core.drain_ready(1)[0].outcome,
        ReinjectOutcome::Denied
    );

    assert!(core.admit(&frame(902, 17, 64)).admitted);
    assert!(core.resolve_ipsec_inner_verdict(
        IpsecInnerVerdict::WouldPermit { request_id: 902 }
    ));
    assert_eq!(
        core.drain_ready(1)[0].outcome,
        ReinjectOutcome::WouldPermit
    );
}

#[test]
fn ipsec_inner_verdict_bridge_maps_e24_to_uncertain() {
    let core = open_core();
    assert!(core.admit(&frame(903, 17, 64)).admitted);
    assert!(core.resolve_ipsec_inner_verdict(IpsecInnerVerdict::Deny {
        request_id: 903,
        stage: "d11",
        reason: ipsec_reason::VERDICT_UNCERTAIN,
        policy_id: 0,
    }));
    assert_eq!(
        core.drain_ready(1)[0].outcome,
        ReinjectOutcome::Uncertain
    );
}

#[test]
fn d11_digest_frozen_vector_matches_go_contract() {
    let mut vector = frame(1, 1, 3);
    vector.lease.permit_epoch = 2;
    vector.lease.queue_epoch = 3;
    vector.lease.queue_number = 4;
    vector.bytes = vec![0x00, 0x11, 0x22];
    vector.origin.owned_ifindex = 5;
    vector.origin.owner = "rg1".to_string();
    vector.origin.stn = "stn1".to_string();
    assert_eq!(
        d11_frame_digest(
            &vector,
            "attest-00000000000000000000000000000000"
        ),
        [
            0x79, 0x72, 0xbb, 0xf3, 0x3f, 0xb7, 0xf8, 0x1d, 0x51, 0xee, 0x31, 0xab,
            0x9b, 0x05, 0x88, 0xf3, 0xd1, 0x04, 0xb3, 0x3d, 0xeb, 0x48, 0xe6, 0x2d,
            0xe6, 0xbb, 0x9a, 0x7e, 0x24, 0xb0, 0x5a, 0xb1,
        ]
    );
}

/// Test stub authority: scripts open/closed without publishing epochs.
struct StubAuthority {
    open: bool,
}
impl ReinjectAuthority for StubAuthority {
    fn allows(&self, _permit_epoch: u64, _queue_number: u16, _queue_epoch: u64) -> bool {
        self.open
    }
    fn permit_open(&self) -> bool {
        self.open
    }
}

// ---------- frozen lease shape ----------

#[test]
fn lease_shape_is_frozen_permit_queue_request() {
    let l = ReinjectLease {
        permit_epoch: 7,
        queue_epoch: 11,
        queue_number: 1,
        request_id: 1,
    };
    assert_eq!(l.permit_epoch, 7);
    assert_eq!(l.queue_epoch, 11);
    assert_eq!(l.request_id, 1);
}

// ---------- authority ----------

#[test]
fn authority_allows_open_permit_any_published_queue_epoch() {
    let mut st = AuthorityState::new();
    st.publish(PERMIT, &[(1, QEPOCH), (2, 13)]);
    assert!(st.allows(PERMIT, 1, QEPOCH));
    assert!(st.allows(PERMIT, 2, 13));
    // The submit frame carries its queue number and epoch; both must match
    // the published pair.
    assert!(!st.allows(PERMIT, 1, 99), "unpublished queue epoch is stale");
    assert!(!st.allows(8, 1, QEPOCH), "wrong permit epoch is stale");
    assert!(!st.allows(0, 1, QEPOCH), "permit epoch 0 never matches");
    assert!(!st.allows(PERMIT, 1, 0), "queue epoch 0 never matches");
    assert!(st.permit_open());
}

#[test]
fn authority_empty_queue_list_admits_nothing() {
    let mut st = AuthorityState::new();
    st.publish(PERMIT, &[]);
    assert!(st.permit_open(), "permit is open");
    assert!(
        !st.allows(PERMIT, 1, QEPOCH),
        "no published queue epoch can match: fail closed"
    );
}

#[test]
fn authority_permit_close_is_monotonic_no_reopen() {
    let mut st = AuthorityState::new();
    assert!(!st.permit_open(), "fresh authority starts closed");
    st.publish(PERMIT, &[(1, QEPOCH)]);
    assert!(st.allows(PERMIT, 1, QEPOCH));
    st.close_permit(PERMIT);
    assert!(!st.permit_open(), "cancel-scope closes the permit");
    assert!(!st.allows(PERMIT, 1, QEPOCH));
    // Re-publishing the SAME epoch must NOT reopen (r6 §3.2: no reopen).
    st.publish(PERMIT, &[(1, QEPOCH)]);
    assert!(!st.permit_open(), "same-epoch republish must not reopen");
    assert!(!st.allows(PERMIT, 1, QEPOCH));
    // A NEW (higher) epoch is a new permit and opens.
    st.publish(PERMIT + 1, &[(1, QEPOCH)]);
    assert!(st.permit_open());
    assert!(st.allows(PERMIT + 1, 1, QEPOCH));
    // close_permit(0) is meaningless (0 = no authority) and changes nothing.
    st.close_permit(0);
    assert!(st.permit_open());
    // A lower close never rewinds the monotonic close horizon.
    st.close_permit(3);
    assert!(st.permit_open());
    st.close_permit(PERMIT + 1);
    assert!(!st.permit_open());
}

#[test]
fn stub_authority_scripts_decisions_through_trait() {
    let open = StubAuthority { open: true };
    let closed = StubAuthority { open: false };
    let auth_open: &dyn ReinjectAuthority = &open;
    let auth_closed: &dyn ReinjectAuthority = &closed;
    assert_eq!(
        decide_pre_write(EntryView::Queued, &lease(1), auth_open),
        PreWrite::Proceed
    );
    assert_eq!(
        decide_pre_write(EntryView::Queued, &lease(1), auth_closed),
        PreWrite::Fenced
    );
    assert_eq!(
        decide_resolve(&lease(1), &written(100), auth_closed),
        (ReinjectOutcome::Written, 100)
    );
}

// ---------- pure decisions ----------

#[test]
fn decide_pre_write_truth_table() {
    let open = StubAuthority { open: true };
    let closed = StubAuthority { open: false };
    let l = lease(1);
    assert_eq!(
        decide_pre_write(EntryView::Unknown, &l, &open),
        PreWrite::Unknown
    );
    assert_eq!(
        decide_pre_write(EntryView::Queued, &l, &open),
        PreWrite::Proceed
    );
    assert_eq!(
        decide_pre_write(EntryView::Queued, &l, &closed),
        PreWrite::Fenced
    );
    // A second pre-check on an in-flight or resolved entry never writes.
    assert_eq!(
        decide_pre_write(EntryView::WriteStarted, &l, &open),
        PreWrite::Cancelled
    );
    assert_eq!(
        decide_pre_write(EntryView::Terminal, &l, &open),
        PreWrite::Cancelled
    );
    assert_eq!(
        decide_pre_write(EntryView::Terminal, &l, &closed),
        PreWrite::Cancelled
    );
    // The production authority answers through the same trait object.
    let mut st = AuthorityState::new();
    st.publish(PERMIT, &[(1, QEPOCH)]);
    let auth: &dyn ReinjectAuthority = &st;
    assert_eq!(
        decide_pre_write(EntryView::Queued, &l, auth),
        PreWrite::Proceed
    );
}

#[test]
fn decide_resolve_post_verify() {
    let open = StubAuthority { open: true };
    let closed = StubAuthority { open: false };
    let l = lease(1);
    // Written under a live permit commits.
    assert_eq!(
        decide_resolve(&l, &written(100), &open),
        (ReinjectOutcome::Written, 100)
    );
    // Written remains a definitive commit once the required pre-write
    // linearization check has passed, even if cancellation races afterward.
    assert_eq!(
        decide_resolve(&l, &written(100), &closed),
        (ReinjectOutcome::Written, 100)
    );
    // Refused/uncertain verdicts are truth regardless of epoch motion:
    // nothing was emitted (refused) or ambiguity already holds (uncertain).
    assert_eq!(
        decide_resolve(&l, &refused(), &closed),
        (ReinjectOutcome::Refused, 0)
    );
    assert_eq!(
        decide_resolve(&l, &uncertain(), &open),
        (ReinjectOutcome::Uncertain, 0)
    );
}

// ---------- admit ----------

#[test]
fn admit_zero_request_id_is_bad_lease() {
    let core = open_core();
    let mut f = frame(0, 1, 64);
    f.lease.request_id = 0;
    let d = core.admit(&f);
    assert!(!d.admitted);
    assert_eq!(d.reason, ADMIT_BAD_LEASE);
    assert_eq!(d.request_id, 0);
    assert_eq!(core.live_count(), 0, "refused submit reserves nothing");
}

#[test]
fn admit_empty_bytes_is_bad_lease() {
    let core = open_core();
    let d = core.admit(&frame(1, 1, 0));
    assert!(!d.admitted);
    assert_eq!(d.reason, ADMIT_BAD_LEASE);
    assert_eq!(core.live_count(), 0);
}

#[test]
fn admit_oversize_bytes_is_bad_lease() {
    let core = open_core();
    // The codec also enforces this; the in-process API must not trust it.
    let d = core.admit(&frame(1, 1, SUBMIT_MAX_DATA_LEN + 1));
    assert!(!d.admitted);
    assert_eq!(d.reason, ADMIT_BAD_LEASE);
    assert_eq!(core.live_count(), 0);
}

#[test]
fn admit_duplicate_id_rejected_until_drained() {
    let core = open_core();
    let d = core.admit(&frame(1, 1, 64));
    assert!(d.admitted);
    let dup = core.admit(&frame(1, 2, 64));
    assert!(!dup.admitted, "live id cannot be reused");
    assert_eq!(dup.reason, ADMIT_BAD_LEASE);
    // Even after terminal resolution the id stays reserved until drained.
    assert_eq!(core.pre_write_check(&lease(1)), PreWrite::Proceed);
    assert!(core.resolve_write(&lease(1), written(64)));
    let dup2 = core.admit(&frame(1, 3, 64));
    assert!(!dup2.admitted, "undrained terminal id cannot be reused");
    assert_eq!(core.drain_ready(16).len(), 1);
    let ok = core.admit(&frame(1, 4, 64));
    assert!(ok.admitted, "ordinary run IDs remain reusable after drain");
}

#[test]
fn attest_terminal_id_tombstone_resets_only_on_run_change() {
    let core = open_core();
    assert!(core.announce_epochs(
        "attest-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        1,
        PERMIT,
        true,
        &[(1, QEPOCH)],
    ));
    let first = core.admit(&frame(1, 1, 64));
    assert!(first.admitted);
    assert_eq!(core.pre_write_check(&lease(1)), PreWrite::Proceed);
    assert!(core.resolve_write(&lease(1), written(64)));
    assert_eq!(core.drain_ready(16).len(), 1);
    let same_run = core.admit(&frame(1, 2, 64));
    assert!(!same_run.admitted);
    assert_eq!(same_run.reason, ADMIT_BAD_LEASE);
    assert!(core.announce_epochs(
        "attest-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        2,
        PERMIT,
        true,
        &[(1, QEPOCH)],
    ));
    let new_run = core.admit(&frame(1, 3, 64));
    assert!(new_run.admitted, "new attestation run clears old tombstones");
}

#[test]
fn attest_tombstone_overflow_is_full_only_in_attest_run() {
    let source = open_core();
    assert!(source.announce_epochs(
        "attest-cccccccccccccccccccccccccccccccc",
        1,
        PERMIT,
        true,
        &[(1, QEPOCH)],
    ));
    for id in 1..=TERMINAL_TOMBSTONE_MAX as u64 + 1 {
        assert!(source.admit(&frame(id, id, 64)).admitted, "id {id} admission");
        assert_eq!(source.pre_write_check(&lease(id)), PreWrite::Proceed);
        assert!(source.resolve_write(&lease(id), written(64)));
        assert_eq!(source.drain_ready(1).len(), 1);
    }
    let source_overflow =
        source.admit(&frame(TERMINAL_TOMBSTONE_MAX as u64 + 2, 1, 64));
    assert!(!source_overflow.admitted);
    assert_eq!(source_overflow.reason, ADMIT_FULL);

    let ordinary_source = ReinjectCore::new_shared();
    assert!(ordinary_source.announce_epochs(
        "ordinary-copy",
        2,
        PERMIT,
        true,
        &[(1, QEPOCH)],
    ));
    let target = ReinjectCore::new_shared();
    assert!(target.announce_epochs(
        "ordinary-copy",
        2,
        PERMIT,
        true,
        &[(1, QEPOCH)],
    ));
    {
        let mut inner = target.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.terminal_tombstones.insert(99_999);
        inner.terminal_tombstone_overflow = true;
    }
    target.copy_authority_from(&ordinary_source);
    {
        let inner = target.inner.lock().unwrap_or_else(|e| e.into_inner());
        assert!(inner.terminal_tombstones.is_empty());
        assert!(!inner.terminal_tombstone_overflow);
    }
    let ordinary = target.admit(&frame(TERMINAL_TOMBSTONE_MAX as u64 + 2, 1, 64));
    assert!(ordinary.admitted, "ordinary handoff must clear D11 overflow poison");
}

#[test]
fn admit_stale_epoch() {
    let core = open_core();
    let mut wrong_permit = frame(1, 1, 64);
    wrong_permit.lease.permit_epoch = PERMIT + 1;
    let d = core.admit(&wrong_permit);
    assert!(!d.admitted);
    assert_eq!(d.reason, ADMIT_STALE);
    let mut wrong_queue = frame(2, 1, 64);
    wrong_queue.lease.queue_epoch = 99;
    let d = core.admit(&wrong_queue);
    assert!(!d.admitted);
    assert_eq!(d.reason, ADMIT_STALE);
    // Closed authority (never published) refuses everything as stale.
    let closed = ReinjectCore::new_shared();
    let d = closed.admit(&frame(3, 1, 64));
    assert!(!d.admitted);
    assert_eq!(d.reason, ADMIT_STALE);
    assert_eq!(core.live_count(), 0);
}

#[test]
fn submit_batch_reports_per_frame_decisions() {
    let core = open_core();
    let mut zero = frame(10, 1, 64);
    zero.lease.request_id = 0;
    let mut stale = frame(11, 1, 64);
    stale.lease.permit_epoch = PERMIT + 1;
    let batch = vec![frame(1, 1, 64), zero, stale, frame(2, 1, 64)];
    let decisions = core.submit_batch(&batch);
    assert_eq!(decisions.len(), 4);
    assert!(decisions[0].admitted);
    assert_eq!(decisions[0].reason, ADMIT_OK);
    assert!(!decisions[1].admitted);
    assert_eq!(decisions[1].reason, ADMIT_BAD_LEASE);
    assert!(!decisions[2].admitted);
    assert_eq!(decisions[2].reason, ADMIT_STALE);
    assert!(decisions[3].admitted);
    assert_eq!(core.live_count(), 2, "only admitted frames reserve");
}

// ---------- pre-write / resolve / drain ----------

#[test]
fn stale_precheck_marks_terminal_no_write() {
    let core = open_core();
    assert!(core.admit(&frame(1, 1, 64)).admitted);
    // The permit rotates between admission and the worker's dequeue.
    core.publish_epochs(PERMIT + 1, &[(1, QEPOCH)]);
    assert_eq!(core.pre_write_check(&lease(1)), PreWrite::Fenced);
    let done = core.drain_ready(16);
    assert_eq!(done.len(), 1);
    assert_eq!(done[0].request_id, 1);
    assert_eq!(done[0].outcome, ReinjectOutcome::Fenced);
    assert_eq!(done[0].bytes_written, 0);
    assert_eq!(core.live_count(), 0);
    // No double completion: the entry is terminal.
    assert_eq!(core.pre_write_check(&lease(1)), PreWrite::Unknown);
    assert!(core.drain_ready(16).is_empty());
}

#[test]
fn written_is_the_commit_point() {
    let core = open_core();
    assert!(core.admit(&frame(1, 9, 64)).admitted);
    assert_eq!(core.pre_write_check(&lease(1)), PreWrite::Proceed);
    assert!(core.resolve_write(&lease(1), written(64)));
    let done = core.drain_ready(16);
    assert_eq!(done.len(), 1);
    assert_eq!(done[0].request_id, 1);
    assert_eq!(done[0].outcome, ReinjectOutcome::Written);
    assert_eq!(done[0].bytes_written, 64);
    assert_eq!(done[0].flow_tag, 9);
    let stats = core.stats_snapshot();
    assert_eq!(stats.completed_written, 1);
    assert_eq!(core.live_count(), 0);
}

#[test]
fn uncertain_is_terminal_never_retried() {
    let core = open_core();
    assert!(core.admit(&frame(1, 1, 64)).admitted);
    assert_eq!(core.pre_write_check(&lease(1)), PreWrite::Proceed);
    assert!(core.resolve_write(&lease(1), uncertain()));
    // First terminal wins: a late second resolve is a no-op, never a retry.
    assert!(!core.resolve_write(&lease(1), written(64)));
    let done = core.drain_ready(16);
    assert_eq!(done.len(), 1);
    assert_eq!(done[0].outcome, ReinjectOutcome::Uncertain);
    assert!(core.drain_ready(16).is_empty(), "exactly one completion");
    assert_eq!(core.live_count(), 0);
    assert_eq!(core.stats_snapshot().completed_uncertain, 1);
}

#[test]
fn refused_is_terminal() {
    let core = open_core();
    assert!(core.admit(&frame(1, 1, 64)).admitted);
    assert_eq!(core.pre_write_check(&lease(1)), PreWrite::Proceed);
    assert!(core.resolve_write(&lease(1), refused()));
    let done = core.drain_ready(16);
    assert_eq!(done.len(), 1);
    assert_eq!(done[0].outcome, ReinjectOutcome::Refused);
    assert_eq!(done[0].bytes_written, 0);
}

#[test]
fn resolve_unknown_id_is_noop() {
    let core = open_core();
    assert!(!core.resolve_write(&lease(999), written(64)));
    assert_eq!(core.live_count(), 0);
    assert!(core.drain_ready(16).is_empty());
}

#[test]
fn write_started_cancel_keeps_actual_outcome_fifo_cascade() {
    let core = open_core();
    // Same flow: r2's cancelled completion must wait behind r1 (head).
    assert!(core.admit(&frame(1, 1, 64)).admitted);
    assert!(core.admit(&frame(2, 1, 64)).admitted);
    assert_eq!(core.pre_write_check(&lease(1)), PreWrite::Proceed);
    // r1 is WRITE_STARTED: cancel flags it but cannot terminal-cancel it;
    // only the still-queued r2 becomes {cancelled}.
    let cancelled = core.cancel(&CancelScope::ids(vec![1, 2]));
    assert_eq!(cancelled, vec![2]);
    assert!(
        core.drain_ready(16).is_empty(),
        "r2 waits behind unresolved head r1"
    );
    // The started write drains to its ACTUAL outcome, then r2 cascades.
    assert!(core.resolve_write(&lease(1), written(64)));
    let done = core.drain_ready(16);
    assert_eq!(done.len(), 2);
    assert_eq!(done[0].request_id, 1);
    assert_eq!(done[0].outcome, ReinjectOutcome::Written);
    assert_eq!(done[1].request_id, 2);
    assert_eq!(done[1].outcome, ReinjectOutcome::Cancelled);
    assert_eq!(core.live_count(), 0);
}

#[test]
fn publish_race_keeps_definitive_write_as_commit() {
    let core = open_core();
    assert!(core.admit(&frame(1, 1, 64)).admitted);
    assert_eq!(core.pre_write_check(&lease(1)), PreWrite::Proceed);
    // A snapshot publish after WRITE_STARTED does not rewrite a known
    // definitive full-frame write. The required authorization check was the
    // one immediately before the TUN write; cancellation observes Written.
    core.publish_epochs(PERMIT + 1, &[(1, QEPOCH)]);
    assert!(core.resolve_write(&lease(1), written(64)));
    let done = core.drain_ready(16);
    assert_eq!(done.len(), 1);
    assert_eq!(
        done[0].outcome,
        ReinjectOutcome::Written,
        "definitive write is the REINJECT COMMIT point"
    );
}

#[test]
fn drain_is_bounded_by_max() {
    let core = open_core();
    for id in 1..=5u64 {
        assert!(core.admit(&frame(id, id, 64)).admitted);
        assert_eq!(core.pre_write_check(&lease(id)), PreWrite::Proceed);
        assert!(core.resolve_write(&lease(id), written(64)));
    }
    assert_eq!(core.live_count(), 5, "undrained terminals hold budget");
    assert_eq!(core.drain_ready(2).len(), 2);
    assert_eq!(core.live_count(), 3);
    assert_eq!(core.drain_ready(100).len(), 3);
    assert_eq!(core.live_count(), 0);
}

#[test]
fn per_flow_fifo_other_flows_progress() {
    let core = open_core();
    assert!(core.admit(&frame(1, 1, 64)).admitted);
    assert!(core.admit(&frame(2, 1, 64)).admitted);
    assert!(core.admit(&frame(3, 2, 64)).admitted);
    // Cancel the head of flow 1: it drains immediately (it IS the head).
    assert_eq!(core.cancel(&CancelScope::ids(vec![1])), vec![1]);
    let done = core.drain_ready(16);
    assert_eq!(done.len(), 1);
    assert_eq!(done[0].request_id, 1);
    assert_eq!(done[0].outcome, ReinjectOutcome::Cancelled);
    // Flow 2 progresses while flow 1's next head is still unresolved.
    assert_eq!(core.pre_write_check(&lease(3)), PreWrite::Proceed);
    assert!(core.resolve_write(&lease(3), written(64)));
    let done = core.drain_ready(16);
    assert_eq!(done.len(), 1);
    assert_eq!(done[0].request_id, 3);
    // Flow 1 unblocks in request order.
    assert_eq!(core.pre_write_check(&lease(2)), PreWrite::Proceed);
    assert!(core.resolve_write(&lease(2), written(64)));
    let done = core.drain_ready(16);
    assert_eq!(done.len(), 1);
    assert_eq!(done[0].request_id, 2);
    assert_eq!(core.live_count(), 0);
}

// ---------- cancel ----------

#[test]
fn cancel_empty_scope_is_noop() {
    let core = open_core();
    assert!(core.admit(&frame(1, 1, 64)).admitted);
    assert!(core.cancel(&CancelScope::none()).is_empty());
    assert_eq!(
        core.pre_write_check(&lease(1)),
        PreWrite::Proceed,
        "empty cancel must not disturb queued leases"
    );
    // And it must not close authority either.
    assert!(core.admit(&frame(2, 1, 64)).admitted);
}

#[test]
fn cancel_permit_scope_cancels_and_closes_globally() {
    let core = open_core();
    assert!(core.admit(&frame(1, 1, 64)).admitted);
    assert!(core.admit(&frame(2, 2, 64)).admitted);
    let cancelled = core.cancel(&CancelScope::permit(PERMIT));
    assert_eq!(cancelled, vec![1, 2]);
    let done = core.drain_ready(16);
    assert_eq!(done.len(), 2);
    assert!(done.iter().all(|c| c.outcome == ReinjectOutcome::Cancelled));
    // Global close: new submits under the permit are stale, with no reopen.
    let d = core.admit(&frame(3, 1, 64));
    assert!(!d.admitted);
    assert_eq!(d.reason, ADMIT_STALE);
    core.publish_epochs(PERMIT, &[(1, QEPOCH)]);
    let d = core.admit(&frame(3, 1, 64));
    assert!(!d.admitted, "same-epoch republish must not reopen");
    core.publish_epochs(PERMIT + 1, &[(1, QEPOCH)]);
    let mut f = frame(3, 1, 64);
    f.lease.permit_epoch = PERMIT + 1;
    assert!(core.admit(&f).admitted, "new permit epoch opens");
}

#[test]
fn cancel_queue_scope_cancels_matching_only() {
    let core = open_core();
    assert!(core.admit(&frame(1, 1, 64)).admitted); // queue 11
    let mut f2 = frame(2, 1, 64);
    f2.lease.queue_epoch = 13;
    f2.lease.queue_number = 2;
    assert!(core.admit(&f2).admitted);
    assert_eq!(core.cancel(&CancelScope::queue(2, 13)), vec![2]);
    assert_eq!(
        core.pre_write_check(&lease(1)),
        PreWrite::Proceed,
        "non-matching queue epoch is unaffected"
    );
    // Queue-scope cancel does not close permit authority.
    assert!(core.admit(&frame(3, 1, 64)).admitted);
}

#[test]
fn cancel_id_set_intersects_scope() {
    let core = open_core();
    assert!(core.admit(&frame(1, 1, 64)).admitted);
    let mut f2 = frame(2, 1, 64);
    f2.lease.queue_epoch = 13;
    f2.lease.queue_number = 2;
    assert!(core.admit(&f2).admitted);
    let mut scope = CancelScope::ids(vec![1, 2]);
    scope.permit_epoch = Some(PERMIT + 1);
    assert!(
        core.cancel(&scope).is_empty(),
        "id set intersected with a non-matching permit cancels nothing"
    );
    let mut mismatched_queue = CancelScope::ids(vec![2]);
    mismatched_queue.permit_epoch = Some(PERMIT + 1);
    mismatched_queue.queue_epochs = vec![(2, 13)];
    assert!(
        core.cancel(&mismatched_queue).is_empty(),
        "mismatched permit must not tombstone queue scope"
    );
    let mut readd = frame(3, 1, 64);
    readd.lease.queue_number = 2;
    readd.lease.queue_epoch = 13;
    assert!(
        core.admit(&readd).admitted,
        "mismatched permit leaves queue epoch admissible"
    );
    let mut scope = CancelScope::ids(vec![1, 2]);
    scope.queue_epochs = vec![(2, 13)];
    assert_eq!(core.cancel(&scope), vec![2]);
}

// ---------- N_live ----------

#[test]
fn n_live_aggregate_bound_queued_plus_unacked() {
    let core = open_core();
    for id in 1..=N_LIVE as u64 {
        let d = core.admit(&frame(id, id, 64));
        assert!(d.admitted, "admission {id} must succeed below the cap");
    }
    assert_eq!(core.live_count(), N_LIVE);
    let d = core.admit(&frame(N_LIVE as u64 + 1, 1, 64));
    assert!(!d.admitted);
    assert_eq!(d.reason, ADMIT_FULL);
    // Terminal-but-undrained ("unacked") still holds budget: NOT per-state.
    assert_eq!(core.pre_write_check(&lease(1)), PreWrite::Proceed);
    assert!(core.resolve_write(&lease(1), written(64)));
    assert_eq!(core.live_count(), N_LIVE);
    let d = core.admit(&frame(N_LIVE as u64 + 1, 1, 64));
    assert!(!d.admitted, "unacked completions hold N_live budget");
    assert_eq!(d.reason, ADMIT_FULL);
    // Draining releases exactly one slot.
    assert_eq!(core.drain_ready(1).len(), 1);
    assert_eq!(core.live_count(), N_LIVE - 1);
    assert!(
        core.admit(&frame(N_LIVE as u64 + 1, 1, 64)).admitted,
        "one drained slot admits one frame"
    );
    assert_eq!(core.live_count(), N_LIVE);
    assert!(
        core.ready_len() <= N_LIVE,
        "ready queue can never exceed the aggregate budget"
    );
}

#[test]
fn completion_queue_cannot_lose_terminals() {
    let core = open_core();
    for id in 1..=100u64 {
        assert!(core.admit(&frame(id, id, 64)).admitted);
        assert_eq!(core.pre_write_check(&lease(id)), PreWrite::Proceed);
        assert!(core.resolve_write(&lease(id), written(64)));
    }
    assert_eq!(core.ready_len(), 100);
    assert_eq!(core.drain_ready(1000).len(), 100);
    assert_eq!(core.live_count(), 0);
}

// ---------- codec ----------

#[test]
fn codec_submit_roundtrip_and_exact_bytes() {
    let frames = vec![
        SubmitFrame {
            lease: ReinjectLease {
                permit_epoch: 7,
                queue_epoch: 11,
                queue_number: 9,
                request_id: 1,
            },
            flow_tag: 2,
            flags: SUBMIT_FLAG_DRY_RUN,
            origin: CaptureOrigin::inet_forward(42, "owner", "stn"),
            bytes: vec![0x45, 0x00],
            snapshot_generation: 13,
            config_generation: 17,
            fib_generation: 19,
            zone_id: 23,
            if_id: 29,
        },
        SubmitFrame {
            lease: ReinjectLease {
                permit_epoch: 8,
                queue_epoch: 12,
                queue_number: 10,
                request_id: 2,
            },
            flow_tag: 3,
            flags: SUBMIT_FLAG_SHADOW,
            origin: CaptureOrigin::inet_forward(43, "owner2", "stn2"),
            bytes: vec![0xaa],
            snapshot_generation: 14,
            config_generation: 18,
            fib_generation: 20,
            zone_id: 24,
            if_id: 30,
        },
    ];
    let payload = encode_submit_batch(&frames);
    let mut expected = vec![0x00, 0x02];
    expected.extend_from_slice(&1u64.to_be_bytes());
    expected.extend_from_slice(&7u64.to_be_bytes());
    expected.extend_from_slice(&11u64.to_be_bytes());
    expected.extend_from_slice(&9u16.to_be_bytes());
    expected.extend_from_slice(&2u64.to_be_bytes());
    expected.push(SUBMIT_FLAG_DRY_RUN);
    expected.extend_from_slice(&[ORIGIN_INET, ORIGIN_FORWARD]);
    expected.extend_from_slice(&42u32.to_be_bytes());
    expected.push(5);
    expected.extend_from_slice(b"owner");
    expected.push(3);
    expected.extend_from_slice(b"stn");
    expected.extend_from_slice(&2u32.to_be_bytes());
    expected.extend_from_slice(&[0x45, 0x00]);
    expected.extend_from_slice(&13u64.to_be_bytes());
    expected.extend_from_slice(&17u64.to_be_bytes());
    expected.extend_from_slice(&19u32.to_be_bytes());
    expected.extend_from_slice(&23u16.to_be_bytes());
    expected.extend_from_slice(&29u32.to_be_bytes());
    expected.extend_from_slice(&2u64.to_be_bytes());
    expected.extend_from_slice(&8u64.to_be_bytes());
    expected.extend_from_slice(&12u64.to_be_bytes());
    expected.extend_from_slice(&10u16.to_be_bytes());
    expected.extend_from_slice(&3u64.to_be_bytes());
    expected.push(SUBMIT_FLAG_SHADOW);
    expected.extend_from_slice(&[ORIGIN_INET, ORIGIN_FORWARD]);
    expected.extend_from_slice(&43u32.to_be_bytes());
    expected.push(6);
    expected.extend_from_slice(b"owner2");
    expected.push(4);
    expected.extend_from_slice(b"stn2");
    expected.extend_from_slice(&1u32.to_be_bytes());
    expected.push(0xaa);
    expected.extend_from_slice(&14u64.to_be_bytes());
    expected.extend_from_slice(&18u64.to_be_bytes());
    expected.extend_from_slice(&20u32.to_be_bytes());
    expected.extend_from_slice(&24u16.to_be_bytes());
    expected.extend_from_slice(&30u32.to_be_bytes());
    assert_eq!(payload, expected);
    assert_eq!(decode_submit_batch(&payload).unwrap(), frames);
    // Empty batch is a legal no-op.
    let empty = encode_submit_batch(&[]);
    assert_eq!(decode_submit_batch(&empty).unwrap(), vec![]);
}

#[test]
fn pooled_submit_decode_owns_bytes_once_in_slab() {
    let frame = frame(77, 9, 64);
    let payload = encode_submit_batch(&[frame]);
    let pool = crate::afxdp::ipsec_inner_queue::IpsecInnerSlabPool::new();
    let pooled = decode_submit_batch_into_pool(&payload, &pool).expect("pooled decode");
    assert_eq!(pooled.len(), 1);
    assert_eq!(pooled[0].bytes_len, 64);
    let slab_id = pooled[0].slab_id;
    let slab = pool.buffer(slab_id).expect("slab buffer");
    assert_eq!(slab.as_slice(), &[0x45; 64]);
    drop(slab);
    assert!(pool.force_release(slab_id));
    assert_eq!(pool.free_count(), IPSEC_INNER_SLAB_CAP);
}

#[test]
fn codec_submit_rejects_over_caps() {
    // n > 64 rejected.
    let mut payload = vec![];
    payload.extend_from_slice(&65u16.to_be_bytes());
    assert_eq!(
        decode_submit_batch(&payload).unwrap_err(),
        CodecError::TooManyFrames
    );
    // data_len > 65535 rejected.
    let mut payload = encode_submit_batch(&[frame(1, 1, 64)]);
    let data_len_pos =
        payload.len() - 64 - SUBMIT_PMECH_TAIL_LEN - std::mem::size_of::<u32>();
    payload[data_len_pos..data_len_pos + 4].copy_from_slice(&65536u32.to_be_bytes());
    assert_eq!(
        decode_submit_batch(&payload).unwrap_err(),
        CodecError::FrameTooLarge
    );
    // Truncated frame rejected.
    let payload = encode_submit_batch(&[frame(1, 1, 64)]);
    let cut = &payload[..payload.len() - 3];
    assert_eq!(
        decode_submit_batch(cut).unwrap_err(),
        CodecError::Truncated
    );
    // Trailing bytes rejected (strict framing: fail closed).
    let mut trailing = payload.clone();
    trailing.push(0x00);
    assert_eq!(
        decode_submit_batch(&trailing).unwrap_err(),
        CodecError::TrailingBytes
    );
}

#[test]
fn codec_cancel_flags_roundtrip() {
    let cases = vec![
        CancelScope::none(),
        CancelScope::ids(vec![1, 2, 300]),
        CancelScope::permit(7),
        CancelScope::queue(0, 11),
        CancelScope {
            ids: Some(vec![9]),
            permit_epoch: Some(7),
            queue_epochs: vec![(0, 11)],
        },
    ];
    for scope in &cases {
        let payload = encode_cancel(scope);
        assert_eq!(&decode_cancel(&payload).unwrap(), scope);
    }
    // Hand-pinned: flags=ids|permit, n=1, id=9, permit=7.
    let mut expected = vec![CANCEL_IDS | CANCEL_PERMIT_SCOPE];
    expected.extend_from_slice(&1u16.to_be_bytes());
    expected.extend_from_slice(&9u64.to_be_bytes());
    expected.extend_from_slice(&7u64.to_be_bytes());
    assert_eq!(
        encode_cancel(&CancelScope {
            ids: Some(vec![9]),
            permit_epoch: Some(7),
            queue_epochs: Vec::new(),
        }),
        expected
    );
    // Unknown flag bits are a protocol violation (strict).
    assert_eq!(decode_cancel(&[0x08]).unwrap_err(), CodecError::BadFlags);
    assert_eq!(decode_cancel(&[]).unwrap_err(), CodecError::Truncated);
}

#[test]
fn codec_admit_complete_roundtrip() {
    let decisions = vec![
        AdmitDecision {
            request_id: 1,
            permit_epoch: PERMIT,
            queue_epoch: QEPOCH,
            queue_number: 1,
            family: ORIGIN_INET,
            hook: ORIGIN_FORWARD,
            owned_ifindex: 0,
            admitted: true,
            reason: ADMIT_OK,
        },
        AdmitDecision {
            request_id: 2,
            permit_epoch: PERMIT,
            queue_epoch: QEPOCH,
            queue_number: 1,
            family: ORIGIN_INET,
            hook: ORIGIN_FORWARD,
            owned_ifindex: 0,
            admitted: false,
            reason: ADMIT_FULL,
        },
    ];
    let payload = encode_admit(&decisions);
    let mut expected = vec![0x00, 0x02];
    expected.extend_from_slice(&1u64.to_be_bytes());
    expected.extend_from_slice(&PERMIT.to_be_bytes());
    expected.extend_from_slice(&QEPOCH.to_be_bytes());
    expected.extend_from_slice(&1u16.to_be_bytes());
    expected.extend_from_slice(&[ORIGIN_INET, ORIGIN_FORWARD]);
    expected.extend_from_slice(&0u32.to_be_bytes());
    expected.extend_from_slice(&[0x01, ADMIT_OK]);
    expected.extend_from_slice(&2u64.to_be_bytes());
    expected.extend_from_slice(&PERMIT.to_be_bytes());
    expected.extend_from_slice(&QEPOCH.to_be_bytes());
    expected.extend_from_slice(&1u16.to_be_bytes());
    expected.extend_from_slice(&[ORIGIN_INET, ORIGIN_FORWARD]);
    expected.extend_from_slice(&0u32.to_be_bytes());
    expected.extend_from_slice(&[0x00, ADMIT_FULL]);
    assert_eq!(payload, expected);
    assert_eq!(decode_admit(&payload).unwrap(), decisions);

    let completions = vec![
        ReinjectCompletion {
            request_id: 1,
            permit_epoch: PERMIT,
            queue_epoch: QEPOCH,
            queue_number: 1,
            family: ORIGIN_INET,
            hook: ORIGIN_FORWARD,
            owned_ifindex: 0,
            outcome: ReinjectOutcome::Written,
            bytes_written: 100,
            flow_tag: 5, // carried in-table, NOT on the wire
        },
        ReinjectCompletion {
            request_id: 2,
            permit_epoch: PERMIT,
            queue_epoch: QEPOCH,
            queue_number: 1,
            family: ORIGIN_INET,
            hook: ORIGIN_FORWARD,
            owned_ifindex: 0,
            outcome: ReinjectOutcome::Uncertain,
            bytes_written: 0,
            flow_tag: 6,
        },
    ];
    let payload = encode_complete(&completions);
    let mut expected = vec![0x00, 0x02];
    expected.extend_from_slice(&1u64.to_be_bytes());
    expected.extend_from_slice(&PERMIT.to_be_bytes());
    expected.extend_from_slice(&QEPOCH.to_be_bytes());
    expected.extend_from_slice(&1u16.to_be_bytes());
    expected.extend_from_slice(&[ORIGIN_INET, ORIGIN_FORWARD]);
    expected.extend_from_slice(&0u32.to_be_bytes());
    expected.push(OUTCOME_WRITTEN);
    expected.extend_from_slice(&100u32.to_be_bytes());
    expected.extend_from_slice(&2u64.to_be_bytes());
    expected.extend_from_slice(&PERMIT.to_be_bytes());
    expected.extend_from_slice(&QEPOCH.to_be_bytes());
    expected.extend_from_slice(&1u16.to_be_bytes());
    expected.extend_from_slice(&[ORIGIN_INET, ORIGIN_FORWARD]);
    expected.extend_from_slice(&0u32.to_be_bytes());
    expected.push(OUTCOME_UNCERTAIN);
    expected.extend_from_slice(&0u32.to_be_bytes());
    assert_eq!(payload, expected);
    let decoded = decode_complete(&payload).unwrap();
    assert_eq!(decoded.len(), 2);
    assert_eq!(decoded[0].request_id, 1);
    assert_eq!(decoded[0].outcome, ReinjectOutcome::Written);
    assert_eq!(decoded[0].bytes_written, 100);

    // Strict value domains.
    let mut bad = vec![0x00, 0x01];
    bad.extend_from_slice(&1u64.to_be_bytes());
    bad.push(0x07);
    bad.push(ADMIT_OK);
    assert!(decode_admit(&bad).is_err());
    let mut bad = vec![0x00, 0x01];
    bad.extend_from_slice(&1u64.to_be_bytes());
    bad.push(0x06);
    bad.extend_from_slice(&0u32.to_be_bytes());
    assert!(decode_complete(&bad).is_err());
}

#[test]
fn codec_message_framing() {
    let payload = vec![0xAA, 0xBB];
    let msg = encode_message(MSG_SUBMIT_BATCH, &payload);
    // len counts the type byte + payload.
    let mut expected = vec![];
    expected.extend_from_slice(&3u32.to_be_bytes());
    expected.push(MSG_SUBMIT_BATCH);
    expected.extend_from_slice(&payload);
    assert_eq!(msg, expected);

    let mut cursor = std::io::Cursor::new(msg);
    let (ty, body) = read_message(&mut cursor).unwrap();
    assert_eq!(ty, MSG_SUBMIT_BATCH);
    assert_eq!(body, payload);

    // Zero length is malformed (must at least carry the type byte).
    let mut cursor = std::io::Cursor::new(0u32.to_be_bytes().to_vec());
    assert_eq!(read_message(&mut cursor).unwrap_err(), CodecError::Truncated);
    // Over-cap length is refused before a single payload byte is read.
    let mut huge = vec![];
    huge.extend_from_slice(&(REINJECT_MAX_MSG as u32 + 2).to_be_bytes());
    huge.push(MSG_SUBMIT_BATCH);
    let mut cursor = std::io::Cursor::new(huge);
    assert_eq!(read_message(&mut cursor).unwrap_err(), CodecError::TooLarge);
    // Truncated payload.
    let mut short = vec![];
    short.extend_from_slice(&10u32.to_be_bytes());
    short.extend_from_slice(&[MSG_SUBMIT_BATCH, 0x01]);
    let mut cursor = std::io::Cursor::new(short);
    assert_eq!(
        read_message(&mut cursor).unwrap_err(),
        CodecError::Truncated
    );
    // Unknown types pass framing; the caller dispatches (and rejects).
    let msg = encode_message(99, &[]);
    let mut cursor = std::io::Cursor::new(msg);
    let (ty, body) = read_message(&mut cursor).unwrap();
    assert_eq!(ty, 99);
    assert!(body.is_empty());
}

#[test]
fn codec_wire_codes_pinned() {
    assert_eq!(MSG_SUBMIT_BATCH, 1);
    assert_eq!(MSG_CANCEL, 2);
    assert_eq!(MSG_ADMIT, 11);
    assert_eq!(MSG_COMPLETE, 12);
    assert_eq!(SUBMIT_MAX_FRAMES, 64);
    assert_eq!(SUBMIT_MAX_DATA_LEN, 65535);
    assert_eq!(REINJECT_MAX_MSG, 1_048_576);
    assert_eq!(ADMIT_OK, 0);
    assert_eq!(ADMIT_STALE, 1);
    assert_eq!(ADMIT_FULL, 2);
    assert_eq!(ADMIT_BAD_LEASE, 3);
    assert_eq!(ADMIT_SHUTDOWN, 4);
    assert_eq!(ReinjectOutcome::Written.wire(), OUTCOME_WRITTEN);
    assert_eq!(ReinjectOutcome::Stale.wire(), OUTCOME_STALE);
    assert_eq!(ReinjectOutcome::Cancelled.wire(), OUTCOME_CANCELLED);
    assert_eq!(ReinjectOutcome::Refused.wire(), OUTCOME_REFUSED);
    assert_eq!(ReinjectOutcome::Uncertain.wire(), OUTCOME_UNCERTAIN);
    for (code, outcome) in [
        (1, ReinjectOutcome::Written),
        (2, ReinjectOutcome::Stale),
        (3, ReinjectOutcome::Cancelled),
        (4, ReinjectOutcome::Refused),
        (5, ReinjectOutcome::Uncertain),
    ] {
        assert_eq!(ReinjectOutcome::from_wire(code), Some(outcome));
    }
    assert_eq!(ReinjectOutcome::from_wire(0), None);
    assert_eq!(ReinjectOutcome::from_wire(6), Some(ReinjectOutcome::Fenced));
    assert_eq!(ReinjectOutcome::from_wire(255), None);
    assert_eq!(ReinjectOutcome::Written.as_str(), "written");
    assert_eq!(ReinjectOutcome::Stale.as_str(), "stale");
    assert_eq!(ReinjectOutcome::Cancelled.as_str(), "cancelled");
    assert_eq!(ReinjectOutcome::Refused.as_str(), "refused");
    assert_eq!(ReinjectOutcome::Uncertain.as_str(), "uncertain");
}

// ---------- leased write classification ----------

#[test]
fn leased_classifier_maps_taxonomy() {
    use crate::io_uring_write::WriteResult;
    use std::cell::Cell;

    // Done: definitive full-frame delivery. No fallback.
    let ran = Cell::new(false);
    let c = classify_leased_write(WriteResult::Done(vec![0u8; 1400]), |_b| {
        ran.set(true);
        refused()
    });
    assert!(c.ok);
    assert!(!c.ring_terminal);
    assert!(c.demotion_cause.is_none());
    assert!(!ran.get());
    assert_eq!(c.verdict, TransferVerdict::Written { bytes: 1400 });

    // NothingWritten: nothing reached the fd; the sync fallback's verdict
    // decides. Fallback MUST run.
    for (sync, expect_written) in [
        (written(64), true),
        (
            TransferVerdict::Refused {
                reason: "e".to_string(),
            },
            false,
        ),
        (
            TransferVerdict::Uncertain {
                reason: "e".to_string(),
            },
            false,
        ),
    ] {
        let ran = Cell::new(false);
        let c = classify_leased_write(
            WriteResult::NothingWritten(vec![0u8; 64], "q full".to_string()),
            |_b| {
                ran.set(true);
                sync.clone()
            },
        );
        assert!(ran.get(), "NothingWritten must invoke the sync fallback");
        assert!(!c.ring_terminal, "transient: keep io_uring, no demotion");
        assert_eq!(c.ok, expect_written);
        assert_eq!(c.verdict, sync);
    }

    // Transferred: bytes already on the TUN (reaped, terminal) -> uncertain,
    // never re-sent. Ring healthy.
    let ran = Cell::new(false);
    let c = classify_leased_write(
        WriteResult::Transferred(vec![0u8; 8], "short write".to_string()),
        |_b| {
            ran.set(true);
            written(8)
        },
    );
    assert!(!c.ok);
    assert!(!c.ring_terminal);
    assert!(!ran.get(), "Transferred must never sync-retry");
    assert!(matches!(c.verdict, TransferVerdict::Uncertain { .. }));

    // Deferred: ambiguous (possibly in flight) -> uncertain, never retried.
    // Only a FATAL ring demotes.
    for fatal in [false, true] {
        let ran = Cell::new(false);
        let c = classify_leased_write(
            WriteResult::Deferred {
                id: 3,
                message: "storm".to_string(),
                fatal_ring: fatal,
            },
            |_b| {
                ran.set(true);
                written(8)
            },
        );
        assert!(!c.ok);
        assert!(!ran.get(), "Deferred must never sync-retry");
        assert!(matches!(c.verdict, TransferVerdict::Uncertain { .. }));
        assert_eq!(c.ring_terminal, fatal);
        assert_eq!(c.demotion_cause.is_some(), fatal);
    }
}

// ---------- stats / legacy path ----------

#[test]
fn stats_split_per_class_and_outcomes() {
    use crate::slowpath::SlowPathReinjector;
    let core = open_core();
    let r = SlowPathReinjector::new_without_worker_with_core(1500, core.clone());
    // Legacy adjudicated (lease None): admitted, but no table entry.
    let outcome = r.enqueue_adjudicated(vec![0x45u8; 64]).unwrap();
    assert!(matches!(
        outcome,
        crate::slowpath::EnqueueOutcome::Accepted
    ));
    assert_eq!(core.live_count(), 0, "legacy path tracks no completions");
    // Legacy delegated.
    let outcome = r.enqueue_delegated(vec![0x45u8; 64]).unwrap();
    assert!(matches!(
        outcome,
        crate::slowpath::EnqueueOutcome::Accepted
    ));
    // Leased submit through the reinjector chokepoint.
    let d = r.submit_leased(frame(1, 1, 64));
    assert!(d.admitted);
    assert_eq!(core.live_count(), 1);
    // Force an MTU refusal on each class.
    r.force_mtu_state_for_test(1500, 64, true);
    r.force_delegated_mtu_state_for_test(64, true);
    let outcome = r.enqueue_adjudicated(vec![0x45u8; 128]).unwrap();
    assert!(matches!(
        outcome,
        crate::slowpath::EnqueueOutcome::MtuExceeded
    ));
    let outcome = r.enqueue_delegated(vec![0x45u8; 128]).unwrap();
    assert!(matches!(
        outcome,
        crate::slowpath::EnqueueOutcome::MtuExceeded
    ));
    let stats = core.stats_snapshot();
    assert_eq!(stats.adjudicated_admitted, 2, "legacy + leased adjudicated");
    assert_eq!(stats.adjudicated_refused, 1);
    assert_eq!(stats.delegated_admitted, 1);
    assert_eq!(stats.delegated_refused, 1);
    assert_eq!(stats.live_descriptors, 1);
}

#[test]
fn stats_live_and_oldest_unacked() {
    let core = open_core();
    let stats = core.stats_snapshot();
    assert_eq!(stats.live_descriptors, 0);
    assert_eq!(stats.oldest_unacked_ms, 0);
    assert!(stats.is_empty());
    assert!(core.admit(&frame(1, 1, 64)).admitted);
    assert!(core.admit(&frame(2, 2, 64)).admitted);
    let stats = core.stats_snapshot();
    assert_eq!(stats.live_descriptors, 2);
    assert!(!stats.is_empty());
    assert_eq!(core.pre_write_check(&lease(1)), PreWrite::Proceed);
    assert!(core.resolve_write(&lease(1), written(64)));
    assert_eq!(core.drain_ready(1).len(), 1);
    assert_eq!(core.stats_snapshot().live_descriptors, 1);
    assert_eq!(core.pre_write_check(&lease(2)), PreWrite::Proceed);
    assert!(core.resolve_write(&lease(2), written(64)));
    assert_eq!(core.drain_ready(16).len(), 1);
    let stats = core.stats_snapshot();
    assert_eq!(stats.live_descriptors, 0);
    assert_eq!(stats.oldest_unacked_ms, 0, "gauge clears when empty");
}

#[test]
fn trusted_and_delegated_carry_no_lease_by_construction() {
    use crate::slowpath::SlowPathReinjector;
    let core = open_core();
    let r = SlowPathReinjector::new_without_worker_with_core(1500, core.clone());
    // Neither API takes a lease, so neither can create table entries.
    r.enqueue(vec![0x45u8; 64]).unwrap();
    r.enqueue_delegated(vec![0x45u8; 64]).unwrap();
    assert_eq!(core.live_count(), 0);
    assert!(core.drain_ready(16).is_empty());
}

// ---------- snapshot compat ----------

#[test]
fn old_snapshot_without_9506_fields_parses_authority_closed() {
    let json = serde_json::json!({
        "version": 27,
        "generation": 5u64,
        "generated_at": "2026-01-01T00:00:00Z",
        "summary": {
            "host_name": "test",
            "dataplane_type": "userspace",
            "interface_count": 0,
            "zone_count": 0,
            "policy_count": 0,
            "scheduler_count": 0,
            "ha_enabled": false
        }
    });
    let snap: crate::protocol::ConfigSnapshot = serde_json::from_value(json).unwrap();
    assert_eq!(snap.permit_epoch, 0, "absent permit_epoch defaults closed");
    assert!(snap.queue_epochs.is_empty());
    // Publishing a legacy snapshot closes 9506 authority; submits go stale
    // while the legacy lease-None path keeps working.
    let core = open_core();
    core.publish_epochs(
        snap.permit_epoch,
        &snap
            .queue_epochs
            .iter()
            .map(|q| (q.queue, q.epoch))
            .collect::<Vec<_>>(),
    );
    let d = core.admit(&frame(1, 1, 64));
    assert!(!d.admitted);
    assert_eq!(d.reason, ADMIT_STALE);
}

#[test]
fn snapshot_9506_fields_roundtrip_and_skip_when_unset() {
    let mut snap = crate::protocol::ConfigSnapshot::default();
    assert_eq!(snap.permit_epoch, 0);
    assert!(snap.queue_epochs.is_empty());
    let v = serde_json::to_value(&snap).unwrap();
    assert!(
        v.get("permit_epoch").is_none(),
        "unset permit_epoch must not perturb the wire specimen"
    );
    assert!(
        v.get("queue_epochs").is_none(),
        "empty queue_epochs must not perturb the wire specimen"
    );
    snap.permit_epoch = 9;
    snap.queue_epochs = vec![crate::protocol::QueueEpochSnapshot { queue: 3, epoch: 21 }];
    let v = serde_json::to_value(&snap).unwrap();
    assert_eq!(v["permit_epoch"], 9);
    assert_eq!(v["queue_epochs"][0]["queue"], 3);
    assert_eq!(v["queue_epochs"][0]["epoch"], 21);
    let back: crate::protocol::ConfigSnapshot = serde_json::from_value(v).unwrap();
    assert_eq!(back.permit_epoch, 9);
    assert_eq!(back.queue_epochs.len(), 1);
    assert_eq!(back.queue_epochs[0].queue, 3);
    assert_eq!(back.queue_epochs[0].epoch, 21);
}

#[test]
fn admit_dry_run_flag_refused_without_live_entry() {
    let core = open_core();
    let mut f = frame(1, 1, 64);
    f.flags = SUBMIT_FLAG_DRY_RUN;
    let d = core.admit(&f);
    assert!(!d.admitted, "dry-run frames must not enter the write admission API");
    assert_eq!(d.reason, ADMIT_NON_DRY_RUN);
    assert_eq!(core.stats_snapshot().non_dry_run_refused, 1);
    assert_eq!(core.live_count(), 0);
    assert!(core.drain_ready(16).is_empty());
}

#[test]
fn submit_adjudicated_dry_run_flag_refused_without_q0_enqueue() {
    use crate::slowpath::SlowPathReinjector;

    let core = open_core();
    let reinjector = SlowPathReinjector::new_without_worker_with_core(1500, core.clone());
    let mut f = frame(1, 1, 64);
    f.flags = SUBMIT_FLAG_DRY_RUN;
    let d = reinjector.submit_adjudicated_frame(f);
    assert!(
        !d.admitted,
        "dry-run frames must be refused before the q0 writer path"
    );
    assert_eq!(d.reason, ADMIT_NON_DRY_RUN);
    assert_eq!(core.stats_snapshot().non_dry_run_refused, 1);
    assert_eq!(core.live_count(), 0);
    assert_eq!(reinjector.delegated_status().queued_packets, 0);
    assert!(core.drain_ready(16).is_empty());
}

#[test]
fn codec_admit_non_dry_run_reason_roundtrips() {
    let decision = AdmitDecision {
        request_id: 9,
        permit_epoch: PERMIT,
        queue_epoch: QEPOCH,
        queue_number: 1,
        family: ORIGIN_INET,
        hook: ORIGIN_FORWARD,
        owned_ifindex: 42,
        admitted: false,
        reason: ADMIT_NON_DRY_RUN,
    };
    let encoded = encode_admit(std::slice::from_ref(&decision));
    let decoded = decode_admit(&encoded).expect("reason 7 is a valid refusal");
    assert_eq!(decoded, vec![decision]);
    assert_eq!(encode_admit(&decoded), encoded);
}

#[test]
fn admission_rejects_invalid_capture_provenance() {
    let cases = [
        (ORIGIN_BRIDGE, ORIGIN_FORWARD, ADMIT_BRIDGE),
        (ORIGIN_BRIDGE, ORIGIN_INPUT, ADMIT_BRIDGE),
        (ORIGIN_INET, ORIGIN_INPUT, ADMIT_INPUT_HOOK),
    ];
    for (family, hook, reason) in cases {
        let core = open_core();
        let mut f = frame(1, 1, 64);
        f.origin.family = family;
        f.origin.hook = hook;
        let decision = core.admit(&f);
        assert!(!decision.admitted, "invalid origin must not reach q0");
        assert_eq!(decision.reason, reason);
        assert_eq!(core.live_count(), 0);
        assert!(core.drain_ready(16).is_empty());
    }

    let core = open_core();
    let mut malformed = frame(2, 1, 64);
    malformed.origin.owner.clear();
    let decision = core.admit(&malformed);
    assert!(!decision.admitted);
    assert_eq!(decision.reason, ADMIT_BAD_LEASE);
    assert_eq!(core.live_count(), 0);
}

#[test]
fn admission_rejects_zero_queue_number() {
    let core = open_core();
    let mut f = frame(1, 1, 64);
    f.lease.queue_number = 0;
    let decision = core.admit(&f);
    assert!(!decision.admitted);
    assert_eq!(decision.reason, ADMIT_BAD_LEASE);
    assert_eq!(core.live_count(), 0);
}

#[test]
fn admission_rejects_unknown_submit_flags() {
    let core = open_core();
    let mut f = frame(1, 1, 64);
    f.flags = 0x80;
    let decision = core.admit(&f);
    assert!(!decision.admitted);
    assert_eq!(decision.reason, ADMIT_BAD_LEASE);
    assert_eq!(core.live_count(), 0);
    let payload = encode_submit_batch(&[f]);
    assert_eq!(decode_submit_batch(&payload).unwrap_err(), CodecError::BadFlags);
}

#[test]
fn dry_run_writer_refusal_counts_adjudicated_class() {
    use crate::slowpath::SlowPathReinjector;

    let core = open_core();
    let reinjector = SlowPathReinjector::new_without_worker_with_core(1500, core.clone());
    let mut f = frame(1, 1, 64);
    f.flags = SUBMIT_FLAG_DRY_RUN;
    let decision = reinjector.submit_adjudicated_frame(f);
    assert!(!decision.admitted);
    let stats = core.stats_snapshot();
    assert_eq!(stats.non_dry_run_refused, 1);
    assert_eq!(stats.adjudicated_refused, 1);
    assert_eq!(core.live_count(), 0);
    assert_eq!(reinjector.delegated_status().queued_packets, 0);
}

#[test]
fn cancel_queue_scope_tombstones_pair_blocks_readmit_and_republish() {
    let core = open_core();
    assert!(core.admit(&frame(1, 1, 64)).admitted);
    let mut f2 = frame(2, 1, 64);
    f2.lease.queue_number = 2;
    f2.lease.queue_epoch = 13;
    assert!(core.admit(&f2).admitted);
    assert_eq!(core.cancel(&CancelScope::queue(2, 13)), vec![2]);
    // Immediate re-admit of the same tombstoned pair must be stale.
    let mut f3 = frame(3, 1, 64);
    f3.lease.queue_number = 2;
    f3.lease.queue_epoch = 13;
    let d = core.admit(&f3);
    assert!(!d.admitted, "tombstoned (queue,epoch) must not re-admit");
    assert_eq!(d.reason, ADMIT_STALE);
    // Same-epoch republish must not reopen the tombstoned pair.
    core.publish_epochs(PERMIT, &[(1, QEPOCH), (2, 13)]);
    let mut f4 = frame(4, 1, 64);
    f4.lease.queue_number = 2;
    f4.lease.queue_epoch = 13;
    let d = core.admit(&f4);
    assert!(!d.admitted, "republish must not erase tombstone");
    assert_eq!(d.reason, ADMIT_STALE);
    // A newer epoch for that queue admits; other queue unaffected.
    core.publish_epochs(PERMIT, &[(1, QEPOCH), (2, 14)]);
    let mut f5 = frame(5, 1, 64);
    f5.lease.queue_number = 2;
    f5.lease.queue_epoch = 14;
    assert!(core.admit(&f5).admitted, "newer epoch for queue admits");
    assert!(core.admit(&frame(6, 2, 64)).admitted, "other queue unaffected");
}

#[test]
fn announce_wire_roundtrip_pins_run_generation_permit_and_queue_epochs() {
    let announcement = AuthorityAnnouncement {
        run_id: "run-1".to_string(),
        generation: 4,
        permit_epoch: 9,
        permit_open: true,
        queue_epochs: vec![(1, 11), (2, 13)],
    };
    let payload = encode_announce(&announcement);
    assert_eq!(
        payload,
        vec![
            5, b'r', b'u', b'n', b'-', b'1', // run_id
            0, 0, 0, 0, 0, 0, 0, 4, // generation
            0, 0, 0, 0, 0, 0, 0, 9, // permit_epoch
            1, // permit_open
            0, 2, // queue count
            0, 1, 0, 0, 0, 0, 0, 0, 0, 11,
            0, 2, 0, 0, 0, 0, 0, 0, 0, 13,
        ]
    );
    assert_eq!(decode_announce(&payload), Ok(announcement));
    assert_eq!(
        decode_announce(&[
            3, b'r', b'u', b'n',
            0, 0, 0, 0, 0, 0, 0, 4,
            0, 0, 0, 0, 0, 0, 0, 9,
            2, // invalid bool
            0, 0,
        ]),
        Err(CodecError::BadValue)
    );
}

#[test]
fn authority_handoff_carries_announce_and_tombstones_to_target() {
    let fallback = ReinjectCore::new_shared();
    assert!(fallback.announce_epochs("run-1", 4, PERMIT, true, &[(1, QEPOCH), (2, 13)]));
    let mut cancelled = frame(1, 1, 64);
    cancelled.lease.queue_number = 2;
    cancelled.lease.queue_epoch = 13;
    assert!(fallback.admit(&cancelled).admitted);
    assert_eq!(fallback.cancel(&CancelScope::queue(2, 13)), vec![1]);

    let target = ReinjectCore::new_shared();
    target.copy_authority_from(&fallback);

    let mut stale = frame(2, 1, 64);
    stale.lease.queue_number = 2;
    stale.lease.queue_epoch = 13;
    assert_eq!(target.admit(&stale).reason, ADMIT_STALE);
    assert!(
        target.admit(&frame(3, 1, 64)).admitted,
        "authority handoff must preserve an unaffected queue"
    );
}

#[test]
fn announce_zero_revokes_prior_open_permit() {
    let core = open_core();
    assert!(core.admit(&frame(1, 1, 64)).admitted);
    assert!(core.announce_epochs("run-1", 4, 0, false, &[]));

    let mut old_lease = frame(2, 1, 64);
    let decision = core.admit(&old_lease);
    assert!(!decision.admitted);
    assert_eq!(decision.reason, ADMIT_STALE);
    old_lease.lease.request_id = 3;
    assert_eq!(
        core.authority_snapshot(),
        ("run-1".to_string(), 4, PERMIT, false, Vec::new())
    );
}
#[test]
fn authority_restart_accepts_new_run_id_with_lower_epoch() {
    let core = ReinjectCore::new_shared();
    assert!(core.announce_epochs("run-a", 4, 9, true, &[(1, 11)]));
    assert!(core.announce_epochs("run-b", 1, 1, true, &[(1, 2)]));
    assert_eq!(
        core.authority_snapshot(),
        ("run-b".to_string(), 1, 1, true, vec![(1, 2)])
    );
}
#[test]
fn authority_rotation_accepts_generation_advance_same_epoch() {
    let core = ReinjectCore::new_shared();
    assert!(core.announce_epochs("run-1", 4, PERMIT, true, &[(1, QEPOCH)]));
    assert!(core.announce_epochs("run-1", 5, PERMIT, true, &[(1, QEPOCH + 1)]));
    assert_eq!(
        core.authority_snapshot(),
        (
            "run-1".to_string(),
            5,
            PERMIT,
            true,
            vec![(1, QEPOCH + 1)]
        )
    );
}

#[test]
fn authority_restart_clears_old_run_provenance() {
    let core = ReinjectCore::new_shared();
    assert!(core.announce_epochs("run-a", 4, PERMIT, true, &[(1, QEPOCH)]));
    assert!(core.admit(&frame(1, 1, 64)).admitted);
    assert_eq!(core.pre_write_check(&lease(1)), PreWrite::Proceed);
    assert!(core.resolve_write(&lease(1), written(64)));
    assert_eq!(
        core.status_snapshot()
            .expect("announced core has a status")
            .provenance
            .len(),
        1
    );

    assert!(core.announce_epochs("run-b", 1, 1, true, &[(1, 2)]));
    let status = core.status_snapshot().expect("new run has a status");
    assert_eq!(status.run_id, "run-b");
    assert!(status.provenance.is_empty());
}
