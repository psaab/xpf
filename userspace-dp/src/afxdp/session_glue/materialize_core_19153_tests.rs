//! #19153: the materialize core's outcomes, and the one identity rule it
//! shares with #18552's promotion.
//!
//! `materialize_current_shared_under_permit` is called here directly, under
//! permits claimed on the pair a resolve's capture names (as the poll path's
//! wrapper claims them). The fixture is `materialize_permit_19153_tests.rs`'s.
//!
//! - a completed removal is `SharedAbsent`;
//! - a superseded capture is `Superseded` for a new session id AND for a new
//!   translation under the same id (not `InstallRefused`: the NAT decision is
//!   part of the identity, not only of the companion-witness check);
//! - an unleased current row is `Installed`, and a locally owned one
//!   `SharedLocal`;
//! - a current row whose zone vanished is `StaleReplayFenced`, and a live
//!   local incumbent makes the install `InstallRefused` (fold 1);
//! - the #10582 clobber refusal is judged before any claim: it allocates
//!   nothing (fold 1, D2);
//! - the predicate `promote::same_synced_incarnation`, as a table;
//! - its #18552 consumer (`synced_row_incarnation`) on a NAT-only change
//!   under the zero-id sentinel.

use super::materialize_permit_19153_tests::{
    ID_A, ID_B, NOW_NS, Shared, flow_key, peer_row, snat,
};
use super::*;
use crate::afxdp::bpf_map::global_tuple_gate;

/// The core's outcome for a resolve's capture, under permits claimed on the
/// pair the capture names.
fn core_outcome(
    sessions: &mut SessionTable,
    shared: &Shared,
    forwarding: &ForwardingState,
    captured: &SyncedSessionEntry,
) -> MaterializeOutcome {
    let companion = reverse_session_key(&captured.key, captured.decision.nat);
    let permits = global_tuple_gate()
        .try_acquire_installs([captured.key.clone(), companion])
        .expect("premise: the pair is unleased");
    materialize_current_shared_under_permit(
        sessions,
        &shared.sessions,
        forwarding,
        &captured.key,
        Some(CapturedIncarnation::of(captured)),
        MaterializeInstall {
            now_ns: NOW_NS,
            tcp_flags: crate::tcp_flags::TCP_ACK,
            fabric_adopted: false,
        },
        &permits,
    )
}

fn outcome_name(outcome: &MaterializeOutcome) -> &'static str {
    match outcome {
        MaterializeOutcome::Installed(_) => "Installed",
        MaterializeOutcome::SharedLocal(_) => "SharedLocal",
        MaterializeOutcome::SharedAbsent => "SharedAbsent",
        MaterializeOutcome::Superseded => "Superseded",
        MaterializeOutcome::StaleReplayFenced => "StaleReplayFenced",
        MaterializeOutcome::InstallRefused => "InstallRefused",
    }
}

/// A zone-validated forwarding view naming the fixture's zones (1 lan, 2 wan),
/// so the #10612 fence is live: a row naming any other zone is stale.
fn zone_validated_forwarding() -> ForwardingState {
    let mut forwarding = ForwardingState::default();
    forwarding.zone_id_to_name.insert(1, "lan".to_string());
    forwarding.zone_id_to_name.insert(2, "wan".to_string());
    forwarding.zone_set_validated = true;
    forwarding
}

/// All six outcomes the core owes a caller (#19153 fold 1, Codex gap: the
/// fence and the refused install too), and the table each leaves: only
/// `Installed` and `SharedLocal` install; `InstallRefused` leaves the local
/// incumbent exactly as it was.
#[test]
fn the_materialize_core_reports_each_outcome_19153() {
    let shared = Shared::new();
    let forwarding = zone_validated_forwarding();

    // Removed: the capture's row is gone.
    let removed_key = flow_key(42_001);
    shared.publish(&peer_row(removed_key.clone(), ID_A, snat(40_201)));
    let removed_capture = shared.capture(&removed_key);
    shared.remove(&removed_key);

    // Superseded: a new id under the same translation, and the same id under
    // a new translation.
    let new_id_key = flow_key(42_002);
    shared.publish(&peer_row(new_id_key.clone(), ID_A, snat(40_202)));
    let new_id_capture = shared.capture(&new_id_key);
    shared.remove(&new_id_key);
    shared.publish(&peer_row(new_id_key.clone(), ID_B, snat(40_202)));
    let new_nat_key = flow_key(42_003);
    shared.publish(&peer_row(new_nat_key.clone(), ID_A, snat(40_203)));
    let new_nat_capture = shared.capture(&new_nat_key);
    shared.remove(&new_nat_key);
    shared.publish(&peer_row(new_nat_key.clone(), ID_A, snat(40_303)));

    // Installed, and SharedLocal (a sibling worker's local publish).
    let current_key = flow_key(42_004);
    shared.publish(&peer_row(current_key.clone(), ID_A, snat(40_204)));
    let current_capture = shared.capture(&current_key);
    let local_key = flow_key(42_005);
    let mut local = peer_row(local_key.clone(), ID_B, snat(40_205));
    local.origin = SessionOrigin::ForwardFlow;
    shared.publish(&local);
    let local_capture = shared.capture(&local_key);

    // StaleReplayFenced: the capture was live, the current row (same
    // incarnation) names a zone this node no longer has.
    let stale_key = flow_key(42_008);
    shared.publish(&peer_row(stale_key.clone(), ID_A, snat(40_208)));
    let stale_capture = shared.capture(&stale_key);
    let mut stale = peer_row(stale_key.clone(), ID_A, snat(40_208));
    stale.metadata.egress_zone = 9;
    shared.publish(&stale);

    // InstallRefused: a live LOCAL incumbent under the key (#10582).
    let incumbent_key = flow_key(42_009);
    shared.publish(&peer_row(incumbent_key.clone(), ID_A, snat(40_209)));
    let incumbent_capture = shared.capture(&incumbent_key);

    let cases: [(&str, &SyncedSessionEntry, bool, &str, Option<SessionOrigin>); 7] = [
        ("removed", &removed_capture, false, "SharedAbsent", None),
        ("new session id", &new_id_capture, false, "Superseded", None),
        ("new translation", &new_nat_capture, false, "Superseded", None),
        ("current", &current_capture, false, "Installed", Some(SessionOrigin::SharedMaterialize)),
        ("locally owned", &local_capture, false, "SharedLocal", Some(SessionOrigin::WorkerLocalImport)),
        ("stale current row", &stale_capture, false, "StaleReplayFenced", None),
        ("local incumbent", &incumbent_capture, true, "InstallRefused", Some(SessionOrigin::ForwardFlow)),
    ];
    for (case, capture, local_incumbent, expected, row) in cases {
        let mut sessions = SessionTable::new();
        if local_incumbent {
            assert!(
                sessions.install_with_protocol(
                    capture.key.clone(),
                    capture.decision,
                    capture.metadata.clone(),
                    NOW_NS,
                    PROTO_TCP,
                    crate::tcp_flags::TCP_ACK,
                ),
                "premise ({case}): the local incumbent installs"
            );
        }
        let outcome = core_outcome(&mut sessions, &shared, &forwarding, capture);
        assert_eq!(outcome_name(&outcome), expected, "{case}: outcome");
        assert_eq!(
            sessions.entry_with_origin(&capture.key).map(|(_, _, origin)| origin),
            row,
            "{case}: the row the table holds afterwards"
        );
        assert_eq!(sessions.len(), usize::from(row.is_some()), "{case}: rows");
    }
}

/// The one identity rule, as a table. NAT equality is mandatory; the session
/// id is compared only when the shared row's id is non-zero.
#[test]
fn the_synced_incarnation_predicate_table_19153() {
    let key = flow_key(42_006);
    let nat = snat(40_206);
    let other_nat = snat(40_306);
    let rows: [(&str, NatDecision, u64, SyncedSessionEntry, bool); 5] = [
        ("same", nat, ID_A, peer_row(key.clone(), ID_A, nat), true),
        ("nat differs", nat, ID_A, peer_row(key.clone(), ID_A, other_nat), false),
        ("id differs", nat, ID_A, peer_row(key.clone(), ID_B, nat), false),
        ("shared id 0, nat equal", nat, ID_A, peer_row(key.clone(), 0, nat), true),
        ("shared id 0, nat differs", nat, ID_A, peer_row(key.clone(), 0, other_nat), false),
    ];
    for (row, nat, session_id, entry, expected) in rows {
        assert_eq!(
            super::promote::same_synced_incarnation(nat, session_id, &entry),
            expected,
            "same_synced_incarnation: {row}"
        );
    }
}

/// #18552's consumer of the same rule. A worker row (non-zero id, as the
/// worker always stores) against a shared row with the zero-id sentinel: only
/// the NAT decision is compared, and a translation change is `Superseded`.
#[test]
fn promotion_identity_supersedes_a_zero_id_translation_change_18552_19153() {
    let key = flow_key(42_007);
    let mut sessions = SessionTable::new();
    assert!(
        sessions.upsert_synced_with_origin(
            peer_row(key.clone(), ID_A, snat(40_207)).into_session_install(NOW_NS),
            false,
        ),
        "premise: the worker row installs"
    );
    let shared = Shared::new();
    shared.publish(&peer_row(key.clone(), 0, snat(40_307)));
    let changed = super::promote::synced_row_incarnation(&sessions, &shared.sessions, &key);
    shared.remove(&key);
    shared.publish(&peer_row(key.clone(), 0, snat(40_207)));
    let same = super::promote::synced_row_incarnation(&sessions, &shared.sessions, &key);

    assert_eq!(
        changed,
        super::promote::SyncedRowIncarnation::Superseded,
        "a zero-id shared row under a different translation must be Superseded"
    );
    assert_eq!(
        same,
        super::promote::SyncedRowIncarnation::Current,
        "a zero-id shared row under the same translation is Current"
    );
}

/// #19153 fold 1 (D2, r24 P3-1): a non-adopted materialize over a live LOCAL
/// incumbent (#10582) is refused on this worker's own table before any claim.
/// That refusal lasts as long as the incumbent, so every packet of the flow
/// meets it: it must not build a permit set (two Vecs, an admission `Arc`, gate
/// entries) or re-read shared. Zero heap allocations is the observable.
#[test]
fn a_local_incumbent_refusal_claims_nothing_19153() {
    let shared = Shared::new();
    let key = flow_key(42_010);
    shared.publish(&peer_row(key.clone(), ID_A, snat(40_210)));
    let captured = shared.capture(&key);
    let mut sessions = SessionTable::new();
    assert!(
        sessions.install_with_protocol(
            key.clone(),
            captured.decision,
            captured.metadata.clone(),
            NOW_NS,
            PROTO_TCP,
            crate::tcp_flags::TCP_ACK,
        ),
        "premise: the local incumbent installs"
    );
    // This thread's gate exists before counting (#18834 per-thread gates).
    let _ = global_tuple_gate();
    let forwarding = ForwardingState::default();
    let mut resolved = ResolvedSessionLookup::shared(captured.clone());
    let ((_, install_failed), allocations) = crate::test_alloc::count_allocs(|| {
        materialize_shared_session_hit(
            &mut sessions,
            &shared.sessions,
            &mut resolved,
            &forwarding,
            NOW_NS + 1,
            crate::tcp_flags::TCP_ACK,
        )
    });
    assert!(install_failed, "the local incumbent must refuse the materialize");
    assert_eq!(
        sessions.entry_with_origin(&key).map(|(_, _, origin)| origin),
        Some(SessionOrigin::ForwardFlow),
        "the local incumbent must survive"
    );
    assert_eq!(
        allocations, 0,
        "a worker-local #10582 refusal must be judged before the claim, not pay the permit set \
         and the shared re-read on every packet"
    );
}
