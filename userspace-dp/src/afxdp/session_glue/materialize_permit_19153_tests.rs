//! #19153: a worker's materialize-on-miss joins the tuple gate's install
//! protocol and installs only what shared authority names under its permit.
//!
//! The repro (`policy_batch_materialize_race_tests.rs`) drives the commit-time
//! policy-delete batch end to end. These cells pin the mechanism one property
//! at a time through the poll path's materialize wrapper, against the real
//! gate (this thread's under `cfg(test)`, #18834) and the real shared map:
//!
//! - (b) a completed removal (lease, shared rows removed, lease dropped)
//!   between the resolve's capture and the materialize installs nothing;
//! - (c) a held lease on the pair, or on the reply tuple alone, refuses the
//!   materialize until it drops;
//! - (d) a shared row replaced by another incarnation (a new session id, or a
//!   new translation) refuses the stale capture, and the next packet installs
//!   the current row;
//! - (e) the control: an unleased, current materialize installs as before and
//!   releases its permit, and a locally owned shared row still installs;
//! - zero id: a capture that matches on the NAT decision alone installs the
//!   CURRENT shared content, never the capture.
//!
//! The core's outcomes, the identity predicate and its #18552 consumer are in
//! `materialize_core_19153_tests.rs`, which reuses this file's fixture.

use super::*;
use crate::afxdp::bpf_map::global_tuple_gate;

pub(super) const NOW_NS: u64 = 5_000_000;
pub(super) const ID_A: u64 = 0x1915_3001;
pub(super) const ID_B: u64 = 0x1915_3002;

/// A TEST-NET tuple of the cell's own.
pub(super) fn flow_key(src_port: u16) -> SessionKey {
    SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 153)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 153)),
        src_port,
        dst_port: 443,
        discriminator: Default::default(),
        routing_domain: 0,
    }
}

pub(super) fn snat(port: u16) -> NatDecision {
    NatDecision {
        rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 153))),
        rewrite_src_port: Some(port),
        ..NatDecision::default()
    }
}

/// A peer-synced forward row, as an HA import publishes it.
pub(super) fn peer_row(key: SessionKey, session_id: u64, nat: NatDecision) -> SyncedSessionEntry {
    SyncedSessionEntry {
        sibling_last_seen_ns: 0,
        last_served_ns: 0,
        key,
        decision: SessionDecision {
            resolution: crate::afxdp::testfx::test_resolution(),
            nat,
            install_table_domain: 0,
            install_table_check: 0,
        },
        metadata: crate::afxdp::testfx::test_metadata(),
        leak_incarnation: 0,
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: crate::tcp_flags::TCP_ACK,
        generation: 0,
        session_id,
        tcp_close_class: 0,
        tcp_handshake_state: 0,
        rev_packets: 0,
        fwd_packets: 0,
        pptp_call_ids: 0,
        persistent_lease_hold: None,
        source_nat_static: None,
    }
}

pub(super) struct Shared {
    pub(super) sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    nat: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    wire: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    indexes: crate::afxdp::SharedSessionOwnerRgIndexes,
}

impl Shared {
    pub(super) fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(FastMap::default())),
            nat: Arc::new(Mutex::new(FastMap::default())),
            wire: Arc::new(Mutex::new(FastMap::default())),
            indexes: crate::afxdp::SharedSessionOwnerRgIndexes::default(),
        }
    }

    pub(super) fn publish(&self, entry: &SyncedSessionEntry) {
        crate::afxdp::shared_ops::publish_shared_session(
            &self.sessions,
            &self.nat,
            &self.wire,
            &self.indexes,
            entry,
        );
    }

    pub(super) fn remove(&self, key: &SessionKey) {
        crate::afxdp::shared_ops::remove_shared_session(
            &self.sessions,
            &self.nat,
            &self.wire,
            &self.indexes,
            key,
        );
    }

    /// The resolve's capture: the shared row the lookup found.
    pub(super) fn capture(&self, key: &SessionKey) -> SyncedSessionEntry {
        crate::afxdp::shared_ops::lookup_shared_session(&self.sessions, key)
            .expect("premise: the resolve found the shared row")
    }
}

/// The poll path's materialize of a resolve's capture, through the real
/// wrapper. Returns `install_failed`.
fn materialize(
    sessions: &mut SessionTable,
    shared: &Shared,
    captured: &SyncedSessionEntry,
) -> bool {
    let mut resolved = ResolvedSessionLookup::shared(captured.clone());
    let (_, install_failed) = materialize_shared_session_hit(
        sessions,
        &shared.sessions,
        &mut resolved,
        &ForwardingState::default(),
        NOW_NS,
        crate::tcp_flags::TCP_ACK,
    );
    install_failed
}

/// (b) The post-removal gap. The resolve captured the shared pair; then a
/// delete completed (the commit-time policy batch's shape: lease the pair,
/// remove both shared rows, drop the lease) before the packet's materialize
/// took its permit. The permit is granted (nothing holds the pair any more),
/// so only the re-read under it stops the revoked incarnation from being
/// installed. Neither half installs.
#[test]
fn a_materialize_after_a_completed_removal_installs_nothing_19153() {
    let shared = Shared::new();
    let forward_key = flow_key(41_001);
    // A NAT-free pair, as in the repro: the reverse key is the swapped tuple.
    let forward = peer_row(forward_key.clone(), ID_A, NatDecision::default());
    shared.publish(&forward);
    let reverse_key = reverse_session_key(&forward_key, NatDecision::default());
    let mut reverse = peer_row(reverse_key.clone(), ID_A + 1, NatDecision::default());
    reverse.metadata.is_reverse = true;
    shared.publish(&reverse);
    let captured_forward = shared.capture(&forward_key);
    let captured_reverse = shared.capture(&reverse_key);

    let lease = global_tuple_gate()
        .acquire_lease([forward_key.clone(), reverse_key.clone()])
        .expect("premise: the idle pair leases");
    shared.remove(&forward_key);
    shared.remove(&reverse_key);
    drop(lease);

    let mut sessions = SessionTable::new();
    let forward_failed = materialize(&mut sessions, &shared, &captured_forward);
    let reverse_failed = materialize(&mut sessions, &shared, &captured_reverse);

    assert!(
        forward_failed && reverse_failed,
        "both materializes must report install_failed after the removal \
         (forward={forward_failed}, reverse={reverse_failed})"
    );
    assert_eq!(
        (sessions.session_id_for(&forward_key), sessions.session_id_for(&reverse_key)),
        (0, 0),
        "the removed incarnation must not be installed on the worker"
    );
    assert_eq!(sessions.len(), 0, "nothing at all may install");
}

/// (c) A held lease on the pair (an HA import or delete, or the policy batch)
/// refuses the materialize: `install_failed`, no row. A lease on the reply
/// tuple alone refuses it too, since the materialize claims the pair. Once the
/// lease drops, the next packet's materialize installs.
#[test]
fn a_held_lease_refuses_the_materialize_until_it_drops_19153() {
    let shared = Shared::new();
    let forward_key = flow_key(41_002);
    shared.publish(&peer_row(forward_key.clone(), ID_A, snat(40_002)));
    let captured = shared.capture(&forward_key);
    let reverse_key = reverse_session_key(&forward_key, captured.decision.nat);
    let mut sessions = SessionTable::new();

    let pair_lease = global_tuple_gate()
        .acquire_lease([forward_key.clone(), reverse_key.clone()])
        .expect("premise: the idle pair leases");
    let pair_failed = materialize(&mut sessions, &shared, &captured);
    let rows_under_pair_lease = sessions.len();
    drop(pair_lease);

    let reply_lease = global_tuple_gate()
        .acquire_lease([reverse_key.clone()])
        .expect("premise: the idle reply tuple leases");
    let reply_failed = materialize(&mut sessions, &shared, &captured);
    let rows_under_reply_lease = sessions.len();
    drop(reply_lease);

    let retry_failed = materialize(&mut sessions, &shared, &captured);

    assert!(
        pair_failed && rows_under_pair_lease == 0,
        "a lease on the pair must refuse the materialize (install_failed={pair_failed}, \
         rows={rows_under_pair_lease})"
    );
    assert!(
        reply_failed && rows_under_reply_lease == 0,
        "a lease on the reply tuple must refuse the materialize \
         (install_failed={reply_failed}, rows={rows_under_reply_lease})"
    );
    assert!(
        !retry_failed && sessions.session_id_for(&forward_key) == ID_A,
        "after the lease drops, the next materialize must install (install_failed={retry_failed}, \
         id={:#x})",
        sessions.session_id_for(&forward_key)
    );
}

/// (d) The shared row was replaced by a different incarnation between the
/// resolve's capture and the materialize: a reused 5-tuple's new session id,
/// or the same id under a new translation. The stale capture installs nothing.
/// The next packet captures the current row and installs it.
#[test]
fn a_superseded_shared_row_refuses_the_stale_capture_19153() {
    let legs: [(&str, u16, u64, NatDecision); 2] = [
        ("session id differs", 41_003, ID_B, snat(40_003)),
        ("translation differs", 41_004, ID_A, snat(40_104)),
    ];
    for (leg, port, successor_id, successor_nat) in legs {
        let shared = Shared::new();
        let key = flow_key(port);
        shared.publish(&peer_row(key.clone(), ID_A, snat(port - 1_000)));
        let captured = shared.capture(&key);
        shared.remove(&key);
        shared.publish(&peer_row(key.clone(), successor_id, successor_nat));

        let mut sessions = SessionTable::new();
        let stale_failed = materialize(&mut sessions, &shared, &captured);
        let rows_after_stale = sessions.len();
        let current = shared.capture(&key);
        let current_failed = materialize(&mut sessions, &shared, &current);
        let installed_nat = sessions
            .entry_with_origin(&key)
            .map(|(decision, _, _)| decision.nat);

        assert!(
            stale_failed && rows_after_stale == 0,
            "{leg}: the stale capture must install nothing (install_failed={stale_failed}, \
             rows={rows_after_stale})"
        );
        assert!(
            !current_failed
                && sessions.session_id_for(&key) == successor_id
                && installed_nat == Some(successor_nat),
            "{leg}: the next packet's capture of the current row must install it \
             (install_failed={current_failed}, id={:#x}, nat={installed_nat:?})",
            sessions.session_id_for(&key)
        );
    }
}

/// (e) The control. With no lease and the captured incarnation current, the
/// materialize installs as before: the captured id and translation, as a
/// `SharedMaterialize` replica. Its permit is released (a lease of the pair
/// succeeds at once). A locally owned shared row (a sibling worker's publish)
/// still installs, as a `WorkerLocalImport` replica.
#[test]
fn an_unleased_current_materialize_installs_as_before_19153() {
    let shared = Shared::new();
    let key = flow_key(41_005);
    shared.publish(&peer_row(key.clone(), ID_A, snat(40_005)));
    let captured = shared.capture(&key);
    let companion = reverse_session_key(&key, captured.decision.nat);
    let mut sessions = SessionTable::new();

    let failed = materialize(&mut sessions, &shared, &captured);
    let installed = sessions.entry_with_origin(&key);
    let lease_after = global_tuple_gate().acquire_lease([key.clone(), companion]);
    let gate_released = lease_after.is_ok();
    drop(lease_after);

    let local_key = flow_key(41_006);
    let mut local = peer_row(local_key.clone(), ID_B, snat(40_006));
    local.origin = SessionOrigin::ForwardFlow;
    shared.publish(&local);
    let local_captured = shared.capture(&local_key);
    let local_failed = materialize(&mut sessions, &shared, &local_captured);
    let local_origin = sessions
        .entry_with_origin(&local_key)
        .map(|(_, _, origin)| origin);

    assert!(!failed, "the control materialize must install");
    assert!(
        installed.as_ref().is_some_and(|(decision, _, origin)| {
            decision.nat == captured.decision.nat && *origin == SessionOrigin::SharedMaterialize
        }) && sessions.session_id_for(&key) == ID_A,
        "the control must install the captured incarnation as SharedMaterialize ({installed:?}, \
         id={:#x})",
        sessions.session_id_for(&key)
    );
    assert!(gate_released, "the materialize must release its permit before returning");
    assert!(
        !local_failed && local_origin == Some(SessionOrigin::WorkerLocalImport),
        "a locally owned shared row must still install as WorkerLocalImport \
         (install_failed={local_failed}, origin={local_origin:?})"
    );
}

/// Zero id. A shared session id of 0 is the unknown/legacy sentinel, so the
/// capture matches the current row on the NAT decision alone. That match only
/// says this packet resolved against the same translation. The row installed
/// is the CURRENT shared content, never the capture: a legacy peer's same-NAT
/// reuse of the tuple installs the current row's state.
#[test]
fn a_zero_id_match_installs_the_current_shared_content_19153() {
    let shared = Shared::new();
    let key = flow_key(41_007);
    let mut captured_row = peer_row(key.clone(), 0, snat(40_007));
    captured_row.metadata.egress_zone = 2;
    shared.publish(&captured_row);
    let captured = shared.capture(&key);
    let mut current_row = peer_row(key.clone(), 0, snat(40_007));
    current_row.metadata.egress_zone = 3;
    shared.remove(&key);
    shared.publish(&current_row);

    let mut sessions = SessionTable::new();
    let failed = materialize(&mut sessions, &shared, &captured);
    let installed_zone = sessions
        .entry_with_origin(&key)
        .map(|(_, metadata, _)| metadata.egress_zone);

    assert!(!failed, "a zero-id capture with the same NAT decision must install");
    assert_eq!(
        installed_zone,
        Some(3),
        "the CURRENT shared content must be installed, not the capture (egress zone 2)"
    );
}
