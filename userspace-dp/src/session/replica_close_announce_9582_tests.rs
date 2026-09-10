//! #9582: a close that ONLY a worker replica sees must reach the peer.
//!
//! Only the installing worker announced close-class transitions. A replica of a
//! local session has origin `WorkerLocalImport`, and `emit_close_state_update` gated
//! it out with every other peer-synced origin. So a server FIN or RST arriving on
//! another RSS queue was never announced. Written before the fix; at base the
//! acceptance cell is RED and the control is GREEN.

use super::tests::{decision, key_v4, metadata};
use super::*;
use crate::tcp_flags::{TCP_ACK, TCP_RST};
use crate::test_zone_ids::*;

const SEC: u64 = 1_000_000_000;
/// An id minted by ANOTHER worker (the installer, worker 3): high bits unlike this table's.
const INSTALLER_ID: u64 = 0x0003_0000_0000_0042;
/// This table is worker 2 on node 0, so its own ids carry `2 << 48`.
const THIS_WORKER: u32 = 2;

fn replica_table() -> SessionTable {
    let mut table = SessionTable::new();
    table.set_session_id_namespace(0, THIS_WORKER);
    table
}

/// Install a forward/reverse replica pair the way a replica worker's import does.
fn install_replica_pair(
    table: &mut SessionTable,
    origin: SessionOrigin,
    forward_id: u64,
    now: u64,
) -> (SessionKey, SessionKey) {
    let forward = key_v4();
    let reverse = reverse_session_key(&forward, decision().nat);
    assert!(
        table.upsert_synced_with_origin(
            SessionInstall {
                key: forward.clone(),
                decision: decision(),
                metadata: metadata(),
                origin,
                now_ns: now,
                protocol: PROTO_TCP,
                tcp_flags: TCP_ACK,
                session_id: forward_id,
                tcp_close_class: 0,
            },
            false,
        ),
        "FIXTURE: the forward replica must install"
    );
    let mut reverse_metadata = metadata();
    reverse_metadata.is_reverse = true;
    reverse_metadata.ingress_zone = TEST_WAN_ZONE_ID;
    reverse_metadata.egress_zone = TEST_LAN_ZONE_ID;
    assert!(
        table.upsert_synced_with_origin(
            SessionInstall {
                key: reverse.clone(),
                decision: decision(),
                metadata: reverse_metadata,
                origin,
                now_ns: now,
                protocol: PROTO_TCP,
                tcp_flags: TCP_ACK,
                session_id: 0,
                tcp_close_class: 0,
            },
            false,
        ),
        "FIXTURE: the reverse replica must install"
    );
    let _ = table.drain_deltas(64);
    (forward, reverse)
}

/// Deliver a server-side RST on the reverse half; return (class on the replica's
/// forward entry, every Update delta as (class, session_id)).
fn server_rst(table: &mut SessionTable, forward: &SessionKey, reverse: &SessionKey, now: u64) -> (u8, Vec<(u8, u64)>) {
    assert!(
        table.lookup(reverse, now, TCP_RST | TCP_ACK).is_some(),
        "FIXTURE: the server RST must match the reverse replica"
    );
    let updates = table
        .drain_deltas(64)
        .into_iter()
        .filter(|d| d.kind == SessionDeltaKind::Update)
        .map(|d| {
            assert_eq!(&d.key, forward, "an Update must name the forward key");
            (d.tcp_close_class, d.session_id)
        })
        .collect();
    (table.close_class_wire_for(forward), updates)
}

#[test]
fn a_close_seen_only_by_a_local_replica_is_announced_with_the_installer_id_9582() {
    let mut table = replica_table();
    let (forward, reverse) = install_replica_pair(&mut table, SessionOrigin::WorkerLocalImport, INSTALLER_ID, SEC);
    assert_eq!(
        table.session_id_for(&forward),
        INSTALLER_ID,
        "FIXTURE: the replica must carry the installer's id"
    );
    let (class, updates) = server_rst(&mut table, &forward, &reverse, SEC + 1_000);
    assert_eq!(
        class, 3,
        "FIXTURE: the replica's own table must record RST; otherwise this cell measures the \
         close tracking, not the announcement"
    );
    assert_eq!(
        updates,
        vec![(3, INSTALLER_ID)],
        "#9582: a server RST seen only by a replica of a LOCAL session must be announced once, \
         as class 3 carrying the installer's id"
    );
}

/// CONTROL: a replica of a PEER import must stay silent, or this node echoes the
/// owner's state back at it.
#[test]
fn a_peer_import_replica_still_announces_nothing_9582() {
    let mut table = replica_table();
    let (forward, reverse) = install_replica_pair(&mut table, SessionOrigin::SyncImport, INSTALLER_ID, SEC);
    let (class, updates) = server_rst(&mut table, &forward, &reverse, SEC + 1_000);
    assert_eq!(class, 3, "FIXTURE: the peer-import replica must record RST too");
    assert!(
        updates.is_empty(),
        "#9582: a replica of a PEER import must never announce, got {updates:?}"
    );
}

/// GUARD: a replica whose id was minted by THIS worker (its publish carried no id)
/// must stay silent.
///
/// Announcing would hand the #9412 sender memo a foreign id for the tuple. The memo
/// then drops the installer's record, and the next sweep row, which carries the
/// installer's id, resends class 0 and undoes the close on the peer.
#[test]
fn a_replica_holding_a_locally_minted_id_stays_silent_9582() {
    let mut table = replica_table();
    let (forward, reverse) = install_replica_pair(&mut table, SessionOrigin::WorkerLocalImport, 0, SEC);
    let minted = table.session_id_for(&forward);
    assert!(
        minted != 0 && minted >> 48 == u64::from(THIS_WORKER),
        "FIXTURE: an import with no carried id must mint in this worker's namespace, got {minted:#x}"
    );
    let (class, updates) = server_rst(&mut table, &forward, &reverse, SEC + 1_000);
    assert_eq!(class, 3, "FIXTURE: the replica's own table must record RST");
    assert!(
        updates.is_empty(),
        "#9582: a replica holding a LOCALLY MINTED id must not announce (it would flip the \
         #9412 memo off the installer's id), got {updates:?}"
    );
}

/// The guard's three branches, driven directly so each is exercisable. Id 0 cannot
/// reach it through an install, because `alloc_session_id` never returns 0.
#[test]
fn only_a_non_zero_id_from_another_namespace_counts_as_carried_9582() {
    let table = replica_table();
    assert!(
        table.session_id_carried_from_another_worker(INSTALLER_ID),
        "an id minted by worker 3 is carried to worker {THIS_WORKER}"
    );
    assert!(
        !table.session_id_carried_from_another_worker((u64::from(THIS_WORKER) << 48) | 7),
        "an id minted by this worker is not carried"
    );
    assert!(
        !table.session_id_carried_from_another_worker(0),
        "0 is never a carried id, although its high bits differ from this worker's namespace"
    );
}
