// #18562: the node-wide punt-seed directory is a SNAPSHOT of live worker-local
// #7770 seeds, so its whole contract is lifecycle: a row exists only while the
// table that minted it still holds that seed incarnation, unmodified. Each
// cell drives the table's real install / removal paths — the directory is
// never written directly except by the cap cell, which pins the directory's own
// bound.

use super::tests::{decision, key_v4, metadata};
use super::*;
use std::sync::Arc;

const T0: u64 = 5_000_000_000;

fn udp_key() -> SessionKey {
    SessionKey {
        protocol: PROTO_UDP,
        ..key_v4()
    }
}

fn table_on(dir: &Arc<PuntSeedDirectory>) -> SessionTable {
    let mut table = SessionTable::new();
    table.set_punt_seed_directory(Arc::clone(dir));
    table
}

fn install(table: &mut SessionTable, key: &SessionKey, origin: SessionOrigin, now_ns: u64) {
    assert!(
        table.install_with_protocol_with_origin(
            key.clone(),
            decision(),
            metadata(),
            origin,
            now_ns,
            key.protocol,
            0,
        ),
        "premise: {origin:?} installs"
    );
}

/// Only a forward `FabricPuntSeed` is published, and the row names the seed's
/// own incarnation and adjudicated zone pair. Every other local origin —
/// including the other transient seed — publishes nothing: the directory is not
/// a second shared-session map.
#[test]
fn only_a_forward_fabric_punt_seed_is_published_18562() {
    for origin in [
        SessionOrigin::ForwardFlow,
        SessionOrigin::LocalMiss,
        SessionOrigin::MissingNeighborSeed,
        SessionOrigin::SyncImport,
    ] {
        let dir = Arc::new(PuntSeedDirectory::new());
        let mut table = table_on(&dir);
        install(&mut table, &udp_key(), origin, T0);
        assert_eq!(dir.len(), 0, "{origin:?} must not reach the punt-seed directory");
    }
    let dir = Arc::new(PuntSeedDirectory::new());
    let mut table = table_on(&dir);
    let key = udp_key();
    install(&mut table, &key, SessionOrigin::FabricPuntSeed, T0);
    let row = dir.probe(&key, T0).expect("a forward punt seed is published");
    assert_eq!(row.session_id, table.session_id_for(&key), "the row names this incarnation");
    assert_eq!(row.metadata.ingress_zone, metadata().ingress_zone);
    assert_eq!(row.metadata.egress_zone, metadata().egress_zone);
    assert!(!row.metadata.is_reverse);

    let dir = Arc::new(PuntSeedDirectory::new());
    let mut table = table_on(&dir);
    let mut reverse = metadata();
    reverse.is_reverse = true;
    assert!(table.install_with_protocol_with_origin(
        key.clone(),
        decision(),
        reverse,
        SessionOrigin::FabricPuntSeed,
        T0,
        PROTO_UDP,
        0,
    ));
    assert_eq!(dir.len(), 0, "a reverse-shaped row is never published (seeds are forward-only)");
}

/// Every way the seed can stop existing — or stop being the snapshot — retires
/// its row: explicit delete, idle expiry, replacement by another install, an
/// in-place HA refresh, the table moving to another directory, and the table
/// being dropped. A retire path missing here would leave a row that admits
/// errors for a flow this node no longer holds. One cell per path, so a
/// mutant of one retire site cannot hide behind another's earlier failure.
fn assert_removal_path_retires(name: &str, path: impl FnOnce(&mut Option<SessionTable>, &SessionKey)) {
    let dir = Arc::new(PuntSeedDirectory::new());
    let mut table = Some(table_on(&dir));
    let key = udp_key();
    install(table.as_mut().unwrap(), &key, SessionOrigin::FabricPuntSeed, T0);
    assert!(dir.probe(&key, T0).is_some(), "{name}: premise: row published");
    path(&mut table, &key);
    assert!(dir.probe(&key, T0 + 1).is_none(), "{name}: the seed's row must be retired");
    assert_eq!(dir.len(), 0, "{name}: no row left behind");
}

#[test]
fn seed_delete_retires_its_row_18562() {
    assert_removal_path_retires("delete", |t, k| t.as_mut().unwrap().delete(k));
}

#[test]
fn seed_idle_expiry_retires_its_row_18562() {
    assert_removal_path_retires("idle expiry", |t, k| {
        let expired = t.as_mut().unwrap().expire_stale_entries(T0 + 3_600_000_000_000);
        assert!(expired.iter().any(|e| e.key == *k), "premise: the seed expired");
    });
}

#[test]
fn seed_replacement_install_retires_its_row_18562() {
    assert_removal_path_retires("replacement install", |t, k| {
        install(t.as_mut().unwrap(), k, SessionOrigin::ForwardFlow, T0 + 1)
    });
}

#[test]
fn seed_in_place_ha_refresh_retires_its_row_18562() {
    assert_removal_path_retires("in-place HA refresh", |t, k| {
        assert!(t.as_mut().unwrap().refresh_for_ha_transition(k, decision(), metadata(), T0 + 1));
    });
}

#[test]
fn table_moved_to_another_directory_retires_its_rows_18562() {
    assert_removal_path_retires("moved to another directory", |t, _| {
        t.as_mut().unwrap().set_punt_seed_directory(Arc::new(PuntSeedDirectory::new()))
    });
}

#[test]
fn dropped_table_retires_its_rows_18562() {
    assert_removal_path_retires("table dropped", |t, _| drop(t.take()));
}

/// A retire removes only the incarnation it names: another worker's seed for
/// the same tuple (its own table) survives this worker's delete, and dies with
/// its own table.
#[test]
fn retire_is_fenced_by_table_and_incarnation_18562() {
    let dir = Arc::new(PuntSeedDirectory::new());
    let mut worker_a = table_on(&dir);
    let mut worker_b = table_on(&dir);
    let key = udp_key();
    install(&mut worker_a, &key, SessionOrigin::FabricPuntSeed, T0);
    install(&mut worker_b, &key, SessionOrigin::FabricPuntSeed, T0 + 1);
    let b_id = worker_b.session_id_for(&key);
    worker_a.delete(&key);
    assert_eq!(
        dir.probe(&key, T0 + 2).map(|r| r.session_id),
        Some(b_id),
        "worker A's delete must not retire worker B's row"
    );
    drop(worker_a);
    assert!(dir.probe(&key, T0 + 2).is_some(), "dropping A must not retire B's row");
    drop(worker_b);
    assert!(dir.probe(&key, T0 + 2).is_none());
}

/// The row stops matching at the seed's idle deadline AS INSTALLED; it is
/// never extended, so a seed kept alive by traffic outlives its row (fail
/// closed) rather than the reverse.
#[test]
fn row_stops_matching_at_the_install_deadline_18562() {
    let dir = Arc::new(PuntSeedDirectory::new());
    let mut table = table_on(&dir);
    let key = udp_key();
    install(&mut table, &key, SessionOrigin::FabricPuntSeed, T0);
    let deadline = dir.probe(&key, T0).expect("published").expires_at_ns;
    assert!(deadline > T0, "premise: a positive idle window");
    assert!(dir.probe(&key, deadline - 1).is_some());
    assert!(dir.probe(&key, deadline).is_none(), "the row must not outlive the installed deadline");
}

/// At the cap the directory first prunes rows past their deadline, then
/// refuses (and counts) rather than evicting a live row.
#[test]
fn full_directory_prunes_expired_rows_then_refuses_18562() {
    let dir = PuntSeedDirectory::new();
    let row = |expires_at_ns| PuntSeedRow {
        decision: decision(),
        metadata: metadata(),
        session_id: 1,
        table_token: 1,
        expires_at_ns,
    };
    let key_n = |n: usize| SessionKey {
        src_port: (n & 0xffff) as u16,
        dst_port: (n >> 16) as u16,
        ..udp_key()
    };
    for n in 0..PUNT_SEED_DIRECTORY_CAP {
        assert!(dir.publish(&key_n(n), row(T0), T0 - 1));
    }
    assert_eq!(dir.len(), PUNT_SEED_DIRECTORY_CAP);
    let extra = key_n(PUNT_SEED_DIRECTORY_CAP);
    assert!(dir.publish(&extra, row(T0 + 10), T0), "expired rows are pruned to make room");
    assert_eq!(dir.len(), 1, "every expired row was pruned");
    for n in 1..PUNT_SEED_DIRECTORY_CAP {
        assert!(dir.publish(&key_n(n), row(T0 + 10), T0));
    }
    let before = PUNT_SEED_DIRECTORY_FULL_TOTAL.load(std::sync::atomic::Ordering::Relaxed);
    assert!(!dir.publish(&key_n(0), row(T0 + 10), T0), "a full directory of live rows refuses");
    assert!(PUNT_SEED_DIRECTORY_FULL_TOTAL.load(std::sync::atomic::Ordering::Relaxed) > before);
    assert!(dir.probe(&extra, T0).is_some(), "no live row was evicted");
}
