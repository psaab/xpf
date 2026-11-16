//! #19147: every removal of a shared session entry releases the coordinator's
//! steering claim on its rows.
//!
//! #9560 round 3 made coordinator writes (HA import, bringup replay, RG
//! activation) claim their rows with the coordinator bit, with the contract
//! "every authoritative removal of the shared entry releases that claim".
//! Six removal sites kept it by hand, and eight did not (#19147's census):
//! - the promote purge;
//! - the SYN-time TCP-pair retire;
//! - the WireGuard tun-origin idle sweep;
//! - the coordinator's stale-replay purge;
//! - the worker loop's stale-replay eviction;
//! - the LocalDelivery replacement on a miss;
//! - the missing-neighbor seed retire;
//! - the wholesale clear of the shared store.
//!
//! The claim then outlived the session, and no worker teardown could delete
//! the row (the #9560 leak class).
//!
//! The release now lives in the removal primitive (`remove_shared_session_if`)
//! and in the wholesale clear (`SharedSessionOwnerRgIndexes::clear`), reached
//! through the coordinator steering handle the index set carries
//! (`attach_coordinator_steering`, from `Coordinator::new`). The cells pin:
//! - the primitive's contract;
//! - that a CLONE of the index set (what every worker and tunnel thread gets)
//!   releases too;
//! - the wholesale clear and the coordinator stop;
//! - the coordinator-side paths, driven end to end.
//!
//! The worker packet-path removals reach the primitive with the worker's clone
//! (`worker/launch.rs`); the clone cell covers them, and the missing-neighbor
//! seed retire has its own path cell in `expiry_shared_retire_10419_tests.rs`.

use super::*;
use crate::afxdp::bpf_map::{
    RECORDER_ONLY_MAP_FD, SteeringHolder, clear_session_map_writes, session_map_writes,
};

/// A coordinator whose BPF maps carry the recorder-only steering map, so the
/// shared store's coordinator release writes into the recorder.
fn recorded_coordinator() -> Coordinator {
    let coordinator = Coordinator::new();
    coordinator
        .bpf_maps
        .store(Arc::new(crate::afxdp::coordinator::BpfMaps {
            session_map_fd: Some(crate::afxdp::bpf_map::OwnedFd {
                fd: RECORDER_ONLY_MAP_FD,
            }),
            ..Default::default()
        }));
    coordinator
}

fn holder_map(
    coordinator: &Coordinator,
    holder: SteeringHolder,
) -> crate::afxdp::bpf_map::SteeringMap<'_> {
    crate::afxdp::bpf_map::SteeringMap {
        fd: RECORDER_ONLY_MAP_FD,
        owners: &coordinator.steering_owners,
        holder,
    }
}

/// Publish `entry` into the coordinator's shared store and claim its rows as
/// `holder`, as an HA import (coordinator) or a worker install (worker) does.
fn publish_and_claim(
    coordinator: &Coordinator,
    entry: &SyncedSessionEntry,
    holder: SteeringHolder,
) {
    publish_shared_session(
        &coordinator.sessions.synced,
        &coordinator.sessions.nat,
        &coordinator.sessions.forward_wire,
        &coordinator.sessions.owner_rg_indexes,
        entry,
    );
    crate::afxdp::bpf_map::publish_session_map_entry_for_session(
        holder_map(coordinator, holder),
        &entry.key,
        entry.decision,
        &entry.metadata,
        false,
        false,
    )
    .expect("FIXTURE: the claiming publish must succeed");
    assert!(
        coordinator
            .steering_owners
            .held_row_count_for(&entry.key, holder)
            > 0,
        "FIXTURE: {holder:?} must hold rows for the entry after its publish"
    );
}

fn coordinator_held(coordinator: &Coordinator, key: &SessionKey) -> usize {
    coordinator
        .steering_owners
        .held_row_count_for(key, SteeringHolder::Coordinator)
}

fn shared_has(coordinator: &Coordinator, key: &SessionKey) -> bool {
    coordinator
        .sessions
        .synced
        .lock()
        .expect("shared")
        .contains_key(key)
}

fn deleted(key: &SessionKey) -> bool {
    session_map_writes()
        .iter()
        .any(|record| &record.key == key && record.value.is_none())
}

/// The primitive: removing a coordinator-claimed entry releases the claim,
/// and the row goes from the BPF map because the coordinator was its last
/// owner.
#[test]
fn removing_a_shared_entry_releases_the_coordinator_claim_19147() {
    let coordinator = recorded_coordinator();
    let entry = synced_entry_port(31_901, 0);
    publish_and_claim(&coordinator, &entry, SteeringHolder::Coordinator);
    clear_session_map_writes();

    crate::afxdp::shared_ops::remove_shared_session(
        &coordinator.sessions.synced,
        &coordinator.sessions.nat,
        &coordinator.sessions.forward_wire,
        &coordinator.sessions.owner_rg_indexes,
        &entry.key,
    );

    assert!(
        !shared_has(&coordinator, &entry.key),
        "FIXTURE: the entry must be removed"
    );
    assert_eq!(
        coordinator_held(&coordinator, &entry.key),
        0,
        "the removal of the shared entry must release the coordinator's claim (#9560 round 3)"
    );
    assert!(
        deleted(&entry.key),
        "the coordinator was the row's last owner, so its release must delete the row: {:?}",
        session_map_writes()
    );
}

/// A worker that still holds the row keeps it: the release gives up only the
/// coordinator's claim.
#[test]
fn a_worker_claim_survives_the_coordinator_release_19147() {
    let coordinator = recorded_coordinator();
    let entry = synced_entry_port(31_902, 0);
    publish_and_claim(&coordinator, &entry, SteeringHolder::Coordinator);
    publish_and_claim(&coordinator, &entry, SteeringHolder::Worker(3));
    clear_session_map_writes();

    crate::afxdp::shared_ops::remove_shared_session(
        &coordinator.sessions.synced,
        &coordinator.sessions.nat,
        &coordinator.sessions.forward_wire,
        &coordinator.sessions.owner_rg_indexes,
        &entry.key,
    );

    assert_eq!(
        coordinator_held(&coordinator, &entry.key),
        0,
        "the coordinator claim must go"
    );
    assert!(
        coordinator
            .steering_owners
            .held_row_count_for(&entry.key, SteeringHolder::Worker(3))
            > 0,
        "the worker's claim must survive"
    );
    assert!(
        !deleted(&entry.key),
        "a row a worker still holds must not be deleted: {:?}",
        session_map_writes()
    );
}

/// A DECLINED removal mutates nothing, the claim included.
#[test]
fn a_declined_removal_keeps_the_coordinator_claim_19147() {
    let coordinator = recorded_coordinator();
    let entry = synced_entry_port(31_903, 0);
    publish_and_claim(&coordinator, &entry, SteeringHolder::Coordinator);
    let before = coordinator_held(&coordinator, &entry.key);

    let outcome = crate::afxdp::shared_ops::remove_shared_session_if(
        &coordinator.sessions.synced,
        &coordinator.sessions.nat,
        &coordinator.sessions.forward_wire,
        &coordinator.sessions.owner_rg_indexes,
        &entry.key,
        |_| false,
    );

    assert!(matches!(
        outcome,
        crate::afxdp::shared_ops::SharedRemoval::Declined
    ));
    assert_eq!(
        coordinator_held(&coordinator, &entry.key),
        before,
        "a declined removal must leave the coordinator's claim intact"
    );
}

/// Removing an entry the coordinator never claimed is a registry lookup: no
/// BPF write or delete.
#[test]
fn removing_an_unclaimed_entry_touches_no_steering_row_19147() {
    let coordinator = recorded_coordinator();
    let entry = synced_entry_port(31_904, 0);
    publish_shared_session(
        &coordinator.sessions.synced,
        &coordinator.sessions.nat,
        &coordinator.sessions.forward_wire,
        &coordinator.sessions.owner_rg_indexes,
        &entry,
    );
    clear_session_map_writes();

    crate::afxdp::shared_ops::remove_shared_session(
        &coordinator.sessions.synced,
        &coordinator.sessions.nat,
        &coordinator.sessions.forward_wire,
        &coordinator.sessions.owner_rg_indexes,
        &entry.key,
    );

    assert!(
        !shared_has(&coordinator, &entry.key),
        "FIXTURE: the entry must be removed"
    );
    assert!(
        session_map_writes().is_empty(),
        "an unclaimed removal must issue no steering syscall: {:?}",
        session_map_writes()
    );
}

/// Workers and tunnel threads remove through a CLONE of the coordinator's
/// index set (`worker/launch.rs`, `tunnel_supervision.rs`). The clone must
/// carry the steering handle, or every worker-side removal path (the promote
/// purge, the SYN-time pair retire, the stale-replay eviction, the
/// LocalDelivery replacement, the seed retire) would release nothing.
#[test]
fn a_cloned_index_set_releases_the_coordinator_claim_too_19147() {
    let coordinator = recorded_coordinator();
    let entry = synced_entry_port(31_905, 0);
    publish_and_claim(&coordinator, &entry, SteeringHolder::Coordinator);
    let worker_copy = coordinator.sessions.owner_rg_indexes.clone();

    crate::afxdp::shared_ops::remove_shared_session(
        &coordinator.sessions.synced,
        &coordinator.sessions.nat,
        &coordinator.sessions.forward_wire,
        &worker_copy,
        &entry.key,
    );

    assert_eq!(
        coordinator_held(&coordinator, &entry.key),
        0,
        "a removal through the worker's clone of the index set must release the coordinator claim"
    );
}

/// The wholesale clear (`SharedSessionOwnerRgIndexes::clear`, the end of the
/// paged clear verb and the coordinator stop with `clear_synced_state`)
/// retires every coordinator claim, without BPF deletes.
#[test]
fn the_wholesale_clear_retires_every_coordinator_claim_19147() {
    let coordinator = recorded_coordinator();
    let first = synced_entry_port(31_906, 0);
    let second = synced_entry_port(31_907, 0);
    publish_and_claim(&coordinator, &first, SteeringHolder::Coordinator);
    publish_and_claim(&coordinator, &second, SteeringHolder::Coordinator);
    publish_and_claim(&coordinator, &second, SteeringHolder::Worker(1));
    clear_session_map_writes();

    coordinator.sessions.owner_rg_indexes.clear(
        &coordinator.sessions.synced,
        &coordinator.sessions.forward_wire,
    );

    for key in [&first.key, &second.key] {
        assert_eq!(
            coordinator_held(&coordinator, key),
            0,
            "the clear must retire the coordinator claim on {key:?}"
        );
    }
    assert!(
        coordinator
            .steering_owners
            .held_row_count_for(&second.key, SteeringHolder::Worker(1))
            > 0,
        "the clear must leave worker claims alone"
    );
    // The ROW side of the registry too (the holdings above are the other
    // half): the worker-held row keeps exactly its worker owner, and the
    // coordinator-only row has none.
    let row_owners = |key: &SessionKey| {
        coordinator
            .steering_owners
            .owner_count(&crate::afxdp::bpf_map::session_map_row(key))
    };
    assert_eq!(
        row_owners(&second.key),
        1,
        "after the clear, the worker-held row must keep exactly its worker owner"
    );
    assert_eq!(
        row_owners(&first.key),
        0,
        "after the clear, the coordinator-only row must have no owner"
    );
    assert!(
        session_map_writes().is_empty(),
        "the retire deletes no BPF row (rows linger unowned, as retire_workers leaves them): {:?}",
        session_map_writes()
    );
}

/// The coordinator stop that clears synced state (`stop()`, the disarm and
/// shutdown teardown) retires the coordinator claims with the shared store.
#[test]
fn the_coordinator_stop_retires_coordinator_claims_with_the_shared_store_19147() {
    let mut coordinator = recorded_coordinator();
    let entry = synced_entry_port(31_908, 0);
    publish_and_claim(&coordinator, &entry, SteeringHolder::Coordinator);

    coordinator.stop();

    assert!(
        !shared_has(&coordinator, &entry.key),
        "FIXTURE: the stop must clear the shared store"
    );
    assert_eq!(
        coordinator_held(&coordinator, &entry.key),
        0,
        "a stop that clears the shared store must retire the coordinator claim"
    );
}

/// The WireGuard tun-origin idle sweep (`coordinator/wg_control/tun_origin.rs`)
/// removes an idle pair from the shared store, and releases its claim.
#[test]
fn the_wg_tun_origin_sweep_releases_the_coordinator_claim_19147() {
    let coordinator = recorded_coordinator();
    let entry = synced_entry_port(31_909, 0);
    publish_and_claim(&coordinator, &entry, SteeringHolder::Coordinator);
    let mut tombstones: FastMap<SessionKey, u64> = FastMap::default();
    tombstones.insert(entry.key.clone(), 0);
    let mut last_sweep = 0u64;

    crate::afxdp::coordinator::sweep_wg_tun_origin_idle(
        &coordinator.sessions.synced,
        &coordinator.sessions.nat,
        &coordinator.sessions.forward_wire,
        &coordinator.sessions.owner_rg_indexes,
        &mut tombstones,
        &mut last_sweep,
        60_000_000_000,
    );

    assert!(
        !shared_has(&coordinator, &entry.key),
        "FIXTURE: the sweep must remove the idle entry"
    );
    assert_eq!(
        coordinator_held(&coordinator, &entry.key),
        0,
        "the tun-origin sweep's removal must release the coordinator claim"
    );
}

/// The coordinator's stale-replay purge (`purge_stale_replayed_synced_sessions`)
/// removes an entry whose zones are gone, and releases its claim.
#[test]
fn the_stale_replay_purge_releases_the_coordinator_claim_19147() {
    let mut coordinator = recorded_coordinator();
    let mut forwarding = test_forwarding_state_with_fabric();
    forwarding
        .zone_id_to_name
        .insert(TEST_LAN_ZONE_ID, "lan".to_string());
    forwarding
        .zone_id_to_name
        .insert(TEST_WAN_ZONE_ID, "wan".to_string());
    forwarding.zone_set_validated = true;
    coordinator.set_forwarding_for_test(forwarding);
    let mut stale = synced_entry_port(31_910, 0);
    stale.metadata.ingress_zone = 9;
    stale.metadata.egress_zone = 10;
    publish_and_claim(&coordinator, &stale, SteeringHolder::Coordinator);

    crate::afxdp::coordinator::purge_stale_replayed_synced_sessions(
        &coordinator,
        std::slice::from_ref(&stale),
    );

    assert!(
        !shared_has(&coordinator, &stale.key),
        "FIXTURE: the purge must remove the stale entry"
    );
    assert_eq!(
        coordinator_held(&coordinator, &stale.key),
        0,
        "the stale-replay purge's removal must release the coordinator claim"
    );
}
