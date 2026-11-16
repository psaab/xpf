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

/// #19147 (review, Codex re-check P3): a deterministic handshake with a
/// racing thread, replacing a wait-and-hope timeout. The racer reports either
/// that it is about to BLOCK on the fence under test (a would-block probe) or
/// that it FINISHED (it was never fenced). The waiter needs one of the two;
/// neither within the safety bound fails the cell, it never passes it.
#[derive(Default)]
struct Handshake19147 {
    state: Mutex<(bool, bool)>,
    changed: std::sync::Condvar,
}

impl Handshake19147 {
    fn blocked(&self) {
        self.state.lock().expect("handshake").0 = true;
        self.changed.notify_all();
    }

    fn finished(&self) {
        self.state.lock().expect("handshake").1 = true;
        self.changed.notify_all();
    }

    /// Wait until the racer blocked on the fence or finished; returns
    /// `finished`.
    fn wait_blocked_or_finished(&self) -> bool {
        let state = self.state.lock().expect("handshake");
        let (state, timeout) = self
            .changed
            .wait_timeout_while(
                state,
                std::time::Duration::from_secs(60),
                |(blocked, finished)| !*blocked && !*finished,
            )
            .expect("handshake");
        assert!(
            !timeout.timed_out(),
            "FIXTURE: the racing thread neither reached the fence nor finished in 60 s"
        );
        state.1
    }

    fn was_blocked(&self) -> bool {
        self.state.lock().expect("handshake").0
    }
}

/// #19147 (review, Codex P2): a coordinator claim racing the wholesale retire
/// must land WHOLE, before or after it, never split between its two sweeps.
///
/// The seam runs between the retire's row sweep and its holdings sweep. In it,
/// another thread publishes a coordinator claim for K (an HA import that
/// published its shared entry before the clear and claims after). Before the
/// fix the claim landed in that window: its row half survived the
/// already-finished row sweep, and the holdings sweep then erased its holdings
/// half. That left a ghost row owner no held-only release can find. With the
/// fix the claim blocks on the publication lock until the retire completes.
///
/// The seam does not sleep and hope: it waits until the claimer either
/// reports that it is about to block on the publication lock (the fence held)
/// or has finished its claim inside the window (no fence).
///
/// The cell checks BOTH registry halves, then that a subsequent held-only
/// release (what the removal primitive runs) finds the claim and leaves the
/// row ownerless.
#[test]
fn a_coordinator_claim_racing_the_wholesale_retire_lands_whole_19147() {
    let coordinator = recorded_coordinator();
    let entry = synced_entry_port(31_911, 0);
    let owners = Arc::clone(&coordinator.steering_owners);
    let handshake = Arc::new(Handshake19147::default());
    let claimer: Arc<Mutex<Option<std::thread::JoinHandle<()>>>> = Arc::new(Mutex::new(None));
    let landed_in_window = Arc::new(std::sync::atomic::AtomicBool::new(false));
    {
        let (owners, handshake, claimer, landed_in_window) = (
            Arc::clone(&owners),
            Arc::clone(&handshake),
            Arc::clone(&claimer),
            Arc::clone(&landed_in_window),
        );
        let entry = entry.clone();
        crate::afxdp::bpf_map::RETIRE_COORDINATOR_BETWEEN_SWEEPS_19147.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                let racer = Arc::clone(&handshake);
                let handle = std::thread::spawn(move || {
                    let probe = Arc::clone(&racer);
                    crate::afxdp::bpf_map::COORDINATOR_PUBLICATION_WOULD_BLOCK_19147
                        .with(|hook| *hook.borrow_mut() = Some(Box::new(move || probe.blocked())));
                    crate::afxdp::bpf_map::publish_session_map_entry_for_session(
                        crate::afxdp::bpf_map::SteeringMap {
                            fd: RECORDER_ONLY_MAP_FD,
                            owners: &owners,
                            holder: SteeringHolder::Coordinator,
                        },
                        &entry.key,
                        entry.decision,
                        &entry.metadata,
                        false,
                        false,
                    )
                    .expect("the racing coordinator claim must publish");
                    racer.finished();
                });
                if handshake.wait_blocked_or_finished() {
                    landed_in_window.store(true, std::sync::atomic::Ordering::Release);
                }
                *claimer.lock().expect("claimer") = Some(handle);
            }));
        });
    }

    coordinator.steering_owners.retire_coordinator();
    let handle = claimer
        .lock()
        .expect("claimer")
        .take()
        .expect("FIXTURE: the seam must have run");
    handle.join().expect("the racing claim thread");

    assert!(
        !landed_in_window.load(std::sync::atomic::Ordering::Acquire),
        "a coordinator claim landed BETWEEN the retire's two sweeps; it must wait for the whole retire"
    );
    assert!(
        handshake.was_blocked(),
        "the racing claim never BLOCKED on the publication lock the retire held, so the contested \
         ordering was not exercised: this cell must fail, never pass, without it"
    );
    let row = crate::afxdp::bpf_map::session_map_row(&entry.key);
    let held = coordinator_held(&coordinator, &entry.key);
    let row_owners = coordinator.steering_owners.owner_count(&row);
    assert!(
        held > 0 && row_owners == 1,
        "the racing claim must be WHOLE: holdings {held}, row owners {row_owners} (a row owner with no \
         holdings is a ghost no held-only release can find)"
    );
    // The removal primitive's release sequence (`remove_shared_session_if`):
    // the bookkeeping under the shared-session lock, then the deferred BPF ops
    // after it.
    let indexes = &coordinator.sessions.owner_rg_indexes;
    let deferred = {
        let _shared = crate::afxdp::shared_ops::lock_shared_recover(&coordinator.sessions.synced);
        indexes
            .release_coordinator_claims_deferred(&entry.key)
            .expect("FIXTURE: the index set must carry the coordinator's steering registry")
    };
    indexes.commit_coordinator_release(deferred);
    assert_eq!(
        coordinator.steering_owners.owner_count(&row),
        0,
        "a subsequent held-only release must find the claim and leave the row ownerless (no ghost owner)"
    );
}

/// #19147 (review, seat r23 P3-3): the release runs UNDER the shared-session
/// lock, so a replacement that publishes the same key under that lock and
/// claims after it cannot lose its claim to the release.
///
/// In the seam just before the release, another thread publishes a
/// replacement K' of the removed key K into the shared store and claims its
/// rows as the coordinator, the HA import's order. With the release under the
/// lock, the replacement's publish waits until the removal (release included)
/// has finished, and its claim survives. A release moved after the lock drops
/// lets the replacement publish and claim first; the identity-blind release
/// of key K then drops K''s claim.
///
/// The seam does not sleep and hope: it waits until the publisher either
/// reports that it is about to block on the shared-session lock (the removal
/// holds it) or has finished publishing and claiming (it does not).
#[test]
fn a_replacement_claimed_during_the_removal_keeps_its_claim_19147() {
    let coordinator = recorded_coordinator();
    let entry = synced_entry_port(31_912, 0);
    publish_and_claim(&coordinator, &entry, SteeringHolder::Coordinator);
    let mut replacement = entry.clone();
    replacement.session_id = 0x19147;
    let sessions = Arc::clone(&coordinator.sessions);
    let owners = Arc::clone(&coordinator.steering_owners);
    let handshake = Arc::new(Handshake19147::default());
    let publisher: Arc<Mutex<Option<std::thread::JoinHandle<()>>>> = Arc::new(Mutex::new(None));
    {
        let (handshake, publisher) = (Arc::clone(&handshake), Arc::clone(&publisher));
        crate::afxdp::shared_ops::BEFORE_COORDINATOR_RELEASE_19147.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                let racer = Arc::clone(&handshake);
                let handle = std::thread::spawn(move || {
                    let probe = Arc::clone(&racer);
                    crate::afxdp::shared_ops::SHARED_PUBLISH_WOULD_BLOCK_19147
                        .with(|hook| *hook.borrow_mut() = Some(Box::new(move || probe.blocked())));
                    publish_shared_session(
                        &sessions.synced,
                        &sessions.nat,
                        &sessions.forward_wire,
                        &sessions.owner_rg_indexes,
                        &replacement,
                    );
                    crate::afxdp::bpf_map::publish_session_map_entry_for_session(
                        crate::afxdp::bpf_map::SteeringMap {
                            fd: RECORDER_ONLY_MAP_FD,
                            owners: &owners,
                            holder: SteeringHolder::Coordinator,
                        },
                        &replacement.key,
                        replacement.decision,
                        &replacement.metadata,
                        false,
                        false,
                    )
                    .expect("the replacement's claim must publish");
                    racer.finished();
                });
                handshake.wait_blocked_or_finished();
                *publisher.lock().expect("publisher") = Some(handle);
            }));
        });
    }

    crate::afxdp::shared_ops::remove_shared_session(
        &coordinator.sessions.synced,
        &coordinator.sessions.nat,
        &coordinator.sessions.forward_wire,
        &coordinator.sessions.owner_rg_indexes,
        &entry.key,
    );
    publisher
        .lock()
        .expect("publisher")
        .take()
        .expect("FIXTURE: the seam must have run")
        .join()
        .expect("the replacement publisher");

    assert!(
        coordinator
            .sessions
            .synced
            .lock()
            .expect("shared")
            .get(&entry.key)
            .is_some_and(|live| live.session_id == 0x19147),
        "FIXTURE: the replacement must be the live shared entry"
    );
    assert!(
        handshake.was_blocked(),
        "the replacement's publish never BLOCKED on the shared-session lock the removal held, so the \
         contested ordering was not exercised: this cell must fail, never pass, without it"
    );
    assert!(
        coordinator_held(&coordinator, &entry.key) > 0,
        "the replacement's coordinator claim must survive the removal of the entry it replaced; a \
         release outside the shared lock drops it"
    );
    assert_eq!(
        coordinator
            .steering_owners
            .owner_count(&crate::afxdp::bpf_map::session_map_row(&entry.key)),
        1,
        "the replacement's row must keep its coordinator owner"
    );
}

fn pct_19147(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    sorted[((sorted.len() as f64 - 1.0) * p).round() as usize]
}

/// #19147 (review, seat r23 P3-2): what the in-lock release costs, against a
/// REAL BPF hash map (it needs CAP_BPF; without it, it prints SKIP).
/// Ignored; run it as root in release:
/// `cargo test --release --bins coordinator_release_lock_hold_bench -- --ignored --nocapture`.
///
/// Each arm seeds N shared entries, then removes them one by one, timing each
/// `remove_shared_session` call (the removal holds the shared-session lock for
/// almost its whole body, so this is about its hold time). Meanwhile WORKERS
/// threads time their own shared-lock acquisitions, standing in for the new-flow
/// publishes that contend on that lock.
/// - **CLAIMED:** every entry carries a coordinator claim (the standby's HA
///   import, or the new primary's activation). The release does its
///   bookkeeping inside the lock and BPF-deletes its rows after it (fold 2).
/// - **UNCLAIMED:** no claim, so the release is a holdings lookup.
#[test]
#[ignore = "#19147 P3-2 bench (root, real BPF map): cargo test --release --bins coordinator_release_lock_hold_bench -- --ignored --nocapture"]
fn coordinator_release_lock_hold_bench_19147() {
    use std::sync::atomic::{AtomicBool, Ordering as AtOrd};
    const N: u16 = 4_000;
    const WORKERS: usize = 4;
    let name = c"x19147bench";
    // SAFETY: a plain map create with a NUL-terminated name and no opts.
    let fd = unsafe {
        libbpf_sys::bpf_map_create(
            libbpf_sys::BPF_MAP_TYPE_HASH,
            name.as_ptr(),
            40,
            1,
            131_072,
            std::ptr::null(),
        )
    };
    if fd < 0 {
        eprintln!(
            "BENCH19147 SKIP: bpf_map_create: {} (needs CAP_BPF)",
            std::io::Error::last_os_error()
        );
        return;
    }
    let coordinator = Coordinator::new();
    coordinator
        .bpf_maps
        .store(Arc::new(crate::afxdp::coordinator::BpfMaps {
            session_map_fd: Some(crate::afxdp::bpf_map::OwnedFd { fd }),
            ..Default::default()
        }));
    let mut base: u16 = 10_000;
    for (round, (arm, claim)) in [
        ("UNCLAIMED", false),
        ("CLAIMED", true),
        ("UNCLAIMED", false),
        ("CLAIMED", true),
    ]
    .into_iter()
    .enumerate()
    {
        let entries: Vec<SyncedSessionEntry> =
            (0..N).map(|i| synced_entry_port(base + i, 0)).collect();
        base += N;
        for entry in &entries {
            publish_shared_session(
                &coordinator.sessions.synced,
                &coordinator.sessions.nat,
                &coordinator.sessions.forward_wire,
                &coordinator.sessions.owner_rg_indexes,
                entry,
            );
            if claim {
                crate::afxdp::bpf_map::publish_session_map_entry_for_session(
                    crate::afxdp::bpf_map::SteeringMap {
                        fd,
                        owners: &coordinator.steering_owners,
                        holder: SteeringHolder::Coordinator,
                    },
                    &entry.key,
                    entry.decision,
                    &entry.metadata,
                    false,
                    false,
                )
                .expect("BENCH: the coordinator claim must write the real map");
            }
        }
        let stop = Arc::new(AtomicBool::new(false));
        let workers: Vec<_> = (0..WORKERS)
            .map(|_| {
                let (shared, stop) = (Arc::clone(&coordinator.sessions.synced), Arc::clone(&stop));
                std::thread::spawn(move || {
                    let mut waits = Vec::with_capacity(1 << 18);
                    while !stop.load(AtOrd::Relaxed) {
                        let started = std::time::Instant::now();
                        let guard = crate::afxdp::shared_ops::lock_shared_recover(&shared);
                        waits.push(started.elapsed().as_nanos() as u64);
                        drop(guard);
                        std::hint::spin_loop();
                    }
                    waits
                })
            })
            .collect();
        let mut holds = Vec::with_capacity(entries.len());
        let burst = std::time::Instant::now();
        for entry in &entries {
            let started = std::time::Instant::now();
            crate::afxdp::shared_ops::remove_shared_session(
                &coordinator.sessions.synced,
                &coordinator.sessions.nat,
                &coordinator.sessions.forward_wire,
                &coordinator.sessions.owner_rg_indexes,
                &entry.key,
            );
            holds.push(started.elapsed().as_nanos() as u64);
        }
        let burst_us = burst.elapsed().as_micros();
        stop.store(true, AtOrd::Relaxed);
        let mut waits: Vec<u64> = workers
            .into_iter()
            .flat_map(|w| w.join().expect("worker"))
            .collect();
        holds.sort_unstable();
        waits.sort_unstable();
        eprintln!(
            "BENCH19147 round={round} arm={arm} n={} burst_us={burst_us} removal_ns p50={} p99={} max={} | worker_lock_wait_ns n={} p50={} p99={} p999={} max={}",
            holds.len(),
            pct_19147(&holds, 0.5),
            pct_19147(&holds, 0.99),
            holds.last().copied().unwrap_or(0),
            waits.len(),
            pct_19147(&waits, 0.5),
            pct_19147(&waits, 0.99),
            pct_19147(&waits, 0.999),
            waits.last().copied().unwrap_or(0),
        );
    }
}

/// #19147 (review, seat r23 P3-2): the release's BPF delete is DEFERRED past
/// the shared-session lock, so it must re-check the row under its shard lock.
///
/// The removed entry's coordinator claim was its row's only owner, so phase 1
/// decides on a delete. In the seam between the unlock and that deferred
/// delete, a replacement publishes the same key and claims it as the
/// coordinator, which writes the row. The deferred delete must see the new
/// owner and skip: the replacement keeps its claim AND its BPF row (its write
/// is the row's last record).
#[test]
fn a_replacement_written_before_the_deferred_delete_keeps_its_row_19147() {
    let coordinator = recorded_coordinator();
    let entry = synced_entry_port(31_913, 0);
    publish_and_claim(&coordinator, &entry, SteeringHolder::Coordinator);
    let mut replacement = entry.clone();
    replacement.session_id = 0x19148;
    clear_session_map_writes();
    {
        let sessions = Arc::clone(&coordinator.sessions);
        let owners = Arc::clone(&coordinator.steering_owners);
        crate::afxdp::shared_ops::BETWEEN_UNLOCK_AND_COMMIT_19147.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                publish_shared_session(
                    &sessions.synced,
                    &sessions.nat,
                    &sessions.forward_wire,
                    &sessions.owner_rg_indexes,
                    &replacement,
                );
                crate::afxdp::bpf_map::publish_session_map_entry_for_session(
                    crate::afxdp::bpf_map::SteeringMap {
                        fd: RECORDER_ONLY_MAP_FD,
                        owners: &owners,
                        holder: SteeringHolder::Coordinator,
                    },
                    &replacement.key,
                    replacement.decision,
                    &replacement.metadata,
                    false,
                    false,
                )
                .expect("the replacement's claim must publish");
            }));
        });
    }

    crate::afxdp::shared_ops::remove_shared_session(
        &coordinator.sessions.synced,
        &coordinator.sessions.nat,
        &coordinator.sessions.forward_wire,
        &coordinator.sessions.owner_rg_indexes,
        &entry.key,
    );

    assert!(
        crate::afxdp::shared_ops::BETWEEN_UNLOCK_AND_COMMIT_19147
            .with(|hook| hook.borrow().is_none()),
        "FIXTURE: the seam between the unlock and the deferred commit must have run"
    );
    assert!(
        coordinator_held(&coordinator, &entry.key) > 0,
        "the replacement's coordinator claim must survive"
    );
    let last = session_map_writes()
        .iter()
        .rev()
        .find(|record| record.key == entry.key)
        .map(|record| record.value);
    assert!(
        matches!(last, Some(Some(_))),
        "the replacement's BPF row must survive: the deferred delete must re-check the row's owners \
         and skip it ({:?})",
        session_map_writes()
    );
}
