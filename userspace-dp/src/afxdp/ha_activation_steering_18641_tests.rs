//! #18641 step 1: an RG activation publishes each forward steering row once.
//!
//! `handle_activated_rgs` runs the reverse prewarm and then
//! `republish_bpf_session_entries_for_owner_rgs`. The republish rewrites the
//! steering row of every key in the `sessions` owner-RG index (S). Before
//! step 1, the prewarm published those same forward rows first, so every
//! S-forward was written twice per activation: the same syscalls as the
//! republish, measured at ~13-18 ms per RG (#18654).
//!
//! **The cells.**
//! - **Duplicate.** An S-forward is written EXACTLY once, and the row
//!   exists afterwards. "Once" kills the duplicate; "exists" kills a skip
//!   that nothing republishes.
//! - **Split-RG.** A forward that is only in the reverse-prewarm index is
//!   still written once. Its owner RG is not the activated one, so the
//!   republish does not reach it (#287/#524). This kills a skip that
//!   over-reaches to every forward.

use super::*;
use crate::afxdp::bpf_map::{
    RECORDER_ONLY_MAP_FD, clear_session_map_writes, session_map_writes,
};

/// A coordinator on the split-RG forwarding fixture, with one worker:
/// - LAN egress on RG2, WAN on RG1;
/// - the recorder-only steering map, so every steering write is observable.
///
/// RG1 and RG2 start in the given states. The session's forward is owned by
/// RG1, and its reply leaves by the LAN, so its reverse resolves to RG2. It is
/// imported through the production verb, which files the forward in S under
/// RG1 and in the reverse-prewarm index under both RGs.
fn imported(rg1_active: bool, rg2_active: bool) -> (Coordinator, SessionKey) {
    let mut coordinator = Coordinator::new();
    coordinator.set_forwarding_for_test(test_forwarding_state_split_rgs());
    coordinator
        .bpf_maps
        .store(Arc::new(crate::afxdp::coordinator::BpfMaps {
            session_map_fd: Some(crate::afxdp::bpf_map::OwnedFd {
                fd: RECORDER_ONLY_MAP_FD,
            }),
            ..Default::default()
        }));
    coordinator.workers.register(
        0,
        WorkerRuntimeRecord::for_test(test_worker_handle(Arc::new(Mutex::new(
            VecDeque::new(),
        )))),
        None,
    );
    coordinator
        .update_ha_state(&[
            HAGroupStatus {
                rg_id: 1,
                active: rg1_active,
                ..HAGroupStatus::default()
            },
            HAGroupStatus {
                rg_id: 2,
                active: rg2_active,
                ..HAGroupStatus::default()
            },
        ])
        .expect("seed initial HA state");
    let entry = synced_entry_port(52_618, 1);
    let forward = entry.key.clone();
    let imported = coordinator.upsert_synced_session(entry);
    assert!(
        coordinator.synced_session_contains(&forward),
        "FIXTURE: the import must file the forward in the shared map ({imported:?})"
    );
    (coordinator, forward)
}

fn activate(coordinator: &Coordinator) {
    coordinator
        .update_ha_state(&[
            HAGroupStatus {
                rg_id: 1,
                active: true,
                ..HAGroupStatus::default()
            },
            HAGroupStatus {
                rg_id: 2,
                active: true,
                ..HAGroupStatus::default()
            },
        ])
        .expect("activate");
}

/// The steering records of `key` during the activation: how many were
/// writes, and whether the last one was a write (the row exists afterwards).
fn forward_steering(key: &SessionKey) -> (usize, bool, Vec<Option<u8>>) {
    let records: Vec<Option<u8>> = session_map_writes()
        .iter()
        .filter(|record| &record.key == key)
        .map(|record| record.value)
        .collect();
    let writes = records.iter().filter(|value| value.is_some()).count();
    let present = records.last().is_some_and(|value| value.is_some());
    (writes, present, records)
}

#[test]
fn activation_writes_an_owner_index_forward_steering_row_once_18641() {
    // RG2 already active; RG1, the forward's owner, activates.
    let (coordinator, forward) = imported(false, true);
    clear_session_map_writes();

    activate(&coordinator);

    let (writes, present, records) = forward_steering(&forward);
    assert!(
        present,
        "the S-forward's steering row is missing after the activation: nothing \
         republished it. Records: {records:?}"
    );
    assert_eq!(
        writes, 1,
        "the S-forward's steering row was written {writes} times in one activation; \
         the prewarm must leave it to the republish (#18641 step 1). Records: \
         {records:?}"
    );
}

#[test]
fn activation_still_writes_a_split_rg_forward_outside_the_owner_index_18641() {
    // RG1, the forward's owner, stays inactive; RG2, its reverse's RG,
    // activates. The forward is a candidate only through the reverse-prewarm
    // index, and the republish (S under RG2) does not reach it.
    let (coordinator, forward) = imported(false, false);
    clear_session_map_writes();

    coordinator
        .update_ha_state(&[
            HAGroupStatus {
                rg_id: 1,
                active: false,
                ..HAGroupStatus::default()
            },
            HAGroupStatus {
                rg_id: 2,
                active: true,
                ..HAGroupStatus::default()
            },
        ])
        .expect("activate rg2");

    let (writes, present, records) = forward_steering(&forward);
    assert!(
        writes == 1 && present,
        "the split-RG forward (owner RG not activated, reverse RG activated) must \
         still get its steering row exactly once from the prewarm (#287/#524): \
         {writes} write(s), present={present}. Records: {records:?}"
    );
}

/// #18641 step 1 (review, seat r24 P3-1): the republish writes the prewarm's
/// OWN owner-index snapshot. A key that leaves S between the prewarm's
/// snapshot and the republish, without being deleted, must still be written:
/// the prewarm skipped it as S, so the republish is its only writer. Before
/// the hand-off the republish re-read the index and missed it, and neither
/// half wrote the row.
///
/// The key leaves S[1] by a real re-home: at the prewarm seam, the same
/// session is re-imported with owner RG 2, which is also active. It is not
/// deleted, so its row must exist after the activation.
#[test]
fn a_key_rehomed_between_the_prewarm_and_the_republish_is_still_written_18641() {
    let (coordinator, forward) = imported(false, true);
    clear_session_map_writes();

    let domain = coordinator.session_domain().clone();
    let rehomed = std::rc::Rc::new(std::cell::Cell::new(false));
    let record = std::rc::Rc::clone(&rehomed);
    crate::afxdp::shared_ops::PREWARM_AFTER_COLLECT_HOOK_18641.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            let mut entry = synced_entry_port(52_618, 1);
            entry.metadata.owner_rg_id = 2;
            let _ = domain.upsert_synced_session(entry);
            record.set(true);
        }));
    });

    activate(&coordinator);

    assert!(rehomed.get(), "FIXTURE: the re-home at the prewarm seam must have run");
    assert_eq!(
        coordinator
            .sessions
            .synced
            .lock()
            .expect("shared")
            .get(&forward)
            .map(|entry| entry.metadata.owner_rg_id),
        Some(2),
        "FIXTURE: the forward must still be shared, now owned by RG 2"
    );
    let (writes, present, records) = forward_steering(&forward);
    assert!(
        present && writes == 1,
        "a forward re-homed out of S after the prewarm's snapshot (not deleted) must be \
         written exactly once by the republish of that snapshot: {writes} write(s), \
         present={present}. Records: {records:?}"
    );
}

/// #18641 step 1 (review, Codex P1-5): the republish is the SOLE activation
/// writer of an owner-index forward's row. A transiently failed write must
/// not leave the forward without its row when the activation returns.
/// Before step 1 the prewarm's write was a second attempt; the republish now
/// retries once instead.
///
/// The forward's first steering write fails (the injector fails it before
/// the recorder sees it, as a failed BPF update leaves no row). Its row must
/// still be present afterwards.
#[test]
fn a_transiently_failed_republish_write_still_leaves_the_row_18641() {
    let (coordinator, forward) = imported(false, true);
    clear_session_map_writes();
    crate::afxdp::bpf_map::FAIL_STEERING_WRITES_FOR
        .with(|slot| *slot.borrow_mut() = Some((forward.clone(), 1)));

    activate(&coordinator);

    let injected_left = crate::afxdp::bpf_map::FAIL_STEERING_WRITES_FOR
        .with(|slot| slot.borrow_mut().take().map(|(_, left)| left));
    assert_eq!(
        injected_left,
        Some(0),
        "FIXTURE: the injected failure must have been consumed by the forward's write"
    );
    let (writes, present, records) = forward_steering(&forward);
    assert!(
        present && writes == 1,
        "after one transient failure the S-forward's row must still be written (by the \
         republish's retry): {writes} successful write(s), present={present}. Records: \
         {records:?}"
    );
}
