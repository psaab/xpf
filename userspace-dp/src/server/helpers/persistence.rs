// State-file persistence helpers (#6234 split out of the former
// monolithic `server/helpers.rs`).
//
// `write_state` holds the `ServerState` lock ONLY long enough to
// `refresh_status` and clone a minimal owned payload
// (`build_state_payload` → `OwnedStatePayload`); the fallible
// serialize + fsync (`encode` + `StateWriter::persist`) run with the
// guard dropped (#5469). The `OwnedStatePayload` type structure is the
// proof that serialization is lock-free — it owns its data and cannot
// reach the guard. Cold path (periodic + fallback delta poll), not the
// worker loop. Bodies byte-for-byte identical to the pre-split source.

use super::{lock_server_recover, refresh_status};
use crate::protocol::{ConfigSnapshot, ProcessStatus};
use crate::server::ServerState;
use serde::Serialize;
use std::sync::{Arc, Mutex};

/// Owned, point-in-time copy of the state that gets persisted to the state
/// file. Cloned out of `ServerState` under the lock (`build_state_payload`) so
/// the expensive serialization and the fsync in `persist` run WITHOUT holding
/// the `ServerState` lock (#5469). Because this owns its data, `encode` cannot
/// reach the guard — the type structure is the proof that serialization happens
/// lock-free.
struct OwnedStatePayload {
    status: ProcessStatus,
    snapshot: Option<ConfigSnapshot>,
}

impl OwnedStatePayload {
    /// Encode to the exact bytes written to the state file. Operates purely on
    /// owned data with no `ServerState` guard in scope, so it can never run
    /// under the lock. Byte-for-byte identical to the pre-#5469 encoding
    /// (`to_vec_pretty` of the same two fields, trailing newline).
    fn encode(&self) -> Result<Vec<u8>, String> {
        #[derive(Serialize)]
        struct Payload<'a> {
            status: &'a ProcessStatus,
            snapshot: &'a Option<ConfigSnapshot>,
        }
        let payload = Payload {
            status: &self.status,
            snapshot: &self.snapshot,
        };
        let mut bytes =
            serde_json::to_vec_pretty(&payload).map_err(|e| format!("encode state: {e}"))?;
        bytes.push(b'\n');
        Ok(bytes)
    }
}

/// Lock-scoped half of `write_state`: refresh the status and clone the minimal
/// owned payload. This is the ONLY part of a state write that touches the
/// `ServerState` guard — it takes `&mut ServerState` (the guarded data), so a
/// caller must hold the lock to reach it, and it returns owned data the caller
/// can persist after dropping the guard.
fn build_state_payload(state: &mut ServerState) -> OwnedStatePayload {
    refresh_status(state);
    OwnedStatePayload {
        status: state.status.clone(),
        snapshot: state.snapshot.clone(),
    }
}

pub(crate) fn write_state(state_file: &str, state: &Arc<Mutex<ServerState>>) -> Result<(), String> {
    // Critical section (#5469): hold the `ServerState` lock ONLY long enough to
    // refresh status and snapshot an owned, point-in-time payload, plus a cheap
    // Arc bump for the writer handle. That lock also gates snapshot apply,
    // status, and HA/control ops, so serializing the full ProcessStatus +
    // ConfigSnapshot and driving `persist` (which does file + parent-dir fsync)
    // under it created a lock convoy: the fallback session-delta poll sets
    // `persist_state` on every nonempty request, so under session churn each
    // delta poll serialized+fsynced the whole state while holding the lock,
    // delaying every other control op that needs it.
    let (payload, writer) = {
        let mut guard = lock_server_recover(&state);
        let payload = build_state_payload(&mut guard);
        let writer = guard.state_writer.clone();
        (payload, writer)
        // Guard dropped here: encode() + persist() below run lock-free.
    };

    let bytes = payload.encode()?;

    // Fail-on-revert probe (#5469): with the guard block above closed, this
    // thread must NOT hold the `ServerState` lock at the persist point. std
    // `Mutex` is non-reentrant, so a same-thread `try_lock` here succeeds only
    // if the guard was truly dropped; revert the guard back across persist and
    // the recorded value flips, turning `write_state_releases_lock_before_persist`
    // RED. Compiled out of production builds.
    #[cfg(test)]
    record_pre_persist_lock_state(state);

    // Serialization + fsync happen with the `ServerState` lock RELEASED. All
    // persists funnel through StateWriter's single writer thread and publish via
    // temp+atomic-rename (`finalize_durably`), so concurrent writers never tear
    // the file; the effective semantics are last-writer-wins, and any transient
    // staleness self-corrects on the next periodic write_state.
    writer
        .persist(state_file, bytes)
        .map_err(|e| format!("write state file: {e}"))?;
    Ok(())
}

#[cfg(test)]
thread_local! {
    /// Records, per write_state-driving thread, whether the `ServerState` lock
    /// was free at the pre-persist point (see `record_pre_persist_lock_state`).
    /// Thread-local so parallel test threads never cross-contaminate.
    static PRE_PERSIST_LOCK_FREE: std::cell::Cell<Option<bool>> =
        const { std::cell::Cell::new(None) };
}

/// Test seam for the #5469 fail-on-revert guard. Runs on `write_state`'s own
/// thread, after the lock-scoped payload build and before `persist`. A
/// same-thread `try_lock` succeeds ONLY if the guard was already dropped (std
/// `Mutex` is non-reentrant), so the recorded flag proves persist runs outside
/// the critical section.
#[cfg(test)]
fn record_pre_persist_lock_state(state: &Arc<Mutex<ServerState>>) {
    let free = state.try_lock().is_ok();
    PRE_PERSIST_LOCK_FREE.with(|c| c.set(Some(free)));
}

/// Reset the pre-persist lock probe for the current thread before driving a
/// `write_state` under test.
#[cfg(test)]
pub(crate) fn clear_pre_persist_lock_probe() {
    PRE_PERSIST_LOCK_FREE.with(|c| c.set(None));
}

/// Take the value recorded by the last `write_state` on the current thread:
/// `Some(true)` if the lock was free at the persist point, `Some(false)` if it
/// was still held (the #5469 regression), `None` if no probe ran.
#[cfg(test)]
pub(crate) fn take_pre_persist_lock_free() -> Option<bool> {
    PRE_PERSIST_LOCK_FREE.with(|c| c.take())
}
