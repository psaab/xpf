// #1345: per-verb handler for set_queue_state. Body byte-identical to
// handlers.rs lines 231-264.

use super::super::helpers::{capture_binding_arm_state, finish_binding_reconcile, refresh_status};
use super::super::ServerState;
use chrono::Utc;
use crate::{ControlResponse, QueueControlRequest};
use std::time::Duration;

pub(super) fn set(
    guard: &mut ServerState,
    queue: Option<QueueControlRequest>,
    response: &mut ControlResponse,
    persist_state: &mut bool,
    // #5862: where the caller records that a binding-settle wait is owed. The
    // wait itself runs in handlers::handle_request AFTER the global ServerState
    // lock is dropped — the same locked-kick / unlocked-wait split #2962 and
    // #4054 use. Holding the lock across a 2 s settle stalled every HA
    // `sync_session` on the "dedicated" session socket, which shares this mutex.
    settle_wait: &mut Option<Duration>,
) {
    let Some(queue_req) = queue else {
        response.ok = false;
        response.error = "missing queue state".to_string();
        return;
    };
    // #6750: capture BEFORE the commit so a failed reconcile can put the
    // helper's report back to the truth. See BindingArmSnapshot.
    let prior = capture_binding_arm_state(&guard.status);
    let mut found = false;
    let mut registration_changed = false;
    for binding in guard
        .status
        .bindings
        .iter_mut()
        .filter(|b| b.queue_id == queue_req.queue_id)
    {
        if binding.registered != queue_req.registered {
            registration_changed = true;
        }
        binding.registered = queue_req.registered;
        binding.armed = queue_req.armed && queue_req.registered;
        binding.last_change = Some(Utc::now());
        found = true;
    }
    if found {
        if registration_changed {
            // #3789: this reconcile re-binds the ALREADY-ACCEPTED stored
            // snapshot (a queue registration toggle, not a new config), so
            // a build reject cannot introduce a rejected snapshot here.
            //
            // #17126: the reconcile / roll-back-on-error / settle /
            // persist tail is shared via `finish_binding_reconcile`
            // (#5621 honest failure, #6750 restore). This handler keeps
            // only its commit (above); reaching the helper means the
            // registration changed, so a settle is always owed.
            finish_binding_reconcile(
                guard,
                response,
                "queue",
                prior,
                true,
                persist_state,
                settle_wait,
            );
            return;
        }
        refresh_status(guard);
        *persist_state = true;
    } else {
        response.ok = false;
        response.error = format!("unknown queue {}", queue_req.queue_id);
    }
}
