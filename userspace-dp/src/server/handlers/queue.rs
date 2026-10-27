// #1345: per-verb handler for set_queue_state. Body byte-identical to
// handlers.rs lines 231-264.

use super::super::helpers::{
    capture_binding_arm_state, reconcile_status_bindings, refresh_status,
    restore_binding_arm_state,
};
use super::super::ServerState;
use chrono::Utc;
use crate::{ControlResponse, QueueControlRequest};
use std::time::Duration;

pub(super) fn set(
    guard: &mut ServerState,
    queue: Option<QueueControlRequest>,
    response: &mut ControlResponse,
    persist_state: &mut bool,
    // #5862/#17135: where the caller records that a binding-settle wait is
    // owed. The wait itself runs in handlers::handle_stream AFTER the global
    // ServerState lock is dropped — the same locked-kick / unlocked-wait
    // split #2962 and #4054 use. Holding the lock across a 2 s settle stalled
    // every HA `sync_session` on the "dedicated" session socket, which
    // shares this mutex.
    deferred: &mut Option<super::Deferred>,
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
            // #5621: the reconcile itself can still FAIL — the mandatory-pin
            // preflight can fault, or the forwarding build can hit a
            // non-policy integrity error on the already-accepted snapshot.
            // Discarding that Err made the handler ack ok=true while the
            // AF_XDP sockets were NOT actually rebound, so the control-socket
            // caller believed the reconcile succeeded when it did not.
            // Surface the failure: report ok=false + the error, refresh
            // status so `show` reflects the real per-binding state, and do
            // NOT persist a success we didn't achieve.
            if let Err(err) = reconcile_status_bindings(guard) {
                response.ok = false;
                response.error = format!("queue reconcile failed: {err}");
                // #6750: roll the requested state back BEFORE refreshing, so the
                // helper stops reporting a registration its sockets never took
                // and Go's poll can see the mismatch that drives a retry.
                restore_binding_arm_state(&mut guard.status, prior);
                refresh_status(guard);
                return;
            }
            *deferred = Some(super::Deferred::Settle(Duration::from_secs(2)));
        }
        refresh_status(guard);
        *persist_state = true;
    } else {
        response.ok = false;
        response.error = format!("unknown queue {}", queue_req.queue_id);
    }
}
