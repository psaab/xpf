// #1345: per-verb handler for set_forwarding_state, split out of handlers.rs in #1345.

use super::super::helpers::{
    capture_binding_arm_state, finish_binding_reconcile, forwarding_unsupported_error,
    set_bindings_forwarding_armed,
};
use super::super::ServerState;
use crate::{ControlResponse, ForwardingControlRequest};

pub(super) fn set(
    guard: &mut ServerState,
    forwarding: Option<ForwardingControlRequest>,
    response: &mut ControlResponse,
    persist_state: &mut bool,
    // #5862/#17135: where the caller records that a binding-settle wait is
    // owed, as `Deferred::Settle`. The wait itself runs in
    // handlers::handle_stream AFTER the global ServerState lock is
    // dropped — the same locked-kick / unlocked-wait split #2962 and
    // #4054 use. Holding the lock across a 2 s settle stalled every HA
    // `sync_session` before #7209 moved that verb off this mutex.
    deferred: &mut Option<super::Deferred>,
) {
    let Some(forwarding_req) = forwarding else {
        response.ok = false;
        response.error = "missing forwarding state".to_string();
        return;
    };
    eprintln!(
        "CTRL_REQ: set_forwarding_state armed={} forwarding_armed_before={}",
        forwarding_req.armed, guard.status.forwarding_armed
    );
    if forwarding_req.armed && !guard.status.capabilities.forwarding_supported {
        response.ok = false;
        response.error = forwarding_unsupported_error(&guard.status.capabilities);
        return;
    }
    // #6750: capture BEFORE the commit so a failed reconcile can put the
    // helper's report back to the truth. See BindingArmSnapshot.
    let prior = capture_binding_arm_state(&guard.status);
    guard.status.forwarding_armed = forwarding_req.armed;
    set_bindings_forwarding_armed(&mut guard.status, forwarding_req.armed);
    // #3789: arming/disarming reconciles the ALREADY-ACCEPTED stored
    // snapshot (a forwarding-state toggle, not a new config), so a build
    // reject cannot introduce a rejected snapshot here.
    //
    // #17126: the reconcile / roll-back-on-error / settle / persist tail is
    // shared with set_binding_state and set_queue_state via
    // `finish_binding_reconcile` (#5621/#6135 honest failure, #6750 restore).
    // This handler keeps only its commit (above) and its settle rule:
    // settle only when arming.
    finish_binding_reconcile(
        guard,
        response,
        "forwarding",
        prior,
        forwarding_req.armed,
        persist_state,
        deferred,
    );
}
