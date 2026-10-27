// #1345: per-verb handler for set_forwarding_state. Body byte-identical
// to handlers.rs lines 132-155.

use super::super::helpers::{
    capture_binding_arm_state, forwarding_unsupported_error, reconcile_status_bindings,
    refresh_status, restore_binding_arm_state, set_bindings_forwarding_armed,
};
use super::super::ServerState;
use crate::{ControlResponse, ForwardingControlRequest};
use std::time::Duration;

pub(super) fn set(
    guard: &mut ServerState,
    forwarding: Option<ForwardingControlRequest>,
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
    // #6135 (4th site of #5621): the reconcile itself can still FAIL — the
    // mandatory-pin preflight can fault, or the forwarding build can hit a
    // non-policy integrity error on the already-accepted snapshot. Discarding
    // that Err made this handler ack ok=true while the AF_XDP sockets were NOT
    // actually reconciled to the new forwarding state, so the control-socket
    // caller believed the reconcile succeeded when it did not. Surface the
    // failure: report ok=false + the error, refresh status so `show` reflects
    // the real per-binding state, and do NOT persist a success we didn't
    // achieve (return BEFORE wait_for_binding_settle / persist_state=true).
    if let Err(err) = reconcile_status_bindings(guard) {
        response.ok = false;
        response.error = format!("forwarding reconcile failed: {err}");
        // #6750: roll the requested state back BEFORE refreshing, so the
        // refreshed status describes what the sockets are actually doing. Go's
        // 1 Hz poll then sees the real state, its
        // `lastStatus.ForwardingArmed == desired` short-circuit fails, and the
        // next tick retries by itself.
        restore_binding_arm_state(&mut guard.status, prior);
        refresh_status(guard);
        return;
    }
    if forwarding_req.armed {
        *deferred = Some(super::Deferred::Settle(Duration::from_secs(2)));
    }
    refresh_status(guard);
    *persist_state = true;
}
