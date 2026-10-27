// #1345: per-verb handler for set_binding_state. Body byte-identical to
// handlers.rs lines 265-291.

use super::super::helpers::{capture_binding_arm_state, finish_binding_reconcile, refresh_status};
use super::super::ServerState;
use chrono::Utc;
use crate::{BindingControlRequest, ControlResponse};

pub(super) fn set(
    guard: &mut ServerState,
    binding: Option<BindingControlRequest>,
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
    let Some(binding_req) = binding else {
        response.ok = false;
        response.error = "missing binding state".to_string();
        return;
    };
    // #6750: capture BEFORE the commit so a failed reconcile can put the
    // helper's report back to the truth. See BindingArmSnapshot.
    let prior = capture_binding_arm_state(&guard.status);
    if let Some(binding) = guard
        .status
        .bindings
        .iter_mut()
        .find(|b| b.slot == binding_req.slot)
    {
        let registration_changed = binding.registered != binding_req.registered;
        binding.registered = binding_req.registered;
        binding.armed = binding_req.armed && binding_req.registered;
        binding.last_change = Some(Utc::now());
        if registration_changed {
            // #3789: re-binds the ALREADY-ACCEPTED stored snapshot (a
            // binding registration toggle, not a new config), so a build
            // reject cannot introduce a rejected snapshot here.
            //
            // #17126: the reconcile / roll-back-on-error / settle /
            // persist tail is shared via `finish_binding_reconcile`
            // (#5621 honest failure, #6750 restore). This handler keeps
            // only its commit (above); reaching the helper means the
            // registration changed, so a settle is always owed.
            finish_binding_reconcile(
                guard,
                response,
                "binding",
                prior,
                true,
                persist_state,
                deferred,
            );
            return;
        }
        refresh_status(guard);
        *persist_state = true;
    } else {
        response.ok = false;
        response.error = format!("unknown binding slot {}", binding_req.slot);
    }
}
