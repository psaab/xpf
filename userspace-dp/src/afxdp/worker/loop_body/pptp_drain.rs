// #13075 (D4-12) — PPTP control-inbox drain, extracted from `worker_loop`
// in loop_body/mod.rs (pure code motion; see housekeeping.rs).
//
// The #7699 placement contract is preserved by construction: the caller
// invokes this immediately after the session-expiry housekeeping (its
// counterpart, on the same clock) and before the conntrack-refresh slice
// and the binding poll — the exact in-loop position. The drain-interval
// gate stays inside `PptpControlInbox::take_pending`; do not name the
// interval constant here or at the call site (see the in-body comment).

use super::*;

#[inline(never)]
pub(super) fn run_pptp_control_drain(
    pptp_control: &crate::session::pptp_control::PptpControlInbox,
    mut sessions: &mut crate::session::SessionTable,
    commands: &Arc<Mutex<VecDeque<WorkerCommand>>>,
    peer_worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    loop_now_ns: u64,
) {
    // #7699: drain the PPTP control inbox — parse the TCP/1723 segments the
    // data path copied out, install the associations locally and publish
    // them to the sibling workers.
    //
    // PLACEMENT: adjacent to the association EXPIRY it is the counterpart
    // of, and on the same clock. This is per-iteration work only in the
    // sense that the CALL is; `take_pending` holds the drain-interval gate
    // ITSELF and returns an empty vec otherwise, so the body below runs
    // once per interval. The gate is deliberately not written here: this
    // loop runs at packet rate, and a call-site gate is one edit from
    // becoming per-poll work — which is exactly what #8399 shipped when the
    // association expiry landed above `expire_stale_entries_ha`'s gate
    // instead of below it. `worker_loop_drains_the_pptp_control_inbox_7699`
    // enforces both halves of that, including the absence of the interval
    // constant from this file — so do not name it here even in a comment.
    crate::afxdp::worker_queue::drain_pptp_control_inbox_for_worker(
        &pptp_control,
        &mut sessions,
        Some(&commands),
        &peer_worker_commands,
        loop_now_ns,
    );
}
