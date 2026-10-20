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
    pptp_enabled: bool,
) {
    // #15950: when the PPTP ALG is disabled, do not install associations
    // from segments buffered before the disable. Purge the inbox so a
    // later re-enable cannot resurrect pre-disable calls either.
    if !pptp_enabled {
        // First disabled poll purges immediately (no interval window in
        // which a re-enable could resurrect pre-disable segments).
        pptp_control.purge_once_per_disable();
        return;
    }
    pptp_control.note_enabled();
    crate::afxdp::worker_queue::drain_pptp_control_inbox_for_worker(
        &pptp_control,
        &mut sessions,
        Some(&commands),
        &peer_worker_commands,
        loop_now_ns,
    );
}
