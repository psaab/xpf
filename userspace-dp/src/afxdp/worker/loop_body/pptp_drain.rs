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
    view_generation: u64,
) {
    // #15950: when the PPTP ALG is disabled, do not install associations
    // from segments buffered before the disable. Purge the inbox so a
    // later re-enable cannot resurrect pre-disable calls either.
    // Epoch eligibility is decided at DRAIN time, never by clearing at
    // poll: observing the bit only advances the epoch on a
    // disabled->enabled transition. A skipped disabled generation is
    // handled because the epoch advances whenever the enabled state is
    // observed after a disabled observation (by any worker sharing this
    // inbox), and steady-enabled polls change nothing.
    pptp_control.note_enabled_state(pptp_enabled, view_generation);
    if !pptp_enabled {
        return;
    }
    crate::afxdp::worker_queue::drain_pptp_control_inbox_for_worker(
        &pptp_control,
        &mut sessions,
        Some(&commands),
        &peer_worker_commands,
        loop_now_ns,
    );
}
