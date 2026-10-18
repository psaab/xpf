// #1345: per-verb handler for stop_workers. Body byte-identical to
// handlers.rs lines 409-433.

use super::super::helpers::refresh_status;
use super::super::ServerState;

pub(super) fn handle(guard: &mut ServerState, persist_state: &mut bool) {
    // Stop all AF_XDP workers without recreating them.
    // Used by PrepareLinkCycle: stops workers BEFORE link
    // DOWN/UP so they don't access DMA-mapped UMEM pages
    // that the NIC unmaps during link cycle. The subsequent
    // "rebind" request (sent by NotifyLinkCycle after the
    // link is back UP) recreates workers with fresh sockets.
    //
    // #14677: use `stop_for_link_cycle`, NOT `stop()`. `stop()` runs
    // `stop_inner(true)`, wiping every HA-synced session, the
    // persistent-NAT allocator state, and the tunnel-owner baseline
    // that `rebind`'s reconcile is supposed to replay/migrate — the
    // exact side effects `rebind.rs` documents as "wrong for a rebind".
    // The link-cycle stop must only join the workers.
    eprintln!("stop_workers: stopping all AF_XDP workers");
    guard.afxdp.stop_for_link_cycle();
    for binding in &mut guard.status.bindings {
        binding.bound = false;
        binding.xsk_registered = false;
        binding.xsk_bind_mode.clear();
        binding.zero_copy = false;
        binding.socket_fd = 0;
        binding.ready = false;
        binding.last_error.clear();
    }
    refresh_status(guard);
    *persist_state = true;
    eprintln!(
        "stop_workers: all workers stopped, bindings={}",
        guard.status.bindings.len()
    );
}
