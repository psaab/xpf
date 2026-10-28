// #1345: per-verb handler for drain_session_deltas, split out of handlers.rs in #1345.

use super::super::helpers::project_status;
use super::super::ServerState;
use crate::{ControlResponse, SessionDeltaDrainRequest};

pub(super) fn drain(
    guard: &mut ServerState,
    session_deltas: Option<&SessionDeltaDrainRequest>,
    response: &mut ControlResponse,
    persist_state: &mut bool,
    drained_delta_slots: &mut Vec<u32>,
) {
    let max = session_deltas.map(|req| req.max).unwrap_or(256).max(1) as usize;
    let (deltas, contributed) = guard.afxdp.drain_session_deltas_attributed(max);
    // #16584: remember exactly which bindings this destructive drain took
    // deltas from, and whether it took any at all. The dispatcher tail arms
    // loss on these slots only if the response fails to reach the peer, and
    // only flags a persist when the drain was non-empty (an empty drain
    // changed no fallback-buffer state worth persisting).
    *drained_delta_slots = contributed;
    let drained_any = !deltas.is_empty();
    response.session_deltas = deltas;
    project_status(guard);
    if drained_any {
        *persist_state = true;
    }
}
