// #1345: per-verb handler for update_ha_state, split out of handlers.rs in #1345.

use super::super::helpers::project_status;
use super::super::ServerState;
use crate::{ControlResponse, HAStateUpdateRequest};

pub(super) fn update(
    guard: &mut ServerState,
    ha_state: Option<HAStateUpdateRequest>,
    response: &mut ControlResponse,
    persist_state: &mut bool,
) {
    let Some(ha_req) = ha_state else {
        response.ok = false;
        response.error = "missing HA state".to_string();
        return;
    };
    #[cfg(feature = "debug-log")]
    eprintln!(
        "CTRL_REQ: update_ha_state groups={} forwarding_armed={}",
        ha_req.groups.len(),
        guard.status.forwarding_armed
    );
    // #6568 (member 4): the OPTIMISTIC write lands before the apply, so on the
    // Err path `status.ha_groups` holds groups that were never applied — the
    // control-socket caller is told ok=false while `show` reports the requested
    // RG state as though it took effect.
    //
    // The Err arm must therefore re-derive status from the coordinator, which
    // is the authoritative source: `project_status` -> helpers/status.rs does
    // `state.status.ha_groups = state.afxdp.ha_groups()`, so it is a genuine
    // revert to what was actually applied rather than a hand-rolled restore of
    // the previous value (which would be wrong if the apply partially landed).
    //
    // This is the third site of the #5621 family, after the #6135 forwarding
    // handler and the binding/rebind pair — same shape, same remedy: report
    // ok=false, refresh status so `show` reflects reality, do NOT persist a
    // success we did not achieve.
    guard.status.ha_groups = ha_req.groups.clone();
    match guard.afxdp.update_ha_state(&ha_req.groups) {
        Ok(()) => {
            project_status(guard);
            *persist_state = true;
        }
        Err(err) => {
            response.ok = false;
            response.error = err;
            project_status(guard);
        }
    }
}
