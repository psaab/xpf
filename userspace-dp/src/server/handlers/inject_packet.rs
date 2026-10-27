// #1345: per-verb handler for inject_packet. Body byte-identical to
// handlers.rs lines 292-308.

use super::super::helpers::project_status;
use super::super::ServerState;
use crate::{ControlResponse, InjectPacketRequest};

pub(super) fn handle(
    guard: &mut ServerState,
    packet: Option<InjectPacketRequest>,
    response: &mut ControlResponse,
    persist_state: &mut bool,
) {
    let Some(packet_req) = packet else {
        response.ok = false;
        response.error = "missing packet injection request".to_string();
        return;
    };
    match guard.afxdp.inject_test_packet(packet_req) {
        Ok(()) => {
            project_status(guard);
            *persist_state = true;
        }
        Err(err) => {
            response.ok = false;
            response.error = err;
        }
    }
}
