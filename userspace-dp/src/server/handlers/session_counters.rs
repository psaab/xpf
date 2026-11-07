//! #7919: the `session_counters` verb — READ-ONLY per-worker report for one
//! 5-tuple.
//!
//! Two-phase like the exports (#2962): `kick` runs under the `ServerState` lock
//! and only broadcasts; `collect` runs the bounded wait with the lock RELEASED.
//!
//! Refusal is explicit. A request with no 5-tuple, or one whose addresses do
//! not parse, is answered with an error rather than with an empty row set — an
//! empty answer to a malformed question is indistinguishable from "no worker
//! holds this session", which is one of the two states the whole verb exists to
//! separate.

use super::super::ServerState;
use crate::ControlResponse;
use crate::afxdp::SessionCounterQueryWait;
use crate::protocol::{SessionCounterQueryRequest, SessionCounterRowWire};
use std::net::IpAddr;

/// Build the lookup key, or `None` with a reason the caller reports.
fn key_from_request(
    req: &SessionCounterQueryRequest,
) -> Result<crate::session::SessionKey, String> {
    let src_ip: IpAddr = req
        .src_ip
        .parse()
        .map_err(|_| format!("session_counters: unparseable src_ip {:?}", req.src_ip))?;
    let dst_ip: IpAddr = req
        .dst_ip
        .parse()
        .map_err(|_| format!("session_counters: unparseable dst_ip {:?}", req.dst_ip))?;
    if src_ip.is_ipv4() != dst_ip.is_ipv4() {
        return Err("session_counters: src_ip and dst_ip families differ".to_string());
    }
    Ok(crate::session::SessionKey {
        addr_family: if src_ip.is_ipv4() {
            libc::AF_INET as u8
        } else {
            libc::AF_INET6 as u8
        },
        protocol: req.protocol,
        src_ip,
        dst_ip,
        src_port: req.src_port,
        dst_port: req.dst_port,
        discriminator: Default::default(),
        routing_domain: 0,
    })
}

/// Locked phase: validate and broadcast. Returns `None` (with the error folded
/// into `response`) when there is nothing to ask.
pub(super) fn kick(
    guard: &mut ServerState,
    req: Option<&SessionCounterQueryRequest>,
    response: &mut ControlResponse,
) -> Option<SessionCounterQueryWait> {
    let Some(req) = req else {
        response.ok = false;
        response.error = "session_counters: no session_counter_query in request".to_string();
        return None;
    };
    match key_from_request(req) {
        Ok(key) => Some(guard.afxdp.kick_session_counter_query(&key)),
        Err(err) => {
            response.ok = false;
            response.error = err;
            None
        }
    }
}

/// Lock-free phase: wait for the replies and render them.
pub(super) fn collect(wait: SessionCounterQueryWait) -> Vec<SessionCounterRowWire> {
    wait.wait_and_collect()
        .into_iter()
        .map(|r| SessionCounterRowWire {
            worker_id: r.worker_id,
            answered: r.answered,
            found: r.found,
            replica: r.replica,
            fwd_packets: r.fwd_packets,
            fwd_bytes: r.fwd_bytes,
            rev_packets: r.rev_packets,
            rev_bytes: r.rev_bytes,
        })
        .collect()
}
