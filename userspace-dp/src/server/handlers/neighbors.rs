// #1345: per-verb handler for update_neighbors. Body byte-identical to
// handlers.rs lines 186-208.

use super::super::helpers::refresh_status;
use super::super::ServerState;
use crate::{afxdp, NeighborSnapshot};

pub(super) fn update(
    guard: &mut ServerState,
    neighbors: Option<&Vec<NeighborSnapshot>>,
    generation: u64,
    replace: bool,
) {
    // #5864: an authoritative replace with zero entries must CLEAR the
    // manager-neighbor table. When the Go publishable set transitions to
    // empty, the field can arrive as absent/None (older wire) or as an
    // explicit `[]` (post-#5864 wire, omitempty removed). Both mean the
    // same thing under NeighborReplace: clear. Only bail early on a
    // NON-replace update with no neighbors — that carries nothing to add
    // and must not touch the existing table.
    let neighbors: &[NeighborSnapshot] = match neighbors {
        Some(neighbors) => neighbors.as_slice(),
        None if replace => &[],
        None => return,
    };
    let mut resolved = Vec::with_capacity(neighbors.len());
    for neigh in neighbors {
        if neigh.ifindex <= 0 || neigh.mac.is_empty() {
            continue;
        }
        let Ok(ip) = neigh.ip.parse::<std::net::IpAddr>() else {
            continue;
        };
        let Some(mac) = afxdp::parse_mac_str(&neigh.mac) else {
            continue;
        };
        if !afxdp::neighbor_state_usable_str(&neigh.state) {
            continue;
        }
        resolved.push((neigh.ifindex, ip, afxdp::NeighborEntry { mac }));
    }
    // #6034: carry the replace-generation envelope. `apply_manager_neighbors`
    // fences a stale / reordered replace (generation <= last applied) and
    // returns false without touching the table; `refresh_status` still runs so
    // the ACK (ProcessStatus.manager_neighbor_generation) reflects the current
    // applied generation and the Go manager can retain retry debt.
    let applied = guard
        .afxdp
        .apply_manager_neighbors(replace, generation, &resolved);
    if !applied {
        eprintln!(
            "update_neighbors: fenced stale replace generation {} (last applied {})",
            generation,
            guard.afxdp.last_applied_manager_neighbor_generation()
        );
    } else if let Some(snapshot) = guard.snapshot.as_mut() {
        // #9520: the helper now enforces neighbours the installed full apply
        // did not carry, so that apply's content digest no longer describes
        // what is enforced and must not vouch for a same-generation retry of it
        // (handlers/snapshot.rs refuses one against an empty installed digest).
        snapshot.content_digest.clear();
    }
    refresh_status(guard);
}
