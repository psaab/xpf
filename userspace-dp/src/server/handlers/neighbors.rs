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
    persist_state: &mut bool,
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
    // #6034/#10035: carry the replace-generation envelope. The helper fences
    // a stale / reordered replace (generation <= last applied) and returns
    // false without touching the table; `refresh_status` still runs so the
    // ACK (`ProcessStatus.manager_neighbor_generation`) reflects the current
    // applied generation. The additive outcome bit distinguishes an
    // exact-match fence from a successful apply: both have the same ACK
    // generation, but only the latter reports `neighbor_replace_applied=true`.
    let applied = guard
        .afxdp
        .apply_manager_neighbors(replace, generation, &resolved);
    if replace {
        guard.status.neighbor_replace_applied = Some(applied);
    }
    if !applied {
        eprintln!(
            "update_neighbors: fenced stale replace generation {} (last applied {})",
            generation,
            guard.afxdp.last_applied_manager_neighbor_generation()
        );
    } else if let Some(snapshot) = guard.snapshot.as_mut() {
        if replace {
            // #12195: an accepted replace defines the stored reconcile-neighbor set.
            // Keep the snapshot (which arm/rebind rebuild from) in sync, and request
            // a state write when that set or its digest changes, like update_fabrics (#3773).
            // #3771 (M11): a family-mismatched row cannot enter this stored
            // reconcile input, even though the manager table accepts it.
            let is_family_mismatch = |neigh: &NeighborSnapshot| {
                if neigh.ifindex <= 0 {
                    return false;
                }
                let Ok(ip) = neigh.ip.parse::<std::net::IpAddr>() else {
                    return false;
                };
                afxdp::neighbor_family_mismatch(&neigh.family, &ip)
            };
            let filtered_neighbors = if neighbors.iter().any(|neigh| is_family_mismatch(neigh)) {
                Some(
                    neighbors
                        .iter()
                        .filter(|neigh| !is_family_mismatch(neigh))
                        .cloned()
                        .collect::<Vec<_>>(),
                )
            } else {
                None
            };
            let has_family_mismatch = filtered_neighbors.is_some();
            let stored_set_changed = if let Some(filtered_neighbors) = filtered_neighbors {
                if snapshot.neighbors.as_slice() != filtered_neighbors.as_slice() {
                    snapshot.neighbors = filtered_neighbors;
                    true
                } else {
                    false
                }
            } else if snapshot.neighbors.as_slice() != neighbors {
                snapshot.neighbors = neighbors.to_vec();
                true
            } else {
                false
            };
            if stored_set_changed {
                // #9520: the stored snapshot is no longer the full apply its
                // content digest describes, so it must not vouch for a
                // same-generation retry of that apply.
                snapshot.content_digest.clear();
                *persist_state = true;
            } else if has_family_mismatch && !snapshot.content_digest.is_empty() {
                // The applied replace changed the live manager table even though
                // M11 excluded its rows from the stored reconcile snapshot.
                snapshot.content_digest.clear();
                *persist_state = true;
            }
        } else {
            // Additive updates still change enforced content even though they
            // cannot replace the stored neighbor set.
            snapshot.content_digest.clear();
        }
    }
    refresh_status(guard);
}
