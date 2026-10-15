// #6386 leaf extraction: the #1769/#1912 per-key rate-limited neighbor
// resolver enqueue helper, lifted verbatim out of poll_descriptor/mod.rs.
// The moved bare fn becomes pub(super) and keeps its existing #[inline]
// (cold-path only; attr-verbatim, no other non-motion change).
//
// #13646: the bounded-insert policy for `resolver_enqueue_throttle` also
// lives here (was wholesale `throttle.clear()` at both insert sites, which
// let one arriving key wipe every in-window rate limit). Reclaim follows
// the neg_neigh #6905 precedent: drop expired entries, else the single
// oldest, never the whole map.

use super::*;

/// #13646: true iff `key` was probed/enqueued within the throttle window.
#[inline]
pub(super) fn probe_throttled(
    throttle: &FastMap<(i32, IpAddr), u64>,
    key: &(i32, IpAddr),
    now_ns: u64,
) -> bool {
    matches!(
        throttle.get(key),
        Some(&t) if now_ns.saturating_sub(t) < RESOLVER_ENQUEUE_THROTTLE_NS
    )
}

/// #13646: free room for one new key without wiping the map: evict every
/// entry past the throttle window, then (only if still full) the single
/// oldest survivor. Allocation-free; O(len), same order as the old clear.
fn reclaim_throttle_one(throttle: &mut FastMap<(i32, IpAddr), u64>, now_ns: u64) {
    let mut oldest: Option<((i32, IpAddr), u64)> = None;
    throttle.retain(|k, inserted| {
        if now_ns.saturating_sub(*inserted) >= RESOLVER_ENQUEUE_THROTTLE_NS {
            return false;
        }
        if oldest.is_none_or(|(_, t)| *inserted < t) {
            oldest = Some((*k, *inserted));
        }
        true
    });
    if throttle.len() >= MAX_NEG_NEIGH_CACHE
        && let Some((victim, _)) = oldest
    {
        throttle.remove(&victim);
    }
}

/// #13646: record `key` as probed at `now_ns`, reclaiming at most one
/// live entry at capacity. Returns false (recording nothing) when the
/// key was throttled or has no interface name, mirroring the enqueue
/// helper's gating so callers can skip the raw-socket probe syscall.
#[inline]
pub(super) fn note_kernel_probe(
    throttle: &mut FastMap<(i32, IpAddr), u64>,
    ifindex_to_name: &FastMap<i32, String>,
    key: (i32, IpAddr),
    now_ns: u64,
) -> bool {
    if probe_throttled(throttle, &key, now_ns) {
        return false;
    }
    if !ifindex_to_name.contains_key(&key.0) {
        return false;
    }
    if throttle.len() >= MAX_NEG_NEIGH_CACHE && !throttle.contains_key(&key) {
        reclaim_throttle_one(throttle, now_ns);
    }
    throttle.insert(key, now_ns);
    true
}

/// #1769/#1912: per-key rate-limited enqueue of the shared neighbor
/// resolver. Both the neg-cache fast-fail branch and the #1912 tunnel
/// outer-hop branch use the identical throttle-check / `ifindex_to_name`
/// clone / `enqueue` / cap-reclaim / `insert` sequence keyed by
/// `(ifindex, next_hop)` — factored here so the throttle window, the cap
/// constant, and the reclaim policy live in ONE place (Copilot #1912 r1
/// Medium). Returns true iff it actually enqueued (i.e. was not throttled
/// and the iface had a name). Cold-path only.
#[inline]
pub(super) fn try_enqueue_resolver(
    resolver: &NeighborResolver,
    throttle: &mut FastMap<(i32, IpAddr), u64>,
    ifindex_to_name: &FastMap<i32, String>,
    key: (i32, IpAddr),
    now_ns: u64,
) -> bool {
    // Cheap (i32, IpAddr) map check runs before any clone.
    if probe_throttled(throttle, &key, now_ns) {
        return false;
    }
    let Some(name) = ifindex_to_name.get(&key.0) else {
        return false;
    };
    resolver.enqueue(key.0, key.1, name.clone());
    // #13646: bound the throttle map like the negative cache without a
    // wholesale clear — reclaim expired entries, else the oldest (#6905).
    if throttle.len() >= MAX_NEG_NEIGH_CACHE && !throttle.contains_key(&key) {
        reclaim_throttle_one(throttle, now_ns);
    }
    throttle.insert(key, now_ns);
    true
}

#[cfg(test)]
#[path = "resolver_enqueue_tests.rs"]
mod tests;
