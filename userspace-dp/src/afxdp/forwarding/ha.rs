//! #5650: HA redundancy-group resolution enforcement and owner-RG attribution
//! for the forwarding path (active/inactive disposition, cached-decision
//! validity, new-flow finalization, demoted/activated RG sets). Pure
//! code-motion split out of `forwarding/mod.rs` (behavior-identical).

use super::*;

pub(in crate::afxdp) fn owner_rg_for_flow(forwarding: &ForwardingState, egress_ifindex: i32) -> i32 {
    forwarding
        .egress
        .get(&egress_ifindex)
        .map(|iface| iface.redundancy_group.max(0))
        .unwrap_or_default()
}

pub(in crate::afxdp) fn owner_rg_for_resolution(
    forwarding: &ForwardingState,
    resolution: ForwardingResolution,
) -> i32 {
    if resolution.tunnel_endpoint_id != 0 {
        return forwarding
            .tunnel_endpoints
            .get(&resolution.tunnel_endpoint_id)
            // #1873 (Codex code r3): a stored tunnel resolution whose
            // egress_ifindex (= the owning netdev's logical_ifindex at
            // resolve time) does not match the CURRENT row belongs to a
            // re-owned id — attributing the NEW owner's RG to it would
            // re-home a stale, drop-only session under the new tunnel
            // in HA metadata/indexes. Return 0 (unknown owner) so
            // callers keep the existing attribution. Fresh resolutions
            // always match (same state), so this only fires for stale
            // stored/synced entries.
            .filter(|endpoint| {
                resolution.egress_ifindex <= 0
                    || endpoint.logical_ifindex == resolution.egress_ifindex
            })
            .map(|endpoint| endpoint.redundancy_group.max(0))
            .unwrap_or_default();
    }
    owner_rg_for_flow(forwarding, resolution.egress_ifindex)
}

pub(in crate::afxdp) fn enforce_ha_resolution(
    forwarding: &ForwardingState,
    ha_state: &Arc<ArcSwap<BTreeMap<i32, HAGroupRuntime>>>,
    resolution: ForwardingResolution,
) -> ForwardingResolution {
    enforce_ha_resolution_at(
        forwarding,
        ha_state,
        monotonic_nanos() / 1_000_000_000,
        resolution,
    )
}

pub(in crate::afxdp) fn enforce_ha_resolution_at(
    forwarding: &ForwardingState,
    ha_state: &Arc<ArcSwap<BTreeMap<i32, HAGroupRuntime>>>,
    now_secs: u64,
    resolution: ForwardingResolution,
) -> ForwardingResolution {
    let state = ha_state.load();
    enforce_ha_resolution_snapshot(forwarding, state.as_ref(), now_secs, resolution)
}

pub(in crate::afxdp) fn enforce_ha_resolution_snapshot(
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    now_secs: u64,
    resolution: ForwardingResolution,
) -> ForwardingResolution {
    if !matches!(
        resolution.disposition,
        ForwardingDisposition::ForwardCandidate
            | ForwardingDisposition::MissingNeighbor
            | ForwardingDisposition::LocalDelivery
    ) {
        return resolution;
    }
    // An EMPTY ha_state means "this box is not clustered", so host-destined
    // traffic is not gated on redundancy-group ownership. That reading is a
    // CONTRACT, not an inference: the Go manager drives the map empty on purpose
    // for a standalone node (clearHelperHAStateLocked), and the sibling gate
    // below depends on it — a standalone node whose map was non-empty would mark
    // every transit ForwardCandidate HAInactive and drop it, the #1928 outage.
    //
    // #7465 asked whether a CLUSTERED node can reach this branch, i.e. be
    // forwarding while its inventory is still empty. Recording the answer so the
    // next reader does not re-derive the theory from the issue title:
    //
    //   NOT reachable — the deferred-XSK-startup resume path in
    //   manager_compile.go. It looks like a candidate because it publishes a
    //   snapshot without an HA publish, but `pendingXSKStartup` requires
    //   `m.publishedSnapshot != 0`, and resetAfterHelperGoneLocked zeroes that
    //   on BOTH the crash-reap and explicit-stop paths (and nils m.proc, which
    //   independently falsifies the same condition). On a clustered node the
    //   only way to set it is the normal publish path, which runs
    //   refreshHAStateFromMapsLocked + syncHAStateLocked — both fail-closed —
    //   BEFORE it arms. So when the deferred branch runs, the live helper is
    //   already holding an inventory and the deferral cannot empty it.
    //
    //   REACHABLE — an ordinary apply failure. Arming does not consult the
    //   inventory: desiredForwardingArmedLocked returns true on a clustered node
    //   whenever any RG with ID>0 is configured, and the 1 Hz poll calls
    //   syncDesiredForwardingStateLocked unconditionally while the HA publish
    //   above it is gated on an active signature plus a 2s hold and a 5s
    //   throttle. An apply that fails between the snapshot publish and
    //   syncHAStateLocked does NOT disarm or stop the helper (#5679 — the
    //   daemon records a deferred commit error and continues), so the poll then
    //   arms a helper that has never been told its inventory.
    //
    // That window is closed on the GO side, in syncDesiredForwardingStateLocked,
    // which refuses to arm a clustered helper with no successful
    // update_ha_state. It is closed there rather than here because the defect is
    // the arm/publish ordering, not the representation: making the empty map
    // tri-state would refine a signal the arm path never reads.
    if resolution.disposition == ForwardingDisposition::LocalDelivery && ha_state.is_empty() {
        return resolution;
    }
    let owner_rg_id = owner_rg_for_resolution(forwarding, resolution);
    if owner_rg_id <= 0 {
        // In cluster mode, rg=0 on a ForwardCandidate to an egress interface
        // means the forwarding snapshot predates the RETH RG propagation fix.
        // Treat as invalid (force re-resolution through the slow path) rather
        // than "always active" which would let stale cached entries bypass
        // HA checks after RG failover.
        if resolution.disposition != ForwardingDisposition::LocalDelivery
            && !ha_state.is_empty()
            && resolution.egress_ifindex > 0
        {
            return ForwardingResolution {
                disposition: ForwardingDisposition::HAInactive,
                ..resolution
            };
        }
        return resolution;
    }
    let Some(group) = ha_state.get(&owner_rg_id) else {
        return ForwardingResolution {
            disposition: ForwardingDisposition::HAInactive,
            ..resolution
        };
    };
    if !group.is_forwarding_active(now_secs) {
        return ForwardingResolution {
            disposition: ForwardingDisposition::HAInactive,
            ..resolution
        };
    }
    resolution
}

pub(in crate::afxdp) fn cached_flow_decision_valid(
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    now_secs: u64,
    cached_owner_rg_id: i32,
    fabric_ingress: bool,
    target_ip: IpAddr,
    // #9752: the session's installing table (None = default). Both lookups
    // below resolve in it so validation judges the X-table candidate.
    install_table: Option<&str>,
    resolution: ForwardingResolution,
) -> bool {
    if enforce_ha_resolution_snapshot(forwarding, ha_state, now_secs, resolution) != resolution {
        return false;
    }
    // RG-stamped redirect hits are the common split-RG cache case. Once the
    // cached owner RG becomes locally active again, invalidate immediately and
    // let the slow path recompute the current local/fabric decision instead of
    // taking a neighbor-map lock on every cache hit.
    if cached_owner_rg_id > 0
        && ha_state
            .get(&cached_owner_rg_id)
            .is_some_and(|group| group.is_forwarding_active(now_secs))
        && (resolution.disposition == ForwardingDisposition::FabricRedirect || fabric_ingress)
    {
        return false;
    }
    if resolution.disposition == ForwardingDisposition::FabricRedirect {
        let local_resolution = enforce_ha_resolution_snapshot(
            forwarding,
            ha_state,
            now_secs,
            match install_table {
                // #9752: same table rule as `prefer_local` (non-flow lookup:
                // existing per-destination hash semantics preserved).
                Some(table) => super::lookup_forwarding_resolution_in_table_with_dynamic(
                    forwarding,
                    dynamic_neighbors,
                    target_ip,
                    Some(table),
                ),
                None => lookup_forwarding_resolution_with_dynamic(
                    forwarding, dynamic_neighbors, target_ip,
                ),
            },
        );
        let local_owner_rg = owner_rg_for_resolution(forwarding, local_resolution);
        let local_egress_is_fabric = local_resolution.egress_ifindex > 0
            && ingress_is_fabric(forwarding, local_resolution.egress_ifindex);
        if matches!(
            local_resolution.disposition,
            ForwardingDisposition::ForwardCandidate | ForwardingDisposition::MissingNeighbor
        ) && local_owner_rg > 0
            && !local_egress_is_fabric
        {
            return false;
        }
    }
    if fabric_ingress
        && prefer_local_forward_candidate_for_fabric_ingress(
            forwarding,
            ha_state,
            dynamic_neighbors,
            now_secs,
            true,
            target_ip,
            install_table,
            resolution,
        ) != resolution
    {
        return false;
    }
    true
}

pub(in crate::afxdp) fn finalize_new_flow_ha_resolution(
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    now_secs: u64,
    resolution: ForwardingResolution,
    fabric_ingress: bool,
    ingress_ifindex: i32,
    ingress_zone: u16,
    ha_startup_grace_until_secs: u64,
) -> ForwardingResolution {
    let enforced = super::session_glue::enforce_session_ha_resolution(
        forwarding,
        ha_state,
        now_secs,
        resolution,
        ingress_ifindex,
        ha_startup_grace_until_secs,
    );
    if fabric_ingress && enforced.disposition == ForwardingDisposition::HAInactive {
        return resolution;
    }
    super::session_glue::redirect_session_via_fabric_if_needed(
        forwarding,
        enforced,
        fabric_ingress,
        ingress_zone,
    )
}

pub(in crate::afxdp) fn demoted_owner_rgs(
    previous: &BTreeMap<i32, HAGroupRuntime>,
    current: &BTreeMap<i32, HAGroupRuntime>,
) -> Vec<i32> {
    previous
        .iter()
        .filter_map(|(rg_id, old)| {
            let became_inactive = match current.get(rg_id) {
                Some(new) => old.active && !new.active,
                None => old.active,
            };
            became_inactive.then_some(*rg_id)
        })
        .collect()
}

pub(in crate::afxdp) fn activated_owner_rgs(
    previous: &BTreeMap<i32, HAGroupRuntime>,
    current: &BTreeMap<i32, HAGroupRuntime>,
) -> Vec<i32> {
    current
        .iter()
        .filter_map(|(rg_id, new)| {
            let became_active = match previous.get(rg_id) {
                Some(old) => !old.active && new.active,
                None => new.active,
            };
            became_active.then_some(*rg_id)
        })
        .collect()
}
