//! #5650: HA redundancy-group resolution enforcement and owner-RG attribution
//! for the forwarding path (active/inactive disposition, cached-decision
//! validity, new-flow finalization, demoted/activated RG sets). Pure
//! code-motion split out of `forwarding/mod.rs` (behavior-identical).

use super::*;

pub(in crate::afxdp) fn owner_rg_for_flow(
    forwarding: &ForwardingState,
    egress_ifindex: i32,
) -> i32 {
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

/// #15742: would-be egress RG peer-owned test for a cluster-terminal
/// resolution. The lookup stamps the selected forwarding row's
/// gateway ifindex (select_source_ifindex_*) before zeroing the
/// egress; if that egress's RG is >0 and not forwarding-active
/// (peer-owned or unknown on a clustered node, mirroring the
/// ForwardCandidate gate), the terminal demotes to fabric redirect.
/// This is destination-dependent: the selected row is ECMP/LPM
/// aware, unlike a static scan of the table's default rows.
pub(in crate::afxdp) fn cluster_terminal_peer_owned_egress_rg(
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    now_secs: u64,
    resolution: &ForwardingResolution,
) -> bool {
    if resolution.source_ifindex <= 0 {
        return false;
    }
    let rg = owner_rg_for_flow(forwarding, resolution.source_ifindex);
    rg > 0
        && ha_state
            .get(&rg)
            .is_none_or(|g| !g.is_forwarding_active(now_secs))
}

/// #16216: is this DiscardRoute a demoted cluster-terminal row whose
/// would-be egress RG is peer-owned RIGHT NOW? The demotion in
/// `enforce_ha_resolution_snapshot` preserves the FIB's
/// `source_ifindex` stamp, so a row demoted while the attribution
/// missed (no live member at lookup time) can still be rescued once
/// the packet reaches a fabric converter: if the stamped egress's RG
/// is not forwarding-active locally, the destination is served by
/// the peer and the packet must cross the fabric instead of dropping.
/// Operator discards never carry the stamp (`source_ifindex == 0`)
/// and never rescue.
pub(in crate::afxdp) fn discard_route_is_cluster_terminal_peer_owned(
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    now_secs: u64,
    resolution: &ForwardingResolution,
) -> bool {
    resolution.disposition == ForwardingDisposition::DiscardRoute
        && cluster_terminal_peer_owned_egress_rg(forwarding, ha_state, now_secs, resolution)
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
    // #15742: a cluster-terminal resolution carries no egress (the FIB
    // zeroed it), so the ordinary owner attribution below cannot run.
    // Demote it only when the same table holds a forwarding sibling at
    // the terminal's prefix whose egress RG is peer-owned; otherwise
    // (locally-owned, standalone, or no sibling) it stays the terminal
    // drop the lookup selected. Operator discard/reject rows never
    // reach here: only cluster_terminal rows produce this disposition.
    //
    // #16216: the demotion must keep the cluster-terminal provenance
    // (`source_ifindex`, the would-be egress the FIB stamped before
    // zeroing the egress). The pre-fix demotion zeroed it with the
    // MTUs, so the stranded DiscardRoute was indistinguishable from an
    // operator discard and no later stage could rescue it: on the
    // split node the attribution can miss at lookup time (no live
    // member, suppressed connected prefix), yet the packet must still
    // cross the fabric to the owner that now serves the destination.
    // `source_ifindex` is consulted only on the DiscardRoute shape and
    // only by the fabric-rescue converters, so operator discards
    // (which never carry the stamp) are bit-identical.
    if resolution.disposition == ForwardingDisposition::ClusterTerminalHAInactive {
        if ha_state.is_empty() {
            return resolution;
        }
        return match cluster_terminal_peer_owned_egress_rg(
            forwarding,
            ha_state,
            now_secs,
            &resolution,
        ) {
            true => resolution,
            false => ForwardingResolution {
                disposition: ForwardingDisposition::DiscardRoute,
                route_mtu: 0,
                transport_route_mtu: 0,
                ..resolution
            },
        };
    }
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
                route_mtu: 0,
                transport_route_mtu: 0,
                ..resolution
            };
        }
        return resolution;
    }
    let Some(group) = ha_state.get(&owner_rg_id) else {
        return ForwardingResolution {
            disposition: ForwardingDisposition::HAInactive,
            route_mtu: 0,
            transport_route_mtu: 0,
            ..resolution
        };
    };
    if !group.is_forwarding_active(now_secs) {
        return ForwardingResolution {
            disposition: ForwardingDisposition::HAInactive,
            route_mtu: 0,
            transport_route_mtu: 0,
            ..resolution
        };
    }
    // #13980: the endpoint RG owns the tunnel source, but it does not
    // necessarily own the physical egress used for outer encapsulation. Resolve
    // the endpoint's outer route through the shared tunnel lookup and gate the
    // outer L3 egress RG as well. Use its egress_ifindex (not tx_ifindex,
    // which can be a VLAN parent) and keep this peer-local computation out of
    // session/wire metadata. This path runs only for tunnel TX candidates.
    if resolution.tunnel_endpoint_id != 0
        && matches!(
            resolution.disposition,
            ForwardingDisposition::ForwardCandidate | ForwardingDisposition::MissingNeighbor
        )
    {
        let Some(endpoint) = forwarding
            .tunnel_endpoints
            .get(&resolution.tunnel_endpoint_id)
        else {
            return ForwardingResolution {
                disposition: ForwardingDisposition::HAInactive,
                route_mtu: 0,
                transport_route_mtu: 0,
                ..resolution
            };
        };
        // GRE/ip6gre have a fixed endpoint destination, so use the L3 egress
        // RG derived once when this forwarding snapshot was built. WireGuard
        // selects an outer destination per peer; its materialized resolution
        // carries that route's next-hop and transport table.
        let outer_rg_id = if endpoint.mode == "wireguard" {
            let Some(next_hop) = resolution.next_hop else {
                return ForwardingResolution {
                    disposition: ForwardingDisposition::HAInactive,
                    route_mtu: 0,
                    transport_route_mtu: 0,
                    ..resolution
                };
            };
            match forwarding
                .wireguard_peer_outer_egress_rgs
                .get(&(resolution.tunnel_endpoint_id, next_hop))
                .copied()
            {
                Some(rg_id) if rg_id >= 0 => Some(rg_id),
                Some(_) => None,
                None => {
                    // Runtime-learned/roaming endpoints are absent from the
                    // config-derived index; resolve only this cold fallback.
                    let outer_egress_ifindex = super::lookup_forwarding_resolution_inner(
                        forwarding,
                        None,
                        next_hop,
                        Some(&endpoint.transport_table),
                    )
                    .resolution
                    .egress_ifindex;
                    forwarding
                        .egress
                        .get(&outer_egress_ifindex)
                        .map(|egress| egress.redundancy_group.max(0))
                }
            }
        } else {
            forwarding
                .tunnel_outer_egress_rgs
                .get(&resolution.tunnel_endpoint_id)
                .copied()
        };
        let Some(outer_rg_id) = outer_rg_id else {
            return ForwardingResolution {
                disposition: ForwardingDisposition::HAInactive,
                route_mtu: 0,
                transport_route_mtu: 0,
                ..resolution
            };
        };
        // A standalone node has no HA inventory and does not gate host egress.
        // Clustered non-RETH underlays (RG 0) also need no ownership gate;
        // positive but absent/inactive RETH groups fail closed.
        if outer_rg_id > 0
            && !ha_state.is_empty()
            && !ha_state
                .get(&outer_rg_id)
                .is_some_and(|group| group.is_forwarding_active(now_secs))
        {
            return ForwardingResolution {
                disposition: ForwardingDisposition::HAInactive,
                route_mtu: 0,
                transport_route_mtu: 0,
                ..resolution
            };
        }
    }
    resolution
}

/// #16220: why a cached decision failed revalidation — the sub-arm the
/// flow-cache post-hit eviction attributes to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::afxdp) enum CachedDecisionInvalid {
    EnforceChanged,
    OwnerActiveRedirect,
    FabricLocalWins,
    FabricIngressLocalWins,
    /// #16220: FabricLocalWins where the local resolution's owner RG is
    /// the SAME as the cached entry's owner (vs a different local owner).
    FabricLocalWinsSameOwner,
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
    cached_flow_decision_invalid_reason(
        forwarding,
        ha_state,
        dynamic_neighbors,
        now_secs,
        cached_owner_rg_id,
        fabric_ingress,
        target_ip,
        install_table,
        resolution,
    )
    .is_none()
}

/// #16222: per-flow twin of `cached_flow_decision_invalid_reason` — the
/// production hit path judges the cached redirect against the SAME
/// resolution the session path produces for this flow (per-flow ECMP
/// hash over the 5-tuple; `target_ip` is already the NAT-translated
/// target). `fabric_link_ingress` is the physical parent/overlay arrival
/// identity, OR-ed into the ingress flag for the retention decision:
/// the session path retains the redirect on fabric-link ingress
/// (resolve.rs), so revalidation must not supersede it there either.
/// The destination-only entry point remains for flow-less fixtures only.
#[allow(clippy::too_many_arguments)]
pub(in crate::afxdp) fn cached_flow_decision_invalid_reason_for_flow(
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    now_secs: u64,
    cached_owner_rg_id: i32,
    fabric_ingress: bool,
    fabric_link_ingress: bool,
    flow_key: Option<&crate::session::SessionKey>,
    target_ip: IpAddr,
    install_table: Option<&str>,
    resolution: ForwardingResolution,
) -> Option<CachedDecisionInvalid> {
    cached_flow_decision_invalid_reason_inner(
        forwarding,
        ha_state,
        dynamic_neighbors,
        now_secs,
        cached_owner_rg_id,
        fabric_ingress || fabric_link_ingress,
        flow_key,
        target_ip,
        install_table,
        resolution,
    )
}

#[allow(clippy::too_many_arguments)]
pub(in crate::afxdp) fn cached_flow_decision_invalid_reason(
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    now_secs: u64,
    cached_owner_rg_id: i32,
    fabric_ingress: bool,
    target_ip: IpAddr,
    install_table: Option<&str>,
    resolution: ForwardingResolution,
) -> Option<CachedDecisionInvalid> {
    cached_flow_decision_invalid_reason_inner(
        forwarding,
        ha_state,
        dynamic_neighbors,
        now_secs,
        cached_owner_rg_id,
        fabric_ingress,
        None,
        target_ip,
        install_table,
        resolution,
    )
}

#[allow(clippy::too_many_arguments)]
fn cached_flow_decision_invalid_reason_inner(
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    now_secs: u64,
    cached_owner_rg_id: i32,
    fabric_ingress: bool,
    flow_key: Option<&crate::session::SessionKey>,
    target_ip: IpAddr,
    install_table: Option<&str>,
    resolution: ForwardingResolution,
) -> Option<CachedDecisionInvalid> {
    if enforce_ha_resolution_snapshot(forwarding, ha_state, now_secs, resolution) != resolution {
        return Some(CachedDecisionInvalid::EnforceChanged);
    }
    // RG-stamped redirect hits are the common split-RG cache case. Once the
    // cached owner RG becomes locally active again, invalidate immediately and
    // let the slow path recompute the current local/fabric decision instead of
    // taking a neighbor-map lock on every cache hit.
    if cached_owner_rg_id > 0
        && fabric_ingress
        && ha_state
            .get(&cached_owner_rg_id)
            .is_some_and(|group| group.is_forwarding_active(now_secs))
        && resolution.disposition == ForwardingDisposition::FabricRedirect
    {
        return Some(CachedDecisionInvalid::OwnerActiveRedirect);
    }
    if resolution.disposition == ForwardingDisposition::FabricRedirect {
        // #16222: judge the cached redirect against the SAME resolution
        // the session path produces for this flow. With a flow key the
        // local candidate uses the per-flow ECMP hash
        // (`lookup_..._for_flow*`, fib.rs #2734); without one it falls
        // back to the destination-only hash (flow-less fixtures only).
        // `target_ip` is already the NAT-translated target
        // (`resolution_target_for_session` at the caller).
        let local_lookup = match (install_table, flow_key) {
            (Some(table), Some(key)) => {
                super::lookup_forwarding_resolution_with_dynamic_for_flow_in_table(
                    forwarding,
                    dynamic_neighbors,
                    target_ip,
                    key,
                    table,
                )
            }
            (Some(table), None) => super::lookup_forwarding_resolution_in_table_with_dynamic(
                forwarding,
                dynamic_neighbors,
                target_ip,
                Some(table),
            ),
            (None, Some(key)) => super::lookup_forwarding_resolution_with_dynamic_for_flow(
                forwarding,
                dynamic_neighbors,
                target_ip,
                key,
            ),
            (None, None) => lookup_forwarding_resolution_with_dynamic(
                forwarding,
                dynamic_neighbors,
                target_ip,
            ),
        };
        let local_resolution =
            enforce_ha_resolution_snapshot(forwarding, ha_state, now_secs, local_lookup.resolution);
        let local_owner_rg = owner_rg_for_resolution(forwarding, local_resolution);
        let local_egress_is_fabric = local_resolution.egress_ifindex > 0
            && ingress_is_fabric(forwarding, local_resolution.egress_ifindex);
        if matches!(
            local_resolution.disposition,
            ForwardingDisposition::ForwardCandidate | ForwardingDisposition::MissingNeighbor
        ) && local_owner_rg > 0
            && !local_egress_is_fabric
        {
            // #16222: a fabric-ingress redirect whose cached owner is NOT
            // the local egress RG was seeded for the split-RG shape: the
            // packet crossed to this node precisely because the egress
            // RG is peer-owned at session resolution time, and the
            // session path (per-flow + fabric converters in resolve.rs)
            // retains the redirect on fabric-link ingress. A local
            // candidate owned by a DIFFERENT RG than the cached stamp
            // therefore does not supersede it on fabric ingress — the
            // two owner attributions name different legs (ingress/LAN
            // RG vs WAN egress RG), not alternatives for this packet.
            // Only a SAME-owner local candidate on fabric ingress (the
            // owner is now local, failback) or any local candidate on
            // direct ingress with a different owner retires it.
            if fabric_ingress && local_owner_rg != cached_owner_rg_id {
                // Fall through to the prefer-local check below, which
                // re-derives with the same per-flow candidate semantics
                // via the resolution comparison; do not evict here.
            } else if local_owner_rg == cached_owner_rg_id && !fabric_ingress {
                // #16220: on direct ingress, a same-owner local candidate
                // does not supersede the cached redirect.
                return None;
            } else {
                return Some(if local_owner_rg == cached_owner_rg_id {
                    CachedDecisionInvalid::FabricLocalWinsSameOwner
                } else {
                    CachedDecisionInvalid::FabricLocalWins
                });
            }
        }
    }
    // #16222: the prefer-local probe below is the generic fabric-ingress
    // supersession for non-redirect resolutions. For a FabricRedirect it
    // would re-derive the same local candidate the block above already
    // judged and evict as FabricIngressLocalWins even when that block
    // deliberately retained the redirect (different-owner fabric
    // ingress). The redirect arm is fully decided above; skip the probe
    // for it so the retention is not undone under a second arm name.
    if fabric_ingress
        && resolution.disposition != ForwardingDisposition::FabricRedirect
        && prefer_local_forward_candidate_for_fabric_ingress_for_flow(
            forwarding,
            ha_state,
            dynamic_neighbors,
            now_secs,
            true,
            flow_key,
            target_ip,
            install_table,
            resolution,
        ) != resolution
    {
        return Some(CachedDecisionInvalid::FabricIngressLocalWins);
    }
    None
}

pub(in crate::afxdp) fn finalize_new_flow_ha_resolution(
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    now_secs: u64,
    resolution: ForwardingResolution,
    // `fabric_ingress` retains the validated stamp/overlay semantic used by
    // the existing HA resolution behavior. `fabric_link_ingress` is the
    // physical parent-or-overlay arrival semantic used only by anti-loop
    // redirect suppression.
    fabric_ingress: bool,
    fabric_link_ingress: bool,
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
        // Preserve the long-standing plain/endpoint-owner fabric-ingress
        // exception, but do not turn the new outer-egress-RG failure back into
        // a forward. The endpoint RG is already active in this case, so
        // HAInactive came from the tunnel's outer egress gate.
        let endpoint_rg_id = owner_rg_for_resolution(forwarding, resolution);
        if resolution.tunnel_endpoint_id != 0
            && endpoint_rg_id > 0
            && ha_state
                .get(&endpoint_rg_id)
                .is_some_and(|group| group.is_forwarding_active(now_secs))
        {
            return enforced;
        }
        return resolution;
    }
    super::session_glue::redirect_session_via_fabric_if_needed(
        forwarding,
        enforced,
        fabric_link_ingress,
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
