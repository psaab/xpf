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
/// #16269: is this DiscardRoute's cluster-terminal origin CERTAIN —
/// the row was demoted from `ClusterTerminalHAInactive` (or still
/// carries that spelling) and its would-be egress RG is locally
/// forwarding-active RIGHT NOW, so on THIS node the row must forward
/// to the WAN instead of dropping? Origin is certain only when the
/// demotion preserved the FIB's `source_ifindex` provenance stamp;
/// `source_ifindex == 0` means the stamp is absent (operator discard,
/// or a row shape the FIB could not attribute) and the answer is
/// always false — fail-closed, never a rescue guess. This is the
/// takeover-side twin of `discard_route_is_cluster_terminal_peer_owned`:
/// that one asks "is the would-be egress peer-owned NOW" (the split
/// node's fabric crossing); this one asks "is it LOCALLY active NOW"
/// (the new owner's fabric-ingress cache hit). A fabric-ingress
/// cached DiscardRoute answering true here is stale by construction:
/// it was demoted while this node did not own the egress RG, and the
/// RG has since activated locally, so the slow path re-resolves it to
/// the local WAN ForwardCandidate.
pub(in crate::afxdp) fn discard_route_cluster_terminal_now_local(
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    now_secs: u64,
    resolution: &ForwardingResolution,
) -> bool {
    if resolution.disposition != ForwardingDisposition::DiscardRoute
        || resolution.source_ifindex <= 0
    {
        return false;
    }
    let rg = owner_rg_for_flow(forwarding, resolution.source_ifindex);
    rg > 0
        && ha_state
            .get(&rg)
            .is_some_and(|g| g.is_forwarding_active(now_secs))
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
    /// #16269: a fabric-ingress cached DiscardRoute whose cluster-
    /// terminal origin is certain (provenance stamp preserved) and
    /// whose would-be egress RG is now locally forwarding-active:
    /// the entry was demoted while this node did not own the RG and
    /// is stale at takeover. The slow path re-resolves it locally.
    FabricIngressDiscardNowLocal,
    /// #16270 (cache supersession): a cached ForwardCandidate whose
    /// egress RG is known (>0) but is NOT forwarding-active locally
    /// right now — the RG left this node (failover) or was never
    /// active here, so serving the stored decision transmits on a
    /// non-owner WAN egress forever. The slow path re-resolves it
    /// (HA enforcement demotes it and the fabric converter redirects
    /// it to the new owner). Guard: only when the egress RG is known
    /// and not active; a locally-active egress (and an unknown /
    /// standalone egress) is never invalidated by this arm.
    ForwardCandidateEgressDeparted,
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
    // #16269: a fabric-ingress cached DiscardRoute whose cluster-
    // terminal origin is certain and whose would-be egress RG is now
    // locally active is stale at takeover: it was demoted while this
    // node did not own the RG. Evict so the slow path re-resolves it
    // to the local WAN ForwardCandidate instead of terminal-dropping
    // every fabric-redirected retransmit on the new owner. Uncertain
    // origin (no provenance stamp) never reaches here — fail-closed.
    if fabric_ingress
        && discard_route_cluster_terminal_now_local(forwarding, ha_state, now_secs, &resolution)
    {
        return Some(CachedDecisionInvalid::FabricIngressDiscardNowLocal);
    }
    // #16270 (cache supersession): a cached ForwardCandidate whose
    // egress RG is known (>0) but is NOT forwarding-active locally
    // right now must not be served locally — its RG has left this
    // node (failover) or was never active here, so the stored
    // decision transmits on a non-owner WAN egress forever (the
    // aged-failover blackhole: fw0 kept WAN-TXing ForwardCandidate
    // egress=14/RG1 tuples after RG1 moved to fw1). This is placed
    // here, deliberately independent of `enforce_ha_resolution_snapshot`
    // above: on the live build that check did NOT evict these
    // entries (enforce_changed stayed 0 post-failover in the cell
    // stats — the stored resolution is re-judged against the same
    // FIB row and the HAInactive demotion did not fire for these
    // cache hits), so the supersession must stand on its own
    // egress-RG test rather than relying on the enforce rewrite.
    // Evict so the slow path re-resolves: HA enforcement demotes
    // the fresh resolution and the fabric converter redirects it
    // to the new owner.
    //
    // Guard (acceptance): only when the egress RG is KNOWN and not
    // active — `owner_rg_for_resolution` > 0 (a real EgressInterface
    // / tunnel-endpoint row names the RG) and that RG is absent
    // from `ha_state` or not forwarding-active. A locally-active
    // egress is bit-identical (the arm never fires), an unknown
    // egress (rg 0: standalone, pre-RETH-propagation, or missing
    // row) is never touched here (the #16220 EnforceChanged arm
    // above owns that clustered-node shape), and an empty HA map
    // (standalone) can never fire because every known RG reads as
    // absent — so the explicit `!ha_state.is_empty()` keeps a
    // standalone node's ForwardCandidates bit-identical too.
    // ForwardCandidate is the only cacheable locally-egressing
    // forward disposition (`from_forward_decision` admits only
    // ForwardCandidate | FabricRedirect; FabricRedirect is judged
    // by the arms below) — MissingNeighbor/LocalDelivery are never
    // cached, so no other disposition needs this arm.
    if resolution.disposition == ForwardingDisposition::ForwardCandidate
        && !ha_state.is_empty()
    {
        let egress_rg = owner_rg_for_resolution(forwarding, resolution);
        if egress_rg > 0
            && !ha_state
                .get(&egress_rg)
                .is_some_and(|group| group.is_forwarding_active(now_secs))
        {
            return Some(CachedDecisionInvalid::ForwardCandidateEgressDeparted);
        }
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
            // #16222 option B (round 2): judge the cached redirect
            // against its OWN stored resolution context — i.e. against
            // the resolution the SESSION path produces for this flow —
            // not against the mere owner inequality. `local_resolution`
            // above IS that per-flow resolution (per-flow ECMP hash over
            // the 5-tuple, NAT-translated target, HA-enforced).
            //
            // A different-owner local candidate supersedes ONLY if it
            // serves the flow locally: the per-flow session resolution
            // for this flow must BE that candidate, i.e. resolving the
            // flow fresh yields a ForwardCandidate/MissingNeighbor that
            // egresses locally (non-fabric egress, owner RG
            // forwarding-active here) INSTEAD of the redirect. That is
            // exactly the condition under which the session path would
            // not have seeded (or would no longer seed) a FabricRedirect
            // for this flow. When the fresh per-flow resolution differs
            // in egress/disposition from what the redirect serves, the
            // candidate is not this flow's serving resolution — the
            // redirect stands.
            //
            // This holds regardless of the arrival spelling: on fw0 the
            // evicting entries are locally-seeded FabricRedirect stamps
            // (owner != WAN RG1) served on LAN/WAN members, so
            // `packet_fabric_ingress == fabric_link_ingress == false`
            // and the round-1 fabric-ingress retention never engaged.
            // The direct-ingress same-owner retention (#16220) is
            // preserved below; a same-owner candidate whose owner is now
            // locally active is the failback case and still supersedes
            // (FabricLocalWinsSameOwner / OwnerActiveRedirect on fabric
            // ingress).
            //
            // Concretely, `serves_flow_locally` requires the per-flow
            // candidate to be the flow's serving resolution: since
            // `local_resolution` is by construction the per-flow
            // resolution for this flow, the serving test reduces to
            // whether a fresh resolution of THIS flow would egress
            // locally under a locally-active owner — which the
            // HA-enforced candidate already guarantees (a peer-owned
            // candidate demotes to HAInactive in
            // `enforce_ha_resolution_snapshot` and never reaches this
            // arm as ForwardCandidate). So a different-owner candidate
            // reaching this arm DOES serve locally *as a route*, and
            // owner inequality alone must not be the eviction trigger:
            // the trigger is whether superseding changes the flow's
            // serving egress. The cached redirect's serving egress is
            // the fabric parent; the candidate's is its local egress.
            // They differ, so the candidate would change where this
            // flow leaves — but only the SESSION path may make that
            // call, and it retains the redirect for this flow's stored
            // context. Hence: a different-owner candidate supersedes
            // only when it serves the flow locally AND the session path
            // would produce it for this flow — which, for a flow whose
            // cached decision is FabricRedirect, it does not (the
            // session path's fabric converters retain the redirect on
            // this stored context). Direct-ingress different-owner
            // eviction is therefore retired for cached redirects whose
            // stored resolution is FabricRedirect; failback remains
            // governed by the same-owner and owner-active arms.
            if local_owner_rg != cached_owner_rg_id && !fabric_ingress {
                // Option B: direct-ingress different-owner candidate
                // does not supersede a cached FabricRedirect judged
                // against its stored resolution context.
            } else if local_owner_rg == cached_owner_rg_id && !fabric_ingress {
                // #16220: on direct ingress, a same-owner local candidate
                // does not supersede the cached redirect.
                return None;
            } else if fabric_ingress && local_owner_rg != cached_owner_rg_id {
                // Round-1 retention kept for genuine fabric ingress:
                // the stamp names the ingress/LAN leg, the candidate
                // the WAN egress leg; not alternatives for this packet.
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
