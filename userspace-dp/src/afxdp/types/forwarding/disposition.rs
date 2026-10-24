// Forwarding disposition / resolution types split from
// forwarding.rs (#16209): ForwardingDisposition, RouteIdentity,
// ForwardingLookupResult, and ForwardingResolution. Pure code
// motion behind `forwarding/mod.rs`'s `use forwarding::*` glob;
// zero layout or access-site change.
// Visibility bill: no widening. ForwardingDisposition and
// ForwardingResolution keep `pub(crate)`; RouteIdentity and
// ForwardingLookupResult keep `pub(crate)` field visibility.

use super::super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ForwardingDisposition {
    LocalDelivery,
    ForwardCandidate,
    FabricRedirect,
    HAInactive,
    /// #15742: cluster Null0 terminal whose would-be egress RG is
    /// peer-owned. Demoted in HA enforcement (not at lookup, which
    /// has no HA map); fabric helpers convert it exactly like
    /// HAInactive. Distinct so operator discard/reject stays a drop
    /// and HAInactive-specific handling is untouched.
    ClusterTerminalHAInactive,
    PolicyDenied,
    NoRoute,
    MissingNeighbor,
    DiscardRoute,
    RejectRoute,
    NextTableUnsupported,
    TableUnavailable,
}

impl ForwardingDisposition {
    /// Whether this disposition can be stored in the per-worker flow cache.
    ///
    /// Forwarding decisions use config/FIB generation, RG epoch, and
    /// neighbor-epoch fencing. Policy-denied and discard-route drops are also
    /// cacheable: those entries carry the same config/FIB fences and a short
    /// expiry so neither a policy change nor a route change can preserve a
    /// stale denial.
    ///
    /// `NoRoute`, `MissingNeighbor`, `HAInactive`, `NextTableUnsupported`,
    /// and `TableUnavailable` remain uncached: they are transient, ownership
    /// dependent, or otherwise not worth persisting. `LocalDelivery` is not a
    /// forwarded flow and has no rewrite descriptor.
    pub(in crate::afxdp) fn is_cacheable(self) -> bool {
        matches!(
            self,
            ForwardingDisposition::ForwardCandidate
                | ForwardingDisposition::FabricRedirect
                | ForwardingDisposition::PolicyDenied
                | ForwardingDisposition::DiscardRoute
        )
    }

    /// Whether a frame with this disposition is eligible for the generic
    /// kernel slow-path reinjection (the filtered wrapper
    /// `maybe_reinject_slow_path` and the trailing chokepoint at
    /// `poll_descriptor::poll_binding_process_descriptor`).
    ///
    /// This is the single source of truth for the slow-path allow-list
    /// (#1913). A disposition that is NOT eligible must be dropped, NOT
    /// handed to the kernel FIB.
    ///
    /// Eligible (reinject to the kernel slow path):
    ///   - `LocalDelivery`: terminate at the kernel stack (or a local
    ///     tunnel-delivery channel) — this is the intended destination.
    ///   - `NoRoute`: userspace has no route, but the kernel FIB may
    ///     (e.g. a route the helper has not yet learned); let the kernel
    ///     try, rate-limited. #7480: eligibility here is necessary but no
    ///     longer sufficient — the NoRoute arm in `poll_descriptor`
    ///     adjudicates the computable zone pair first and downgrades a
    ///     denied frame to `PolicyDenied`, so only a POLICY-PERMITTED
    ///     NoRoute frame reaches the kernel. The disposition stays eligible
    ///     because #7409's importer bounds the FIB divergence without
    ///     closing it; dropping it outright would black-hole every learned
    ///     destination between snapshot pushes.
    ///   - `MissingNeighbor`: route exists, ARP/NDP unresolved; the kernel
    ///     can resolve and forward (the userspace prober runs in parallel).
    ///

    /// NOT eligible (drop — do NOT reinject):
    ///   - `PolicyDenied`: a zone-policy DENY. Reinjecting would silently
    ///     bypass the firewall by forwarding the packet via the kernel FIB
    ///     (the bug #1913 fixes).
    ///   - `HAInactive`: the owning RG is not active on this node;
    ///     reinjecting hands the packet to the standby's kernel FIB
    ///     (duplicate/asymmetric forwarding, wrong-node plaintext send).
    ///   - `DiscardRoute`: matched a discard/reject route whose entire
    ///     purpose is to drop the traffic.
    ///   - `NextTableUnsupported`: an inter-VRF next-table chain the helper
    ///     cannot resolve — deeper than `MAX_NEXT_TABLE_DEPTH`, or a cycle
    ///     (`fib.rs`). Reinjecting handed it to the kernel FIB, which forwards
    ///     with no zone policy, session, NAT or screen (#6664).
    ///
    ///     Unlike `NoRoute` this is NOT transient, so the #7409 "do not
    ///     black-hole a destination the kernel can still reach" argument does
    ///     not apply: no FIB refresh resolves an over-deep or cyclic chain, so
    ///     delegating it was a STANDING policy bypass for that config rather
    ///     than a window. Failing closed matches the posture this codebase
    ///     already takes when the dataplane cannot represent a config.
    ///
    ///     This is defense-in-depth, not a live exposure fix, and the
    ///     distinction is worth stating honestly: no config that reaches the
    ///     dataplane can currently produce this disposition. Every
    ///     `next_table`-bearing route in the FIB lives in the GLOBAL table --
    ///     the only two producers are the global static-route pass and the
    ///     synthetic ip-rule leak pass, and a next-table authored UNDER a
    ///     routing-instance is hard-rejected at commit (#5830) and dropped
    ///     from the snapshot even on the tolerant load / peer-sync path
    ///     (`pkg/dataplane/userspace/routes.go`). So the recursion is at most
    ///     one hop, global -> instance, and it terminates there: neither the
    ///     depth cap nor a cycle is reachable. That safety is an EMERGENT
    ///     property of two guards in a different language and package, not an
    ///     invariant this predicate enforces -- a third `next_table` producer,
    ///     or one relaxed guard, would silently reopen the bypass. Fail closed
    ///     here so the dataplane's own posture is correct on its own terms.
    ///   - `TableUnavailable`: the session's installing table cannot be
    ///     resolved — there is no table the kernel could correctly forward
    ///     it in, so unlike `NoRoute` there is nothing to delegate.
    ///   - `ForwardCandidate` / `FabricRedirect`: handled by the forward /
    ///     fabric path, never the generic slow path. Some callers bypass
    ///     this predicate on purpose; the authoritative enumeration lives
    ///     on `maybe_reinject_slow_path_from_frame` and is pinned by
    ///     `raw_reinject_primitive_caller_set_is_pinned_7480`. Deliberately
    ///     NOT restated here — this comment carried a stale count of its
    ///     own until #7480, which is what a restatement does. (#1946: `FabricRedirect`
    ///     with no fabric XSK binding, or whose build/enqueue failed, is
    ///     dropped fail-closed + counted, never reinjected — a
    ///     cross-chassis L2 redirect is not kernel-FIB routable.)
    pub(in crate::afxdp) fn is_slow_path_eligible(self) -> bool {
        matches!(
            self,
            ForwardingDisposition::LocalDelivery
                | ForwardingDisposition::NoRoute
                | ForwardingDisposition::MissingNeighbor
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct RouteIdentity {
    pub(crate) domain: u32,
    pub(crate) table: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ForwardingLookupResult {
    pub(crate) resolution: ForwardingResolution,
    pub(crate) selected_route: Option<RouteIdentity>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ForwardingResolution {
    pub(crate) disposition: ForwardingDisposition,
    pub(crate) local_ifindex: i32,
    pub(crate) egress_ifindex: i32,
    pub(crate) tx_ifindex: i32,
    pub(crate) tunnel_endpoint_id: u16,
    pub(crate) next_hop: Option<IpAddr>,
    pub(crate) neighbor_mac: Option<[u8; 6]>,
    pub(crate) src_mac: Option<[u8; 6]>,
    pub(crate) tx_vlan_id: u16,
    /// #15742: for a ClusterTerminalHAInactive resolution, the gateway
    /// ifindex of the forwarding row that WOULD have carried this
    /// destination (selected at lookup before the terminal zeroed the
    /// egress). HA enforcement attributes its RG to decide demotion.
    /// Zero on every other resolution.
    pub(crate) source_ifindex: i32,
    /// Selected route's L3 MTU. Zero means no route-specific constraint.
    pub(crate) route_mtu: u32,
    /// Outer transport route's MTU for native tunnel resolutions. Kept
    /// distinct from `route_mtu`, which constrains the inner/overlay packet.
    pub(crate) transport_route_mtu: u32,
}

impl ForwardingResolution {
    pub(in crate::afxdp) fn status(
        self,
        debug: Option<&ResolutionDebug>,
        forwarding: &ForwardingState,
    ) -> PacketResolution {
        PacketResolution {
            disposition: match self.disposition {
                ForwardingDisposition::LocalDelivery => "local_delivery",
                ForwardingDisposition::ForwardCandidate => "forward_candidate",
                ForwardingDisposition::FabricRedirect => "fabric_redirect",
                ForwardingDisposition::HAInactive | ForwardingDisposition::ClusterTerminalHAInactive => "ha_inactive",
                ForwardingDisposition::PolicyDenied => "policy_denied",
                ForwardingDisposition::NoRoute => "no_route",
                ForwardingDisposition::MissingNeighbor => "missing_neighbor",
                ForwardingDisposition::DiscardRoute => "discard_route",
                ForwardingDisposition::RejectRoute => "reject_route",
                ForwardingDisposition::NextTableUnsupported => "next_table_unsupported",
                ForwardingDisposition::TableUnavailable => "table_unavailable",
            }
            .to_string(),
            local_ifindex: self.local_ifindex,
            egress_ifindex: self.egress_ifindex,
            ingress_ifindex: debug.map(|d| d.ingress_ifindex).unwrap_or_default(),
            next_hop: self.next_hop.map(|ip| ip.to_string()).unwrap_or_default(),
            neighbor_mac: self.neighbor_mac.map(format_mac).unwrap_or_default(),
            src_ip: debug
                .and_then(|d| d.src_ip)
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
            dst_ip: debug
                .and_then(|d| d.dst_ip)
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
            src_port: debug.map(|d| d.src_port).unwrap_or_default(),
            dst_port: debug.map(|d| d.dst_port).unwrap_or_default(),
            from_zone: debug
                .and_then(|d| d.from_zone)
                .and_then(|id| forwarding.zone_id_to_name.get(&id).cloned())
                .unwrap_or_default(),
            to_zone: debug
                .and_then(|d| d.to_zone)
                .and_then(|id| forwarding.zone_id_to_name.get(&id).cloned())
                .unwrap_or_default(),
        }
    }
}
