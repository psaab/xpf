// Forwarding/routing types extracted from afxdp/types/mod.rs (Issue 68.2).
// Includes the forwarding-state aggregator, connected/non-connected
// route entries, egress and tunnel-endpoint descriptors, fabric-link
// descriptor, forwarding disposition + resolution enums, and the
// per-binding lookup table.
//
// Pure relocation. Original `pub(super)` widened to `pub(in crate::afxdp)`
// in this file; types/mod.rs re-exports via `pub(in crate::afxdp) use
// forwarding::*;` so external call sites resolve unchanged.

use super::*;

#[derive(Clone, Debug, Default)]
pub(in crate::afxdp) struct ForwardingState {
    pub(in crate::afxdp) local_v4: FastSet<Ipv4Addr>,
    pub(in crate::afxdp) local_v6: FastSet<Ipv6Addr>,
    pub(in crate::afxdp) interface_nat_v4: FastMap<Ipv4Addr, i32>,
    pub(in crate::afxdp) interface_nat_v6: FastMap<Ipv6Addr, i32>,
    pub(in crate::afxdp) connected_v4: Vec<ConnectedRouteV4>,
    pub(in crate::afxdp) connected_v6: Vec<ConnectedRouteV6>,
    pub(in crate::afxdp) routes_v4: FastMap<String, Vec<RouteEntryV4>>,
    pub(in crate::afxdp) routes_v6: FastMap<String, Vec<RouteEntryV6>>,
    pub(in crate::afxdp) tunnel_endpoints: FastMap<u16, TunnelEndpoint>,
    pub(in crate::afxdp) tunnel_endpoint_by_ifindex: FastMap<i32, u16>,
    pub(in crate::afxdp) neighbors: FastMap<(i32, IpAddr), NeighborEntry>,
    pub(in crate::afxdp) ifindex_to_name: FastMap<i32, String>,
    pub(in crate::afxdp) ifindex_to_config_name: FastMap<i32, String>,
    /// #921: ifindex → zone ID (was `FastMap<i32, String>`). Built
    /// at config-commit time from the snapshot's per-interface
    /// zone NAME via the `zone_name_to_id` lookup. Hot-path callers
    /// read u16 directly; slow-path display sites translate via
    /// `zone_id_to_name`. Unknown / dropped zones map to `0`.
    pub(in crate::afxdp) ifindex_to_zone_id: FastMap<i32, u16>,
    pub(in crate::afxdp) zone_name_to_id: FastMap<String, u16>,
    pub(in crate::afxdp) zone_id_to_name: FastMap<u16, String>,
    pub(in crate::afxdp) egress: FastMap<i32, EgressInterface>,
    pub(in crate::afxdp) ingress_logical_ifindex: FastMap<(i32, u16), i32>,
    pub(in crate::afxdp) fabrics: Vec<FabricLink>,
    pub(in crate::afxdp) allow_dns_reply: bool,
    pub(in crate::afxdp) allow_embedded_icmp: bool,
    pub(in crate::afxdp) session_timeouts: crate::session::SessionTimeouts,
    pub(in crate::afxdp) policy: PolicyState,
    pub(in crate::afxdp) source_nat_rules: Vec<SourceNatRule>,
    pub(in crate::afxdp) static_nat: StaticNatTable,
    pub(in crate::afxdp) dnat_table: DnatTable,
    pub(in crate::afxdp) nat64: Nat64State,
    pub(in crate::afxdp) nptv6: Nptv6State,
    pub(in crate::afxdp) screen_profiles: FastMap<String, ScreenProfile>,
    pub(in crate::afxdp) tunnel_interfaces: FastSet<i32>,
    pub(in crate::afxdp) filter_state: crate::filter::FilterState,
    pub(in crate::afxdp) cos: CoSState,
    pub(in crate::afxdp) tx_selection_enabled_v4: bool,
    pub(in crate::afxdp) tx_selection_enabled_v6: bool,
    #[allow(dead_code)]
    pub(in crate::afxdp) gre_acceleration: bool,
    pub(in crate::afxdp) flow_export_config: Option<crate::flowexport::FlowExportConfig>,
    pub(in crate::afxdp) mirror_configs: FastMap<i32, MirrorRuntimeConfig>,
    pub(in crate::afxdp) tcp_mss_all_tcp: u16,
    pub(in crate::afxdp) tcp_mss_ipsec_vpn: u16,
    pub(in crate::afxdp) tcp_mss_gre_in: u16,
    pub(in crate::afxdp) tcp_mss_gre_out: u16,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::afxdp) struct MirrorRuntimeConfig {
    pub(in crate::afxdp) output_ifindex: i32,
    pub(in crate::afxdp) rate: u32,
}

#[derive(Clone, Copy, Debug)]
pub(in crate::afxdp) struct ConnectedRouteV4 {
    pub(in crate::afxdp) prefix: PrefixV4,
    pub(in crate::afxdp) ifindex: i32,
    pub(in crate::afxdp) tunnel_endpoint_id: u16,
}

#[derive(Clone, Copy, Debug)]
pub(in crate::afxdp) struct ConnectedRouteV6 {
    pub(in crate::afxdp) prefix: PrefixV6,
    pub(in crate::afxdp) ifindex: i32,
    pub(in crate::afxdp) tunnel_endpoint_id: u16,
}

#[derive(Clone, Debug)]
pub(in crate::afxdp) struct RouteEntryV4 {
    pub(in crate::afxdp) prefix: PrefixV4,
    pub(in crate::afxdp) ifindex: i32,
    pub(in crate::afxdp) tunnel_endpoint_id: u16,
    pub(in crate::afxdp) next_hop: Option<Ipv4Addr>,
    pub(in crate::afxdp) discard: bool,
    pub(in crate::afxdp) next_table: String,
}

#[derive(Clone, Debug)]
pub(in crate::afxdp) struct RouteEntryV6 {
    pub(in crate::afxdp) prefix: PrefixV6,
    pub(in crate::afxdp) ifindex: i32,
    pub(in crate::afxdp) tunnel_endpoint_id: u16,
    pub(in crate::afxdp) next_hop: Option<Ipv6Addr>,
    pub(in crate::afxdp) discard: bool,
    pub(in crate::afxdp) next_table: String,
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NeighborEntry {
    pub mac: [u8; 6],
}

#[derive(Clone, Debug)]
pub(in crate::afxdp) struct EgressInterface {
    pub(in crate::afxdp) bind_ifindex: i32,
    pub(in crate::afxdp) vlan_id: u16,
    pub(in crate::afxdp) mtu: usize,
    pub(in crate::afxdp) src_mac: [u8; 6],
    /// #921: u16 zone ID (was `zone: String`). Resolved at config
    /// build time via `zone_name_to_id`; `0` means "unknown" (the
    /// zone wasn't in the snapshot's zones list, or had a reserved
    /// id and was dropped).
    pub(in crate::afxdp) zone_id: u16,
    pub(in crate::afxdp) redundancy_group: i32,
    pub(in crate::afxdp) primary_v4: Option<Ipv4Addr>,
    pub(in crate::afxdp) primary_v6: Option<Ipv6Addr>,
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub(in crate::afxdp) struct TunnelEndpoint {
    pub(in crate::afxdp) id: u16,
    pub(in crate::afxdp) logical_ifindex: i32,
    pub(in crate::afxdp) redundancy_group: i32,
    pub(in crate::afxdp) mode: String,
    pub(in crate::afxdp) outer_family: i32,
    pub(in crate::afxdp) source: IpAddr,
    pub(in crate::afxdp) destination: IpAddr,
    pub(in crate::afxdp) key: u32,
    pub(in crate::afxdp) ttl: u8,
    pub(in crate::afxdp) transport_table: String,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(in crate::afxdp) struct FabricLink {
    pub(in crate::afxdp) parent_ifindex: i32,
    pub(in crate::afxdp) overlay_ifindex: i32,
    pub(in crate::afxdp) peer_addr: IpAddr,
    pub(in crate::afxdp) peer_mac: [u8; 6],
    pub(in crate::afxdp) local_mac: [u8; 6],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ForwardingDisposition {
    LocalDelivery,
    ForwardCandidate,
    FabricRedirect,
    HAInactive,
    PolicyDenied,
    NoRoute,
    MissingNeighbor,
    DiscardRoute,
    NextTableUnsupported,
}

impl ForwardingDisposition {
    /// Whether this disposition produces a stable forwarding decision that can
    /// be stored in the per-worker flow cache.
    ///
    /// Cacheable:
    ///   - `ForwardCandidate`: Normal forwarded traffic with a resolved
    ///     neighbor and egress interface. The common fast path.
    ///   - `FabricRedirect`: Targets a fabric overlay binding. Cacheable
    ///     because each cache entry captures the owning RG epoch into
    ///     `FlowCacheStamp::owner_rg_epoch` at insert time
    ///     (`flow_cache.rs:60-83`), and `FlowCache::lookup`
    ///     (`flow_cache.rs:314-347`) treats the entry as a miss when
    ///     `current_epoch != entry.stamp.owner_rg_epoch`. The owning RG
    ///     bumps its epoch on every active/standby flip, so the window
    ///     in which a cached `FabricRedirect` could point at a stale
    ///     fabric peer is bounded by the next RG epoch bump (#1065).
    ///
    /// Not cacheable:
    ///   - `LocalDelivery`: Delivered to the kernel stack, not forwarded
    ///     through XSK bindings. No rewrite descriptor to cache.
    ///   - `HAInactive`: The owning RG is not active on this node. Transient
    ///     state that changes on failover — must never be cached.
    ///   - `PolicyDenied`: Packet was denied by policy. Drop decisions are
    ///     not cached to allow policy changes to take effect immediately.
    ///   - `NoRoute`: No route to destination. Transient — may resolve when
    ///     FIB is updated.
    ///   - `MissingNeighbor`: Route exists but ARP/NDP is unresolved.
    ///     Transient — resolves when the neighbor entry appears.
    ///   - `DiscardRoute`: Matched a discard/reject route. Not cacheable for
    ///     the same reason as PolicyDenied.
    ///   - `NextTableUnsupported`: Inter-VRF route leaking hit an
    ///     unsupported next-table. Permanent miss, not worth caching.
    pub(in crate::afxdp) fn is_cacheable(self) -> bool {
        matches!(
            self,
            ForwardingDisposition::ForwardCandidate | ForwardingDisposition::FabricRedirect
        )
    }
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
                ForwardingDisposition::HAInactive => "ha_inactive",
                ForwardingDisposition::PolicyDenied => "policy_denied",
                ForwardingDisposition::NoRoute => "no_route",
                ForwardingDisposition::MissingNeighbor => "missing_neighbor",
                ForwardingDisposition::DiscardRoute => "discard_route",
                ForwardingDisposition::NextTableUnsupported => "next_table_unsupported",
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

#[derive(Clone, Debug)]
pub(in crate::afxdp) struct BindingIdentity {
    pub(in crate::afxdp) slot: u32,
    pub(in crate::afxdp) queue_id: u32,
    pub(in crate::afxdp) worker_id: u32,
    pub(in crate::afxdp) interface: Arc<str>,
    pub(in crate::afxdp) ifindex: i32,
}

#[derive(Clone, Debug, Default)]
pub(in crate::afxdp) struct WorkerBindingLookup {
    pub(in crate::afxdp) by_if_queue: FastMap<(i32, u32), usize>,
    pub(in crate::afxdp) first_by_if: FastMap<i32, usize>,
    pub(in crate::afxdp) all_by_if: FastMap<i32, Vec<usize>>,
    pub(in crate::afxdp) by_slot: FastMap<u32, usize>,
}

impl WorkerBindingLookup {
    pub(in crate::afxdp) fn from_bindings(bindings: &[BindingWorker]) -> Self {
        let mut lookup = Self::default();
        for (index, binding) in bindings.iter().enumerate() {
            lookup
                .by_if_queue
                .insert((binding.ifindex, binding.queue_id), index);
            lookup.first_by_if.entry(binding.ifindex).or_insert(index);
            lookup
                .all_by_if
                .entry(binding.ifindex)
                .or_default()
                .push(index);
            lookup.by_slot.insert(binding.slot, index);
        }
        lookup
    }

    pub(in crate::afxdp) fn target_index(
        &self,
        current_index: usize,
        current_ifindex: i32,
        ingress_queue_id: u32,
        egress_ifindex: i32,
    ) -> Option<usize> {
        if current_ifindex == egress_ifindex {
            return Some(current_index);
        }
        self.by_if_queue
            .get(&(egress_ifindex, ingress_queue_id))
            .copied()
            .or_else(|| self.first_by_if.get(&egress_ifindex).copied())
    }

    pub(in crate::afxdp) fn slot_index(&self, slot: u32) -> Option<usize> {
        self.by_slot.get(&slot).copied()
    }

    pub(in crate::afxdp) fn fabric_target_index(&self, egress_ifindex: i32, flow_hash: u64) -> Option<usize> {
        let indices = self.all_by_if.get(&egress_ifindex)?;
        if indices.is_empty() {
            return None;
        }
        Some(indices[(flow_hash as usize) % indices.len()])
    }
}
