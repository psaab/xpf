// FIB route types split from forwarding.rs (#16209): connected /
// non-connected route entries, weighted ECMP next-hops, leak rules,
// the mirror runtime config, and the public NeighborEntry. Pure
// code motion behind `forwarding/mod.rs`'s `use forwarding::*` glob;
// zero layout or access-site change.
// Visibility bill: no widening. Every item keeps its pre-split
// visibility; sibling access goes through the parent's glob re-export.

use super::super::*;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::afxdp) struct MirrorRuntimeConfig {
    pub(in crate::afxdp) output_ifindex: i32,
    pub(in crate::afxdp) rate: u32,
}

/// One resolved weighted ECMP next-hop candidate for a route (#2389/#11402).
/// A route retains every authored member so lookup can distribute flows in
/// proportion to its weight and skip a dead candidate. `next_hop == None`
/// with a non-zero `ifindex` is an interface-only ("via <if>") candidate.
/// `weight` preserves this leg's Linux multipath weight; the selector treats
/// zero defensively as 1.
#[derive(Clone, Copy, Debug)]
pub(in crate::afxdp) struct RouteNextHopV4 {
    pub(in crate::afxdp) next_hop: Option<Ipv4Addr>,
    pub(in crate::afxdp) ifindex: i32,
    /// Stable logical interface identity; unlike ifindex, it is shared by
    /// HA peers and survives node-local kernel renumbering.
    pub(in crate::afxdp) logical_interface_id: u64,
    pub(in crate::afxdp) tunnel_endpoint_id: u16,
    pub(in crate::afxdp) weight: u32,
}

#[derive(Clone, Copy, Debug)]
pub(in crate::afxdp) struct RouteNextHopV6 {
    pub(in crate::afxdp) next_hop: Option<Ipv6Addr>,
    pub(in crate::afxdp) ifindex: i32,
    /// Stable logical interface identity shared across HA peers, independent of
    /// the node-local ifindex.
    pub(in crate::afxdp) logical_interface_id: u64,
    pub(in crate::afxdp) tunnel_endpoint_id: u16,
    pub(in crate::afxdp) weight: u32,
}

/// Stable 64-bit, FNV-1a-derived identity for a configured interface name.
/// Computed while building the snapshot so per-flow ECMP ranking reads one word.
pub(in crate::afxdp) fn ecmp_logical_interface_id(interface: &str) -> u64 {
    interface
        .bytes()
        .fold(0xcbf2_9ce4_8422_2325u64, |hash, byte| {
            (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3)
        })
        ^ interface.len() as u64
}

#[derive(Clone, Debug)]
pub(in crate::afxdp) struct ConnectedRouteV4 {
    pub(in crate::afxdp) prefix: PrefixV4,
    /// #10645: this row's interface HOST address (unmasked). `prefix` is
    /// the MASKED network, so `prefix.addr()` equals the host only for a
    /// /32 — the local-delivery ifindex attribution compares against this
    /// field so interface addresses of any width resolve their real
    /// ifindex. Populated from the interface address's `.addr()` in
    /// `populate_interfaces`, alongside the `local_tables_v*` key.
    pub(in crate::afxdp) host: Ipv4Addr,
    pub(in crate::afxdp) ifindex: i32,
    pub(in crate::afxdp) tunnel_endpoint_id: u16,
    /// #2388: canonical routing-table name this connected route belongs to
    /// (e.g. "inet.0" or "tenant-a.inet.0"). The lookup filters connected
    /// routes by table so a per-VRF / next-table lookup never matches a
    /// connected prefix owned by a different routing-instance. The
    /// connected vec holds one entry per interface address, so the
    /// per-packet linear scan plus a string compare stays cheap.
    pub(in crate::afxdp) table: String,
}

#[derive(Clone, Debug)]
pub(in crate::afxdp) struct ConnectedRouteV6 {
    pub(in crate::afxdp) prefix: PrefixV6,
    /// #10645: this row's interface HOST address (unmasked); see
    /// `ConnectedRouteV4::host`.
    pub(in crate::afxdp) host: Ipv6Addr,
    /// Linux interface-address scope copied from `InterfaceAddressSnapshot`;
    /// link-local gateway inference only accepts RT_SCOPE_UNIVERSE (0).
    pub(in crate::afxdp) scope: i32,
    pub(in crate::afxdp) ifindex: i32,
    pub(in crate::afxdp) tunnel_endpoint_id: u16,
    /// #2388: canonical routing-table name this connected route belongs to.
    pub(in crate::afxdp) table: String,
}

#[derive(Clone, Debug)]
pub(in crate::afxdp) struct LeakRuleV4 {
    pub(in crate::afxdp) prefix: PrefixV4,
    pub(in crate::afxdp) next_table: String,
    /// #9955: lower kernel ip-rule priorities are evaluated first.
    pub(in crate::afxdp) rule_priority: u32,
    /// #16799: a rib-group return row (kernel priority in (1000, 2000))
    /// runs AFTER the source VRF table's own lookup (the l3mdev rule at
    /// 1000), not before it. Deferred rows are evaluated only when the
    /// source table's own LPM (and, for main, the 30000-band leaks)
    /// produced no route. All other leaks keep stage-1 precedence.
    pub(in crate::afxdp) post_table: bool,
    /// #9951: stable per-incarnation identity. A removed and later re-added
    /// leak gets a new value, so an old session cannot pass an ABA check.
    pub(in crate::afxdp) incarnation: u64,
}

#[derive(Clone, Debug)]
pub(in crate::afxdp) struct LeakRuleV6 {
    pub(in crate::afxdp) prefix: PrefixV6,
    pub(in crate::afxdp) next_table: String,
    /// #9955: lower kernel ip-rule priorities are evaluated first.
    pub(in crate::afxdp) rule_priority: u32,
    /// #16799: v4 twin (see `LeakRuleV4::post_table`).
    pub(in crate::afxdp) post_table: bool,
    /// #9951: stable per-incarnation identity (see `LeakRuleV4`).
    pub(in crate::afxdp) incarnation: u64,
}

#[derive(Clone, Debug)]
pub(in crate::afxdp) struct RouteEntryV4 {
    pub(in crate::afxdp) prefix: PrefixV4,
    /// #2389: all resolved equal-cost next-hops from `RouteSnapshot.next_hops`.
    /// A connected-prefix marker may be empty only when an exactly matching
    /// `ConnectedRouteV4` backs it; lookup selects that connected entry instead.
    /// `populate_routes` rejects unbacked empty ordinary routes (#12063). The
    /// legacy single `next_hop` / `ifindex` / `tunnel_endpoint_id` accessors
    /// below select the FIRST candidate; the multipath selector reads the whole
    /// slice.
    pub(in crate::afxdp) next_hops: Vec<RouteNextHopV4>,
    pub(in crate::afxdp) discard: bool,
    pub(in crate::afxdp) reject: bool,
    /// #15742: cluster Null0 default provenance (see RouteSnapshot).
    pub(in crate::afxdp) cluster_terminal: bool,
    pub(in crate::afxdp) next_table: String,
    /// #2390: Junos route preference (admin distance; lower = preferred).
    pub(in crate::afxdp) preference: i32,
    /// Kernel-selected route MTU, in bytes. Zero means no route MTU.
    pub(in crate::afxdp) mtu: u32,
    /// #9955: kernel ip-rule priority for a next-table leak. Zero for
    /// ordinary routes and legacy snapshots.
    pub(in crate::afxdp) rule_priority: u32,
    /// #16614: config-authored next-table route. Such rows live in the
    /// ordinary LPM list (not the stage-1 leak index): selection hands
    /// the lookup to `next_table`, and a target miss is terminal.
    pub(in crate::afxdp) next_table_route: bool,
}

#[derive(Clone, Debug)]
pub(in crate::afxdp) struct RouteEntryV6 {
    pub(in crate::afxdp) prefix: PrefixV6,
    /// #2389: all resolved equal-cost next-hops. See `RouteEntryV4`.
    pub(in crate::afxdp) next_hops: Vec<RouteNextHopV6>,
    pub(in crate::afxdp) discard: bool,
    pub(in crate::afxdp) reject: bool,
    /// #15742: cluster Null0 default provenance (see RouteSnapshot).
    pub(in crate::afxdp) cluster_terminal: bool,
    pub(in crate::afxdp) next_table: String,
    /// #2390: Junos route preference (admin distance; lower = preferred).
    pub(in crate::afxdp) preference: i32,
    /// Kernel-selected route MTU, in bytes. Zero means no route MTU.
    pub(in crate::afxdp) mtu: u32,
    /// #9955: kernel ip-rule priority for a next-table leak. Zero for
    /// ordinary routes and legacy snapshots.
    pub(in crate::afxdp) rule_priority: u32,
    /// #16614: v4 twin (see `RouteEntryV4`).
    pub(in crate::afxdp) next_table_route: bool,
}

impl RouteEntryV4 {
    /// First (primary) next-hop ifindex, or 0 if the route has no resolved
    /// next-hop (discard / next-table / connected marker). Preserves the pre-#2389 single
    /// next-hop accessor for call sites that do not multipath-select.
    pub(in crate::afxdp) fn ifindex(&self) -> i32 {
        self.next_hops.first().map(|nh| nh.ifindex).unwrap_or(0)
    }
    pub(in crate::afxdp) fn tunnel_endpoint_id(&self) -> u16 {
        self.next_hops
            .first()
            .map(|nh| nh.tunnel_endpoint_id)
            .unwrap_or(0)
    }
    pub(in crate::afxdp) fn next_hop(&self) -> Option<Ipv4Addr> {
        self.next_hops.first().and_then(|nh| nh.next_hop)
    }
}

impl RouteEntryV6 {
    pub(in crate::afxdp) fn ifindex(&self) -> i32 {
        self.next_hops.first().map(|nh| nh.ifindex).unwrap_or(0)
    }
    pub(in crate::afxdp) fn tunnel_endpoint_id(&self) -> u16 {
        self.next_hops
            .first()
            .map(|nh| nh.tunnel_endpoint_id)
            .unwrap_or(0)
    }
    pub(in crate::afxdp) fn next_hop(&self) -> Option<Ipv6Addr> {
        self.next_hops.first().and_then(|nh| nh.next_hop)
    }
}

#[cfg(test)]
impl RouteEntryV4 {
    /// Test-only single-next-hop constructor preserving the pre-#2389
    /// `{ ifindex, tunnel_endpoint_id, next_hop }` shape so existing FIB
    /// tests read straightforwardly.
    pub(in crate::afxdp) fn single(
        prefix: PrefixV4,
        ifindex: i32,
        tunnel_endpoint_id: u16,
        next_hop: Option<Ipv4Addr>,
        discard: bool,
        next_table: String,
        preference: i32,
    ) -> Self {
        RouteEntryV4 {
            prefix,
            next_hops: vec![RouteNextHopV4 {
                next_hop,
                ifindex,
                logical_interface_id: 0,
                tunnel_endpoint_id,
                weight: 1,
            }],
            discard,
            reject: false,
            cluster_terminal: false,
            next_table,
            preference,
            mtu: 0,
            rule_priority: 0,
            next_table_route: false,
        }
    }
}

#[cfg(test)]
impl RouteEntryV6 {
    pub(in crate::afxdp) fn single(
        prefix: PrefixV6,
        ifindex: i32,
        tunnel_endpoint_id: u16,
        next_hop: Option<Ipv6Addr>,
        discard: bool,
        next_table: String,
        preference: i32,
    ) -> Self {
        RouteEntryV6 {
            prefix,
            next_hops: vec![RouteNextHopV6 {
                next_hop,
                ifindex,
                logical_interface_id: 0,
                tunnel_endpoint_id,
                weight: 1,
            }],
            discard,
            reject: false,
            cluster_terminal: false,
            next_table,
            preference,
            mtu: 0,
            rule_priority: 0,
            next_table_route: false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NeighborEntry {
    pub mac: [u8; 6],
}
