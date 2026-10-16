//! P-MECH snapshot DTOs for route-based IPsec authority.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
pub(crate) struct IpsecPMechTunnelRowSnapshot {
    #[serde(rename = "stn", default)]
    pub stn: String,
    #[serde(rename = "if_id", default)]
    pub if_id: u32,
    #[serde(rename = "logical_ifindex", default)]
    pub logical_ifindex: i32,
    #[serde(rename = "explicit_selectors", default)]
    pub explicit_selectors: Vec<IpsecTrafficSelectorSnapshot>,
    #[serde(rename = "effective_prefixes", default)]
    pub effective_prefixes: Vec<String>,
    #[serde(rename = "ingress_prefixes", default)]
    pub ingress_prefixes: Vec<String>,
    #[serde(rename = "destination_prefixes", default)]
    pub destination_prefixes: Vec<String>,
    #[serde(rename = "inventory_generation", default)]
    pub inventory_generation: u64,
    #[serde(rename = "fib_generation", default)]
    pub fib_generation: u32,
    #[serde(rename = "source_kind", default)]
    pub source_kind: String,
    #[serde(rename = "selector_provenance", default)]
    pub selector_provenance: String,
    #[serde(rename = "inventory_complete", default)]
    pub inventory_complete: bool,
    #[serde(rename = "inventory_valid", default)]
    pub inventory_valid: bool,
    #[serde(rename = "inventory_reason", default)]
    pub inventory_reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
pub(crate) struct IpsecTrafficSelectorSnapshot {
    #[serde(rename = "name", default)]
    pub name: String,
    #[serde(rename = "local_ts", default)]
    pub local_ts: String,
    #[serde(rename = "remote_ts", default)]
    pub remote_ts: String,
    #[serde(rename = "source", default)]
    pub source: String,
}

/// One tunnel-relevant main-table route with every resolved nexthop leg. Go
/// carries only routes with a leg on a tunnel's logical ifindex, routes that
/// overlap a remote traffic selector, and invalid routes kept for audit; the
/// per-tunnel projection recomputed from these rows equals the full-table one.
#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
pub(crate) struct IpsecMainRouteSnapshot {
    #[serde(rename = "domain")]
    pub domain: u32,
    #[serde(rename = "table")]
    pub table: u32,
    #[serde(rename = "family", default)]
    pub family: String,
    #[serde(rename = "destination", default)]
    pub destination: String,
    #[serde(rename = "protocol", default)]
    pub protocol: u8,
    #[serde(rename = "disposition", default)]
    pub disposition: u8,
    #[serde(rename = "next_hops", default)]
    pub next_hops: Vec<IpsecMainRouteNextHopSnapshot>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
pub(crate) struct IpsecMainRouteNextHopSnapshot {
    #[serde(rename = "ifindex", default)]
    pub ifindex: u32,
    #[serde(rename = "weight", default)]
    pub weight: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
pub(crate) struct IpsecPMechInventorySnapshot {
    #[serde(rename = "policy_identity", default)]
    pub policy_identity: String,
    #[serde(rename = "generation", default)]
    pub generation: u64,
    #[serde(rename = "fib_generation", default)]
    pub fib_generation: u32,
    #[serde(rename = "complete", default)]
    pub complete: bool,
    #[serde(rename = "main_routes", default)]
    pub main_routes: Vec<IpsecMainRouteSnapshot>,
    #[serde(rename = "tunnel_rows", default)]
    pub tunnel_rows: Vec<IpsecPMechTunnelRowSnapshot>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
pub(crate) struct IpsecBindlessSelectorSnapshot {
    #[serde(rename = "local_ts", default)]
    pub local_ts: String,
    #[serde(rename = "remote_ts", default)]
    pub remote_ts: String,
}
