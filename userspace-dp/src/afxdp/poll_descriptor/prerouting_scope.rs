// Provenance: extracted from poll_descriptor/mod.rs at
// b70cdf8357 (2026-07-23, #6386): the #5802 pre-routing NAT
// ingress-scope resolver (`PreroutingIngressScope` +
// `prerouting_ingress_scope`). At that commit both items were
// already `pub(super)`; the ONLY non-motion change was the
// added `#[inline]` on `prerouting_ingress_scope` — it restored
// same-CGU inlining eligibility across the new module boundary
// (#6386 hot-path preservation contract) — and the bodies
// matched their prior location. That is a split-time record,
// not a claim about the current tree: this file has been
// edited since.

use super::*;

/// #5802: the ingress identity the pre-routing DNAT / static-NAT / NPTv6
/// scope matches `from zone` / `from interface` / `from routing-instance`
/// against, resolved from the LOGICAL VLAN unit that received the frame.
///
/// The borrowed `&str` fields live for the `forwarding` borrow; `""` = no
/// scope constraint (unscoped rule, matches every ingress).
pub(super) struct PreroutingIngressScope<'a> {
    /// The logical unit ingress ifindex (VLAN sub-interface), or the physical
    /// bind ifindex for an untagged port. Threaded into the later zone-pair
    /// policy so the pre-routing NAT scope and the zone policy share ONE
    /// ingress identity.
    pub logical_ifindex: i32,
    /// Ingress zone name (a fabric-encoded override wins, else the logical
    /// unit's zone).
    pub zone_name: &'a str,
    /// Ingress interface config name (e.g. `reth0.50`).
    pub ifname: &'a str,
    /// Ingress interface routing-instance (`""` = default VRF).
    pub routing_instance: &'a str,
    /// #16045: true when this scope was derived for an ambiguous fabric
    /// arrival (a claimed zone withheld pending the owner-RG gate) and
    /// the LOCAL fabric/logical identity answered. A scoped rule match
    /// under that identity is unproven provenance: the later policy may
    /// promote the claimed zone, so a translation selected here would be
    /// keyed to a zone the policy never adjudicated. Callers fail closed
    /// on any scoped match while this holds; unscoped rules (which fire
    /// under every ingress identity) are unaffected.
    pub ambiguous_provenance: bool,
}

/// Resolve the pre-routing NAT scope identity for a received frame.
///
/// `ifindex_to_zone_id` / `ifindex_to_config_name` /
/// `ifindex_to_routing_instance` are keyed by the LOGICAL unit ifindex
/// (forwarding_build/interfaces.rs); a VLAN sub-interface's physical bind
/// ifindex maps only to its parent's FIRST unit. #5802: scoping the
/// pre-routing DNAT/static-NAT/NPTv6 lookups against the raw physical
/// `meta.ingress_ifindex` on a trunk whose VLAN units sit in distinct zones /
/// interfaces / routing-instances let a packet on one unit match another
/// unit's scoped NAT rule (or miss its own) — a NAT scope-escape ahead of the
/// correct logical zone policy. This resolves the logical unit first (the same
/// identity the zone-policy / filter / CoS path uses, #3021) and reads the
/// scope from it. An untagged port has no `(parent, vlan)` mapping, so it
/// resolves logical == physical and the scope is byte-identical to pre-#5802.
///
/// The zone matches a fabric-ingress `zone_override` (peer-encoded) first,
/// exactly as the pre-#5802 code did; only the physical→logical ifindex used
/// for the local-unit fallback lookups changes.
#[inline]
pub(super) fn prerouting_ingress_scope(
    forwarding: &ForwardingState,
    physical_ifindex: i32,
    ingress_vlan_id: u16,
    zone_override: Option<u32>,
    fabric_ingress_scope_ifindex: Option<i32>,
) -> PreroutingIngressScope<'_> {
    prerouting_ingress_scope_provenance(
        forwarding,
        physical_ifindex,
        ingress_vlan_id,
        zone_override,
        fabric_ingress_scope_ifindex,
        false,
    )
}

/// #16045: like [`prerouting_ingress_scope`], but for an ambiguous
/// fabric arrival whose claimed zone (and, for the V2 form, peer
/// NAT-scope ifindex) is withheld pending the owner-RG gate. The
/// identity is resolved from the LOCAL fabric/logical ingress exactly
/// as the unpromoted production scope is, and stamped
/// `ambiguous_provenance` so callers can fail closed on any scoped
/// translation it selects. The claimed zone is NEVER substituted
/// here: granting it before owner proof would violate the #15916
/// withholding contract.
#[inline]
pub(super) fn prerouting_ingress_scope_ambiguous(
    forwarding: &ForwardingState,
    physical_ifindex: i32,
    ingress_vlan_id: u16,
) -> PreroutingIngressScope<'_> {
    prerouting_ingress_scope_provenance(
        forwarding,
        physical_ifindex,
        ingress_vlan_id,
        None,
        None,
        true,
    )
}

#[inline]
fn prerouting_ingress_scope_provenance(
    forwarding: &ForwardingState,
    physical_ifindex: i32,
    ingress_vlan_id: u16,
    zone_override: Option<u32>,
    fabric_ingress_scope_ifindex: Option<i32>,
    ambiguous_provenance: bool,
) -> PreroutingIngressScope<'_> {
    let logical_ifindex =
        resolve_ingress_logical_ifindex(forwarding, physical_ifindex, ingress_vlan_id)
            .unwrap_or(physical_ifindex);
    let unknown_vlan = crate::afxdp::forwarding::unknown_ingress_vlan(
        forwarding,
        physical_ifindex,
        ingress_vlan_id,
    );
    // #10313/#10656: preserve physical parent/unit config identity for
    // interface/RI scope, but don't let any fallback zone answer an unknown
    // VID. A fabric-encoded override remains authoritative; only the local
    // ifindex-zone fallback is suppressed for an unknown local pair.
    // #919: ingress_zone_override is Option<u32>; DNAT/static NAT lookups take
    // zone names, so resolve ID→name lazily on this miss path. A fabric-encoded
    // override wins; else resolve the LOGICAL unit's zone (#5802).
    let zone_name = zone_override
        .and_then(|id| forwarding.zone_id_to_name.get(&id).map(|s| s.as_str()))
        .or_else(|| {
            if unknown_vlan {
                None
            } else {
                forwarding
                    .ifindex_to_zone_id
                    .get(&logical_ifindex)
                    .and_then(|id| forwarding.zone_id_to_name.get(id))
                    .map(|s| s.as_str())
            }
        })
        .unwrap_or("");
    // #3096: ingress interface config-name + routing-instance for the DNAT
    // `from interface` / `from routing-instance` scope. A validated V2 fabric
    // identity names the original peer ingress unit; the local logical unit
    // remains authoritative for zone and filter policy.
    let nat_scope_ifindex = fabric_ingress_scope_ifindex.unwrap_or(logical_ifindex);
    let ifname = forwarding
        .ifindex_to_config_name
        .get(&nat_scope_ifindex)
        .map(|s| s.as_str())
        .unwrap_or("");
    let routing_instance = forwarding
        .ifindex_to_routing_instance
        .get(&nat_scope_ifindex)
        .map(|s| s.as_str())
        .unwrap_or("");
    PreroutingIngressScope {
        logical_ifindex,
        zone_name,
        ifname,
        routing_instance,
        ambiguous_provenance,
    }
}

#[cfg(test)]
#[path = "prerouting_scope_tests.rs"]
mod tests;
