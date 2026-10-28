// #17197: the single production pre-routing DNAT verdict, shared by the
// session-miss poll loop and the Stage-11 IPsec claim discriminator.
//
// Before this extraction the poll loop evaluated the three DNAT tiers
// (static -> persistent -> dynamic pool) inline, while Stage 11 kept a
// hand-maintained copy (`ipsec_destination_matches_transit_dnat`) that
// consulted only the dynamic tier through the collapsing
// `lookup_with_counter_scoped` API. The copy drifted after every
// production change (#11439 raw ifindex, #16047 scope copy, #16045
// ambiguous provenance / persistent tier / Poisoned), so a Stage-11
// claim could disagree with the translation production would select.
//
// This function IS the production decision. Hit counters and
// persistent-lease keys are returned, never applied: no NAT rule
// counter is charged and no lease hold is taken here. The poll loop
// applies them at its committed-install sites (#2218); Stage 11 only
// reads the classification. The counting entry point's persistent
// tier still takes the allocator's counted write guard (the poll
// loop's committed-install telemetry is unchanged); Stage 11 calls
// [`prerouting_dnat_verdict_peek`], whose persistent tier reads under
// an uncounted read guard, so the claim path charges no allocator
// lock telemetry either (see that function). `#[inline]`,
// allocation-free, borrowed counter handles (#6386 hot-path
// preservation contract).

use super::prerouting_scope::PreroutingIngressScope;
use super::*;
use crate::nat::PersistentInbound;

/// The pre-routing DNAT verdict for one packet, in Junos evaluation
/// order (static -> persistent -> dynamic pool, #6473).
///
/// Counter and lease side effects are returned, not applied:
/// - `Static` / `Dynamic` carry the matched rule's hit counter
///   (`None` for an uncounted rule); the caller charges it exactly
///   once at a committed session install (#2218), except for the
///   `Poisoned` arm, which the caller charges at the drop because no
///   session is ever installed (#16483).
/// - `Persistent` carries the lease key the caller holds for the
///   installed session's lifetime (#15111).
#[derive(Clone, Debug)]
pub(in crate::afxdp) enum PreroutingDnatVerdict {
    /// Static-NAT (1:1) translation won.
    Static(NatDecision, Option<Arc<crate::nat::NatRuleCounter>>),
    /// A live persistent-NAT lease admitted the packet.
    Persistent(NatDecision, Option<crate::nat::PersistentSourceKey>),
    /// The dynamic DNAT pool table translated the packet.
    Dynamic(NatDecision, Option<Arc<crate::nat::NatRuleCounter>>),
    /// A poisoned rule claimed the packet, or a scope-constrained
    /// match was selected under ambiguous provenance: the caller
    /// must drop it (fail closed, #14947/#16045). Carries the
    /// claiming rule's counter when one exists.
    Poisoned(Option<Arc<crate::nat::NatRuleCounter>>),
    /// A persistent-NAT lease exists for the tuple but denies this
    /// remote: the caller must drop it.
    Denied,
    /// No tier translated the packet (including a healthy
    /// `destination-nat off` exemption): forward untranslated.
    None,
}

impl PreroutingDnatVerdict {
    /// The translation this verdict selects, if any.
    #[inline]
    pub(in crate::afxdp) fn decision(&self) -> Option<NatDecision> {
        match self {
            PreroutingDnatVerdict::Static(decision, _)
            | PreroutingDnatVerdict::Persistent(decision, _)
            | PreroutingDnatVerdict::Dynamic(decision, _) => Some(*decision),
            PreroutingDnatVerdict::Poisoned(_)
            | PreroutingDnatVerdict::Denied
            | PreroutingDnatVerdict::None => None,
        }
    }

    /// #17197: does this verdict translate the destination to a
    /// configured interface address (DNAT-to-self)? Stage 11 claims
    /// only `None` verdicts and translations to self; a translation
    /// to a non-local target is transit and must not be claimed, and
    /// `Poisoned` / `Denied` verdicts are drops, never claims.
    #[inline]
    pub(in crate::afxdp) fn translates_to_self(&self, forwarding: &ForwardingState) -> bool {
        match self.decision().and_then(|decision| decision.rewrite_dst) {
            Some(IpAddr::V4(target)) => forwarding.configured_iface_v4.contains(&target),
            Some(IpAddr::V6(target)) => forwarding.configured_iface_v6.contains(&target),
            None => false,
        }
    }
}

/// Evaluate the production pre-routing DNAT decision for `flow` under
/// the already-resolved ingress `scope`.
///
/// The translation target is `flow.dst_ip` — the poll loop's
/// `parse_packet_destination_from_frame(..).unwrap_or(flow.dst_ip)`
/// resolution reads the same header the flow was parsed from, so the
/// two agree on every real packet. `packet_icmp` is the packet's
/// ICMP type/code (`policy_packet_icmp`), `None` for non-ICMP
/// packets. `suppress_destination_nat` is the caller's on-link NDP
/// exemption (#15117): every tier is skipped and the verdict is
/// `None`.
///
/// Allocation-free: no NAT rule counter is charged and no lease
/// hold is taken here; both are returned for the caller to apply.
/// The persistent tier uses the allocator's counting lookup
/// (`persistent_inbound_lookup_for_rule`, `lock_live`), so this
/// entry point charges the allocator's live-write lock telemetry
/// (`live_write_lock_acquisitions`, plus contended on contention)
/// exactly as the pre-extraction poll loop did.
#[inline]
#[allow(clippy::too_many_arguments)]
pub(in crate::afxdp) fn prerouting_dnat_verdict(
    forwarding: &ForwardingState,
    meta: &UserspaceDpMeta,
    flow: &SessionFlow,
    scope: &PreroutingIngressScope<'_>,
    packet_icmp: Option<(u8, u8)>,
    suppress_destination_nat: bool,
    now_ns: u64,
) -> PreroutingDnatVerdict {
    prerouting_dnat_verdict_inner(
        forwarding,
        meta,
        flow,
        scope,
        packet_icmp,
        suppress_destination_nat,
        now_ns,
        false,
    )
}

/// #17197: Stage-11 variant of [`prerouting_dnat_verdict`] with the
/// same tier order, scope handling and classification, but whose
/// persistent tier uses the allocator's non-counting peek
/// (`persistent_inbound_peek_for_rule`, `read_live`): no write guard
/// is taken and no `live_write_lock_acquisitions` /
/// `live_write_lock_contended` telemetry is charged. Stage 11 is a
/// pure classification (it never holds the returned lease key and
/// never charges the returned counters), so charging it the poll
/// loop's committed-install lock telemetry — on a path the deleted
/// mirror never touched the allocator from — would inject the
/// observer into the NAT status counters. The classification can
/// race a concurrent lease mint/revoke exactly as any read-guard
/// snapshot can; the poll loop re-evaluates with the counting entry
/// point before installing, so a stale peek never installs state.
#[inline]
#[allow(clippy::too_many_arguments)]
pub(in crate::afxdp) fn prerouting_dnat_verdict_peek(
    forwarding: &ForwardingState,
    meta: &UserspaceDpMeta,
    flow: &SessionFlow,
    scope: &PreroutingIngressScope<'_>,
    packet_icmp: Option<(u8, u8)>,
    suppress_destination_nat: bool,
    now_ns: u64,
) -> PreroutingDnatVerdict {
    prerouting_dnat_verdict_inner(
        forwarding,
        meta,
        flow,
        scope,
        packet_icmp,
        suppress_destination_nat,
        now_ns,
        true,
    )
}

#[inline]
#[allow(clippy::too_many_arguments)]
fn prerouting_dnat_verdict_inner(
    forwarding: &ForwardingState,
    meta: &UserspaceDpMeta,
    flow: &SessionFlow,
    scope: &PreroutingIngressScope<'_>,
    packet_icmp: Option<(u8, u8)>,
    suppress_destination_nat: bool,
    now_ns: u64,
    persistent_peek: bool,
) -> PreroutingDnatVerdict {
    let resolution_target = flow.dst_ip;
    if suppress_destination_nat {
        return PreroutingDnatVerdict::None;
    }
    let scope_ambiguous = scope.ambiguous_provenance;
    // #6473 (Junos order): static DNAT first.
    let static_dnat_decision = if scope_ambiguous {
        forwarding
            .static_nat
            .match_dnat_ambiguous_provenance_scoped(
                resolution_target,
                flow.forward_key.dst_port,
                Some(flow.forward_key.src_ip),
                scope.zone_name,
                scope.ifname,
                scope.routing_instance,
            )
    } else {
        forwarding.static_nat.match_dnat_with_counter_scoped(
            resolution_target,
            flow.forward_key.dst_port,
            Some(flow.forward_key.src_ip),
            scope.zone_name,
            scope.ifname,
            scope.routing_instance,
        )
    };
    if let Some((decision, counter)) = static_dnat_decision {
        return PreroutingDnatVerdict::Static(decision, counter);
    }
    // Persistent-NAT DNAT next. #16045: persistent-NAT scope is
    // ingress-keyed; under ambiguous provenance the reader is skipped.
    if !scope_ambiguous {
        let mut persistent_dnat = None;
        let mut persistent_lease_hold: Option<crate::nat::PersistentSourceKey> = None;
        let mut persistent_dnat_denied = false;
        for rule in &forwarding.source_nat_rules {
            if !rule.persistent_nat || !rule.pool_mode {
                continue;
            }
            let pool_contains_target = match resolution_target {
                IpAddr::V4(ip) => rule.pool_index_v4.contains_key(&ip),
                IpAddr::V6(ip) => rule.pool_index_v6.contains_key(&ip),
            };
            if !pool_contains_target {
                continue;
            }
            // #14322/#15133/#15936: the lease this rule minted is
            // scoped to ITS normalized effective scope (authored scope
            // fields, empty zones replaced by the packet's resolved
            // zones). Keying by the rule — never by `rule.from_zone`
            // alone — keeps an interface-, routing-instance- or
            // global-scoped sibling that shares the pool from
            // authorizing (or denying) inbound on this rule's lease:
            // the empty-zone spelling used to collapse to UNSCOPED,
            // where any grant bucket admits. The packet pair is the
            // original flow's (internal ingress zone, arrival zone):
            // for a zone-authored rule the internal side IS
            // `rule.from_zone`. For a non-zone rule this pre-routing
            // reader knows only the arrival zone, so it spells
            // (arrival, arrival) and the allocator's #15936 authored
            // fallback recovers the grant via the mint provenance
            // recorded on the bucket — never UNSCOPED.
            let arrival_scope = crate::nat::NatScopeCtx {
                ingress_ifname: scope.ifname,
                ingress_routing_instance: scope.routing_instance,
                ..crate::nat::NatScopeCtx::default()
            };
            let packet_from_zone: &str = if rule.from_zone.is_empty() {
                scope.zone_name
            } else {
                &rule.from_zone
            };
            match if persistent_peek {
                rule.pool_allocator.persistent_inbound_peek_for_rule(
                    meta.protocol,
                    resolution_target,
                    flow.forward_key.dst_port,
                    flow.forward_key.src_ip,
                    flow.forward_key.src_port,
                    now_ns,
                    rule,
                    scope.zone_name,
                    packet_from_zone,
                    scope.zone_name,
                    &arrival_scope,
                )
            } else {
                rule.pool_allocator.persistent_inbound_lookup_for_rule(
                    meta.protocol,
                    resolution_target,
                    flow.forward_key.dst_port,
                    flow.forward_key.src_ip,
                    flow.forward_key.src_port,
                    now_ns,
                    rule,
                    scope.zone_name,
                    packet_from_zone,
                    scope.zone_name,
                    &arrival_scope,
                )
            } {
                PersistentInbound::Miss => {}
                PersistentInbound::Denied => {
                    persistent_dnat_denied = true;
                }
                PersistentInbound::Permitted {
                    internal_ip,
                    internal_port,
                    address_only,
                    lease_key,
                } => {
                    let candidate = NatDecision {
                        rewrite_dst: Some(internal_ip),
                        rewrite_dst_port: (!address_only).then_some(internal_port),
                        ..NatDecision::default()
                    };
                    if persistent_dnat.is_some_and(|previous| previous != candidate) {
                        persistent_dnat_denied = true;
                    } else {
                        if persistent_dnat.is_none() {
                            persistent_lease_hold = lease_key;
                        }
                        persistent_dnat = Some(candidate);
                    }
                }
            }
        }
        if persistent_dnat_denied {
            return PreroutingDnatVerdict::Denied;
        }
        if let Some(decision) = persistent_dnat {
            return PreroutingDnatVerdict::Persistent(decision, persistent_lease_hold);
        }
    }
    // Dynamic DNAT pool last. #14947: a poisoned DNAT claim drops the
    // packet — it must not fall through to NPTv6/NAT64/policy as
    // untranslated transit.
    if forwarding.dnat_table.is_empty() {
        return PreroutingDnatVerdict::None;
    }
    // #16045: tri-state form fails closed on scope-constrained matches
    // under ambiguous provenance.
    let (lookup, counter) = if scope_ambiguous {
        forwarding
            .dnat_table
            .lookup_result_ambiguous_provenance_scoped(
                meta.protocol,
                flow.forward_key.src_ip,
                resolution_target,
                flow.forward_key.src_port,
                flow.forward_key.dst_port,
                scope.zone_name,
                scope.ifname,
                scope.routing_instance,
                packet_icmp,
            )
    } else {
        forwarding.dnat_table.lookup_result_with_counter_scoped(
            meta.protocol,
            flow.forward_key.src_ip,
            resolution_target,
            flow.forward_key.src_port,
            flow.forward_key.dst_port,
            scope.zone_name,
            scope.ifname,
            scope.routing_instance,
            packet_icmp,
        )
    };
    match lookup {
        crate::nat::DnatLookup::Matched(decision) => {
            PreroutingDnatVerdict::Dynamic(decision, counter)
        }
        crate::nat::DnatLookup::Poisoned => PreroutingDnatVerdict::Poisoned(counter),
        crate::nat::DnatLookup::NoMatch => PreroutingDnatVerdict::None,
    }
}

#[cfg(test)]
#[path = "prerouting_dnat_tests.rs"]
mod tests;
