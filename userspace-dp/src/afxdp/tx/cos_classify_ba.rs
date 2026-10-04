use super::*;

/// Behavior-aggregate trust from the ingress unit's classifier bindings.
pub(super) type BaIngressTrust = crate::afxdp::types::CoSIngressClassifierBindings;

/// Read the classifier-type bindings from the logical ingress unit.
pub(super) fn ba_ingress_trust(
    forwarding: &ForwardingState,
    ingress_ifindex: u32,
    ingress_vlan_id: u16,
) -> BaIngressTrust {
    if ingress_ifindex == 0 {
        // Locally generated replies have no wire ingress. Their classifier
        // source is handled by the egress interface's existing compiled tables.
        return BaIngressTrust::default();
    }
    let logical = resolve_ingress_logical_ifindex(
        forwarding,
        ingress_ifindex as i32,
        ingress_vlan_id,
    )
    .unwrap_or(ingress_ifindex as i32);
    forwarding
        .cos
        .ingress_classifier_bindings
        .get(&logical)
        .copied()
        .unwrap_or_default()
}

/// Resolve the BA queue from the logical ingress unit's indexed classifier
/// tables, then clamp it to the egress interface's materialized queue set.
/// Locally generated packets have no ingress binding and retain the legacy
/// egress-classifier lookup.
pub(super) fn resolve_trusted_ba_queue_id(
    forwarding: &ForwardingState,
    egress_iface: &CoSInterfaceConfig,
    ingress_ifindex: u32,
    dscp: u8,
    ingress_pcp: u8,
    vlan_present: bool,
    trust: BaIngressTrust,
) -> Option<u8> {
    let queue_id = if ingress_ifindex == 0 {
        resolve_cos_dscp_classifier_queue_id(egress_iface, dscp)
            .or_else(|| resolve_cos_inet_precedence_classifier_queue_id(egress_iface, dscp))
            .or_else(|| {
                resolve_cos_ieee8021_classifier_queue_id(
                    egress_iface,
                    ingress_pcp,
                    vlan_present,
                )
            })
    } else {
        trust
            .dscp
            .and_then(|index| forwarding.cos.dscp_classifier_tables.get(index))
            .and_then(|classifier| classifier.queue_by_dscp.get(&(dscp & 0x3f)).copied())
            .or_else(|| {
                trust
                    .inet_precedence
                    .and_then(|index| forwarding.cos.inet_precedence_classifier_tables.get(index))
                    .and_then(|classifier| {
                        classifier
                            .queue_by_prec
                            .get(&((dscp >> 3) & 0x7))
                            .copied()
                    })
            })
            .or_else(|| {
                if !vlan_present {
                    return None;
                }
                trust
                    .ieee8021
                    .and_then(|index| forwarding.cos.ieee8021_classifier_tables.get(index))
                    .and_then(|classifier| classifier.queue_by_pcp.get(&ingress_pcp).copied())
            })
    }?;
    Some(if egress_iface.queues.iter().any(|queue| queue.queue_id == queue_id) {
        queue_id
    } else {
        egress_iface.default_queue
    })
}
