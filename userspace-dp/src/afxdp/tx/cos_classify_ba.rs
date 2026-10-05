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
            .and_then(|classifier| classifier.queue_by_dscp[usize::from(dscp & 0x3f)])
            .or_else(|| {
                trust
                    .inet_precedence
                    .and_then(|index| forwarding.cos.inet_precedence_classifier_tables.get(index))
                    .and_then(|classifier| {
                        classifier.queue_by_prec[usize::from((dscp >> 3) & 0x7)]
                    })
            })
            .or_else(|| {
                if !vlan_present {
                    return None;
                }
                trust
                    .ieee8021
                    .and_then(|index| forwarding.cos.ieee8021_classifier_tables.get(index))
                    .and_then(|classifier| {
                        classifier
                            .queue_by_pcp
                            .get(usize::from(ingress_pcp))
                            .copied()
                            .flatten()
                    })
            })
    }?;
    let word = egress_iface.queue_id_bitmap[usize::from(queue_id) >> 6];
    let bit = 1_u64 << (queue_id & 63);
    Some(if word & bit != 0 {
        queue_id
    } else {
        egress_iface.default_queue
    })
}

/// Resolve the current packet's ingress-classified loss-priority. Each binding
/// is read only when higher-precedence classifiers leave this code-point
/// unclassified.
pub(super) fn resolve_trusted_ba_loss_priority(
    lp: &CoSLossPriorityRewrite,
    forwarding: &ForwardingState,
    ingress_ifindex: u32,
    dscp: u8,
    ingress_pcp: u8,
    vlan_present: bool,
    trust: BaIngressTrust,
) -> u8 {
    if ingress_ifindex == 0 {
        let dscp_lp = lp.dscp_lp_by_dscp[usize::from(dscp & 0x3f)];
        if dscp_lp != u8::MAX {
            return dscp_lp;
        }
        let precedence_lp = lp.inet_precedence_lp_by_prec[usize::from((dscp >> 3) & 0x7)];
        if precedence_lp != u8::MAX {
            return precedence_lp;
        }
        if vlan_present {
            let pcp_lp = lp
                .ieee8021_lp_by_pcp
                .get(usize::from(ingress_pcp))
                .copied()
                .unwrap_or(u8::MAX);
            if pcp_lp != u8::MAX {
                return pcp_lp;
            }
        }
        return 0;
    }

    let dscp_lp = trust
        .dscp
        .and_then(|index| forwarding.cos.dscp_classifier_tables.get(index))
        .map(|classifier| classifier.lp_by_dscp[usize::from(dscp & 0x3f)])
        .unwrap_or(u8::MAX);
    if dscp_lp != u8::MAX {
        return dscp_lp;
    }
    let precedence_lp = trust
        .inet_precedence
        .and_then(|index| forwarding.cos.inet_precedence_classifier_tables.get(index))
        .map(|classifier| classifier.lp_by_prec[usize::from((dscp >> 3) & 0x7)])
        .unwrap_or(u8::MAX);
    if precedence_lp != u8::MAX {
        return precedence_lp;
    }
    if vlan_present {
        let pcp_lp = trust
            .ieee8021
            .and_then(|index| forwarding.cos.ieee8021_classifier_tables.get(index))
            .and_then(|classifier| classifier.lp_by_pcp.get(usize::from(ingress_pcp)).copied())
            .unwrap_or(u8::MAX);
        if pcp_lp != u8::MAX {
            return pcp_lp;
        }
    }
    0
}
/// #3995/#11430/#11679: resolve the egress DSCP rewrite for this packet's
/// egress queue and ingress-classified loss-priority. Returns `None` when the
/// egress interface has no matching rewrite pair; filter rewrites take
/// precedence over this CoS result.
pub(super) fn resolve_cos_queue_lp_rewrite(
    forwarding: &ForwardingState,
    egress_ifindex: i32,
    ingress_ifindex: u32,
    queue_id: u8,
    dscp: u8,
    ingress_pcp: u8,
    vlan_present: bool,
    trust: BaIngressTrust,
) -> Option<u8> {
    let lp = forwarding.cos.lp_rewrite.get(&egress_ifindex)?;
    let plp = resolve_trusted_ba_loss_priority(
        lp,
        forwarding,
        ingress_ifindex,
        dscp,
        ingress_pcp,
        vlan_present,
        trust,
    );
    lp.dscp_rewrite_by_queue_lp.get(&(queue_id, plp)).copied()
}
