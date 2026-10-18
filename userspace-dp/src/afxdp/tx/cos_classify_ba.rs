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

/// Read BA bindings from the validated peer logical unit when the V2 fabric
/// stamp carries one; otherwise use this packet's local ingress identity.
pub(super) fn ba_ingress_trust_for_packet(
    forwarding: &ForwardingState,
    meta: impl Into<ForwardPacketMeta>,
) -> BaIngressTrust {
    let meta = meta.into();
    if meta.fabric_ingress_ifindex != 0 {
        return forwarding
            .cos
            .ingress_classifier_bindings
            .get(&(meta.fabric_ingress_ifindex as i32))
            .copied()
            .unwrap_or_default();
    }
    ba_ingress_trust(forwarding, meta.ingress_ifindex, meta.ingress_vlan_id)
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
    let queue_id = resolve_trusted_ba_class_queue_id(
        forwarding,
        egress_iface,
        ingress_ifindex,
        dscp,
        ingress_pcp,
        vlan_present,
        trust,
    )?;
    let word = egress_iface.queue_id_bitmap[usize::from(queue_id) >> 6];
    let bit = 1_u64 << (queue_id & 63);
    Some(if word & bit != 0 {
        queue_id
    } else {
        egress_iface.default_queue
    })
}

/// #13968: resolve the packet's ORIGINAL (pre-clamp) forwarding-class queue
/// id from the trusted ingress BA classifiers — the same code-point walk as
/// [`resolve_trusted_ba_queue_id`] but WITHOUT clamping to the egress
/// interface's materialized queue set. The egress DSCP rewrite keys on this
/// class, not on the queue the egress scheduler happened to materialize:
/// when the class has no scheduler-map entry on egress the queue clamps to
/// the default queue, but the packet must still be re-marked by its own
/// class's rewrite entry. Returns `None` when no BA classifier matches.
pub(super) fn resolve_trusted_ba_class_queue_id(
    forwarding: &ForwardingState,
    egress_iface: &CoSInterfaceConfig,
    ingress_ifindex: u32,
    dscp: u8,
    ingress_pcp: u8,
    vlan_present: bool,
    trust: BaIngressTrust,
) -> Option<u8> {
    if ingress_ifindex == 0 {
        return resolve_cos_dscp_classifier_queue_id(egress_iface, dscp)
            .or_else(|| resolve_cos_inet_precedence_classifier_queue_id(egress_iface, dscp))
            .or_else(|| {
                resolve_cos_ieee8021_classifier_queue_id(egress_iface, ingress_pcp, vlan_present)
            });
    }
    trust
        .dscp
        .and_then(|index| forwarding.cos.dscp_classifier_tables.get(index))
        .and_then(|classifier| classifier.queue_by_dscp[usize::from(dscp & 0x3f)])
        .or_else(|| {
            trust
                .inet_precedence
                .and_then(|index| forwarding.cos.inet_precedence_classifier_tables.get(index))
                .and_then(|classifier| classifier.queue_by_prec[usize::from((dscp >> 3) & 0x7)])
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

/// #14636: resolve the egress DSCP rewrite with an explicit forwarding-class
/// queue id taking precedence over the packet's BA class: a filter-selected
/// class overrides BA classification, so the rewrite must key on that class
/// first, then the BA class, then the clamped queue.
#[allow(clippy::too_many_arguments)]
pub(super) fn resolve_cos_priority_class_lp_rewrite(
    forwarding: &ForwardingState,
    egress_ifindex: i32,
    ingress_ifindex: u32,
    filter_class_queue_id: Option<u8>,
    class_queue_id: Option<u8>,
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
    filter_class_queue_id
        .and_then(|cq| lp.dscp_rewrite_by_fc_lp.get(&(cq, plp)).copied())
        .or_else(|| {
            class_queue_id.and_then(|cq| lp.dscp_rewrite_by_fc_lp.get(&(cq, plp)).copied())
        })
        .or_else(|| lp.dscp_rewrite_by_queue_lp.get(&(queue_id, plp)).copied())
}

/// #13968: resolve the egress DSCP rewrite by the packet's ORIGINAL
/// forwarding-class (its pre-clamp BA class queue id) and loss-priority,
/// falling back to the clamped-queue entry only when the class has no
/// rewrite entry of its own. When the class IS materialized on egress both
/// keys name the same (class, LP) entry, so this is bit-identical to
/// [`resolve_cos_queue_lp_rewrite`]; when it is not, the clamped queue's
/// class (usually best-effort) must not bleach the packet's marking.
#[allow(clippy::too_many_arguments)]
pub(super) fn resolve_cos_class_lp_rewrite(
    forwarding: &ForwardingState,
    egress_ifindex: i32,
    ingress_ifindex: u32,
    class_queue_id: Option<u8>,
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
    class_queue_id
        .and_then(|cq| lp.dscp_rewrite_by_fc_lp.get(&(cq, plp)).copied())
        .or_else(|| lp.dscp_rewrite_by_queue_lp.get(&(queue_id, plp)).copied())
}
