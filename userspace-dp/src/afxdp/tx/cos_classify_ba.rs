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

/// #16506 (with Y28-05): resolve the egress DSCP rewrite keyed ONLY on the
/// packet's FINAL forwarding class. The rewrite rule is keyed
/// `(forwarding-class, loss-priority)` (docs/cos-traffic-shaping.md, #3995),
/// so the only legitimate keys are the final class's own entry and — when
/// that final class is materialized on the egress interface — the entry
/// compiled under its own queue. There is deliberately NO fallback to any
/// other class:
///
/// - With a filter class (`filter_class_queue_id: Some`): the filter class
///   is the final class (#14636/#14663). The overridden BA class's entry and
///   the clamped/pinned queue's entry (that queue is the filter class's
///   materialized queue, the default queue when the class is
///   unmaterialized, or a scheduler alias — in the alias and default cases
///   it carries a DIFFERENT class's entry) must never supply the rewrite.
///   A filter class absent from the rule is "not rewritten" (`None`).
/// - Without a filter class the BA class is the final class. Its own entry
///   keys first (#13968); the queue entry is consulted only when that queue
///   IS the BA class's own materialized queue — i.e. the class is
///   materialized on egress, so both keys name the same
///   `(class, loss-priority)` entry. An unmaterialized BA class clamped to
///   the default queue must not inherit the default queue's class entry
///   (Y28-05).
/// - With NO class at all (unclassified / locally generated): the egress
///   queue itself is the classification result, so its own entry keys the
///   rewrite — the pre-#13968 queue-keyed behaviour, preserved.
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
    // The final class: a filter-selected class outranks BA classification;
    // otherwise the packet's BA class. `None` = no class was ever assigned.
    if let Some(final_class_queue_id) = filter_class_queue_id.or(class_queue_id) {
        if let Some(rewrite) = lp
            .dscp_rewrite_by_fc_lp
            .get(&(final_class_queue_id, plp))
            .copied()
        {
            return Some(rewrite);
        }
        // Queue-keyed fallback ONLY when the egress queue is the final
        // class's own materialized queue (its global queue id), so the
        // `(queue, LP)` entry names the same `(class, LP)` pair as the
        // class key above. This preserves the queue-compiled view for a
        // materialized class (the two tables are compiled from the same
        // rule, so for a materialized class they agree); it never crosses
        // to another class's entry.
        if queue_id == final_class_queue_id {
            return lp.dscp_rewrite_by_queue_lp.get(&(queue_id, plp)).copied();
        }
        return None;
    }
    // No class was ever assigned (both class ids `None`): there is no
    // final class, but the egress queue itself was still selected (egress
    // classifiers for locally generated packets, or the interface
    // default). The queue IS the classification result in that case, so
    // its own entry keys the rewrite exactly as the pre-#13968
    // queue-keyed resolver did. This arm must NOT run when a class WAS
    // assigned: then the queue may be a clamp/alias carrying another
    // class's entry (#16506/Y28-05).
    lp.dscp_rewrite_by_queue_lp.get(&(queue_id, plp)).copied()
}

/// #13968/#16506: resolve the egress DSCP rewrite by the packet's ORIGINAL
/// forwarding-class (its pre-clamp BA class queue id) and loss-priority.
/// Without a filter class the BA class IS the final class, so this shares
/// the final-class-only keying of
/// [`resolve_cos_priority_class_lp_rewrite`]: the class's own entry, then
/// the queue entry only when the queue is that class's own materialized
/// queue. When the class is not materialized, the clamped queue's class
/// (usually best-effort) must not bleach the packet's marking (Y28-05).
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
    resolve_cos_priority_class_lp_rewrite(
        forwarding,
        egress_ifindex,
        ingress_ifindex,
        None,
        class_queue_id,
        queue_id,
        dscp,
        ingress_pcp,
        vlan_present,
        trust,
    )
}
