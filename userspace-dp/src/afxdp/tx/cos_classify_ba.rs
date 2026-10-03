use super::*;

/// Behavior-aggregate trust from the ingress unit's classifier bindings.
pub(super) type BaIngressTrust = crate::afxdp::types::CoSIngressClassifierBindings;

/// Read the classifier-type bindings from the logical ingress unit.
pub(super) fn ba_ingress_trust(
    forwarding: &ForwardingState,
    ingress_ifindex: u32,
    ingress_vlan_id: u16,
) -> BaIngressTrust {
    // Locally generated replies have no wire ingress; their DSCP/PCP is
    // stack-assigned and retains the pre-gate egress BA behavior.
    if ingress_ifindex == 0 {
        return BaIngressTrust {
            dscp: true,
            inet_precedence: true,
            ieee8021: true,
        };
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

/// Resolve the BA queue, considering only classifier types bound on ingress.
pub(super) fn resolve_trusted_ba_queue_id(
    iface: &CoSInterfaceConfig,
    dscp: u8,
    ingress_pcp: u8,
    vlan_present: bool,
    trust: BaIngressTrust,
) -> Option<u8> {
    (if trust.dscp {
        resolve_cos_dscp_classifier_queue_id(iface, dscp)
    } else {
        None
    })
    .or_else(|| {
        if trust.inet_precedence {
            resolve_cos_inet_precedence_classifier_queue_id(iface, dscp)
        } else {
            None
        }
    })
    .or_else(|| {
        if trust.ieee8021 {
            resolve_cos_ieee8021_classifier_queue_id(iface, ingress_pcp, vlan_present)
        } else {
            None
        }
    })
}
