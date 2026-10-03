use super::*;

/// #11386: classifier trust on the logical ingress unit. Wire markings from a
/// unit without the corresponding binding must not select an egress BA queue.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct BaIngressTrust {
    pub(super) dscp: bool,
    pub(super) inet_precedence: bool,
    pub(super) ieee8021: bool,
}

/// Read the classifier-type bindings from the logical ingress unit.
pub(super) fn ba_ingress_trust(
    forwarding: &ForwardingState,
    ingress_ifindex: u32,
    ingress_vlan_id: u16,
) -> BaIngressTrust {
    let logical = resolve_ingress_logical_ifindex(
        forwarding,
        ingress_ifindex as i32,
        ingress_vlan_id,
    )
    .unwrap_or(ingress_ifindex as i32);
    let Some(ingress) = forwarding.cos.interfaces.get(&logical) else {
        return BaIngressTrust::default();
    };
    BaIngressTrust {
        dscp: !ingress.dscp_classifier.is_empty(),
        inet_precedence: !ingress.inet_precedence_classifier.is_empty(),
        ieee8021: !ingress.ieee8021_classifier.is_empty(),
    }
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
