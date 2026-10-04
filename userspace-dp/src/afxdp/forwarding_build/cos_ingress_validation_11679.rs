use super::*;

pub(super) fn validate_consumed_ingress_classifier_domains(
    iface: &InterfaceSnapshot,
    tables: &ClassifierTables<'_>,
    ingress_bindings: CoSIngressClassifierBindings,
) -> Result<(), crate::policy::SnapshotIntegrityError> {
    if iface.ifindex <= 0
        || iface.is_unit == Some(false)
        || ingress_bindings == CoSIngressClassifierBindings::default()
    {
        return Ok(());
    }

    // Reuse the existing egress builders with no materialized queue set: only
    // their fail-closed code-point-domain checks matter for ingress-only units.
    let no_materialized_queues: &[u8] = &[];
    if ingress_bindings.dscp.is_some() {
        let _ = build_cos_dscp_queue_table(
            &iface.cos_dscp_classifier,
            &tables.dscp_classifiers,
            no_materialized_queues,
            0,
        )?;
        let _ = build_cos_dscp_lp_table(&iface.cos_dscp_classifier, &tables.dscp_classifiers)?;
    }
    if ingress_bindings.inet_precedence.is_some() {
        let _ = build_cos_inet_precedence_queue_table(
            &iface.cos_inet_precedence_classifier,
            &tables.inet_precedence_classifiers,
            no_materialized_queues,
            0,
        )?;
        let _ = build_cos_inet_precedence_lp_table(
            &iface.cos_inet_precedence_classifier,
            &tables.inet_precedence_classifiers,
        )?;
    }
    if ingress_bindings.ieee8021.is_some() {
        let _ = build_cos_ieee8021_queue_table(
            &iface.cos_ieee8021_classifier,
            &tables.ieee8021_classifiers,
            no_materialized_queues,
            0,
        )?;
        let _ = build_cos_ieee8021_lp_table(
            &iface.cos_ieee8021_classifier,
            &tables.ieee8021_classifiers,
        )?;
    }
    Ok(())
}
