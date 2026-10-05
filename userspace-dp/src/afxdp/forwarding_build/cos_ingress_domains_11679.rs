use super::build_cos_state;
use crate::protocol::snapshot::{ConfigSnapshot, InterfaceSnapshot};
use crate::protocol::{
    ClassOfServiceSnapshot, CoSDSCPClassifierEntrySnapshot, CoSDSCPClassifierSnapshot,
    CoSForwardingClassSnapshot, CoSIEEE8021ClassifierEntrySnapshot,
    CoSIEEE8021ClassifierSnapshot, CoSINetPrecedenceClassifierEntrySnapshot,
    CoSINetPrecedenceClassifierSnapshot, CoSSchedulerMapEntrySnapshot, CoSSchedulerMapSnapshot,
    CoSSchedulerSnapshot,
};

fn ingress_only_snapshot(
    class_of_service: ClassOfServiceSnapshot,
    classifier_kind: &str,
    classifier_name: &str,
) -> ConfigSnapshot {
    let mut ingress = InterfaceSnapshot {
        name: "xe0.0".to_string(),
        ifindex: 42,
        is_unit: Some(true),
        ..Default::default()
    };
    match classifier_kind {
        "dscp" => ingress.cos_dscp_classifier = classifier_name.to_string(),
        "pcp" => ingress.cos_ieee8021_classifier = classifier_name.to_string(),
        "precedence" => ingress.cos_inet_precedence_classifier = classifier_name.to_string(),
        _ => unreachable!("test passes a known classifier kind"),
    }
    ConfigSnapshot {
        interfaces: vec![ingress],
        class_of_service: Some(class_of_service),
        ..Default::default()
    }
}

fn ingress_only_classes() -> Vec<CoSForwardingClassSnapshot> {
    vec![
        CoSForwardingClassSnapshot {
            name: "best-effort".to_string(),
            queue: 0,
        },
        CoSForwardingClassSnapshot {
            name: "voice".to_string(),
            queue: 5,
        },
    ]
}

#[test]
fn consumed_ingress_dscp_domain_is_validated_without_egress_cos_admission_11679() {
    let cos = ClassOfServiceSnapshot {
        forwarding_classes: ingress_only_classes(),
        dscp_classifiers: vec![CoSDSCPClassifierSnapshot {
            name: "bad-dscp".to_string(),
            entries: vec![CoSDSCPClassifierEntrySnapshot {
                forwarding_class: "voice".to_string(),
                loss_priority: "high".to_string(),
                dscp_values: vec![110],
            }],
        }],
        ..Default::default()
    };
    let result = build_cos_state(&ingress_only_snapshot(cos, "dscp", "bad-dscp"));
    assert!(matches!(
        result,
        Err(crate::policy::SnapshotIntegrityError::CosDscpCodePointOutOfRange {
            classifier,
            dscp: 110,
        }) if classifier == "bad-dscp"
    ));
}

#[test]
fn consumed_ingress_pcp_domain_is_validated_without_egress_cos_admission_11679() {
    let cos = ClassOfServiceSnapshot {
        forwarding_classes: ingress_only_classes(),
        ieee8021_classifiers: vec![CoSIEEE8021ClassifierSnapshot {
            name: "bad-pcp".to_string(),
            entries: vec![CoSIEEE8021ClassifierEntrySnapshot {
                forwarding_class: "voice".to_string(),
                loss_priority: "high".to_string(),
                code_points: vec![9],
            }],
        }],
        ..Default::default()
    };
    let result = build_cos_state(&ingress_only_snapshot(cos, "pcp", "bad-pcp"));
    assert!(matches!(
        result,
        Err(crate::policy::SnapshotIntegrityError::CosIeee8021CodePointOutOfRange {
            classifier,
            pcp: 9,
        }) if classifier == "bad-pcp"
    ));
}

#[test]
fn consumed_ingress_precedence_domain_is_validated_without_egress_cos_admission_11679() {
    let cos = ClassOfServiceSnapshot {
        forwarding_classes: ingress_only_classes(),
        inet_precedence_classifiers: vec![CoSINetPrecedenceClassifierSnapshot {
            name: "bad-precedence".to_string(),
            entries: vec![CoSINetPrecedenceClassifierEntrySnapshot {
                forwarding_class: "voice".to_string(),
                loss_priority: "high".to_string(),
                precedences: vec![8],
            }],
        }],
        ..Default::default()
    };
    let result = build_cos_state(&ingress_only_snapshot(
        cos,
        "precedence",
        "bad-precedence",
    ));
    assert!(matches!(
        result,
        Err(crate::policy::SnapshotIntegrityError::CosInetPrecedenceCodePointOutOfRange {
            classifier,
            precedence: 8,
        }) if classifier == "bad-precedence"
    ));
}

#[test]
fn unbound_invalid_classifier_does_not_fail_ingress_domain_validation_11679() {
    let cos = ClassOfServiceSnapshot {
        forwarding_classes: ingress_only_classes(),
        dscp_classifiers: vec![CoSDSCPClassifierSnapshot {
            name: "unbound-bad-dscp".to_string(),
            entries: vec![CoSDSCPClassifierEntrySnapshot {
                forwarding_class: "voice".to_string(),
                loss_priority: "high".to_string(),
                dscp_values: vec![110],
            }],
        }],
        ..Default::default()
    };
    let snapshot = ingress_only_snapshot(cos, "dscp", "unbound-bad-dscp");
    let mut unbound_snapshot = snapshot;
    unbound_snapshot.interfaces[0].cos_dscp_classifier.clear();

    let state = build_cos_state(&unbound_snapshot)
        .expect("unbound classifier domains are not consumed and remain unchecked");
    assert!(state.ingress_classifier_bindings.is_empty());
}

#[test]
fn queue_255_is_preserved_in_classifier_and_materialized_bitmap_11679() {
    let cos = ClassOfServiceSnapshot {
        forwarding_classes: vec![
            CoSForwardingClassSnapshot {
                name: "best-effort".to_string(),
                queue: 0,
            },
            CoSForwardingClassSnapshot {
                name: "voice".to_string(),
                queue: 255,
            },
        ],
        dscp_classifiers: vec![CoSDSCPClassifierSnapshot {
            name: "voice-dscp".to_string(),
            entries: vec![CoSDSCPClassifierEntrySnapshot {
                forwarding_class: "voice".to_string(),
                loss_priority: "high".to_string(),
                dscp_values: vec![46],
            }],
        }],
        schedulers: vec![CoSSchedulerSnapshot {
            name: "voice-scheduler".to_string(),
            transmit_rate_bytes: 1_000_000,
            ..Default::default()
        }],
        scheduler_maps: vec![CoSSchedulerMapSnapshot {
            name: "voice-map".to_string(),
            entries: vec![CoSSchedulerMapEntrySnapshot {
                forwarding_class: "voice".to_string(),
                scheduler: "voice-scheduler".to_string(),
            }],
        }],
        ..Default::default()
    };
    let mut egress = InterfaceSnapshot {
        name: "xe0.0".to_string(),
        ifindex: 42,
        is_unit: Some(true),
        ..Default::default()
    };
    egress.cos_scheduler_map = "voice-map".to_string();
    egress.cos_dscp_classifier = "voice-dscp".to_string();
    let snapshot = ConfigSnapshot {
        interfaces: vec![egress],
        class_of_service: Some(cos),
        ..Default::default()
    };

    let state = build_cos_state(&snapshot).expect("queue 255 is a valid queue id");
    let interface = state.interfaces.get(&42).expect("scheduler map admits CoS");
    assert_eq!(interface.dscp_queue_by_dscp[46], 255);
    assert_ne!(interface.queue_id_bitmap[0] & 1, 0);
    assert_ne!(interface.queue_id_bitmap[3] & (1_u64 << 63), 0);
    assert_eq!(state.dscp_classifier_tables[0].queue_by_dscp[46], Some(255));
}
