use super::build_cos_state;
use crate::protocol::snapshot::{ConfigSnapshot, InterfaceSnapshot};
use crate::protocol::{
    ClassOfServiceSnapshot, CoSDSCPRewriteRuleEntrySnapshot, CoSDSCPRewriteRuleSnapshot,
    CoSForwardingClassSnapshot, CoSSchedulerMapEntrySnapshot, CoSSchedulerMapSnapshot,
    CoSSchedulerSnapshot,
};

fn snapshot_with_cos(
    units: Vec<InterfaceSnapshot>,
    class_of_service: ClassOfServiceSnapshot,
) -> ConfigSnapshot {
    ConfigSnapshot {
        interfaces: units,
        class_of_service: Some(class_of_service),
        ..Default::default()
    }
}

fn snapshot_with_units(units: Vec<InterfaceSnapshot>) -> ConfigSnapshot {
    snapshot_with_cos(units, ClassOfServiceSnapshot::default())
}

fn unit(name: &str, ifindex: i32, shaping_rate: u64) -> InterfaceSnapshot {
    InterfaceSnapshot {
        name: name.to_string(),
        ifindex,
        is_unit: Some(true),
        cos_shaping_rate_bytes_per_sec: shaping_rate,
        ..Default::default()
    }
}

fn assert_duplicate_ifindex(snapshot: &ConfigSnapshot) {
    match build_cos_state(snapshot) {
        Err(crate::policy::SnapshotIntegrityError::CosDuplicateUnitIfindex {
            ifindex,
            first_interface,
            second_interface,
        }) => {
            assert_eq!(ifindex, 42);
            assert_eq!(first_interface, "wg0.0");
            assert_eq!(second_interface, "wg0.1");
        }
        other => panic!("expected duplicate-unit-ifindex integrity error, got {other:?}"),
    }
}

fn scheduler_map_cos() -> ClassOfServiceSnapshot {
    ClassOfServiceSnapshot {
        forwarding_classes: vec![CoSForwardingClassSnapshot {
            name: "best-effort".to_string(),
            queue: 0,
        }],
        schedulers: vec![
            CoSSchedulerSnapshot {
                name: "scheduler-15m".to_string(),
                transmit_rate_bytes: 15_000_000,
                ..Default::default()
            },
            CoSSchedulerSnapshot {
                name: "scheduler-5m".to_string(),
                transmit_rate_bytes: 5_000_000,
                ..Default::default()
            },
        ],
        scheduler_maps: vec![
            CoSSchedulerMapSnapshot {
                name: "map-15m".to_string(),
                entries: vec![CoSSchedulerMapEntrySnapshot {
                    forwarding_class: "best-effort".to_string(),
                    scheduler: "scheduler-15m".to_string(),
                }],
            },
            CoSSchedulerMapSnapshot {
                name: "map-5m".to_string(),
                entries: vec![CoSSchedulerMapEntrySnapshot {
                    forwarding_class: "best-effort".to_string(),
                    scheduler: "scheduler-5m".to_string(),
                }],
            },
        ],
        ..Default::default()
    }
}
fn loss_priority_rewrite_cos() -> ClassOfServiceSnapshot {
    let rule = |name: &str, high_dscp| CoSDSCPRewriteRuleSnapshot {
        name: name.to_string(),
        entries: vec![
            CoSDSCPRewriteRuleEntrySnapshot {
                forwarding_class: "best-effort".to_string(),
                loss_priority: "low".to_string(),
                dscp_value: 10,
            },
            CoSDSCPRewriteRuleEntrySnapshot {
                forwarding_class: "best-effort".to_string(),
                loss_priority: "medium-low".to_string(),
                dscp_value: 10,
            },
            CoSDSCPRewriteRuleEntrySnapshot {
                forwarding_class: "best-effort".to_string(),
                loss_priority: "medium-high".to_string(),
                dscp_value: 10,
            },
            CoSDSCPRewriteRuleEntrySnapshot {
                forwarding_class: "best-effort".to_string(),
                loss_priority: "high".to_string(),
                dscp_value: high_dscp,
            },
        ],
    };
    ClassOfServiceSnapshot {
        forwarding_classes: vec![CoSForwardingClassSnapshot {
            name: "best-effort".to_string(),
            queue: 0,
        }],
        dscp_rewrite_rules: vec![rule("rewrite-a", 20), rule("rewrite-b", 30)],
        ..Default::default()
    }
}

#[test]
fn differing_cos_for_logical_units_sharing_ifindex_rejects_snapshot() {
    // A shared netdev cannot enforce separate shaping rates for these units;
    // accepting the snapshot silently makes whichever row is visited last win.
    let snapshot = snapshot_with_units(vec![
        unit("wg0.0", 42, 15_000_000),
        unit("wg0.1", 42, 5_000_000),
    ]);

    assert_duplicate_ifindex(&snapshot);
}
#[test]
fn differing_scheduler_maps_for_logical_units_sharing_ifindex_reject_snapshot() {
    let mut unit_0 = unit("wg0.0", 42, 100_000_000);
    unit_0.cos_scheduler_map = "map-15m".to_string();
    let mut unit_1 = unit("wg0.1", 42, 100_000_000);
    unit_1.cos_scheduler_map = "map-5m".to_string();
    let snapshot = snapshot_with_cos(vec![unit_0, unit_1], scheduler_map_cos());

    assert_duplicate_ifindex(&snapshot);
}
#[test]
fn differing_loss_priority_rewrites_for_shared_ifindex_reject_snapshot() {
    let mut unit_0 = unit("wg0.0", 42, 100_000_000);
    unit_0.cos_dscp_rewrite_rule = "rewrite-a".to_string();
    let mut unit_1 = unit("wg0.1", 42, 100_000_000);
    unit_1.cos_dscp_rewrite_rule = "rewrite-b".to_string();
    let snapshot = snapshot_with_cos(vec![unit_0, unit_1], loss_priority_rewrite_cos());

    assert_duplicate_ifindex(&snapshot);
}

#[test]
fn identical_cos_for_logical_units_sharing_ifindex_remains_valid() {
    let snapshot = snapshot_with_units(vec![
        unit("wg0.0", 42, 15_000_000),
        unit("wg0.1", 42, 15_000_000),
    ]);

    let state = build_cos_state(&snapshot).expect("identical CoS settings are unambiguous");
    assert_eq!(state.interfaces[&42].shaping_rate_bytes, 15_000_000);
}
#[test]
fn configured_and_unconfigured_units_sharing_ifindex_reject_snapshot() {
    let snapshot = snapshot_with_units(vec![unit("wg0.0", 42, 15_000_000), unit("wg0.1", 42, 0)]);

    assert_duplicate_ifindex(&snapshot);
}

#[test]
fn base_interface_alias_does_not_conflict_with_unit_cos() {
    let base = InterfaceSnapshot {
        name: "wg0".to_string(),
        ifindex: 42,
        is_unit: Some(false),
        ..Default::default()
    };
    let snapshot = snapshot_with_units(vec![base, unit("wg0.0", 42, 15_000_000)]);

    let state = build_cos_state(&snapshot).expect("base alias is not a sibling CoS unit");
    assert_eq!(state.interfaces[&42].shaping_rate_bytes, 15_000_000);
}
