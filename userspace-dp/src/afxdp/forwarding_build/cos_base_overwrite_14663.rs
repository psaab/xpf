//! #14663 leg 4: a base-interface row (`is_unit == Some(false)`) sharing an
//! ifindex with a logical unit must not overwrite the unit's CoS runtime
//! state (`lp_rewrite` / `interfaces`), regardless of row order.

use super::build_cos_state;
use crate::protocol::snapshot::{ConfigSnapshot, InterfaceSnapshot};
use crate::protocol::{
    ClassOfServiceSnapshot, CoSDSCPRewriteRuleEntrySnapshot, CoSDSCPRewriteRuleSnapshot,
    CoSForwardingClassSnapshot, CoSSchedulerMapEntrySnapshot, CoSSchedulerMapSnapshot,
    CoSSchedulerSnapshot,
};

fn cos_14663() -> ClassOfServiceSnapshot {
    ClassOfServiceSnapshot {
        forwarding_classes: vec![
            CoSForwardingClassSnapshot {
                name: "best-effort".to_string(),
                queue: 0,
            },
            CoSForwardingClassSnapshot {
                name: "expedited-forwarding".to_string(),
                queue: 5,
            },
        ],
        schedulers: vec![
            CoSSchedulerSnapshot {
                name: "unit-sched".to_string(),
                transmit_rate_bytes: 15_000_000,
                ..Default::default()
            },
            CoSSchedulerSnapshot {
                name: "base-sched".to_string(),
                transmit_rate_bytes: 5_000_000,
                ..Default::default()
            },
        ],
        scheduler_maps: vec![
            CoSSchedulerMapSnapshot {
                name: "unit-map".to_string(),
                entries: vec![CoSSchedulerMapEntrySnapshot {
                    forwarding_class: "expedited-forwarding".to_string(),
                    scheduler: "unit-sched".to_string(),
                }],
            },
            CoSSchedulerMapSnapshot {
                name: "base-map".to_string(),
                entries: vec![CoSSchedulerMapEntrySnapshot {
                    forwarding_class: "best-effort".to_string(),
                    scheduler: "base-sched".to_string(),
                }],
            },
        ],
        dscp_rewrite_rules: vec![
            CoSDSCPRewriteRuleSnapshot {
                name: "unit-rw".to_string(),
                entries: vec![CoSDSCPRewriteRuleEntrySnapshot {
                    forwarding_class: "expedited-forwarding".to_string(),
                    loss_priority: "low".to_string(),
                    dscp_value: 46,
                }],
            },
            CoSDSCPRewriteRuleSnapshot {
                name: "base-rw".to_string(),
                entries: vec![CoSDSCPRewriteRuleEntrySnapshot {
                    forwarding_class: "best-effort".to_string(),
                    loss_priority: "low".to_string(),
                    dscp_value: 7,
                }],
            },
        ],
        ..Default::default()
    }
}

fn unit_row() -> InterfaceSnapshot {
    InterfaceSnapshot {
        name: "ge-0/0/0.0".to_string(),
        ifindex: 42,
        is_unit: Some(true),
        cos_shaping_rate_bytes_per_sec: 15_000_000,
        cos_scheduler_map: "unit-map".to_string(),
        cos_dscp_rewrite_rule: "unit-rw".to_string(),
        ..Default::default()
    }
}

fn base_row() -> InterfaceSnapshot {
    InterfaceSnapshot {
        name: "ge-0/0/0".to_string(),
        ifindex: 42,
        is_unit: Some(false),
        cos_shaping_rate_bytes_per_sec: 5_000_000,
        cos_scheduler_map: "base-map".to_string(),
        cos_dscp_rewrite_rule: "base-rw".to_string(),
        ..Default::default()
    }
}

fn assert_unit_state_wins(rows: Vec<InterfaceSnapshot>, order: &str) {
    let snapshot = ConfigSnapshot {
        interfaces: rows,
        class_of_service: Some(cos_14663()),
        ..Default::default()
    };
    let state = build_cos_state(&snapshot).expect("base+unit snapshot must build");
    let cfg = state
        .interfaces
        .get(&42)
        .unwrap_or_else(|| panic!("{order}: unit CoS interface state must survive the base row"));
    assert_eq!(
        cfg.shaping_rate_bytes, 15_000_000,
        "{order}: base row must not overwrite the unit's shaping rate"
    );
    let lp = state
        .lp_rewrite
        .get(&42)
        .unwrap_or_else(|| panic!("{order}: unit lp_rewrite must survive the base row"));
    assert_eq!(
        lp.dscp_rewrite_by_fc_lp.get(&(5, 0)),
        Some(&46),
        "{order}: unit EF rewrite (46) must survive; base BE rewrite must not replace it"
    );
    assert_ne!(
        lp.dscp_rewrite_by_fc_lp.get(&(0, 0)),
        Some(&7),
        "{order}: base row's rewrite (7) must not be installed under the unit's ifindex"
    );
}

#[test]
fn base_row_after_unit_does_not_overwrite_unit_cos_14663() {
    assert_unit_state_wins(vec![unit_row(), base_row()], "unit-then-base");
}

#[test]
fn base_row_before_unit_does_not_block_unit_cos_14663() {
    // Control/order twin: unit after base must still install (first-wins for
    // the unit domain, base never counts as the first unit).
    assert_unit_state_wins(vec![base_row(), unit_row()], "base-then-unit");
}
