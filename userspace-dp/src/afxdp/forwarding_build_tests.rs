// Tests for afxdp/forwarding_build.rs — relocated from inline
// `#[cfg(test)] mod tests` to keep forwarding_build.rs under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "forwarding_build_tests.rs"]` from forwarding_build.rs.

use super::*;
use crate::{
    ClassOfServiceSnapshot, CoSDSCPClassifierEntrySnapshot, CoSDSCPClassifierSnapshot,
    CoSDSCPRewriteRuleEntrySnapshot, CoSDSCPRewriteRuleSnapshot, CoSForwardingClassSnapshot,
    CoSIEEE8021ClassifierEntrySnapshot, CoSIEEE8021ClassifierSnapshot,
    CoSSchedulerMapEntrySnapshot, CoSSchedulerMapSnapshot, CoSSchedulerSnapshot,
};

#[test]
fn build_cos_state_translates_scheduler_map_entries() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 42,
            cos_shaping_rate_bytes_per_sec: 10_000_000,
            cos_shaping_burst_bytes: 256_000,
            cos_scheduler_map: "wan-map".into(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![
                CoSForwardingClassSnapshot {
                    name: "best-effort".into(),
                    queue: 0,
                },
                CoSForwardingClassSnapshot {
                    name: "expedited-forwarding".into(),
                    queue: 1,
                },
            ],
            schedulers: vec![
                CoSSchedulerSnapshot {
                    name: "be-sched".into(),
                    transmit_rate_bytes: 3_000_000,
                    transmit_rate_exact: false,
                    priority: "low".into(),
                    buffer_size_bytes: 128_000,
                    surplus_sharing: false,
                },
                CoSSchedulerSnapshot {
                    name: "ef-sched".into(),
                    transmit_rate_bytes: 7_000_000,
                    transmit_rate_exact: true,
                    priority: "strict-high".into(),
                    buffer_size_bytes: 64_000,
                    surplus_sharing: false,
                },
            ],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "expedited-forwarding".into(),
                        scheduler: "ef-sched".into(),
                    },
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "best-effort".into(),
                        scheduler: "be-sched".into(),
                    },
                ],
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
        }),
        ..Default::default()
    };

    let state = build_cos_state(&snapshot);
    let iface = state.interfaces.get(&42).expect("missing CoS interface");
    assert_eq!(iface.shaping_rate_bytes, 10_000_000);
    assert_eq!(iface.burst_bytes, 256_000);
    assert_eq!(iface.default_queue, 0);
    assert_eq!(iface.queues.len(), 2);
    assert_eq!(iface.queues[0].queue_id, 0);
    assert_eq!(iface.queues[0].forwarding_class, "best-effort");
    assert_eq!(iface.queues[0].priority, 5);
    assert_eq!(iface.queues[0].transmit_rate_bytes, 3_000_000);
    assert!(!iface.queues[0].exact);
    assert_eq!(iface.queues[0].surplus_weight, 5);
    assert_eq!(iface.queues[0].buffer_bytes, 128_000);
    assert_eq!(iface.queues[1].queue_id, 1);
    assert_eq!(iface.queues[1].forwarding_class, "expedited-forwarding");
    assert_eq!(iface.queues[1].priority, 0);
    assert_eq!(iface.queues[1].transmit_rate_bytes, 7_000_000);
    assert!(iface.queues[1].exact);
    assert_eq!(iface.queues[1].surplus_weight, 12);
    assert_eq!(iface.queues[1].buffer_bytes, 64_000);
}

// #915 (Copilot code-review #3): regression test that
// `build_cos_state` correctly propagates the snapshot
// `surplus_sharing` flag into the runtime `CoSQueueConfig`.
// The builders test alone is insufficient because it starts from
// a hand-built `CoSQueueConfig`, so a regression that stops
// `build_cos_state` from copying the snapshot field would not
// show up there. This test starts from a `CoSSchedulerSnapshot`
// with `surplus_sharing=true` and verifies the field arrives at
// `CoSQueueConfig.surplus_sharing`.
#[test]
fn build_cos_state_propagates_surplus_sharing_from_snapshot() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 42,
            cos_shaping_rate_bytes_per_sec: 10_000_000,
            cos_shaping_burst_bytes: 256_000,
            cos_scheduler_map: "wan-map".into(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![
                CoSForwardingClassSnapshot { name: "iperf-a".into(), queue: 4 },
                CoSForwardingClassSnapshot { name: "iperf-b".into(), queue: 5 },
            ],
            schedulers: vec![
                CoSSchedulerSnapshot {
                    name: "iperf-a".into(),
                    transmit_rate_bytes: 1_000_000_000 / 8,
                    transmit_rate_exact: true,
                    priority: "low".into(),
                    buffer_size_bytes: 128 * 1024,
                    surplus_sharing: true, // opt-in
                },
                CoSSchedulerSnapshot {
                    name: "iperf-b".into(),
                    transmit_rate_bytes: 10_000_000_000 / 8,
                    transmit_rate_exact: true,
                    priority: "low".into(),
                    buffer_size_bytes: 128 * 1024,
                    surplus_sharing: false, // explicit hard-cap
                },
            ],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "iperf-a".into(),
                        scheduler: "iperf-a".into(),
                    },
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "iperf-b".into(),
                        scheduler: "iperf-b".into(),
                    },
                ],
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
        }),
        ..Default::default()
    };

    let state = build_cos_state(&snapshot);
    let iface = state.interfaces.get(&42).expect("missing CoS interface");
    let q4 = iface.queues.iter().find(|q| q.queue_id == 4).unwrap();
    let q5 = iface.queues.iter().find(|q| q.queue_id == 5).unwrap();
    assert!(q4.surplus_sharing,
        "snapshot scheduler iperf-a (surplus_sharing=true) must reach \
         CoSQueueConfig.surplus_sharing on queue 4");
    assert!(!q5.surplus_sharing,
        "snapshot scheduler iperf-b (surplus_sharing=false) must reach \
         CoSQueueConfig.surplus_sharing=false on queue 5");
    // Sanity: both still exact (so the strip-on-non-exact rule wouldn't have
    // fired even if it had been at this layer).
    assert!(q4.exact && q5.exact);
}

#[test]
fn build_cos_state_falls_back_to_default_best_effort_queue() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 7,
            cos_shaping_rate_bytes_per_sec: 1_000_000,
            cos_scheduler_map: "missing-map".into(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot::default()),
        ..Default::default()
    };

    let state = build_cos_state(&snapshot);
    let iface = state
        .interfaces
        .get(&7)
        .expect("missing fallback CoS interface");
    assert_eq!(iface.shaping_rate_bytes, 1_000_000);
    assert_eq!(iface.burst_bytes, default_cos_burst_bytes(1_000_000));
    assert_eq!(iface.default_queue, 0);
    assert_eq!(iface.queues.len(), 1);
    assert_eq!(iface.queues[0].queue_id, 0);
    assert_eq!(iface.queues[0].forwarding_class, "best-effort");
    assert_eq!(iface.queues[0].priority, 5);
    assert_eq!(iface.queues[0].transmit_rate_bytes, 1_000_000);
    assert!(!iface.queues[0].exact);
    assert_eq!(iface.queues[0].surplus_weight, 1);
    assert_eq!(
        iface.queues[0].buffer_bytes,
        default_cos_burst_bytes(1_000_000)
    );
}

#[test]
fn build_cos_state_derives_exact_queue_default_burst_from_queue_rate() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 42,
            cos_shaping_rate_bytes_per_sec: 25_000_000_000 / 8,
            cos_scheduler_map: "wan-map".into(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![CoSForwardingClassSnapshot {
                name: "best-effort".into(),
                queue: 0,
            }],
            schedulers: vec![CoSSchedulerSnapshot {
                name: "be-sched".into(),
                transmit_rate_bytes: 100_000_000 / 8,
                transmit_rate_exact: true,
                priority: "low".into(),
                buffer_size_bytes: 0,
                surplus_sharing: false,
            }],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![CoSSchedulerMapEntrySnapshot {
                    forwarding_class: "best-effort".into(),
                    scheduler: "be-sched".into(),
                }],
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
        }),
        ..Default::default()
    };

    let state = build_cos_state(&snapshot);
    let iface = state.interfaces.get(&42).expect("missing CoS interface");

    assert_eq!(iface.shaping_rate_bytes, 25_000_000_000 / 8);
    assert_eq!(
        iface.burst_bytes,
        default_cos_burst_bytes(25_000_000_000 / 8),
        "interface burst should still derive from the parent shaper"
    );
    assert_eq!(iface.queues.len(), 1);
    assert_eq!(iface.queues[0].transmit_rate_bytes, 100_000_000 / 8);
    assert!(iface.queues[0].exact);
    assert_eq!(
        iface.queues[0].buffer_bytes,
        default_cos_burst_bytes(100_000_000 / 8),
        "exact queue burst must derive from the scheduler rate, not the 25 Gb/s parent shaper"
    );
}

#[test]
fn build_cos_state_uses_effective_transmit_rate_for_surplus_weight() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 9,
            cos_shaping_rate_bytes_per_sec: 1_000_000,
            cos_scheduler_map: "test-map".into(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![CoSForwardingClassSnapshot {
                name: "best-effort".into(),
                queue: 0,
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
            schedulers: vec![CoSSchedulerSnapshot {
                name: "be-sched".into(),
                transmit_rate_bytes: 0,
                transmit_rate_exact: false,
                priority: "low".into(),
                buffer_size_bytes: 0,
                surplus_sharing: false,
            }],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "test-map".into(),
                entries: vec![CoSSchedulerMapEntrySnapshot {
                    forwarding_class: "best-effort".into(),
                    scheduler: "be-sched".into(),
                }],
            }],
        }),
        ..Default::default()
    };

    let state = build_cos_state(&snapshot);
    let iface = state.interfaces.get(&9).expect("missing CoS interface");
    assert_eq!(iface.queues.len(), 1);
    assert_eq!(iface.queues[0].transmit_rate_bytes, 1_000_000);
    assert_eq!(iface.queues[0].surplus_weight, 16);
}

#[test]
fn build_cos_state_binds_dscp_classifier_to_usable_interface_queue_ids() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 42,
            cos_shaping_rate_bytes_per_sec: 10_000_000,
            cos_scheduler_map: "wan-map".into(),
            cos_dscp_classifier: "wan-classifier".into(),
            cos_ieee8021_classifier: "wan-pcp".into(),
            cos_dscp_rewrite_rule: "wan-rewrite".into(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![
                CoSForwardingClassSnapshot {
                    name: "best-effort".into(),
                    queue: 0,
                },
                CoSForwardingClassSnapshot {
                    name: "voice".into(),
                    queue: 5,
                },
            ],
            dscp_classifiers: vec![CoSDSCPClassifierSnapshot {
                name: "wan-classifier".into(),
                entries: vec![
                    CoSDSCPClassifierEntrySnapshot {
                        forwarding_class: "voice".into(),
                        loss_priority: "low".into(),
                        dscp_values: vec![46],
                    },
                    CoSDSCPClassifierEntrySnapshot {
                        forwarding_class: "best-effort".into(),
                        loss_priority: "low".into(),
                        dscp_values: vec![0],
                    },
                ],
            }],
            ieee8021_classifiers: vec![CoSIEEE8021ClassifierSnapshot {
                name: "wan-pcp".into(),
                entries: vec![CoSIEEE8021ClassifierEntrySnapshot {
                    forwarding_class: "voice".into(),
                    loss_priority: "low".into(),
                    code_points: vec![5],
                }],
            }],
            dscp_rewrite_rules: vec![CoSDSCPRewriteRuleSnapshot {
                name: "wan-rewrite".into(),
                entries: vec![CoSDSCPRewriteRuleEntrySnapshot {
                    forwarding_class: "voice".into(),
                    loss_priority: "low".into(),
                    dscp_value: 46,
                }],
            }],
            schedulers: vec![
                CoSSchedulerSnapshot {
                    name: "be".into(),
                    transmit_rate_bytes: 1_000_000,
                    transmit_rate_exact: false,
                    priority: "low".into(),
                    buffer_size_bytes: 0,
                    surplus_sharing: false,
                },
                CoSSchedulerSnapshot {
                    name: "voice".into(),
                    transmit_rate_bytes: 2_000_000,
                    transmit_rate_exact: false,
                    priority: "high".into(),
                    buffer_size_bytes: 0,
                    surplus_sharing: false,
                },
            ],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "best-effort".into(),
                        scheduler: "be".into(),
                    },
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "voice".into(),
                        scheduler: "voice".into(),
                    },
                ],
            }],
            ..Default::default()
        }),
        ..Default::default()
    };

    let state = build_cos_state(&snapshot);
    let iface = state.interfaces.get(&42).expect("missing CoS interface");
    assert_eq!(iface.dscp_classifier, "wan-classifier");
    assert_eq!(iface.ieee8021_classifier, "wan-pcp");
    assert_eq!(
        iface
            .queues
            .iter()
            .find(|queue| queue.queue_id == 5)
            .and_then(|queue| queue.dscp_rewrite),
        Some(46)
    );
    assert!(iface.queues.iter().any(|queue| queue.queue_id == 5));
    let classifier = state
        .dscp_classifiers
        .get("wan-classifier")
        .expect("missing classifier");
    assert_eq!(classifier.queue_by_dscp.get(&46), Some(&5));
    assert_eq!(classifier.queue_by_dscp.get(&0), Some(&0));
    let pcp_classifier = state
        .ieee8021_classifiers
        .get("wan-pcp")
        .expect("missing 802.1p classifier");
    assert_eq!(pcp_classifier.queue_by_pcp.get(&5), Some(&5));
}

#[test]
fn build_forwarding_state_prefers_logical_unit_for_ingress_lookup() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![
            InterfaceSnapshot {
                name: "ge-0-0-1".into(),
                ifindex: 10,
                hardware_addr: "02:00:00:00:00:10".into(),
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "ge-0-0-1.0".into(),
                ifindex: 11,
                parent_ifindex: 10,
                vlan_id: 0,
                hardware_addr: "02:00:00:00:00:10".into(),
                ..Default::default()
            },
        ],
        ..Default::default()
    };

    let state = build_forwarding_state(&snapshot);
    assert_eq!(state.ingress_logical_ifindex.get(&(10, 0)), Some(&11));
}
#[test]
fn build_forwarding_state_disables_tx_selection_when_no_cos_or_filters_exist() {
    let state = build_forwarding_state(&ConfigSnapshot::default());
    assert!(!state.tx_selection_enabled_v4);
    assert!(!state.tx_selection_enabled_v6);
}

#[test]
fn build_forwarding_state_enables_tx_selection_when_cos_interfaces_exist() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 42,
            cos_shaping_rate_bytes_per_sec: 10_000_000,
            cos_scheduler_map: "wan-map".into(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![CoSForwardingClassSnapshot {
                name: "best-effort".into(),
                queue: 0,
            }],
            schedulers: vec![CoSSchedulerSnapshot {
                name: "be-sched".into(),
                transmit_rate_bytes: 10_000_000,
                ..Default::default()
            }],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![CoSSchedulerMapEntrySnapshot {
                    forwarding_class: "best-effort".into(),
                    scheduler: "be-sched".into(),
                }],
            }],
            ..Default::default()
        }),
        ..Default::default()
    };

    let state = build_forwarding_state(&snapshot);
    assert!(state.tx_selection_enabled_v4);
    assert!(state.tx_selection_enabled_v6);
}

/// #919/#922: any zone with id ≥ ZONE_ID_RESERVED_MIN must be
/// dropped at config-build time so a hostile/buggy snapshot cannot
/// collide with the JUNOS_GLOBAL_ZONE_ID sentinel (u16::MAX).
#[test]
fn build_forwarding_state_rejects_reserved_zone_ids() {
    use crate::ZoneSnapshot;
    let snapshot = ConfigSnapshot {
        zones: vec![
            ZoneSnapshot {
                name: "ok".into(),
                id: 5,
            },
            ZoneSnapshot {
                name: "reserved-edge".into(),
                id: crate::policy::ZONE_ID_RESERVED_MIN,
            },
            ZoneSnapshot {
                name: "global-sentinel".into(),
                id: crate::policy::JUNOS_GLOBAL_ZONE_ID,
            },
        ],
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);
    assert_eq!(state.zone_name_to_id.get("ok").copied(), Some(5));
    assert!(state.zone_name_to_id.get("reserved-edge").is_none());
    assert!(state.zone_name_to_id.get("global-sentinel").is_none());
    assert!(state
        .zone_id_to_name
        .get(&crate::policy::ZONE_ID_RESERVED_MIN)
        .is_none());
    assert!(state
        .zone_id_to_name
        .get(&crate::policy::JUNOS_GLOBAL_ZONE_ID)
        .is_none());
}

/// #921: ifindex_to_zone_id is populated at config build time
/// from the snapshot's per-interface zone NAME via zone_name_to_id.
#[test]
fn ifindex_to_zone_id_populated_from_snapshot_at_build_time() {
    use crate::ZoneSnapshot;
    let snapshot = ConfigSnapshot {
        zones: vec![ZoneSnapshot {
            name: "trust".into(),
            id: 7,
        }],
        interfaces: vec![InterfaceSnapshot {
            name: "ge-0/0/0".into(),
            zone: "trust".into(),
            ifindex: 42,
            hardware_addr: "02:00:00:00:00:42".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);
    assert_eq!(state.ifindex_to_zone_id.get(&42).copied(), Some(7));
}

/// #921: EgressInterface.zone_id is set from the snapshot at
/// config build time.
#[test]
fn egress_interface_zone_id_set_from_snapshot() {
    use crate::ZoneSnapshot;
    let snapshot = ConfigSnapshot {
        zones: vec![ZoneSnapshot {
            name: "wan".into(),
            id: 11,
        }],
        interfaces: vec![InterfaceSnapshot {
            name: "ge-0/0/1".into(),
            zone: "wan".into(),
            ifindex: 99,
            hardware_addr: "02:00:00:00:00:99".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);
    let eg = state.egress.get(&99).expect("egress");
    assert_eq!(eg.zone_id, 11);
}

/// #921: an interface whose zone snapshot field references a zone
/// that was DROPPED at config build time (reserved id, > u8 max)
/// collapses to zone_id == 0 (the canonical "unknown" sentinel).
#[test]
fn interface_pointing_at_skipped_zone_collapses_to_zone_id_zero() {
    use crate::ZoneSnapshot;
    let snapshot = ConfigSnapshot {
        zones: vec![ZoneSnapshot {
            name: "reserved".into(),
            id: crate::policy::ZONE_ID_RESERVED_MIN, // dropped at build
        }],
        interfaces: vec![InterfaceSnapshot {
            name: "ge-0/0/2".into(),
            zone: "reserved".into(),
            ifindex: 23,
            hardware_addr: "02:00:00:00:00:23".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);
    // Zone was dropped; the interface still appears in the
    // ifindex_to_zone_id map but with the unknown sentinel 0.
    assert_eq!(state.ifindex_to_zone_id.get(&23).copied(), Some(0));
}

/// #921: an EgressInterface whose snapshot zone string isn't in
/// the zones list collapses to zone_id == 0.
#[test]
fn egress_with_unknown_zone_name_collapses_to_zone_id_zero() {
    use crate::ZoneSnapshot;
    let snapshot = ConfigSnapshot {
        zones: vec![ZoneSnapshot {
            name: "trust".into(),
            id: 3,
        }],
        interfaces: vec![InterfaceSnapshot {
            name: "ge-0/0/3".into(),
            zone: "ghost".into(), // not in zones
            ifindex: 56,
            hardware_addr: "02:00:00:00:00:56".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);
    let eg = state.egress.get(&56).expect("egress");
    assert_eq!(eg.zone_id, 0);
}

// ---------------------------------------------------------------------
// #916: zero-shaping-rate (transparent root) tests.
// ---------------------------------------------------------------------

#[test]
fn build_cos_state_includes_zero_shaping_rate_interface() {
    // Pre-#916, an interface with `cos_shaping_rate_bytes_per_sec == 0`
    // was silently dropped by `build_cos_state`'s upstream skip,
    // which masked the runtime deadlock by suppressing the entire
    // CoS runtime. The bug surface for the operator was "CoS
    // classifier doesn't apply on this interface". The fix permits
    // the interface through; the runtime handles transparent-root
    // semantics.
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 42,
            cos_shaping_rate_bytes_per_sec: 0, // <- the case under test
            cos_shaping_burst_bytes: 0,
            cos_scheduler_map: "wan-map".into(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![CoSForwardingClassSnapshot {
                name: "best-effort".into(),
                queue: 0,
            }],
            schedulers: vec![],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![CoSSchedulerMapEntrySnapshot {
                    forwarding_class: "best-effort".into(),
                    scheduler: String::new(),
                }],
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
        }),
        ..Default::default()
    };
    let state = build_cos_state(&snapshot);
    assert!(
        state.interfaces.contains_key(&42),
        "zero-shaping-rate interface must be included in CoSState (transparent root)"
    );
    let iface = &state.interfaces[&42];
    assert_eq!(iface.shaping_rate_bytes, 0);
    // burst_bytes falls back to default_cos_burst_bytes(0) which floors
    // at COS_MIN_BURST_BYTES (96 KB).
    assert!(iface.burst_bytes >= 64 * 1500);
}

#[test]
fn build_cos_state_zero_shaping_rate_queue_inherits_transparent() {
    // When the scheduler has no transmit-rate AND the interface has
    // no shaping-rate, the queue's effective rate falls through to
    // 0. Verify the queue config carries `transmit_rate_bytes == 0`
    // (the runtime build path will pre-fill tokens to the buffer cap
    // and the queue-service will bypass the cos_refill_ns_until check).
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 42,
            cos_shaping_rate_bytes_per_sec: 0,
            cos_scheduler_map: "wan-map".into(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![CoSForwardingClassSnapshot {
                name: "iperf-a".into(),
                queue: 4,
            }],
            schedulers: vec![CoSSchedulerSnapshot {
                name: "no-rate".into(),
                transmit_rate_bytes: 0, // <- fallback chains to 0
                transmit_rate_exact: false,
                priority: "low".into(),
                buffer_size_bytes: 0,
                surplus_sharing: false,
            }],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![CoSSchedulerMapEntrySnapshot {
                    forwarding_class: "iperf-a".into(),
                    scheduler: "no-rate".into(),
                }],
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
        }),
        ..Default::default()
    };
    let state = build_cos_state(&snapshot);
    let iface = state.interfaces.get(&42).expect("transparent iface present");
    let queue = iface
        .queues
        .iter()
        .find(|q| q.queue_id == 4)
        .expect("iperf-a queue present");
    assert_eq!(
        queue.transmit_rate_bytes, 0,
        "transparent root + no scheduler rate → transparent queue (rate 0)"
    );
}

#[test]
fn build_cos_state_mixed_zero_and_nonzero_shaping_rate() {
    // Two interfaces in the same snapshot — one with shaping-rate
    // configured, one without. Both must produce CoSState entries
    // with the correct semantics.
    let snapshot = ConfigSnapshot {
        interfaces: vec![
            InterfaceSnapshot {
                ifindex: 42,
                cos_shaping_rate_bytes_per_sec: 25_000_000_000 / 8,
                cos_scheduler_map: "wan-map".into(),
                ..Default::default()
            },
            InterfaceSnapshot {
                ifindex: 43,
                cos_shaping_rate_bytes_per_sec: 0,
                cos_scheduler_map: "wan-map".into(),
                ..Default::default()
            },
        ],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![CoSForwardingClassSnapshot {
                name: "best-effort".into(),
                queue: 0,
            }],
            schedulers: vec![],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![CoSSchedulerMapEntrySnapshot {
                    forwarding_class: "best-effort".into(),
                    scheduler: String::new(),
                }],
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
        }),
        ..Default::default()
    };
    let state = build_cos_state(&snapshot);
    let shaped = state
        .interfaces
        .get(&42)
        .expect("shaped iface in CoSState");
    let transparent = state
        .interfaces
        .get(&43)
        .expect("transparent iface in CoSState");
    assert_eq!(shaped.shaping_rate_bytes, 25_000_000_000 / 8);
    assert_eq!(transparent.shaping_rate_bytes, 0);
    // Both must have at least one queue.
    assert!(!shaped.queues.is_empty());
    assert!(!transparent.queues.is_empty());
}

#[test]
fn build_cos_state_skips_interface_with_no_cos_config() {
    // An interface that is NOT participating in CoS (no scheduler-map,
    // no classifier, no rewrite-rule, no shaping-rate) must NOT receive
    // a CoSState entry — otherwise the per-interface owner-worker
    // dispatch funnels every TX into one worker, collapsing throughput
    // (regression hunted in iperf3 -P 12 -R: 22 Gbps → 2 Gbps until
    // this gate was reinstated).
    let snapshot = ConfigSnapshot {
        interfaces: vec![
            // Forwarding-only LAN egress with no CoS at all.
            InterfaceSnapshot {
                ifindex: 100,
                cos_shaping_rate_bytes_per_sec: 0,
                cos_shaping_burst_bytes: 0,
                cos_scheduler_map: String::new(),
                cos_dscp_classifier: String::new(),
                cos_ieee8021_classifier: String::new(),
                cos_dscp_rewrite_rule: String::new(),
                ..Default::default()
            },
            // Sibling that DOES participate in CoS — must still appear.
            InterfaceSnapshot {
                ifindex: 101,
                cos_shaping_rate_bytes_per_sec: 0,
                cos_scheduler_map: "wan-map".into(),
                ..Default::default()
            },
        ],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![CoSForwardingClassSnapshot {
                name: "best-effort".into(),
                queue: 0,
            }],
            schedulers: vec![],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![CoSSchedulerMapEntrySnapshot {
                    forwarding_class: "best-effort".into(),
                    scheduler: String::new(),
                }],
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
        }),
        ..Default::default()
    };
    let state = build_cos_state(&snapshot);
    assert!(
        !state.interfaces.contains_key(&100),
        "interface with no CoS config must NOT be added to CoSState"
    );
    assert!(
        state.interfaces.contains_key(&101),
        "interface with scheduler-map but no shaping-rate must still appear (transparent root)"
    );
}

#[test]
fn build_cos_state_admits_each_cos_field_in_isolation() {
    // The skip predicate is an OR over five arms (rate, scheduler-map,
    // DSCP classifier, 802.1p classifier, DSCP rewrite). Pin every arm so
    // a future refactor can't silently drop one — Codex review on
    // PR #1183 flagged this as coverage debt (Q5). The sixth `InterfaceSnapshot`
    // CoS field, `cos_shaping_burst_bytes`, is intentionally NOT a
    // standalone arm; see the dedicated burst-only-skip test below and
    // the gate comment in `forwarding_build.rs::build_cos_state` for
    // rationale.
    let cos = ClassOfServiceSnapshot {
        forwarding_classes: vec![CoSForwardingClassSnapshot {
            name: "best-effort".into(),
            queue: 0,
        }],
        schedulers: vec![],
        scheduler_maps: vec![CoSSchedulerMapSnapshot {
            name: "wan-map".into(),
            entries: vec![CoSSchedulerMapEntrySnapshot {
                forwarding_class: "best-effort".into(),
                scheduler: String::new(),
            }],
        }],
        dscp_classifiers: vec![CoSDSCPClassifierSnapshot {
            name: "dscp-cls".into(),
            entries: vec![CoSDSCPClassifierEntrySnapshot {
                forwarding_class: "best-effort".into(),
                loss_priority: String::new(),
                dscp_values: vec![0],
            }],
        }],
        ieee8021_classifiers: vec![CoSIEEE8021ClassifierSnapshot {
            name: "p8021-cls".into(),
            entries: vec![CoSIEEE8021ClassifierEntrySnapshot {
                forwarding_class: "best-effort".into(),
                loss_priority: String::new(),
                code_points: vec![0],
            }],
        }],
        dscp_rewrite_rules: vec![CoSDSCPRewriteRuleSnapshot {
            name: "dscp-rw".into(),
            entries: vec![CoSDSCPRewriteRuleEntrySnapshot {
                forwarding_class: "best-effort".into(),
                loss_priority: String::new(),
                dscp_value: 0,
            }],
        }],
    };
    let cases: &[(i32, &str, InterfaceSnapshot)] = &[
        (
            201,
            "shaping-rate only",
            InterfaceSnapshot {
                ifindex: 201,
                cos_shaping_rate_bytes_per_sec: 1_000_000,
                ..Default::default()
            },
        ),
        (
            203,
            "scheduler-map only",
            InterfaceSnapshot {
                ifindex: 203,
                cos_scheduler_map: "wan-map".into(),
                ..Default::default()
            },
        ),
        (
            204,
            "DSCP classifier only",
            InterfaceSnapshot {
                ifindex: 204,
                cos_dscp_classifier: "dscp-cls".into(),
                ..Default::default()
            },
        ),
        (
            205,
            "802.1p classifier only",
            InterfaceSnapshot {
                ifindex: 205,
                cos_ieee8021_classifier: "p8021-cls".into(),
                ..Default::default()
            },
        ),
        (
            206,
            "DSCP rewrite-rule only",
            InterfaceSnapshot {
                ifindex: 206,
                cos_dscp_rewrite_rule: "dscp-rw".into(),
                ..Default::default()
            },
        ),
    ];
    for (ifindex, label, iface) in cases {
        let snapshot = ConfigSnapshot {
            interfaces: vec![iface.clone()],
            class_of_service: Some(cos.clone()),
            ..Default::default()
        };
        let state = build_cos_state(&snapshot);
        assert!(
            state.interfaces.contains_key(ifindex),
            "{label}: interface must be admitted to CoSState (ifindex {ifindex})"
        );
    }
}

#[test]
fn build_cos_state_skips_interface_with_burst_only_no_other_cos_knobs() {
    // The Go compiler permits a committed config to carry
    // `BurstSizeBytes > 0` independently of `ShapingRateBytes`
    // (`pkg/config/compiler_class_of_service.go:285-312`), so this
    // snapshot shape IS reachable from real config. We deliberately
    // skip it anyway: pre-f0e364d7 also skipped burst-only (the old
    // `shaping_rate == 0` skip caught it), and admitting it would
    // install the cross-binding owner-worker redirect that PR #1183
    // exists to remove. The buffer-cap admission effect that admission
    // would unlock has never been observable in production.
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 250,
            cos_shaping_rate_bytes_per_sec: 0,
            cos_shaping_burst_bytes: 256_000,
            cos_scheduler_map: String::new(),
            cos_dscp_classifier: String::new(),
            cos_ieee8021_classifier: String::new(),
            cos_dscp_rewrite_rule: String::new(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot::default()),
        ..Default::default()
    };
    let state = build_cos_state(&snapshot);
    assert!(
        !state.interfaces.contains_key(&250),
        "interface with burst-only (no rate, no classes, no rewrite) must NOT be in CoSState"
    );
}

#[test]
fn build_cos_state_skips_interface_with_unresolvable_named_references() {
    // A typo'd scheduler-map / classifier / rewrite-rule name is
    // non-empty but does not resolve to any entry in the CoS config.
    // Pre-fix, an is-non-empty gate would admit such an interface and
    // build only a default best-effort queue with rate=0, re-triggering
    // the owner-worker redirect collapse for an interface with no
    // effective CoS policy. The predicate must require named references
    // to actually resolve.
    let cos = ClassOfServiceSnapshot {
        forwarding_classes: vec![CoSForwardingClassSnapshot {
            name: "best-effort".into(),
            queue: 0,
        }],
        schedulers: vec![],
        scheduler_maps: vec![CoSSchedulerMapSnapshot {
            name: "wan-map".into(),
            entries: vec![CoSSchedulerMapEntrySnapshot {
                forwarding_class: "best-effort".into(),
                scheduler: String::new(),
            }],
        }],
        dscp_classifiers: vec![CoSDSCPClassifierSnapshot {
            name: "dscp-cls".into(),
            entries: vec![CoSDSCPClassifierEntrySnapshot {
                forwarding_class: "best-effort".into(),
                loss_priority: String::new(),
                dscp_values: vec![0],
            }],
        }],
        ieee8021_classifiers: vec![CoSIEEE8021ClassifierSnapshot {
            name: "p8021-cls".into(),
            entries: vec![CoSIEEE8021ClassifierEntrySnapshot {
                forwarding_class: "best-effort".into(),
                loss_priority: String::new(),
                code_points: vec![0],
            }],
        }],
        dscp_rewrite_rules: vec![CoSDSCPRewriteRuleSnapshot {
            name: "dscp-rw".into(),
            entries: vec![CoSDSCPRewriteRuleEntrySnapshot {
                forwarding_class: "best-effort".into(),
                loss_priority: String::new(),
                dscp_value: 0,
            }],
        }],
    };
    // Each typo'd reference (one CoS field non-empty but unresolvable)
    // must NOT admit the interface to CoSState.
    let cases: &[(i32, &str, InterfaceSnapshot)] = &[
        (
            301,
            "typo'd scheduler-map",
            InterfaceSnapshot {
                ifindex: 301,
                cos_scheduler_map: "wan-mapp".into(),
                ..Default::default()
            },
        ),
        (
            302,
            "typo'd DSCP classifier",
            InterfaceSnapshot {
                ifindex: 302,
                cos_dscp_classifier: "dscp-cls-typo".into(),
                ..Default::default()
            },
        ),
        (
            303,
            "typo'd 802.1p classifier",
            InterfaceSnapshot {
                ifindex: 303,
                cos_ieee8021_classifier: "p8021-cls-typo".into(),
                ..Default::default()
            },
        ),
        (
            304,
            "typo'd DSCP rewrite-rule",
            InterfaceSnapshot {
                ifindex: 304,
                cos_dscp_rewrite_rule: "dscp-rw-typo".into(),
                ..Default::default()
            },
        ),
    ];
    for (ifindex, label, iface) in cases {
        let snapshot = ConfigSnapshot {
            interfaces: vec![iface.clone()],
            class_of_service: Some(cos.clone()),
            ..Default::default()
        };
        let state = build_cos_state(&snapshot);
        assert!(
            !state.interfaces.contains_key(ifindex),
            "{label}: unresolvable name must NOT admit interface to CoSState (ifindex {ifindex})"
        );
    }
}

#[test]
fn build_cos_state_skips_interface_with_resolvable_but_empty_scheduler_map() {
    // Copilot review on PR #1183 caught this: `compileClassOfService`
    // keeps a named scheduler-map even when it has zero entries, so
    // a `contains_key` admission check would let a config like
    // `set class-of-service interfaces ifd unit X scheduler-map empty-map`
    // (with `empty-map` declared but no entries) pass the gate, then
    // collapse downstream to a synthetic best-effort default queue —
    // re-triggering the owner-worker redirect collapse for an interface
    // with no effective CoS policy.
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 401,
            cos_shaping_rate_bytes_per_sec: 0,
            cos_scheduler_map: "empty-map".into(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![CoSForwardingClassSnapshot {
                name: "best-effort".into(),
                queue: 0,
            }],
            schedulers: vec![],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "empty-map".into(),
                entries: vec![], // <- the critical case: declared but empty
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
        }),
        ..Default::default()
    };
    let state = build_cos_state(&snapshot);
    assert!(
        !state.interfaces.contains_key(&401),
        "interface attached to a resolvable but empty scheduler-map must NOT enter CoSState"
    );
}

#[test]
fn build_cos_state_skips_interface_with_scheduler_map_all_undefined_forwarding_classes() {
    // The Junos compiler emits a warning for scheduler-map entries that
    // reference undefined forwarding-classes but does NOT drop the
    // scheduler-map itself. After resolution, every entry's
    // `class_to_queue.get` returns None, so `queues` is empty and the
    // interface would otherwise fall through to the synthetic default
    // best-effort queue. The post-build gate must reject this case so
    // we don't reintroduce the owner-worker redirect on an interface
    // with no effective CoS policy.
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 402,
            cos_shaping_rate_bytes_per_sec: 0,
            cos_scheduler_map: "broken-map".into(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            // forwarding_classes intentionally does NOT include the
            // class names referenced by `broken-map` below, so every
            // entry collapses at `class_to_queue.get(&entry.forwarding_class)`.
            forwarding_classes: vec![CoSForwardingClassSnapshot {
                name: "best-effort".into(),
                queue: 0,
            }],
            schedulers: vec![],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "broken-map".into(),
                entries: vec![
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "missing-class-a".into(),
                        scheduler: String::new(),
                    },
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "missing-class-b".into(),
                        scheduler: String::new(),
                    },
                ],
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
        }),
        ..Default::default()
    };
    let state = build_cos_state(&snapshot);
    assert!(
        !state.interfaces.contains_key(&402),
        "scheduler-map whose entries all reference undefined forwarding-classes must NOT admit interface"
    );
}

#[test]
fn build_cos_state_skips_classifier_only_mapping_to_unmaterialized_queue() {
    // An interface attaches a DSCP classifier whose entries map to
    // forwarding-class `voice` (queue 5). The interface has NO
    // scheduler-map, so the only queue it would materialize is the
    // synthetic default best-effort (queue 0). The classifier maps to
    // queue 5, which the interface won't have at runtime — packets
    // matching the classifier would land in `resolve_cos_queue_idx`
    // and get dropped, while the interface still installs the
    // owner-worker redirect. Gate must skip such interfaces.
    // (Copilot review on PR #1183 caught this.)
    let cos = ClassOfServiceSnapshot {
        forwarding_classes: vec![
            CoSForwardingClassSnapshot {
                name: "best-effort".into(),
                queue: 0,
            },
            CoSForwardingClassSnapshot {
                name: "voice".into(),
                queue: 5,
            },
        ],
        schedulers: vec![],
        scheduler_maps: vec![],
        dscp_classifiers: vec![CoSDSCPClassifierSnapshot {
            name: "voice-cls".into(),
            entries: vec![CoSDSCPClassifierEntrySnapshot {
                forwarding_class: "voice".into(), // queue 5
                loss_priority: String::new(),
                dscp_values: vec![0x2e],
            }],
        }],
        ieee8021_classifiers: vec![],
        dscp_rewrite_rules: vec![],
    };
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 501,
            cos_dscp_classifier: "voice-cls".into(),
            ..Default::default()
        }],
        class_of_service: Some(cos),
        ..Default::default()
    };
    let state = build_cos_state(&snapshot);
    assert!(
        !state.interfaces.contains_key(&501),
        "DSCP classifier mapping to queue the interface won't materialize (no scheduler-map) must NOT admit"
    );
}

#[test]
fn build_cos_state_admits_classifier_mapping_to_materialized_queue() {
    // The opposite of the previous test: a DSCP classifier mapping to
    // queue 0 is OK on an interface with no scheduler-map, because the
    // synthetic default best-effort queue IS queue 0. Packets land
    // there and the classifier IS observable, so the interface
    // legitimately needs to be in CoSState.
    let cos = ClassOfServiceSnapshot {
        forwarding_classes: vec![CoSForwardingClassSnapshot {
            name: "best-effort".into(),
            queue: 0,
        }],
        schedulers: vec![],
        scheduler_maps: vec![],
        dscp_classifiers: vec![CoSDSCPClassifierSnapshot {
            name: "be-cls".into(),
            entries: vec![CoSDSCPClassifierEntrySnapshot {
                forwarding_class: "best-effort".into(), // queue 0
                loss_priority: String::new(),
                dscp_values: vec![0x10],
            }],
        }],
        ieee8021_classifiers: vec![],
        dscp_rewrite_rules: vec![],
    };
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 502,
            cos_dscp_classifier: "be-cls".into(),
            ..Default::default()
        }],
        class_of_service: Some(cos),
        ..Default::default()
    };
    let state = build_cos_state(&snapshot);
    assert!(
        state.interfaces.contains_key(&502),
        "DSCP classifier mapping to materialized queue must admit interface"
    );
}

#[test]
fn build_cos_state_skips_rewrite_only_mapping_to_unmaterialized_class() {
    // A DSCP rewrite-rule whose ONLY entry is for forwarding-class
    // `voice` is attached to an interface with no scheduler-map. The
    // interface only has the synthetic default best-effort class —
    // the `voice` rewrite has no queue to attach to, so no packet can
    // ever observe it. Gate must skip.
    let cos = ClassOfServiceSnapshot {
        forwarding_classes: vec![
            CoSForwardingClassSnapshot {
                name: "best-effort".into(),
                queue: 0,
            },
            CoSForwardingClassSnapshot {
                name: "voice".into(),
                queue: 5,
            },
        ],
        schedulers: vec![],
        scheduler_maps: vec![],
        dscp_classifiers: vec![],
        ieee8021_classifiers: vec![],
        dscp_rewrite_rules: vec![CoSDSCPRewriteRuleSnapshot {
            name: "voice-rw".into(),
            entries: vec![CoSDSCPRewriteRuleEntrySnapshot {
                forwarding_class: "voice".into(),
                loss_priority: String::new(),
                dscp_value: 0x2e,
            }],
        }],
    };
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 503,
            cos_dscp_rewrite_rule: "voice-rw".into(),
            ..Default::default()
        }],
        class_of_service: Some(cos),
        ..Default::default()
    };
    let state = build_cos_state(&snapshot);
    assert!(
        !state.interfaces.contains_key(&503),
        "DSCP rewrite-rule for class the interface won't materialize must NOT admit"
    );
}

#[test]
fn build_cos_state_admits_rewrite_only_mapping_to_materialized_class() {
    // A DSCP rewrite-rule with a `best-effort` entry is observable on
    // an interface with no scheduler-map, because the synthetic default
    // best-effort queue IS the materialized class. Packets in that
    // queue can carry the rewrite — interface should be admitted.
    let cos = ClassOfServiceSnapshot {
        forwarding_classes: vec![CoSForwardingClassSnapshot {
            name: "best-effort".into(),
            queue: 0,
        }],
        schedulers: vec![],
        scheduler_maps: vec![],
        dscp_classifiers: vec![],
        ieee8021_classifiers: vec![],
        dscp_rewrite_rules: vec![CoSDSCPRewriteRuleSnapshot {
            name: "be-rw".into(),
            entries: vec![CoSDSCPRewriteRuleEntrySnapshot {
                forwarding_class: "best-effort".into(),
                loss_priority: String::new(),
                dscp_value: 0,
            }],
        }],
    };
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 504,
            cos_dscp_rewrite_rule: "be-rw".into(),
            ..Default::default()
        }],
        class_of_service: Some(cos),
        ..Default::default()
    };
    let state = build_cos_state(&snapshot);
    assert!(
        state.interfaces.contains_key(&504),
        "DSCP rewrite-rule for the materialized best-effort class must admit"
    );
}
