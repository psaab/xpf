// Tests for main.rs — relocated from inline `#[cfg(test)] mod tests` to
// keep main.rs under the modularity-discipline LOC threshold (#1048).
// Loaded as a sibling module via `#[path = "main_tests.rs"]` from main.rs.

use super::*;
use crate::test_zone_ids::*;
use std::collections::BTreeMap;

fn test_zone_name_to_id() -> rustc_hash::FxHashMap<String, u16> {
    let mut m = rustc_hash::FxHashMap::default();
    m.insert("lan".to_string(), TEST_LAN_ZONE_ID);
    m.insert("wan".to_string(), TEST_WAN_ZONE_ID);
    m.insert("trust".to_string(), TEST_TRUST_ZONE_ID);
    m.insert("untrust".to_string(), TEST_UNTRUST_ZONE_ID);
    m.insert("sfmix".to_string(), TEST_SFMIX_ZONE_ID);
    m
}

#[test]
fn same_binding_plan_ignores_runtime_only_snapshot_changes() {
    let current = ConfigSnapshot {
        userspace: serde_json::json!({
            "binary": "/usr/libexec/xpf-userspace-dp",
            "control_socket": "/run/xpf/control.sock",
            "state_file": "/run/xpf/state.json",
            "workers": 2,
            "ring_entries": 2048,
            "poll_mode": "interrupt",
        }),
        interfaces: vec![
            InterfaceSnapshot {
                name: "ge-0/0/1.0".to_string(),
                zone: "lan".to_string(),
                linux_name: "ge-0-0-1".to_string(),
                ifindex: 11,
                rx_queues: 4,
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "fab0".to_string(),
                zone: "control".to_string(),
                linux_name: "fab0".to_string(),
                ifindex: 149,
                rx_queues: 16,
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "gr-0/0/0.0".to_string(),
                zone: "sfmix".to_string(),
                linux_name: "gr-0-0-0".to_string(),
                ifindex: 586,
                rx_queues: 1,
                tunnel: true,
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "fxp0.0".to_string(),
                zone: "mgmt".to_string(),
                linux_name: "fxp0".to_string(),
                ifindex: 42,
                rx_queues: 1,
                ..Default::default()
            },
        ],
        fabrics: vec![FabricSnapshot {
            name: "fab0".to_string(),
            parent_linux_name: "ge-0-0-0".to_string(),
            parent_ifindex: 21,
            rx_queues: 1,
            ..Default::default()
        }],
        ..Default::default()
    };
    let mut next = current.clone();
    next.userspace = serde_json::json!({
        "binary": "/tmp/other-helper",
        "control_socket": "/tmp/control.sock",
        "state_file": "/tmp/state.json",
        "workers": 2,
        "ring_entries": 2048,
        "poll_mode": "busy-poll",
    });
    next.interfaces.push(InterfaceSnapshot {
        name: "em0.0".to_string(),
        zone: "mgmt".to_string(),
        linux_name: "em0".to_string(),
        ifindex: 99,
        rx_queues: 1,
        ..Default::default()
    });
    next.interfaces[1].ifindex = 154;

    assert!(same_binding_plan(&current, &next));
}

#[test]
fn same_binding_plan_canonicalizes_shared_umem_json_set_order() {
    let current = ConfigSnapshot {
        userspace: serde_json::from_str(
            r#"{
                "workers": 2,
                "ring_entries": 2048,
                "shared_umem": {
                    "mode": "cross-nic",
                    "interfaces": ["ge-0-0-1", "ge-0-0-2"],
                    "phase0_artifact": {
                        "selected_interfaces": ["ge-0-0-1", "ge-0-0-2"],
                        "selected_nic_pci_ids": ["0000:08:00.0", "0000:09:00.0"],
                        "selected_device_pair": ["0000:08:00.0", "0000:09:00.0"],
                        "mtu": {"ge-0-0-1": 1500, "ge-0-0-2": 1500}
                    }
                }
            }"#,
        )
        .unwrap(),
        ..Default::default()
    };
    let next = ConfigSnapshot {
        userspace: serde_json::from_str(
            r#"{
                "shared_umem": {
                    "phase0_artifact": {
                        "mtu": {"ge-0-0-2": 1500, "ge-0-0-1": 1500},
                        "selected_device_pair": ["0000:09:00.0", "0000:08:00.0"],
                        "selected_nic_pci_ids": ["0000:09:00.0", "0000:08:00.0"],
                        "selected_interfaces": ["ge-0-0-2", "ge-0-0-1"]
                    },
                    "interfaces": ["ge-0-0-2", "ge-0-0-1"],
                    "mode": "cross-nic"
                },
                "ring_entries": 2048,
                "workers": 2
            }"#,
        )
        .unwrap(),
        ..Default::default()
    };

    assert!(same_binding_plan(&current, &next));
}

#[test]
fn same_binding_plan_detects_shared_umem_json_set_membership_change() {
    let current = ConfigSnapshot {
        userspace: serde_json::from_str(
            r#"{
                "workers": 2,
                "ring_entries": 2048,
                "shared_umem": {
                    "mode": "cross-nic",
                    "interfaces": ["ge-0-0-1", "ge-0-0-2"],
                    "phase0_artifact": {
                        "selected_interfaces": ["ge-0-0-1", "ge-0-0-2"],
                        "selected_nic_pci_ids": ["0000:08:00.0", "0000:09:00.0"]
                    }
                }
            }"#,
        )
        .unwrap(),
        ..Default::default()
    };
    let next = ConfigSnapshot {
        userspace: serde_json::from_str(
            r#"{
                "workers": 2,
                "ring_entries": 2048,
                "shared_umem": {
                    "mode": "cross-nic",
                    "interfaces": ["ge-0-0-1", "ge-0-0-3"],
                    "phase0_artifact": {
                        "selected_interfaces": ["ge-0-0-1", "ge-0-0-3"],
                        "selected_nic_pci_ids": ["0000:08:00.0", "0000:0a:00.0"]
                    }
                }
            }"#,
        )
        .unwrap(),
        ..Default::default()
    };

    assert!(!same_binding_plan(&current, &next));
}

#[test]
fn binding_plan_key_hashes_large_shared_umem_artifact() {
    let huge_note = "x".repeat(1024 * 1024);
    let snapshot = ConfigSnapshot {
        userspace: serde_json::json!({
            "workers": 2,
            "ring_entries": 2048,
            "shared_umem": {
                "mode": "cross-nic",
                "interfaces": ["ge-0-0-1", "ge-0-0-2"],
                "phase0_artifact": {
                    "selected_interfaces": ["ge-0-0-1", "ge-0-0-2"],
                    "selected_nic_pci_ids": ["0000:08:00.0", "0000:09:00.0"],
                    "diagnostic_note": huge_note
                }
            }
        }),
        ..Default::default()
    };

    let key = crate::server::helpers::snapshot_binding_plan_key(&snapshot);
    assert!(key.starts_with("sha256:"));
    assert_eq!(key.len(), "sha256:".len() + 64);
    assert!(!key.contains("diagnostic_note"));
    assert!(!key.contains('x'));
}

#[test]
fn same_binding_plan_detects_binding_topology_change() {
    let current = ConfigSnapshot {
        userspace: serde_json::json!({
            "workers": 2,
            "ring_entries": 2048,
        }),
        interfaces: vec![InterfaceSnapshot {
            name: "ge-0/0/1.0".to_string(),
            zone: "lan".to_string(),
            linux_name: "ge-0-0-1".to_string(),
            ifindex: 11,
            rx_queues: 4,
            ..Default::default()
        }],
        ..Default::default()
    };
    let mut next = current.clone();
    next.interfaces[0].rx_queues = 8;

    assert!(!same_binding_plan(&current, &next));
}

#[test]
fn queue_planner_filters_non_data_interfaces() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![
            InterfaceSnapshot {
                name: "ge-0/0/1".to_string(),
                linux_name: "ge-0-0-1".to_string(),
                zone: "trust".to_string(),
                ifindex: 11,
                rx_queues: 1,
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "xe-0/0/0".to_string(),
                linux_name: "xe-0-0-0".to_string(),
                zone: "untrust".to_string(),
                ifindex: 12,
                rx_queues: 1,
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "fab0".to_string(),
                linux_name: "fab0".to_string(),
                ifindex: 13,
                rx_queues: 4,
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let bindings = replan_queues(Some(&snapshot), 2, &[], true).expect("plan");
    assert_eq!(bindings.len(), 2);
    assert!(bindings.iter().all(|b| {
        b.interface.starts_with("ge-")
            || b.interface.starts_with("xe-")
            || b.interface.starts_with("et-")
    }));
    assert!(bindings.iter().all(|b| b.registered));
}

// #2915 / #10308 fail-on-revert: the plan-key hash and queue planner MUST
// agree on the binding interface set. Both route through
// `include_userspace_binding_interface` (the Rust mirror of the Go
// authoritative allowlist), whose exclusion is keyed on interface identity,
// not a zone name. A data NIC in a `mgmt`/`control`-named zone is a candidate;
// real lifeline names remain excluded.
#[test]
fn queue_planner_and_plan_key_agree_on_binding_set() {
    use crate::server::helpers::snapshot_binding_plan_key;

    let mk = |mgmt_ifindex: i32, data_rx: usize| ConfigSnapshot {
        interfaces: vec![
            InterfaceSnapshot {
                name: "ge-0/0/9".to_string(),
                linux_name: "ge-0-0-9".to_string(),
                zone: "mgmt".to_string(),
                ifindex: mgmt_ifindex,
                rx_queues: 1,
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "ge-0/0/1".to_string(),
                linux_name: "ge-0-0-1".to_string(),
                zone: "trust".to_string(),
                ifindex: 11,
                rx_queues: data_rx,
                ..Default::default()
            },
        ],
        ..Default::default()
    };

    let base = mk(99, 1);
    let bindings = replan_queues(Some(&base), 1, &[], true).expect("plan");
    let planned = bindings
        .iter()
        .map(|b| b.interface.clone())
        .collect::<std::collections::BTreeSet<_>>();

    assert_eq!(
        planned,
        ["ge-0-0-1".to_string(), "ge-0-0-9".to_string()]
            .into_iter()
            .collect(),
        "mgmt-named data NIC must stay in the binding plan, got {planned:?}"
    );
    assert_eq!(bindings.len(), 2, "both data interfaces should be planned");

    let mgmt_changed = mk(123, 1);
    assert_ne!(
        snapshot_binding_plan_key(&base),
        snapshot_binding_plan_key(&mgmt_changed),
        "a change to a mgmt-named data interface must bump the plan key"
    );
    let bindings_changed = replan_queues(Some(&mgmt_changed), 1, &[], true).expect("plan");
    assert_eq!(
        bindings.iter().map(|b| b.interface.clone()).collect::<Vec<_>>(),
        bindings_changed
            .iter()
            .map(|b| b.interface.clone())
            .collect::<Vec<_>>(),
        "changing the mgmt-named data NIC must not alter the planned interface set"
    );

    let data_changed = mk(99, 4);
    assert_ne!(
        snapshot_binding_plan_key(&base),
        snapshot_binding_plan_key(&data_changed),
        "a change to a trust-zoned data interface must bump the plan key"
    );
}

// #2916 fail-on-revert: the same-plan fast path in `apply_snapshot`
// (`handlers/snapshot.rs`) skips `replan_queues` whenever the plan key is
// unchanged. That is only sound if EVERY field `replan_queues` reads to build
// the binding layout is also hashed into `snapshot_binding_plan_key`. If a
// planner-consumed field were dropped from the hash, two snapshots that
// produce DIFFERENT layouts could share a key, the apply path would take the
// same-plan branch, and the live AF_XDP worker layout would stay stale.
//
// #2915 unified the candidate SET (both paths filter through
// `include_userspace_binding_interface`). This test pins the remaining half of
// the #2916 invariant: for a single candidate interface, mutating ANY of the
// three fields `replan_queues` consumes to construct the layout — `linux_name`
// (candidate identity + dedup key), `ifindex` (per-binding ifindex, drives
// registered/armed/ready gating), and `rx_queues` (queue_count) — MUST bump
// the plan key. Each property is paired with a `replan_queues` assertion
// proving the mutated field actually changes the produced layout, so the test
// cannot be satisfied by a field that the planner ignores.
//
// Revert proof: drop any one of `linux_name`, `ifindex`, or `rx_queues` from
// the `iface=...` segment in `update_snapshot_binding_plan_key` and the
// matching property goes RED — a real layout change becomes invisible to the
// same-plan branch.
#[test]
fn plan_key_covers_every_replan_queues_input() {
    use crate::server::helpers::{replan_queues, snapshot_binding_plan_key};

    let mk = |linux_name: &str, ifindex: i32, rx_queues: usize| ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "ge-0/0/1".to_string(),
            linux_name: linux_name.to_string(),
            zone: "trust".to_string(),
            ifindex,
            rx_queues,
            ..Default::default()
        }],
        ..Default::default()
    };

    let base = mk("ge-0-0-1", 11, 2);
    let base_key = snapshot_binding_plan_key(&base);
    let base_layout: Vec<(String, i32, u32)> =
        replan_queues(Some(&base), 2, &[], true).expect("plan")
        .iter()
        .map(|b| (b.interface.clone(), b.ifindex, b.queue_id))
        .collect();

    // linux_name change -> different bound netdev -> must bump key.
    let name_changed = mk("ge-0-0-2", 11, 2);
    assert_ne!(
        base_key,
        snapshot_binding_plan_key(&name_changed),
        "a candidate linux_name change must bump the plan key (#2916): the \
         same-plan branch would otherwise leave the binding on the old netdev"
    );
    let name_layout: Vec<String> = replan_queues(Some(&name_changed), 2, &[], true).expect("plan")
        .iter()
        .map(|b| b.interface.clone())
        .collect();
    assert!(
        name_layout.iter().all(|i| i == "ge-0-0-2"),
        "replan_queues must bind the new linux_name; got {name_layout:?}"
    );

    // ifindex change -> different per-binding ifindex -> must bump key.
    let ifindex_changed = mk("ge-0-0-1", 99, 2);
    assert_ne!(
        base_key,
        snapshot_binding_plan_key(&ifindex_changed),
        "a candidate ifindex change must bump the plan key (#2916): the \
         same-plan branch would otherwise leave bindings pointed at the stale \
         ifindex"
    );
    assert!(
        replan_queues(Some(&ifindex_changed), 2, &[], true).expect("plan")
            .iter()
            .all(|b| b.ifindex == 99),
        "replan_queues must carry the new ifindex onto every binding"
    );

    // rx_queues change -> different queue_count -> must bump key.
    let rx_changed = mk("ge-0-0-1", 11, 4);
    assert_ne!(
        base_key,
        snapshot_binding_plan_key(&rx_changed),
        "a candidate rx_queues change must bump the plan key (#2916): the \
         same-plan branch would otherwise leave a stale queue count"
    );
    assert_ne!(
        base_layout.len(),
        replan_queues(Some(&rx_changed), 2, &[], true).expect("plan").len(),
        "replan_queues must emit a different number of bindings when \
         rx_queues changes"
    );
}

// #3007 fail-on-revert: when the snapshot carries the degenerate `rx_queues ==
// 0` fallback, `replan_queues` reads the live channel count from sysfs
// (`rx_queue_count`) and THAT count drives the layout. The plan key MUST hash
// the same resolved count — otherwise two refreshes with the same (rx_queues=0)
// snapshot but a DIFFERENT actual sysfs channel count (operator ran `ethtool -L
// <if> combined N` out of band, no config commit) share a plan key, the
// same-plan-skip is taken, and the queues are never re-planned to the new count.
//
// Revert proof: change the iface hash in `update_snapshot_binding_plan_key` back
// to hashing `iface.rx_queues` (the raw 0) instead of `effective_rx_queues(...)`
// and this test goes RED — both keys collapse to the same 0-derived hash.
#[test]
fn plan_key_folds_sysfs_resolved_rx_queues_when_snapshot_is_zero() {
    use crate::server::helpers::{
        clear_rx_queue_count_override, set_rx_queue_count_override, snapshot_binding_plan_key,
    };

    // Degenerate snapshot: the Go control plane did not populate a count.
    let mk = || ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "ge-0/0/1".to_string(),
            linux_name: "ge-0-0-1".to_string(),
            zone: "trust".to_string(),
            ifindex: 11,
            rx_queues: 0,
            ..Default::default()
        }],
        ..Default::default()
    };

    // sysfs reports 4 combined channels.
    set_rx_queue_count_override("ge-0-0-1", 4);
    let key_4 = snapshot_binding_plan_key(&mk());

    // Operator runs `ethtool -L ge-0-0-1 combined 6` out of band; the snapshot
    // is byte-identical (still rx_queues=0) but the live channel count changed.
    set_rx_queue_count_override("ge-0-0-1", 6);
    let key_6 = snapshot_binding_plan_key(&mk());

    clear_rx_queue_count_override();

    assert_ne!(
        key_4, key_6,
        "an out-of-band channel change (sysfs rx-queue count) MUST bump the plan \
         key when the snapshot rx_queues is the degenerate 0 fallback (#3007); \
         otherwise the same-plan-skip leaves a stale single-/under-queued layout"
    );
}

// #3007 no-regression: for a NONZERO snapshot rx_queues the plan key must be
// independent of sysfs — the resolved count equals the raw field, sysfs is never
// read, and the key is byte-identical to the pre-#3007 hash for the normal case.
#[test]
fn plan_key_for_nonzero_rx_queues_ignores_sysfs() {
    use crate::server::helpers::{
        clear_rx_queue_count_override, set_rx_queue_count_override, snapshot_binding_plan_key,
    };

    let snap = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "ge-0/0/1".to_string(),
            linux_name: "ge-0-0-1".to_string(),
            zone: "trust".to_string(),
            ifindex: 11,
            rx_queues: 6,
            ..Default::default()
        }],
        ..Default::default()
    };

    // No override: real sysfs returns 0 for the fake netdev, but rx_queues>0 so
    // it is never consulted. This is the pre-#3007 code path (hash iface.rx_queues).
    clear_rx_queue_count_override();
    let baseline = snapshot_binding_plan_key(&snap);

    // Even a wildly different sysfs count must NOT change the key when the
    // snapshot already carries a real count.
    set_rx_queue_count_override("ge-0-0-1", 999);
    let with_override = snapshot_binding_plan_key(&snap);
    clear_rx_queue_count_override();

    assert_eq!(
        baseline, with_override,
        "a nonzero snapshot rx_queues must produce a plan key independent of \
         sysfs (no regression for the normal case, #3007)"
    );
}

// #3091 fail-on-revert: a WAN VLAN unit (`reth0.80` → Linux `ge-0-0-2.80`) is a
// software VLAN device that the kernel exposes with a SINGLE RX queue. Its
// physical parent (`ge-0-0-2`) carries the VLAN-tagged frames on its 6 hardware
// queues. The parent is already a binding candidate, so the VLAN child must be
// deduped onto it and must NOT enter the candidate list as a separate 1-queue
// interface — otherwise `replan_bindings_from_candidates` takes the MIN
// rx_queues across all candidates (`min(6, 1) == 1`), plans a single queue, and
// the dataplane runs with one worker (~6 Gbps, the regression).
//
// Revert proof: delete the `vlan_child_parent_netdev` dedup block in
// `replan_queues` and this test goes RED — the child re-enters the candidate
// list, `queue_count` collapses to 1, and the parent binds on a single queue.
#[test]
fn queue_planner_dedups_wan_vlan_child_onto_physical_parent() {
    use crate::server::helpers::replan_queues;

    let snapshot = ConfigSnapshot {
        interfaces: vec![
            // Physical WAN netdev: 6 hardware RX queues (mlx5 VF).
            InterfaceSnapshot {
                name: "ge-0/0/2".to_string(),
                linux_name: "ge-0-0-2".to_string(),
                zone: "untrust".to_string(),
                ifindex: 12,
                rx_queues: 6,
                ..Default::default()
            },
            // VLAN unit reth0.50: software VLAN netdev, 1 RX queue.
            InterfaceSnapshot {
                name: "ge-0/0/2.50".to_string(),
                linux_name: "ge-0-0-2.50".to_string(),
                parent_linux_name: "ge-0-0-2".to_string(),
                zone: "untrust".to_string(),
                ifindex: 50,
                parent_ifindex: 12,
                vlan_id: 50,
                rx_queues: 1,
                ..Default::default()
            },
            // VLAN unit reth0.80: software VLAN netdev, 1 RX queue.
            InterfaceSnapshot {
                name: "ge-0/0/2.80".to_string(),
                linux_name: "ge-0-0-2.80".to_string(),
                parent_linux_name: "ge-0-0-2".to_string(),
                zone: "untrust".to_string(),
                ifindex: 80,
                parent_ifindex: 12,
                vlan_id: 80,
                rx_queues: 1,
                ..Default::default()
            },
            // LAN netdev: 6 hardware RX queues (also mlx5 VF).
            InterfaceSnapshot {
                name: "ge-0/0/1".to_string(),
                linux_name: "ge-0-0-1".to_string(),
                zone: "trust".to_string(),
                ifindex: 11,
                rx_queues: 6,
                ..Default::default()
            },
        ],
        ..Default::default()
    };

    let bindings = replan_queues(Some(&snapshot), 6, &[], true).expect("plan");

    // The VLAN-child netdevs must NOT be planned as separate candidates.
    assert!(
        bindings
            .iter()
            .all(|b| b.interface != "ge-0-0-2.50" && b.interface != "ge-0-0-2.80"),
        "VLAN-child netdevs must be deduped onto the parent, not planned as \
         separate 1-queue candidates; got {:?}",
        bindings.iter().map(|b| &b.interface).collect::<Vec<_>>()
    );

    // The plan must span all 6 hardware queues (queue_count = min over the two
    // remaining 6-queue physical candidates), NOT collapse to 1.
    let queue_ids: std::collections::BTreeSet<u32> = bindings.iter().map(|b| b.queue_id).collect();
    assert_eq!(
        queue_ids,
        (0..6).collect::<std::collections::BTreeSet<u32>>(),
        "queue_count must be 6 (parent hardware queues), not collapsed to 1 by \
         the VLAN child's single software queue"
    );

    // Both physical parents bind on all 6 queues.
    for netdev in ["ge-0-0-1", "ge-0-0-2"] {
        let q: std::collections::BTreeSet<u32> = bindings
            .iter()
            .filter(|b| b.interface == netdev)
            .map(|b| b.queue_id)
            .collect();
        assert_eq!(
            q,
            (0..6).collect::<std::collections::BTreeSet<u32>>(),
            "{netdev} must bind on all 6 hardware queues"
        );
    }

    // The plan spans workers 0..5 (one per queue), i.e. multi-worker.
    let workers: std::collections::BTreeSet<u32> = bindings.iter().map(|b| b.worker_id).collect();
    assert_eq!(
        workers.len(),
        6,
        "the plan must spread across 6 workers, not a single worker (#3091)"
    );
}

// #3091: an ORPHAN VLAN child whose physical parent is NOT itself a binding
// candidate must still be re-keyed onto the parent netdev with the parent's
// HARDWARE queue count, never the child's single software queue. (This is the
// defensive fallback path; the common case is the parent-is-candidate dedup
// above.) Here the parent never appears as its own snapshot interface, so the
// child resolves the parent's queue count from sysfs — in the unit-test
// sandbox that yields 1 via `rx_queue_count`'s `.max(1)`, but the binding is
// keyed on the PARENT netdev (`ge-0-0-9`), proving the child's own netdev name
// never reaches the candidate list.
#[test]
fn queue_planner_rekeys_orphan_vlan_child_onto_parent_netdev() {
    use crate::server::helpers::replan_queues;

    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "ge-0/0/9.30".to_string(),
            linux_name: "ge-0-0-9.30".to_string(),
            parent_linux_name: "ge-0-0-9".to_string(),
            zone: "untrust".to_string(),
            ifindex: 130,
            parent_ifindex: 19,
            vlan_id: 30,
            rx_queues: 1,
            ..Default::default()
        }],
        ..Default::default()
    };

    let bindings = replan_queues(Some(&snapshot), 2, &[], true).expect("plan");
    assert!(
        bindings.iter().all(|b| b.interface == "ge-0-0-9"),
        "orphan VLAN child must bind on the parent netdev, not its own \
         child netdev; got {:?}",
        bindings.iter().map(|b| &b.interface).collect::<Vec<_>>()
    );
    assert!(
        bindings.iter().all(|b| b.ifindex == 19),
        "orphan VLAN child binding must use the parent ifindex"
    );
}

// #2917 SSOT fail-on-revert: the AF_XDP bind target for a VLAN unit MUST be the
// physical PARENT netdev on BOTH planes. The Go control plane resolves the same
// target via `userspaceBindTargetNetdev` (mirrored from `vlan_child_parent_netdev`)
// and emits it from `UserspaceBoundLinuxInterfaces` (the D3/RSS allowlist); the
// Rust planner must bind the identical netdev so the allowlist, RSS steering, and
// shim maps all target one netdev. A non-VLAN unit binds its OWN netdev (its unit
// netdev and physical netdev are the same device).
//
// Revert proof: change `vlan_child_parent_netdev` to return `None` (or change
// `replan_queues` to push `linux_name` for the VLAN child) and this test goes RED
// — the VLAN child `ge-0-0-2.80` re-enters the candidate list, so a binding with
// `interface == "ge-0-0-2.80"` appears and the parent-only assertion fails.
#[test]
fn replan_queues_binds_vlan_unit_on_parent_netdev() {
    use crate::server::helpers::replan_queues;

    let snapshot = ConfigSnapshot {
        interfaces: vec![
            // Physical WAN netdev parent of the VLAN unit: 6 hardware queues.
            InterfaceSnapshot {
                name: "ge-0/0/2".to_string(),
                linux_name: "ge-0-0-2".to_string(),
                zone: "untrust".to_string(),
                ifindex: 12,
                rx_queues: 6,
                ..Default::default()
            },
            // Tagged VLAN unit reth0.80 → software netdev `ge-0-0-2.80`.
            InterfaceSnapshot {
                name: "ge-0/0/2.80".to_string(),
                linux_name: "ge-0-0-2.80".to_string(),
                parent_linux_name: "ge-0-0-2".to_string(),
                zone: "untrust".to_string(),
                ifindex: 80,
                parent_ifindex: 12,
                vlan_id: 80,
                rx_queues: 1,
                ..Default::default()
            },
            // Plain non-VLAN LAN netdev: binds its OWN netdev, 6 queues.
            InterfaceSnapshot {
                name: "ge-0/0/1".to_string(),
                linux_name: "ge-0-0-1".to_string(),
                zone: "trust".to_string(),
                ifindex: 11,
                rx_queues: 6,
                ..Default::default()
            },
        ],
        ..Default::default()
    };

    let bindings = replan_queues(Some(&snapshot), 6, &[], true).expect("plan");
    let bound: std::collections::BTreeSet<&str> =
        bindings.iter().map(|b| b.interface.as_str()).collect();

    // The VLAN unit binds the PARENT netdev, never its `.80` unit netdev.
    assert!(
        bound.contains("ge-0-0-2"),
        "VLAN unit must bind its physical parent `ge-0-0-2`; bound: {bound:?}"
    );
    assert!(
        !bound.contains("ge-0-0-2.80"),
        "VLAN unit MUST NOT bind its `.80` software unit netdev (no hw queues); \
         bound: {bound:?}"
    );
    // The non-VLAN interface binds its own netdev.
    assert!(
        bound.contains("ge-0-0-1"),
        "non-VLAN interface must bind its own netdev `ge-0-0-1`; bound: {bound:?}"
    );
}

// #3175 fail-on-revert: an ORPHAN VLAN child (a VLAN unit whose physical parent
// is NOT itself a binding candidate) is re-keyed in the LAYOUT onto its parent
// netdev using the parent's HARDWARE queue count (`rx_queue_count(parent)`). The
// plan key MUST hash the SAME value. Before #3175 the key loop hashed the
// child's own software-queue count (`effective_rx_queues(child.rx_queues, ...)`,
// the lone 1-queue VLAN device), so an out-of-band `ethtool -L <parent> combined
// N` on the parent (no config commit) left the key unchanged → same-plan-skip →
// stale layout while `replan_queues` would actually re-plan to the new count.
//
// Revert proof: change `plan_key_rx_queues` back to returning
// `effective_rx_queues(iface.rx_queues, resolved_linux_name)` for the orphan
// case and this test goes RED — the child's rx_queues=1 is hashed for both
// counts, so key_4 == key_6.
#[test]
fn plan_key_folds_parent_sysfs_queues_for_orphan_vlan_child() {
    use crate::server::helpers::{
        clear_rx_queue_count_override, set_rx_queue_count_override, snapshot_binding_plan_key,
    };

    // Orphan VLAN child only: its physical parent `ge-0-0-9` is NOT present as
    // its own snapshot interface, so it is not a binding candidate. The child is
    // a real software VLAN device with a single RX queue (rx_queues=1, nonzero),
    // proving the key must NOT hash the child's own count.
    let mk = || ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "ge-0/0/9.30".to_string(),
            linux_name: "ge-0-0-9.30".to_string(),
            parent_linux_name: "ge-0-0-9".to_string(),
            zone: "untrust".to_string(),
            ifindex: 130,
            parent_ifindex: 19,
            vlan_id: 30,
            rx_queues: 1,
            ..Default::default()
        }],
        ..Default::default()
    };

    // Parent sysfs reports 4 combined channels.
    set_rx_queue_count_override("ge-0-0-9", 4);
    let key_4 = snapshot_binding_plan_key(&mk());

    // Operator runs `ethtool -L ge-0-0-9 combined 6` out of band; the snapshot is
    // byte-identical (child still rx_queues=1) but the parent's live channel
    // count changed.
    set_rx_queue_count_override("ge-0-0-9", 6);
    let key_6 = snapshot_binding_plan_key(&mk());

    clear_rx_queue_count_override();

    assert_ne!(
        key_4, key_6,
        "an out-of-band channel change on the parent of an ORPHAN VLAN child MUST \
         bump the plan key — the key must hash rx_queue_count(parent), the same \
         value the layout uses, not the child's lone software queue (#3175)"
    );
}

// #3175 no-regression: a NORMAL VLAN child (parent IS a binding candidate) keeps
// the pre-#3175 behavior. The layout dedups the child onto the candidate parent
// (which carries its own physical key entry), so the child's key contribution
// stays `effective_rx_queues(child.rx_queues, ...)` and must NOT reach into the
// parent's sysfs channel count. Overriding the parent's sysfs must leave the
// plan key byte-identical.
#[test]
fn plan_key_for_normal_vlan_child_ignores_parent_sysfs() {
    use crate::server::helpers::{
        clear_rx_queue_count_override, set_rx_queue_count_override, snapshot_binding_plan_key,
    };

    let snap = ConfigSnapshot {
        interfaces: vec![
            // Physical parent IS a candidate (nonzero rx_queues).
            InterfaceSnapshot {
                name: "ge-0/0/2".to_string(),
                linux_name: "ge-0-0-2".to_string(),
                zone: "untrust".to_string(),
                ifindex: 12,
                rx_queues: 6,
                ..Default::default()
            },
            // Normal VLAN child (parent present as a candidate above).
            InterfaceSnapshot {
                name: "ge-0/0/2.80".to_string(),
                linux_name: "ge-0-0-2.80".to_string(),
                parent_linux_name: "ge-0-0-2".to_string(),
                zone: "untrust".to_string(),
                ifindex: 80,
                parent_ifindex: 12,
                vlan_id: 80,
                rx_queues: 1,
                ..Default::default()
            },
        ],
        ..Default::default()
    };

    clear_rx_queue_count_override();
    let baseline = snapshot_binding_plan_key(&snap);

    // A wildly different parent sysfs count must NOT change the key: the parent's
    // own rx_queues (6) is nonzero so sysfs is never consulted, and the normal
    // VLAN child must NOT take the orphan branch (parent IS a candidate).
    set_rx_queue_count_override("ge-0-0-2", 999);
    let with_override = snapshot_binding_plan_key(&snap);
    clear_rx_queue_count_override();

    assert_eq!(
        baseline, with_override,
        "a normal VLAN child (parent IS a candidate) must keep the #3007 \
         behavior — the plan key stays independent of the parent's sysfs channel \
         count (only the orphan case re-keys onto the parent, #3175)"
    );
}

#[test]
fn queue_planner_excludes_tunnel_and_local_fabric_ge_interfaces() {
    // #2915: `ge-*`-named interfaces in tunnel or local-fabric contexts are
    // excluded by `include_userspace_binding_interface` (and the Go
    // allowlist). The prefix-only predicate would have planned them.
    let snapshot = ConfigSnapshot {
        interfaces: vec![
            InterfaceSnapshot {
                name: "ge-0/0/5".to_string(),
                linux_name: "ge-0-0-5".to_string(),
                zone: "trust".to_string(),
                ifindex: 30,
                rx_queues: 1,
                tunnel: true,
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "ge-0/0/6".to_string(),
                linux_name: "ge-0-0-6".to_string(),
                zone: "trust".to_string(),
                ifindex: 31,
                rx_queues: 1,
                local_fabric_member: "fab0".to_string(),
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "ge-0/0/7".to_string(),
                linux_name: "ge-0-0-7".to_string(),
                zone: "untrust".to_string(),
                ifindex: 32,
                rx_queues: 1,
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let bindings = replan_queues(Some(&snapshot), 1, &[], true).expect("plan");
    assert_eq!(
        bindings.iter().map(|b| b.interface.clone()).collect::<Vec<_>>(),
        vec!["ge-0-0-7".to_string()],
        "tunnel and local-fabric ge-* interfaces must be excluded from the plan"
    );
}

#[test]
fn queue_planner_includes_fabric_parent_interface() {
    // The fabric parent (ge-0/0/0) is not in snapshot.interfaces but is
    // referenced by snapshot.fabrics.  It needs an XSK binding so the
    // userspace DP can transmit fabric-redirect packets.
    let snapshot = ConfigSnapshot {
        interfaces: vec![
            InterfaceSnapshot {
                name: "ge-0/0/1".to_string(),
                linux_name: "ge-0-0-1".to_string(),
                zone: "trust".to_string(),
                ifindex: 11,
                rx_queues: 1,
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "ge-0/0/2".to_string(),
                linux_name: "ge-0-0-2".to_string(),
                zone: "untrust".to_string(),
                ifindex: 12,
                rx_queues: 1,
                ..Default::default()
            },
        ],
        fabrics: vec![FabricSnapshot {
            parent_unbindable: false,
            name: "fab0".to_string(),
            parent_interface: "ge-0/0/0".to_string(),
            parent_linux_name: "ge-0-0-0".to_string(),
            parent_ifindex: 21,
            overlay_linux_name: "fab0".to_string(),
            overlay_ifindex: 101,
            rx_queues: 1,
            peer_address: "10.99.13.2".to_string(),
            local_mac: String::new(),
            peer_mac: String::new(),
            up: true,
        }],
        ..Default::default()
    };
    let bindings = replan_queues(Some(&snapshot), 1, &[], true).expect("plan");
    // Should have 3 bindings: ge-0-0-1, ge-0-0-2, ge-0-0-0 (fabric parent)
    assert_eq!(bindings.len(), 3);
    let fabric_binding = bindings
        .iter()
        .find(|b| b.interface == "ge-0-0-0")
        .expect("fabric parent binding missing");
    assert_eq!(fabric_binding.ifindex, 21);
    assert!(fabric_binding.registered);
}

#[test]
fn queue_planner_deduplicates_fabric_parent_already_in_interfaces() {
    // When the fabric parent is already in snapshot.interfaces (e.g. as a
    // RETH member), it should not be duplicated.
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "ge-0/0/0".to_string(),
            linux_name: "ge-0-0-0".to_string(),
            zone: "trust".to_string(),
            ifindex: 21,
            rx_queues: 1,
            ..Default::default()
        }],
        fabrics: vec![FabricSnapshot {
            parent_unbindable: false,
            name: "fab0".to_string(),
            parent_interface: "ge-0/0/0".to_string(),
            parent_linux_name: "ge-0-0-0".to_string(),
            parent_ifindex: 21,
            overlay_linux_name: "fab0".to_string(),
            overlay_ifindex: 101,
            rx_queues: 1,
            peer_address: "10.99.13.2".to_string(),
            local_mac: String::new(),
            peer_mac: String::new(),
            up: true,
        }],
        ..Default::default()
    };
    let bindings = replan_queues(Some(&snapshot), 1, &[], true).expect("plan");
    // ge-0-0-0 appears in both interfaces and fabrics but should only
    // produce one binding.
    assert_eq!(bindings.len(), 1);
    assert_eq!(bindings[0].interface, "ge-0-0-0");
    assert_eq!(bindings[0].ifindex, 21);
}

#[test]
fn build_synced_session_entry_preserves_fabric_ingress() {
    let req = SessionSyncRequest {
        operation: "upsert".to_string(),
        addr_family: libc::AF_INET as u8,
        protocol: 6,
        src_ip: "10.0.61.102".to_string(),
        dst_ip: "172.16.80.200".to_string(),
        src_port: 40000,
        dst_port: 5201,
        ingress_zone: "lan".to_string(),
        egress_zone: "wan".to_string(),
        owner_rg_id: 1,
        egress_ifindex: 5,
        tx_ifindex: 5,
        tx_vlan_id: 80,
        fabric_ingress: true,
        ..SessionSyncRequest::default()
    };

    let entry =
        build_synced_session_entry(&req, &test_zone_name_to_id(), 0).expect("synced session entry");
    assert!(entry.metadata.fabric_ingress);
    assert!(entry.origin.is_peer_synced());
    assert_eq!(entry.metadata.owner_rg_id, 1);
}

// #2785: a synced session must carry the per-policy `then log` selection so
// it emits the same RT_FLOW SESSION_CREATE/CLOSE records after failover.
// Reverting the helpers.rs mapping hard-codes both false and this fails RED.
#[test]
fn build_synced_session_entry_applies_log_flags() {
    let req = SessionSyncRequest {
        operation: "upsert".to_string(),
        addr_family: libc::AF_INET as u8,
        protocol: 6,
        src_ip: "10.0.61.102".to_string(),
        dst_ip: "172.16.80.200".to_string(),
        src_port: 40000,
        dst_port: 5201,
        ingress_zone: "lan".to_string(),
        egress_zone: "wan".to_string(),
        egress_ifindex: 5,
        tx_ifindex: 5,
        log_session_init: true,
        log_session_close: true,
        ..SessionSyncRequest::default()
    };
    let entry =
        build_synced_session_entry(&req, &test_zone_name_to_id(), 0).expect("synced session entry");
    assert!(entry.metadata.log_session_init, "log_session_init applied");
    assert!(entry.metadata.log_session_close, "log_session_close applied");

    // Close-only: init must NOT leak true.
    let req_close = SessionSyncRequest {
        log_session_init: false,
        log_session_close: true,
        ..req.clone()
    };
    let entry_close = build_synced_session_entry(&req_close, &test_zone_name_to_id(), 0)
        .expect("synced session entry");
    assert!(!entry_close.metadata.log_session_init);
    assert!(entry_close.metadata.log_session_close);

    // Old peer omits the fields => serde(default) false => no per-policy log.
    let req_none = SessionSyncRequest {
        log_session_init: false,
        log_session_close: false,
        ..req
    };
    let entry_none = build_synced_session_entry(&req_none, &test_zone_name_to_id(), 0)
        .expect("synced session entry");
    assert!(!entry_none.metadata.log_session_init);
    assert!(!entry_none.metadata.log_session_close);
}

// #3301: the admitting policy's firewall metadata (policy_id,
// policy_counter_idx, per-application inactivity-timeout) must ride the
// session-sync wire and be applied to the peer's SyncedSessionEntry so a
// peer-PROMOTED session is correctly attributed, counted, and aged after
// failover. Reverting build_synced_session_entry to the hard 0/None imports
// fails this RED.
#[test]
fn build_synced_session_entry_applies_policy_fields_3301() {
    let req = SessionSyncRequest {
        operation: "upsert".to_string(),
        addr_family: libc::AF_INET as u8,
        protocol: 6,
        src_ip: "10.0.61.102".to_string(),
        dst_ip: "172.16.80.200".to_string(),
        src_port: 40000,
        dst_port: 5201,
        ingress_zone: "lan".to_string(),
        egress_zone: "wan".to_string(),
        egress_ifindex: 5,
        tx_ifindex: 5,
        policy_id: 42,
        policy_counter_idx: 7,
        inactivity_timeout: 30,
        ..SessionSyncRequest::default()
    };
    let entry =
        build_synced_session_entry(&req, &test_zone_name_to_id(), 0).expect("synced session entry");
    assert_eq!(entry.metadata.policy_id, 42, "policy_id must be applied");
    assert_eq!(
        entry.metadata.policy_counter_idx, 7,
        "policy_counter_idx must be applied"
    );
    assert_eq!(
        entry.metadata.inactivity_timeout_ns,
        Some(30u64 * 1_000_000_000),
        "inactivity_timeout (s) must convert to ns and be applied"
    );

    // Mixed-version: an OLD peer omits the new fields (serde default 0). The
    // sync MUST still decode + install with today's defaults (unattributed /
    // no counter / global timeout), NOT be rejected (rolling-upgrade safe).
    let req_legacy: SessionSyncRequest =
        serde_json::from_str(r#"{"operation":"upsert","addr_family":2,"protocol":6,"src_ip":"10.0.61.102","dst_ip":"172.16.80.200","src_port":40000,"dst_port":5201,"ingress_zone":"lan","egress_zone":"wan","egress_ifindex":5,"tx_ifindex":5}"#)
            .expect("legacy SessionSyncRequest without policy fields decodes");
    assert_eq!(req_legacy.policy_id, 0, "missing policy_id defaults to 0");
    assert_eq!(
        req_legacy.policy_counter_idx, 0,
        "missing policy_counter_idx defaults to 0"
    );
    assert_eq!(
        req_legacy.inactivity_timeout, 0,
        "missing inactivity_timeout defaults to 0"
    );
    let entry_legacy = build_synced_session_entry(&req_legacy, &test_zone_name_to_id(), 0)
        .expect("legacy synced session still installs (not rejected)");
    assert_eq!(entry_legacy.metadata.policy_id, 0);
    assert_eq!(entry_legacy.metadata.policy_counter_idx, 0);
    assert_eq!(
        entry_legacy.metadata.inactivity_timeout_ns, None,
        "0 inactivity_timeout maps to None (use global per-protocol timeout)"
    );
}

#[test]
fn build_synced_session_entry_preserves_tunnel_endpoint_id() {
    let req = SessionSyncRequest {
        operation: "upsert".to_string(),
        addr_family: libc::AF_INET as u8,
        protocol: 1,
        src_ip: "10.0.61.102".to_string(),
        dst_ip: "10.255.192.41".to_string(),
        ingress_zone: "lan".to_string(),
        egress_zone: "sfmix".to_string(),
        egress_ifindex: 586,
        tx_ifindex: 0,
        tunnel_endpoint_id: 3,
        ..SessionSyncRequest::default()
    };

    let entry =
        build_synced_session_entry(&req, &test_zone_name_to_id(), 0).expect("synced session entry");
    assert_eq!(entry.decision.resolution.tunnel_endpoint_id, 3);
    assert_eq!(entry.decision.resolution.egress_ifindex, 586);
    assert_eq!(
        entry.decision.resolution.disposition,
        afxdp::ForwardingDisposition::ForwardCandidate
    );
}

/// #919/#922: when a peer sends both legacy zone names and the new
/// u16 IDs, the daemon must trust the IDs. Models a new-peer-to-new-
/// daemon flow where the IDs are authoritative even if the names
/// drift (e.g., a name string is misspelled or unresolved).
#[test]
fn build_synced_session_entry_prefers_id_over_legacy_zone_name() {
    let req = SessionSyncRequest {
        operation: "upsert".to_string(),
        addr_family: libc::AF_INET as u8,
        protocol: 6,
        src_ip: "10.0.61.102".to_string(),
        dst_ip: "172.16.80.200".to_string(),
        src_port: 40000,
        dst_port: 5201,
        ingress_zone: "stale-name".to_string(),
        egress_zone: "stale-name".to_string(),
        ingress_zone_id: 1,
        egress_zone_id: 2,
        owner_rg_id: 1,
        egress_ifindex: 5,
        tx_ifindex: 5,
        ..SessionSyncRequest::default()
    };
    let entry =
        build_synced_session_entry(&req, &test_zone_name_to_id(), 0).expect("synced session entry");
    assert_eq!(entry.metadata.ingress_zone, 1);
    assert_eq!(entry.metadata.egress_zone, 2);
}

/// #919/#922: an old peer (legacy strings, no IDs) lands at a new
/// daemon. `ingress_zone_id == 0` triggers the name-lookup
/// fallback; the session is still installed with the resolved ID.
#[test]
fn build_synced_session_entry_falls_back_to_zone_name_when_id_zero() {
    let req = SessionSyncRequest {
        operation: "upsert".to_string(),
        addr_family: libc::AF_INET as u8,
        protocol: 6,
        src_ip: "10.0.61.102".to_string(),
        dst_ip: "172.16.80.200".to_string(),
        src_port: 40000,
        dst_port: 5201,
        ingress_zone: "lan".to_string(),
        egress_zone: "wan".to_string(),
        owner_rg_id: 1,
        egress_ifindex: 5,
        tx_ifindex: 5,
        ..SessionSyncRequest::default()
    };
    let entry =
        build_synced_session_entry(&req, &test_zone_name_to_id(), 0).expect("synced session entry");
    let m = test_zone_name_to_id();
    assert_eq!(entry.metadata.ingress_zone, m["lan"]);
    assert_eq!(entry.metadata.egress_zone, m["wan"]);
}

/// #919/#922: an old peer with strings that the new daemon doesn't
/// know about. Both legacy and ID lookups fail; metadata zone IDs
/// are 0. The session is still installed (we don't drop it) — the
/// caller observes zone-id 0 and treats it as "unknown".
#[test]
fn build_synced_session_entry_unknown_zone_name_does_not_drop_session() {
    let req = SessionSyncRequest {
        operation: "upsert".to_string(),
        addr_family: libc::AF_INET as u8,
        protocol: 6,
        src_ip: "10.0.61.102".to_string(),
        dst_ip: "172.16.80.200".to_string(),
        src_port: 40000,
        dst_port: 5201,
        ingress_zone: "totally-unknown".to_string(),
        egress_zone: "another-unknown".to_string(),
        owner_rg_id: 1,
        egress_ifindex: 5,
        tx_ifindex: 5,
        ..SessionSyncRequest::default()
    };
    let entry =
        build_synced_session_entry(&req, &test_zone_name_to_id(), 0).expect("synced session entry");
    assert_eq!(entry.metadata.ingress_zone, 0);
    assert_eq!(entry.metadata.egress_zone, 0);
}

#[test]
fn queue_planner_preserves_existing_state() {
    let existing = vec![BindingStatus {
        slot: 0,
        queue_id: 0,
        worker_id: 0,
        interface: "ge-0-0-1".to_string(),
        ifindex: 11,
        registered: true,
        armed: true,
        ready: true,
        last_change: Some(Utc::now()),
        ..Default::default()
    }];
    let bindings = replan_bindings_from_candidates(
        1,
        &existing,
        vec![("ge-0-0-1".to_string(), 1)],
        BTreeMap::from([("ge-0-0-1".to_string(), 11)]),
        true,
    ).expect("plan");
    if let Some(b0) = bindings.iter().find(|b| b.slot == 0) {
        assert!(b0.registered);
        assert!(b0.armed);
        assert!(b0.ready);
    } else {
        panic!("binding 0 missing");
    }
}

#[test]
fn queue_planner_ignores_tunnel_netdevices_for_transit() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![
            InterfaceSnapshot {
                name: "gr-0/0/0.0".to_string(),
                linux_name: "gr-0-0-0".to_string(),
                ifindex: 586,
                rx_queues: 1,
                tunnel: true,
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "ge-0/0/2.80".to_string(),
                linux_name: "ge-0-0-2.80".to_string(),
                zone: "untrust".to_string(),
                ifindex: 24,
                parent_ifindex: 6,
                rx_queues: 1,
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let bindings = replan_queues(Some(&snapshot), 1, &[], true).expect("plan");
    assert_eq!(bindings.len(), 1);
    assert_eq!(bindings[0].interface, "ge-0-0-2.80");
    assert_eq!(bindings[0].ifindex, 24);
}

#[test]
fn queue_planner_preserves_manual_unregistration() {
    let existing = vec![BindingStatus {
        slot: 0,
        queue_id: 0,
        worker_id: 0,
        interface: "ge-0-0-1".to_string(),
        ifindex: 11,
        registered: false,
        armed: false,
        last_change: Some(Utc::now()),
        ..Default::default()
    }];
    let bindings = replan_bindings_from_candidates(
        1,
        &existing,
        vec![("ge-0-0-1".to_string(), 1)],
        BTreeMap::from([("ge-0-0-1".to_string(), 11)]),
        true,
    ).expect("plan");
    let b0 = bindings.iter().find(|b| b.slot == 0).expect("binding 0");
    assert!(!b0.registered);
    assert!(!b0.armed);
}

#[test]
fn queue_planner_keeps_queue_zero_available_for_userspace() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![
            InterfaceSnapshot {
                name: "ge-0/0/1".to_string(),
                linux_name: "ge-0-0-1".to_string(),
                zone: "trust".to_string(),
                ifindex: 11,
                rx_queues: 2,
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "reth1.0".to_string(),
                linux_name: "reth1".to_string(),
                parent_linux_name: "ge-0-0-1".to_string(),
                ifindex: 21,
                addresses: vec![InterfaceAddressSnapshot {
                    family: "inet".to_string(),
                    address: "10.0.61.1/24".to_string(),
                    scope: 0,
                }],
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let bindings = replan_queues(Some(&snapshot), 2, &[], true).expect("plan");
    let q0 = bindings
        .iter()
        .find(|b| b.interface == "ge-0-0-1" && b.queue_id == 0)
        .expect("queue 0 binding");
    let q1 = bindings
        .iter()
        .find(|b| b.interface == "ge-0-0-1" && b.queue_id == 1)
        .expect("queue 1 binding");
    assert!(q0.registered);
    assert!(q1.registered);
}

#[test]
fn queue_planner_binds_each_interfaces_own_queue_count_7497() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![
            InterfaceSnapshot {
                name: "ge-0/0/1".to_string(),
                linux_name: "ge-0-0-1".to_string(),
                zone: "trust".to_string(),
                rx_queues: 4,
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "ge-0/0/2".to_string(),
                linux_name: "ge-0-0-2".to_string(),
                zone: "untrust".to_string(),
                rx_queues: 2,
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let bindings = replan_queues(Some(&snapshot), 2, &[], true).expect("plan");
    // #7497: 4 + 2 = 6, not min(4,2) x 2 = 4. Under the old global-minimum rule
    // ge-0-0-1's queues 2 and 3 were left UNBOUND, and an unbound queue is not
    // idle — the shim takes `drop_degraded_transit` on BINDING_MISSING, so every
    // transit packet RSS steered there was dropped.
    assert_eq!(
        bindings.len(),
        6,
        "each interface must contribute its own queue count (4 + 2), not the \
         global minimum applied to both (2 x 2)"
    );
    let queues = summarize_queues(&bindings);
    assert_eq!(queues.len(), 4, "the widest interface sets the queue-id range");
    // The plan is RAGGED: rows 0-1 carry both interfaces, rows 2-3 carry only
    // the 4-queue one. Asserting the ragged shape rather than just the count is
    // what distinguishes per-interface planning from "bind 6 things".
    for (idx, q) in queues.iter().enumerate() {
        assert_eq!(q.queue_id, idx as u32);
        let want = if idx < 2 {
            vec!["ge-0-0-1".to_string(), "ge-0-0-2".to_string()]
        } else {
            vec!["ge-0-0-1".to_string()]
        };
        assert_eq!(
            q.interfaces, want,
            "queue {idx} membership: only interfaces that HAVE queue {idx}"
        );
        assert!(!q.registered);
    }
}

#[test]
fn queue_planner_dedups_physical_and_unit_to_same_netdev() {
    // #1921 regression: the snapshot lists BOTH the physical interface and
    // its unit (`ge-0/0/0` + `ge-0/0/0.0`); for a non-VLAN unit both resolve
    // to the SAME Linux netdev. replan_queues must plan ONE binding per
    // (netdev, queue_id), not two — a duplicate is a guaranteed double-bind
    // (the second XSK on an already-bound queue returns EBUSY, the queue
    // never goes READY, and transit is dropped: the virtio multi-queue
    // forwarding outage).
    let snapshot = ConfigSnapshot {
        interfaces: vec![
            InterfaceSnapshot {
                name: "ge-0/0/0".to_string(),
                linux_name: "ge-0-0-0".to_string(),
                zone: "trust".to_string(),
                rx_queues: 4,
                ..Default::default()
            },
            InterfaceSnapshot {
                // unit 0 of the same physical NIC — same Linux netdev.
                name: "ge-0/0/0.0".to_string(),
                linux_name: "ge-0-0-0".to_string(),
                zone: "trust".to_string(),
                rx_queues: 4,
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let bindings = replan_queues(Some(&snapshot), 1, &[], true).expect("plan");
    // 4 queues x 1 netdev = 4 bindings, NOT 8.
    assert_eq!(
        bindings.len(),
        4,
        "physical+unit on the same netdev must not double the binding plan"
    );
    // Every (ifindex, queue_id) pair must be unique (no double-bind).
    let mut seen = std::collections::HashSet::new();
    for b in &bindings {
        assert!(
            seen.insert((b.ifindex, b.queue_id)),
            "duplicate binding for (ifindex={}, queue_id={})",
            b.ifindex,
            b.queue_id
        );
    }
    let queues = summarize_queues(&bindings);
    assert_eq!(queues.len(), 4);
    for q in &queues {
        assert_eq!(q.interfaces, vec!["ge-0-0-0".to_string()]);
    }
}

#[test]
fn afxdp_runtime_stays_off_when_forwarding_is_unarmed() {
    let status = ProcessStatus {
        forwarding_armed: false,
        capabilities: UserspaceCapabilities {
            forwarding_supported: true,
            unsupported_reasons: Vec::new(),
        },
        ..Default::default()
    };
    assert!(!should_run_afxdp(&status));
}

#[test]
fn afxdp_runtime_stays_off_when_forwarding_is_unsupported() {
    let status = ProcessStatus {
        forwarding_armed: true,
        capabilities: UserspaceCapabilities {
            forwarding_supported: false,
            unsupported_reasons: vec!["ha".to_string()],
        },
        ..Default::default()
    };
    assert!(!should_run_afxdp(&status));
}

#[test]
fn afxdp_runtime_starts_only_when_armed_and_supported() {
    let status = ProcessStatus {
        forwarding_armed: true,
        capabilities: UserspaceCapabilities {
            forwarding_supported: true,
            unsupported_reasons: Vec::new(),
        },
        ..Default::default()
    };
    assert!(should_run_afxdp(&status));
}

#[test]
fn forwarding_arm_updates_registered_bindings() {
    let mut status = ProcessStatus {
        bindings: vec![
            BindingStatus {
                registered: true,
                ..Default::default()
            },
            BindingStatus {
                registered: false,
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    set_bindings_forwarding_armed(&mut status, true);
    assert!(status.bindings[0].armed);
    assert!(!status.bindings[1].armed);
    set_bindings_forwarding_armed(&mut status, false);
    assert!(!status.bindings[0].armed);
    assert!(!status.bindings[1].armed);
}

#[test]
fn binding_counters_snapshot_projects_ring_pressure_fields() {
    // #802/#804: verify projection from BindingStatus into the
    // focused BindingCountersSnapshot carries every ring-pressure
    // field (with the #804 split of bound-pending vs CoS queue
    // overflow), plus the operator-facing TX drop trio re-surfaced
    // for triage. Non-coprime-prime per field so an accidental
    // re-attribution across fields is caught.
    let binding = BindingStatus {
        slot: 0,
        queue_id: 4,
        worker_id: 7,
        ifindex: 12,
        dbg_tx_ring_full: 11,
        dbg_sendto_enobufs: 13,
        dbg_bound_pending_overflow: 17,
        dbg_cos_queue_overflow: 41,
        rx_fill_ring_empty_descs: 19,
        outstanding_tx: 23,
        tx_errors: 29,
        tx_shared_recycle_unknown_slot_drops: 43,
        tx_shared_recycle_unknown_slot_rescued: 61,
        tx_submit_error_drops: 31,
        pending_tx_local_overflow_drops: 37,
        mirror_drops_queue_full_same_worker: 47,
        mirror_drops_queue_full_cross_worker: 49,
        // #918 / #943: pin per-set LRU collision and V_min telemetry
        // through the projection so a future refactor that drops
        // either assignment surfaces here.
        flow_cache_collision_evictions: 53,
        active_flow_count: 71,
        flow_cache_capacity: 4096,
        v_min_throttle_hard_cap_overrides: 59,
        v_min_throttles: 67,
        ..Default::default()
    };
    // #804: exercise the `impl From<&BindingStatus>` path. The old
    // named `from_binding_status` was renamed to the idiomatic
    // `From` impl so iterator adaptors and `into()` callsites get
    // the conversion for free.
    let snap = BindingCountersSnapshot::from(&binding);
    assert_eq!(snap.worker_id, 7);
    assert_eq!(snap.ifindex, 12);
    assert_eq!(snap.queue_id, 4);
    assert_eq!(snap.dbg_tx_ring_full, 11);
    assert_eq!(snap.dbg_sendto_enobufs, 13);
    assert_eq!(snap.dbg_bound_pending_overflow, 17);
    assert_eq!(snap.dbg_cos_queue_overflow, 41);
    assert_eq!(snap.rx_fill_ring_empty_descs, 19);
    assert_eq!(snap.outstanding_tx, 23);
    assert_eq!(snap.tx_errors, 29);
    assert_eq!(snap.tx_shared_recycle_unknown_slot_drops, 43);
    assert_eq!(snap.tx_shared_recycle_unknown_slot_rescued, 61);
    assert_eq!(snap.tx_submit_error_drops, 31);
    assert_eq!(snap.pending_tx_local_overflow_drops, 37);
    assert_eq!(snap.mirror_drops_queue_full_same_worker, 47);
    assert_eq!(snap.mirror_drops_queue_full_cross_worker, 49);
    assert_eq!(snap.flow_cache_collision_evictions, 53);
    // #1219: pin active_flow_count projection through the From impl.
    assert_eq!(snap.active_flow_count, 71);
    assert_eq!(snap.flow_cache_capacity, 4096);
    assert_eq!(snap.v_min_throttle_hard_cap_overrides, 59);
    assert_eq!(snap.v_min_throttles, 67);
}

#[test]
fn binding_counters_snapshot_serializes_with_expected_wire_keys() {
    // #802/#804: the daemon's poll path parses these JSON keys. Pin
    // the wire names so a rename that breaks the consumer is caught
    // at CI, not in the field. Uses `serde_json::Value` key
    // introspection rather than substring matching so a key that
    // happens to appear inside another field's string value does
    // not accidentally pass the assertion (the original #802 test
    // was flagged in round-1 review as brittle for exactly this
    // reason).
    let snap = BindingCountersSnapshot {
        worker_id: 1,
        ifindex: 2,
        queue_id: 3,
        dbg_tx_ring_full: 4,
        dbg_sendto_enobufs: 5,
        dbg_bound_pending_overflow: 6,
        dbg_cos_queue_overflow: 12,
        rx_fill_ring_empty_descs: 7,
        outstanding_tx: 8,
        tx_completion_ring_available: 30,
        tx_completion_ring_available_max: 32,
        tx_errors: 9,
        tx_shared_recycle_unknown_slot_drops: 14,
        tx_shared_recycle_unknown_slot_rescued: 15,
        tx_submit_error_drops: 10,
        pending_tx_local_overflow_drops: 11,
        mirrored_packets: 32,
        mirrored_bytes: 33,
        mirror_drops_no_frame: 34,
        mirror_drops_tx_frame_reserve: 35,
        mirror_drops_no_binding: 36,
        mirror_drops_queue_full: 37,
        mirror_drops_queue_full_same_worker: 38,
        mirror_drops_queue_full_cross_worker: 39,
        // #812: populated so wire-key assertions below also cover
        // the new TX submit-latency fields.
        tx_submit_latency_hist: vec![13, 14, 15],
        tx_submit_latency_count: 16,
        tx_submit_latency_sum_ns: 17,
        // #825: populated so wire-key assertions below also cover
        // the new TX kick-latency fields.
        tx_kick_latency_hist: vec![18, 19, 20],
        tx_kick_latency_count: 21,
        tx_kick_latency_sum_ns: 22,
        tx_kick_retry_count: 23,
        // #878: UMEM / TX-ring utilization fields. Plausible
        // values so the wire-key assertions below also cover them.
        umem_total_frames: 24,
        umem_inflight_frames: 25,
        tx_ring_capacity: 26,
        // #918: per-set LRU collision-eviction counter.
        flow_cache_collision_evictions: 27,
        // #1219: non-zero fixture so the wire-key assertion below also covers
        // this field explicitly. Note: active_flow_count has no
        // skip_serializing_if and serializes even when 0; the non-zero
        // value here is chosen to make the test intent obvious.
        active_flow_count: 31,
        flow_cache_capacity: 4096,
        v_min_throttle_hard_cap_overrides: 28,
        v_min_throttles: 29,
        v_min_suspended_batches: 30,
    };
    let value: serde_json::Value =
        serde_json::to_value(&snap).expect("serialize snapshot to Value");
    let obj = value
        .as_object()
        .expect("snapshot serializes as a JSON object");
    for key in [
        "worker_id",
        "ifindex",
        "queue_id",
        "dbg_tx_ring_full",
        "dbg_sendto_enobufs",
        "dbg_bound_pending_overflow",
        "dbg_cos_queue_overflow",
        "rx_fill_ring_empty_descs",
        "outstanding_tx",
        // #1241: TX completion-ring uniformity wire keys. These
        // are required before full flow-fairness measurements so
        // step1/fairness consumers can separate CQ backlog from
        // RSS-placement skew.
        "tx_completion_ring_available",
        "tx_completion_ring_available_max",
        "tx_errors",
        "tx_shared_recycle_unknown_slot_drops",
        "tx_shared_recycle_unknown_slot_rescued",
        "tx_submit_error_drops",
        "pending_tx_local_overflow_drops",
        "mirrored_packets",
        "mirrored_bytes",
        "mirror_drops_no_frame",
        "mirror_drops_tx_frame_reserve",
        "mirror_drops_no_binding",
        "mirror_drops_queue_full",
        "mirror_drops_queue_full_same_worker",
        "mirror_drops_queue_full_cross_worker",
        // #812: new wire keys — absence from BindingCountersSnapshot
        // JSON breaks the Go-side step1-capture consumer.
        "tx_submit_latency_hist",
        "tx_submit_latency_count",
        "tx_submit_latency_sum_ns",
        // #825: new wire keys — absence breaks the P3 / step1
        // kick-latency consumer.
        "tx_kick_latency_hist",
        "tx_kick_latency_count",
        "tx_kick_latency_sum_ns",
        "tx_kick_retry_count",
        // #878: UMEM / TX-ring utilization wire keys (Copilot
        // A.1: must be in the asserted list since the comment
        // above claims wire-key assertions cover them).
        "umem_total_frames",
        "umem_inflight_frames",
        "tx_ring_capacity",
        // #918: per-set LRU collision-eviction counter wire key.
        "flow_cache_collision_evictions",
        // #1219: distinct active flow count wire key — absence breaks
        // the fairness harness's Cstruct computation. The field is
        // always serialized (no skip_serializing_if); the non-zero
        // fixture value makes the assertion intent clear.
        "active_flow_count",
        // #1453/#1454: Rust-owned flow-cache denominator wire key.
        "flow_cache_capacity",
        // #941 Work item D / #943: V_min throttle counter wire keys.
        // Absence breaks the binding-counter snapshot consumer that
        // gates fairness diagnostics on these fields.
        "v_min_throttle_hard_cap_overrides",
        "v_min_throttles",
    ] {
        assert!(
            obj.contains_key(key),
            "wire key `{key}` missing from snapshot JSON object: {value}"
        );
    }
    // #804: the pre-split `dbg_pending_overflow` wire key must not
    // reappear — that was the conflation the split removed.
    assert!(
        !obj.contains_key("dbg_pending_overflow"),
        "pre-split wire key `dbg_pending_overflow` unexpectedly present: {value}"
    );
    // Round-trip: the daemon's JSON → Rust decode path must be
    // symmetric with the Rust encode path.
    let json = serde_json::to_string(&snap).expect("serialize snapshot");
    let round: BindingCountersSnapshot = serde_json::from_str(&json).expect("deserialize snapshot");
    assert_eq!(round, snap);
}

fn run_control_request(
    state: Arc<Mutex<ServerState>>,
    state_file: &str,
    request: ControlRequest,
) -> ControlResponse {
    let (mut client, server) = std::os::unix::net::UnixStream::pair().expect("control socket pair");
    let running = Arc::new(AtomicBool::new(true));
    let state_file = state_file.to_string();
    let handle = {
            let sd = state.lock().expect("state").afxdp.session_domain().clone();
            std::thread::spawn(move || handle_stream(server, &state_file, state, running, sd, SocketMode::Main))
        };

    serde_json::to_writer(&mut client, &request).expect("write request");
    std::io::Write::write_all(&mut client, b"\n").expect("newline");

    let response: ControlResponse =
        serde_json::from_reader(std::io::BufReader::new(client)).expect("read response");
    handle
        .join()
        .expect("handler thread")
        .expect("handler result");
    response
}

/// #3789: clearing `defer_workers` on a same-plan apply TRIGGERS the
/// deferred-binding reconcile (`debug_reconcile_calls` 0 -> 1). When that
/// reconcile aborts in the pre-teardown preflight — here the gen-2 snapshot
/// clears its mandatory map pins, so it stops at `missing_xsk_pin` — the
/// full-reconcile handler leg now FAILS CLOSED: it reports `ok=false` and
/// keeps the prior deferred (gen-1) snapshot as the boot baseline. Before
/// #3789 `afxdp.reconcile` returned `()`, the handler swallowed the abort,
/// stored the rejected gen-2 (defer_workers=false) snapshot, and acked
/// ok=true — the M1 class #3766 fixed only for the same-plan *refresh* leg.
///
/// #5171: the gen-1 DEFERRED apply now carries valid (test-sentinel) map
/// pins so it passes the new `validate_snapshot_buildable` gate and is
/// still defer-accepted (ok=true). Before #5171 the deferred apply skipped
/// that integrity build entirely, so gen-1 was acked ok=true even with NO
/// map pins — the fail-open this test used to lean on to keep gen-1 valid.
/// The missing-pin abort is now injected at gen-2 (map pins cleared) where
/// the reconcile actually runs.
#[test]
fn apply_snapshot_same_plan_clearing_defer_workers_reconcile_abort_fails_closed_3789() {
    let state = Arc::new(Mutex::new(ServerState {
        status: ProcessStatus {
            workers: 1,
            ring_entries: 64,
            forwarding_armed: true,
            capabilities: UserspaceCapabilities {
                forwarding_supported: true,
                unsupported_reasons: Vec::new(),
            },
            ..ProcessStatus::default()
        },
        snapshot: None,
        afxdp: afxdp::Coordinator::new(),
        state_writer: Arc::new(StateWriter::new()),
        quarantined_after_panic: false,
    }));
    let state_file = format!(
        "{}/xpf-defer-workers-reconcile-{}.json",
        std::env::temp_dir().display(),
        std::process::id()
    );
    let _ = std::fs::remove_file(&state_file);

    let deferred_snapshot = ConfigSnapshot {
        version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
        generation: 1,
        fib_generation: 1,
        generated_at: Utc::now(),
        capabilities: UserspaceCapabilities {
            forwarding_supported: true,
            unsupported_reasons: Vec::new(),
        },
        userspace: serde_json::json!({
            "workers": 1,
            "ring_entries": 64,
        }),
        // #5171: define the "lan" zone the interface references so the
        // forwarding build in validate_snapshot_buildable resolves it. Before
        // #5171 the deferred apply skipped the build entirely, so this gen-1
        // snapshot was accepted even though its zoned interface referenced an
        // UNDEFINED zone (a non-buildable config) — the fail-open this fix
        // closes.
        zones: vec![ZoneSnapshot {
            name: "lan".to_string(),
            id: 1,
            ..ZoneSnapshot::default()
        }],
        interfaces: vec![InterfaceSnapshot {
            name: "ge-0/0/1.0".to_string(),
            zone: "lan".to_string(),
            linux_name: "ge-0-0-1".to_string(),
            ifindex: 11,
            rx_queues: 1,
            ..InterfaceSnapshot::default()
        }],
        // #5171: valid (test-sentinel) map pins so the deferred apply passes
        // validate_snapshot_buildable and is still accepted (ok=true). The
        // missing-pin abort is injected at gen-2 below, not here.
        map_pins: MapPins {
            xsk: "test-map-pin-ok://xsk".to_string(),
            heartbeat: "test-map-pin-ok://heartbeat".to_string(),
            sessions: "test-map-pin-ok://sessions".to_string(),
            ..MapPins::default()
        },
        defer_workers: true,
        ..ConfigSnapshot::default()
    };

    let response = run_control_request(
        state.clone(),
        &state_file,
        ControlRequest {
            request_type: "apply_snapshot".to_string(),
            snapshot: Some(deferred_snapshot.clone()),
            ..ControlRequest::default()
        },
    );
    assert!(response.ok, "unexpected error: {}", response.error);
    let status = response.status.expect("status response");
    assert_eq!(status.debug_reconcile_calls, 0);
    assert_eq!(status.bindings.len(), 1);
    assert!(status.bindings[0].registered);
    assert!(status.bindings[0].last_error.is_empty());

    let mut resumed_snapshot = deferred_snapshot.clone();
    resumed_snapshot.generation = 2;
    resumed_snapshot.fib_generation = 2;
    resumed_snapshot.generated_at = Utc::now();
    resumed_snapshot.defer_workers = false;
    // #5171: clear the mandatory map pins on gen-2 so the deferred-binding
    // reconcile aborts at `missing_xsk_pin` (map pins are NOT part of the
    // binding-plan key, so gen-1 and gen-2 stay same-plan). Pre-#5171 the
    // missing pin lived on gen-1, but a deferred apply with no pins is now
    // rejected by validate_snapshot_buildable before it can be stored.
    resumed_snapshot.map_pins = MapPins::default();
    assert!(same_binding_plan(&deferred_snapshot, &resumed_snapshot));

    let response = run_control_request(
        state.clone(),
        &state_file,
        ControlRequest {
            request_type: "apply_snapshot".to_string(),
            snapshot: Some(resumed_snapshot),
            ..ControlRequest::default()
        },
    );
    // #3789: the aborted deferred-binding reconcile must fail closed.
    assert!(
        !response.ok,
        "an aborted deferred-binding reconcile must fail closed (#3789), got ok=true"
    );
    assert!(
        response.error.contains("missing_xsk_pin"),
        "unexpected error: {}",
        response.error
    );
    let status = response.status.expect("status response");
    // The reconcile WAS triggered (the point of clearing defer_workers) and
    // aborted at the missing mandatory pin.
    assert_eq!(status.debug_reconcile_calls, 1);
    assert_eq!(status.debug_reconcile_stage, "missing_xsk_pin");
    // #3789: the rejected gen-2 snapshot must NOT overwrite the boot
    // baseline — the prior deferred (gen-1, defer_workers=true) snapshot
    // stays stored.
    {
        let guard = state.lock().expect("state poisoned");
        let stored = guard.snapshot.as_ref().expect("snapshot");
        assert_eq!(
            stored.generation, 1,
            "a rejected apply must keep the prior snapshot as the boot baseline"
        );
        assert!(
            stored.defer_workers,
            "a rejected apply must keep the prior deferred snapshot intact"
        );
    }

    let _ = std::fs::remove_file(&state_file);
}

#[test]
fn apply_snapshot_rejects_unsupported_protocol_version() {
    let (mut client, server) = std::os::unix::net::UnixStream::pair().expect("control socket pair");
    let state = Arc::new(Mutex::new(ServerState {
        status: ProcessStatus::default(),
        snapshot: None,
        afxdp: afxdp::Coordinator::new(),
        state_writer: Arc::new(StateWriter::new()),
        quarantined_after_panic: false,
    }));
    let running = Arc::new(AtomicBool::new(true));
    let state_file = format!(
        "{}/xpf-policy-scheduler-version-gate-{}.json",
        std::env::temp_dir().display(),
        std::process::id()
    );
    let handle = {
        let state = state.clone();
        let running = running.clone();
        {
            let sd = state.lock().expect("state").afxdp.session_domain().clone();
            std::thread::spawn(move || handle_stream(server, &state_file, state, running, sd, SocketMode::Main))
        }
    };

    let request = ControlRequest {
        request_type: "apply_snapshot".to_string(),
        snapshot: Some(ConfigSnapshot {
            version: CONFIG_SNAPSHOT_PROTOCOL_VERSION - 1,
            generated_at: Utc::now(),
            ..ConfigSnapshot::default()
        }),
        ..ControlRequest::default()
    };
    serde_json::to_writer(&mut client, &request).expect("write request");
    std::io::Write::write_all(&mut client, b"\n").expect("newline");

    let response: ControlResponse =
        serde_json::from_reader(std::io::BufReader::new(client)).expect("read response");
    assert!(!response.ok);
    assert!(
        response
            .error
            .contains("unsupported snapshot protocol version"),
        "unexpected error: {}",
        response.error
    );
    handle
        .join()
        .expect("handler thread")
        .expect("handler result");
}

fn apply_snapshot_for_test(
    state: Arc<Mutex<ServerState>>,
    snapshot: ConfigSnapshot,
) -> ControlResponse {
    let (mut client, server) = std::os::unix::net::UnixStream::pair().expect("control socket pair");
    let running = Arc::new(AtomicBool::new(true));
    let state_file = format!(
        "{}/xpf-apply-snapshot-test-{}-{}.json",
        std::env::temp_dir().display(),
        std::process::id(),
        snapshot.generation
    );
    let handle = {
        let state = state.clone();
        let running = running.clone();
        let state_file = state_file.clone();
        {
            let sd = state.lock().expect("state").afxdp.session_domain().clone();
            std::thread::spawn(move || handle_stream(server, &state_file, state, running, sd, SocketMode::Main))
        }
    };

    let request = ControlRequest {
        request_type: "apply_snapshot".to_string(),
        snapshot: Some(snapshot),
        ..ControlRequest::default()
    };
    serde_json::to_writer(&mut client, &request).expect("write request");
    std::io::Write::write_all(&mut client, b"\n").expect("newline");

    let response: ControlResponse =
        serde_json::from_reader(std::io::BufReader::new(client)).expect("read response");
    handle
        .join()
        .expect("handler thread")
        .expect("handler result");
    let _ = std::fs::remove_file(state_file);
    response
}

fn persistent_snat_apply_snapshot(generation: u64) -> ConfigSnapshot {
    ConfigSnapshot {
        version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
        generated_at: Utc::now(),
        generation,
        capabilities: UserspaceCapabilities {
            forwarding_supported: true,
            ..UserspaceCapabilities::default()
        },
        // #2440: the reconcile preflight now opens the mandatory map
        // FDs (xsk/heartbeat/sessions) BEFORE publishing the forwarding
        // state, so a snapshot with empty mandatory pins aborts before
        // the SNAT state this test inspects is published. Wire the
        // mandatory pins to the bpf_map::pin test sentinel (resolves to
        // a dummy fd without bpffs) so the apply proceeds to publish.
        // Sentinel literal mirrors `TEST_MAP_PIN_OK` in
        // userspace-dp/src/afxdp/bpf_map/pin.rs (the const is
        // afxdp-scoped, not reachable from this crate-root test module).
        map_pins: MapPins {
            xsk: "test-map-pin-ok://xsk".to_string(),
            heartbeat: "test-map-pin-ok://heartbeat".to_string(),
            sessions: "test-map-pin-ok://sessions".to_string(),
            ..MapPins::default()
        },
        source_nat_rules: vec![SourceNATRuleSnapshot {
            name: "persistent-snat".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            pool_name: "persistent-pool".to_string(),
            pool_addresses: vec!["203.0.113.10".to_string()],
            port_low: 40000,
            port_high: 40001,
            persistent_nat: true,
            persistent_nat_permit_any_remote_host: true,
            persistent_nat_inactivity_timeout: 300,
            ..SourceNATRuleSnapshot::default()
        }],
        ..ConfigSnapshot::default()
    }
}

fn apply_path_persistent_snat_key(
    src_port: u16,
    dst_ip: std::net::IpAddr,
    dst_port: u16,
) -> crate::session::SessionKey {
    crate::session::SessionKey {
        addr_family: 2,
        protocol: 17,
        src_ip: "192.0.2.10".parse().unwrap(),
        dst_ip,
        src_port,
        dst_port,
            discriminator: Default::default(),
            routing_domain: 0,
    }
}

#[test]
fn apply_snapshot_same_plan_preserves_persistent_snat_lease_state() {
    // #10647: worker bring-up waits for the IPsec SA monitor baseline, which
    // needs a privileged NETLINK_XFRM bind. Unprivileged, bring-up aborts with
    // IpsecSaNotReady before this test's subject — skip explicitly (visible
    // with --nocapture) instead of failing on sandbox privilege.
    if !crate::afxdp::forwarding::xfrm_monitor_usable() {
        eprintln!("SKIP: needs NETLINK_XFRM bind privilege for the SA-monitor baseline");
        return;
    }
    // #7413: this test brings a coordinator up and therefore spawns a
    // `neigh-monitor` thread, which the #6637 leak gates count PROCESS-WIDE.
    // It is the one spawner outside `coordinator/tests.rs`, which is why the
    // guard is `pub(crate)` rather than module-scoped.
    let _neigh_serial = crate::afxdp::neigh_monitor_test_serial();
    let state = Arc::new(Mutex::new(ServerState {
        status: ProcessStatus {
            forwarding_armed: true,
            capabilities: UserspaceCapabilities {
                forwarding_supported: true,
                ..UserspaceCapabilities::default()
            },
            ..ProcessStatus::default()
        },
        snapshot: None,
        afxdp: afxdp::Coordinator::new(),
        state_writer: Arc::new(StateWriter::new()),
        quarantined_after_panic: false,
    }));

    let initial = apply_snapshot_for_test(state.clone(), persistent_snat_apply_snapshot(1));
    assert!(initial.ok, "initial apply failed: {}", initial.error);

    let first_dst: std::net::IpAddr = "8.8.8.8".parse().unwrap();
    let first_nat = {
        let guard = state.lock().expect("server state");
        match guard.afxdp.test_match_source_nat_result_for_tuple(
            "lan",
            "wan",
            "192.0.2.10".parse().unwrap(),
            first_dst,
            17,
            12345,
            53,
            None,
            None,
            1,
        ) {
            crate::nat::SourceNatLookup::Matched(decision) => decision,
            other => panic!("unexpected first SNAT lookup result: {other:?}"),
        }
    };
    {
        let guard = state.lock().expect("server state");
        guard.afxdp.test_release_source_nat_allocation(
            &apply_path_persistent_snat_key(12345, first_dst, 53),
            first_nat,
            2,
        );
        let status = guard.afxdp.source_nat_pool_statuses();
        assert_eq!(status[0].live_flows, 0);
        assert_eq!(status[0].used_ports, 1);
        assert_eq!(status[0].persistent_leases, 1);
        assert_eq!(status[0].allocations_total, 1);
        assert_eq!(status[0].reuses_total, 0);
    }

    let refresh = apply_snapshot_for_test(state.clone(), persistent_snat_apply_snapshot(2));
    assert!(refresh.ok, "same-plan apply failed: {}", refresh.error);
    {
        let guard = state.lock().expect("server state");
        let status = guard.afxdp.source_nat_pool_statuses();
        assert_eq!(status[0].live_flows, 0);
        assert_eq!(status[0].used_ports, 1);
        assert_eq!(status[0].persistent_leases, 1);
        assert_eq!(status[0].allocations_total, 1);
        assert_eq!(status[0].reuses_total, 0);
    }

    let second_dst: std::net::IpAddr = "1.1.1.1".parse().unwrap();
    let reused = {
        let guard = state.lock().expect("server state");
        match guard.afxdp.test_match_source_nat_result_for_tuple(
            "lan",
            "wan",
            "192.0.2.10".parse().unwrap(),
            second_dst,
            17,
            12345,
            443,
            None,
            None,
            3,
        ) {
            crate::nat::SourceNatLookup::Matched(decision) => decision,
            other => panic!("unexpected reused SNAT lookup result: {other:?}"),
        }
    };
    assert_eq!(reused.rewrite_src, first_nat.rewrite_src);
    assert_eq!(reused.rewrite_src_port, first_nat.rewrite_src_port);
    {
        let guard = state.lock().expect("server state");
        let status = guard.afxdp.source_nat_pool_statuses();
        assert_eq!(status[0].live_flows, 1);
        assert_eq!(status[0].used_ports, 1);
        assert_eq!(status[0].persistent_leases, 1);
        assert_eq!(status[0].allocations_total, 1);
        assert_eq!(status[0].reuses_total, 1);
    }
    // #6637: this test's apply reaches coordinator bringup, which spawns the
    // `neigh-monitor` thread. There is no `impl Drop for Coordinator`, and this
    // one lives inside a ServerState behind an Arc<Mutex<..>>, so nothing here
    // tears it down — it was the last of the eight spawners in the suite still
    // leaking. The thread holds a netlink socket subscribed to RTMGRP_NEIGH and
    // parses every host neighbor event into a map nobody reads for the life of
    // the test binary.
    state.lock().expect("server state").afxdp.stop();
}

#[test]
fn binding_counters_snapshot_tolerates_pre_split_wire() {
    // #804: a helper snapshot that pre-dates the
    // dbg_pending_overflow → {dbg_bound_pending_overflow,
    // dbg_cos_queue_overflow} split must still deserialize — the
    // two new fields should default to 0 rather than the decode
    // failing. This is the compat contract the split relies on.
    let legacy_json = r#"{
        "worker_id": 1,
        "ifindex": 2,
        "queue_id": 3,
        "dbg_tx_ring_full": 4,
        "dbg_sendto_enobufs": 5,
        "dbg_pending_overflow": 99,
        "rx_fill_ring_empty_descs": 7,
        "outstanding_tx": 8,
        "tx_errors": 9,
        "tx_submit_error_drops": 10,
        "pending_tx_local_overflow_drops": 11
    }"#;
    let snap: BindingCountersSnapshot =
        serde_json::from_str(legacy_json).expect("legacy snapshot decodes");
    // The unknown legacy field is discarded; the two new fields
    // default to 0 via `serde(default)`. Callers that need a total
    // across either path must sum the two explicitly — there is no
    // silent re-attribution of the legacy number to one bucket.
    assert_eq!(snap.dbg_bound_pending_overflow, 0);
    assert_eq!(snap.dbg_cos_queue_overflow, 0);
    // Everything else round-trips as expected.
    assert_eq!(snap.worker_id, 1);
    assert_eq!(snap.dbg_tx_ring_full, 4);
    assert_eq!(snap.rx_fill_ring_empty_descs, 7);
}

#[test]
fn config_snapshot_three_color_policers_roundtrip() {
    let json = r#"{
        "version": 1,
        "generation": 42,
        "generated_at": "2026-05-17T00:00:00Z",
        "summary": {
            "host_name": "fw",
            "dataplane_type": "userspace",
            "interface_count": 0,
            "zone_count": 0,
            "policy_count": 0,
            "scheduler_count": 0,
            "ha_enabled": false
        },
        "three_color_policers": [
            {
                "name": "tr",
                "mode": "two-rate",
                "color_blind": true,
                "committed_rate_bytes_per_sec": 125000,
                "committed_burst_bytes": 50000,
                "peak_or_excess_rate_bytes_per_sec": 250000,
                "peak_or_excess_burst_bytes": 100000,
                "then_action": "discard"
            }
        ]
    }"#;
    let snap: ConfigSnapshot = serde_json::from_str(json).expect("three-color snapshot decodes");
    assert_eq!(snap.three_color_policers.len(), 1);
    let policer = &snap.three_color_policers[0];
    assert_eq!(policer.name, "tr");
    assert_eq!(policer.mode, "two-rate");
    assert!(policer.color_blind);
    assert_eq!(policer.committed_rate_bytes_per_sec, 125000);
    assert_eq!(policer.committed_burst_bytes, 50000);
    assert_eq!(policer.peak_or_excess_rate_bytes_per_sec, 250000);
    assert_eq!(policer.peak_or_excess_burst_bytes, 100000);

    let encoded = serde_json::to_value(&snap).expect("three-color snapshot serializes");
    assert!(
        encoded.get("three_color_policers").is_some(),
        "three_color_policers wire key missing from Rust serialization: {encoded}"
    );
}

/// #7357 §2: `mirror_exclusions` is a Go-side diagnostic the helper never
/// consumes, and it must stay that way in BOTH directions.
///
/// The Go builder now records why a port-mirroring entry was refused so the
/// show surfaces can render the applied verdict. The helper has no use for it
/// and models no field for it — which is fine only because the DTOs carry no
/// `#[serde(deny_unknown_fields)]`. That is an ABSENCE, and an absence is
/// exactly what a later hardening commit removes without realising a
/// mixed-version wire depended on it (the #6853 lesson, same shape).
///
/// So this pins it: a snapshot carrying the new key must still decode, and the
/// entries the helper DOES consume must survive intact rather than the parse
/// failing or the unknown key displacing them.
#[test]
fn config_snapshot_tolerates_mirror_exclusions_7357() {
    let json = r#"{
        "version": 1,
        "generation": 42,
        "generated_at": "2026-05-17T00:00:00Z",
        "summary": {
            "host_name": "fw",
            "dataplane_type": "userspace",
            "interface_count": 0,
            "zone_count": 0,
            "policy_count": 0,
            "scheduler_count": 0,
            "ha_enabled": false
        },
        "mirror_configs": [
            {"ingress_ifindex": 11, "output_ifindex": 22, "rate": 100}
        ],
        "mirror_exclusions": [
            {"instance": "span1", "reason": "output interface ge-0/0/9.0 has no ifindex"},
            {"instance": "span2", "input": "ge-0/0/0.0", "reason": "ingress interface ge-0/0/0.0 already mirrored by instance span1"}
        ]
    }"#;
    let snap: ConfigSnapshot = serde_json::from_str(json)
        .expect("a snapshot carrying mirror_exclusions must still decode on the helper");
    assert_eq!(
        snap.mirror_configs,
        vec![MirrorConfigSnapshot {
            ingress_ifindex: 11,
            output_ifindex: 22,
            rate: 100,
        }],
        "the unknown mirror_exclusions key must not disturb the entries the helper does consume"
    );
}

#[test]
fn config_snapshot_mirror_configs_roundtrip() {
    let json = r#"{
        "version": 1,
        "generation": 42,
        "generated_at": "2026-05-17T00:00:00Z",
        "summary": {
            "host_name": "fw",
            "dataplane_type": "userspace",
            "interface_count": 0,
            "zone_count": 0,
            "policy_count": 0,
            "scheduler_count": 0,
            "ha_enabled": false
        },
        "mirror_configs": [
            {"ingress_ifindex": 11, "output_ifindex": 22, "rate": 100},
            {"ingress_ifindex": 12, "output_ifindex": 22, "rate": 0}
        ]
    }"#;
    let snap: ConfigSnapshot = serde_json::from_str(json).expect("mirror snapshot decodes");
    assert_eq!(
        snap.mirror_configs,
        vec![
            MirrorConfigSnapshot {
                ingress_ifindex: 11,
                output_ifindex: 22,
                rate: 100,
            },
            MirrorConfigSnapshot {
                ingress_ifindex: 12,
                output_ifindex: 22,
                rate: 0,
            },
        ],
        "Rust snapshot DTO must round-trip the Go mirror_configs wire shape"
    );

    let encoded = serde_json::to_value(&snap).expect("mirror snapshot serializes");
    assert!(
        encoded.get("mirror_configs").is_some(),
        "mirror_configs wire key missing from Rust serialization: {encoded}"
    );
}

#[test]
fn tx_latency_hist_serialization_roundtrip() {
    // #812 plan §6.1 test #4. Construct a BindingCountersSnapshot
    // with a non-trivial TX submit-latency histogram; JSON-encode,
    // JSON-decode; assert field-equality — including the Vec<u64>
    // contents (no length truncation, no reorder).
    let snap = BindingCountersSnapshot {
        worker_id: 2,
        ifindex: 11,
        queue_id: 5,
        dbg_tx_ring_full: 0,
        dbg_sendto_enobufs: 0,
        dbg_bound_pending_overflow: 0,
        dbg_cos_queue_overflow: 0,
        rx_fill_ring_empty_descs: 0,
        outstanding_tx: 0,
        tx_completion_ring_available: 0,
        tx_completion_ring_available_max: 0,
        tx_errors: 0,
        tx_shared_recycle_unknown_slot_drops: 0,
        tx_shared_recycle_unknown_slot_rescued: 0,
        tx_submit_error_drops: 0,
        pending_tx_local_overflow_drops: 0,
        mirrored_packets: 0,
        mirrored_bytes: 0,
        mirror_drops_no_frame: 0,
        mirror_drops_tx_frame_reserve: 0,
        mirror_drops_no_binding: 0,
        mirror_drops_queue_full: 0,
        mirror_drops_queue_full_same_worker: 0,
        mirror_drops_queue_full_cross_worker: 0,
        // Hand-built plausible histogram — bucket 0 heavy,
        // tail in buckets 6-7, saturation bucket 15 empty.
        tx_submit_latency_hist: vec![9001, 123, 45, 30, 12, 4, 8, 2, 0, 0, 0, 0, 0, 0, 0, 0],
        tx_submit_latency_count: 9225,
        tx_submit_latency_sum_ns: 12_345_678,
        // #825: unrelated-to-submit values so the round-trip
        // also covers the four new fields.
        tx_kick_latency_hist: vec![4000, 80, 20, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        tx_kick_latency_count: 4105,
        tx_kick_latency_sum_ns: 7_654_321,
        tx_kick_retry_count: 42,
        // #878: UMEM / TX-ring utilization fields.
        umem_total_frames: 12_288,
        umem_inflight_frames: 4_096,
        tx_ring_capacity: 2_048,
        // #918: per-set LRU collision-eviction counter.
        flow_cache_collision_evictions: 17,
        active_flow_count: 0,
        flow_cache_capacity: 0,
        v_min_throttle_hard_cap_overrides: 18,
        v_min_throttles: 19,
        v_min_suspended_batches: 20,
    };
    let json = serde_json::to_string(&snap).expect("serialize snapshot");
    let back: BindingCountersSnapshot = serde_json::from_str(&json).expect("deserialize snapshot");
    assert_eq!(back, snap);
    assert_eq!(back.tx_submit_latency_hist.len(), 16);
    assert_eq!(back.tx_submit_latency_hist[0], 9001);
    assert_eq!(back.tx_submit_latency_hist[7], 2);
}

#[test]
fn tx_latency_hist_backward_compat_old_payload_deserializes() {
    // #812 plan §6.1 test #4 (second half). A pre-#812 JSON
    // payload MUST deserialize without the three new fields
    // — they default to empty Vec / zero u64 via
    // `#[serde(default)]`. This is the wire-compat contract
    // the step1-capture consumer relies on.
    let legacy_json = r#"{
        "worker_id": 5,
        "ifindex": 7,
        "queue_id": 2,
        "dbg_tx_ring_full": 0,
        "dbg_sendto_enobufs": 0,
        "dbg_bound_pending_overflow": 0,
        "dbg_cos_queue_overflow": 0,
        "rx_fill_ring_empty_descs": 0,
        "outstanding_tx": 0,
        "tx_errors": 0,
        "tx_submit_error_drops": 0,
        "pending_tx_local_overflow_drops": 0
    }"#;
    let snap: BindingCountersSnapshot =
        serde_json::from_str(legacy_json).expect("pre-#812 payload decodes");
    assert_eq!(snap.worker_id, 5);
    assert!(
        snap.tx_submit_latency_hist.is_empty(),
        "pre-#812 payload must default to empty Vec<u64>",
    );
    assert_eq!(snap.tx_submit_latency_count, 0);
    assert_eq!(snap.tx_submit_latency_sum_ns, 0);
}

#[test]
fn tx_latency_hist_binding_counters_snapshot_is_static_send() {
    // #812 plan §6.1 test #8 (runtime corollary of the named
    // compile-time const-assert
    // `_ASSERT_BINDING_COUNTERS_SNAPSHOT_IS_OWNED_STATIC_SEND`
    // in protocol.rs). Exercise the `'static + Send` bound at
    // test time too so if the const-assert were ever silently
    // removed, this test still fires. A reference-holding
    // future field would fail EITHER the compile (const-
    // assert) OR this runtime helper (which requires
    // `T: 'static + Send`), catching the regression two
    // different ways.
    fn require_static_send<T: 'static + Send>() {}
    require_static_send::<BindingCountersSnapshot>();
}

// ---------------------------------------------------------------------------
// #5619: an IPsec secure tunnel (st<N>) gets no AF_XDP binding.
// ---------------------------------------------------------------------------
//
// Route-based IPsec decrypts in the KERNEL XFRM stack, which delivers the
// plaintext on the xfrmi netdev, and the dataplane has no path to hand a
// plaintext frame back INTO an xfrmi for the egress direction.
//
// THE REASON THAT IS PROVABLE HERE (#6691 round 8) is neither of those: an
// xfrm interface has exactly ONE RX queue (`numrxqueues 1`; a lone `rx-0`
// under `/sys/class/net/<if>/queues`), so admitting one puts an AF_XDP binding
// on a netdev the dataplane can never transmit back into.
//
// Until #7497 the harm was GLOBAL rather than local: the planner's queue count
// was the minimum across all candidates, so one zoned xfrmi took every physical
// interface on the box down to one queue and one worker (the #3091
// single-worker regression). #7497 made each interface contribute its own
// `min(rx_queues, 16)`, so that amplification is gone — a spurious xfrmi now
// costs exactly one spurious binding, plus one slot against the
// MAX_BINDING_SLOTS capacity.
//
// A guard named `secure_tunnel_would_collapse_the_global_queue_count` asserted
// the collapse and was RETIRED in the same work: with per-interface counts the
// LAN keeps its own queues whether or not the tunnel is admitted, so the
// assertion held identically with the exclusion deleted — it had stopped being
// a fail-on-revert. The exclusion is guarded by the two identity tests below,
// both of which DO fail when `include_userspace_binding_interface` stops
// refusing on `secure_tunnel` (measured).
//
// Earlier rounds of this comment asserted instead that "an XSK cannot come up
// on a virtual netdev, so the shim would DROP the plaintext". Zero-copy indeed
// cannot (no `ndo_bpf`/`ndo_xsk_wakeup`) — but zero-copy is not required for
// every socket role (`XskSocketRole::Private` → `requires_zerocopy() == false`,
// generic-XDP interfaces are offered `COPY_ONLY_BIND_FLAGS`, and a failed
// shared-UMEM group falls back to a private socket). A copy-mode binding is
// REACHABLE in this code, so that claim was never established; settling it
// needs a live NIC. It is not asserted anywhere below.
//
// Before #5619 the xfrmi was kept out of the binding plan by ACCIDENT: the Go
// snapshot resolved `st0.0` to the nonexistent netdev `st0`, so the unit
// carried ifindex 0. #5619 fixed that name — which means this exclusion now has
// to be stated deliberately.

/// The real planner must produce NO binding for a secure tunnel, while still
/// planning the ordinary data interface beside it.
///
/// There is no Rust classification table paired with the Go one any more, and
/// the paragraph that described one has been removed: #6691 round 5 deleted
/// `is_secure_tunnel_ifname` and made this plane read the snapshot's
/// `secure_tunnel` flag, so the name shape is never re-derived here. This test
/// sets that flag directly, which is exactly what the Go control plane ships.
#[test]
fn binding_candidate_excludes_secure_tunnel() {
    use crate::server::helpers::replan_queues;

    let snapshot = ConfigSnapshot {
        interfaces: vec![
            InterfaceSnapshot {
                name: "ge-0/0/1".to_string(),
                linux_name: "ge-0-0-1".to_string(),
                zone: "trust".to_string(),
                ifindex: 11,
                rx_queues: 2,
                ..Default::default()
            },
            // The xfrmi as it appears AFTER the #5619 name fix: a real netdev
            // name and a resolved ifindex. Pre-fix this row carried linux_name
            // "st0" and ifindex 0, so it was excluded for the wrong reason —
            // this row must be excluded on its own merits.
            InterfaceSnapshot {
                name: "st0.0".to_string(),
                // #6691 r5: ownership is resolved by the Go control plane and
                // shipped in the snapshot; no Rust-side name rule exists now.
                secure_tunnel: true,
                linux_name: "st0.0".to_string(),
                zone: "vpn".to_string(),
                ifindex: 42,
                rx_queues: 1,
                ..Default::default()
            },
        ],
        ..Default::default()
    };

    let bindings = replan_queues(Some(&snapshot), 2, &[], true).expect("plan");
    assert!(
        !bindings.is_empty(),
        "premise broken: the ordinary data interface must still be planned, \
         otherwise this test would pass vacuously"
    );
    assert!(
        bindings.iter().all(|b| b.interface != "st0.0"),
        "the planner produced an AF_XDP binding for a secure tunnel (#5619). \
         An xfrmi has ONE RX queue and the planner's queue count is the global \
         minimum, so admitting it collapses every physical interface to a \
         single queue and a single worker (#3091). Planned: {:?}",
        bindings.iter().map(|b| &b.interface).collect::<Vec<_>>()
    );
    assert!(
        bindings.iter().any(|b| b.interface == "ge-0-0-1"),
        "the ordinary data interface must still be planned"
    );
}

/// #5619: adding a secure tunnel must leave the binding PLAN byte-identical.
///
/// The Go half of this differential lives in
/// `TestSecureTunnelAddsNothingToTheAdjudicatedSets`
/// (pkg/dataplane/userspace/secure_tunnel_ifname_5619_test.go), which pins the
/// ingress-adjudication set and the RSS allowlist. This is the binding-plan
/// half: the same candidate list is planned twice, once with a RESOLVED
/// secure-tunnel row and once without it, and the produced layout must be
/// identical — same slots, same queue ids, same interfaces.
///
/// The premise matters as much as the result. The tunnel row carries a real
/// netdev name and a real ifindex, i.e. it is the row as it appears AFTER the
/// #5619 name fix. Were it the pre-fix row (linux_name "st0", ifindex 0) the
/// two plans would match for the old accidental reason and this would prove
/// nothing.
#[test]
fn secure_tunnel_adds_nothing_to_the_binding_plan() {
    use crate::server::helpers::replan_queues;

    let lan = InterfaceSnapshot {
        name: "ge-0/0/1".to_string(),
        linux_name: "ge-0-0-1".to_string(),
        zone: "trust".to_string(),
        ifindex: 11,
        rx_queues: 2,
        ..Default::default()
    };
    let tunnel = InterfaceSnapshot {
        name: "st0.0".to_string(),
        // #6691 r5: ownership is resolved by the Go control plane and
        // shipped in the snapshot; no Rust-side name rule exists now.
        secure_tunnel: true,
        linux_name: "st0.0".to_string(),
        zone: "vpn".to_string(),
        ifindex: 42,
        rx_queues: 1,
        ..Default::default()
    };
    // PREMISE: this is the POST-fix row — resolved name, real ifindex.
    assert_eq!(tunnel.linux_name, "st0.0");
    assert!(tunnel.ifindex > 0);

    let with_tunnel = ConfigSnapshot {
        interfaces: vec![lan.clone(), tunnel],
        ..Default::default()
    };
    let without_tunnel = ConfigSnapshot {
        interfaces: vec![lan],
        ..Default::default()
    };

    let got = replan_queues(Some(&with_tunnel), 2, &[], true).expect("plan");
    let want = replan_queues(Some(&without_tunnel), 2, &[], true).expect("plan");

    assert!(
        !want.is_empty(),
        "premise broken: the ordinary data interface must still be planned, \
         otherwise this differential is vacuous"
    );
    let key = |bindings: &[BindingStatus]| -> Vec<(u32, u32, String)> {
        bindings
            .iter()
            .map(|b| (b.slot, b.queue_id, b.interface.clone()))
            .collect()
    };
    assert_eq!(
        key(&got),
        key(&want),
        "adding a route-based IPsec secure tunnel CHANGED the binding plan. The \
         xfrmi must add nothing: the dataplane cannot transmit back into an \
         xfrm interface, so a binding there can only drop (#5619 / #3091). \
         Since #7497 each interface contributes its own queue count, so the \
         cost of admitting it is one spurious binding rather than collapsing \
         every other interface onto one queue — this identity check is what \
         holds the exclusion now."
    );
}

// ---------------------------------------------------------------------------
// #5173: the shim must not transform a packet's queue coordinate.
// ---------------------------------------------------------------------------
//
// AF_XDP delivery is queue-bound: the kernel's `xsk_rcv_check` drops a redirect
// whose target socket is bound to a different (netdev, queue) than the packet
// arrived on. So between "which queue did this arrive on" and "which XSK do we
// redirect to" the queue coordinate must survive unchanged.
//
// SCOPE, stated plainly, because the three checks below are NOT the same kind
// of check and that difference decides what they can catch.
//
// The shim is `no_std`, built for `bpfel-unknown-none`, so this crate cannot
// execute the shim BINARY. What it can do — and now does — is compile the
// shim's own index module for the host and RUN it: `binding_index.rs` is
// `#[path]`-included below, so `shim_binding_slot_never_leaves_its_interfaces_row`
// is a behavioural test of the exact source the BPF object is built from. The
// mapping and the stride bound are results there, not claims about text.
//
// What execution cannot cover is whether the shim still CALLS that function,
// and with what arguments. That half is unavoidably a source assertion, and a
// source assertion only sees what it is written to look for. Two hostile rounds
// escaped earlier versions of it with every guard green:
//
//   round 1 — transform the raw `rx_queue_index` before the identity call, and
//             add a raw fallback lookup in a DIFFERENT file, which a
//             file-scoped check cannot see by construction.
//   round 2 — the repo-scoped rewrite that fixed round 1 replaced a token-exact
//             index pin with a bare occurrence COUNT of the needle
//             `USERSPACE_BINDINGS.get(` — and a count cannot see an index that
//             has been transformed. Six mutations reintroduced #5173 green,
//             including `.get(idx % 4)`, dropping `binding_slot` from the path
//             entirely, and reinstating the removed unbounded raw-queue
//             fallback with a single NEWLINE before `.get(` — which is exactly
//             the formatting rustfmt emits for a chain of that length.
//
// Coverage had REGRESSED while the claim strengthened. So the source half is
// now TOKEN-based rather than substring-based, and it pins whole STATEMENTS
// rather than counting needles: `shim_token_vec` drops whitespace, so rustfmt
// reflow is invisible to it while any added, removed or altered token is not.
// What is STILL unbound is enumerated on
// `shim_index_path_has_one_construction_and_one_lookup` — that list is not
// empty and cannot be made empty by a source assertion.
//
// The planner half of #5173 was reverted from this PR (see #6702), so the
// executable coverage that used to be cited here no longer exists in this
// branch; `queue_planner_uses_smallest_queue_count` — master's own test,
// restored by that revert — is what exercises the real planner now, and it is
// the negative control for the mutation matrix precisely because it is true in
// both worlds.

/// Collapse a Rust snippet to a formatting-insensitive token VECTOR.
///
/// Identifiers (and numbers) are single tokens; every other non-whitespace
/// character is its own token. Whitespace is dropped entirely.
///
/// This is the whole reason the checks below survive rustfmt AND catch what a
/// substring count cannot. A newline is not a token here, so
/// `USERSPACE_BINDINGS\n.get(` and `USERSPACE_BINDINGS.get(` are the SAME
/// sequence — while as substrings they differ, and that one-character
/// difference was the entire bypass for the reinstated raw-queue fallback in
/// the round-2 review. Conversely `.get(idx)` and `.get(idx % 4)` are the same
/// SUBSTRING prefix but different token sequences, which is the direction a
/// bare needle count is blind in.
fn shim_token_vec(src: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut chars = src.chars().peekable();
    while let Some(c) = chars.next() {
        if c.is_whitespace() {
            continue;
        }
        if c.is_alphanumeric() || c == '_' {
            let mut w = String::from(c);
            while let Some(&n) = chars.peek() {
                if n.is_alphanumeric() || n == '_' {
                    w.push(n);
                    chars.next();
                } else {
                    break;
                }
            }
            out.push(w);
        } else {
            out.push(c.to_string());
        }
    }
    out
}

/// Space-joined [`shim_token_vec`], for readable assertion messages.
fn shim_tokens(src: &str) -> String {
    shim_token_vec(src).join(" ")
}

/// Count occurrences of a token SEQUENCE inside a token stream.
///
/// Windows overlap, so a repeat that abuts its predecessor is still counted —
/// undercounting here would be a fail-OPEN, and the whole point of these checks
/// is that a second occurrence must be impossible to hide.
fn shim_token_seq_count(hay: &[String], needle: &[&str]) -> usize {
    if needle.is_empty() || hay.len() < needle.len() {
        return 0;
    }
    hay.windows(needle.len())
        .filter(|w| w.iter().zip(needle).all(|(a, b)| a.as_str() == *b))
        .count()
}

// #5173: the index computation is EXECUTED here, not described.
//
// `binding_index.rs` is the shim's own source, `#[path]`-included and compiled
// for the host. What runs below is the code the BPF object is built from.
#[path = "../../userspace-xdp/src/binding_index.rs"]
mod shim_binding_index;

/// The value ladder both coordinate axes are driven over: `2^k`, `2^k - 1` and
/// `2^k + 1` for every representable `k`, plus `0` and `ceiling`.
///
/// NOT a hand-picked spread, and the difference IS the round-6 defect. The
/// executed grid this replaces was `ifindex ∈ {0,1,2,7,63,1000,65535}` ×
/// `queue ∈ [0,64)`, and on it `& 0xffff` is the identity on every ifindex
/// while `& 0x3f` is the identity on every queue. Both masks were added to the
/// shim's own function bodies, compiled, and left all three tests below GREEN
/// with a masking instruction in the emitted object. The grid's largest tested
/// value on each axis WAS the boundary of the mask that walked through it — the
/// check was precisely coextensive with the defect it existed to catch.
///
/// A ladder removes that tell, and the caller asserts the property that makes
/// it work: the bitwise OR of the returned values is all-ones across the
/// representable range, so ANY mask that clears a bit alters at least one
/// tested result. That is a property rather than a bigger grid, which matters —
/// simply widening the old spread would have moved the boundary to the new
/// maximum and bought one round. It is still not the primary bound: an executed
/// axis always has a largest value, so the function BODIES are pinned
/// token-for-token as well, in
/// `shim_index_path_has_one_construction_and_one_lookup`.
fn shim_coordinate_ladder(ceiling: u32) -> Vec<u32> {
    let mut out = vec![0u32, ceiling];
    for k in 0..u32::BITS {
        let p = 1u32 << k;
        out.extend([p - 1, p]);
        if let Some(next) = p.checked_add(1) {
            out.push(next);
        }
    }
    out.retain(|v| *v <= ceiling);
    out.sort_unstable();
    out.dedup();
    out
}

/// Every `(ifindex, queue)` resolves to its OWN interface's row, or to nothing.
///
/// This replaces four source-spelling checks that a hostile review escaped
/// twice. The mapping, the stride bound, and the property that a slot never
/// leaves its interface's row are now results of running the shim's function.
///
/// Driven over [`shim_coordinate_ladder`] on both axes rather than over the
/// hand-picked spread it used to carry — see there for the two masks that
/// walked through that spread with this test green.
#[test]
fn shim_binding_slot_never_leaves_its_interfaces_row() {
    use shim_binding_index::{BINDING_QUEUES_PER_IFACE as STRIDE, RawRxQueue, binding_slot};

    // NEITHER axis has a ceiling (#9900 F-150). The interface-half axis used
    // to stop at 2^28 - 1 because the plain `u32` multiply overflowed above
    // it and host and target genuinely disagreed (a debug host build panics
    // on the overflow, the release target wraps). The checked multiply
    // resolves what overflows to NO slot, identically on both targets, so the
    // axis runs to `u32::MAX` like the queue axis and asserts the `None`
    // above 2^28 - 1 exactly as it asserts exact slots below it. The queue
    // coordinate is rejected before the multiply, so its axis always ran to
    // `u32::MAX`.
    const IFINDEX_CEILING: u32 = u32::MAX;
    let ifindexes = shim_coordinate_ladder(IFINDEX_CEILING);
    let queues = shim_coordinate_ladder(u32::MAX);

    // Each axis is floored on ITS OWN dimension. A combined count would let one
    // axis collapse to nothing while the other satisfied the threshold alone,
    // and the round-6 escape lived in exactly one axis at a time.
    let check_axis = |label: &str, values: &[u32], ceiling: u32, probes: [u32; 3], floor: usize| {
        assert!(
            values.len() >= floor,
            "#5173: the {label} axis must carry at least {floor} values, found {}",
            values.len(),
        );
        for probe in probes {
            assert!(
                values.contains(&probe),
                "#5173: the {label} axis must test {probe}. The spread this replaced stopped just \
                 below exactly these points, which is what made `& 0xffff` (ifindex) and `& 0x3f` \
                 (queue) the identity on every value it tested.",
            );
        }
        assert_eq!(
            values.iter().fold(0u32, |acc, v| acc | v),
            ceiling,
            "#5173: the {label} axis must set every bit a representable value can carry, or a \
             mask clearing one of them is the identity on the whole axis and this test cannot \
             see it",
        );
    };
    check_axis(
        "ifindex",
        &ifindexes,
        IFINDEX_CEILING,
        [65536, 65537, IFINDEX_CEILING],
        80,
    );
    check_axis("queue", &queues, u32::MAX, [64, 65, u32::MAX], 90);
    assert!(
        queues.iter().any(|q| *q < STRIDE) && queues.iter().any(|q| *q >= STRIDE),
        "#5173: the queue axis must straddle the stride boundary, or one half of the mapping is \
         never exercised",
    );

    for &ifindex in &ifindexes {
        // u64 throughout: the top of the ifindex axis puts `row_start + STRIDE`
        // far past `u32::MAX`, and the expected value must be computed in a
        // width that cannot itself wrap.
        let row_start = u64::from(ifindex) * u64::from(STRIDE);
        for &q in &queues {
            let got = binding_slot(ifindex, RawRxQueue::from_ctx_field(q));
            if q >= STRIDE {
                assert_eq!(
                    got,
                    None,
                    "#5173: queue {q} is at or above the stride and must resolve to NO binding; \
                     clamping it back into range is the mis-steer in another form, and indexing \
                     with it addresses ifindex {}'s row",
                    u64::from(ifindex) + u64::from(q) / u64::from(STRIDE),
                );
                continue;
            }
            // #9900 F-150: above 2^28 - 1 the composed index overflows `u32`
            // and must resolve to NO binding — a wrap would land on another
            // interface's row, which is the defect this ladder exists to catch.
            let exact = row_start + u64::from(q);
            if exact > u64::from(u32::MAX) {
                assert_eq!(
                    got, None,
                    "#9900: ifindex {ifindex} x queue {q} composes {exact}, past `u32::MAX`, \
                     and must fail closed as a clean miss, not wrap onto another row",
                );
                continue;
            }
            let slot = got.unwrap_or_else(|| panic!("in-stride queue {q} resolved to no binding"));
            assert_eq!(
                u64::from(slot),
                row_start + u64::from(q),
                "#5173: the slot must be the packet's OWN queue in its OWN interface's row",
            );
            assert!(
                u64::from(slot) >= row_start && u64::from(slot) < row_start + u64::from(STRIDE),
                "#5173: slot {slot} escaped ifindex {ifindex}'s row [{row_start}, {})",
                row_start + u64::from(STRIDE),
            );
        }
    }
}

/// The queue coordinate cannot be transformed after it is wrapped.
///
/// `RawRxQueue` has a private field and no arithmetic impls, so `queue % 2`,
/// `queue & 3` and friends do not COMPILE outside its module — enforced by the
/// compiler rather than asserted about source text. Verified by compiling both
/// directions: `rx_queue % 4` is rejected (E0369) and the tuple constructor is
/// unreachable outside the module (E0423), while reducing the raw `u32` BEFORE
/// construction builds clean — the constructor must accept a bare integer,
/// because the value originates in an aya context no `core`-only module can
/// see.
///
/// TWO things this does NOT cover, stated because an earlier revision claimed
/// there was only one:
///
///  - a reduction applied before the wrap;
///  - a value forged out of raw bytes rather than constructed —
///    `transmute::<u32, RawRxQueue>(..)`, `mem::zeroed()`,
///    `MaybeUninit::assume_init()`, a pointer read. A private field stops the
///    CONSTRUCTOR, not a fabrication, and naming `transmute` alone (as an
///    earlier revision did) understates it: the class is open-ended and every
///    member of it compiles.
///
/// Both are bounded by source instead, in
/// `shim_index_path_has_one_construction_and_one_lookup` — not by chasing the
/// symbols, which would always be one symbol behind, but by bounding the one
/// NAME the pinned lookup statement will accept. Neither is bounded by a type,
/// and no type can bound them.
///
/// This test itself is not decorative: `for_trace()` feeds the queue index the
/// shim hands to the helper in `record_trace`, so corrupting it is a runtime
/// defect and reds here — for any corruption visible somewhere on
/// [`shim_coordinate_ladder`], which is the whole `u32` range at `2^k ± 1`.
/// The shipped version of that sentence said "reds here" with no qualifier
/// while the test evaluated `for_trace()` at exactly ONE input, 3; `self.0 &
/// 0x3f` returns 3 for input 3, so the claim was false for precisely the mask
/// that was demonstrated walking through the index path in the same round. The
/// body is also pinned token-for-token in
/// `shim_index_path_has_one_construction_and_one_lookup`, which is what covers
/// a corruption no executed value can see.
#[test]
fn shim_raw_rx_queue_exposes_no_arithmetic() {
    use shim_binding_index::RawRxQueue;
    let a = RawRxQueue::from_ctx_field(3);
    let b = RawRxQueue::from_ctx_field(3);
    assert_eq!(a, b, "the wrapper must preserve the coordinate verbatim");
    for q in shim_coordinate_ladder(u32::MAX) {
        assert_eq!(
            RawRxQueue::from_ctx_field(q).for_trace(),
            q,
            "#5173: the telemetry readback must return the coordinate VERBATIM; a reduction here \
             makes every trace record name a queue the redirect did not use, which is the \
             mis-traced-drop hazard `binding_index.rs` documents",
        );
    }
}

/// REPO-scoped and TOKEN-exact: the whole shim crate wraps the coordinate in
/// exactly one place and reads the binding map in exactly one place, and BOTH
/// of those statements are pinned token-for-token.
///
/// Two rounds of hostile review shaped this, and both lessons are load-bearing:
///
///  1. **File-scoped is not enough.** A reviewer escaped the per-file version by
///     putting a raw fallback lookup in a DIFFERENT file, which a per-file check
///     cannot see by construction. Hence the crate walk.
///  2. **A count is not enough.** The repo-scoped rewrite that fixed (1)
///     replaced the token-exact index pin with a bare `str::matches` count of
///     `USERSPACE_BINDINGS.get(`. A count cannot see an index that has been
///     transformed, so `.get(idx % 4)` — #5173 verbatim — passed, as did
///     dropping `binding_slot` from the packet path and inlining a reduced
///     index, and as did reinstating the deleted unbounded raw-queue fallback
///     with one NEWLINE before `.get(`. Coverage had regressed while the claim
///     strengthened. Hence whole-STATEMENT token pins.
///  3. **A statement pin fixes SPELLING, not VALUE.** Both coordinates reach
///     the pinned lookup by NAME, so pinning that statement says nothing about
///     what the names are worth. Round 3 shadowed each of them one line above
///     the pin — `% 4` on the ifindex, and an unsafe raw-bytes forgery on the
///     queue — and all three tests stayed green. Hence the binding bounds: a
///     value can only reach the pinned statement through a binding of that
///     exact name, so bounding the BINDINGS is what bounds the values. (The
///     first attempt at that bounded one SPELLING of a binding rather than
///     bindings — see (5).)
///  4. **A compile-time claim is only true while the type still says so.**
///     Adding `impl Rem<u32> for RawRxQueue` and a `pub` field reddened
///     nothing, and with one shadow line reintroduced #5173 with no `unsafe`
///     at all. Hence the trait-impl and field-privacy bounds.
///  5. **A binding bound must bound BINDINGS, not one spelling of one.**
///     `["let", name]` matches a bare-identifier `let` pattern and nothing
///     else. Round 4 walked through it four ways, all compiling with all three
///     tests green: `let (rx_queue, _z) = (transmute::<u32, RawRxQueue>(q % 4),
///     0u32);` — which is #5173 in the EMITTED OBJECT, gaining `r1 &= 0x3`
///     before the map lookup and losing the `> 0xf` stride guard —
///     `let Some(<name>) = … else`, a `macro_rules!` body taking an
///     `$n:ident`, and the closure/`fn` parameter that used to be carried
///     below as the declared residual. Hence the mention TALLY, which is
///     complete over binding forms WRITTEN IN THE WALKED SOURCE in a way no
///     pattern match is: such a binding cannot exist without writing the name
///     it binds.
///  6. **"Written in the walked source" is load-bearing, and round 5 broke the
///     claim that omitted it.** A PROC MACRO binds a name without writing it
///     here: its expansion carries `Span::call_site()`, so it resolves — and
///     shadows — at the invocation. `macro_rules!` is not this hole (a body
///     identifier is def-site hygienic, and an `$n:ident` metavariable is
///     written by the invocation, which IS in the walk); a proc macro is. A
///     crate outside `userspace-xdp/src` emitting
///     `let rx_queue = RawRxQueue::from_ctx_field(rx_queue.for_trace() % 4);`
///     from a parsed string, invoked by the one line `xdp_evil::tune!();`,
///     left every tally exactly where it was, all three tests green, and the
///     emitted object carrying `r2 &= 0x3` after the `xdp_md.rx_queue_index`
///     load the pristine object performs unmasked. Counting cannot see that by
///     construction, so the ROUTE is bounded instead: the shim's Cargo manifest
///     is pinned token-for-token, and both cargo configs read for this build
///     refuse `--extern`, `[patch]` and `[replace]`. Acquiring a proc macro in
///     tree therefore reds. Which is a bound on ACQUIRING one, not on the two
///     already pinned, and not on a config outside the repository — see the
///     residual below.
///  7. **A tally is per FILE, or it is fungible.** A crate total lets a mention
///     freed in one file pay for a shadow added to another; the tally is
///     therefore pinned per file. For the queue coordinate that is what closes
///     conservation, because every one of its `lib.rs` mentions is inside a
///     pinned statement. For the interface coordinate it does not — also below.
///  8. **Everything above bounds where a value COMES FROM and how it is
///     PASSED. None of it bounded what the shim's own functions DO with it.**
///     Round 6 needed one in-place arithmetic edit inside a function BODY —
///     `RawRxQueue(rx_queue_index & 0x3f)` — and that is cheaper than all six
///     escapes before it: no binding, no proc macro, no `--extern`, no
///     `[patch]`, no manifest edit, no deletion, and nothing spent from the
///     tally, since `rx_queue_index` is a different token to the counted
///     `rx_queue`. Both bodies took a mask, compiled, and left every bound here
///     green with the mask in the emitted object. The one value-level check
///     that should have seen it was an enumerated grid whose LARGEST TESTED
///     VALUE ON EACH AXIS WAS THE MASK'S BOUNDARY — `65535 & 0xffff == 65535`,
///     and every `q < 64` satisfies `q & 0x3f == q` — so the check was exactly
///     coextensive with the defect. Hence the three body pins here, and hence
///     `shim_coordinate_ladder` replacing the grid with a property. The pins
///     are the primary bound: widening an axis relocates a boundary, it does
///     not remove one.
///
/// # What is still unbound — and it cannot be driven to zero here
///
/// These are source assertions about a call site whose coordinate originates in
/// an aya `XdpContext`, which a `core`-only module cannot see. So a residual is
/// structural, not an oversight. The list is SHORTER than it was, because the
/// binding bounds subsume what used to be enumerated symbol by symbol — a
/// forged `RawRxQueue` (`transmute`, `mem::zeroed`, `MaybeUninit::assume_init`,
/// a pointer read: an open-ended class no symbol list could keep up with) can
/// only be USED by binding the name the pinned lookup passes, and every form of
/// binding raises that name's count. What remains:
///
///  - **A PROC-MACRO EXPANSION binds without writing the name here.** The
///    tally walks source; a proc macro's tokens are in another crate and its
///    `Span::call_site()` spans shadow a local at the invocation. Round 5 built
///    one and it left every bound green with `& 0x3` in the emitted object.
///    What ships against it is a bound on the ROUTE — the shim's Cargo manifest
///    is pinned token-for-token and both cargo configs refuse `--extern`,
///    `[patch]` and `[replace]` — so acquiring a proc macro IN TREE reds. Three
///    things that does not reach, stated because a route bound is only worth its
///    coverage: the two dependencies already pinned (`aya-ebpf-macros` is itself
///    a proc-macro crate, since `#[xdp]` comes from it, and no test here reads
///    upstream source); a cargo config outside the repository; and `RUSTFLAGS`
///    in the environment. The last two are properties of the machine running
///    the build rather than of reviewable source. So the honest statement is
///    that a proc-macro expansion is bounded by in-tree acquisition cost, not by
///    the tally, and an existing macro's behaviour is out of scope entirely.
///    This is the one residual that is not conservation.
///  - **CONSERVATION — the tally counts, and classifies only in part.** Every
///    binding form written here has to write the name, so none of them is FREE;
///    but an author who also DELETES an existing mention pays for one and leaves
///    the tally where it was. The shipped version of this paragraph then claimed
///    more than was true for BOTH names, so the inventory is now stated site by
///    site.
///
///    The tally is PER FILE, which stops a mention freed in one file from paying
///    for a shadow in another. For `rx_queue` the mention budget in `lib.rs` is
///    fully spent: its three mentions are all inside pinned statements — the
///    construction, the `for_trace()` readback and the lookup — and `lib.rs` is
///    the only file a shadow of THAT NAME can sit in, because that is where the
///    pinned definition and the pinned use are. In `binding_index.rs` the
///    parameter is pinned by the signature and the two body uses are
///    load-bearing for the build and the executed stride test, so the one free
///    mention of that name in the whole crate is a single doc line there — and
///    per-file pinning means it cannot be spent on `lib.rs`. (Before round 5
///    this was NOT true and the paragraph claimed it anyway: `for_trace()`'s
///    caller was unpinned, and renaming `binding_slot`'s parameter freed three
///    more. Five of the seven were free, not one.)
///
///    **The shipped version of the paragraph above said "for `rx_queue` that
///    closes it", and that was FALSE.** Spending the budget for the two COUNTED
///    names closes nothing on its own, because a statement pin bounds how the
///    construction is SPELLED and the tally bounds how often two names are
///    WRITTEN — neither bounds what a THIRD name in that statement is BOUND TO.
///    The demonstrated form, measured on this tree and reproduced by hand
///    before this paragraph was written, attacks `ctx`. Five statement-scope
///    lines above the pinned construction, shadow `ctx` with a doctored
///    `xdp_md`, then restore it before `bpf_xdp_adjust_meta` needs the real
///    one:
///
///    ```ignore
///    let real_ctx = ctx;
///    let q_masked = unsafe { (*ctx.ctx).rx_queue_index } & 0x3;
///    let mut shadow_md: xdp_md = unsafe { core::mem::zeroed() };
///    shadow_md.rx_queue_index = q_masked;
///    let ctx = &XdpContext { ctx: &mut shadow_md };
///    // …the PINNED construction statement, byte-identical, reads the
///    //   doctored struct…
///    let ctx = real_ctx;
///    ```
///
///    Measured: builds for `bpfel-unknown-none`; the live kernel verifier
///    PASSes; the emitted object gains `r &= 0x3` AND LOSES the `> 0xf` stride
///    guard entirely (1 → 0 occurrences of `0xf goto`, which LLVM only removes
///    once it can prove the value is under 16); every `shim_*` test stays
///    GREEN. That is #5173 back in the shipped program with the whole merge
///    path green. The counted names are untouched: `rx_queue` still appears
///    three times in `lib.rs`, `ingress_ifindex` twenty-two, and the
///    construction statement still matches its pin token-for-token.
///
///    Two bounds below now close the DEMONSTRATED forms of this — `ctx` joins
///    the per-file tally, and `let ctx` is refused outright. They do not close
///    the CLASS, and cannot: the class is semantic (what a name resolves to)
///    and the instrument is syntactic (which names appear, and how often).
///    Read that as a raised bar, not a proof.
///
///    For `ingress_ifindex` it does NOT close, and the previous claim that
///    buying a shadow there "costs a visibly deleted telemetry call" was false:
///    an ALIAS refunds mentions with nothing deleted at all. Two pins narrow
///    that — every `record_trace` call's argument prefix, so an argument cannot
///    be rerouted through an alias, and `record_trace`'s own signature, because
///    renaming its interface parameter was itself worth two free mentions.
///
///    What is left, stated as inventory rather than as a defence — and stated
///    COMPLETELY this time, because the shipped version of this paragraph named
///    three of the six in the round that rewrote it specifically to be
///    complete. `lib.rs` names `ingress_ifindex` 22 times. Sixteen are pinned:
///    two by `INGRESS_STATEMENT` (the read writes the name twice), one by
///    `LOOKUP_STATEMENT`, twelve by `TRACE_ARGUMENT_PREFIX` and one by
///    `TRACE_SIGNATURE`. The other SIX are free:
///
///      - `:127` and `:246` — the two `#[repr(C)]` struct field DECLARATIONS.
///        The wire contract with userspace-dp is by offset, so this test says
///        nothing about those names.
///      - `:437` — the ingress-interface gate, `USERSPACE_INGRESS_IFACES.get`.
///      - `:696` — the `UserspaceDpMeta` initializer.
///      - `:1124` — the `UserspaceTraceValue` initializer.
///      - `:1140` — the trace-key mix. Dropping the coordinate from it compiles
///        and degrades trace-key distribution rather than the index path.
///
///    Buying a shadow of the interface coordinate therefore still costs only
///    edits that compile and red nothing, and this test does not prevent it.
///    Driving it to zero would mean pinning most of a trace function that has
///    nothing to do with the index path; the bound above is the bound that
///    ships. (Line numbers drift; the count does not — it is pinned by
///    `MENTIONS_PER_FILE`, so a seventh free mention is a RED whatever it is.)
///  - **The ifindex half is a bare `u32`.** `binding_slot`'s queue argument is a
///    newtype; its ifindex argument is not, and it cannot be one without a
///    second wrapper whose constructor would take a bare `u32` for the same
///    aya-shaped reason — moving the residual, not closing it. Its definition,
///    its use, `binding_slot`'s signature, every trace call's argument prefix
///    and its per-file tally are pinned below; none of that is the type system,
///    and the paragraph above says where that leaves it.
///  - **Anything the tokenizer sees as identical text.** Comments and string
///    literals are tokenized like code. That direction is fail-CLOSED (a
///    spurious RED, never a silent pass), which is the correct polarity, but it
///    does mean a prose mention can trip the count bounds below.
#[test]
fn shim_index_path_has_one_construction_and_one_lookup() {
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let crate_dir = repo_root.join("userspace-xdp");
    let root = crate_dir.join("src");
    let mut sources: Vec<(String, String)> = Vec::new();
    fn walk(root: &std::path::Path, dir: &std::path::Path, out: &mut Vec<(String, String)>) {
        for e in std::fs::read_dir(dir).expect("read shim src dir") {
            let p = e.expect("dir entry").path();
            if p.is_dir() {
                walk(root, &p, out);
            } else if p.extension().and_then(|x| x.to_str()) == Some("rs") {
                let body = std::fs::read_to_string(&p).expect("read shim source");
                // RELATIVE to the walked root. The per-file mention tally at the
                // bottom pins these names, and an absolute path — which depends
                // on where the checkout lives — is not pinnable.
                let rel = p.strip_prefix(root).unwrap_or(&p).display().to_string();
                out.push((rel, body));
            }
        }
    }
    walk(&root, &root, &mut sources);
    // `read_dir` order is unspecified; the per-file tally is compared as an
    // ordered list, so sort before anything reads this.
    sources.sort();
    assert!(
        !sources.is_empty(),
        "found no shim sources under {}",
        root.display()
    );

    let tokens: Vec<(String, Vec<String>)> = sources
        .iter()
        .map(|(name, body)| (name.clone(), shim_token_vec(body)))
        .collect();

    // Files in which `needle` occurs, one entry per occurrence.
    let seq = |needle: &[&str]| -> Vec<String> {
        tokens
            .iter()
            .flat_map(|(name, toks)| {
                std::iter::repeat(name.clone()).take(shim_token_seq_count(toks, needle))
            })
            .collect()
    };

    // ---- The walk IS the crate only while the crate IS the walk. ----------
    //
    // A `#[path]` module or an `include!` pulls source in from outside
    // `userspace-xdp/src/`, and every bound below would silently stop covering
    // it — a fail-open in the one dimension walking the directory exists to
    // close. Matched on TOKENS so `#[ path` does not slip past, same as
    // everything else here.
    //
    // The first version of this refusal matched only the literal spellings
    // `[ path` and `include !`, and round 3 walked straight through it twice:
    //
    //   - `#[cfg_attr(all(), path = "…/evil.rs")] mod evil;` never emits the
    //     token pair `[ path`, and rustc really does compile the off-tree file
    //     (proven positively: a syntax error in it fails the build pointing at
    //     the off-tree line). A second, reduced binding-map read was placed on
    //     the packet path there with every bound below green.
    //   - `use core::include as inc;` then `inc!("…")` never emits `include !`.
    //
    // So match the two capabilities, not their spellings. Any attribute form
    // that redirects a module — bare, `cfg_attr`-wrapped, or nested to any
    // depth — has to write the token pair `path =`. Any route to the macro,
    // aliased or not, has to NAME `include` to import it. Both are refused
    // outright; prose that trips them is a spurious RED, which is the polarity
    // this whole test is built on.
    //
    // `extern crate` is refused with them, for the CRATE half of the same
    // fail-open. A crate placed on the search path by `-L dependency=…` — which
    // the repo-root config may legally spell, since `rustflags` is not banned
    // there (see below) — is not nameable in edition 2024 without either
    // `--extern` (refused in both cargo configs) or an `extern crate` item
    // HERE. Refusing the pair closes the second half, so the route is bounded
    // at both ends rather than at one, which is what the shipped comment on the
    // cargo-config refusal claimed and did not have.
    let offpath: Vec<String> = seq(&["[", "path"])
        .into_iter()
        .chain(seq(&["path", "="]))
        .chain(seq(&["include"]))
        .chain(seq(&["extern", "crate"]))
        .collect();
    assert!(
        offpath.is_empty(),
        "#5173: {offpath:?} names a module-path attribute, the `include` macro, or an \
         `extern crate` item, so the shim crate is no longer confined to {}. The bounds in this \
         test walk that directory; source pulled in from elsewhere — or a crate pulled in from a \
         `-L` search path — would be invisible to every one of them, the exact fail-open this \
         refusal exists to close. Extend the walk before adding any of them. (Prose tripping \
         this is a false RED. The convention is DESCRIBE THE ATTRIBUTE, DO NOT SPELL IT -- say \
         \"pulled in by source path\" rather than writing the bracket-path token; see the \
         module comment in userspace-xdp/src/lib.rs, which says \"described, not spelled\", and \
         the one at the top of ipv6_ext_walk.rs. This message previously named only the \
         prohibition, and a doc comment explaining WHY the shared module exists tripped it.)",
        root.display()
    );

    // ---- …and a DEPENDENCY is a third way in that the walk cannot see. ----
    //
    // `#[path]` and `include!` pull SOURCE in from outside the walk, and are
    // refused above. A proc-macro dependency does something the token bounds
    // cannot see at all: its expansion is tokens that appear in no file here,
    // and a `Span::call_site()` token resolves — and SHADOWS — at the
    // invocation. Round 5 built it. A crate outside `userspace-xdp/src`
    // emitting, from a parsed string,
    //
    //     let rx_queue = RawRxQueue::from_ctx_field(rx_queue.for_trace() % 4);
    //
    // invoked by the single line `xdp_evil::tune!();` — thirteen tokens naming
    // neither coordinate and neither constructor — left EVERY count below
    // exactly where it was, all three tests green, and the emitted object
    // carrying `r2 &= 0x3` immediately after the `xdp_md.rx_queue_index` load
    // that the pristine object performs unmasked. Compiled and disassembled,
    // not argued.
    //
    // `macro_rules!` is not this hole: a body identifier is def-site hygienic,
    // and an `$n:ident` metavariable is written by the INVOCATION, which is in
    // the walk. Only a proc macro binds a name that is written nowhere here.
    //
    // Counting mentions cannot see it by construction, so bound the ROUTE
    // instead: the expansion needs a proc-macro crate, a proc-macro crate needs
    // a dependency entry, and the manifest is pinned token-for-token here. That
    // makes acquiring one a deliberate act that reds — the same idiom as
    // `BINDINGS_MENTIONS`. It is a cheap pin to hold: this file has changed
    // twice in the repo's history, once to add it and once in a repo-wide
    // rename.
    //
    // What this does NOT bound, stated because the rest of this test is only
    // worth what its claims are worth: the two dependencies already pinned.
    // `aya-ebpf-macros` IS a proc-macro crate (it supplies `#[xdp]`), and
    // nothing here reads upstream code. That residual is carried on the doc
    // comment; it is not covered by any bound below.
    let manifest_path = crate_dir.join("Cargo.toml");
    let manifest = std::fs::read_to_string(&manifest_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", manifest_path.display()));
    #[rustfmt::skip]
    const SHIM_MANIFEST: &[&str] = &[
        "[", "package", "]",
        "name", "=", "\"", "xpf", "-", "userspace", "-", "xdp", "\"",
        "version", "=", "\"", "0", ".", "1", ".", "0", "\"",
        "edition", "=", "\"", "2024", "\"",
        "[", "dependencies", "]",
        "aya", "-", "ebpf", "=", "\"", "0", ".", "1", ".", "1", "\"",
        "aya", "-", "ebpf", "-", "macros", "=", "\"", "0", ".", "1", ".", "2", "\"",
        "[", "lib", "]",
        "crate", "-", "type", "=", "[", "\"", "cdylib", "\"", "]",
    ];
    let manifest_owned = shim_token_vec(&manifest);
    let manifest_tokens: Vec<&str> = manifest_owned.iter().map(String::as_str).collect();
    assert_eq!(
        manifest_tokens,
        SHIM_MANIFEST,
        "#5173: {} must be exactly:\n  {}\nA new dependency is the one route by which a binding \
         of either coordinate can exist without its name appearing anywhere the mention tally \
         below walks: a proc macro's expansion is call-site hygienic, so it shadows a local here \
         while writing nothing here. That was demonstrated compiling, with all three tests green \
         and `& 0x3` in the emitted object. Matched on TOKENS, so whitespace and line breaks are \
         not a RED, but a `[patch]`, a `[replace]`, a path dependency, a reordered key or a \
         version bump all are. \
         If you are changing this deliberately, update this constant and say why — and if what \
         you added can expand to arbitrary statements, the mention tally below no longer bounds \
         rebindings and this test's doc comment needs revising with it.",
        manifest_path.display(),
        SHIM_MANIFEST.join(" "),
    );

    // ---- …and the manifest is not the only file that can add a crate. -----
    //
    // Pinning `Cargo.toml` bounds the ORDINARY route. Two cargo config files
    // are read for this build — the crate's own and the repo root's, since
    // cargo loads ancestor configs — and either can inject a crate the manifest
    // never names, via a `--extern` rustflag, or swap one it does name, via
    // `[patch]` / `[replace]`. So refuse those CAPABILITIES rather than pin the
    // files: both are mostly explanatory comments and a token-exact pin of
    // either would red on a reworded sentence.
    //
    // `extern`, `patch`, `replace` and `rustc` are refused in BOTH files;
    // `rustflags` is refused only in the crate-local one, because the repo-root
    // config carries an x86_64-scoped link-arg (#3595) that is inert for
    // `bpfel-unknown-none`.
    //
    // `rustc` is on the list because of what it TOKENIZES: `rustc-wrapper`
    // becomes `rustc`, `-`, `wrapper`, so none of `extern`/`patch`/`replace`
    // appears in it and the shipped list did not see it at all. A wrapper is
    // exec'd as `<wrapper> <rustc> <args…>` and is free to append
    // `--extern <procmacro>=<path>` to every invocation — the exact acquisition
    // capability the manifest pin above exists to close, through a door the
    // refusal did not cover. Measured, not argued: a wrapper added to the
    // repo-root config IS invoked for the `bpfel-unknown-none` shim build (7
    // invocations, 3 naming the target triple) with all three tests green.
    // Neither config contains a bare `rustc` token today, so the ban costs
    // nothing; `rustc-workspace-wrapper` lands on it too.
    //
    // A NARROWER gap that the shipped comment claimed was closed and was not:
    // it said "the `extern` refusal covers that file's injection route
    // regardless of the flag it would be spelled with". It does not.
    // `rustflags` is legal in the repo-root config, and `-L dependency=…`
    // there spells the injection in the SOURCE instead, as `extern crate evil;`
    // — which this refusal never reads. Closed at the other end: the walk
    // refuses the token pair `extern crate` (above, with `[path]`/`include`),
    // because `-L` only tells rustc where to LOOK. Naming the crate still needs
    // either `--extern` (refused here) or `extern crate` (refused there).
    //
    // NOT covered, and it cannot be: a cargo config outside the repository
    // (`$CARGO_HOME/config.toml`), or `RUSTFLAGS` in the environment. Those are
    // properties of the machine running the build, not of reviewable source;
    // the build recipe that sets the environment is itself hashed by the #4977
    // freshness manifest.
    for (label, path, banned) in [
        (
            "userspace-xdp/.cargo/config.toml",
            crate_dir.join(".cargo").join("config.toml"),
            &["extern", "patch", "replace", "rustflags", "rustc"][..],
        ),
        (
            ".cargo/config.toml",
            repo_root.join(".cargo").join("config.toml"),
            &["extern", "patch", "replace", "rustc"][..],
        ),
    ] {
        let body = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let toks = shim_token_vec(&body);
        let found: Vec<&str> = banned
            .iter()
            .copied()
            .filter(|k| shim_token_seq_count(&toks, &[k]) > 0)
            .collect();
        assert!(
            found.is_empty(),
            "#5173: {label} names {found:?}, any of which can put a crate into the shim build \
             that {} never mentions — `--extern` injects one outright, `[patch]`/`[replace]` \
             substitutes one already pinned, and `rustc-wrapper` (which contains none of the \
             other three tokens) wraps every `rustc` invocation and can append `--extern` to \
             all of them. A proc macro acquired that way expands \
             call-site-hygienic tokens that shadow a coordinate while writing its name nowhere \
             the tally below walks, which is the escape the manifest pin above exists to close; \
             a second door to the same room closes with it. Refused as capabilities rather than \
             pinned token-for-token because these files are mostly comments. (Prose using one of \
             these words is a spurious RED; reword it.)",
            manifest_path.display(),
        );
    }

    // ---- The binding lookup, pinned as a whole statement. -----------------
    //
    // This single assertion is what closes the round-2 escapes, because the
    // sequence names every part an attacker has to touch: `binding_slot` is on
    // the packet path, BOTH of its arguments are untransformed, and the value
    // handed to the map read is the resolved slot with nothing applied to it.
    #[rustfmt::skip]
    const LOOKUP_STATEMENT: &[&str] = &[
        "let", "binding", "=",
        "binding_slot", "(", "ingress_ifindex", ",", "rx_queue", ")",
        ".", "and_then", "(", "|", "idx", "|",
        "USERSPACE_BINDINGS", ".", "get", "(", "idx", ")", ")", ";",
    ];
    let pinned = seq(LOOKUP_STATEMENT);
    // Show what IS there when the pin fails. "found 0 occurrences" on its own
    // would send the next author hunting for a needle this test already holds.
    let actual: Vec<String> = sources
        .iter()
        .flat_map(|(name, body)| {
            body.lines()
                .filter(|l| l.contains("USERSPACE_BINDINGS"))
                .map(move |l| format!("{name}: {}", shim_tokens(l)))
        })
        .collect();
    assert_eq!(
        pinned.len(),
        1,
        "#5173: the shim's binding lookup must be exactly this statement, once:\n  {}\nfound \
         {} occurrence(s) {pinned:?}.\nLines naming the map, tokenized:\n{actual:#?}\nEvery \
         round-2 escape is a token inside that sequence: `.get(idx % 4)` reduces the resolved \
         slot; `binding_slot(ingress_ifindex % 4, ..)` reduces the interface coordinate; \
         inlining the index drops `binding_slot` off the packet path so the executed stride \
         bound no longer governs anything. A needle COUNT sees none of those — the whole \
         statement must match.",
        LOOKUP_STATEMENT.join(" "),
        pinned.len(),
    );

    // ---- No second lookup, however it is spelled or wrapped. --------------
    let lookups = seq(&["USERSPACE_BINDINGS", ".", "get", "("]);
    assert_eq!(
        lookups.len(),
        1,
        "#5173: the shim crate must contain exactly ONE binding-map read; found {lookups:?}. A \
         second one is how the removed raw-queue fallback returns, and it indexed with an \
         unbounded rx_queue_index. This is TOKEN-matched, not substring-matched, because the \
         predecessor check was defeated by putting a newline before `.get(` — the very \
         formatting rustfmt produces for a chain this long."
    );

    // ---- …and no ALIAS that would dodge the check above. ------------------
    //
    // `use USERSPACE_BINDINGS as BINDS;` (or `let b = &USERSPACE_BINDINGS;`)
    // gives a second lookup a name the sequence above cannot match. Pinning the
    // identifier's total occurrence count is what closes that: any alias, any
    // re-export, any local rebinding has to NAME the static to create itself.
    const BINDINGS_MENTIONS: usize = 2; // the `static` item + the one lookup
    let mentions = seq(&["USERSPACE_BINDINGS"]);
    assert_eq!(
        mentions.len(),
        BINDINGS_MENTIONS,
        "#5173: `USERSPACE_BINDINGS` must be named exactly {BINDINGS_MENTIONS} times in the shim \
         crate — its `static` definition and the single lookup — but was named {} times \
         {mentions:?}. This bound is deliberately tight: an alias, a re-export or a local \
         rebinding is how a second, unbounded lookup gets a name the sequence checks above \
         cannot see, and all of them have to mention the static to exist. A comment that spells \
         the identifier trips this too; that is a spurious RED, never a silent pass. If you are \
         adding a legitimate mention, raise the constant deliberately and say why.",
        mentions.len(),
    );

    // ---- The wrap site, pinned the same way. ------------------------------
    #[rustfmt::skip]
    const CONSTRUCTION_STATEMENT: &[&str] = &[
        "let", "rx_queue", "=",
        "RawRxQueue", ":", ":", "from_ctx_field", "(",
        "unsafe", "{", "(", "*", "ctx", ".", "ctx", ")", ".", "rx_queue_index", "}",
        ")", ";",
    ];
    let ctor_site = seq(CONSTRUCTION_STATEMENT);
    assert_eq!(
        ctor_site.len(),
        1,
        "#5173: the coordinate must be wrapped by exactly this statement, once:\n  {}\nfound {} \
         occurrence(s) {ctor_site:?}. The constructor takes a bare u32, so a reduction applied \
         BEFORE the wrap is one of the two escapes the newtype cannot prevent (`transmute` is \
         the other, and nothing here catches it) — which is why the argument SPELLING is pinned \
         and not just the call's existence.\nWhat that pin does NOT do, stated because an \
         earlier revision claimed it did: pinning the spelling does not make the spelling \
         load-bearing. This sequence is byte-identical whatever `ctx` is bound to, and a \
         statement-scope rebinding of `ctx` above this line — a zeroed `xdp_md` carrying a \
         masked queue index, restored immediately after — reintroduces #5173 in the emitted \
         object with this assertion, the tallies and the kernel verifier all green. That form \
         is now caught by the `ctx` column of the per-file tally and by the `let ctx` refusal \
         below, neither of which is this check.",
        CONSTRUCTION_STATEMENT.join(" "),
        ctor_site.len(),
    );

    // A second construction re-opens the pre-wrap reduction, so bound the
    // constructor's name the same way the static's is bounded above: aliasing
    // the TYPE (`use RawRxQueue as RQ;`) still has to name the method.
    const CTOR_MENTIONS: usize = 2; // the `fn` item + the one call
    let ctors = seq(&["from_ctx_field"]);
    assert_eq!(
        ctors.len(),
        CTOR_MENTIONS,
        "#5173: `from_ctx_field` must be named exactly {CTOR_MENTIONS} times in the shim crate — \
         its definition and the single call — but was named {} times {ctors:?}. A second \
         construction site is a second chance to reduce the raw integer before it is wrapped, \
         and renaming the type on import does not hide the method name.",
        ctors.len(),
    );

    // ---- …and the constructor's BODY, which is where a mask costs NOTHING. -
    //
    // Round 6, and structurally unlike the six escapes before it: ONE in-place
    // arithmetic edit inside a shim function body.
    //
    //     RawRxQueue(rx_queue_index & 0x3f)
    //
    // It creates no binding, needs no proc macro, no `--extern`, no `[patch]`,
    // no manifest edit and no deletion, and it spends NOTHING from the per-file
    // tally — `rx_queue_index` is a different token to the counted `rx_queue`.
    // Every bound in this test stayed green and the emitted object gained
    // `r1 &= 0x3f` at insn 1006, on the `xdp_md.rx_queue_index` load the
    // pristine object performs unmasked. That is byte-for-byte the shape round
    // 5's proc-macro escape produced, reached with none of its machinery.
    //
    // It is RUNTIME-REACHABLE, not a theoretical hole. On a NIC left above 64
    // combined channels with the helper's queue count capped at ≤16 — one of
    // the two remediations `docs/afxdp-packet-processing.md` names — a packet on
    // hardware queue 70 resolves to `None` today and takes the designed
    // binding-missing path. Masked, `70 & 0x3f = 6` resolves to a LIVE binding,
    // the shim redirects to an XSK bound to a queue the packet did not arrive
    // on, `xsk_rcv_check()` returns `-EINVAL` and the driver discards while the
    // last recorded trace stage stays REDIRECT. #5173 verbatim. The Go
    // publish-side `queue_id >= 16` refusal (`maps_sync.go`) bounds what Go
    // WRITES, not what arrives from hardware.
    //
    // The pins above fix these functions' INTERFACE; this is what fixes what
    // they DO. Pinning the body rather than widening the executed axis is
    // deliberate — see `shim_coordinate_ladder`: any executed axis has a
    // largest tested value, and a mask sized to it is invisible by
    // construction, so widening relocates the boundary instead of removing it.
    // These are 1-, 1- and 4-line functions; the pins are cheap to hold.
    #[rustfmt::skip]
    const CTOR_ITEM: &[&str] = &[
        "pub", "fn", "from_ctx_field", "(", "rx_queue_index", ":", "u32", ")", "-", ">", "Self",
        "{",
        "RawRxQueue", "(", "rx_queue_index", ")",
        "}",
    ];
    let ctor_item = seq(CTOR_ITEM);
    assert_eq!(
        ctor_item.len(),
        1,
        "#5173: the constructor must be exactly this item, once:\n  {}\nfound {} occurrence(s) \
         {ctor_item:?}. Its SIGNATURE alone is not enough: the wrapper is an identity function \
         and a reduction written INSIDE it reaches every packet while creating no binding, \
         spending no mention from the tally below, and touching no other pinned sequence. \
         Demonstrated compiling with every other bound in this test green.",
        CTOR_ITEM.join(" "),
        ctor_item.len(),
    );

    // ---- The wrap site's only READER, pinned too. -------------------------
    //
    // `for_trace()` has exactly one caller, and until round 5 that caller was
    // the only statement on the packet path naming the queue coordinate that
    // was NOT pinned — which made it a FREE mention rather than a load-bearing
    // one. Re-sourcing the traced index straight from the context field,
    //
    //     let rx_queue_index = unsafe { (*ctx.ctx).rx_queue_index };
    //
    // is the same value, deletes nothing, and costs ZERO tokens of the counted
    // name (`rx_queue_index` is a different token to `rx_queue`). The freed slot
    // then paid for a tuple-pattern `transmute` shadow with the crate tally
    // still exactly at its bound: compiled, all three tests green, and the
    // emitted object carrying `r1 &= 0x3` immediately before the `<<= 0x4`
    // stride multiply. Pinning the readback removes that slot, and it is worth
    // pinning on its own account: it makes the queue index every `record_trace`
    // reports the WRAPPED coordinate read back, not an independent read that
    // could disagree with the one the lookup consumed.
    #[rustfmt::skip]
    const TRACE_READBACK_STATEMENT: &[&str] = &[
        "let", "rx_queue_index", "=", "rx_queue", ".", "for_trace", "(", ")", ";",
    ];
    let readback = seq(TRACE_READBACK_STATEMENT);
    assert_eq!(
        readback.len(),
        1,
        "#5173: the traced queue index must be read back by exactly this statement, once:\n  \
         {}\nfound {} occurrence(s) {readback:?}. Re-sourcing it from the context field is the \
         same value for zero tokens of the counted name, and the mention it frees is enough to \
         buy a shadow with the crate tally unchanged — demonstrated compiling with every other \
         bound green and `& 0x3` in the emitted object. It also keeps telemetry honest: what is \
         traced must be the coordinate that was wrapped, not a second read of the context.",
        TRACE_READBACK_STATEMENT.join(" "),
        readback.len(),
    );

    // …and the readback's own BODY, same class as the constructor's above.
    // `for_trace(self) -> u32 { self.0 & 0x3f }` is a telemetry defect that
    // pins on the CALLER cannot see, and the executed test could not either
    // until this round: it evaluated the readback at one input, 3, and
    // `3 & 0x3f == 3`.
    #[rustfmt::skip]
    const TRACE_READBACK_ITEM: &[&str] = &[
        "pub", "fn", "for_trace", "(", "self", ")", "-", ">", "u32",
        "{",
        "self", ".", "0",
        "}",
    ];
    let readback_item = seq(TRACE_READBACK_ITEM);
    assert_eq!(
        readback_item.len(),
        1,
        "#5173: the telemetry readback must be exactly this item, once:\n  {}\nfound {} \
         occurrence(s) {readback_item:?}. A reduction inside it makes every trace record name a \
         queue the redirect did not use — the mis-traced-drop hazard `binding_index.rs` \
         documents — while the pinned call site above stays byte-identical.",
        TRACE_READBACK_ITEM.join(" "),
        readback_item.len(),
    );

    // ---- `binding_slot`'s SIGNATURE, pinned. ------------------------------
    //
    // The lookup statement pins the CALLER's argument names. Nothing pinned the
    // callee's parameter names, and three of the seven mentions of the queue
    // coordinate live there. Renaming the parameter and its two body uses is
    // behaviour-preserving — the executed stride test calls positionally — so
    // it reddened nothing while dropping the tally from 7 to 4, and a deficit
    // is topped back up with prose, which the tokenizer counts identically to
    // code. That is three free slots bought with a cosmetic edit, and round 5
    // composed exactly that with the readback re-source above into a compiled
    // #5173 sitting at the bound.
    //
    // With the signature pinned the rename has nowhere to go: rename the
    // parameter and this sequence breaks; leave it and neither body use can be
    // deleted without breaking the build or the executed stride test. The pin
    // also fixes the parameter ORDER and both parameter TYPES, which nothing
    // else here did.
    #[rustfmt::skip]
    const BINDING_SLOT_SIGNATURE: &[&str] = &[
        "pub", "fn", "binding_slot", "(",
        "ingress_ifindex", ":", "u32", ",", "rx_queue", ":", "RawRxQueue", ")",
        "-", ">", "Option", "<", "u32", ">",
    ];
    let slot_sig = seq(BINDING_SLOT_SIGNATURE);
    assert_eq!(
        slot_sig.len(),
        1,
        "#5173: the slot resolver must be declared by exactly this signature, once:\n  {}\nfound \
         {} occurrence(s) {slot_sig:?}. A parameter rename here is behaviour-preserving and the \
         executed stride test calls positionally, so nothing else sees it — but it moves three \
         mentions out of the tally below, and the tally is what bounds rebindings of the name. \
         Renaming a parameter is not worth breaking a build over; buying three free slots with \
         it is.",
        BINDING_SLOT_SIGNATURE.join(" "),
        slot_sig.len(),
    );

    // ---- …and the BODY that signature wraps. ------------------------------
    //
    // The second instance of the round-6 class, in the other coordinate:
    //
    //     Some((ingress_ifindex & 0xffff) * BINDING_QUEUES_PER_IFACE + rx_queue.0)
    //
    // adds four tokens inside the body, writes `ingress_ifindex` in the same
    // place it was already written, and left all three tests green while the
    // object gained `r1 &= 0xffff0` at insn 1118, wedged between the `<<= 0x4`
    // stride multiply and the `|= rx_queue`. Its runtime reach is BOUNDED — the
    // Go publish side fails closed at ifindex ≥ 65536 (#4894) — so this
    // instance is a GUARD defect rather than a shipping one, and it is pinned
    // because it proves the hole is a CLASS and not one function.
    //
    // Anchored on the return type so the sequence is unambiguously this
    // function's body. The stride guard is inside the pin deliberately: an
    // executed axis proves the guard's EFFECT at the values it runs, and this
    // proves its SPELLING at all of them.
    //
    // The sharpest reason the pin and not a wider axis is the primary bound —
    // measured while closing round 6, because "the executed test would catch a
    // real one" is the argument that would retire it. This body:
    //
    //     #[cfg(target_arch = "bpf")]      const MASK: u32 = 0x3;
    //     #[cfg(not(target_arch = "bpf"))] const MASK: u32 = !0;
    //     Some(ingress_ifindex * BINDING_QUEUES_PER_IFACE + (rx_queue.0 & MASK))
    //
    // masks the coordinate in the BPF object and is the exact identity on the
    // host, where `MASK` is `!0`. The executed axis stayed green at every one
    // of its ~7700 points and so did the per-file tally — the spelling writes
    // each coordinate the same number of times. ONLY this pin reddened. A host
    // test cannot see a target-conditional body by construction, however wide
    // its axes are.
    #[rustfmt::skip]
    const BINDING_SLOT_BODY: &[&str] = &[
        "-", ">", "Option", "<", "u32", ">",
        "{",
        "if", "rx_queue", ".", "0", ">", "=", "BINDING_QUEUES_PER_IFACE", "{",
        "return", "None", ";",
        "}",
        // #9900 F-150: the tail is a checked multiply, not a wrapping one —
        // an interface id at or above 2^28 resolves to no slot.
        "ingress_ifindex", ".", "checked_mul", "(", "BINDING_QUEUES_PER_IFACE", ")",
        "?", ".", "checked_add", "(", "rx_queue", ".", "0", ")",
        "}",
    ];
    let slot_body = seq(BINDING_SLOT_BODY);
    assert_eq!(
        slot_body.len(),
        1,
        "#5173: the slot resolver's body must be exactly this, once:\n  {}\nfound {} \
         occurrence(s) {slot_body:?}. A mask applied to either coordinate INSIDE the body reaches \
         every packet, creates no binding, spends nothing from the tally below and moves no other \
         pinned sequence — it is the cheapest reintroduction of #5173 there is, and the executed \
         axis cannot be relied on to catch it because any axis has a largest tested value that a \
         mask can be sized to.",
        BINDING_SLOT_BODY.join(" "),
        slot_body.len(),
    );

    // ---- The INTERFACE half of the index, pinned the same way. ------------
    //
    // `binding_slot` takes two coordinates and only the queue one is a
    // newtype, so the ifindex is the half a type cannot defend. Round 3 used
    // exactly that: the statement pin above fixes how the argument is SPELLED,
    // not what it is WORTH, and
    //
    //     let ingress_ifindex = ingress_ifindex % 4;
    //
    // one line above the pinned lookup compiles for the real target, is #5173
    // through the interface dimension, and left all three tests green. Pinning
    // where the value comes FROM closes the other half of that: reducing it at
    // the definition instead breaks this sequence.
    #[rustfmt::skip]
    const INGRESS_STATEMENT: &[&str] = &[
        "let", "ingress_ifindex", "=",
        "unsafe", "{", "(", "*", "ctx", ".", "ctx", ")", ".", "ingress_ifindex", "}", ";",
    ];
    let ifx_site = seq(INGRESS_STATEMENT);
    assert_eq!(
        ifx_site.len(),
        1,
        "#5173: the interface coordinate must be read by exactly this statement, once:\n  \
         {}\nfound {} occurrence(s) {ifx_site:?}. It is a bare u32 all the way to `binding_slot`, \
         so unlike the queue coordinate NOTHING rejects a reduction of it by type — pinning both \
         its definition and its use is the whole defence. `let mut`, or any arithmetic applied \
         here, changes this sequence.",
        INGRESS_STATEMENT.join(" "),
        ifx_site.len(),
    );

    // ---- Telemetry must report the coordinates the lookup CONSUMES. -------
    //
    // The shipped version of the residual said that buying a shadow of the
    // interface coordinate "costs a visibly deleted telemetry call". It does
    // not. Round 5 bought one with an ALIAS and deleted nothing:
    //
    //     let ifx = ingress_ifindex;                     // +1
    //     let (ingress_ifindex, _z) = (ifx % 4, 0u32);   // +1  (tuple pattern)
    //
    // then routed TWO existing `record_trace` arguments through `ifx` instead
    // (-2). Net zero. The tally stayed exactly at its bound, `["let", name]`
    // stayed at one, all three tests stayed green, no trace call was removed and
    // the two rerouted sites record the identical integer — while the emitted
    // object gained `r1 &= 0x3` after the `xdp_md.ingress_ifindex` load. That is
    // #5173 through the interface dimension, which is precisely the round-3
    // defect, reintroduced without deleting anything.
    //
    // Pinning the argument PREFIX is what sees it, and it is a CLASSIFYING
    // bound rather than a counting one: it says where the mentions are, not just
    // how many there are. Every call must report the same three names the
    // binding lookup consumes, so an alias cannot be refunded there. It also
    // fixes a real telemetry property — a trace record that names a different
    // interface or queue than the one the redirect used is the "drop MIS-TRACED
    // as having reached redirect" hazard `binding_index.rs` documents.
    //
    // The two counts are pinned separately so a red says which happened: a new
    // trace call (raise both), or an existing one no longer passing the
    // canonical coordinates (raise neither — fix the call).
    //
    // The CALLEE's signature is pinned with them, for the same reason
    // `binding_slot`'s is: pinning only the call sites leaves the parameter name
    // free, and renaming `record_trace`'s own `ingress_ifindex` parameter is
    // behaviour-preserving, reds nothing else, and frees TWO mentions — the
    // declaration and the trace-key mix — which is exactly the price of the
    // alias shadow above. Found while checking what the residual actually was;
    // it is cheaper to pin than to document.
    const TRACE_CALL_SITES: usize = 12;
    #[rustfmt::skip]
    const TRACE_SIGNATURE: &[&str] = &[
        "fn", "record_trace", "(",
        "ctrl_flags", ":", "u32", ",",
        "ingress_ifindex", ":", "u32", ",",
        "rx_queue_index", ":", "u32", ",",
        "selected_queue", ":", "u32", ",",
        "slot", ":", "u32", ",",
        "stage", ":", "u32", ",",
        "reason", ":", "u32", ",",
        "parsed", ":", "&", "ParsedPacket", ",",
        ")",
    ];
    let trace_sig = seq(TRACE_SIGNATURE);
    assert_eq!(
        trace_sig.len(),
        1,
        "#5173: the trace recorder must be declared by exactly this signature, once:\n  {}\nfound \
         {} occurrence(s) {trace_sig:?}. Renaming the interface parameter here is invisible to \
         the call-site pin below and to every other bound, and it frees two mentions from the \
         tally — the declaration and the trace-key mix — which is the exact price of buying a \
         shadow with an alias. Reordering or retyping the parameters also lands here, which is \
         worth having on its own: the call sites are pinned positionally.",
        TRACE_SIGNATURE.join(" "),
        trace_sig.len(),
    );
    #[rustfmt::skip]
    const TRACE_ARGUMENT_PREFIX: &[&str] = &[
        "record_trace", "(",
        "ctrl", ".", "flags", ",",
        "ingress_ifindex", ",", "rx_queue_index", ",", "selected_queue", ",",
    ];
    // The `fn record_trace(` item tokenizes to the same pair as a call, so the
    // total is the call sites plus the definition.
    let trace_opens = seq(&["record_trace", "("]);
    assert_eq!(
        trace_opens.len(),
        TRACE_CALL_SITES + 1,
        "#5173: the shim crate must contain exactly {} `record_trace(` occurrences — \
         {TRACE_CALL_SITES} call sites plus the `fn` item — but found {} {trace_opens:?}. This \
         is pinned because the NEXT assertion counts only the calls that DO pass the canonical \
         coordinates, and on its own that is satisfied by adding a thirteenth call that does \
         not. Pinning the total is what makes the pair say `all of them`. If you are adding or \
         removing a trace call, move both constants together and say why.",
        TRACE_CALL_SITES + 1,
        trace_opens.len(),
    );
    let canonical_traces = seq(TRACE_ARGUMENT_PREFIX);
    assert_eq!(
        canonical_traces.len(),
        TRACE_CALL_SITES,
        "#5173: every `record_trace` call must open with exactly:\n  {}\nfound {} of \
         {TRACE_CALL_SITES} {canonical_traces:?}. A call that reports the coordinates under any \
         OTHER name is how a shadow is paid for without deleting anything: alias the interface \
         coordinate, reroute two arguments through the alias, and the mention tally below is \
         refunded while the object gains a mask on the index. It is also wrong on its own terms \
         — a trace record must describe the packet the binding lookup actually resolved.",
        TRACE_ARGUMENT_PREFIX.join(" "),
        canonical_traces.len(),
    );

    // ---- Neither coordinate may be re-bound, in ANY binding form. ---------
    //
    // The two statement pins fix the definition and the use; a SHADOW between
    // them changes neither. Two bounds close that, and they are deliberately
    // different in KIND, because the first one alone was escaped.
    //
    // `let <name>` is the PRECISE bound. It matches the exact shape of the
    // three escapes round 3 demonstrated, so when it reds its message can say
    // what was done:
    //
    //   - `ingress_ifindex` rebound to `ingress_ifindex % 4` — #5173 through
    //     the interface dimension, invisible to both statement pins;
    //   - `rx_queue` shadowed by an unsafe forgery — `core::mem::zeroed()`,
    //     `transmute`, `MaybeUninit::assume_init`, a pointer read. The newtype
    //     stops the CONSTRUCTOR, never a raw-bytes fabrication, and the class
    //     is open-ended, so bounding the class by symbol name would always be
    //     one symbol behind. Bounding the BINDING is not: the lookup statement
    //     is pinned to pass the identifier `rx_queue`, so a forged value is
    //     only reachable by binding that exact name;
    //   - `rx_queue` shadowed by arithmetic once an impl makes it legal (see
    //     the trait bound below) — a complete #5173 reintroduction with no
    //     `unsafe` anywhere.
    //
    // Matching `let <name>` rather than `<name> =` is deliberate: a type
    // annotation (`let rx_queue: RawRxQueue = …`) puts a token between the two
    // and slips a `<name> =` pair, and the unsafe-forgery shadow is spelled
    // exactly that way. Reassignment without `let` needs `mut`, which breaks
    // whichever statement pin above declares the name.
    //
    // The MENTION TALLY is the bound that is complete over binding FORMS, and
    // it ships because `let <name>` on its own was escaped FOUR ways in round 4
    // — every one of them compiling for `bpfel-unknown-none`, with all three
    // tests green. `["let", name]` matches only a BARE-IDENTIFIER `let` pattern;
    // put any token between the two and it is gone. The four:
    //
    //   - a tuple pattern —
    //         let (rx_queue, _z) = (transmute::<u32, RawRxQueue>(q % 4), 0u32);
    //     which is a COMPILED #5173, not a theoretical one: the emitted program
    //     gains `r1 &= 0x3` before the map lookup and LOSES the `> 0xf` stride
    //     guard, because LLVM can then prove the index in range;
    //   - `let Some(<name>) = … else { … };`, and every other refutable or
    //     destructuring pattern with it;
    //   - a `macro_rules!` body taking an `$n:ident`. An earlier revision of
    //     this comment asserted that such a body "must still write these tokens
    //     to define itself, and macro hygiene stops an out-of-crate one from
    //     shadowing here". That was simply WRONG on the first half: the body
    //     writes `let $n`, and an `ident` metavariable is call-site-hygienic, so
    //     an in-crate macro shadows fine;
    //   - a closure or `fn` PARAMETER — which this test used to carry as its
    //     declared residual, and no longer does.
    //
    // Enumerating binding FORMS would always be one form behind, exactly as
    // enumerating fabrication symbols would. Counting MENTIONS is not — for
    // bindings WRITTEN IN THE WALKED SOURCE. A binding of `<name>` — tuple,
    // struct, slice or `Some(..)` pattern, `let … else`, `if let`, `while let`,
    // `for`, a match arm, a `macro_rules!` expansion, a closure or `fn`
    // parameter — cannot exist without writing the name here, so every one of
    // them moves this tally. Same idiom, and the same reasoning, as
    // `BINDINGS_MENTIONS` and `CTOR_MENTIONS` above; the numbers are larger only
    // because these two are ordinary working identifiers rather than one-site
    // symbols.
    //
    // "Written in the walked source" is a REAL qualifier and round 5 found the
    // gap: a PROC MACRO binds a name without writing it here, because its
    // expansion carries `Span::call_site()` and therefore resolves — and
    // shadows — at the invocation. Counting cannot see that by construction; the
    // manifest pin above bounds the route to it instead, and the doc comment
    // carries what remains as a residual. Do not restate this tally as complete
    // over binding forms without that qualifier: an earlier revision did, and it
    // was false.
    //
    // PER FILE, not crate-wide. A crate total is FUNGIBLE across files: a doc
    // line deleted in `binding_index.rs` would pay for a shadow added to
    // `lib.rs`, which is a conservation escape the total cannot see. Pinning the
    // tally per file makes the conservation residual per-file too, and for the
    // queue coordinate that spends the budget: `lib.rs` names it three times and
    // all three are inside pinned statements — the construction, the `for_trace`
    // readback and the lookup. It does NOT spend it for the interface
    // coordinate; see CONSERVATION on the doc comment for the free slots that
    // remain there.
    //
    // A spent budget is NOT a closed hole, and the shipped version of the
    // paragraph above said it was ("has nothing left to spend"). Both counted
    // names can be fully accounted for while #5173 is reintroduced through a
    // THIRD name that neither of them tracks — `ctx`. Shadow it a few
    // statement-scope lines above the pinned construction with a zeroed
    // `xdp_md` whose `rx_queue_index` is masked, restore it before
    // `bpf_xdp_adjust_meta` needs the real one, and the pinned statement is
    // byte-identical while reading a different struct. Measured on this tree:
    // builds for `bpfel-unknown-none`, live kernel verifier PASS, the emitted
    // object gains `&= 0x3` and LOSES the `> 0xf` stride guard, and every
    // `shim_*` test green — with `rx_queue` still at 3 in `lib.rs` and
    // `ingress_ifindex` still at 22.
    //
    // So `ctx` gets a column. That closes the DEMONSTRATED forms — a `let`
    // shadow, a pattern binding, a parameter — and it does not close the class:
    // the class is what a name RESOLVES TO, and every instrument in this file
    // is about which names the source WRITES. Do not read a green tally as
    // proof that the coordinate arrives intact.
    //
    // The `ctx` column is only counted on files that already name a coordinate,
    // and that is sound rather than a gap: the construction statement is pinned
    // and it names `rx_queue`, so whatever file holds it necessarily has a row.
    // A shadow has to be in lexical scope AT that statement — same function,
    // therefore same file — and the two ways to inject a binding across a file
    // boundary are already refused above (`include!`/`#[path]` by the
    // confinement bound) or carried as the declared proc-macro residual.
    //
    // Paths are relative to the walked root, so this is pinnable and a NEW file
    // that mentions either coordinate is a red rather than an invisible
    // addition.
    #[rustfmt::skip]
    const MENTIONS_PER_FILE: &[(&str, usize, usize, usize)] = &[
        //  file                 ingress_ifindex  rx_queue         ctx
        //                       ---------------  --------         ---
        //  binding_index.rs:    1 doc + param    1 doc + param    PROSE ONLY —
        //                       + 1 body use     + 2 body uses    this module is
        //                                                         `core`-only
        //                                                         and cannot see
        //                                                         an
        //                                                         `XdpContext`:
        //                                                         2 quoting the
        //                                                         pinned read,
        //                                                         1 naming the
        //                                                         escape
        //  lib.rs:              2 struct fields, 3, ALL inside    the `#[xdp]`
        //                       the pinned read  pinned           entry param,
        //                       (x2), the iface  statements: the  the inner
        //                       gate, the pinned construction,    fn's param,
        //                       lookup, 12 trace `for_trace`      and every
        //                       args, the meta   readback and     `ctx.`/
        //                       write, the trace the lookup       `(*ctx.ctx)`
        //                       fn's param, its                   read on the
        //                       struct init and                   packet path
        //                       its key mix
        //
        //  #8249 moved this row 22 -> 25, deliberately. The metadata store was
        //  OUTLINED out of the entry program to recover 72 bytes of its stack
        //  frame (the GRE call path was at 504 of BPF's 512-byte combined
        //  limit), so the coordinate is now also written at the new call site,
        //  as that function's PARAMETER, and as its struct-literal field
        //  shorthand. Three code mentions, no prose ones — the comment there
        //  describes the coordinate rather than spelling it, exactly so this
        //  row tracks code and not wording.
        //
        //  What it is NOT: a pack/unpack of the coordinate. An earlier revision
        //  folded it and the queue index into one u64 to fit BPF's five-argument
        //  limit, which would have created precisely the by-type reduction site
        //  this test exists to make expensive. `pkt_len` is stored at the call
        //  site instead, so both coordinates still travel as bare u32s.
        ("binding_index.rs",     3,               4,               3),
        ("lib.rs",               25,              3,               17),
    ];

    // ---- …and `ctx` may not be rebound AT ALL. ---------------------------
    //
    // The column above sees a rebinding because it moves the count. This sees
    // the single most direct form regardless of the count, so that trading a
    // prose mention for a shadow — the conservation move the tally is honest
    // about not classifying — still reds on the shape. Zero today: the context
    // is a parameter on both functions that take one and is never re-`let` in
    // this crate.
    let ctx_rebinds = seq(&["let", "ctx"]);
    assert!(
        ctx_rebinds.is_empty(),
        "#5173: `ctx` must never be rebound with a `let` in the shim crate, but {} do \
         {ctx_rebinds:?}. The construction statement below is pinned token-for-token, which \
         bounds how it is SPELLED and not what `ctx` resolves to when it runs: shadowing `ctx` \
         above it with a doctored `xdp_md` and restoring it afterwards puts a masked queue index \
         into `RawRxQueue` with the pin, the tallies and the kernel verifier all green. That was \
         demonstrated end to end, so this refusal exists. It closes the `let` form only — a \
         pattern binding or a parameter is caught by the `ctx` column of the tally above, and \
         neither bound closes the CLASS, which is semantic while both of these are syntactic. \
         Prose spelling `let` immediately before the identifier trips this; that is a spurious \
         RED, never a silent pass, and the shim's own comments are worded around it.",
        ctx_rebinds.len(),
    );

    for name in ["ingress_ifindex", "rx_queue"] {
        let rebinds = seq(&["let", name]);
        assert_eq!(
            rebinds.len(),
            1,
            "#5173: `{name}` must be bound by exactly ONE `let {name}` statement in the shim \
             crate, but {} match {rebinds:?}. Both statement pins above stay green when the \
             coordinate is SHADOWED between its definition and its use, so this is the bound that \
             sees it — a one-line `%` shadow, or a shadow whose value is forged out of raw bytes \
             by any `unsafe` construction the newtype cannot prevent. Do not add a second binding \
             of this name; if the value genuinely needs deriving, give the derived value a \
             DIFFERENT name and note that the pinned lookup statement will then reject passing \
             it. (This bound sees a bare-identifier `let` and nothing else — a tuple pattern, a \
             `let … else`, a macro expansion or a parameter slips it, which is what the tally \
             below is for.)",
            rebinds.len(),
        );
    }

    // One row per file that names either coordinate, in walk order. Compared as
    // a whole list so a file appearing, disappearing or trading a mention with
    // another file is a red — which a pair of crate totals is not.
    let tally: Vec<(String, usize, usize, usize)> = tokens
        .iter()
        .filter_map(|(file, toks)| {
            let ifx = shim_token_seq_count(toks, &["ingress_ifindex"]);
            let queue = shim_token_seq_count(toks, &["rx_queue"]);
            let ctx = shim_token_seq_count(toks, &["ctx"]);
            (ifx + queue > 0).then(|| (file.clone(), ifx, queue, ctx))
        })
        .collect();
    let expected: Vec<(String, usize, usize, usize)> = MENTIONS_PER_FILE
        .iter()
        .map(|(f, ifx, queue, ctx)| ((*f).to_string(), *ifx, *queue, *ctx))
        .collect();
    assert_eq!(
        tally, expected,
        "#5173: the shim crate must name `ingress_ifindex`, `rx_queue` and `ctx` exactly this \
         many times in exactly these files — (file, ingress_ifindex, rx_queue, ctx) — but the \
         walk found {tally:#?} against {expected:#?}.\nThis is the bound that is complete over \
         binding FORMS written here, and the reason it is a tally rather than a pattern match: a \
         rebinding in ANY form — a tuple, struct, slice or `Some(..)` pattern, a `let … else`, \
         `if let`, `while let`, `for`, a match arm, a `macro_rules!` expansion, or a closure/`fn` \
         parameter — has to WRITE the name to exist, so all of them land here even though only \
         the bare-identifier `let` lands on the bounds above. Five such forms were demonstrated \
         compiling with every other check green: a `transmute` forgery bound through a tuple \
         pattern, and a `ctx` shadow carrying a doctored `xdp_md` past the byte-identical pinned \
         construction — both reintroduced #5173 in the emitted object.\nComplete over FORMS is \
         not complete over the CLASS. The `ctx` column exists because two fully-accounted \
         coordinate columns did not stop the shadow that hijacked the third name, and adding it \
         closes the forms demonstrated so far, not the possibility of another name. What this \
         file measures is which identifiers the source writes; what #5173 is about is what they \
         resolve to at run time. Those are different questions and a green tally answers only \
         the first.\nIt is PER FILE because a crate total is fungible: a freed mention in one \
         file would pay for a shadow in another. What it does NOT see is a binding written \
         outside the walk — a proc-macro expansion; the manifest pin above bounds the route to \
         that, and this test's doc comment carries it as a residual.\nA comment or doc line that \
         spells any of the three identifiers lands here too; that is a spurious RED, never a \
         silent pass. If you are adding a legitimate mention, move the row deliberately and say \
         why.",
    );

    // ---- The newtype's compile-time half, tested rather than assumed. -----
    //
    // `binding_index.rs` claims the coordinate cannot be reduced because
    // `RawRxQueue` has a private field and implements no arithmetic — "enforced
    // by the compiler rather than asserted about source text". True, but only
    // while both remain so, and nothing tested that. Round 3 added
    // `impl Rem<u32>` plus a `pub` field and NOTHING went red; with one shadow
    // line that is a full #5173 reintroduction with no `unsafe` marker for a
    // reader to catch. These two bounds are what make the compile-time claim a
    // claim about the code that is actually there.
    // The shipped needle was the ADJACENT pair `for RawRxQueue`, and its message
    // said "must implement NO traits" — wider than what it checked.
    // `impl core::ops::Rem<u32> for &RawRxQueue` tokenizes `… for & RawRxQueue`,
    // the adjacency fails, and `&rx_queue % 4` then compiles. So step over the
    // reference sugar (`&`, `mut`, a lifetime) between `for` and the type.
    //
    // "NO traits" was also literally false about the type as it stands, in a way
    // the same message went on to contradict two sentences later: the `struct`
    // carries `#[derive(Clone, Copy, PartialEq, Eq, Debug)]`, so it implements
    // five. What this refuses is a WRITTEN `impl … for` block, and the five
    // derives are exactly why that is the right line to draw — none of them
    // yields the inner `u32` or an arithmetic operator, so none of them can
    // reduce the coordinate, whereas a hand-written impl is how `Rem`,
    // `BitAnd`, `Shr`, `Deref` or `Into` would arrive.
    let mut trait_impls: Vec<String> = Vec::new();
    for (name, toks) in &tokens {
        for i in 0..toks.len() {
            if toks[i] != "for" {
                continue;
            }
            let mut j = i + 1;
            loop {
                match toks.get(j).map(String::as_str) {
                    Some("&") | Some("mut") => j += 1,
                    // A lifetime is the tick plus its name, two tokens.
                    Some("'") => j += 2,
                    _ => break,
                }
            }
            if toks.get(j).map(String::as_str) == Some("RawRxQueue") {
                trait_impls.push(name.clone());
            }
        }
    }
    assert!(
        trait_impls.is_empty(),
        "#5173: `RawRxQueue` must carry NO hand-written `impl … for` block, on the type OR on a \
         reference to it — found {trait_impls:?}. An arithmetic impl (`Rem`, `BitAnd`, `Shr`) \
         makes reducing the coordinate compile, and `Deref`/`Into` hand out the raw integer to \
         be reduced elsewhere; either way the module's compile-time half is gone while every \
         other check here stays green. This is deliberately narrower than \"implements no \
         traits\", which the type does not satisfy and never has: it derives `Clone`, `Copy`, \
         `PartialEq`, `Eq` and `Debug`. Those are allowed because none of them exposes the inner \
         `u32` or an operator — and mechanically they do not trip this needle either, since a \
         `#[derive]` names its traits BEFORE the type rather than after `for`."
    );

    // …and the type's mention count, which is the bound that is complete over
    // impl FORMS the way the needle above is not. Coherence means an impl of
    // any shape — on the type, on a reference, on a wrapper, inherent or
    // trait — has to NAME the type to exist, so all of them land here. Same
    // idiom as `BINDINGS_MENTIONS` and `CTOR_MENTIONS`; the residual is the same
    // too, and stated rather than papered over: this is a CRATE total, so an
    // author who also deletes an existing mention can pay for one. What that
    // buys on its own is an impl, not a defect — reducing the coordinate still
    // needs a shadow, and the per-file coordinate tally below is what bounds
    // those.
    const RAW_TYPE_MENTIONS: usize = 8;
    let raw_type = seq(&["RawRxQueue"]);
    assert_eq!(
        raw_type.len(),
        RAW_TYPE_MENTIONS,
        "#5173: `RawRxQueue` must be named exactly {RAW_TYPE_MENTIONS} times in the shim crate — \
         in `binding_index.rs` the module doc, the `struct` item, the inherent `impl` header, the \
         constructor body and `binding_slot`'s parameter type; in `lib.rs` the `use`, one doc line \
         and the pinned construction — but was named {} times {raw_type:?}. An `impl` block of any \
         shape has to write this name, which is why the count is the bound and the needle above is \
         only the precise message. A comment spelling the identifier trips it too; that is a \
         spurious RED, never a silent pass.",
        raw_type.len(),
    );
    let decl = seq(&["RawRxQueue", "(", "u32", ")"]);
    assert_eq!(
        decl.len(),
        1,
        "#5173: `RawRxQueue`'s field must stay PRIVATE — expected exactly one declaration with an \
         unqualified `u32` field, found {} {decl:?}. Marking it `pub` re-exposes the coordinate to \
         arithmetic outside the module, which is the same defect as an arithmetic impl by another \
         route.",
        decl.len(),
    );
}

// #4555/#6923: the session map has two writers, and the shim's over-limit
// refusal is an invariant about the MAP, not about the packet in front of it.
// An IPv6 chain longer than the shim's `MAX_EXT_HDRS` leaves the shim probing
// `(AF_INET6, <a next-header its walk traverses>, src, dst, 0, 0)`; the packet
// path can no longer mint that key (`metadata_tuple_complete`), and neither may
// an HA import, because the session map is global and the shim probes whatever
// row is present regardless of who wrote it. A peer-synced `LocalDelivery` row
// in particular publishes `PASS_TO_KERNEL`, returning the frame to the kernel
// stack unfiltered.
//
// Reverting `reject_unresolved_ipv6_ext_protocol` makes the first assertion
// fail with "must be REFUSED".
#[test]
fn synced_session_rejects_unresolved_ipv6_ext_protocol_6923() {
    let sync_req = |family: u8, protocol: u8, src: &str, dst: &str| SessionSyncRequest {
        operation: "upsert".to_string(),
        addr_family: family,
        protocol,
        src_ip: src.to_string(),
        dst_ip: dst.to_string(),
        src_port: 0,
        dst_port: 0,
        ingress_zone: "lan".to_string(),
        egress_zone: "wan".to_string(),
        // #7188: state the discriminator explicitly. This fixture sweeps
        // protocol 47 in over-reach guard (a), and #7188's install gate refuses
        // a protocol-47 record whose peer did NOT carry a discriminator — so
        // leaving the field at its "not carried" default would make that guard
        // pass for the wrong reason (refused by the new gate, never reaching
        // the #6923 one it was written to test). An explicit `None` is what a
        // modern peer sends for every protocol in this sweep.
        tunnel_discriminator: crate::session::TunnelDiscriminator::None.to_wire(),
        ..SessionSyncRequest::default()
    };
    let v6 = libc::AF_INET6 as u8;

    // Every next-header value the walk traverses is refused on IPv6.
    let traversable: Vec<u8> = (0u8..=255)
        .filter(|p| crate::afxdp::ipv6_ext_header_is_traversable(*p))
        .collect();
    assert_eq!(traversable.len(), 10, "#6923: the traversable set changed size");
    for protocol in &traversable {
        let err = build_synced_session_key(
            &sync_req(v6, *protocol, "2001:db8::11", "2001:db8::22"),
            0,
            SyncedKeyIntent::Install,
        )
            .expect_err(&format!(
                "#6923: a synced IPv6 session keyed on extension-header protocol {protocol} must \
                 be REFUSED — importing it hands the shim a hit for the exact over-limit chain it \
                 refused to parse"
            ));
        assert!(
            err.contains("unresolved IPv6 extension-header protocol"),
            "#6923: protocol {protocol}: unexpected rejection reason {err}"
        );
    }

    // OVER-REACH GUARDS, all GREEN under the revert.
    //
    // (a) A resolved IPv6 terminal still imports, INCLUDING ones that carry
    //     ports 0/0 the same way an unresolved chain does — ESP (50, never
    //     traversable: encrypted payload) and No-Next-Header (59, a terminal
    //     verdict on both sides). Refusing on "ports are 0/0" would take these
    //     with it.
    for protocol in [6u8, 17, 50, 58, 59, 47] {
        let key = build_synced_session_key(
            &sync_req(v6, protocol, "2001:db8::11", "2001:db8::22"),
            0,
            SyncedKeyIntent::Install,
        )
        .unwrap_or_else(|e| {
            panic!("#6923: a resolved IPv6 protocol {protocol} must still import: {e}")
        });
        assert_eq!(key.protocol, protocol);
    }

    // (b) IPv4 is untouched — the same numbers are ordinary IPv4 protocols.
    for protocol in &traversable {
        let key = build_synced_session_key(
            &sync_req(libc::AF_INET as u8, *protocol, "192.0.2.1", "192.0.2.2"),
            0,
            SyncedKeyIntent::Install,
        )
        .unwrap_or_else(|e| panic!("#6923: IPv4 protocol {protocol} must still import: {e}"));
        assert_eq!(key.protocol, *protocol);
    }

    // (c) The whole entry builder refuses too, not just the key helper — the
    //     `upsert` verb goes through `build_synced_session_entry`.
    assert!(
        build_synced_session_entry(
            &sync_req(v6, 60, "2001:db8::11", "2001:db8::22"),
            &test_zone_name_to_id(),
            0,
        )
        .is_err(),
        "#6923: the upsert path must refuse the same key the delete path refuses"
    );
}

// ---------------------------------------------------------------------------
// #6211 F2 — the worker-id MINT-SITE bound
// ---------------------------------------------------------------------------
//
// `replan_bindings_from_candidates` mints `worker_id = queue_id % workers`, and
// the NAT allocator records one holder BIT per worker id. An id too wide for
// that mask sets no bit on reserve and clears none on release — self-consistent,
// but it collapses that worker to the pre-fix single-holder behaviour: it frees
// a pool port another worker is still forwarding through. That is the original
// over-release reintroduced through its own fix, so the plan is refused instead.
//
// This is the ONLY bound. A cap on the raw `--workers` value would be wrong, and
// the third case below is the control that proves it.
#[test]
fn no_plan_can_mint_a_worker_id_beyond_the_nat_holder_mask_6211_f2() {
    use std::collections::BTreeSet;
    // #7497 changed which LAYER enforces this. The two cells this replaces drove
    // 128- and 129-queue candidate lists through the planner to reach the
    // runtime refusal directly. That is no longer possible: every candidate is
    // capped at BINDING_QUEUES_PER_IFACE on the way in, so the minted queue-id
    // range is 0..=15 and `worker_id = queue_id % workers` cannot reach 128 by
    // any candidate list. Their fixtures could not be repaired — the gate is
    // unreachable from the entry point — so they became this: the PROPERTY they
    // protected, asserted over the inputs that are now expressible.
    //
    // Read the coverage honestly. This asserts an invariant with THREE
    // enforcers, so no single mutation reds it:
    //   1. by construction, upstream — the stride cap (this is what makes the
    //      runtime check unreachable today);
    //   2. at the point of use — `allocator.rs:2278` returns 0 for
    //      `worker_id >= MAX_NAT_HOLDER_WORKERS`, so a wide id sets no holder
    //      bit even if one were minted;
    //   3. the planner's own #6211 refusal, which becomes load-bearing again
    //      the moment anyone raises the stride.
    // The mask WIDTH itself is pinned to the constant by a compile-time assert
    // (`allocator.rs:217`, `u128::BITS == MAX_NAT_HOLDER_WORKERS`).
    //
    // An editor removing layer 1 or 3 will NOT see this go red. That is a
    // property of the design, not an oversight, and it is written down here so
    // the next reader does not mistake a green run for single-layer coverage.
    for workers in [1usize, 2, 15, 16, 17, 127, 128, 129, 200] {
        for rx in [1usize, 2, 15, 16, 17, 128, 129, 200] {
            let mut cands = Vec::new();
            let mut ifidx = BTreeMap::new();
            for i in 0..3usize {
                let n = format!("ge-0-0-{i}");
                ifidx.insert(n.clone(), (i + 2) as i32);
                cands.push((n, rx));
            }
            let plan = replan_bindings_from_candidates(workers, &[], cands, ifidx, true)
                .expect("plan");
            for b in &plan {
                assert!(
                    b.worker_id < crate::nat::MAX_NAT_HOLDER_WORKERS,
                    "workers={workers} rx={rx} minted worker_id={} — at or beyond \
                     the {}-bit NAT holder mask, whose bit would silently not \
                     exist (#6211 F2)",
                    b.worker_id,
                    crate::nat::MAX_NAT_HOLDER_WORKERS
                );
            }
            // Non-vacuity: an empty plan satisfies the assertion above for free,
            // and after #7497 every input here is expected to PLAN. If a future
            // change starts refusing these, the loop above stops testing
            // anything and this is what says so.
            assert!(
                !plan.is_empty(),
                "workers={workers} rx={rx} produced an EMPTY plan; the worker-id \
                 assertion above is then vacuous"
            );
            let ids: BTreeSet<u32> = plan.iter().map(|b| b.worker_id).collect();
            assert_eq!(
                ids.len(),
                workers.min(rx.min(BINDING_QUEUES_PER_IFACE)),
                "workers={workers} rx={rx}: distinct worker ids must be \
                 min(workers, capped queues)"
            );
        }
    }
}

/// #7497: each interface contributes `min(rx, BINDING_QUEUES_PER_IFACE)` rows.
///
/// This is the cell that actually binds the cap: deleting the `.min(...)` makes
/// a 200-queue NIC plan 200 rows and this goes red immediately. The invariant
/// test above cannot do that job, because the #6211 refusal absorbs an
/// over-cap plan by returning nothing.
#[test]
fn per_interface_queue_count_is_capped_at_the_stride_7497() {
    let plan = replan_bindings_from_candidates(
        4,
        &[],
        vec![("ge-0-0-1".to_string(), 200)],
        BTreeMap::from([("ge-0-0-1".to_string(), 11)]),
        true,
    ).expect("plan");
    assert_eq!(
        plan.len(),
        BINDING_QUEUES_PER_IFACE,
        "a 200-queue NIC must contribute exactly BINDING_QUEUES_PER_IFACE rows"
    );
    let max_q = plan.iter().map(|b| b.queue_id).max().unwrap();
    assert_eq!(
        max_q as usize,
        BINDING_QUEUES_PER_IFACE - 1,
        "the highest minted queue id must be the last addressable one; a queue \
         id at the stride would alias the adjacent ifindex's queue-0 row (#4894)"
    );
}

/// #7497 blocker 3 regression: the operator's worker knob still caps the number
/// of worker groups, which is the number of spawned worker threads —
/// `plan_workers` keys its `BTreeMap<u32, Vec<BindingPlan>>` by `worker_id` and
/// spawns one worker per key.
///
/// Measured before this change went in: `distinct_worker_ids == min(workers,
/// queues)` across the matrix, with `workers 1` giving exactly one group at
/// every queue count. Nothing else in the suite would notice if that stopped
/// holding, and the field symptom is a CPU graph nobody attributes to a config
/// knob.
#[test]
fn worker_knob_still_caps_worker_groups_7497() {
    use std::collections::BTreeSet;
    for workers in [1usize, 2, 3, 6, 8, 64] {
        for rx in [1usize, 2, 6, 16] {
            let mut cands = Vec::new();
            let mut ifidx = BTreeMap::new();
            for i in 0..2usize {
                let n = format!("ge-0-0-{i}");
                ifidx.insert(n.clone(), (i + 2) as i32);
                cands.push((n, rx));
            }
            let plan = replan_bindings_from_candidates(workers, &[], cands, ifidx, true)
                .expect("plan");
            let ids: BTreeSet<u32> = plan.iter().map(|b| b.worker_id).collect();
            assert_eq!(
                ids.len(),
                workers.min(rx),
                "workers={workers} rx={rx}: worker groups must be \
                 min(workers, queues) — the knob must still bind"
            );
        }
    }
}

// #6211 F2 FALSE-REFUSAL control — the reason the check lives at the MINT site
// and not on the raw `--workers` value.
//
// `queue_count` is the per-interface RX-queue minimum, computed independently of
// `workers`, and the id is `queue_id % workers` with `queue_id < queue_count`.
// So a huge `--workers` on a small NIC mints only SMALL ids: 200 workers on a
// 16-queue interface yields ids 0..15, every one of them representable. A cap on
// `--workers` would refuse this safe configuration; the mint-site check must
// accept it.
#[test]
fn replan_accepts_huge_worker_count_on_a_small_queue_nic_6211_f2() {
    let workers = crate::nat::MAX_NAT_HOLDER_WORKERS as usize + 72; // 200
    let bindings = replan_bindings_from_candidates(
        workers,
        &[],
        vec![("ge-0-0-1".to_string(), 16)],
        BTreeMap::from([("ge-0-0-1".to_string(), 11)]),
        true,
    ).expect("plan");
    assert_eq!(
        bindings.len(),
        16,
        "16 RX queues plan 16 bindings however large --workers is"
    );
    assert_eq!(
        bindings.iter().map(|b| b.worker_id).max(),
        Some(15),
        "#6211 F2: --workers {workers} on a 16-queue NIC mints ids 0..15, all \
         representable — the bound is on the MINTED id, not on --workers, so \
         this safe configuration must NOT be refused"
    );
}

// ---------------------------------------------------------------------------
// #6691 round 8: an orphan VLAN child must not re-key onto a REFUSED parent.
// ---------------------------------------------------------------------------
//
// `replan_queues` has two reasons to find no parent candidate, and only one of
// them means "the parent is absent". The other means "the parent is present and
// the binding contract refused it" — and the orphan branch's remedy (promote
// the parent into the candidate list) is exactly wrong there: it hands the
// planner the netdev the contract just excluded, sourced from a sibling row
// that never had to pass the test itself.
//
// The snapshot below is the real Go wire snapshot for a strict-valid config:
//
//	set security ipsec vpn V bind-interface st10
//	set interfaces st10 vlan-tagging
//	set interfaces st10 unit 5 vlan-id 100
//	set interfaces st10 unit 5 family inet address 192.0.2.1/24
//	set security zones security-zone trust interfaces st10.5
//
// The base row `st10` carries `secure_tunnel: true` (the VPN binds it); the
// unit derives `10<<16 | 6` against the bound `10<<16 | 1`, so it is correctly
// NOT a secure tunnel — and its `parent_linux_name` is the xfrmi.
//
// The assertion is the QUEUE COUNT, not plan identity, because the queue count
// IS the harm: `replan_bindings_from_candidates` takes the global minimum and
// an xfrm interface has exactly one RX queue, so admitting it drags every
// physical interface on the box to one queue and one worker (#3091).
//
// FAIL-ON-REVERT: measured at head before the fix, this snapshot planned a
// binding for `st10` and the LAN's planned queue count fell from 4 to 1.

#[test]
fn orphan_vlan_child_cannot_readmit_its_refused_parent() {
    use crate::server::helpers::{
        clear_rx_queue_count_override, replan_queues, set_rx_queue_count_override,
        snapshot_binding_plan_key,
    };

    clear_rx_queue_count_override();
    set_rx_queue_count_override("ge-0-0-0", 4);
    // The measured xfrmi property: `ip -d link` reports `numrxqueues 1` and
    // /sys/class/net/<if>/queues holds a single `rx-0`.
    set_rx_queue_count_override("st10", 1);

    let lan = InterfaceSnapshot {
        name: "ge-0/0/0".to_string(),
        linux_name: "ge-0-0-0".to_string(),
        zone: "trust".to_string(),
        ifindex: 10,
        rx_queues: 4,
        ..Default::default()
    };
    let xfrmi = InterfaceSnapshot {
        name: "st10".to_string(),
        linux_name: "st10".to_string(),
        zone: "trust".to_string(),
        secure_tunnel: true,
        ifindex: 11,
        rx_queues: 1,
        ..Default::default()
    };
    let sibling = InterfaceSnapshot {
        name: "st10.5".to_string(),
        // The VLAN device the Go builder names for `vlan-id 100`; it exists on
        // no box (a VLAN cannot be created on an ARPHRD_NONE xfrmi), which is
        // why its own ifindex is 0 and the PARENT redirect is the only way it
        // contributes anything.
        linux_name: "st10.100".to_string(),
        parent_linux_name: "st10".to_string(),
        zone: "trust".to_string(),
        ifindex: 0,
        parent_ifindex: 11,
        vlan_id: 100,
        rx_queues: 1,
        ..Default::default()
    };

    // Premises. Without all three the assertions below cannot discriminate.
    assert!(
        !crate::server::helpers::include_userspace_binding_interface(&xfrmi),
        "premise: the xfrmi's own row must already be refused a binding"
    );
    assert!(
        crate::server::helpers::include_userspace_binding_interface(&sibling),
        "premise: the sibling must NOT be refused on its own merits — otherwise \
         no laundering is being tested"
    );
    assert!(
        lan.rx_queues > xfrmi.rx_queues,
        "premise: the LAN must have MORE queues than the tunnel, or the global \
         minimum cannot move and this test is vacuous"
    );

    let snapshot = ConfigSnapshot {
        interfaces: vec![lan.clone(), xfrmi, sibling],
        ..Default::default()
    };
    let bindings = replan_queues(Some(&snapshot), 4, &[], true).expect("plan");

    assert!(
        bindings.iter().all(|b| b.interface != "st10"),
        "the planner produced an AF_XDP binding for the xfrmi. Its own row was \
         refused; a zoned sibling unit re-keyed onto it through the orphan-VLAN \
         parent redirect. Planned: {:?}",
        bindings
            .iter()
            .map(|b| &b.interface)
            .collect::<std::collections::BTreeSet<_>>()
    );
    let lan_queues = bindings
        .iter()
        .filter(|b| b.interface == "ge-0-0-0")
        .map(|b| b.queue_id)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        lan_queues.len(),
        lan.rx_queues,
        "the LAN was planned onto {} queue(s), not its own {}. The xfrmi entered \
         the candidate list through its sibling and its single RX queue became \
         the global minimum — every interface on the box is now one queue and \
         one worker (#3091). Planned: {:?}",
        lan_queues.len(),
        lan.rx_queues,
        bindings
            .iter()
            .map(|b| (b.interface.clone(), b.queue_id))
            .collect::<Vec<_>>(),
    );

    // #2915: the plan-key HASH must drop exactly the rows the LAYOUT drops. The
    // refused sibling contributes no candidate, so a snapshot without it at all
    // must hash identically — otherwise the key would churn (or, in the unsafe
    // direction, a change to the dropped row would not bump the key while the
    // layout stayed the same).
    let without_sibling = ConfigSnapshot {
        interfaces: snapshot.interfaces[..2].to_vec(),
        ..Default::default()
    };
    assert_eq!(
        snapshot_binding_plan_key(&snapshot),
        snapshot_binding_plan_key(&without_sibling),
        "the plan key still hashes a row that produces no candidate: the hash and \
         the layout disagree about the binding plan (#2915)"
    );

    clear_rx_queue_count_override();
}

/// The NON-REFUSED orphan case must keep working. This is #3175's own scenario
/// and it is the negative control for the refusal above.
///
/// THE PARENT ROW IS PRESENT AND UNZONED, which is the only shape that can
/// discriminate the two predicates. An earlier revision of this test omitted
/// the parent row entirely, and it did not bind: with no row resolving to
/// `ge-0-0-2`, BOTH `snapshot_refuses_parent_netdev` and the wrong-but-tempting
/// `!include_userspace_binding_interface(p)` return false for want of anything
/// to examine, so the mutation survived. Measured, not reasoned — it survived
/// the grid before the fixture was corrected.
///
/// With the parent row present and unzoned, the parent is NOT a candidate (an
/// empty zone fails `include_userspace_binding_interface`) yet it is NOT
/// refused either (an unzoned physical NIC is not an unbindable NETDEV). Its
/// hardware queues really do carry the child's tagged frames, so the #3175
/// re-key must still happen.
///
/// FAIL-ON-REVERT: widen `snapshot_refuses_parent_netdev` to fire on any
/// non-candidate parent — the obvious wrong simplification — and this test goes
/// RED with an empty binding list.
#[test]
fn orphan_vlan_child_still_rekeys_onto_an_unzoned_parent() {
    use crate::server::helpers::{
        clear_rx_queue_count_override, include_userspace_binding_interface, replan_queues,
        set_rx_queue_count_override, userspace_unbindable_netdev,
    };

    clear_rx_queue_count_override();
    set_rx_queue_count_override("ge-0-0-2", 6);

    // Present, unzoned: not a candidate, but not refused either.
    let parent = InterfaceSnapshot {
        name: "ge-0/0/2".to_string(),
        linux_name: "ge-0-0-2".to_string(),
        zone: String::new(),
        ifindex: 30,
        rx_queues: 6,
        ..Default::default()
    };
    let child = InterfaceSnapshot {
        name: "reth0.80".to_string(),
        linux_name: "ge-0-0-2.80".to_string(),
        parent_linux_name: "ge-0-0-2".to_string(),
        zone: "untrust".to_string(),
        ifindex: 31,
        parent_ifindex: 30,
        vlan_id: 80,
        rx_queues: 1,
        ..Default::default()
    };

    assert!(
        !include_userspace_binding_interface(&parent),
        "premise: the parent must NOT be a candidate, or this is the ordinary \
         VLAN-dedup path and the orphan branch never runs"
    );
    assert!(
        !userspace_unbindable_netdev(&parent),
        "premise: the parent must NOT be refused — the whole point is that \
         'not a candidate' and 'refused' are different facts"
    );

    let snapshot = ConfigSnapshot {
        interfaces: vec![parent, child],
        ..Default::default()
    };
    let bindings = replan_queues(Some(&snapshot), 6, &[], true).expect("plan");
    let planned = bindings
        .iter()
        .map(|b| b.interface.clone())
        .collect::<std::collections::BTreeSet<_>>();
    assert!(
        planned.contains("ge-0-0-2"),
        "an orphan VLAN child whose parent is present-but-not-a-candidate must \
         still re-key onto the parent netdev (#3175) — refusing it here would \
         take the child's traffic off the dataplane. Planned: {planned:?}"
    );
    let queues = bindings
        .iter()
        .filter(|b| b.interface == "ge-0-0-2")
        .map(|b| b.queue_id)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        queues.len(),
        6,
        "the orphan re-key must use the PARENT's hardware queue count, not the \
         child's lone software queue"
    );

    clear_rx_queue_count_override();
}

/// #6691 round 9: `snapshot_refuses_parent_netdev` must need EVERY owner of a
/// netdev to be unbindable, not just one — the Rust half of the Go blocker in
/// `buildUserspaceRefusedNetdevs`.
///
/// THE SNAPSHOT IS WHAT THE GO BUILDER SHIPS, not a hand-invented shape. A
/// unit-level `tunnel` stanza sets `Tunnel` on the UNIT row only
/// (`iface.Tunnel != nil || unit.Tunnel != nil`, interfaces.go), and a unit-0
/// row with no vlan-id resolves to the BASE netdev (snapshotLinuxName's unit-0
/// collapse) — so `ge-0/0/5` and `ge-0/0/5.0` arrive here as two rows on ONE
/// netdev that disagree about whether it may be bound.
///
/// THE BASE ROW IS UNZONED ON PURPOSE, and that is the shape that makes this
/// observable rather than merely inconsistent. An empty zone excludes the
/// base row for the ROW reason that remains after #10308; it is not a
/// management/control-name exemption. The trust VLAN child's re-key is the
/// netdev's only route into the plan under the ANY-owner rule, so refusing it
/// would leave NO binding for a netdev whose ifindex the Go ingress map carries.
/// An ifindex in the ingress map with no READY binding is `drop_degraded_transit`
/// (BINDING_MISSING).
///
/// FAIL-ON-REVERT: change `snapshot_refuses_parent_netdev` back to
/// `.iter().any(...)` and this goes RED — planned came back without
/// `ge-0-0-5` at all.
#[test]
fn a_netdev_with_a_bindable_owner_is_not_refused() {
    use crate::server::helpers::{
        clear_rx_queue_count_override, include_userspace_binding_interface, replan_queues,
        set_rx_queue_count_override, userspace_unbindable_netdev,
    };
    clear_rx_queue_count_override();
    set_rx_queue_count_override("ge-0-0-5", 6);

    // The base NIC. Bindable as a DEVICE; excluded only because it is unzoned.
    let base = InterfaceSnapshot {
        name: "ge-0/0/5".to_string(),
        linux_name: "ge-0-0-5".to_string(),
        zone: String::new(),
        ifindex: 30,
        rx_queues: 6,
        ..Default::default()
    };
    // The unit-level tunnel row: Tunnel set, and collapsed onto the base netdev.
    let tunnel_unit = InterfaceSnapshot {
        name: "ge-0/0/5.0".to_string(),
        linux_name: "ge-0-0-5".to_string(),
        zone: String::new(),
        tunnel: true,
        ifindex: 30,
        parent_ifindex: 30,
        rx_queues: 6,
        ..Default::default()
    };
    // The trust-zoned VLAN child whose frames arrive on the base NIC's queues.
    let vlan_child = InterfaceSnapshot {
        name: "ge-0/0/5.100".to_string(),
        linux_name: "ge-0-0-5.100".to_string(),
        parent_linux_name: "ge-0-0-5".to_string(),
        zone: "trust".to_string(),
        ifindex: 31,
        parent_ifindex: 30,
        vlan_id: 100,
        rx_queues: 1,
        ..Default::default()
    };

    // Premises. Without all three this cannot discriminate ANY from EVERY.
    assert!(
        !userspace_unbindable_netdev(&base),
        "premise: the base row must be a BINDABLE device, or the two rows agree"
    );
    assert!(
        userspace_unbindable_netdev(&tunnel_unit),
        "premise: the unit row must be unbindable, or nothing is disagreeing"
    );
    assert!(
        !include_userspace_binding_interface(&base),
        "premise: the base must NOT be a candidate on its own (empty zone), or the \
         netdev enters the plan regardless and the refusal is unobservable"
    );

    let snapshot = ConfigSnapshot {
        interfaces: vec![base, tunnel_unit, vlan_child],
        ..Default::default()
    };
    let bindings = replan_queues(Some(&snapshot), 6, &[], true).expect("plan");
    let planned = bindings
        .iter()
        .map(|b| b.interface.clone())
        .collect::<std::collections::BTreeSet<_>>();
    assert!(
        planned.contains("ge-0-0-5"),
        "the trust VLAN child produced no candidate because a SIBLING row on the \
         same netdev is a tunnel. The netdev has a bindable owner, so it is not \
         refused — and dropping it leaves the Go ingress map carrying ifindex 30 \
         with no READY binding (drop_degraded_transit). Planned: {planned:?}"
    );
    let queues = bindings
        .iter()
        .filter(|b| b.interface == "ge-0-0-5")
        .map(|b| b.queue_id)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        queues.len(),
        6,
        "the re-key must use the PARENT's 6 hardware queues, not the child's lone \
         software queue"
    );

    clear_rx_queue_count_override();
}

/// #6691 round 9: `replan_queues`' FABRIC loop must ask the refused index too.
///
/// Round 8 gated the interface loop and left the fabric loop unconditional,
/// recording the gap as unreachable — a judgement made against the PRE-round-8
/// exclusion, which was keyed on the ref's NAME. The kernel-kind half refuses a
/// device for what it IS, so a slot-shaped `ge-0/0/0` created out of band is
/// both refused and a legal `fabric-options member-interfaces` value; the Go
/// control plane ships it as a fabric row whose parent netdev carries
/// `secure_tunnel` on its own interface row.
///
/// Planning a binding onto it is the same #3091 collapse the exclusion exists to
/// prevent: an xfrm interface has one RX queue and the planner takes the global
/// minimum across candidates.
///
/// FAIL-ON-REVERT: drop the `snapshot_refuses_parent_netdev` guard from the
/// fabric candidate loop and this reds — `ge-0-0-0` reappears in the plan and
/// the LAN's queue count collapses from 6 to 1.
#[test]
fn fabric_loop_cannot_readmit_a_refused_member_netdev() {
    use crate::protocol::FabricSnapshot;
    use crate::server::helpers::{
        clear_rx_queue_count_override, replan_queues, set_rx_queue_count_override,
        userspace_unbindable_netdev,
    };

    clear_rx_queue_count_override();
    set_rx_queue_count_override("ge-0-0-3", 6);
    // The measured xfrmi property: exactly one RX queue.
    set_rx_queue_count_override("ge-0-0-0", 1);

    // The fabric MEMBER's own interface row: an xfrm device by kernel kind,
    // under a slot-shaped name. This is what the Go builder ships.
    let member = InterfaceSnapshot {
        name: "ge-0/0/0".to_string(),
        linux_name: "ge-0-0-0".to_string(),
        zone: String::new(),
        secure_tunnel: true,
        ifindex: 20,
        rx_queues: 1,
        ..Default::default()
    };
    let lan = InterfaceSnapshot {
        name: "ge-0/0/3".to_string(),
        linux_name: "ge-0-0-3".to_string(),
        zone: "trust".to_string(),
        ifindex: 21,
        rx_queues: 6,
        ..Default::default()
    };

    // Premises. Without both, the fabric loop is not being tested.
    assert!(
        userspace_unbindable_netdev(&member),
        "premise: the fabric member's netdev must be REFUSED, or there is nothing \
         for the fabric loop to re-admit"
    );
    assert!(
        lan.rx_queues > member.rx_queues,
        "premise: the LAN must have MORE queues than the member, or the global \
         minimum cannot move and the collapse assertion is vacuous"
    );

    let snapshot = ConfigSnapshot {
        interfaces: vec![member, lan.clone()],
        fabrics: vec![FabricSnapshot {
            name: "fab0".to_string(),
            parent_linux_name: "ge-0-0-0".to_string(),
            parent_ifindex: 20,
            // #6691 round 10: the fabric votes on this netdev too, so its vote
            // is set to what the Go builder ships for this config — the base row
            // and the fabric parent are judged from the same config and the same
            // kernel sample (fabricParentUnbindable), so they agree here.
            //
            // Round 10 also called the disagreeing snapshot "not producible",
            // and round 11 measured two ways to produce it: a canonical alias
            // between the member's name and its stanza, and a fabric refresh
            // re-sampling the kernel between applies. Both are fixed at their
            // source in the control plane, and the rule changed as well — a
            // fabric vote is counted only where no row owns the netdev — so this
            // fixture no longer depends on the agreement for its verdict. See
            // `fabric_vote_cannot_overturn_an_owning_row` below, which drives
            // exactly the disagreement this comment used to call impossible.
            parent_unbindable: true,
            rx_queues: 1,
            ..Default::default()
        }],
        ..Default::default()
    };
    let bindings = replan_queues(Some(&snapshot), 6, &[], true).expect("plan");
    let planned = bindings
        .iter()
        .map(|b| b.interface.clone())
        .collect::<std::collections::BTreeSet<_>>();
    assert!(
        !planned.contains("ge-0-0-0"),
        "the fabric loop planned an AF_XDP binding for a REFUSED member netdev. \
         Its own interface row carries secure_tunnel; the fabric row re-admitted \
         it without asking. Planned: {planned:?}"
    );
    let lan_queues = bindings
        .iter()
        .filter(|b| b.interface == "ge-0-0-3")
        .map(|b| b.queue_id)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        lan_queues.len(),
        lan.rx_queues,
        "the LAN was planned onto {} queue(s), not its own {} — the refused \
         member entered the candidate list through the fabric loop and its single \
         RX queue became the global minimum (#3091). Planned: {:?}",
        lan_queues.len(),
        lan.rx_queues,
        bindings
            .iter()
            .map(|b| (b.interface.clone(), b.queue_id))
            .collect::<Vec<_>>(),
    );

    // #2915: the plan-key HASH must drop exactly what the LAYOUT drops.
    let without_fabric = ConfigSnapshot {
        fabrics: Vec::new(),
        ..snapshot.clone()
    };
    assert_eq!(
        snapshot_binding_plan_key(&snapshot),
        snapshot_binding_plan_key(&without_fabric),
        "the plan key still hashes a fabric row that produces no candidate: the \
         hash and the layout disagree about the binding plan (#2915)"
    );

    clear_rx_queue_count_override();
}

/// #6691 round 10: a fabric parent netdev that NO INTERFACE ROW OWNS is still
/// refusable, and the fabric's own snapshot row is what carries the verdict.
///
/// THE FIXTURE'S POINT IS WHAT IT OMITS. The round-9 guard above builds an
/// `InterfaceSnapshot` for `ge-0-0-0` carrying `secure_tunnel: true` — and
/// `snapshot_refuses_parent_netdev` tallies OWNERS, so that row is the only
/// reason the netdev was refusable at all. A fabric member needs no interface
/// stanza on the Go side, so the row is routinely absent while the fabric loops
/// still push the netdev into the candidate list. With zero owners the
/// unanimity `owners > 0 && owners == unbindable` answers "not refused", and
/// round 9 planned an AF_XDP binding on the refused device.
///
/// This snapshot therefore carries the LAN row and nothing else: the member has
/// no row, only `FabricSnapshot.parent_unbindable`, which is the wire field the
/// Go plane computes from evidence (kernel link kind) this process cannot see.
///
/// FAIL-ON-REVERT: drop the fabric arm from `snapshot_refuses_parent_netdev`
/// and this reds on both the planned set and the collapsed LAN queue count.
#[test]
fn ownerless_fabric_parent_is_refused() {
    use crate::protocol::FabricSnapshot;
    use crate::server::helpers::{
        clear_rx_queue_count_override, replan_queues, set_rx_queue_count_override,
    };

    clear_rx_queue_count_override();
    set_rx_queue_count_override("ge-0-0-3", 6);
    set_rx_queue_count_override("ge-0-0-0", 1);

    let lan = InterfaceSnapshot {
        name: "ge-0/0/3".to_string(),
        linux_name: "ge-0-0-3".to_string(),
        zone: "trust".to_string(),
        ifindex: 21,
        rx_queues: 6,
        ..Default::default()
    };
    let snapshot = ConfigSnapshot {
        // DELIBERATELY no row for ge-0-0-0 — see above.
        interfaces: vec![lan.clone()],
        fabrics: vec![FabricSnapshot {
            name: "fab0".to_string(),
            parent_linux_name: "ge-0-0-0".to_string(),
            parent_ifindex: 20,
            parent_unbindable: true,
            rx_queues: 1,
            ..Default::default()
        }],
        ..Default::default()
    };

    // PREMISE: nothing in `interfaces` owns the member netdev. If a future
    // edit adds one back, this silently becomes the round-9 test.
    assert!(
        !snapshot
            .interfaces
            .iter()
            .any(|i| i.linux_name == "ge-0-0-0"),
        "premise: the ownerless case needs NO interface row for the fabric parent"
    );

    let bindings = replan_queues(Some(&snapshot), 6, &[], true).expect("plan");
    let planned = bindings
        .iter()
        .map(|b| b.interface.clone())
        .collect::<std::collections::BTreeSet<_>>();
    assert!(
        !planned.contains("ge-0-0-0"),
        "the fabric loop planned an AF_XDP binding for a netdev the control plane \
         marked unbindable. No interface row speaks for it, so `parent_unbindable` \
         is the only evidence this plane has. Planned: {planned:?}"
    );
    let lan_queues = bindings
        .iter()
        .filter(|b| b.interface == "ge-0-0-3")
        .map(|b| b.queue_id)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        lan_queues.len(),
        lan.rx_queues,
        "the LAN was planned onto {} queue(s), not its own {} — the ownerless \
         refused parent entered the candidate list and its single RX queue became \
         the global minimum (#3091). Planned: {:?}",
        lan_queues.len(),
        lan.rx_queues,
        bindings
            .iter()
            .map(|b| (b.interface.clone(), b.queue_id))
            .collect::<Vec<_>>(),
    );

    // #2915: the plan-key HASH must drop exactly what the LAYOUT drops.
    let without_fabric = ConfigSnapshot {
        fabrics: Vec::new(),
        ..snapshot.clone()
    };
    assert_eq!(
        snapshot_binding_plan_key(&snapshot),
        snapshot_binding_plan_key(&without_fabric),
        "the plan key hashes an ownerless fabric row that produces no candidate: \
         the hash and the layout disagree about the binding plan (#2915)"
    );

    // NEGATIVE CONTROL, and it is the REFERENCE CLUSTER's own shape: an
    // ownerless fabric parent that is NOT unbindable must still be planned.
    // loss:xpf-userspace-fw0/fw1 authors `fab0 fabric-options member-interfaces
    // ge-0/0/0` with no interface row for it, so "ownerless => refused" would
    // take the fabric parent out of every cluster this project runs.
    let bindable = ConfigSnapshot {
        interfaces: vec![lan],
        fabrics: vec![FabricSnapshot {
            name: "fab0".to_string(),
            parent_linux_name: "ge-0-0-0".to_string(),
            parent_ifindex: 20,
            parent_unbindable: false,
            rx_queues: 1,
            ..Default::default()
        }],
        ..Default::default()
    };
    let planned = replan_queues(Some(&bindable), 6, &[], true).expect("plan")
        .iter()
        .map(|b| b.interface.clone())
        .collect::<std::collections::BTreeSet<_>>();
    assert!(
        planned.contains("ge-0-0-0"),
        "an ownerless fabric parent with no refusal was dropped: being ownerless \
         is not what refuses a netdev, the control plane's verdict is. \
         Planned: {planned:?}"
    );

    clear_rx_queue_count_override();
}

/// #6691 round 11: a fabric vote must not overturn the verdict of a row that
/// OWNS the netdev.
///
/// Round 10 counted the fabric parent as an owner beside any interface row, so
/// one device could have TWO owners whose verdicts came from DIFFERENT evidence
/// — this plane reads a wire field, the Go plane reads a config lookup plus a
/// kernel dump — and the unanimity rule reads any disagreement as an ADMISSION.
/// So every way to make those two differ was a fail-open, and round 10's own
/// fixture comment (above) called the disagreeing snapshot unproducible. Two
/// producers were then measured on the control plane: a canonical alias between
/// the member's name and its interface stanza (`gr-0/0/3` vs `gr-0-0-3`, one
/// device, both spellings legal), and a fabric refresh re-sampling the kernel
/// between applies.
///
/// Both are fixed at their source, and this rule is what makes a THIRD one
/// harmless: a device has ONE verdict — the row's where a row exists, the
/// fabric's where none does.
///
/// The fixture is the disagreement itself: an unbindable member row with a
/// fabric row that says bindable. Under the round-10 tally that is
/// `owners=2, unbindable=1` → not refused → the netdev is planned and its single
/// RX queue becomes the global minimum (#3091).
///
/// FAIL-ON-REVERT: count the fabric vote unconditionally (drop the `owners == 0`
/// guard in `snapshot_refuses_parent_netdev`) and this reds on both the planned
/// set and the collapsed LAN queue count.
#[test]
fn fabric_vote_cannot_overturn_an_owning_row() {
    use crate::protocol::FabricSnapshot;
    use crate::server::helpers::{
        clear_rx_queue_count_override, replan_queues, set_rx_queue_count_override,
        userspace_unbindable_netdev,
    };

    clear_rx_queue_count_override();
    set_rx_queue_count_override("ge-0-0-3", 6);
    set_rx_queue_count_override("ge-0-0-0", 1);

    let member = InterfaceSnapshot {
        name: "ge-0/0/0".to_string(),
        linux_name: "ge-0-0-0".to_string(),
        zone: String::new(),
        secure_tunnel: true,
        ifindex: 20,
        rx_queues: 1,
        ..Default::default()
    };
    let lan = InterfaceSnapshot {
        name: "ge-0/0/3".to_string(),
        linux_name: "ge-0-0-3".to_string(),
        zone: "trust".to_string(),
        ifindex: 21,
        rx_queues: 6,
        ..Default::default()
    };
    assert!(
        userspace_unbindable_netdev(&member),
        "premise: the owning row must REFUSE the netdev, or there is no verdict \
         for the fabric vote to overturn"
    );

    let snapshot = ConfigSnapshot {
        interfaces: vec![member, lan.clone()],
        fabrics: vec![FabricSnapshot {
            name: "fab0".to_string(),
            parent_linux_name: "ge-0-0-0".to_string(),
            parent_ifindex: 20,
            // THE DISAGREEMENT. The row says unbindable; the fabric says
            // bindable.
            parent_unbindable: false,
            rx_queues: 1,
            ..Default::default()
        }],
        ..Default::default()
    };

    let bindings = replan_queues(Some(&snapshot), 6, &[], true).expect("plan");
    let planned = bindings
        .iter()
        .map(|b| b.interface.clone())
        .collect::<std::collections::BTreeSet<_>>();
    assert!(
        !planned.contains("ge-0-0-0"),
        "a fabric row voting `bindable` overturned the verdict of the only row \
         that describes the device, and the refused netdev was planned. A \
         disagreement between two owners of ONE device is not evidence of \
         bindability — it is evidence that one of them was computed from the \
         wrong input. Planned: {planned:?}"
    );
    let lan_queues = bindings
        .iter()
        .filter(|b| b.interface == "ge-0-0-3")
        .map(|b| b.queue_id)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        lan_queues.len(),
        lan.rx_queues,
        "the LAN was planned onto {} queue(s), not its own {} — the refused \
         netdev entered the candidate list on the fabric's vote and its single \
         RX queue became the global minimum (#3091). Planned: {:?}",
        lan_queues.len(),
        lan.rx_queues,
        bindings
            .iter()
            .map(|b| (b.interface.clone(), b.queue_id))
            .collect::<Vec<_>>(),
    );

    clear_rx_queue_count_override();
}

/// #6691 round 9b: the version check refuses in BOTH operand orders.
///
/// `apply_snapshot_rejects_unsupported_protocol_version` drives
/// `CONFIG_SNAPSHOT_PROTOCOL_VERSION - 1`, which is a v5 control plane meeting
/// this v6 helper. The other half of the mixed-version matrix — a v6 control
/// plane meeting a v5 helper — cannot be run here, because that needs a v5
/// helper BINARY. What it depends on is that `snapshot.version != CONST`
/// refuses whichever side is newer, so this drives `+ 1` to measure that
/// directly rather than inferring it from the symmetry of one line.
///
/// Without this, "an older helper refuses a newer snapshot" is READ. With it,
/// both operand orders are measured against the real `handle_stream` dispatch.
#[test]
fn apply_snapshot_rejects_a_newer_protocol_version_too() {
    use crate::{ConfigSnapshot, ControlRequest, ControlResponse, CONFIG_SNAPSHOT_PROTOCOL_VERSION};

    let (mut client, server) = std::os::unix::net::UnixStream::pair().expect("control socket pair");
    let state = Arc::new(Mutex::new(ServerState {
        status: ProcessStatus::default(),
        snapshot: None,
        afxdp: afxdp::Coordinator::new(),
        state_writer: Arc::new(StateWriter::new()),
        quarantined_after_panic: false,
    }));
    let running = Arc::new(AtomicBool::new(true));
    let state_file = format!(
        "{}/xpf-newer-version-gate-{}.json",
        std::env::temp_dir().display(),
        std::process::id()
    );
    let handle = {
        let state = state.clone();
        let running = running.clone();
        {
            let sd = state.lock().expect("state").afxdp.session_domain().clone();
            std::thread::spawn(move || handle_stream(server, &state_file, state, running, sd, SocketMode::Main))
        }
    };

    let request = ControlRequest {
        request_type: "apply_snapshot".to_string(),
        snapshot: Some(ConfigSnapshot {
            version: CONFIG_SNAPSHOT_PROTOCOL_VERSION + 1,
            generated_at: Utc::now(),
            ..ConfigSnapshot::default()
        }),
        ..ControlRequest::default()
    };
    serde_json::to_writer(&mut client, &request).expect("write request");
    std::io::Write::write_all(&mut client, b"\n").expect("newline");

    let response: ControlResponse =
        serde_json::from_reader(std::io::BufReader::new(client)).expect("read response");
    assert!(
        !response.ok,
        "a snapshot at a NEWER protocol version was accepted. The check must refuse \
         whichever side is ahead — an older helper that accepts a newer snapshot \
         enforces fields it cannot see, which is the failure the version exists to \
         prevent"
    );
    assert!(
        response
            .error
            .contains("unsupported snapshot protocol version"),
        "unexpected error: {}",
        response.error
    );
    handle
        .join()
        .expect("handler thread")
        .expect("handler result");
}

/// #6691 round 16: `snapshot_refuses_parent_netdev` counts an owning row BY
/// NAME with no ifindex filter, so a row whose own link lookup missed
/// (`ifindex: 0`) still speaks for the netdev — and the Go control plane's
/// ingress-adjudication map must reach the same verdict from the same evidence.
///
/// WHY A ROW CAN CARRY IFINDEX 0 WHILE THE FABRIC ROW CARRIES A LIVE ONE: the
/// two are sampled at different instants. `buildInterfaceSnapshots`
/// (interfaces.go) and `buildFabricSnapshotsFrom` (fabric.go) each take their
/// own `buildLinkSnapshot`, and `SyncFabricState` (manager_fabric_sync.go) refreshes the
/// fabric rows ALONE and persists them back into `m.lastSnapshot` beside
/// interface rows that were never re-sampled.
///
/// THE FIXTURE'S POINT IS `parent_unbindable: false`. It isolates the ifindex-0
/// interface row as the ONLY refusal evidence in the snapshot: the fabric arm of
/// `snapshot_refuses_parent_netdev` runs only at `owners == 0`, so if this side
/// ever gained an `ifindex > 0` filter on the owner walk the row would stop
/// counting, the fabric arm would vote bindable, and this plane would plan a
/// binding for a netdev Go's NAME-keyed readers (the RSS allowlist and, since
/// round 16, the ingress map) refuse. That is the split in the other direction —
/// a binding with no ingress entry takes `cpumap_or_pass` and leaves the
/// adjudicated path.
///
/// FAIL-ON-REVERT: add `|| p.ifindex <= 0` to the `continue` in
/// `snapshot_refuses_parent_netdev`'s owner walk and this reds — `gr-0-0-3`
/// appears in the planned set.
#[test]
fn zero_ifindex_owner_row_still_refuses_the_fabric_parent() {
    use crate::protocol::FabricSnapshot;
    use crate::server::helpers::{
        clear_rx_queue_count_override, replan_queues, set_rx_queue_count_override,
    };

    clear_rx_queue_count_override();
    set_rx_queue_count_override("gr-0-0-3", 1);
    set_rx_queue_count_override("ge-0-0-3", 6);

    let snapshot = ConfigSnapshot {
        interfaces: vec![
            InterfaceSnapshot {
                name: "ge-0/0/3".to_string(),
                linux_name: "ge-0-0-3".to_string(),
                zone: "trust".to_string(),
                ifindex: 21,
                rx_queues: 6,
                ..Default::default()
            },
            // The stale half: owns `gr-0-0-3` (its bind target is its own
            // netdev) and is unbindable (the `tunnel` exclusion class), but its
            // own link lookup missed.
            InterfaceSnapshot {
                name: "gr-0/0/3".to_string(),
                linux_name: "gr-0-0-3".to_string(),
                zone: "vpn".to_string(),
                ifindex: 0,
                tunnel: true,
                ..Default::default()
            },
        ],
        // The fresh half, deliberately voting BINDABLE — see the doc above.
        fabrics: vec![FabricSnapshot {
            name: "fab0".to_string(),
            parent_linux_name: "gr-0-0-3".to_string(),
            parent_ifindex: 20,
            parent_unbindable: false,
            rx_queues: 1,
            ..Default::default()
        }],
        ..Default::default()
    };

    let bindings = replan_queues(Some(&snapshot), 6, &[], true).expect("plan");
    let planned = bindings
        .iter()
        .map(|b| b.interface.clone())
        .collect::<std::collections::BTreeSet<_>>();
    assert!(
        !planned.contains("gr-0-0-3"),
        "an owning row at ifindex 0 must still refuse the netdev: the Go plane's \
         name-keyed readers refuse it, so a binding here is a plan/ingress split. \
         Planned: {planned:?}"
    );
    // ANTI-VACUITY: the LAN row must still be planned, so the assertion above is
    // not passing because the planner produced nothing at all.
    assert!(
        planned.contains("ge-0-0-3"),
        "premise broken: the unrefused LAN netdev must still be planned. Planned: {planned:?}"
    );

    clear_rx_queue_count_override();
}


/// #6749: a binding-plan EXPANSION must not disable the whole dataplane.
///
/// `replan_bindings_from_candidates` rebuilds the binding vector by SLOT, and a
/// slot that did not exist before comes from `BindingStatus::default()` —
/// `armed: false`. `refresh_status` then computes
/// `enabled = forwarding_armed && ... && bindings.iter().all(|b| b.registered
/// && b.armed)` (helpers/status.rs), so ONE unarmed slot makes `enabled` false
/// for every binding on the box, and Go's `resolveCtrlEnableLocked` keys
/// ctrl-enable on that flag: ctrl goes to 0 and ALL transit drops.
///
/// It does not self-heal, and that is what makes it indefinite rather than a
/// one-tick blip. The only other writer of per-binding `armed` is
/// `set_bindings_forwarding_armed`, reached only from the `set_forwarding_state`
/// handler — and Go suppresses that RPC as a no-op whenever the arm state has
/// not CHANGED (`syncDesiredForwardingStateLocked`:
/// `if m.lastStatus.ForwardingArmed == desired { return nil }`). The helper's
/// global `forwarding_armed` is still true across an expansion, so nothing ever
/// re-arms the new slot.
///
/// The second cell is the load-bearing one. Hardcoding `armed = true` for new
/// slots passes the first cell and silently ARMS a box that is deliberately
/// disarmed — an HA secondary, a shutdown, a protocol-gate disarm — which is a
/// forwarding fail-OPEN, strictly worse than the outage being fixed. The new
/// slot must INHERIT the global state, exactly as `set_bindings_forwarding_armed`
/// would have set it.
#[test]
fn expansion_arms_new_slots_from_the_global_state_6749() {
    fn expand(forwarding_armed: bool) -> Vec<BindingStatus> {
        // One pre-existing, fully armed slot — the box is forwarding.
        let existing = vec![BindingStatus {
            slot: 0,
            interface: "ge-0-0-1".into(),
            ifindex: 11,
            registered: true,
            armed: forwarding_armed,
            last_change: Some(chrono::Utc::now()),
            ..Default::default()
        }];
        // The plan grows to two interfaces: slot 1 is NEW.
        let mut ifindex_by_name = std::collections::BTreeMap::new();
        ifindex_by_name.insert("ge-0-0-1".to_string(), 11);
        ifindex_by_name.insert("ge-0-0-2".to_string(), 12);
        replan_bindings_from_candidates(
            1,
            &existing,
            vec![("ge-0-0-1".to_string(), 1), ("ge-0-0-2".to_string(), 1)],
            ifindex_by_name,
            forwarding_armed,
        ).expect("plan")
    }

    let armed = expand(true);
    assert_eq!(armed.len(), 2, "premise: the plan must actually have expanded");
    assert!(
        armed.iter().all(|b| b.registered),
        "premise: both slots must be registered, else `enabled` is false for a different reason",
    );
    assert!(
        armed.iter().all(|b| b.armed),
        "a NEW slot came back unarmed on an ARMED box. refresh_status requires \
         all(registered && armed), so this makes status.enabled false for EVERY \
         binding, Go drops ctrl to 0, and all transit stops — indefinitely, because \
         Go suppresses set_forwarding_state when the arm state has not changed \
         (#6749). Slots: {:?}",
        armed.iter().map(|b| (b.slot, b.armed)).collect::<Vec<_>>(),
    );

    let disarmed = expand(false);
    assert_eq!(disarmed.len(), 2);
    assert!(
        disarmed.iter().all(|b| !b.armed),
        "a new slot came back ARMED on a DISARMED box. The new slot must INHERIT \
         the global arm state, not assume `true` — hardcoding it would arm an HA \
         secondary or a box mid-shutdown, a forwarding fail-OPEN strictly worse \
         than the outage #6749 is about. Slots: {:?}",
        disarmed.iter().map(|b| (b.slot, b.armed)).collect::<Vec<_>>(),
    );
}

/// #6749: an EXISTING slot's arm state is preserved across a replan, and is not
/// overwritten by the global flag.
///
/// The inheritance above applies only to slots that did not exist before
/// (`!had_existing`). A slot that is mid-bringup — registered but not yet armed
/// — must stay unarmed through an unrelated replan rather than being declared
/// armed because the box as a whole is. Without this cell, "inherit on new
/// slots" and "stamp the global flag over every slot" are indistinguishable,
/// and the second would claim a queue is carrying before its XSK is bound.
#[test]
fn expansion_does_not_overwrite_an_existing_slots_arm_state_6749() {
    let existing = vec![BindingStatus {
        slot: 0,
        interface: "ge-0-0-1".into(),
        ifindex: 11,
        registered: true,
        armed: false, // mid-bringup on an otherwise armed box
        last_change: Some(chrono::Utc::now()),
        ..Default::default()
    }];
    let mut ifindex_by_name = std::collections::BTreeMap::new();
    ifindex_by_name.insert("ge-0-0-1".to_string(), 11);
    ifindex_by_name.insert("ge-0-0-2".to_string(), 12);
    let out = replan_bindings_from_candidates(
        1,
        &existing,
        vec![("ge-0-0-1".to_string(), 1), ("ge-0-0-2".to_string(), 1)],
        ifindex_by_name,
        true,
    ).expect("plan");
    assert!(
        !out[0].armed,
        "the pre-existing mid-bringup slot was declared armed by the replan; \
         only a NEW slot inherits the global state (#6749)",
    );
    assert!(out[1].armed, "the new slot must inherit the armed box state");
}

/// #8279: the userspace-ingress test must precede the L3 PARSE, because the
/// parse's failure arm is a DROP.
///
/// THE DEFECT. `try_xdp_userspace` used to run `parse_l2`, then the L3 parse,
/// then `drop_degraded_transit(ctrl, USERSPACE_FALLBACK_REASON_PARSE_FAIL)` on
/// a parse failure, and only THEN test the ingress map. So a frame on an
/// ifindex this shim does not adjudicate could still be DROPPED by it.
///
/// WHY THAT IS REACHABLE, and it is not the interface set anyone would guess.
/// The shim is attached to a strictly LARGER set than the ingress set: every
/// zoned netdev goes into `st.xdpIfindexes` (`pkg/dataplane/compiler_iface.go`),
/// tunnels included — the comment there says so ("Tunnels need XDP for ingress")
/// — and `syncInterfaceAttachments` reconciles the difference away only at the
/// two POST-acceptance points, deliberately (#5485). A tunnel netdev on a
/// userspace-dataplane box is an anchor TUN: ARPHRD_NONE, raw L3, **no Ethernet
/// header**. Measured on a live kernel rather than assumed — a generic-XDP
/// program attaches to such a TUN, runs on packets userspace WRITES into it,
/// and sees the bare IP header (byte 0 = 0x45, bytes 12..14 = the IP SOURCE
/// octets), against an ARPHRD_ETHER control on the same harness that saw
/// 0x0800 at the same offset.
///
/// So `parse_l2` reads the source-address octets as an ethertype. A source in
/// `8.0.0.0/16` reads as `ETH_P_IP`, the shifted `parse_ipv4` reads the third
/// source octet as version/IHL, and 241 of its 256 values fail — dropping the
/// packet. The packet's fate was selectable by its own source address, on an
/// interface this shim has no authority over.
///
/// WHY A SOURCE GUARD. The property is an ORDER inside a BPF program that no
/// test in this workspace can execute — the same reason #5173's index path and
/// #7480's wiring are pinned rather than run. What is pinned here is exactly
/// the ordering, not a spelling.
///
/// WHY TOKEN SEQUENCES AND NOT BARE NAMES. `shim_token_vec` tokenizes comments
/// and string literals like code (see the #5173 module notes), and the fix's own
/// comment names `parse_ipv4` and `drop_degraded_transit` in prose ABOVE the
/// gate. A bare-identifier ordering check would read those prose tokens and go
/// RED on correct code. Each needle below is a CALL-SHAPED sequence that prose
/// does not reproduce, and each is asserted to occur exactly ONCE so a needle
/// that has stopped matching fails loudly instead of making the ordering
/// vacuously true.
#[test]
fn shim_ingress_test_precedes_the_l3_parse_8279() {
    let lib = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("userspace-xdp/src/lib.rs");
    let src = std::fs::read_to_string(&lib).expect("read shim lib.rs");

    // Scope to `try_xdp_userspace`'s body. `degraded_ctrl_disabled_action` has
    // a BYTE-IDENTICAL parse arm, and it deliberately never consults the
    // ingress map: with `ctrl.enabled == 0` the shim must fail closed on EVERY
    // attached interface, adjudicated or not (#5485 relies on exactly that).
    // Applying this ordering rule there would invert that posture, so the slice
    // is the point, not an implementation convenience.
    let start = src
        .find("\nfn try_xdp_userspace(")
        .expect("#8279: `fn try_xdp_userspace(` not found -- the slice below would be empty");
    let rest = &src[start + 1..];
    let end = rest[1..]
        .find("\nfn ")
        .map(|i| i + 1)
        .expect("#8279: no following top-level `fn` -- the slice would run to EOF");
    let body = &rest[..end];
    let toks = shim_token_vec(body);
    assert!(
        toks.len() > 200,
        "#8279: the `try_xdp_userspace` slice is only {} tokens, which is far too \
         short to be the real function -- the slice markers have drifted and every \
         assertion below would be testing the wrong text",
        toks.len()
    );

    fn only_index(toks: &[String], needle: &[&str], label: &str) -> usize {
        let hits: Vec<usize> = toks
            .windows(needle.len())
            .enumerate()
            .filter(|(_, w)| w.iter().zip(needle).all(|(a, b)| a.as_str() == *b))
            .map(|(i, _)| i)
            .collect();
        assert_eq!(
            hits.len(),
            1,
            "#8279: expected exactly ONE {label} site in the shim, found {}. \
             The ordering assertion below is meaningless unless each site is \
             unique -- a needle that stopped matching would make it vacuously \
             true, and a SECOND site would make \"first occurrence\" the wrong \
             question. Needle: {needle:?}",
            hits.len()
        );
        hits[0]
    }

    let gate = only_index(
        &toks,
        &["USERSPACE_INGRESS_IFACES", ".", "get", "(", "&", "ingress_ifindex", ")"],
        "userspace-ingress map lookup",
    );
    let parse_v4 = only_index(
        &toks,
        &["parse_ipv4", "(", "data", ",", "data_end", ","],
        "parse_ipv4 call",
    );
    let parse_v6 = only_index(
        &toks,
        &["parse_ipv6", "(", "data", ",", "data_end", ","],
        "parse_ipv6 call",
    );
    let parse_fail = only_index(
        &toks,
        &[
            "drop_degraded_transit", "(", "ctrl", ",",
            "USERSPACE_FALLBACK_REASON_PARSE_FAIL", ")",
        ],
        "parse-failure drop",
    );

    for (label, idx) in [
        ("the IPv4 parse", parse_v4),
        ("the IPv6 parse", parse_v6),
        ("the parse-failure DROP", parse_fail),
    ] {
        assert!(
            gate < idx,
            "#8279: {label} is reached BEFORE the userspace-ingress test \
             (gate at token {gate}, {label} at token {idx}). The shim is \
             attached to more interfaces than it adjudicates, and a raw-L3 \
             netdev in that gap has its IP SOURCE octets read as an ethertype \
             -- so with this ordering a packet's fate is selectable by its own \
             source address on an interface the shim has no authority over. \
             The ingress test must come first."
        );
    }
}

// ---------------------------------------------------------------------------
// #7497: the binding-slot capacity cap.
// ---------------------------------------------------------------------------

/// The helper's `MAX_BINDING_SLOTS` and the shim's `BINDING_SLOT_MAP_MAX_ENTRIES`
/// must be the same number, and this ASSERTS THE AGREEMENT rather than pinning
/// either side to a literal.
///
/// The distinction matters. A test that pinned `MAX_BINDING_SLOTS == 4096` would
/// encode which of the two spellings is trusted, and would stay green if the
/// shim's map were resized underneath it — which is precisely the drift that
/// makes the plan-time cap admit slots the XSK map cannot address. Because
/// `binding_index.rs` is `#[path]`-included above, the value on the shim side of
/// this comparison is read out of the source the BPF object is built from.
#[test]
fn shim_and_helper_agree_on_binding_slot_capacity_7497() {
    assert_eq!(
        shim_binding_index::BINDING_SLOT_MAP_MAX_ENTRIES,
        crate::server::helpers::MAX_BINDING_SLOTS,
        "userspace-xdp BINDING_SLOT_MAP_MAX_ENTRIES and userspace-dp \
         MAX_BINDING_SLOTS disagree; the planner would cap against a capacity \
         the heartbeat/XSK maps do not have (#7497)"
    );
    // Same rule for the stride. #7497 gave the planner its own
    // BINDING_QUEUES_PER_IFACE so it can cap each interface's queue count, which
    // made a SECOND literal of a fact the shim already owns. Asserted as an
    // agreement, not pinned to 16 on either side, so it reds whichever one moves.
    //
    // Drift here is not cosmetic: if the shim strides by 32 while the planner
    // caps at 16 the plan silently loses half of every interface's queues, and
    // if the planner caps HIGHER than the shim's stride it mints queue ids that
    // resolve into the adjacent ifindex's row — the aliasing class #4894 and
    // #5173 exist to prevent.
    assert_eq!(
        shim_binding_index::BINDING_QUEUES_PER_IFACE as usize,
        crate::server::helpers::BINDING_QUEUES_PER_IFACE,
        "userspace-xdp BINDING_QUEUES_PER_IFACE and userspace-dp \
         BINDING_QUEUES_PER_IFACE disagree; the planner would cap each \
         interface's queue count against a stride the shim does not use (#7497)"
    );
}

/// The capacity of the slot-keyed maps is NOT the capacity of the binding array,
/// and conflating them is the #7497 defect. Pinning the ratio keeps a future
/// author from "unifying" the two constants: the write-side guards check the
/// composed index against the larger value, which does not protect the smaller
/// maps.
#[test]
fn binding_slot_capacity_is_far_below_the_binding_array_7497() {
    use shim_binding_index::{BINDING_QUEUES_PER_IFACE, BINDING_SLOT_MAP_MAX_ENTRIES};
    // The binding ARRAY is MAX_INTERFACES * stride = 65536 * 16 = 1,048,576.
    let binding_array_max: u64 = 65_536u64 * BINDING_QUEUES_PER_IFACE as u64;
    assert!(
        (BINDING_SLOT_MAP_MAX_ENTRIES as u64) < binding_array_max,
        "slot-map capacity {} must be strictly below the binding array {}",
        BINDING_SLOT_MAP_MAX_ENTRIES,
        binding_array_max
    );
    assert_eq!(
        binding_array_max / BINDING_SLOT_MAP_MAX_ENTRIES as u64,
        256,
        "a bound checked against the binding array admits 256x what the \
         slot-keyed maps can address (#7497)"
    );
}

/// Build `n` candidate interfaces each advertising `rx` RX queues.
fn slot_cap_candidates_7497(n: usize, rx: usize) -> (Vec<(String, usize)>, BTreeMap<String, i32>) {
    let mut candidates = Vec::with_capacity(n);
    let mut ifindex_by_name = BTreeMap::new();
    for i in 0..n {
        let name = format!("ge-0-0-{i}");
        ifindex_by_name.insert(name.clone(), (i + 2) as i32);
        candidates.push((name, rx));
    }
    (candidates, ifindex_by_name)
}

/// A plan whose binding count exceeds the slot-keyed map capacity is REFUSED
/// whole, not truncated.
///
/// The fixture straddles the boundary rather than sitting far past it: at 16
/// queues, 256 interfaces is exactly `MAX_BINDING_SLOTS` and must be admitted,
/// while 257 is one binding over and must be refused. A fixture that only
/// tested a wildly oversized plan would stay green against an off-by-one in the
/// comparison, and a `>=` there would refuse a configuration that binds cleanly.
#[test]
fn plan_exceeding_binding_slot_capacity_is_refused_7497() {
    use crate::server::helpers::{MAX_BINDING_SLOTS, replan_bindings_from_candidates};

    let stride = 16usize;
    let exact = MAX_BINDING_SLOTS as usize / stride; // 256 interfaces x 16 queues

    // Control: exactly at capacity must still plan. If this goes red the cap is
    // refusing safe boxes, which is the failure direction a one-sided test
    // cannot see.
    let (candidates, ifindex_by_name) = slot_cap_candidates_7497(exact, stride);
    let at_cap =
        replan_bindings_from_candidates(4, &[], candidates, ifindex_by_name, true).expect("plan");
    assert_eq!(
        at_cap.len(),
        MAX_BINDING_SLOTS as usize,
        "a plan of exactly MAX_BINDING_SLOTS bindings must be admitted"
    );
    let max_slot = at_cap.iter().map(|b| b.slot).max().unwrap();
    assert_eq!(
        max_slot,
        MAX_BINDING_SLOTS - 1,
        "the densest admitted plan must still mint its highest slot inside the maps"
    );

    // One binding over the capacity: refused whole.
    let (candidates, ifindex_by_name) = slot_cap_candidates_7497(exact + 1, stride);
    let over = replan_bindings_from_candidates(4, &[], candidates, ifindex_by_name, true);
    assert!(
        over.is_err(),
        "a plan of {} bindings exceeds MAX_BINDING_SLOTS ({}) and must be refused \
         whole as Err, not truncated and not an empty Ok",
        (exact + 1) * stride,
        MAX_BINDING_SLOTS,
    );
}

/// One interface's candidates with a caller-chosen ifindex, for the
/// #9900 F-150 ceiling cells below.
fn ifindex_ceiling_candidates_9900(
    ifindex: i32,
) -> (Vec<(String, usize)>, BTreeMap<String, i32>) {
    let mut ifindex_by_name = BTreeMap::new();
    ifindex_by_name.insert("ge-0-0-0".to_string(), ifindex);
    (vec![("ge-0-0-0".to_string(), 2)], ifindex_by_name)
}

/// A plan naming an ifindex at or above the addressable ceiling is REFUSED
/// whole, not minted into binding-missing queues.
///
/// The fixture straddles the boundary: 65535 plans (registered, armed), 65536
/// refuses. A fixture that only tested a wildly oversized ifindex would stay
/// green against an off-by-one in the comparison.
#[test]
fn plan_with_wild_ifindex_is_refused_9900() {
    use crate::server::helpers::{MAX_BINDING_IFINDEX, replan_bindings_from_candidates};

    // Boundary, admitted side: the largest plannable ifindex still plans.
    let (candidates, ifindex_by_name) = ifindex_ceiling_candidates_9900(MAX_BINDING_IFINDEX - 1);
    let admitted =
        replan_bindings_from_candidates(4, &[], candidates, ifindex_by_name, true).expect("plan");
    assert_eq!(admitted.len(), 2, "one interface x two queues must plan");
    assert!(
        admitted.iter().all(|b| b.registered && b.armed),
        "an admitted boundary plan must be fully usable, not degraded"
    );

    // Boundary, refused side: the ceiling itself refuses whole.
    let (candidates, ifindex_by_name) = ifindex_ceiling_candidates_9900(MAX_BINDING_IFINDEX);
    let refused = replan_bindings_from_candidates(4, &[], candidates, ifindex_by_name, true);
    assert!(
        refused.is_err(),
        "ifindex {MAX_BINDING_IFINDEX} is past the addressable rows and must be refused whole as Err"
    );

    // One wild interface poisons the WHOLE plan, not just its own rows — a
    // partial plan is an availability failure indistinguishable from healthy.
    let candidates = vec![("ge-0-0-0".to_string(), 2), ("ge-0-0-1".to_string(), 2)];
    let mut ifindex_by_name = BTreeMap::new();
    ifindex_by_name.insert("ge-0-0-0".to_string(), 7);
    ifindex_by_name.insert("ge-0-0-1".to_string(), 100_000);
    let refused = replan_bindings_from_candidates(4, &[], candidates, ifindex_by_name, true);
    assert!(
        refused.is_err(),
        "one wild ifindex must refuse the whole plan as Err, including the ordinary interface"
    );
}

/// Control: ordinary ifindexes (and the missing/non-positive shapes the
/// per-binding degrade owns) plan exactly as before — the refusal only fires
/// on a resolved wild value.
#[test]
fn plan_with_ordinary_ifindexes_unchanged_9900() {
    use crate::server::helpers::replan_bindings_from_candidates;

    let candidates = vec![
        ("ge-0-0-0".to_string(), 2),
        ("ge-0-0-1".to_string(), 4),
        ("ge-0-0-9".to_string(), 1),
    ];
    let mut ifindex_by_name = BTreeMap::new();
    ifindex_by_name.insert("ge-0-0-0".to_string(), 7);
    ifindex_by_name.insert("ge-0-0-1".to_string(), 0);
    // ge-0-0-9 has no entry at all: unknown ifindex.
    let plan =
        replan_bindings_from_candidates(4, &[], candidates, ifindex_by_name, true).expect("plan");
    assert_eq!(plan.len(), 7, "2 + 4 + 1 rows must all mint");
    let usable: Vec<_> = plan.iter().filter(|b| b.registered).collect();
    assert_eq!(usable.len(), 2, "only the resolved interface registers");
    assert!(
        usable.iter().all(|b| b.interface == "ge-0-0-0"),
        "the unresolved rows degrade per-binding instead of refusing"
    );
}

/// Every slot an admitted plan mints is addressable in the slot-keyed maps.
///
/// This is the property the cap exists to guarantee, asserted over the plan's
/// OUTPUT rather than over the arithmetic that produced it — so it still holds
/// if the minting loop changes shape.
#[test]
fn every_minted_slot_is_addressable_7497() {
    use crate::server::helpers::{MAX_BINDING_SLOTS, replan_bindings_from_candidates};

    for (ifaces, rx) in [(1usize, 1usize), (3, 6), (17, 16), (256, 16)] {
        let (candidates, ifindex_by_name) = slot_cap_candidates_7497(ifaces, rx);
        let plan = replan_bindings_from_candidates(6, &[], candidates, ifindex_by_name, true)
            .expect("plan");
        for b in &plan {
            assert!(
                b.slot < MAX_BINDING_SLOTS,
                "{ifaces} ifaces x {rx} queues minted slot {} outside the \
                 heartbeat/XSK maps ({} entries)",
                b.slot,
                MAX_BINDING_SLOTS
            );
        }
    }
}

/// #7497 blocker 6: prior state follows the binding's IDENTITY
/// (`interface`, `queue_id`), not its slot.
///
/// Slot is a position in the minted sequence. Change one interface's queue
/// count and the sequence reshuffles: `[A(rx=4), B(rx=2)]` mints slot 5 as
/// `(A,q3)`, and after B grows to 4 queues slot 5 is `(B,q2)`. Carrying
/// `registered`/`armed`/`ready`/counters across that reshuffle attaches one
/// interface's state to a different interface's queue, and a later
/// `binding slot 5 unregister` retargets whichever row now holds the slot.
///
/// The fixture is the issue's own example, and it is chosen so the two keyings
/// DISAGREE: with slot-keyed carry-forward at least one row inherits another
/// row's tag, so the assertion below fails. A fixture where the queue counts
/// did not change would be satisfied by either keying.
#[test]
fn carry_forward_follows_binding_identity_not_slot_7497() {
    // A unique, decodable tag per (interface, queue) so a misattribution names
    // both the row that received it and the row it belonged to.
    fn tag(iface: &str, queue: u32) -> u64 {
        let iface_code = iface.bytes().last().unwrap_or(b'?') as u64;
        iface_code * 1000 + queue as u64 + 1
    }

    let ifidx = BTreeMap::from([
        ("ge-0-0-1".to_string(), 11),
        ("ge-0-0-2".to_string(), 12),
    ]);

    // Generation 1: A has 4 queues, B has 2.
    let mut gen1 = replan_bindings_from_candidates(
        4,
        &[],
        vec![("ge-0-0-1".to_string(), 4), ("ge-0-0-2".to_string(), 2)],
        ifidx.clone(),
        true,
    ).expect("plan");
    assert_eq!(gen1.len(), 6, "4 + 2 rows");
    for b in gen1.iter_mut() {
        b.rx_packets = tag(&b.interface, b.queue_id);
    }
    // The reshuffle the issue names: slot 5 belongs to (A,q3) here.
    let slot5_before = gen1
        .iter()
        .find(|b| b.slot == 5)
        .map(|b| (b.interface.clone(), b.queue_id))
        .expect("slot 5 exists in generation 1");
    assert_eq!(
        slot5_before,
        ("ge-0-0-1".to_string(), 3),
        "fixture precondition: slot 5 is (A,q3) before B grows"
    );

    // Generation 2: B grows to 4 queues (`ethtool -L ge-0-0-2 combined 4`).
    let gen2 = replan_bindings_from_candidates(
        4,
        &gen1,
        vec![("ge-0-0-1".to_string(), 4), ("ge-0-0-2".to_string(), 4)],
        ifidx,
        true,
    ).expect("plan");
    assert_eq!(gen2.len(), 8, "4 + 4 rows after B grows");

    // The reshuffle actually happened — otherwise the two keyings agree and this
    // test proves nothing.
    let slot5_after = gen2
        .iter()
        .find(|b| b.slot == 5)
        .map(|b| (b.interface.clone(), b.queue_id))
        .expect("slot 5 exists in generation 2");
    assert_ne!(
        slot5_before, slot5_after,
        "fixture is inert: slot 5 addresses the same (interface, queue) in both \
         generations, so slot-keyed and identity-keyed carry-forward agree"
    );

    for b in &gen2 {
        let had_predecessor = (b.interface == "ge-0-0-1" && b.queue_id < 4)
            || (b.interface == "ge-0-0-2" && b.queue_id < 2);
        let want = if had_predecessor {
            tag(&b.interface, b.queue_id)
        } else {
            0
        };
        assert_eq!(
            b.rx_packets, want,
            "slot {} ({} q{}) carried tag {} but its identity's tag is {}; state \
             was carried by SLOT and landed on the wrong (interface, queue)",
            b.slot, b.interface, b.queue_id, b.rx_packets, want
        );
    }
}

// #8640 (found while censusing #8612): the OTHER HALF of a cross-language
// agreement. The Go half is
// `pkg/config/nat_port_floor_sync_sentinel_8640_test.go`.
//
// `build_synced_session_entry` reads a zero translated port off the sync wire
// as "this session has no port translation":
//
//	let nat_src_port = if req.nat_src_port != 0 { Some(req.nat_src_port) } else { None };
//
// That inference is sound ONLY because a source pool can never allocate port 0
// — enforced in Go, by `parseSourcePoolPortRange`'s `n < 1` rejection, in
// another package and another language, with nothing connecting the two except
// these two tests.
//
// This pins THIS side of the agreement: the mapping is exactly
// `0 -> None, n -> Some(n)`. If someone changes it (say, to carry an explicit
// has-translation flag on the wire, which is what #4088 did for the allocator's
// equivalent heuristic), this reds and the Go-side comment about what depends on
// the floor stops being true — which is the point. Neither half can move
// silently.
#[test]
fn a_zero_translated_port_means_no_translation_on_the_sync_wire_8640() {
    let base = || SessionSyncRequest {
        operation: "upsert".to_string(),
        addr_family: libc::AF_INET as u8,
        protocol: 6,
        src_ip: "10.0.61.102".to_string(),
        dst_ip: "172.16.80.200".to_string(),
        src_port: 40000,
        dst_port: 5201,
        ingress_zone: "lan".to_string(),
        egress_zone: "wan".to_string(),
        owner_rg_id: 1,
        egress_ifindex: 5,
        nat_src_ip: "172.16.80.8".to_string(),
        ..SessionSyncRequest::default()
    };

    // ZERO on the wire => None. This is the branch the Go floor protects.
    let mut req = base();
    req.nat_src_port = 0;
    let entry = build_synced_session_entry(&req, &test_zone_name_to_id(), 0)
        .expect("synced session entry (zero port)");
    assert_eq!(
        entry.decision.nat.rewrite_src_port, None,
        "a zero nat_src_port must read as NO port translation. If this changed, \
         pkg/config's port-floor agreement test is now describing a dependency \
         that no longer exists — update both halves together"
    );

    // POSITIVE CONTROL: a real port must survive as Some(n). Without it, a
    // build that dropped rewrite_src_port entirely would satisfy the assertion
    // above, and this whole agreement would be pinning a field nothing sets.
    let mut req = base();
    req.nat_src_port = 51000;
    let entry = build_synced_session_entry(&req, &test_zone_name_to_id(), 0)
        .expect("synced session entry (real port)");
    assert_eq!(
        entry.decision.nat.rewrite_src_port,
        Some(51000),
        "a NON-zero nat_src_port must survive as the translated port; without \
         this row the zero-case assertion is satisfied by a path that never \
         sets rewrite_src_port at all"
    );
}

#[test]
fn build_synced_session_entry_carries_install_table_identity_9752() {
    let req = SessionSyncRequest {
        operation: "upsert".to_string(),
        addr_family: libc::AF_INET as u8,
        protocol: 6,
        src_ip: "10.0.61.102".to_string(),
        dst_ip: "172.16.80.200".to_string(),
        src_port: 40000,
        dst_port: 5201,
        ingress_zone: "lan".to_string(),
        egress_zone: "wan".to_string(),
        owner_rg_id: 1,
        egress_ifindex: 5,
        tx_ifindex: 5,
        install_table_domain: 525590,
        install_table_check: 0x1234_5678,
        ..SessionSyncRequest::default()
    };
    let entry =
        build_synced_session_entry(&req, &test_zone_name_to_id(), 0).expect("synced session entry");
    assert_eq!(
        entry.decision.install_table_domain, 525590,
        "import must adopt the origin's table domain verbatim"
    );
    assert_eq!(
        entry.decision.install_table_check, 0x1234_5678,
        "import must adopt the owner check verbatim (opaque u32)"
    );
}

#[test]
fn build_synced_session_entry_defaults_install_table_for_legacy_peer_9752() {
    let req = SessionSyncRequest {
        operation: "upsert".to_string(),
        addr_family: libc::AF_INET as u8,
        protocol: 6,
        src_ip: "10.0.61.102".to_string(),
        dst_ip: "172.16.80.200".to_string(),
        src_port: 40000,
        dst_port: 5201,
        ingress_zone: "lan".to_string(),
        egress_zone: "wan".to_string(),
        ..SessionSyncRequest::default()
    };
    // A legacy payload omits both keys: serde(default) 0 = default table.
    let legacy: SessionSyncRequest =
        serde_json::from_str(r#"{"operation":"upsert","src_ip":"10.0.61.102"}"#)
            .expect("legacy request decodes");
    assert_eq!(legacy.install_table_domain, 0);
    assert_eq!(legacy.install_table_check, 0);
    let entry =
        build_synced_session_entry(&req, &test_zone_name_to_id(), 0).expect("synced session entry");
    assert_eq!(entry.decision.install_table_domain, 0);
    assert_eq!(entry.decision.install_table_check, 0);
}
