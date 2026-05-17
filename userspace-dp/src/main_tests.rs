// Tests for main.rs — relocated from inline `#[cfg(test)] mod tests` to
// keep main.rs under the modularity-discipline LOC threshold (#1048).
// Loaded as a sibling module via `#[path = "main_tests.rs"]` from main.rs.

use super::*;
use crate::test_zone_ids::*;

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
                ifindex: 11,
                rx_queues: 1,
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "xe-0/0/0".to_string(),
                linux_name: "xe-0-0-0".to_string(),
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
    let bindings = replan_queues(Some(&snapshot), 2, &[]);
    assert_eq!(bindings.len(), 2);
    assert!(bindings.iter().all(|b| {
        b.interface.starts_with("ge-")
            || b.interface.starts_with("xe-")
            || b.interface.starts_with("et-")
    }));
    assert!(bindings.iter().all(|b| b.registered));
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
                ifindex: 11,
                rx_queues: 1,
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "ge-0/0/2".to_string(),
                linux_name: "ge-0-0-2".to_string(),
                ifindex: 12,
                rx_queues: 1,
                ..Default::default()
            },
        ],
        fabrics: vec![FabricSnapshot {
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
        }],
        ..Default::default()
    };
    let bindings = replan_queues(Some(&snapshot), 1, &[]);
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
            ifindex: 21,
            rx_queues: 1,
            ..Default::default()
        }],
        fabrics: vec![FabricSnapshot {
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
        }],
        ..Default::default()
    };
    let bindings = replan_queues(Some(&snapshot), 1, &[]);
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

    let entry = build_synced_session_entry(&req, &test_zone_name_to_id())
        .expect("synced session entry");
    assert!(entry.metadata.fabric_ingress);
    assert!(entry.origin.is_peer_synced());
    assert_eq!(entry.metadata.owner_rg_id, 1);
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

    let entry = build_synced_session_entry(&req, &test_zone_name_to_id())
        .expect("synced session entry");
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
    let entry = build_synced_session_entry(&req, &test_zone_name_to_id())
        .expect("synced session entry");
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
    let entry = build_synced_session_entry(&req, &test_zone_name_to_id())
        .expect("synced session entry");
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
    let entry = build_synced_session_entry(&req, &test_zone_name_to_id())
        .expect("synced session entry");
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
    );
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
                ifindex: 24,
                parent_ifindex: 6,
                rx_queues: 1,
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let bindings = replan_queues(Some(&snapshot), 1, &[]);
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
    );
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
    let bindings = replan_queues(Some(&snapshot), 2, &[]);
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
fn queue_planner_uses_smallest_queue_count() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![
            InterfaceSnapshot {
                name: "ge-0/0/1".to_string(),
                linux_name: "ge-0-0-1".to_string(),
                rx_queues: 4,
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "ge-0/0/2".to_string(),
                linux_name: "ge-0-0-2".to_string(),
                rx_queues: 2,
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let bindings = replan_queues(Some(&snapshot), 2, &[]);
    assert_eq!(bindings.len(), 4);
    let queues = summarize_queues(&bindings);
    assert_eq!(queues.len(), 2);
    for (idx, q) in queues.iter().enumerate() {
        assert_eq!(q.queue_id, idx as u32);
        assert_eq!(
            q.interfaces,
            vec!["ge-0-0-1".to_string(), "ge-0-0-2".to_string()]
        );
        assert!(!q.registered);
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
        tx_submit_error_drops: 31,
        pending_tx_local_overflow_drops: 37,
        // #918 / #943: pin per-set LRU collision and V_min telemetry
        // through the projection so a future refactor that drops
        // either assignment surfaces here.
        flow_cache_collision_evictions: 53,
        active_flow_count: 71,
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
    assert_eq!(snap.tx_submit_error_drops, 31);
    assert_eq!(snap.pending_tx_local_overflow_drops, 37);
    assert_eq!(snap.flow_cache_collision_evictions, 53);
    // #1219: pin active_flow_count projection through the From impl.
    assert_eq!(snap.active_flow_count, 71);
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
        tx_submit_error_drops: 10,
        pending_tx_local_overflow_drops: 11,
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
        v_min_throttle_hard_cap_overrides: 28,
        v_min_throttles: 29,
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
        "tx_submit_error_drops",
        "pending_tx_local_overflow_drops",
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
    let round: BindingCountersSnapshot =
        serde_json::from_str(&json).expect("deserialize snapshot");
    assert_eq!(round, snap);
}

#[test]
fn apply_snapshot_rejects_unsupported_protocol_version() {
    let (mut client, server) = std::os::unix::net::UnixStream::pair().expect("control socket pair");
    let state = Arc::new(Mutex::new(ServerState {
        status: ProcessStatus::default(),
        snapshot: None,
        afxdp: afxdp::Coordinator::new(),
        state_writer: Arc::new(StateWriter::new()),
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
        std::thread::spawn(move || handle_stream(server, &state_file, state, running))
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
        tx_submit_error_drops: 0,
        pending_tx_local_overflow_drops: 0,
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
        v_min_throttle_hard_cap_overrides: 18,
        v_min_throttles: 19,
    };
    let json = serde_json::to_string(&snap).expect("serialize snapshot");
    let back: BindingCountersSnapshot =
        serde_json::from_str(&json).expect("deserialize snapshot");
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
