use super::*;
use serde_json::json;
use std::sync::Arc;

#[test]
fn policy_defaults_to_cross_nic_auto() {
    let snapshot = ConfigSnapshot::default();
    let policy = SharedUmemPolicy::from_snapshot(&snapshot);
    assert_eq!(policy.mode, SharedUmemMode::CrossNic);
    assert!(policy.interfaces.is_empty());
    assert!(policy.phase0_audit.is_none());
}

#[test]
fn explicit_off_disables_shared_umem() {
    let snapshot = ConfigSnapshot {
        userspace: json!({
            "shared_umem": {
                "mode": "off"
            }
        }),
        ..ConfigSnapshot::default()
    };
    let policy = SharedUmemPolicy::from_snapshot(&snapshot);
    assert_eq!(policy.mode, SharedUmemMode::Off);
}

#[test]
fn explicit_interfaces_limit_policy_candidates() {
    let snapshot = ConfigSnapshot {
        userspace: json!({
            "shared_umem": {
                "mode": "cross-nic",
                "interfaces": ["lan0", "wan0"]
            }
        }),
        ..ConfigSnapshot::default()
    };
    let policy = SharedUmemPolicy::from_snapshot(&snapshot);
    assert_eq!(
        policy.interfaces,
        BTreeSet::from(["lan0".to_string(), "wan0".to_string()])
    );
    assert!(policy.selects_interface("lan0"));
    assert!(!policy.selects_interface("dmz0"));
}

#[test]
fn artifact_interfaces_do_not_gate_or_select_runtime_policy() {
    let snapshot = ConfigSnapshot {
        userspace: json!({
            "shared_umem": {
                "mode": "cross-nic",
                "phase0_artifact": {
                    "passed": true,
                    "selected_interfaces": ["lan0", "wan0"]
                }
            }
        }),
        ..ConfigSnapshot::default()
    };
    let policy = SharedUmemPolicy::from_snapshot(&snapshot);
    assert!(policy.interfaces.is_empty());
    assert!(policy.selects_interface("dmz0"));
    assert_eq!(
        policy
            .phase0_audit
            .as_ref()
            .and_then(|audit| audit.reason.as_deref()),
        Some("Phase 0 artifact missing kernel_release")
    );
}

#[test]
fn explicit_config_filter_is_not_blocked_by_stale_artifact() {
    let snapshot = ConfigSnapshot {
        userspace: json!({
            "shared_umem": {
                "mode": "cross-nic",
                "interfaces": ["lan0", "wan0"],
                "phase0_artifact": {
                    "passed": false,
                    "selected_interfaces": ["dmz0"]
                }
            }
        }),
        ..ConfigSnapshot::default()
    };
    let policy = SharedUmemPolicy::from_snapshot(&snapshot);
    assert_eq!(
        policy.interfaces,
        BTreeSet::from(["lan0".to_string(), "wan0".to_string()])
    );
    assert_eq!(
        policy
            .phase0_audit
            .as_ref()
            .and_then(|audit| audit.reason.as_deref()),
        Some("Phase 0 artifact did not pass")
    );
}

#[test]
fn same_device_debug_auto_selects_all_interfaces() {
    let snapshot = ConfigSnapshot {
        userspace: json!({
            "shared_umem": {
                "mode": "same-device-debug"
            }
        }),
        ..ConfigSnapshot::default()
    };
    let policy = SharedUmemPolicy::from_snapshot(&snapshot);
    assert_eq!(policy.mode, SharedUmemMode::SameDeviceDebug);
    assert!(policy.selects_interface("lan0"));
}

#[test]
fn off_policy_clears_stale_shared_status() {
    let mut status = BindingStatus {
        slot: 7,
        queue_id: 1,
        worker_id: 0,
        interface: "lan0".to_string(),
        shared_umem_mode: "cross-nic".to_string(),
        shared_umem_group: "cross-nic:w0:lan0,wan0".to_string(),
        shared_umem_socket_role: "owner".to_string(),
        ..BindingStatus::default()
    };
    status.ready = true;
    let plan = BindingPlan {
        status,
        live: Arc::new(BindingLiveState::new()),
        xsk_map_fd: -1,
        heartbeat_map_fd: -1,
        session_map: crate::afxdp::bpf_map::SteeringMapRef::new(-1, std::sync::Arc::default()),
        conntrack_v4_fd: -1,
        conntrack_v6_fd: -1,
        ring_entries: 256,
        bind_strategy: AfXdpBindStrategy::UmemOwnerSocket,
        poll_mode: crate::PollMode::Interrupt,
        shared_umem: SharedUmemBindingPlan::shared(
            SharedUmemMode::CrossNic,
            "cross-nic:w0:lan0,wan0".to_string(),
            SharedUmemSocketRole::Owner,
        ),
    };
    let mut workers = BTreeMap::from([(0, vec![plan])]);
    let snapshot = ConfigSnapshot {
        userspace: json!({
            "shared_umem": {
                "mode": "off"
            }
        }),
        ..ConfigSnapshot::default()
    };
    apply_shared_umem_policy_to_workers(&snapshot, &mut workers);
    let status = &workers.get(&0).unwrap()[0].status;
    assert_eq!(status.shared_umem_mode, "");
    assert_eq!(status.shared_umem_group, "");
    assert_eq!(status.shared_umem_socket_role, "");
    assert_eq!(status.shared_umem_disabled_reason, "");
    assert_eq!(
        workers.get(&0).unwrap()[0].shared_umem,
        SharedUmemBindingPlan::private()
    );
}
