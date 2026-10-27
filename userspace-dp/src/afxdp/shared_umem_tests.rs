use super::*;
use serde_json::json;
use std::sync::Arc;

#[test]
fn policy_defaults_to_cross_nic_auto() {
    let snapshot = ConfigSnapshot::default();
    let policy = SharedUmemPolicy::from_snapshot(&snapshot);
    assert_eq!(policy.mode, SharedUmemMode::CrossNic);
    assert!(policy.interfaces.is_empty());
}

#[test]
fn explicit_off_disables_shared_umem() {
    let snapshot = ConfigSnapshot {
        userspace: serde_json::from_value(json!({
            "shared_umem": {
                "mode": "off"
            }
        }))
        .unwrap(),
        ..ConfigSnapshot::default()
    };
    let policy = SharedUmemPolicy::from_snapshot(&snapshot);
    assert_eq!(policy.mode, SharedUmemMode::Off);
}

#[test]
fn explicit_interfaces_limit_policy_candidates() {
    let snapshot = ConfigSnapshot {
        userspace: serde_json::from_value(json!({
            "shared_umem": {
                "mode": "cross-nic",
                "interfaces": ["lan0", "wan0"]
            }
        }))
        .unwrap(),
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
fn unknown_shared_umem_keys_are_ignored() {
    // #17134: unknown keys in the typed subtree (e.g. a future Go
    // `SharedUMEMConfig` field, or a retired artifact object
    // an older daemon might still emit) must be tolerated, not rejected:
    // no `deny_unknown_fields`, rolling-upgrade safe.
    let userspace: crate::protocol::UserspaceSnapshot = serde_json::from_value(json!({
        "workers": 2,
        "shared_umem": {
            "mode": "cross-nic",
            "interfaces": ["lan0", "wan0"],
            "legacy_artifact": {"passed": false, "selected_interfaces": ["dmz0"]},
            "future_field": 1
        }
    }))
    .expect("unknown shared_umem keys tolerated");
    let snapshot = ConfigSnapshot {
        userspace,
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
fn null_userspace_decodes_as_default() {
    // #17134: the #16132 `config_snapshot` specimen carries
    // `"userspace": null`; the typed field must decode it as default
    // rather than rejecting the whole snapshot.
    // Decode through ConfigSnapshot so the field's null-tolerant
    // deserializer (not the struct's derived one) is what runs.
    let mut raw = serde_json::to_value(ConfigSnapshot::default()).expect("default serializes");
    raw["userspace"] = serde_json::Value::Null;
    let snapshot: ConfigSnapshot =
        serde_json::from_value(raw).expect("null userspace decodes");
    let policy = SharedUmemPolicy::from_snapshot(&snapshot);
    assert_eq!(policy.mode, SharedUmemMode::CrossNic);
    assert!(policy.interfaces.is_empty());
}

#[test]
fn same_device_debug_auto_selects_all_interfaces() {
    let snapshot = ConfigSnapshot {
        userspace: serde_json::from_value(json!({
            "shared_umem": {
                "mode": "same-device-debug"
            }
        }))
        .unwrap(),
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
        session_map: crate::afxdp::bpf_map::SteeringMapRef::unbound(),
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
        userspace: serde_json::from_value(json!({
            "shared_umem": {
                "mode": "off"
            }
        }))
        .unwrap(),
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
