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
fn present_but_modeless_snapshot_defaults_to_cross_nic() {
    // #17134 fold (Rev18187 B1): Go emits a present `shared_umem` with
    // no `mode` leaf routinely (`Mode` is `json:"mode,omitempty"` and
    // `compileSharedUMEMConfig` sets it only from a `mode` leaf — a
    // stanza setting only `interface …` or only
    // `phase0-artifact-file`). The pre-#17134 `Value` reader defaulted
    // a missing mode to CrossNic; the typed path must too — an empty
    // mode falling through to `Off` would silently mark every binding
    // private. Covers the missing leaf, an explicit empty string, and
    // an explicit null.
    for shared in [
        json!({ "interfaces": ["lan0", "wan0"] }),
        json!({ "mode": "", "interfaces": ["lan0"] }),
        json!({ "mode": null, "interfaces": ["lan0"] }),
        json!({ "phase0_artifact_file": "/run/xpf/phase0.json" }),
    ] {
        let snapshot = ConfigSnapshot {
            userspace: serde_json::from_value(json!({ "shared_umem": shared }))
                .expect("modeless shared_umem decodes"),
            ..ConfigSnapshot::default()
        };
        let policy = SharedUmemPolicy::from_snapshot(&snapshot);
        assert_eq!(
            policy.mode,
            SharedUmemMode::CrossNic,
            "present-but-modeless shared_umem must stay cross-NIC/auto"
        );
    }
    // …with its configured interface filter intact.
    let snapshot = ConfigSnapshot {
        userspace: serde_json::from_value(json!({
            "shared_umem": { "interfaces": ["lan0", "wan0"] }
        }))
        .unwrap(),
        ..ConfigSnapshot::default()
    };
    let policy = SharedUmemPolicy::from_snapshot(&snapshot);
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

#[test]
fn shared_umem_mode_accepts_only_canonical_set_17149() {
    // #17149: exactly the Go schema enum (auto|off|same-device-debug|
    // cross-nic). Former aliases must no longer map to a mode.
    assert_eq!(parse_shared_umem_mode("auto"), SharedUmemMode::CrossNic);
    assert_eq!(
        parse_shared_umem_mode("cross-nic"),
        SharedUmemMode::CrossNic
    );
    assert_eq!(
        parse_shared_umem_mode("same-device-debug"),
        SharedUmemMode::SameDeviceDebug
    );
    assert_eq!(parse_shared_umem_mode("off"), SharedUmemMode::Off);
}

#[test]
fn shared_umem_mode_unknown_falls_back_off_17149() {
    // Fail-safe fallback for handcrafted / pre-#17149 snapshots: unknown
    // values (including every former alias and typos) select Off rather
    // than panicking or silently enabling sharing. The arm logs once;
    // the log itself is not asserted here.
    for value in [
        "cross-nick",
        "bogus",
        "Cross-Nic",
        "on",
        "enable",
        "enabled",
        "disable",
        "disabled",
        "cross_nic",
        "same_device_debug",
        "",
    ] {
        assert_eq!(
            parse_shared_umem_mode(value),
            SharedUmemMode::Off,
            "unknown mode {value:?} must fall back to Off"
        );
    }
    // Snapshot-level: a typo'd mode yields an Off policy, not CrossNic.
    let snapshot = ConfigSnapshot {
        userspace: serde_json::from_value(json!({
            "shared_umem": {
                "mode": "cross-nick"
            }
        }))
        .unwrap(),
        ..ConfigSnapshot::default()
    };
    assert_eq!(
        SharedUmemPolicy::from_snapshot(&snapshot).mode,
        SharedUmemMode::Off
    );
}
