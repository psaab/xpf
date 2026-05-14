use super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq)]
struct SharedUmemPolicy {
    mode: SharedUmemMode,
    interfaces: BTreeSet<String>,
    artifact_passed: bool,
    artifact_interfaces_match: bool,
    artifact_environment_reason: Option<String>,
}

impl SharedUmemPolicy {
    fn from_snapshot(snapshot: &ConfigSnapshot) -> Self {
        let Some(shared) = snapshot.userspace.get("shared_umem") else {
            return Self::off();
        };
        let mode = shared
            .get("mode")
            .and_then(|v| v.as_str())
            .map(parse_shared_umem_mode)
            .unwrap_or(SharedUmemMode::Off);
        let configured_interfaces = string_set_from_array(shared.get("interfaces"))
            .or_else(|| string_set_from_array(shared.get("interface_names")))
            .unwrap_or_default();
        let artifact = shared
            .get("phase0_artifact")
            .or_else(|| shared.get("artifact"));
        let artifact_interfaces = artifact.and_then(|a| {
            string_set_from_array(a.get("selected_interfaces"))
                .or_else(|| string_set_from_array(a.get("interfaces")))
        });
        let interfaces = if configured_interfaces.is_empty() {
            artifact_interfaces.clone().unwrap_or_default()
        } else {
            configured_interfaces
        };
        let artifact_passed = artifact.is_some_and(phase0_artifact_passed);
        let artifact_interfaces_match = artifact_interfaces
            .as_ref()
            .is_none_or(|artifact_interfaces| artifact_interfaces == &interfaces);
        let artifact_environment_reason =
            artifact.and_then(|a| phase0_artifact_environment_mismatch(a, &interfaces));
        Self {
            mode,
            interfaces,
            artifact_passed,
            artifact_interfaces_match,
            artifact_environment_reason,
        }
    }

    fn off() -> Self {
        Self {
            mode: SharedUmemMode::Off,
            interfaces: BTreeSet::new(),
            artifact_passed: false,
            artifact_interfaces_match: false,
            artifact_environment_reason: None,
        }
    }

    fn gate_reason(&self) -> Option<String> {
        if self.mode == SharedUmemMode::Off {
            return Some("shared UMEM mode is off".to_string());
        }
        if !self.artifact_passed {
            return Some("missing passing Phase 0 shared-UMEM artifact".to_string());
        }
        if !self.artifact_interfaces_match {
            return Some("Phase 0 artifact selected interfaces do not match config".to_string());
        }
        if let Some(reason) = &self.artifact_environment_reason {
            return Some(reason.clone());
        }
        if self.mode == SharedUmemMode::CrossNic && self.interfaces.is_empty() {
            return Some(
                "cross-NIC shared UMEM requires selected interfaces from config or Phase 0 artifact"
                    .to_string(),
            );
        }
        if self.mode == SharedUmemMode::SameDeviceDebug && self.interfaces.is_empty() {
            return Some(
                "same-device-debug shared UMEM requires selected interfaces from config or Phase 0 artifact"
                    .to_string(),
            );
        }
        None
    }
}

pub(super) fn apply_shared_umem_policy_to_workers(
    snapshot: &ConfigSnapshot,
    workers: &mut BTreeMap<u32, Vec<BindingPlan>>,
) {
    let policy = SharedUmemPolicy::from_snapshot(snapshot);
    if policy.mode == SharedUmemMode::Off {
        mark_all_private(workers);
        publish_shared_umem_plan_to_status(workers);
        return;
    }
    if let Some(reason) = policy.gate_reason() {
        mark_selected_private(workers, policy.mode, &policy.interfaces, reason);
        publish_shared_umem_plan_to_status(workers);
        return;
    }
    match policy.mode {
        SharedUmemMode::Off => {}
        SharedUmemMode::SameDeviceDebug => apply_same_device_debug_groups(workers, &policy),
        SharedUmemMode::CrossNic => apply_cross_nic_groups(workers, &policy),
    }
    publish_shared_umem_plan_to_status(workers);
}

fn mark_all_private(workers: &mut BTreeMap<u32, Vec<BindingPlan>>) {
    for plans in workers.values_mut() {
        for plan in plans {
            plan.shared_umem = SharedUmemBindingPlan::private();
        }
    }
}

fn apply_cross_nic_groups(
    workers: &mut BTreeMap<u32, Vec<BindingPlan>>,
    policy: &SharedUmemPolicy,
) {
    for (&worker_id, plans) in workers.iter_mut() {
        let mut eligible = Vec::new();
        for idx in 0..plans.len() {
            let plan = &plans[idx];
            if !policy.interfaces.contains(&plan.status.interface) {
                continue;
            }
            match shared_umem_interface_info(&plan.status.interface) {
                Ok(info) if info.cross_nic_eligible() => eligible.push((idx, info)),
                Ok(info) => {
                    plans[idx].shared_umem = SharedUmemBindingPlan::disabled(
                        SharedUmemMode::CrossNic,
                        format!(
                            "interface {} ineligible for cross-NIC shared UMEM: driver={} device_path={}",
                            plan.status.interface, info.driver, info.device_path
                        ),
                    );
                }
                Err(err) => {
                    plans[idx].shared_umem =
                        SharedUmemBindingPlan::disabled(SharedUmemMode::CrossNic, err);
                }
            }
        }
        let distinct_devices = eligible
            .iter()
            .map(|(_, info)| info.device_path.as_str())
            .collect::<BTreeSet<_>>();
        if eligible.len() < 2 || distinct_devices.len() < 2 {
            for (idx, _) in eligible {
                plans[idx].shared_umem = SharedUmemBindingPlan::disabled(
                    SharedUmemMode::CrossNic,
                    "cross-NIC shared UMEM requires at least two eligible NICs".to_string(),
                );
            }
            continue;
        }
        let key = format!(
            "cross-nic:w{}:{}",
            worker_id,
            eligible
                .iter()
                .map(|(_, info)| info.ifname.as_str())
                .collect::<Vec<_>>()
                .join(",")
        );
        assign_group_roles(
            plans,
            eligible.into_iter().map(|(idx, _)| idx),
            SharedUmemMode::CrossNic,
            key,
        );
    }
}

fn apply_same_device_debug_groups(
    workers: &mut BTreeMap<u32, Vec<BindingPlan>>,
    policy: &SharedUmemPolicy,
) {
    for (&worker_id, plans) in workers.iter_mut() {
        let mut by_device: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        for idx in 0..plans.len() {
            let plan = &plans[idx];
            if !policy.interfaces.contains(&plan.status.interface) {
                continue;
            }
            match shared_umem_interface_info(&plan.status.interface) {
                Ok(info) if info.same_device_debug_eligible() => {
                    by_device.entry(info.device_path).or_default().push(idx);
                }
                Ok(info) => {
                    plans[idx].shared_umem = SharedUmemBindingPlan::disabled(
                        SharedUmemMode::SameDeviceDebug,
                        format!(
                            "interface {} ineligible for same-device-debug shared UMEM: driver={} device_path={}",
                            plan.status.interface, info.driver, info.device_path
                        ),
                    );
                }
                Err(err) => {
                    plans[idx].shared_umem =
                        SharedUmemBindingPlan::disabled(SharedUmemMode::SameDeviceDebug, err);
                }
            }
        }
        for (device, indexes) in by_device {
            if indexes.len() < 2 {
                for idx in indexes {
                    plans[idx].shared_umem = SharedUmemBindingPlan::disabled(
                        SharedUmemMode::SameDeviceDebug,
                        "same-device-debug shared UMEM requires at least two bindings".to_string(),
                    );
                }
                continue;
            }
            let key = format!("same-device-debug:w{}:{device}", worker_id);
            assign_group_roles(plans, indexes, SharedUmemMode::SameDeviceDebug, key);
        }
    }
}

fn assign_group_roles<I>(plans: &mut [BindingPlan], indexes: I, mode: SharedUmemMode, key: String)
where
    I: IntoIterator<Item = usize>,
{
    let mut indexes = indexes.into_iter().collect::<Vec<_>>();
    indexes.sort_by_key(|idx| {
        let plan = &plans[*idx];
        (plan.status.queue_id, plan.status.ifindex, plan.status.slot)
    });
    for (pos, idx) in indexes.into_iter().enumerate() {
        let role = if pos == 0 {
            SharedUmemSocketRole::Owner
        } else {
            SharedUmemSocketRole::Secondary
        };
        plans[idx].shared_umem = SharedUmemBindingPlan::shared(mode, key.clone(), role);
    }
}

fn publish_shared_umem_plan_to_status(workers: &mut BTreeMap<u32, Vec<BindingPlan>>) {
    for plans in workers.values_mut() {
        for plan in plans {
            let shared = &plan.shared_umem;
            plan.status.shared_umem_mode = if shared.mode == SharedUmemMode::Off {
                String::new()
            } else {
                shared.mode.as_str().to_string()
            };
            plan.status.shared_umem_group = shared.group_key.clone();
            plan.status.shared_umem_socket_role =
                if shared.socket_role == SharedUmemSocketRole::Private {
                    String::new()
                } else {
                    shared.socket_role.as_str().to_string()
                };
            plan.status.shared_umem_disabled_reason = shared.disabled_reason.clone();
        }
    }
}

fn mark_selected_private(
    workers: &mut BTreeMap<u32, Vec<BindingPlan>>,
    mode: SharedUmemMode,
    interfaces: &BTreeSet<String>,
    reason: String,
) {
    for plans in workers.values_mut() {
        for plan in plans {
            if interfaces.is_empty() || interfaces.contains(&plan.status.interface) {
                eprintln!(
                    "xpf-userspace-dp: shared UMEM disabled for {} if{}q{}: {}",
                    plan.status.interface, plan.status.ifindex, plan.status.queue_id, reason
                );
                plan.shared_umem = SharedUmemBindingPlan::disabled(mode, reason.clone());
            }
        }
    }
}

#[derive(Clone, Debug)]
struct SharedUmemInterfaceInfo {
    ifname: String,
    driver: String,
    device_path: String,
}

impl SharedUmemInterfaceInfo {
    fn cross_nic_eligible(&self) -> bool {
        self.driver == "mlx5_core" && !self.device_path.is_empty()
    }

    fn same_device_debug_eligible(&self) -> bool {
        self.cross_nic_eligible()
    }
}

fn shared_umem_interface_info(ifname: &str) -> Result<SharedUmemInterfaceInfo, String> {
    let driver = interface_driver_name(ifname)
        .ok_or_else(|| format!("interface {ifname} has no driver for shared UMEM"))?;
    if driver == "virtio_net" {
        return Err(format!("interface {ifname} uses virtio_net"));
    }
    let device_path = interface_device_path(ifname)
        .ok_or_else(|| format!("interface {ifname} has no PCI device path"))?;
    Ok(SharedUmemInterfaceInfo {
        ifname: ifname.to_string(),
        driver,
        device_path,
    })
}

fn interface_device_path(ifname: &str) -> Option<String> {
    if ifname.is_empty() {
        return None;
    }
    let path = Path::new("/sys/class/net").join(ifname).join("device");
    let canonical = std::fs::canonicalize(path).ok()?;
    canonical.to_str().map(str::to_string)
}

fn parse_shared_umem_mode(value: &str) -> SharedUmemMode {
    match value {
        "same-device-debug" | "same_device_debug" => SharedUmemMode::SameDeviceDebug,
        "cross-nic" | "cross_nic" => SharedUmemMode::CrossNic,
        _ => SharedUmemMode::Off,
    }
}

fn string_set_from_array(value: Option<&serde_json::Value>) -> Option<BTreeSet<String>> {
    let arr = value?.as_array()?;
    Some(
        arr.iter()
            .filter_map(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect(),
    )
}

fn phase0_artifact_passed(value: &serde_json::Value) -> bool {
    value.get("passed").and_then(|v| v.as_bool()) == Some(true)
        || matches!(
            value.get("status").and_then(|v| v.as_str()),
            Some("pass" | "passed" | "PASS")
        )
}

fn phase0_artifact_environment_mismatch(
    artifact: &serde_json::Value,
    interfaces: &BTreeSet<String>,
) -> Option<String> {
    let Some(artifact_kernel) = artifact.get("kernel_release").and_then(|v| v.as_str()) else {
        return Some("Phase 0 artifact missing kernel_release".to_string());
    };
    let Some(current_kernel) = current_kernel_release() else {
        return Some("unable to read current kernel_release for shared UMEM gate".to_string());
    };
    if artifact_kernel != current_kernel {
        return Some(format!(
            "Phase 0 artifact kernel_release {artifact_kernel} != current {current_kernel}"
        ));
    }

    let Some(artifact_interfaces) = string_set_from_array(artifact.get("selected_interfaces"))
        .or_else(|| string_set_from_array(artifact.get("interfaces")))
    else {
        return Some("Phase 0 artifact missing selected_interfaces".to_string());
    };
    if &artifact_interfaces != interfaces {
        return Some("Phase 0 artifact selected interfaces do not match config".to_string());
    }

    let Some(artifact_pci_ids) = string_set_from_array(artifact.get("selected_nic_pci_ids"))
        .or_else(|| string_set_from_array(artifact.get("pci_ids")))
    else {
        return Some("Phase 0 artifact missing selected_nic_pci_ids".to_string());
    };
    let Some(current_pci_ids) = interface_pci_ids(interfaces) else {
        return Some("unable to read current NIC PCI IDs for shared UMEM gate".to_string());
    };
    if artifact_pci_ids != current_pci_ids {
        return Some(format!(
            "Phase 0 artifact PCI IDs {:?} != current {:?}",
            artifact_pci_ids, current_pci_ids
        ));
    }

    let Some(artifact_device_set) = artifact_selected_device_ids(artifact) else {
        return Some(
            "Phase 0 artifact missing selected_device_set/selected_device_pair".to_string(),
        );
    };
    if artifact_device_set != current_pci_ids {
        return Some(format!(
            "Phase 0 artifact selected device set {:?} != current {:?}",
            artifact_device_set, current_pci_ids
        ));
    }

    let Some(artifact_driver_value) = artifact
        .get("driver")
        .or_else(|| artifact.get("driver_name"))
    else {
        return Some("Phase 0 artifact missing driver".to_string());
    };
    let Some(artifact_driver) = artifact_string_by_interface(artifact_driver_value, interfaces)
    else {
        return Some("Phase 0 artifact driver must be a string or interface map".to_string());
    };
    let Some(current_driver) = interface_driver_by_name(interfaces) else {
        return Some("unable to read current interface driver for shared UMEM gate".to_string());
    };
    if artifact_driver != current_driver {
        return Some(format!(
            "Phase 0 artifact driver {:?} != current {:?}",
            artifact_driver, current_driver
        ));
    }

    let Some(artifact_mtu_value) = artifact.get("mtu") else {
        return Some("Phase 0 artifact missing mtu".to_string());
    };
    let Some(artifact_mtu) = artifact_u32_by_interface(artifact_mtu_value, interfaces) else {
        return Some("Phase 0 artifact mtu must be a number or interface map".to_string());
    };
    let Some(current_mtu) = interface_mtu_by_name(interfaces) else {
        return Some("unable to read current interface MTU for shared UMEM gate".to_string());
    };
    if artifact_mtu != current_mtu {
        return Some(format!(
            "Phase 0 artifact MTU {:?} != current {:?}",
            artifact_mtu, current_mtu
        ));
    }

    let Some(artifact_queues_value) = artifact.get("queue_topology") else {
        return Some("Phase 0 artifact missing queue_topology".to_string());
    };
    let Some(artifact_queues) = artifact_u32_by_interface(artifact_queues_value, interfaces) else {
        return Some(
            "Phase 0 artifact queue_topology must be a number or interface map".to_string(),
        );
    };
    let Some(current_queues) = interface_rx_queue_count_by_name(interfaces) else {
        return Some("unable to read current RX queue topology for shared UMEM gate".to_string());
    };
    if artifact_queues != current_queues {
        return Some(format!(
            "Phase 0 artifact queue_topology {:?} != current {:?}",
            artifact_queues, current_queues
        ));
    }

    None
}

fn artifact_selected_device_ids(artifact: &serde_json::Value) -> Option<BTreeSet<String>> {
    string_set_from_array(artifact.get("selected_device_set"))
        .or_else(|| string_set_from_array(artifact.get("selected_devices")))
        .or_else(|| string_set_from_array(artifact.get("selected_device_pair")))
}

fn current_kernel_release() -> Option<String> {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn interface_pci_ids(interfaces: &BTreeSet<String>) -> Option<BTreeSet<String>> {
    let mut out = BTreeSet::new();
    for ifname in interfaces {
        let device_path = interface_device_path(ifname)?;
        let pci_id = Path::new(&device_path).file_name()?.to_str()?.to_string();
        out.insert(pci_id);
    }
    Some(out)
}

fn artifact_string_by_interface(
    value: &serde_json::Value,
    interfaces: &BTreeSet<String>,
) -> Option<BTreeMap<String, String>> {
    if let Some(single) = value.as_str() {
        return Some(
            interfaces
                .iter()
                .map(|ifname| (ifname.clone(), single.to_string()))
                .collect(),
        );
    }
    let object = value.as_object()?;
    let mut out = BTreeMap::new();
    for ifname in interfaces {
        let value = object.get(ifname)?.as_str()?;
        out.insert(ifname.clone(), value.to_string());
    }
    Some(out)
}

fn interface_driver_by_name(interfaces: &BTreeSet<String>) -> Option<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    for ifname in interfaces {
        out.insert(ifname.clone(), interface_driver_name(ifname)?);
    }
    Some(out)
}

fn artifact_u32_by_interface(
    value: &serde_json::Value,
    interfaces: &BTreeSet<String>,
) -> Option<BTreeMap<String, u32>> {
    if let Some(single) = value.as_u64().and_then(|v| u32::try_from(v).ok()) {
        return Some(
            interfaces
                .iter()
                .map(|ifname| (ifname.clone(), single))
                .collect(),
        );
    }
    let object = value.as_object()?;
    let mut out = BTreeMap::new();
    for ifname in interfaces {
        let value = object.get(ifname)?.as_u64()?;
        out.insert(ifname.clone(), u32::try_from(value).ok()?);
    }
    Some(out)
}

fn interface_mtu_by_name(interfaces: &BTreeSet<String>) -> Option<BTreeMap<String, u32>> {
    let mut out = BTreeMap::new();
    for ifname in interfaces {
        let path = Path::new("/sys/class/net").join(ifname).join("mtu");
        out.insert(ifname.clone(), read_u32_file(path)?);
    }
    Some(out)
}

fn interface_rx_queue_count_by_name(
    interfaces: &BTreeSet<String>,
) -> Option<BTreeMap<String, u32>> {
    let mut out = BTreeMap::new();
    for ifname in interfaces {
        let path = Path::new("/sys/class/net").join(ifname).join("queues");
        let count = std::fs::read_dir(path)
            .ok()?
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.starts_with("rx-"))
            })
            .count();
        out.insert(ifname.clone(), u32::try_from(count).ok()?);
    }
    Some(out)
}

fn read_u32_file(path: impl AsRef<Path>) -> Option<u32> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::Arc;

    #[test]
    fn policy_defaults_off() {
        let snapshot = ConfigSnapshot::default();
        assert_eq!(
            SharedUmemPolicy::from_snapshot(&snapshot).mode,
            SharedUmemMode::Off
        );
    }

    #[test]
    fn cross_nic_requires_phase0_artifact() {
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
            policy.gate_reason().as_deref(),
            Some("missing passing Phase 0 shared-UMEM artifact")
        );
    }

    #[test]
    fn artifact_interface_mismatch_blocks_policy() {
        let snapshot = ConfigSnapshot {
            userspace: json!({
                "shared_umem": {
                    "mode": "cross-nic",
                    "interfaces": ["lan0", "wan0"],
                    "phase0_artifact": {
                        "passed": true,
                        "selected_interfaces": ["lan0", "dmz0"]
                    }
                }
            }),
            ..ConfigSnapshot::default()
        };
        let policy = SharedUmemPolicy::from_snapshot(&snapshot);
        assert_eq!(
            policy.gate_reason().as_deref(),
            Some("Phase 0 artifact selected interfaces do not match config")
        );
    }

    #[test]
    fn artifact_interfaces_select_cross_nic_policy_when_config_omits_interfaces() {
        let snapshot = ConfigSnapshot {
            userspace: json!({
                "shared_umem": {
                    "mode": "cross-nic",
                    "phase0_artifact": {
                        "passed": true,
                        "kernel_release": current_kernel_release().expect("kernel release"),
                        "selected_interfaces": ["lan0", "wan0"],
                        "selected_nic_pci_ids": ["0000:08:00.0", "0000:09:00.0"],
                        "selected_device_set": ["0000:08:00.0", "0000:09:00.0"],
                        "driver": {"lan0": "mlx5_core", "wan0": "mlx5_core"},
                        "mtu": {"lan0": 1500, "wan0": 1500},
                        "queue_topology": {"lan0": 6, "wan0": 6}
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
        assert!(policy.artifact_interfaces_match);
        assert_ne!(
            policy.gate_reason().as_deref(),
            Some("cross-NIC shared UMEM requires explicit interfaces")
        );
    }

    #[test]
    fn phase0_environment_gate_rejects_missing_selected_device_set() {
        let mut artifact = empty_interface_phase0_artifact();
        artifact
            .as_object_mut()
            .expect("artifact object")
            .remove("selected_device_set");

        assert_eq!(
            phase0_artifact_environment_mismatch(&artifact, &BTreeSet::new()).as_deref(),
            Some("Phase 0 artifact missing selected_device_set/selected_device_pair")
        );
    }

    #[test]
    fn phase0_environment_gate_rejects_missing_driver() {
        let mut artifact = empty_interface_phase0_artifact();
        artifact
            .as_object_mut()
            .expect("artifact object")
            .remove("driver");

        assert_eq!(
            phase0_artifact_environment_mismatch(&artifact, &BTreeSet::new()).as_deref(),
            Some("Phase 0 artifact missing driver")
        );
    }

    #[test]
    fn phase0_environment_gate_rejects_kernel_release_mismatch() {
        let mut artifact = empty_interface_phase0_artifact();
        artifact.as_object_mut().expect("artifact object").insert(
            "kernel_release".to_string(),
            json!("not-the-current-kernel"),
        );

        let reason = phase0_artifact_environment_mismatch(&artifact, &BTreeSet::new())
            .expect("kernel release mismatch");
        assert!(reason.starts_with("Phase 0 artifact kernel_release"));
    }

    #[test]
    fn phase0_environment_gate_rejects_interface_mismatch() {
        let mut artifact = empty_interface_phase0_artifact();
        artifact
            .as_object_mut()
            .expect("artifact object")
            .insert("selected_interfaces".to_string(), json!(["dmz0"]));

        assert_eq!(
            phase0_artifact_environment_mismatch(&artifact, &BTreeSet::new()).as_deref(),
            Some("Phase 0 artifact selected interfaces do not match config")
        );
    }

    #[test]
    fn phase0_environment_gate_rejects_pci_mismatch() {
        let mut artifact = empty_interface_phase0_artifact();
        artifact
            .as_object_mut()
            .expect("artifact object")
            .insert("selected_nic_pci_ids".to_string(), json!(["0000:00:00.0"]));

        let reason = phase0_artifact_environment_mismatch(&artifact, &BTreeSet::new())
            .expect("PCI mismatch");
        assert!(reason.starts_with("Phase 0 artifact PCI IDs"));
    }

    #[test]
    fn phase0_environment_gate_rejects_selected_device_set_mismatch() {
        let mut artifact = empty_interface_phase0_artifact();
        artifact
            .as_object_mut()
            .expect("artifact object")
            .insert("selected_device_set".to_string(), json!(["0000:00:00.0"]));

        let reason = phase0_artifact_environment_mismatch(&artifact, &BTreeSet::new())
            .expect("device-set mismatch");
        assert!(reason.starts_with("Phase 0 artifact selected device set"));
    }

    #[test]
    fn phase0_environment_gate_accepts_legacy_selected_device_pair_alias() {
        let mut artifact = empty_interface_phase0_artifact();
        let object = artifact.as_object_mut().expect("artifact object");
        object.remove("selected_device_set");
        object.insert("selected_device_pair".to_string(), json!([]));

        assert_eq!(
            phase0_artifact_environment_mismatch(&artifact, &BTreeSet::new()),
            None
        );
    }

    #[test]
    fn phase0_environment_gate_rejects_driver_mismatch() {
        let (interfaces, mut artifact) = live_interface_phase0_artifact()
            .expect("test host must expose a sysfs-backed netdev with driver/device/mtu/queues");
        let ifname = interfaces.iter().next().expect("interface").clone();
        artifact.as_object_mut().expect("artifact object").insert(
            "driver".to_string(),
            json!({ ifname: "not_the_live_driver" }),
        );

        let reason =
            phase0_artifact_environment_mismatch(&artifact, &interfaces).expect("driver mismatch");
        assert!(reason.starts_with("Phase 0 artifact driver"));
    }

    #[test]
    fn phase0_environment_gate_rejects_mtu_mismatch() {
        let (interfaces, mut artifact) = live_interface_phase0_artifact()
            .expect("test host must expose a sysfs-backed netdev with driver/device/mtu/queues");
        let ifname = interfaces.iter().next().expect("interface").clone();
        let live_mtu = interface_mtu_by_name(&interfaces)
            .expect("live mtu")
            .get(&ifname)
            .copied()
            .expect("interface mtu");
        artifact.as_object_mut().expect("artifact object").insert(
            "mtu".to_string(),
            json!({ ifname: live_mtu.saturating_add(1) }),
        );

        let reason =
            phase0_artifact_environment_mismatch(&artifact, &interfaces).expect("MTU mismatch");
        assert!(reason.starts_with("Phase 0 artifact MTU"));
    }

    #[test]
    fn phase0_environment_gate_rejects_queue_topology_mismatch() {
        let (interfaces, mut artifact) = live_interface_phase0_artifact()
            .expect("test host must expose a sysfs-backed netdev with driver/device/mtu/queues");
        let ifname = interfaces.iter().next().expect("interface").clone();
        let live_queues = interface_rx_queue_count_by_name(&interfaces)
            .expect("live queues")
            .get(&ifname)
            .copied()
            .expect("interface queue count");
        artifact.as_object_mut().expect("artifact object").insert(
            "queue_topology".to_string(),
            json!({ ifname: live_queues.saturating_add(1) }),
        );

        let reason = phase0_artifact_environment_mismatch(&artifact, &interfaces)
            .expect("queue topology mismatch");
        assert!(reason.starts_with("Phase 0 artifact queue_topology"));
    }

    #[test]
    fn phase0_environment_gate_accepts_driver_name_alias() {
        let mut artifact = empty_interface_phase0_artifact();
        let object = artifact.as_object_mut().expect("artifact object");
        object.remove("driver");
        object.insert("driver_name".to_string(), json!({}));

        assert_eq!(
            phase0_artifact_environment_mismatch(&artifact, &BTreeSet::new()),
            None
        );
    }

    #[test]
    fn artifact_string_by_interface_reads_non_empty_driver_name_map() {
        let interfaces = BTreeSet::from(["lan0".to_string()]);
        assert_eq!(
            artifact_string_by_interface(&json!({"lan0": "mlx5_core"}), &interfaces),
            Some(BTreeMap::from([(
                "lan0".to_string(),
                "mlx5_core".to_string()
            )]))
        );
    }

    #[test]
    fn complete_phase0_artifact_reaches_cross_nic_interface_gate() {
        let snapshot = ConfigSnapshot {
            userspace: json!({
                "shared_umem": {
                    "mode": "cross-nic",
                    "interfaces": [],
                    "phase0_artifact": empty_interface_phase0_artifact()
                }
            }),
            ..ConfigSnapshot::default()
        };
        let policy = SharedUmemPolicy::from_snapshot(&snapshot);
        assert_eq!(
            policy.gate_reason().as_deref(),
            Some(
                "cross-NIC shared UMEM requires selected interfaces from config or Phase 0 artifact"
            )
        );
    }

    #[test]
    fn complete_phase0_artifact_reaches_same_device_interface_gate() {
        let snapshot = ConfigSnapshot {
            userspace: json!({
                "shared_umem": {
                    "mode": "same-device-debug",
                    "interfaces": [],
                    "phase0_artifact": empty_interface_phase0_artifact()
                }
            }),
            ..ConfigSnapshot::default()
        };
        let policy = SharedUmemPolicy::from_snapshot(&snapshot);
        assert_eq!(
            policy.gate_reason().as_deref(),
            Some(
                "same-device-debug shared UMEM requires selected interfaces from config or Phase 0 artifact"
            )
        );
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
            session_map_fd: -1,
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
        apply_shared_umem_policy_to_workers(&ConfigSnapshot::default(), &mut workers);
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

    fn empty_interface_phase0_artifact() -> serde_json::Value {
        json!({
            "passed": true,
            "kernel_release": current_kernel_release().expect("kernel release"),
            "selected_interfaces": [],
            "selected_nic_pci_ids": [],
            "selected_device_set": [],
            "driver": {},
            "mtu": {},
            "queue_topology": {}
        })
    }

    fn live_interface_phase0_artifact() -> Option<(BTreeSet<String>, serde_json::Value)> {
        for entry in std::fs::read_dir("/sys/class/net")
            .ok()?
            .filter_map(Result::ok)
        {
            let Some(ifname) = entry.file_name().to_str().map(str::to_string) else {
                continue;
            };
            let interfaces = BTreeSet::from([ifname]);
            let Some(pci_ids) = interface_pci_ids(&interfaces) else {
                continue;
            };
            let Some(driver) = interface_driver_by_name(&interfaces) else {
                continue;
            };
            let Some(mtu) = interface_mtu_by_name(&interfaces) else {
                continue;
            };
            let Some(queue_topology) = interface_rx_queue_count_by_name(&interfaces) else {
                continue;
            };
            let artifact = json!({
                "passed": true,
                "kernel_release": current_kernel_release()?,
                "selected_interfaces": interfaces,
                "selected_nic_pci_ids": pci_ids,
                "selected_device_set": pci_ids,
                "driver": driver,
                "mtu": mtu,
                "queue_topology": queue_topology
            });
            return Some((interfaces, artifact));
        }
        None
    }
}
