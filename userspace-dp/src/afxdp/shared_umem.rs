use super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq)]
struct SharedUmemPolicy {
    mode: SharedUmemMode,
    interfaces: BTreeSet<String>,
    phase0_audit: Option<Phase0Audit>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Phase0Audit {
    reason: Option<String>,
}

impl SharedUmemPolicy {
    fn from_snapshot(snapshot: &ConfigSnapshot) -> Self {
        let Some(shared) = snapshot.userspace.get("shared_umem") else {
            return Self::auto();
        };
        let mode = shared
            .get("mode")
            .and_then(|v| v.as_str())
            .map(parse_shared_umem_mode)
            .unwrap_or(SharedUmemMode::CrossNic);
        let interfaces = string_set_from_array(shared.get("interfaces"))
            .or_else(|| string_set_from_array(shared.get("interface_names")))
            .unwrap_or_default();
        let artifact = shared
            .get("phase0_artifact")
            .or_else(|| shared.get("artifact"));
        let phase0_audit = artifact.map(|artifact| {
            let audit_interfaces = if interfaces.is_empty() {
                string_set_from_array(artifact.get("selected_interfaces"))
                    .or_else(|| string_set_from_array(artifact.get("interfaces")))
                    .unwrap_or_default()
            } else {
                interfaces.clone()
            };
            Phase0Audit {
                reason: phase0_artifact_audit_reason(artifact, &audit_interfaces),
            }
        });
        Self {
            mode,
            interfaces,
            phase0_audit,
        }
    }

    fn auto() -> Self {
        Self {
            mode: SharedUmemMode::CrossNic,
            interfaces: BTreeSet::new(),
            phase0_audit: None,
        }
    }

    fn selects_interface(&self, ifname: &str) -> bool {
        self.interfaces.is_empty() || self.interfaces.contains(ifname)
    }
}

pub(super) fn apply_shared_umem_policy_to_workers(
    snapshot: &ConfigSnapshot,
    workers: &mut BTreeMap<u32, Vec<BindingPlan>>,
) {
    let policy = SharedUmemPolicy::from_snapshot(snapshot);
    log_phase0_audit(&policy);
    if policy.mode == SharedUmemMode::Off {
        mark_all_private(workers);
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
            if !policy.selects_interface(&plan.status.interface) {
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
            if !policy.selects_interface(&plan.status.interface) {
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
            publish_shared_umem_plan_to_binding_status(&mut plan.status, &plan.shared_umem);
        }
    }
}

pub(super) fn publish_shared_umem_plan_to_binding_status(
    status: &mut BindingStatus,
    shared: &SharedUmemBindingPlan,
) {
    status.shared_umem_mode = if shared.mode == SharedUmemMode::Off {
        String::new()
    } else {
        shared.mode.as_str().to_string()
    };
    status.shared_umem_group = shared.group_key.clone();
    status.shared_umem_socket_role = if shared.socket_role == SharedUmemSocketRole::Private {
        String::new()
    } else {
        shared.socket_role.as_str().to_string()
    };
    status.shared_umem_disabled_reason = shared.disabled_reason.clone();
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

/// #17149: the accepted set is exactly the Go schema enum for
/// `system dataplane shared-umem mode`
/// (pkg/config/schema_system.go: auto|off|same-device-debug|cross-nic).
/// Previously 11 spellings were accepted and any other value fell
/// through `_ => Off`, so a typo committed clean on the Go side and
/// silently disabled shared UMEM here. Unknown values still fall back
/// to Off for fail-safety (a handcrafted / pre-#17149 persisted
/// snapshot must not brick the helper), but the fallback is now
/// operator-visible: it logs once per process instead of silently
/// selecting Off.
fn parse_shared_umem_mode(value: &str) -> SharedUmemMode {
    match value {
        "auto" | "cross-nic" => SharedUmemMode::CrossNic,
        "same-device-debug" => SharedUmemMode::SameDeviceDebug,
        "off" => SharedUmemMode::Off,
        other => {
            static WARNED: std::sync::atomic::AtomicBool =
                std::sync::atomic::AtomicBool::new(false);
            if !WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
                eprintln!(
                    "xpf-userspace-dp: unknown shared-umem mode {other:?} \
                     (expected auto|off|same-device-debug|cross-nic); \
                     falling back to Off (shared UMEM disabled) (#17149)"
                );
            }
            SharedUmemMode::Off
        }
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

fn log_phase0_audit(policy: &SharedUmemPolicy) {
    let Some(audit) = &policy.phase0_audit else {
        return;
    };
    match &audit.reason {
        Some(reason) => eprintln!(
            "xpf-userspace-dp: shared UMEM Phase 0 audit mismatch (non-blocking): {reason}"
        ),
        None => eprintln!("xpf-userspace-dp: shared UMEM Phase 0 audit passed"),
    }
}

fn phase0_artifact_audit_reason(
    artifact: &serde_json::Value,
    interfaces: &BTreeSet<String>,
) -> Option<String> {
    if !phase0_artifact_passed(artifact) {
        return Some("Phase 0 artifact did not pass".to_string());
    }
    if interfaces.is_empty() {
        return Some("Phase 0 artifact has no selected interfaces to audit".to_string());
    }
    phase0_artifact_environment_mismatch(artifact, interfaces)
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
        return Some("unable to read current kernel_release for shared UMEM audit".to_string());
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
        return Some(
            "Phase 0 artifact selected interfaces do not match audit interfaces".to_string(),
        );
    }

    let Some(artifact_pci_ids) = string_set_from_array(artifact.get("selected_nic_pci_ids"))
        .or_else(|| string_set_from_array(artifact.get("pci_ids")))
    else {
        return Some("Phase 0 artifact missing selected_nic_pci_ids".to_string());
    };
    let Some(current_pci_ids) = interface_pci_ids(interfaces) else {
        return Some("unable to read current NIC PCI IDs for shared UMEM audit".to_string());
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
        return Some("unable to read current interface driver for shared UMEM audit".to_string());
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
        return Some("unable to read current interface MTU for shared UMEM audit".to_string());
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
        return Some("unable to read current RX queue topology for shared UMEM audit".to_string());
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
#[path = "shared_umem_tests.rs"]
mod tests;
