use super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq)]
struct SharedUmemPolicy {
    mode: SharedUmemMode,
    interfaces: BTreeSet<String>,
}

impl SharedUmemPolicy {
    // #17134: the Phase 0 environment audit that used to run here read
    // `shared_umem.phase0_artifact`, a key no Go build has emitted since
    // #5300 renamed it to `phase0_artifact_file` (a path). The audit is
    // owned by the Go compile-time `sharedUMEMAuditWarnings`; this policy
    // now consumes only the typed mode/interfaces the helper acts on.
    fn from_snapshot(snapshot: &ConfigSnapshot) -> Self {
        let Some(shared) = &snapshot.userspace.shared_umem else {
            return Self::auto();
        };
        let mode = parse_shared_umem_mode(&shared.mode);
        let interfaces = shared
            .interfaces
            .iter()
            .filter(|s| !s.is_empty())
            .cloned()
            .collect();
        Self { mode, interfaces }
    }

    fn auto() -> Self {
        Self {
            mode: SharedUmemMode::CrossNic,
            interfaces: BTreeSet::new(),
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

fn parse_shared_umem_mode(value: &str) -> SharedUmemMode {
    match value {
        "auto" | "on" | "enable" | "enabled" => SharedUmemMode::CrossNic,
        "same-device-debug" | "same_device_debug" => SharedUmemMode::SameDeviceDebug,
        "cross-nic" | "cross_nic" => SharedUmemMode::CrossNic,
        "off" | "disable" | "disabled" => SharedUmemMode::Off,
        _ => SharedUmemMode::Off,
    }
}

#[cfg(test)]
#[path = "shared_umem_tests.rs"]
mod tests;
