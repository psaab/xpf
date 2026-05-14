use super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq)]
struct SharedUmemPolicy {
    mode: SharedUmemMode,
    interfaces: BTreeSet<String>,
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

#[cfg(test)]
mod tests {
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
}
