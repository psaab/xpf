# Hostile Plan Review: Bare-metal Interface Device-Map Plan (#1956)

**Verdict:** `PLAN-NEEDS-MAJOR`

---

## Executive Summary

The proposed plan introduces a hybrid stable-identity managed allowlist (`chassis device-map` config stanza) to replace positional PCI-order interface naming and avoid unmanaged interface cleanup hazards on bare-metal systems. 

While the plan correctly identifies core issues in `enumerateAndRenameInterfaces` and `compiler_iface.go`, it contains **critical runtime/reboot validation discrepancies** and **operational design flaws** that could permanently brick administrator access or cause silent traffic misrouting. Specifically, the runtime application of mapping changes without renaming interfaces introduces a deferred reboot lockout hazard. Additionally, the lack of stale `.link` file cleanup will cause systemd-networkd to ignore configuration changes, and the sequential PCI-MAC resolution logic allows silent slot hijacking.

---

## Severity-Tagged Findings

### [CRITICAL-HAZARD] Deferred Reboot Lockout: Runtime commits succeed but brick the next boot
* **Severity:** CRITICAL
* **Files & Line Citations:**
  * [pkg/daemon/daemon_run.go:336-360](file:///home/ps/git/bpfrx/pkg/daemon/daemon_run.go#L336-L360) (startup rename branch)
  * [pkg/daemon/daemon_apply.go:231](file:///home/ps/git/bpfrx/pkg/daemon/daemon_apply.go#L231) (`applyConfigLocked` reconciliation)
* **Detailed Trace:**
  1. The interface renaming loop (`enumerateAndRenameInterfaces` or the proposed `enumerateAndRenameMapped`) is structured to execute *only* at daemon startup or when leaving bootstrap mode. It does not run on subsequent configuration commits at runtime to prevent disruptive link-cycling.
  2. If an operator commits a device-map configuration change at runtime (e.g. mapping `fxp0` or a revenue port to a different PCI address), `applyConfigLocked` compiles the new configuration using the updated map. However, the physical kernel interfaces are **not** renamed at runtime.
  3. Consequently, the compiler uses the new names in its generated networkd configs, but no physical interfaces match them. The system might appear reachable temporarily if the old files persist, or the commit succeeds because it does not fail-fast at runtime.
  4. On the next reboot, the renaming loop finally runs and renames the physical interfaces to the new mappings. If the mappings were invalid (e.g., mapping `fxp0` to a missing or incorrect PCI address), the box becomes permanently unreachable.
  5. The operator cannot use the `commit confirmed` rollback to recover, because the commit was already successfully confirmed during the runtime session when it "worked."
* **Remediation:** Any change to the `chassis device-map` stanza must be treated as a non-dynamic configuration change. The commit path must either force a system reboot, or reject modifications to the device-map at runtime.

---

### [HIGH-RISK] Stale `.link` files cause systemd-networkd to ignore map updates
* **Severity:** HIGH
* **Files & Line Citations:**
  * [pkg/daemon/linksetup.go:269-291](file:///home/ps/git/bpfrx/pkg/daemon/linksetup.go#L269-L291) (`writeLinkFile`)
  * [pkg/networkd/networkd.go:133-145](file:///home/ps/git/bpfrx/pkg/networkd/networkd.go#L133-L145) (stale file cleanup)
* **Detailed Trace:**
  1. The daemon persists interface names across boots by writing systemd `.link` files (e.g., `/etc/systemd/network/10-xpf-ge-0-0-3.link`) matching on the physical NIC's `OriginalName`.
  2. If the operator updates the device-map to move a physical NIC to a different logical name (e.g., from `ge-0/0/3` to `ge-0/0/4`), `enumerateAndRenameMapped` writes `10-xpf-ge-0-0-4.link`.
  3. However, the old `10-xpf-ge-0-0-3.link` file is never deleted from `/etc/systemd/network`.
  4. Upon reboot, systemd-networkd processes both `.link` files. Since both match the same physical device, systemd-networkd applies the first one in alphabetical order.
  5. Because `10-xpf-ge-0-0-3` sorts before `10-xpf-ge-0-0-4`, the stale link file is applied, and the interface is renamed to `ge-0-0-3`, completely ignoring the new device-map configuration.
* **Remediation:** `enumerateAndRenameMapped` must scan `/etc/systemd/network/` for any `10-xpf-*.link` files that are not defined in the active configuration's device-map and delete them before writing the new link files and reloading networkctl.

---

### [HIGH-RISK] Silent PCI-MAC Mismatch / Slot-Hijacking
* **Severity:** HIGH
* **Files & Line Citations:**
  * [pkg/daemon/bootstrap.go:377-388](file:///home/ps/git/bpfrx/pkg/daemon/bootstrap.go#L377-L388) (`resolveLifelineCurrentName`)
* **Detailed Trace:**
  1. The plan proposes resolving identities sequentially: `pci` -> `mac` (permanent).
  2. If both `pci` and `mac` are defined in a device-map entry, and the card in that slot is replaced (or if a different card is plugged into the same slot during maintenance):
     * The engine checks PCI first. Since the new card occupies the configured PCI address, the engine matches it immediately, completely ignoring the MAC address mismatch.
     * The original card, now moved to a different slot, is left unmapped or mapped to the wrong port.
  3. This results in silent slot-hijacking, where physical ports are mapped to the wrong logical names (e.g., trust zone traffic routed to the untrust zone) without any validation warnings.
* **Remediation:** If both `pci` and `mac` are specified for an entry, the resolution engine must validate that the detected device's permanent MAC matches the configured MAC. If they mismatch, it must trigger a fatal check or warn and refuse to bind to prevent silent misrouting.

---

### [HIGH-RISK] Management Lockout via Mapping to Missing/Non-PCI devices
* **Severity:** HIGH
* **Files & Line Citations:**
  * [pkg/daemon/bootstrap.go:403-432](file:///home/ps/git/bpfrx/pkg/daemon/bootstrap.go#L403-L432) (`protectedInterfaces`)
* **Detailed Trace:**
  1. The plan suggests that if a map references a missing NIC, the `commit-check` only warns, and the logical name is left unbound.
  2. While warning is appropriate for revenue ports (e.g., to support shared configs across nodes with differing hardware), if the operator maps the *active management interface* (configured via `system management-interface`, or `fxp0` by default) to a missing PCI address, the commit will succeed.
  3. On the next reboot, the management interface will fail to bind, locking the operator out of the box entirely.
* **Remediation:** The schema/compiler validation must make it a **FATAL** commit error if the logical interface currently used for management (or identified in the lifeline record) is mapped to a non-existent or invalid PCI/MAC address.

---

### [MEDIUM-RISK] Empty-tree Non-nil Struct Activation Bug
* **Severity:** MEDIUM
* **Files & Line Citations:**
  * [pkg/config/compiler_system.go:879-885](file:///home/ps/git/bpfrx/pkg/config/compiler_system.go#L879-L885) (`compileChassis`)
* **Detailed Trace:**
  1. In the Go configuration compiler, empty blocks (e.g. `chassis { device-map { } }`) compile into non-nil pointer structs (i.e., `cfg.Chassis.DeviceMap != nil`) with empty slices.
  2. If the daemon checks `if cfg.Chassis.DeviceMap != nil` to activate device-map mode, an empty block will trigger it.
  3. Since the entries list is empty, the daemon will rename no interfaces. Under the default `leave-alone` policy, it will leave all interfaces unmanaged, silently disabling the firewall's dataplane while reporting a successful commit.
* **Remediation:** The daemon must explicitly check that `cfg.Chassis.DeviceMap != nil && len(cfg.Chassis.DeviceMap.Entries) > 0` to activate device-map mode.

---

### [MEDIUM-RISK] Missing FPC Slot Alignment Validation on Cluster Mode
* **Severity:** MEDIUM
* **Files & Line Citations:**
  * [pkg/config/types.go:55](file:///home/ps/git/bpfrx/pkg/config/types.go#L55) (`SlotToNodeID`)
  * [pkg/cluster/monitor.go:259](file:///home/ps/git/bpfrx/pkg/cluster/monitor.go#L259) (monitor alignment checks)
* **Detailed Trace:**
  1. The plan allows the operator to configure arbitrary logical names (e.g., `ge-7/0/3`) in the device-map.
  2. If an operator mistakenly maps a `ge-7/0/3` name on node 0 (where the FPC slot must be 0), the physical interface will be named `ge-7-0-3` in the kernel.
  3. When `RethToPhysical` or the cluster health monitors run, they verify if the interface FPC slot matches the local node-id (`SlotToNodeID(slot) == localNodeID`). Because FPC slot 7 maps to node 1, node 0 will assign it a score of 0, breaking RETH link membership resolution and health monitoring.
* **Remediation:** Add a compile-time check validating that for every device-map entry, `SlotToNodeID(InterfaceSlot(name)) == localNodeID`. Fail compilation if slot alignment is violated in cluster mode.
