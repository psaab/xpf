# Hostile Plan Review (Round 2) — Bare-Metal Interface Device-Map Plan (#1956)

**Verdict:** `PLAN-NEEDS-MAJOR`

While the v2 updates to the device-map plan (`plan.md`) make a commendable effort to address the deferred reboot lockout (via R-8 commit pre-flight), stale `.link` conflict (via R-2), and other round-1 findings, a deep adversarial review of the proposed system mechanics against the actual codebase reveals several critical security, HA configuration, and operational failure modes that still remain unaddressed.

---

## Severity-Tagged Findings

### 1. [CRITICAL-HAZARD] Peer Node / Standby Lockout Hazard during Config Sync
* **Severity:** CRITICAL
* **Files & Line Citations:**
  * [pkg/configstore/store.go#L446-L454](file:///home/ps/git/bpfrx/pkg/configstore/store.go#L446-L454) (`compileTreeStrict` check path)
  * [pkg/configstore/store.go#L475-L496](file:///home/ps/git/bpfrx/pkg/configstore/store.go#L475-L496) (`compileTreeLenient` active sync path)
  * [docs/research/1956-bare-metal-device-map/plan.md#L475-L486](file:///home/ps/git/bpfrx/docs/research/1956-bare-metal-device-map/plan.md#L475-L486) (v2 R-8 Resolution)
* **Detailed Trace:**
  1. Under HA configuration synchronization, a single configuration commit made on the primary node (Node 0) compiles per-node settings (using `CompileConfigForNode`) for both nodes.
  2. The proposed R-8 commit-time pre-flight check runs inside the compiler check path (`compileTreeStrict`) and resolves mappings against *currently-present NICs* (querying local sysfs/netlink/PCI buses).
  3. Consequently, the primary node (Node 0) has access *only* to its own local hardware. It cannot query Node 1's physical NICs. To allow commits on Node 0 to succeed, the compiler cannot make missing NICs fatal across the entire config; it can only warn about Node 1's absent hardware.
  4. Once Node 0 commits, config-sync pushes the config to Node 1, which executes `SyncApply`. Because `SyncApply` uses `compileTreeLenient` to prevent HA sync lockups/loops, it does not strictly enforce commit-time checks and will persist the invalid device-map onto Node 1's disk.
  5. On the next reboot of Node 1, it will apply the incorrect device-map mappings, resulting in a deferred reboot lockout on the peer/standby node, completely outside the protection of Node 0's active `commit confirmed` rollback window.
* **Remediation:** The pre-flight validator must be node-aware: only validate the local node's device-map section against local hardware on the active node. During passive HA config-sync (`SyncApply`), if a node detects that its *own* local section of the device-map would cause a management lockout on reboot, it must safely reject the sync or immediately force an automatic fallback/recovery action rather than silently persisting the hazard.

---

### 2. [HIGH-RISK] Rollback-to-Positional / Deletion Bypass of Pre-Flight Check
* **Severity:** HIGH
* **Files & Line Citations:**
  * [docs/research/1956-bare-metal-device-map/plan.md#L475-L486](file:///home/ps/git/bpfrx/docs/research/1956-bare-metal-device-map/plan.md#L475-L486) (v2 R-8 Resolution)
  * [docs/research/1956-bare-metal-device-map/plan.md#L487-L496](file:///home/ps/git/bpfrx/docs/research/1956-bare-metal-device-map/plan.md#L487-L496) (v2 R-9 Resolution)
* **Detailed Trace:**
  1. R-9 specifies that deleting or rolling back past the device-map reverts the system to positional `manage-down` (claim-all) behavior.
  2. If an operator deletes the device-map stanza or rolls back to a candidate config prior to the device-map, the R-8 pre-flight check has no device-map entries to resolve against the present NICs.
  3. Because the pre-flight check finds no proposed map, it succeeds without errors.
  4. However, on the next reboot, the positional naming logic (`enumerateAndRenameInterfaces`) will run. Since the physical NIC order may have shifted, physical ports will silently swap names (e.g. physical NIC B instead of NIC A becomes `ge-0/0/3`), mismatching configured zones.
  5. Furthermore, the compiler's reconcile path will run immediately at commit time, marking all previously "left alone" unmanaged interfaces (e.g., host mgmt or cluster interfaces) as `Unmanaged: true`, immediately bringing them down and stripping their IP addresses.
* **Remediation:** The R-8 pre-flight validator must also run when transitioning from device-map mode to positional mode (e.g. when the map is deleted). It must simulate the positional rename mapping against the actual hardware, compare it to the active device-map, and raise a warning/error if a configured revenue/management interface is about to be re-bound to a different physical port or if a currently active/configured interface is about to be brought down by the claim-all policy.

---

### 3. [HIGH-RISK] One-Boot `udev`-before-daemon Window on Offline Changes/Rollbacks
* **Severity:** HIGH
* **Files & Line Citations:**
  * [docs/research/1956-bare-metal-device-map/plan.md#L399-L408](file:///home/ps/git/bpfrx/docs/research/1956-bare-metal-device-map/plan.md#L399-L408) (v2 R-2 Resolution)
  * [pkg/daemon/daemon_run.go#L344-L360](file:///home/ps/git/bpfrx/pkg/daemon/daemon_run.go#L344-L360) (startup rename branch)
* **Detailed Trace:**
  1. udev applies systemd `.link` files (e.g. `/etc/systemd/network/10-xpf-*.link`) at early boot during kernel device discovery, long before `xpfd` starts.
  2. If the operator performs an offline recovery action, restores an older backup, or executes a grub-level rollback to an older configuration that has a different device-map, the `xpfd` daemon is not running to clean up the `.link` files on disk.
  3. Upon reboot, udev will process the stale `.link` files left behind in `/etc/systemd/network/`, renaming interface A to `ge-0-0-3` (the old mapping).
  4. When `xpfd` finally starts, it reads the new config which maps interface B to `ge-0-0-3` and interface A to `ge-0-0-4`.
  5. The daemon will attempt to rename the devices using netlink, but trying to rename B to `ge-0-0-3` will fail with `EEXIST` because the name is already claimed by A. This breaks the boot-up rename process and results in a lockout.
* **Remediation:** If the daemon encounters an `EEXIST` error during interface renaming at startup, it must not fail silently or abort. It must implement a multi-pass renaming strategy (e.g. rename conflicting interfaces to temporary placeholder names like `tmp-ge-0-0-3` first) to break the naming circular deadlock before applying the final mappings.

---

### 4. [MEDIUM-RISK] Underspecified "Predictable Name" Teardown in R-5
* **Severity:** MEDIUM
* **Files & Line Citations:**
  * [docs/research/1956-bare-metal-device-map/plan.md#L432-L444](file:///home/ps/git/bpfrx/docs/research/1956-bare-metal-device-map/plan.md#L432-L444) (v2 R-5 Resolution)
  * [pkg/networkd/networkd.go#L133-L145](file:///home/ps/git/bpfrx/pkg/networkd/networkd.go#L133-L145) (stale file sweep)
* **Detailed Trace:**
  1. R-5 specifies that when an interface transitions to `leave-alone`, the daemon must perform a teardown, including "rename the kernel device back to a stable predictable name".
  2. Predictable interface names (e.g. `enp3s0`, `eno1`) are dynamically generated by udev based on hardware properties and the host system's specific systemd configuration policies.
  3. The plan does not describe how the daemon will discover this name. If `xpfd` tries to calculate it manually, it is highly likely to miscalculate on hosts with custom udev rule overrides or non-standard kernels, causing conflicts. If it relies on triggering a asynchronous udev event (e.g. `udevadm trigger`), it introduces a race condition with systemd-networkd.
* **Remediation:** Define the exact mechanism for discovering the host OS's predictable name (e.g., querying the udev database `/run/udev/data/` or using `udevadm info` properties like `ID_NET_NAME_PATH` or `ID_NET_NAME_ONBOARD`) instead of hardcoding a generic pattern or guessing.

---

### 5. [MEDIUM-RISK] Missing General FPC Slot Node-ID Alignment Validation
* **Severity:** MEDIUM
* **Files & Line Citations:**
  * [docs/research/1956-bare-metal-device-map/plan.md#L445-L452](file:///home/ps/git/bpfrx/docs/research/1956-bare-metal-device-map/plan.md#L445-L452) (v2 R-6 Resolution)
  * [docs/research/1956-bare-metal-device-map/plan.md#L226-L233](file:///home/ps/git/bpfrx/docs/research/1956-bare-metal-device-map/plan.md#L226-L233) (§6.6)
* **Detailed Trace:**
  1. The validator described in §6.6 and R-6 only rejects FPC slot mismatches (e.g., FPC slot 7 on Node 0) for *reth members*.
  2. If an operator configures a regular interface (e.g. a standalone revenue interface or a fabric member) to an incorrect FPC name (e.g., mapping a physical NIC to `ge-7/0/3` on Node 0), the validation will pass.
  3. The interface will be renamed to `ge-7-0-3` on Node 0. This violates cluster FPC slot alignment conventions, causing internal monitors and routing domain logic to assume it belongs to Node 1, leading to silent packet drops and HA monitor failures.
* **Remediation:** Generalize the FPC validator: in cluster mode, validate that *every* logical interface name mapped in the device-map has an FPC slot that aligns with the target Node ID, not just reth members.
