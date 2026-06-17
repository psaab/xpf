# Hostile Plan Review (Round 3) — Bare-Metal Interface Device-Map Plan (#1956)

**Verdict:** `PLAN-NEEDS-MAJOR`

While the v3 updates to the device-map plan ([plan.md](file:///home/ps/git/bpfrx/.claude/worktrees/1956-research/docs/research/1956-bare-metal-device-map/plan.md)) successfully resolve several concerns from Round 2 (such as structural validation of key-ordering and ordering the teardown hook prior to systemd-networkd Apply), a deep adversarial analysis of the proposed mechanics against the actual codebase reveals new second-order critical security, rollback split-brain, and interface-renaming deadlock hazards.

---

## Severity-Tagged Findings

### 1. [CRITICAL-HAZARD] V-1 SyncApply "Delta Refusal" Creates Permanent Config Divergence & Silent Overwrite Loops
* **Severity:** CRITICAL
* **Files & Line Citations:**
  * [SyncApply in pkg/configstore/store.go#L531-L619](file:///home/ps/git/bpfrx/pkg/configstore/store.go#L531-L619) (SyncApply transaction flow)
  * [handleConfigSync in pkg/daemon/daemon_ha_sync.go#L347-L373](file:///home/ps/git/bpfrx/pkg/daemon/daemon_ha_sync.go#L347-L373) (HA config sync consumer)
* **Detailed Trace:**
  1. The operator commits a configuration on Node 0 (primary) that contains an incorrect device-map mapping for Node 1 (standby).
  2. Because Node 0 only runs strict local validation at commit time, the commit succeeds on Node 0 and is synced to Node 1.
  3. Node 1 receives the config via `handleConfigSync` and calls `syncAndApply` which invokes `SyncApply`.
  4. The proposed V-1 resolution states that the passive node's admission gate will "refuse the sync for the device-map delta". 
  5. If Node 1 implements this by modifying/stripping the `device-map` section of the incoming tree while saving the rest:
     - Node 0 and Node 1 now run with **diverged active configurations** in their respective `active.json` stores.
     - When Node 1 fails over to become active and the operator commits *any* subsequent configuration change (e.g. editing a firewall policy), Node 1 will push its active configuration (which lacks/reverts the device-map change) back to Node 0.
     - Node 0 will accept the sync, **silently rolling back Node 0's device-map configuration** to the old state and potentially causing a remote lockout or traffic drop on Node 0.
  6. If Node 1 instead implements this by rejecting the *entire* sync transaction:
     - The sync fails with an error returned to `handleConfigSync`. 
     - Because config sync is a push-and-forget transaction, Node 1 remains on the old configuration, while Node 0 remains on the new one.
     - Any subsequent commits on Node 0 (e.g., updating security rules or adding VLANs) will continue to fail config sync to Node 1 because the synced config text still contains the invalid device-map entry for Node 1.
     - This reintroduces the exact **HA-sync stall/lockup** that `compileTreeLenient` was introduced to prevent.
* **Remediation:** 
  - To prevent config divergence, the validation must be run *before* the commit succeeds on Node 0. Implement a distributed pre-commit validation check: during `commit check` on the active node, the active node must query the passive node (via the cluster control channel) to validate its device-map against local hardware.
  - If a passive-node check is the only option, the passive node must reject the entire sync transaction (stalling sync and raising an alarm) to prevent silent configuration overwrite loops, rather than partially modifying the configuration text.

---

### 2. [HIGH-RISK] V-3 Confirmed Rollback "Conservative Path" Causes Persistent Store-vs-Kernel Split-Brain
* **Severity:** HIGH
* **Files & Line Citations:**
  * [executeConfirmedRollback in pkg/daemon/daemon_apply.go#L222-L251](file:///home/ps/git/bpfrx/pkg/daemon/daemon_apply.go#L222-L251) (confirmed rollback timeout handler)
  * [PromoteRollback in pkg/configstore/store.go#L1320-L1389](file:///home/ps/git/bpfrx/pkg/configstore/store.go#L1320-L1389) (rollback store state promotion)
* **Detailed Trace:**
  1. An operator commits a new candidate configuration with `commit confirmed`. The confirmed commit timer is armed.
  2. The operator loses connectivity (or fails to confirm), and the confirm timer expires, invoking `executeConfirmedRollback`.
  3. `executeConfirmedRollback` calls `d.store.PromoteRollback(gen)`, which atomically updates the store database state (`s.active = s.confirmPrevTree`) to the old config.
  4. Under V-3(b), if applying the rollback target would transition from device-map to positional-claim-all and down a currently-up NIC, the daemon logs loudly and "takes the conservative path rather than blindly applying" (i.e., it returns early without calling `applyConfigLocked`).
  5. Because the store database has already been promoted to the old config in step 3, but the dataplane apply was skipped in step 4, the **database state and the kernel/dataplane state are permanently diverged**.
  6. The unconfirmed candidate configuration remains active in the dataplane, exposing the system to security or operational hazards, while any subsequent configuration edit by the operator will compile against the old database state but apply on top of the candidate's kernel state, causing unpredictable routing and connectivity behavior.
* **Remediation:** 
  - Do not defer safety checks to the timeout path. The active config and the rollback target must be validated *prior* to arming the confirm timer (during the initial `commit confirmed` pre-flight check). If the rollback target is invalid or would down a NIC, the `commit confirmed` command must be rejected at the CLI.
  - Once a confirmed commit starts, the timeout rollback must apply the rollback target config unconditionally in the dataplane to prevent split-brain.

---

### 3. [HIGH-RISK] V-2 Startup Temp-Rename Algorithm Strands and Mis-renames Unmapped/Leave-Alone Interfaces
* **Severity:** HIGH
* **Files & Line Citations:**
  * [plan.md#L557-L570](file:///home/ps/git/bpfrx/.claude/worktrees/1956-research/docs/research/1956-bare-metal-device-map/plan.md#L557-L570) (V-2 Resolution)
  * [Apply in pkg/networkd/networkd.go#L94-L214](file:///home/ps/git/bpfrx/pkg/networkd/networkd.go#L94-L214) (networkd file sweep and apply)
* **Detailed Trace:**
  1. Suppose in a previous boot, NIC-C was managed by `xpfd` and named `ge-0/0/3`.
  2. In the new config, the operator deletes the mapping for NIC-C (it is now unmanaged/leave-alone), and maps NIC-A (previously named `enp3s0`) to `ge-0/0/3`.
  3. Upon reboot, the stale `.link` file for NIC-C names it `ge-0/0/3`.
  4. The daemon starts and runs `enumerateAndRenameMapped`:
     - It detects that NIC-C is named `ge-0/0/3`, which is desired by NIC-A.
     - It renames NIC-C to `xpf-tmp-0` to break the collision.
     - It renames NIC-A to `ge-0/0/3`.
     - It writes new `.link` files (only for NIC-A, none for NIC-C because it is unmanaged).
  5. The teardown hook (V-4) runs next:
     - It reads the stale/previously-managed record to rename the old device (`ge-0/0/3`) back to its predictable name.
     - It looks for the device named `ge-0/0/3` and finds **NIC-A** (which was just renamed to `ge-0/0/3` in step 4).
     - It renames **NIC-A** back to its predictable name (`enp3s0`), breaking its new mapping.
     - Meanwhile, NIC-C remains stranded as `xpf-tmp-0` and never gets renamed back to its predictable name.
* **Remediation:** 
  - The multi-pass rename sequence must track the identities (MAC/PCI) of all interfaces it moves to temporary names.
  - If a temporary-renamed interface is not mapped to a new name in the desired config, the daemon must rename it back to its host-predictable name directly inside the rename sequence, rather than relying on the teardown hook.

---

### 4. [MEDIUM-RISK] V-6 Direct Parsing of `/run/udev/data/` is Fragile
* **Severity:** MEDIUM
* **Files & Line Citations:**
  * [plan.md#L626-L630](file:///home/ps/git/bpfrx/.claude/worktrees/1956-research/docs/research/1956-bare-metal-device-map/plan.md#L626-L630) (V-6 Predictable Name Discovery)
* **Detailed Trace:**
  1. The plan specifies discovering the host's predictable name by reading the udev database under `/run/udev/data/`.
  2. Reading `/run/udev/data/` files directly bypasses public APIs and couples `xpfd` directly to internal systemd/udev storage layouts and file formats, which are subject to breaking changes between systemd versions.
* **Remediation:** 
  - Query the predictable name using the public, stable `udevadm info --query=property -p /sys/class/net/<name>` CLI or equivalent libudev bindings, rather than parsing `/run/udev/data/` files directly.
