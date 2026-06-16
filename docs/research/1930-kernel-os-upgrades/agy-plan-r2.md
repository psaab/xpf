# Adversarial Plan Review (Round 2): Major Kernel/OS Upgrades (#1930)

This document presents the Round 2 adversarial review of the major kernel/OS upgrades plan documented in [plan.md](file:///home/ps/git/bpfrx/.claude/worktrees/1930-research-kernel-os-upgrades/docs/research/1930-kernel-os-upgrades/plan.md). It evaluates the revised "v2" design against the original Round 1 hazards and examines new operational risks introduced by the updated mechanics.

---

## 1. Verdict & Summary

### Verdict: PLAN-NEEDS-WORK

### High-Level Justification
While the v2 plan makes significant structural improvements — notably dropping the high-risk `do-release-upgrade` path and moving HA orchestration out of the in-process `rolling.go` — the core safety mechanism of **Lane 1 (in-place kernel upgrades) remains fundamentally broken**. 

The proposed one-shot boot fallback logic (A1') is a logical impossibility under UEFI Secure Boot and ext4 `metadata_csum` constraints: it relies on a file-based candidate marker that neither GRUB nor a hung candidate kernel can clear, guaranteeing an infinite boot-loop on early boot hang. Additionally, the external HA orchestration and watchdog assertions introduce new unmitigated failure modes.

---

## 2. Verification of v1 Hazards in v2 Plan

### Hazard A: GRUB grubenv Boot-Loop (ext4 `metadata_csum` / UEFI Secure Boot)
* **The v1 Hazard:** GRUB cannot write back to `grubenv` at boot time under Secure Boot or ext4 `metadata_csum`, preventing it from clearing `next_entry`. A hung candidate kernel triggers a watchdog reboot, but GRUB reads the uncleared `next_entry` and boots the bad kernel again, leading to an infinite boot-loop.
* **The v2 Revision (A1'):** The default boot target is pinned to the stable known-good kernel. The candidate kernel is booted by setting a candidate marker in `grubenv` (written by Linux, which supports `metadata_csum`). The plan states: *"On a fallback (watchdog/clean reset to the known-good default), the known-good boot's early Linux unit clears the marker so a subsequent reboot does not re-enter the candidate."*
* **Adversarial Assessment: UNRESOLVED / FATAL.** 
  The proposed fix contains a fatal logic loop:
  1. The candidate marker is written to `/boot/grub/grubenv` by the running known-good OS.
  2. The node reboots.
  3. GRUB reads `/boot/grub/grubenv`, sees the candidate marker is set, and sets the boot target to the candidate kernel.
  4. GRUB cannot clear the marker in `grubenv` because write commands (`save_env`) are locked down under UEFI Secure Boot and the ext4 driver is read-only due to `metadata_csum`.
  5. The candidate kernel boots and **hangs early** (e.g., kernel panic, ACPI probe freeze, or initramfs mount failure) before Linux userspace starts.
  6. The hardware watchdog fires and resets the system.
  7. The system reboots into GRUB. GRUB reads `grubenv`. The candidate marker is **still set** (because neither GRUB nor the hung kernel could clear it).
  8. GRUB boots the hung candidate kernel **again**.
  9. The node is trapped in an infinite boot-loop.
  
  The claim that the "known-good boot's early Linux unit clears the marker on fallback" is invalid because **the known-good boot never occurs** on a watchdog reset if the candidate marker is still set.
* **Required Fix:** Drop the file-based candidate marker. Under Secure Boot and UEFI, one-shot boots *must* use the standard UEFI `BootNext` variable via `efibootmgr`. The UEFI firmware itself clears `BootNext` before booting it, ensuring that any subsequent hardware reset automatically falls back to `BootOrder` (the known-good default) without bootloader writes.

### Hazard B: HA Orchestration `rolling.go` Process Death
* **The v1 Hazard:** The upgrade runner (`rolling.go`) runs inside the local `xpfd` daemon. A reboot kills the process mid-upgrade, leaving the node permanently drained and causing a full cluster outage if the peer is blindly upgraded next.
* **The v2 Revision:** Moved HA orchestration to an external script [xpf-deploy.py](file:///home/ps/git/bpfrx/.claude/worktrees/1930-research-kernel-os-upgrades/scripts/deploy/xpf-deploy.py) that runs on a deployment host, coordinates node reboots, implements a cluster-wide lock, and verifies Node A rejoins as master/healthy before starting Node B.
* **Adversarial Assessment: PARTIALLY RESOLVED / GAPS REMAIN.** 
  Moving orchestration externally is correct, but introduces new failure modes:
  * **Orchestrator Disconnection / Crash:** If the operator's laptop running `xpf-deploy.py` loses connection, crashes, or is shut down while Node A is rebooting, Node A remains permanently drained (`ForceSecondary`). No local watchdog or timeout exists to clear the drained state if the orchestrator disappears.
  * **Cluster Lock Leak:** If the orchestrator crashes mid-run, the cluster-wide lock remains held indefinitely. The plan does not specify where the lock is stored or how stale locks are leased or manually broken.
  * **Version Check Gap:** The orchestrator polls Node A until "healthy + rejoined." If Node A failed to boot the new kernel and successfully fell back to the old kernel, the orchestrator might see a "healthy" node (running the old kernel) and proceed to upgrade Node B. The orchestrator must explicitly assert that the running kernel version on Node A matches the *target* version before proceeding.

### Hazard C: Watchdog Disarming on Clean Shutdown
* **The v1 Hazard:** Standard Linux watchdog drivers cleanly disarm the watchdog on shutdown, leaving the candidate's early boot unprotected.
* **The v2 Revision:** Requires a persistent hardware/firmware watchdog (`nowayout=1`) or initramfs early-arm.
* **Adversarial Assessment: PARTIALLY RESOLVED / WEAK SAFETY NET.**
  * **Initramfs hook is too late:** If the candidate kernel hangs prior to initramfs execution (e.g., during decompression, early CPU initialization, or ACPI setup), the initramfs hook never runs.
  * **Hardware warm-reset limitations:** Many motherboard/BMC watchdogs are physically reset or disabled when the CPU reset line is asserted during a warm reboot. Setting `nowayout=1` only prevents Linux userspace from closing `/dev/watchdog` to disarm it; it does not force the physical hardware timer to persist across system resets.
  * **Pre-assert impossibility:** There is no standard Linux API for the `xpfd` pre-assert to verify whether the hardware watchdog will actually survive a warm reboot on the host platform.
* **Required Fix:** Acknowledge that the "never brick" guarantee is hardware-dependent. If a persistent firmware/hypervisor watchdog is not present or cannot be verified, Lane 1 must fail-closed and force Lane 2 (image-replace).

### Hazard D: Mixed-State User-Space on Lane 3 (`do-release-upgrade`)
* **The v1 Hazard:** In-place `do-release-upgrade` can leave the node with N+1 user-space packages running on an old N kernel, which can break the `xpfd` daemon or verifier shim.
* **The v2 Revision:** Marked `do-release-upgrade` as completely unsupported and removed B2 from the design. Lane 3 is now image-replace (Lane 2) only.
* **Adversarial Assessment: RESOLVED.** 
  This is a highly disciplined scope decision that eliminates a major source of untestable brick paths.

### Hazard E: Kernel Package Accrual & Purging
* **The v1 Hazard:** Failed candidate kernels accumulate in `/boot`, leading to filesystem exhaustion.
* **The v2 Revision:** Added pre-assert capacity checks on `/boot` and implemented an automated `apt-get purge` in `gc()` for unpromoted candidate kernels.
* **Adversarial Assessment: RESOLVED.**
  The sequence safely manages `/boot` space before and after candidate execution.

---

## 3. Review of New v2 Features

### LANE 2 Mixed-Base HA Compatibility Gate
* **The v2 design:** Before replacing the image on the second HA node, the orchestrator introspects the new image's HA/session-sync protocol version and fails closed if it is not backward-compatible with the still-running peer.
* **Adversarial Assessment: GAPS IN SPECIFICATION.**
  The plan does not specify *how* the orchestrator (running on a deployment host or the peer node) extracts and inspects the HA protocol version of a non-running, baked image file before deploying it. If this depends on a metadata manifest or running a dummy container, it must be defined.

### Forward-Health-Beacon-Gated Promotion
* **The v2 design:** The promotion systemd unit requires the candidate kernel to pass both structural BPF verification (`xpfd verify-dataplane`) and a forward health beacon (sending/receiving a live traffic probe) before writing the promotion marker.
* **Adversarial Assessment: OPERATIONAL RISK / STANDALONE OUTAGE.**
  * **Standalone Reboot Gap:** For standalone nodes, booting into the candidate kernel suspends active forwarding. If the health beacon timeout is too long (e.g., 2 minutes), a candidate kernel that boots but fails to forward will cause a prolonged traffic outage before rolling back. The timeout budget must be tightly bounded.
  * **Beacon Stability:** The beacon must probe a highly stable destination (such as the HA peer link) rather than an external gateway, to prevent transient network issues from triggering spurious kernel rollbacks.

---

## 4. New Brick & Outage Paths Introduced by v2

1. **GRUB Submenu Pathing Failure:** 
   Ubuntu systems typically group secondary kernels under an "Advanced options" submenu in `grub.cfg`. If submenus are enabled, passing just the menuentry ID (e.g., `gnulinux-6.18.0-2-generic`) to `grub-reboot` will fail to select the entry, causing GRUB to boot the default kernel instead. The plan must mandate `GRUB_DISABLE_SUBMENU=y` in `/etc/default/grub.d/99-xpf.cfg` or construct the hierarchical boot path (e.g., `gnulinux-advanced-...>gnulinux-6.18.0-2-generic`).
2. **`apt-mark` Shell Expansion Failure:**
   The plan specifies running `apt-mark hold linux-*`. Because `apt-mark` does not perform wildcard pattern matching internally, the shell will try to expand `linux-*` against files in the current working directory, resulting in command failure or unheld packages. The command must use a subshell expansion:
   `apt-mark hold $(dpkg-query -W -f='${Package}\n' 'linux-*')`
3. **Secure Boot Lockout Loop:**
   If an unsigned candidate kernel is installed under Secure Boot, the UEFI firmware will block it and display a verification screen. Because GRUB cannot clear the candidate marker and the kernel never boots to do so, the node is stuck displaying the Secure Boot violation screen on every reboot, resulting in a manual intervention brick.

---

## 5. Actionable Recommendations for v3 Plan

1. **Implement UEFI `BootNext` for One-Shot Boot (A1'):** Replace the file-based candidate marker in `grubenv` with UEFI `BootNext`. Write `BootNext` via `efibootmgr` to point to the candidate kernel. Since the UEFI boot manager clears `BootNext` before booting, any watchdog reset will automatically fall back to the default `BootOrder` (known-good kernel) without requiring bootloader write support.
2. **Define Cluster Lock Storage and Lifespan:** Specify where the external orchestrator's cluster-wide lock is stored and how it recovers from an orchestrator crash (e.g., a short TTL on a lock entry).
3. **Mandate `GRUB_DISABLE_SUBMENU=y`:** Ensure `bake.py` configures GRUB to disable submenus so that candidate menuentry IDs are top-level and resolvable directly by name.
4. **Fix `apt-mark hold` Syntax:** Update the plan to use a concrete package-query command rather than a wildcard glob.
5. **Tighten Version Checks in HA Orchestration:** Force the orchestrator to check `uname -r` or `xpfd version` on Node A to ensure it actually successfully booted and promoted the *new* kernel before proceeding to Node B.
