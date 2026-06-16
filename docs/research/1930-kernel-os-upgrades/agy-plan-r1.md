# Adversarial Plan Review: Major Kernel/OS Upgrades (#1930)

This review pressure-tests the proposed 3-lane kernel/OS upgrade design for the `xpf` firewall appliance documented in [plan.md](file:///home/ps/git/bpfrx/.claude/worktrees/1930-research-kernel-os-upgrades/docs/research/1930-kernel-os-upgrades/plan.md).

---

## 1. Factual Verification against Codebase Grounding

We verified the plan's assertions against the active codebase on the `research/1930-kernel-os-upgrades` branch:

1. **`scripts/image/bake.py`**:
   - **Asserts newest kernel $\ge$ 6.18**: Verified in [bake.py:L211-214](file:///home/ps/git/bpfrx/.claude/worktrees/1930-research-kernel-os-upgrades/scripts/image/bake.py#L211-214).
   - **Asserts `linux-modules-extra` (mlx5/i40e)**: Verified in [bake.py:L216-217](file:///home/ps/git/bpfrx/.claude/worktrees/1930-research-kernel-os-upgrades/scripts/image/bake.py#L216-217) (checks Mellanox driver path).
   - **Purges all-but-newest & asserts exactly one kernel**: Verified in [bake.py:L232-239](file:///home/ps/git/bpfrx/.claude/worktrees/1930-research-kernel-os-upgrades/scripts/image/bake.py#L232-239).
   - **GRUB drop-in setup**: Verified in [bake.py:L264](file:///home/ps/git/bpfrx/.claude/worktrees/1930-research-kernel-os-upgrades/scripts/image/bake.py#L264) (writes `init_on_alloc=0` to `/etc/default/grub.d/99-xpf.cfg`).
   - **No `apt-mark hold` or `GRUB_DEFAULT=saved` on master**: Verified; they are currently absent from `bake.py`.

2. **`pkg/dataplane/verify_userspace_shim.go`**:
   - **Verifier load and exit code contract**: Verified in [verify_userspace_shim.go:L54-128](file:///home/ps/git/bpfrx/.claude/worktrees/1930-research-kernel-os-upgrades/pkg/dataplane/verify_userspace_shim.go#L54-128). It loads the spec anonymously, verifies against the running kernel, and returns `ErrUserspaceShimVerifierReject` on verifier error.

3. **`pkg/upgrade/`**:
   - **Upgrade runner state machine**: Verified in [runner.go](file:///home/ps/git/bpfrx/.claude/worktrees/1930-research-kernel-os-upgrades/pkg/upgrade/runner.go) and [cutover.go](file:///home/ps/git/bpfrx/.claude/worktrees/1930-research-kernel-os-upgrades/pkg/upgrade/cutover.go).
   - **HA rolling logic**: Verified in [rolling.go](file:///home/ps/git/bpfrx/.claude/worktrees/1930-research-kernel-os-upgrades/pkg/upgrade/rolling.go).

4. **`docs/in-place-upgrade.md`**:
   - **Deferred kernel/OS updates**: Verified in [in-place-upgrade.md:L169-170](file:///home/ps/git/bpfrx/.claude/worktrees/1930-research-kernel-os-upgrades/docs/in-place-upgrade.md#L169-170).

---

## 2. Hard Bricking Hazards & Operational Risks

### Hazard A: The GRUB Environment Write Failure (UEFI Secure Boot + ext4 `metadata_csum`)
The core safety mechanism of Lane 1 relies on `grub-reboot` executing a *one-shot* boot of the candidate kernel. If the candidate boot hangs, the hardware watchdog resets the box, and GRUB falls back to booting the old default kernel because the one-shot flag is cleared.
* **The UEFI Secure Boot Block**: Under UEFI Secure Boot, GRUB's environment modification capability is locked down for security. Commands like `save_env` and any automatic write-back to `/boot/grub/grubenv` are compiled out or disabled.
* **The ext4 Metadata Checksum Block**: Modern Linux distributions format ext4 with `metadata_csum` enabled by default. GRUB's ext2/3/4 filesystem driver does not support writing metadata checksums; thus, GRUB mounts the filesystem read-only for writes. Any attempt by GRUB to clear `next_entry` or modify `grubenv` at boot time fails.
* **Impact**: If the candidate kernel hangs or panics early, the watchdog will reset the machine. However, because GRUB was unable to clear the one-shot boot variable in `grubenv`, it will **repeatedly boot the failing candidate kernel**, trapping the device in an infinite boot-loop.

### Hazard B: The HA Orchestration Reboot Hole
The plan proposes using the existing `rolling.go` (`drain` $\rightarrow$ `act` $\rightarrow$ `restore`) to orchestrate HA upgrades.
* **Process Termination**: `RunRolling` runs as a local Go process on the node being upgraded. For service upgrades (in-place), this works because the service restart is fast and managed. However, for a kernel upgrade, the entire node must `reboot`.
* **The Orphaned Upgrade State**: The moment the node executes `reboot`, the local `xpfd` / CLI process running `RunRolling` is terminated. The state machine is cut short at Step 5. It will never execute Step 6 (wait for sync) or Step 7 (`ResetFailover`).
* **Cluster Outage risk**: The upgraded node boots, but remains in the `ForceSecondary` (drained) state because nothing called `ResetFailover` to rejoin. If the external deploy driver blindly commands Node B to upgrade next without verifying Node A has fully promoted, rejoined, and assumed MASTER, both nodes will be down, creating a total cluster outage.

### Hazard C: Watchdog Disarming on Clean Shutdown
* **Clean Shutdown Disarm**: When `xpfd upgrade kernel` triggers a reboot, the system goes through a standard systemd shutdown. During this shutdown, the kernel shuts down drivers cleanly. Standard Linux watchdog drivers disarm the hardware watchdog on driver shutdown/unload.
* **Impact**: During the warm reset, the hardware watchdog is NOT running. If the candidate kernel hangs extremely early (e.g., decompression, initial ACPI probe, initramfs load), there is no active watchdog to reboot the box. The appliance remains permanently bricked until manual/operator power-cycling.

### Hazard D: Mixed-State User-Space on Lane 3 (`do-release-upgrade`) Failure
* **Irreversible User-space Upgrades**: Running `do-release-upgrade` modifies the entire user-space filesystem in-place (upgrading `libc`, `systemd`, and the `xpfd` binary).
* **Impact**: If the subsequent candidate kernel fails verification, the boot-loader reverts to the old kernel. However, the system is now running the new N+1 user-space on top of the old N kernel. This untested combination is a major operational risk; the new `xpfd` binary or its verifier shim might fail to load on the old kernel, degrading the box to config-only mode with no automated path to restore the user-space packages.

### Hazard E: Kernel Package Accrual & Purging
* **Pruning Deficit**: Installing new kernels via `apt` places packages in `/boot`. If the candidate fails verification and rolls back, the failed kernel package remains installed. The plan notes "/boot is small — prune is mandatory" but provides no automated mechanism in `pkg/upgrade` or `gc()` to prune failed kernel packages from `dpkg`.

---

## 3. Recommended Design Adjustments

1. **Boot Counting via EFI Variables / ESP Partition**:
   - To bypass the GRUB write limitations under Secure Boot and ext4 checksums, migrate to a boot counting mechanism that writes to the FAT32 EFI System Partition (ESP), or leverages systemd-boot's native boot counting (which uses EFI variables that are writable under Secure Boot).

2. **External Orchestration of HA Reboots**:
   - Do not rely on the local node's `rolling.go` process surviving the reboot. The external deploy driver (`xpf-deploy.py`) must drive the sequence: drain Node A $\rightarrow$ trigger Node A reboot/upgrade $\rightarrow$ poll Node A until online $\rightarrow$ verify Node A health $\rightarrow$ promote Node A $\rightarrow$ proceed to Node B.

3. **Verify Watchdog `nowayout` / Hardware Persistence**:
   - The hardware watchdog must be configured with `nowayout=1`, and the platform must be validated to ensure the watchdog remains armed during a warm reset.

4. **Disable In-place OS Upgrades (Lane 3 B2)**:
   - Mark `do-release-upgrade` (Path B2) as **EXPLICITLY UNSUPPORTED** or deprecated. Force Lane 3 upgrades to use image-replace (Path B1) exclusively to avoid mixed user-space/kernel state bricks.

5. **Pruning Hook in GC**:
   - Extend the `gc()` logic to invoke `apt-get purge` for unpromoted candidate kernels.
