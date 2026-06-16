# #1930 Kernel/OS Upgrades — Round 4 Hostile Plan Review

## 1. Executive Summary & Verdict

### Verdict: `PLAN-NEEDS-WORK`

The v4 revision makes substantial progress by unifying the boot substrate under **Path Option A4** (fixed A/B UEFI slots, shim-staged, `BootNext`-selected). This resolves all primary hazards identified in Round 3 (including the GRUB `grubenv` read contradiction, Secure Boot write lockdowns, and bare-kernel signature failures).

However, A4 introduces a **fatal technical blocker** regarding how signed GRUB binaries resolve configuration files under Secure Boot, a physical impossibility regarding NVRAM registration during offline image baking, and an internal contradiction in kernel staging locations. These issues must be addressed before the plan can be considered ready for implementation.

---

## 2. Verification of Round 3 Hazard Resolutions

The proposed **A4** substrate successfully addresses the hazards identified in Round 3:

*   **Hazard A (GRUB can't read `BootNext`): Resolved.** Under A4, the UEFI firmware uses `BootNext` to select the slot entry (`xpf-A` or `xpf-B`). GRUB does not need to read `BootNext` at runtime because the boot path itself selects the slot-specific environment.
*   **Hazard B (Secure-Boot GRUB lockdown blocks `save_env`): Resolved.** A4 performs no environment block writes at boot time. The one-shot state is managed entirely via the firmware-cleared `BootNext` variable.
*   **Hazard C (Bare-`vmlinuz` fails Secure Boot signature): Resolved.** The boot entry executes `shimx64.efi` -> `grubx64.efi` -> kernel. The signed shim correctly verifies the kernel signature using the MOK database.
*   **Risk 1 (BootOrder corruption): Resolved.** §3.1 and §5 INC-1 specify that promotion must be a non-destructive edit that reads the current `BootOrder` and inserts the candidate at the front, preserving platform entries (PXE, recovery).
*   **Risk 2 (NVRAM wear): Resolved.** The A/B slots are permanently registered during bootstrap, avoiding NVRAM fragmentation and write-limit errors from dynamic entry creation.

---

## 3. Consistency and Phrasing Audit

A4 is threaded consistently through almost all sections. There is one minor residual framing in §2 (Grounding):
*   **Line 91 ([plan.md:91](file:///home/ps/git/bpfrx/.claude/worktrees/1930-research-kernel-os-upgrades/docs/research/1930-kernel-os-upgrades/plan.md#L91)):** Mentions *"the UEFI `BootNext` per-kernel boot entries"*. Under A4, these are permanently registered A/B slots, not per-kernel entries. This should be rephrased to *"the UEFI `BootNext` A/B slot entries"*.

---

## 4. Deep Dive: New Flaws in A4

### Flaw 1: The Signed GRUB Prefix/Lockdown Gotcha (Fatal Blocker)
*   **The Assumption:** The plan assumes that copying `shimx64.efi` and `grubx64.efi` to `/EFI/xpf-A/` and `/EFI/xpf-B/` on the ESP allows them to load a slot-private `grub.cfg` located in the same directory.
*   **The Reality:** The official Canonical-signed `grubx64.efi` binary used for Secure Boot contains a hardcoded prefix (typically `/EFI/ubuntu` or a UUID-based search block) embedded and cryptographically signed within the binary. When executed from `/EFI/xpf-A/grubx64.efi`, it will ignore any `grub.cfg` in `/EFI/xpf-A/` and instead search for the `/boot` partition UUID to load `/boot/grub/grub.cfg` (or fall back to `/EFI/ubuntu/grub.cfg`).
*   **Consequence:** Both slots will load the *exact same* configuration file from `/boot/grub/grub.cfg`, breaking the configuration isolation and booting the same kernel.
*   **Mitigation:** Rather than relying on separate ESP configuration files that signed GRUB will ignore, the shared `/boot/grub/grub.cfg` must dynamically branch based on the folder from which GRUB was executed. GRUB sets the `$cmdpath` variable to the directory of the running binary. The main `/boot/grub/grub.cfg` can inspect `$cmdpath` (e.g., if it contains `xpf-B`, boot the candidate; if `xpf-A`, boot the active kernel).

### Flaw 2: Offline Bake NVRAM Registration (Logical Impossibility)
*   **The Claim:** §5 INC-0 states that `bake.py` *"registers the two FIXED A/B UEFI slots (`xpf-A`/`xpf-B`)..."*.
*   **The Reality:** `bake.py` runs offline using `virt-customize` on a disk image. UEFI NVRAM variables (configured via `efibootmgr`) live on the host motherboard's NVRAM, not on the disk image. Running `efibootmgr` inside `virt-customize` will fail due to the lack of `/sys/firmware/efi/efivars` in the chroot, and even if it succeeded, it would write to the build host's NVRAM, not the target hardware.
*   **Consequence:** Deployed appliances will boot with empty NVRAM state and will not have the `xpf-A`/`xpf-B` boot options registered.
*   **Mitigation:** `bake.py` should only stage the files on the ESP (under `/EFI/xpf-A/` and `/EFI/xpf-B/`). The actual NVRAM registration and `BootOrder` initialization must be deferred to a systemd bootstrap service (e.g. `xpf-day0-config`) running on the actual running hardware during first boot.

### Flaw 3: Kernel Staging Contradiction & ESP Space Exhaustion
*   **The Contradiction:** §3.1 states: *"The kernel images themselves live in `/boot`, not the ESP — only shim/grub/`grub.cfg` are staged per slot."* However, §5 INC-1 states: *"stage the candidate kernel + a slot-private `grub.cfg` into the INACTIVE slot's ESP dir"*.
*   **Consequence:** If the kernel and initramfs (often totaling 50–80 MB) are copied into the ESP, it risks exhausting the space on small ESP partitions (which are frequently restricted to 100 MB or less).
*   **Mitigation:** Confirm that kernels are *never* copied to the ESP. The candidate kernel must remain in `/boot`, and only the references (or `$cmdpath`-based branch configuration) should be updated.

### Flaw 4: Single Point of Failure (Shared `/boot` Partition)
*   **The Vulnerability:** Because both slots load their kernels and initrd files from the same `/boot` partition (ext4), this design does not achieve true OS-level A/B isolation. 
*   **Consequence:** A filesystem corruption on `/boot`, or a space exhaustion event during `apt install`, will break BOTH the active and candidate kernels. If both kernels are unbootable, the firmware will boot-loop on the default `BootOrder` entry (slot A).
*   **Mitigation:** The plan must explicitly document this limit. The A/B isolation is only a boot-selection and boot-loop recovery channel, not a full disk-level failover.

---

## 5. Required Action Items to Achieve PLAN-READY

To transition the plan to `PLAN-READY`, the following changes must be made:

1.  **Correct the GRUB prefix execution path:** Clarify how the Canonical-signed `grubx64.efi` will load the correct configuration. Detail the use of the `$cmdpath` variable inside the shared `/boot/grub/grub.cfg` to detect and branch boot targets based on whether the active or inactive slot launched the bootloader.
2.  **Move NVRAM registration to first boot:** Remove UEFI NVRAM registration from the offline `bake.py` phase (INC-0) and move it to an in-guest first-boot service (e.g. `xpf-day0-config`).
3.  **Resolve the kernel staging contradiction:** Correct the phrasing in §5 INC-1 to ensure candidate kernels are never staged to the ESP.
4.  **Rephrase the residual glob reference:** Fix the phrasing on line 91 to refer to "A/B slot entries" instead of "per-kernel boot entries".
