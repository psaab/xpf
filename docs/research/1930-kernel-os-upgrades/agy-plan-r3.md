# #1930 Kernel/OS Upgrades — Round 3 Final Convergence Review

## 1. Executive Summary & Verdict

### Verdict: `PLAN-NEEDS-WORK`

While v3 successfully addresses and reframes the Round 2 findings (including watchdog persistence, orchestrator fail-safe states, offline mixed-base gates, and state-carry text contracts), the newly introduced **UEFI `BootNext` + per-kernel UEFI entry** mechanism contains a critical logical contradiction, an unviable Secure Boot fallback assumption, and lacks concrete implementation details regarding bootloader execution and boot order promotion safety. These must be resolved before proceeding to implementation.

---

## 2. Deep Dive: UEFI `BootNext` & Bootloader Interaction

The core improvement in v3 is the pivot to **UEFI `BootNext`** to close the pre-Linux early-boot hang loop. While the UEFI firmware's behavior of clearing `BootNext` *before* execution is handed to the target entry is standard and correct, the integration of this mechanism with the existing GRUB/Shim bootloader has several flaws:

### Hazard A: The BootNext / GRUB Read Contradiction
*   **The Claim:** The plan suggests that if a single-shim/GRUB topology is kept, the selection of the candidate can be done *"via a GRUB id that GRUB reads from a one-shot it does NOT have to clear, because the firmware already cleared `BootNext`"*.
*   **The Flaw:** By definition, the UEFI boot manager deletes the `BootNext` variable *prior* to launching the EFI binary. Once GRUB is executing, `BootNext` is already gone from NVRAM. GRUB cannot read `BootNext` to determine whether it was booted as a one-shot candidate or as a normal default boot.
*   **Consequence:** A single-shim/GRUB setup cannot use `BootNext` to dynamically choose a non-default menu entry without writing state elsewhere. If state is written to a file, we are back to the A1' loop hazard (or we hit write lockdowns).

### Hazard B: The GRUB Lockdown Fallback is Unviable under Secure Boot
*   **The Claim:** The plan proposes a fallback option: *"move the GRUB grubenv to the FAT32 ESP... so GRUB's own `save_env next_entry=` succeeds"*.
*   **The Flaw:** When UEFI Secure Boot is active, GRUB enters **lockdown mode**. In lockdown mode, GRUB's `save_env` command is compiled out or blocked with `error: secure boot forbids writing to the environment block` to prevent tampering with boot variables.
*   **Consequence:** Moving the `grubenv` file to a FAT32 ESP does *not* bypass Secure Boot write restrictions. GRUB will still refuse to clear the one-shot variable at boot time, making this fallback option completely unviable on Secure Boot-enabled appliances.

### Hazard C: "Per-Kernel UEFI Entry" Secure Boot Lockout
*   **The Claim:** The plan recommends creating a custom UEFI boot entry for the candidate kernel.
*   **The Flaw:** If the custom entry points directly to the kernel's EFI stub (`vmlinuz`), the motherboard's UEFI firmware will reject the kernel's signature under Secure Boot. This is because Canonical-signed kernels are signed with the Canonical key, which is *not* present in the motherboard's default UEFI `db` (it is trusted via Shim's MOK database).
*   **Consequence:** To boot a Canonical-signed kernel under Secure Boot, the boot option must execute `shimx64.efi` -> `grubx64.efi`. To make a candidate-specific boot option, the upgrade process must stage a temporary copy of Shim, GRUB, and a custom `grub.cfg` (hardcoding the candidate boot target) in a dedicated directory on the ESP (e.g. `\EFI\xpf-candidate\`). The plan fails to model this file-staging requirement on the ESP, which is critical given the typically limited size of ESP partitions.

---

## 3. Confirming Fixes of Round 2 Findings

v3 successfully resolved the other Round 2 findings:

1.  **Watchdog Persistence (Path Option D):** Correctly reframed. The plan acknowledges that hardware watchdog survival across warm reboots cannot be guaranteed in software and provides clear `D1` (fail-closed strict) and `D2` (warn-and-proceed) policies.
2.  **`apt-mark` Globs:** Replaced the unsafe shell-expanded glob with a concrete package list expansion via `dpkg-query -W -f='${Package}\n' 'linux-*'`.
3.  **GRUB Submenus:** Addressed by adding `GRUB_DISABLE_SUBMENU=y` to the bake config, simplifying menu entry indexing.
4.  **Secure Boot Lockout Fail-Safe:** The pivot to `BootNext` ensures that a signature verification failure by the firmware falls back to the default `BootOrder` because `BootNext` is cleared before verification/execution.
5.  **External Orchestrator Robustness:** The orchestrator sequence now includes a `running kernel == target` version anchor, a leased TTL lock on the control-plane store, and a local self-recovery timeout for orphaned drains.
6.  **Mixed-Base Introspection:** Correctly shifted from an online boot check to an offline file read of the baked image version manifest.
7.  **State-Carry Contract:** Corrected to carry only `xpf.conf` and `node-id` (text configuration) and re-derive `.configdb` and keys on the new image.

---

## 4. New Risks Introduced by v3

### Risk 1: `BootOrder` Corruption and Platform Entry Erasure
*   **Vulnerability:** Running `efibootmgr --bootorder` to promote a candidate kernel requires passing a list of boot entry IDs. If the upgrade daemon constructs this list statically or incorrectly, it risks stripping out other system boot options (such as PXE boot, UEFI Shell, or system recovery tools) that were originally configured.
*   **Mitigation:** The implementation must query the existing `BootOrder`, verify the position of the known-good entry, and perform a list manipulation to insert the candidate at the front, preserving all other non-XPF boot entries.

### Risk 2: NVRAM Wear and Size Limits
*   **Vulnerability:** Dynamically creating and deleting UEFI boot entries on every kernel upgrade writes directly to NVRAM. On some server motherboards and virtualization hypervisors, NVRAM space is highly constrained (sometimes 64KB total) and lacks stable garbage collection, leading to "No space left on device" errors or firmware hangs.
*   **Mitigation:** Limit UEFI boot entry creation by using a fixed set of A/B slot entries (e.g., `xpf-a` and `xpf-b`) that are permanently registered, rather than generating a new entry UUID on every patch.

---

## 5. Required Action Items to Achieve PLAN-READY

To transition the plan to `PLAN-READY`, the following clarifications must be added:

1.  **Specify the exact bootloader execution path for the Candidate UEFI entry:** Document whether it copies Shim, GRUB, and a custom stub `grub.cfg` to a candidate folder on the ESP, or if it uses another mechanism.
2.  **Explicitly remove the GRUB-grubenv FAT32 fallback (A1''-fallback):** Acknowledge that Secure Boot lockdown blocks this fallback.
3.  **Specify BootOrder preservation rules:** Detail how `efibootmgr` commands will parse and modify the existing `BootOrder` to prevent erasure of platform-specific boot paths.
