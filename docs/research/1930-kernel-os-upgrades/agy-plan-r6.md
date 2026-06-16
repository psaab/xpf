# Major underlying VM/OS + kernel upgrades (plan-of-action) — Round 6 Review

Target: `docs/research/1930-kernel-os-upgrades/plan.md`
Worktree: `.claude/worktrees/1930-research-kernel-os-upgrades`

## 1. Review Summary and Core Findings

This is the Round 6 convergence review of the major underlying VM/OS and kernel upgrades plan. The implementation plan has gone through five prior rounds of adversarial pressure-testing. We find that the resulting architecture (v6.1) successfully addresses the fundamental constraints of UEFI Secure Boot, the limitations of GRUB environment variables, filesystem checksum compatibility, and the necessity of external HA orchestration across reboots.

All prior major UEFI flaws, such as writing to the `grubenv` block on ext4 with `metadata_csum` (which GRUB fails to write at boot time), the boot-loop risks, NVRAM wear, and separate `/boot` vs. ESP staging issues, have been resolved. The final A4 design represents a robust, implementable boot selection mechanism.

### Key Strengths of the A4 UEFI Substrate:
- **Loop-Safe One-Shot Boot via firmware `BootNext`**: Avoids write-dependence on local filesystems at critical failing bootloader moments. The UEFI firmware consumes and clears the `BootNext` flag prior to boot-option execution. If an early hang occurs and the watchdog resets the host, the firmware automatically falls back to the permanent `BootOrder` entries (lines 272-280).
- **Secure-Boot Compliance**: Staging a private copy of the signed `shimx64.efi` and `grubx64.efi` under slot-private directories on the ESP ensures the UEFI trust chain remains intact.
- **Grub Lockdown Safety**: Sourcing the selector script file (`xpf.selector`) relative to `$cmdpath` (which points to the slot directory) avoids string comparison logic and works seamlessly under UEFI Secure Boot lockdown (lines 241-256).
- **Survival Across `update-grub`**: Moving the slot selection logic to an executable `/etc/grub.d/09_xpf` drop-in ensures the custom boot path is reliably re-emitted into `/boot/grub/grub.cfg` on every kernel installation or purge (lines 248-251, 351-367).

---

## 2. Invariant & Edge-Case Verification

### A. `$cmdpath` Partition and Prefix Resolution
Under signed GRUB, `$cmdpath` contains the device prefix (e.g., `(hd0,gpt1)/EFI/xpf-A`). GRUB's native `source` command handles paths containing device prefixes directly (e.g., `source "(hd0,gpt1)/EFI/xpf-A/xpf.selector"`). Double-quoting `"$cmdpath/xpf.selector"` prevents path expansion issues due to whitespace. This is a highly robust solution.

### B. Separate `/boot` Partition vs. Relative Kernel Paths
In standard Debian/Ubuntu installations, the `/boot` filesystem may reside on a separate partition. If `/boot` is a separate mount point, GRUB's root variable at the execution of `/boot/grub/grub.cfg` points to the root of the boot partition, and kernel images must be referenced as `/$xpf_slot_kernel` (relative to the boot partition root) rather than `/boot/$xpf_slot_kernel`. 
Because `/etc/grub.d/09_xpf` is executed in userspace during `update-grub`, the implementation can leverage standard GRUB configuration helper functions (such as `make_system_path_relative_to_its_root`) to dynamically output the correct relative paths in `/boot/grub/grub.cfg`. This is a routine integration step.

### C. Non-Blocking NVRAM Registration
Moving the `efibootmgr` slot registration out of `xpf-day0-config` and into an independent, non-blocking `.deb`-packaged oneshot systemd unit (lines 287-301) prevents the SAFE-BOOTSTRAP lifeline from bricking on read-only NVRAM environments or VM environments with disabled EFI variables. 

---

## 3. Verdict

**PLAN-READY**

The proposed plan is sound, robust, and ready for implementation. All key constraints and failure modes have been folded into the final design.
