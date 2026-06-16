# Claude SMR — r6 final affirmation (#1930)

Plan: v6.2 (30bfc5794). My r4 and r5 passes were PLAN-READY; r6 folds were the
two Codex cross-section contradictions (INC-1 ESP sizing, §10 first-boot test),
which are doc-consistency fixes that do not change the converged A4 design.

Re-verified v6.2: the A4 substrate (fixed A/B UEFI slots, ESP-staged shim+grub +
`/etc/grub.d/09_xpf` `$cmdpath`-branch sourcing a GRUB-script `xpf.selector`,
firmware-cleared `BootNext` one-shot, non-destructive `BootOrder` promotion,
separate non-blocking `.deb` NVRAM-registration oneshot, kernels in `/boot`,
documented shared-`/boot` SPOF) is correct, Secure-Boot-aware, brick-loop-safe by
firmware, HA-sequenced in place, and internally consistent across all 11 sections
+ increments + risks. The two earlier false attributions (`deploy_rolling()`,
`master.key`-carries) are corrected. No remaining blockers.

Verdict: **PLAN-READY**.
