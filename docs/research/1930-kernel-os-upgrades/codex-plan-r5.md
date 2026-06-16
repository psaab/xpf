# Codex — hostile plan review r5 (#1930)

Codex thread `019ed2c2-0074-7d21-a061-6c54e83d9f0f`, turn
`019ed2c2-04a0-7240-8e6b-463e710e26ca`. Reviewed v5.2 (read the real
`xpf-day0-config`, `.service`, bake, deploy, `pkg/upgrade`). Verdict:
**PLAN-NEEDS-WORK**.

CONFIRMED HOLDS: `$cmdpath` mechanism sound; `/etc/grub.d/09_xpf` (not hand-edit);
NVRAM-not-in-bake; kernels in `/boot`; shared-`/boot` SPOF; active-slot-never-
pruned + atomic selector; state-carry TEXT-only; do-release-upgrade UNSUPPORTED.

- **FLAW-1 (FATAL):** the `09_xpf` fragment was specified as bare `linux`/`initrd`
  — GRUB needs a `menuentry { … }` (implicit `boot`) or explicit `… ; boot`, else
  GRUB falls through and the candidate slot may not boot. → v6.1 specifies a
  self-contained first/default `menuentry --id xpf-slot { source selector; linux;
  initrd }` with `GRUB_DEFAULT=xpf-slot`.
- **FLAW-2 (MAJOR):** stale "slot `grub.cfg`" text still in active sections
  (§3.1 "within each slot's private grub.cfg", §8 "Slot grub.cfg staging is
  atomic"). → v6.1 scrubbed both to the selector model.
- **FLAW-3 (MAJOR):** first-boot registration "extend xpf-day0-config" + "every
  boot" conflicts with the existing unit (`ConditionPathExists=!…day0-applied`,
  exits early once `.configdb` exists, `Before=xpfd`). → already fixed in v6: a
  SEPARATE `.deb`-shipped non-blocking `xpf-uefi-slots`-style oneshot, not gated
  by the day-0 stamp, not `Before=xpfd`, bounded `efibootmgr` timeout.
- **FLAW-4 (MAJOR):** `docs/install-images.md:187-192` still advertises
  `deploy_rolling()`. → v6.1 adds the doc fix to ACCEPTANCE criteria (not just
  INC-3 prose).
