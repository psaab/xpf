# Claude SMR — hostile plan review r5 (#1930)

Reviewer: Claude SMR. Posture: HOSTILE. Plan: v5.1 (1aede53bf). r4 AGY = 4 UEFI
flaws (folded v5); r4 Codex = F13 consistency + NEW-F15..F20 (folded v5.1).

I re-traced the v5.1 A4 substrate (fixed A/B UEFI slots, ESP-staged shim+grub +
`$cmdpath`-branched shared `grub.cfg`, first-boot NVRAM registration,
`BootNext`-selected, non-destructive `BootOrder`) for correctness and verified
the r4 folds + cross-section consistency.

## r4 disposition (verified in v5.1)
- **AGY F1 (signed GRUB ignores per-dir grub.cfg):** RESOLVED — per-slot
  `grub.cfg` dropped; the SHARED `grub.cfg` `$cmdpath`-branches; shipped as a
  `/etc/grub.d/09_xpf_cmdpath` fragment so `update-grub` re-emits it (the detail
  that makes F1's fix durable — without it the candidate dpkg `update-grub` would
  clobber the branch).
- **AGY F2 (offline bake can't write NVRAM):** RESOLVED — bake STAGES ESP files +
  the fragment; `efibootmgr` registration + initial `BootOrder` is a first-boot
  service.
- **AGY F3 (kernels on ESP):** RESOLVED — kernels stay in `/boot`; only
  shim+grub+selector per slot; split `/boot` vs ESP capacity pre-asserts.
- **AGY F4 (shared /boot SPOF):** RESOLVED — documented as a boot-selection /
  loop-recovery channel, not disk A/B; corrupt `/boot` → LANE 2.
- **Codex F13/F15/F16 (substrate inconsistency + stale per-candidate mechanics):**
  RESOLVED — I grepped: no active `grub-set-default`, no "removes the candidate
  UEFI entry", no "static slot grub.cfg" as the live design; `$cmdpath` is the
  single substrate across §2/§3.1/Path A/INC/risks/acceptance/tests/§8/§11.
- **Codex F17 (LANE 1 HA = recreate-via-launch error):** RESOLVED — §11 now says
  LANE 1 HA drives `xpfd upgrade kernel` IN PLACE per node (recreate is LANE 2).
- **Codex F18 (slot detection):** RESOLVED — promotion requires `BootCurrent`==
  candidate-slot AND `uname -r`==candidate.
- **Codex F19 (BootNext power loss):** RESOLVED — NVRAM-durable single-shot +
  `BootOrder` fallback.
- **Codex F20 (stale doc):** RESOLVED — INC-3 adds the `install-images.md` fix.

## A4 correctness re-trace (v5.1)
- `$cmdpath` IS populated under signed GRUB (it is set by core to the device/dir
  the image was loaded from — independent of the signed `prefix`; the signed
  prefix locks where GRUB looks for its initial config, but `$cmdpath` still
  reflects the launch dir, which is exactly why the shared-config branch works).
- The shared-config branch as a `/etc/grub.d/` fragment survives `update-grub` —
  correct and necessary.
- First-boot NVRAM registration ordering: must run BEFORE the box needs the A/B
  slots (i.e. at first boot, alongside/after day-0 config, before any kernel
  bump). The plan places it in `xpf-day0-config`'s first-boot path — sound; the
  #1922 SAFE-BOOTSTRAP lifeline is independent (mgmt reachability), no conflict.
- Lifecycle (bake-stage → first-boot-register → arm → PASS/promote or
  hang/revert) is correct and loop-free.

## NEW finding (minor, non-blocking)

### N3 — name the first-boot-registration idempotency + the "slots already
### registered" case
The first-boot NVRAM registration must be **idempotent**: on every boot it should
verify the two slots exist in NVRAM with the right loader paths and the
`BootOrder` has the active slot reachable, and re-create/repair only if missing
(NVRAM can be cleared by a firmware reset / VM redefinition). State this so the
implementation doesn't either (a) duplicate slots on each boot or (b) assume
one-time registration that a NVRAM wipe would silently undo. This is a
"state the idempotency contract" doc item, not a design change.

## Verdict

PLAN-READY — v5.1 resolves all r4 findings (AGY's 4 UEFI flaws + Codex's
consistency/stale-mechanics/LANE-1-HA/slot-detection/power-loss/doc items). The
A4 substrate is now correct (signed-GRUB-aware via `$cmdpath` shipped as a
grub.d fragment, first-boot NVRAM registration, kernels in `/boot`, documented
shared-`/boot` SPOF) and threaded consistently through every section, with the
two earlier false attributions (`deploy_rolling()`, master.key-carries) fixed.
N3 (state the first-boot-registration idempotency contract) is a non-blocking
completeness note I recommend folding. The design is brick-loop-safe by firmware,
Secure-Boot-correct, HA-sequenced, and honest about its hardware-dependent
early-hang bound — implementable as the increments describe. Research output:
PLAN-READY.
