# Claude SMR — hostile plan review r4 (FINAL) (#1930)

Reviewer: Claude SMR. Posture: HOSTILE. Plan: v4 (fde6ecd02). My r3 was
PLAN-READY+N1; AGY + Codex r3 were PLAN-NEEDS-WORK on the substrate Secure-Boot
detail + cross-section inconsistency + two false attributions. v4 adopts the
single A4 substrate.

I re-traced A4 (fixed A/B UEFI slots, shim→grub→static slot `grub.cfg`,
`BootNext`-selected, non-destructive `BootOrder`) for correctness and verified
the cross-section consistency Codex F13 demanded.

## r3 disposition (verified)
- **AGY Hazard A (GRUB can't read BootNext)** — RESOLVED. A4 never asks GRUB to
  read `BootNext`; the firmware picks the slot, and each slot's `grub.cfg` is
  static (one hardcoded kernel). The selection is firmware-side; GRUB just boots
  its slot's kernel.
- **AGY Hazard B (Secure-Boot GRUB lockdown blocks save_env even on ESP)** —
  RESOLVED. A4 does ZERO GRUB env writes at boot (no `save_env`, no `next_entry`);
  the one-shot is the firmware's `BootNext`. Lockdown is irrelevant.
- **AGY Hazard C (bare vmlinuz fails Secure-Boot sig)** — RESOLVED. Each slot is
  shim→grub→MOK-signed kernel; the slot staging copies shim+grub, not a raw
  kernel UEFI entry.
- **AGY Risk 1 (BootOrder corruption)** — RESOLVED. Promotion is a documented
  non-destructive reorder preserving platform entries.
- **AGY Risk 2 (NVRAM wear)** — RESOLVED. Two FIXED permanently-registered slots,
  not per-upgrade entries.
- **Codex F13 (cross-section inconsistency)** — RESOLVED. I grepped: no residual
  "ESP-grubenv (PRIMARY/form 1)", no "per-kernel UEFI entries (recommended)", no
  "single GRUB entry reads BootNext". §2/§3.1/Path A/INC-0/INC-1/risks/
  acceptance/tests/§8/§11 all describe the A/B fixed-slot design. Consistent.
- **Codex F12 (`deploy_rolling()` false attribution)** — RESOLVED. All
  references now state it does NOT exist; the rolling driver is NEW INC work.
- **Codex F11 (§7 master.key carries)** — RESOLVED. §7 now states the per-lane
  TEXT-vs-DB contract.
- **My r3 N1** — subsumed: A4 uses no per-kernel UEFI entries at all.

## A4 correctness check (would it actually work?)
Traced the lifecycle:
- **Bake bootstrap:** both slots seeded pointing at the shipped known-good
  kernel; active slot first in `BootOrder`. Sound — both slots boot the same
  good kernel until the first upgrade.
- **Arm:** the candidate kernel is `apt`-installed into `/boot` (known-good NOT
  removed — held + GC only prunes un-promoted), and the INACTIVE slot's `grub.cfg`
  is rewritten to point at the candidate; `BootNext`=inactive-slot. The active
  slot still points at the known-good kernel which is still in `/boot`. Sound.
- **Candidate PASS:** non-destructive `BootOrder` reorder → inactive(candidate)
  slot becomes active. The now-inactive slot still points at the prior known-good
  (the A/B rollback target). Sound.
- **Candidate hang/REJECT:** firmware cleared `BootNext` → reset boots the active
  (known-good) slot. The candidate kernel + its slot staging are GC-pruned. Sound.
- **No loop, Secure-Boot-OK, no NVRAM churn, no GRUB write.** A4 is correct.

## NEW finding (minor, non-blocking)

### N2 — "both slots bad" + the ESP `grub.cfg` write is the one remaining
### write-path that must be crash-safe (state, don't re-loop)
Two small completeness items the plan should name so an implementer doesn't
reintroduce a hazard:
1. **Both-slots-bad:** if a promoted kernel later proves bad AND the rollback
   slot's kernel was meanwhile pruned/overwritten, there is no good slot. The
   plan must state the **invariant that the active slot's kernel is NEVER pruned**
   (only the *un-promoted candidate* is pruned), so the rollback slot always
   holds a known-good kernel. This is implied (GC prunes "un-promoted") but should
   be an explicit invariant — it is the A/B safety guarantee.
2. **Slot `grub.cfg` staging crash-safety:** rewriting the inactive slot's
   `grub.cfg` on the FAT ESP must be atomic-rename (write temp + rename), so a
   crash mid-stage leaves the inactive slot pointing at its *previous* (valid)
   kernel, never a truncated file. The ESP is FAT (Linux writes it fine — this is
   a Linux-side write, not a GRUB-at-boot write, so no lockdown issue), but FAT
   rename atomicity + an `fsync`/`sync` before arming `BootNext` should be stated.
   Reuse the `pkg/fsatomic` discipline (§7 preserved interfaces) for the ESP
   write too.

Neither blocks the design — both are "state the invariant / use atomic-rename"
refinements, well within PLAN-READY for research output. I add them so v4 carries
the A/B safety invariant explicitly.

## Verdict

PLAN-READY — v4's A4 substrate (fixed A/B UEFI slots, shim→grub→static slot
`grub.cfg`, firmware-cleared `BootNext`, non-destructive `BootOrder`) resolves
every r3 kill: it does no GRUB env write (Secure-Boot lockdown moot), never asks
GRUB to read `BootNext` (firmware selects the slot), boots shim→grub→MOK kernel
(Secure-Boot-correct), uses fixed slots (no NVRAM wear), and reorders `BootOrder`
non-destructively. The substrate is now threaded consistently through all
sections and the two false attributions (`deploy_rolling()`, master.key-carries)
are corrected. The lifecycle is correct (bake bootstrap → arm → PASS/promote or
hang/revert) with no loop. N2 (state the "active slot kernel never pruned"
invariant + atomic ESP `grub.cfg` rename) is a non-blocking completeness
refinement I recommend folding, but the design is sound and implementable as-is.
This is research output (PLAN-READY = the design is right and the increments are
buildable), not code.
