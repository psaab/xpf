# Claude SMR — hostile plan review r3 (FINAL) (#1930)

Reviewer: Claude SMR. Posture: HOSTILE. Plan: v3 (b035e5590). r2 verdict was
PLAN-NEEDS-WORK (B4 early-hang loop).

I re-traced the v3 `BootNext` substrate against the actual image topology
(`bake.py` builds from the **Ubuntu cloud image**, `ubuntu-<rel>-server-cloudimg-
amd64.img`, line 159) and re-checked every r2 disposition.

## r2 disposition (verified)
- **B4 / early-hang boot-loop — RESOLVED in principle.** `BootNext` is a UEFI
  NVRAM variable the **firmware** consumes before handing off, so a pre-Linux
  hang + reset comes up with `BootNext` already gone and the firmware uses
  `BootOrder` (known-good first). This genuinely closes the loop that A1/A1'
  could not — the clear no longer depends on GRUB-writing-ext4 or
  Linux-being-reached. Correct mechanism choice. (One topology caveat — N1
  below — but the loop logic is sound.)
- **Watchdog reframe (Path D)** — RESOLVED. Honest: loop closed by `BootNext`
  regardless; watchdog only triggers the reset; D1/D2 expose the non-SW-verifiable
  hardware dependence. Good.
- **apt-mark hold dpkg-query / GRUB_DISABLE_SUBMENU / Secure Boot fail-safe /
  orchestrator lease+version-check+self-recovery / mixed-base manifest** — all
  RESOLVED and concrete.
- **State-carry (Codex F11)** — RESOLVED and now CORRECT: §3.3 matches
  `docs/install-images.md:188-190` ("text config is the portable artifact — not
  `.configdb`"). Good catch folded properly.
- **xpf-deploy.py over-attribution (Codex F12)** — RESOLVED; §3.2 + §2 now say
  VM-granular recreate, gates are new.
- **do-release-upgrade contradiction (Codex F8)** — RESOLVED; UNSUPPORTED
  everywhere, no "gated fallback" line remains.

## NEW finding (non-blocking, must be acknowledged in the plan)

### N1 — Ubuntu cloud images do NOT ship per-kernel UEFI boot entries; the
### "BootNext to a per-kernel UEFI entry" RECOMMENDATION needs a topology choice
v3 §3.1 / Path A1'' recommends "each kernel gets its own UEFI boot entry … then
`efibootmgr --bootnext <candidate-entry>`." But the bake base is the stock Ubuntu
cloud image, which boots via **a single `ubuntu` UEFI entry → shimx64 → grubx64
→ GRUB menu** (GRUB resolves the kernel from `grub.cfg`); it does NOT create one
`efibootmgr` entry per kernel. Per-kernel UEFI entries only exist with a **UKI**
(unified kernel image, one EFI binary per kernel) or a `kernelstub`/systemd-boot
layout — none of which the cloud image uses. So the *recommended* form silently
assumes a boot topology the image doesn't have; implementing it means adopting
UKIs (a real, separate change with its own Secure-Boot-signing story).

This does NOT break the design — the plan already lists the brick-safe
**A1''-fallback: GRUB grubenv on the FAT32 ESP** (GRUB can write FAT, so GRUB's
own `save_env next_entry=` succeeds and the one-shot is consumed reliably). On the
*single-GRUB-entry cloud image*, the cleanest loop-safe one-shot is actually one
of:
- **(i) `BootNext` to a SECOND UEFI entry** that chainloads GRUB with a
  candidate-selecting argument (two fixed UEFI entries: "normal" and
  "try-candidate"; firmware clears `BootNext` → reset returns to "normal"); OR
- **(ii) grubenv on the ESP** (FAT, GRUB-writable) so GRUB's `next_entry`
  one-shot works as designed — no UEFI-entry juggling at all.

Both are loop-safe; (ii) is the smallest change to the existing GRUB cloud image.
**The plan must pick the concrete topology for the cloud-image base** rather than
recommend per-kernel UEFI entries (which imply UKIs). My recommendation: make the
PRIMARY the **ESP-grubenv one-shot (ii)** for the GRUB cloud image, keep
`BootNext`-to-a-second-fixed-entry (i) as the alternative, and note UKI/
per-kernel-entries as the systemd-boot/A3 future. This is a recommendation-
ordering fix, not a new blocker — every listed option closes the loop.

## MINOR
- **m1:** §3.1 should state that whichever one-shot substrate is chosen, the
  `verify-dataplane`/forward-beacon promotion still owns the *durable* default
  flip (BootOrder or grub-set-default), so the one-shot substrate choice (i/ii)
  is orthogonal to the verify/promote logic — make that separation explicit so an
  implementer doesn't couple them.

## Verdict

PLAN-READY — v3 resolves the r2 early-hang boot-loop (the firmware-cleared
`BootNext` one-shot is the correct fix and works regardless of whether the
candidate reaches Linux), and cleanly folds every other r2 finding including the
two Codex factual corrections (state-carry = TEXT config; xpf-deploy.py =
VM-granular recreate). The single new item (N1: the cloud-image base has no
per-kernel UEFI entries, so the *recommended* one-shot form implies UKIs) is a
recommendation-ordering refinement — the plan already carries the brick-safe
ESP-grubenv fallback, so the design is sound either way; I ask only that the plan
promote a concrete loop-safe topology for the GRUB cloud image (ESP-grubenv as
primary) rather than per-kernel UEFI entries. With that ordering fix the plan is
implementable and brick-safe. This is research output, not code — N1 is a "state
the topology" doc fix, well within PLAN-READY.
