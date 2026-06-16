# Claude SMR — hostile plan review r2 (#1930)

Reviewer: Claude SMR. Posture: HOSTILE. Plan under review: v2 (479a992ef).
r1 verdict was PLAN-NEEDS-WORK (B1/B2/B3 + M1-M4).

I re-read v2 end-to-end and independently traced the A1' one-shot substrate
against GRUB's actual `next_entry` semantics (RH bug 1520148, k3os#804, Arch
266415). Most r1 findings are properly resolved. **But the v2 A1' substrate, as
written, does NOT actually break the boot-loop for the early-hang case** — the
exact failure A1' was introduced to fix. New BLOCKER below.

## r1 disposition (verified resolved)
- **B1 (rolling.go act ≠ reboot):** RESOLVED. §3.1-HA moves HA orchestration to
  the external `xpf-deploy.py` with a rejoin-confirm gate + cluster lock;
  rolling.go is explicitly NOT used for the kernel reboot cut. Correct.
- **B2 (dpkg postinst moves default):** RESOLVED. INC-1 pins a stable known-good
  menuentry id and re-asserts it did not move after the candidate install.
- **B3 (grub-reboot needs stable id):** RESOLVED. Stable id resolved from the
  regenerated grub.cfg + existence assert.
- **M1 (Secure Boot):** RESOLVED (posture stated, LANE 1 scoped to signed).
- **M2 (watchdog budget / forward beacon):** RESOLVED (promotion + disarm gated
  on the forward health beacon, not structural verify).
- **M3 (/boot prune-before-install):** RESOLVED (pre-assert + prune + GC).
- **M4 (drop do-release-upgrade):** RESOLVED (UNSUPPORTED).

## NEW BLOCKER

### B4 — A1' "Linux clears the marker" does NOT prevent a boot-loop for an early-hang candidate
v2 §3.1 / Path A1' says: the candidate is requested via "a one-shot `next_entry`
whose clear is performed by an early Linux userspace/initramfs unit," and "on a
fallback (watchdog/clean reset to the known-good default), the known-good boot's
early Linux unit clears the marker." Trace the early-hang case GRUB+metadata_csum
actually produces:

1. `grub-editenv` (from Linux, works) sets `next_entry=<candidate>`.
2. Reboot. GRUB reads `next_entry`, boots the **candidate**, and is *supposed* to
   `save_env next_entry=` to consume it — but **fails silently** (metadata_csum /
   Secure Boot). `next_entry` is STILL SET.
3. Candidate **hangs before Linux** (the early-boot hang A1' must survive).
4. Persistent watchdog resets the box.
5. GRUB runs again, reads `next_entry` (STILL the candidate), boots the
   **candidate AGAIN** → back to step 3. **INFINITE BOOT-LOOP.**

The "known-good boot's Linux clears the marker" step is NEVER REACHED, because
GRUB keeps honoring the still-set `next_entry` and never falls through to the
known-good default. A1' only works for a candidate that *reaches Linux* (where
the candidate's own Linux can `grub-editenv unset next_entry`) — i.e. the
**promote/verify-fail-but-booted** case, NOT the **early-hang** case. So v2 still
bricks on early hang, which is precisely the case the persistent watchdog +
one-shot were supposed to make brick-proof. The watchdog turns a hang into a
RESET, but with `next_entry` un-clearable by GRUB the reset re-enters the
candidate — the watchdog makes the loop *faster*, not safer.

**This is the same class as r1 B2/AGY-A; v2 reworded it (moved the clear to
Linux) without fixing the early-hang sub-case.** Per
`feedback_verify_whole_function_body`, I traced the whole path, not the happy
sub-path.

**Acceptable fixes (the plan must pick one and state it):**
- **F-a (boot-counting on a GRUB-WRITABLE medium):** put the one-shot/counter in
  a grubenv on a filesystem GRUB *can* write (a dedicated small partition GRUB
  writes, or fix the boot fs to not use metadata_csum for the grubenv block).
  Then GRUB itself consumes the one-shot reliably → reset boots known-good.
- **F-b (systemd-boot/UKI boot-counting — promote A3 from "future"):** the ESP
  is FAT32 (GRUB/firmware-writable, Secure-Boot-OK); systemd-boot's tries-counter
  auto-reverts. The plan currently DEFERS A3; if F-a is not adopted, A3 is the
  ONLY brick-safe option and must be promoted to the recommendation, accepting
  the bootloader-migration cost. (Mitigate A3's "boots-but-rejects miscount" by
  having the promotion unit `bootctl` mark good ONLY on forward-beacon PASS, and
  deliberately leave the candidate "bad" on REJECT so the counter reverts.)
- **F-c (honest scope reduction):** if neither F-a nor F-b is in scope, LANE 1
  CANNOT be brick-proof against early hang on a metadata_csum/Secure-Boot GRUB
  image. Then LANE 1's guarantee must be restated as "brick-proof against
  verify-fail / boots-but-rejects (the common shim-verifier case); an early
  *kernel* hang requires operator/console recovery" — and the one-shot must use
  a counter capped at 1 so at most ONE candidate re-entry happens before the
  known-good default is forced (requires GRUB to write the counter — back to
  F-a). Realistically F-c collapses into F-a.

The cleanest honest answer is **F-a (GRUB-writable grubenv location) OR F-b
(systemd-boot)**; the plan must choose, because "Linux clears next_entry" does
not close the early-hang loop.

## MINOR
- **m1:** §3.1 step 5 "issues a clean reboot (or lets the watchdog fire) → boots
  the known-good default" — same B4 issue: a clean reboot after a *verify
  REJECT* DOES reach Linux first (so the candidate's Linux can unset next_entry
  before rebooting), so the REJECT path is fine; make the plan explicitly
  distinguish "REJECT (reached Linux, clear then reboot — safe)" from "early hang
  (never reached Linux — needs B4's fix)." The conflation is what hid B4.
- **m2:** the initramfs-early-arm watchdog fallback (§2 inv 3) is asserted but
  not specified; if it is the brick-proofing mechanism it needs the same rigor as
  the bootloader choice (an initramfs hook that arms /dev/watchdog before the
  pivot, with a documented earliest-arm point).

## Verdict

PLAN-NEEDS-WORK — v2 correctly resolved 6 of the 7 r1 issues, but the headline
LANE-1 brick-proofing (A1') still loops on an early-boot candidate hang: GRUB
cannot clear its own `next_entry` on this image, so a watchdog reset re-enters
the failing candidate forever and the "Linux clears the marker" step is never
reached. The plan must choose a GRUB-writable one-shot medium (F-a) or promote
systemd-boot boot-counting (F-b), and must explicitly separate the "candidate
reached Linux" (safe) path from the "early hang" (currently-looping) path. Fix
B4 and this is PLAN-READY.
