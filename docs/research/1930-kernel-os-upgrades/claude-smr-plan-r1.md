# Claude SMR — hostile plan review r1 (#1930)

Reviewer: Claude SMR (domain SMR + CPU/arch + SW-design). Posture: HOSTILE.
Plan under review: `docs/research/1930-kernel-os-upgrades/plan.md` @ v1
(203fab2dd).

I read the plan end-to-end AND verified its load-bearing factual claims against
`origin/master` source (`bake.py`, `verify_userspace_shim.go`, `pkg/upgrade/
rolling.go`, `cutover.go`, `flip.go`, `docs/in-place-upgrade.md`). Findings below
are ordered by severity. This is not a rubber stamp.

## BLOCKER findings

### B1 — "Reuse rolling.go's drain/act/restore primitive" is WRONG for a kernel bump
The plan (§3.1.e, §5 INC-2, §7) says LANE 1 HA "reuses `pkg/upgrade/rolling.go`'s
drain → act → restore primitive." I verified `rolling.go:62-82`: `RunRolling`
does drain (`ForceSecondary` + `DrainComplete` STRONG predicate) → **single-node
STOP→FLIP→START cut** → restore. The "act" is a *binary symlink flip + systemctl
restart* — it NEVER reboots. A kernel bump's "act" is a **reboot into a candidate
kernel**, which:
- takes the node fully offline for the whole boot (tens of seconds), not a
  sub-second binary swap;
- cannot be a STOP→FLIP→START in-process step — the node is gone until it
  reboots, verifies, and rejoins the cluster;
- means the drain predicate (`DrainComplete`) must hold across a reboot, and the
  node must re-establish session-sync + VRRP + re-drain-confirm AFTER the reboot
  before the rolling drive moves to the second node.

The plan treats the kernel "act" as a drop-in for the binary "act." It is a
**different state machine**: drain → arm one-shot + watchdog → REBOOT → (on
candidate boot) verify → promote-or-revert → **rejoin + re-confirm primary on
peer + re-establish sync** → only THEN proceed to node 2. INC-2 as written would
not work. The plan must add a "reboot-and-rejoin" sub-state and define the
post-reboot re-confirmation gate, or it's underspecified to the point of being
unbuildable.

### B2 — The dpkg `linux-image-*` postinst runs `update-grub` and can move the default
The plan's whole brick-proofing rests on "GRUB *default* is never changed until
verify PASS" (§3.1.3, §8). But installing the candidate kernel package
(`apt-get install linux-image-<cand>`, §3.1.2.b) triggers the kernel package's
**own** `postinst` maintainer script, which runs `update-grub` /
`grub-mkconfig`. With Ubuntu's default `GRUB_DEFAULT=0` semantics, the newest
kernel becomes menuentry 0 and `update-grub` regenerates the menu so the NEW
kernel is the default — BEFORE `xpf-upgrade` ever calls `grub-reboot`. The plan
assumes the default only changes via an explicit `grub-set-default`; in reality
the apt install of the kernel itself can flip the effective default depending on
`GRUB_DEFAULT`. The plan MUST pin `GRUB_DEFAULT` to a **specific known-good
menuentry id** (not `0`, not "newest") so that an in-place kernel install does
NOT change what boots by default, and the candidate is reached ONLY via the
one-shot `grub-reboot`. `GRUB_DEFAULT=saved` (the plan's choice) plus a `grubenv`
that points at the known-good entry is correct ONLY if `update-grub` does not
rewrite `saved_entry` — verify that interaction explicitly. This is the single
most likely real-world brick path and the plan does not address it.

### B3 — `grub-reboot <candidate>` requires a STABLE menuentry identifier across update-grub
`grub-reboot` takes a menuentry title or id. After installing a new kernel,
`update-grub` regenerates `/boot/grub/grub.cfg` and the **submenu structure /
entry ordering can change** (Ubuntu nests non-default kernels under an "Advanced
options" submenu). A numeric `grub-reboot 1` is fragile; the plan must use
**stable menuentry IDs** (`--id` / `GRUB_DISABLE_SUBMENU` or
`gnulinux-<version>-advanced-<uuid>`-form ids) and assert the candidate id
actually exists in the regenerated grub.cfg before arming. Not mentioned.

## MAJOR findings

### M1 — Secure Boot is unaddressed and can hard-fail the candidate kernel
`bake.py` has zero Secure Boot / shim-signed handling (verified: no `efi`,
`shim`, `signed`, `secure` references). If the appliance ever runs on a
Secure-Boot-enabled hypervisor/host, an `apt`-installed Ubuntu `linux-image`
*is* signed by Canonical (so it boots), but a **custom or HWE kernel** may not
be — and the one-shot boot of an unsigned candidate would fail at the shim
verification stage, BEFORE the promotion oneshot, before even the HW watchdog's
userspace pet. The plan's "HW watchdog catches early hang" covers a *hang*, not
a Secure Boot *refusal-to-load* (which is a clean fail-to-GRUB, recoverable, but
the plan should say so). At minimum the plan must state the Secure Boot posture
(disabled on the appliance? Canonical-signed kernels only?) and scope LANE 1 to
Canonical-signed kernels.

### M2 — Watchdog deadline vs verify+health duration is a real race, hand-waved
§6 risk #9 acknowledges "watchdog fires during a legitimately-slow-but-fine
boot" and proposes "pet early on liveness, disarm on verify PASS." But the
verify (`ebpf.NewCollection` over the full shim) + health beacon (dataplane
loads + forwards a probe) can take *seconds to tens of seconds*, and the HW
watchdog deadline (`RuntimeWatchdogSec`) is typically tight. If verify runs long
on a busy first boot, the watchdog resets a kernel that would have PASSed →
spurious revert (annoying, not a brick) OR — worse — if the design pets-on-
liveness to avoid that, a candidate kernel that boots to systemd but whose shim
silently fails to forward (verify says PASS structurally but live forwarding is
broken) gets the watchdog pet and is never reset, defeating the safety net. The
plan needs a concrete budget: watchdog deadline ≥ (worst-case boot + verify +
health) with margin, AND the disarm must be gated on the *health beacon* (actual
forward), not just the structural verify. State the numbers.

### M3 — `/boot` space exhaustion is mentioned but the failure mode is mis-scoped
§6 risk #10 says "prune is mandatory." But the brick risk is sharper: if the
candidate kernel install fails PARTWAY because `/boot` is full (Ubuntu `/boot`
is small, ~512MB-1GB, and an initramfs is ~100MB), you can end up with a
**broken initramfs for the running kernel** or a half-installed candidate, and
the next `update-grub` references a kernel whose initramfs is truncated → the
running (old) kernel itself may fail to boot on the next reset. The prune MUST
happen BEFORE the candidate install (free space first), and the plan should
verify free `/boot` space as a pre-assert in `xpfd upgrade kernel`, alongside
the GRUB/watchdog pre-asserts (§3.1.2.a).

### M4 — LANE 3 do-release-upgrade (Path Option B2) is incoherent and should be DROPPED
The plan offers B2 as a "documented, non-HA, console-attended escape hatch," but
then loads it with so many constraints (`apt-mark hold linux-*` first, route the
kernel through LANE 1, neutralize needrestart, replace do-release-upgrade's final
reboot with a LANE-1 boot) that it is no longer `do-release-upgrade` — it's a
bespoke fragile procedure that happens to call `do-release-upgrade` in the
middle. `do-release-upgrade` with `linux-*` held will often refuse to proceed or
leave the release half-upgraded (it expects to manage the kernel). And the whole
appliance model is image-replace-first (#1879). Offering B2 invites operators to
brick hand-built boxes following a procedure that cannot be tested in CI. RECO:
drop B2 entirely; LANE 3 = image-replace ONLY, with an explicit "in-place base-OS
major upgrade is unsupported — re-image" statement. A documented unsupported path
is safer than a documented fragile one. (If the user insists on an escape hatch,
make it "do-release-upgrade is at your own risk, unsupported, re-image after," NOT
a numbered procedure that implies we stand behind it.)

## MINOR / nits

- **m1:** §2 "no `apt-mark hold`" — VERIFIED correct (bake.py has no apt-mark).
  Good; the plan's factual claim holds. (Noting because B-findings hinge on
  trusting the plan's facts; this one checks out.)
- **m2:** §3.1 happy path doesn't say what `xpf-upgrade kernel` does on a NON-HA
  watchdog-less platform at the *pre-assert* stage vs the *bake* stage — the
  bake should refuse to produce an image without a watchdog device OR clearly
  mark LANE 1 unavailable. Clarify where the "no watchdog ⇒ LANE 2 only"
  decision is enforced (bake-time capability flag vs runtime pre-assert). The
  plan has the runtime pre-assert (good) but should also note the bake can't
  guarantee the *runtime* hypervisor exposes `/dev/watchdog`.
- **m3:** §6.5 session-sync wire compat: a kernel bump does NOT change the xpf
  binary or wire protocol (shim is embedded, version fixed across a kernel move)
  — so risk #7/§6.5 about session-sync wire compat is largely a NON-issue for
  LANE 1 (it matters for LANE 2/3 where the xpf version may also move). The plan
  conflates the two; tighten the scoping so LANE 1 isn't burdened with a wire-
  compat concern it doesn't have.
- **m4:** INC-0 should also disable `unattended-upgrades` for `linux-*`
  explicitly (risk #8 names it but INC-0's bullet list doesn't include it).

## Verdict

PLAN-NEEDS-WORK — The 3-lane decomposition and the core invariant
(verify-dataplane is kernel-space ⇒ one-shot-boot, HW-watchdog-not-softdog) are
correct and well-grounded, and the factual claims about the bake gaps check out.
But three BLOCKERs make the LANE 1 mechanism unbuildable as written: (B1) the
HA "act" is a reboot-and-rejoin, NOT rolling.go's STOP→FLIP→START, and the plan
reuses the wrong primitive; (B2) the dpkg kernel postinst's own `update-grub`
can move the boot default before `grub-reboot` is ever armed, defeating the
"default never changes until verify PASS" foundation; (B3) `grub-reboot` needs a
stable menuentry id that survives `update-grub` regeneration. Fix B1-B3, address
the watchdog-budget (M2) and /boot-ordering (M3) concretely, decide Secure Boot
posture (M1), and drop the incoherent do-release-upgrade escape hatch (M4), and
this is PLAN-READY.
