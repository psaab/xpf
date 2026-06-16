# #1930 — Major underlying VM/OS + kernel upgrades (plan-of-action)

- **Issue:** #1930 (deferred from #1917)
- **Status:** v2 — folds r1 reviews (Claude SMR + AGY converged PLAN-NEEDS-WORK).
  Major LANE-1 pivot: the bootloader one-shot revert moves OFF GRUB-grubenv
  (brick-loop under Secure Boot / ext4 `metadata_csum`) and the HA reboot
  orchestration moves OFF the in-process `rolling.go` (process dies at reboot).
- **Branch:** `research/1930-kernel-os-upgrades`
- **Scope discipline:** `/research` only. STOP at PLAN-READY. No production
  source touched, no PR opened. User approves via `/engineer 1930`.

---

## 1. Problem statement

#1917 (MERGED) shipped in-place upgrade of the **control plane (xpfd) + data
plane (userspace-dp helper / embedded AF_XDP shim)** as one matched, atomically
cut-over unit (`pkg/upgrade/`, `cmd/xpfd/upgrade.go`, `docs/in-place-upgrade.md`).
It explicitly deferred everything *below the xpf binary line* to this issue —
`docs/in-place-upgrade.md:169` states verbatim: *"Kernel/OS upgrades are #1930."*

This issue owns three coupled problems, all rooted in one hard invariant:

> **The embedded AF_XDP shim `.o` is kernel-space-verifier-gated (#1864).** The
> kernel BPF verifier — not a build-host check — decides whether the shim loads.
> `VerifyEmbeddedUserspaceShim` (`pkg/dataplane/verify_userspace_shim.go:54`)
> runs `ebpf.NewCollection` against the **running** kernel. A kernel the embedded
> `.o` has never been verified against can REJECT it → **no dataplane** (the box
> degrades to config-only mode; this exact failure took both HA cluster
> dataplanes down on 2026-06-10, the incident that motivated #1864).

The three problems:

1. **Routine kernel bumps (CVE remediation).** Today `bake.py` pins the image to
   exactly one kernel ≥ 6.18 (the verifier floor) but does NOT `apt-mark hold
   linux-*`. An unattended `apt upgrade` (or the operator running it for security
   patches) can pull a new kernel and reboot into it — moving the running kernel
   out from under a shim `.o` that was verifier-gated against a *different*
   kernel. There is no safe, tested channel to move the kernel.

2. **Base-OS major-version upgrades** (Ubuntu N → N+1, e.g. 26.04 → 28.04). This
   moves the kernel, glibc, systemd, FRR, strongSwan, kea, chrony, the apt repo
   set, and the boot stack all at once. `do-release-upgrade` on a live appliance
   is a high-blast-radius, multi-reboot, interactive-by-default operation. The
   question is whether to support it in-place at all, vs mandating image-replace.

3. **Boot-loader / watchdog footguns.** The #1917 research (§6.3c, §6.7) and the
   r1 reviews surfaced concrete bricking hazards in any one-shot kernel-boot
   mechanism: GRUB cannot clear its own one-shot flag at boot on ext4
   `metadata_csum` / Secure Boot (boot-loop), a clean reboot disarms a
   non-persistent watchdog (early-boot unprotected), the dpkg kernel postinst's
   `update-grub` can move the boot default, `grub-reboot` needs a stable
   menuentry id, and `needrestart` mid-transaction restarts. These must be
   designed-in, not discovered live.

### What is explicitly OUT of scope (already owned elsewhere)
- In-place xpfd + dataplane cut-over → #1917 (MERGED, `pkg/upgrade/`).
- Signed/hosted apt repo + install.sh → #1924 (OPEN).
- The shim toolchain pin + verify gate itself → #1864 (MERGED).
- SAFE-BOOTSTRAP mgmt-lifeline daemon work → #1922 (MERGED).
- The appliance image bake/deploy substrate → #1879 (MERGED): `scripts/image/
  bake.py`, `scripts/deploy/xpf-deploy.py`, `scripts/image/validate.py`.

---

## 2. Grounding — what already exists on master (verified, not assumed)

All of the following are MERGED on `origin/master` (verified by `git ls-tree`):

| Artifact | What it does | Relevance to #1930 |
|---|---|---|
| `pkg/dataplane/verify_userspace_shim.go` | `VerifyEmbeddedUserspaceShim()` / `VerifyUserspaceShimObject()` — kernel verify-only load, anonymous maps, never attaches; exit-code contract via `ErrUserspaceShimVerifierReject`. | The **kernel-side gate** the one-shot boot channel must invoke on the candidate kernel. |
| `cmd/xpfd/upgrade.go` + `pkg/upgrade/` | `xpfd upgrade [--rolling]` — staged→runtime-version copy, verify, atomic symlink flip, journal, auto-rollback, HA rolling drain. (`runner.go`, `cutover.go`, `flip.go`, `rolling.go`, `state.go`, `system_linux.go`.) | The **mechanism to reuse**: the kernel channel is a sibling state-machine; base-OS image-replace HA sequencing mirrors `rolling.go`. |
| `scripts/image/bake.py` | virt-customize: installs `linux-generic`, **HARD-ASSERTs newest kernel ≥ 6.18**, asserts `linux-modules-extra` (mlx5/i40e), purges all-but-newest kernel + **asserts exactly one kernel**, GRUB drop-in (`/etc/default/grub.d/99-xpf.cfg` = `init_on_alloc=0` only), build-host `verify-dataplane` pre-gate. | The **image-replace substrate** (Path C) + the place to add `apt-mark hold linux-*`, a pinned stable known-good `GRUB_DEFAULT` id, the persistent-watchdog + Linux-cleared one-shot substrate, and the promotion oneshot unit. |
| `scripts/deploy/xpf-deploy.py` | Pushes a baked image to incus / a target; HA two-node deploy. | The Path-C deploy driver the base-OS-major and heavy-kernel paths reuse. |
| `scripts/image/validate.py` | Factory-boot + in-guest `verify-dataplane` validation gate. | The acceptance gate for "xpf still loads + forwards on the new base." |
| `docs/in-place-upgrade.md` | The #1917 operator doc. Line 169 hands kernel/OS to #1930. | The doc to extend with the kernel channel + base-OS playbook. |
| `pkg/dataplane/README.md` §`#1864` | Toolchain pin + 3 verify gates (build, install, deploy pre-flight). | The contract the kernel channel must not break (verify is the only install gate). |

### Concrete gaps in the current substrate (the #1930 work surface)
- **No `apt-mark hold linux-*`** anywhere in `bake.py` — the floor is asserted
  at bake time but nothing prevents `apt upgrade` from moving it post-deploy.
- **GRUB drop-in is `init_on_alloc=0` only** — no pinned `GRUB_DEFAULT`, no
  stable known-good menuentry id, no Linux-cleared one-shot substrate. A naive
  `grub-reboot` channel would boot-loop on this image (§2 invariant 2).
- **No persistent watchdog config** in the image — no firmware/hypervisor
  watchdog, no `nowayout`, no initramfs early-arm. A clean reboot would leave the
  candidate's early boot unprotected (§2 invariant 3).
- **No `needrestart` blacklist** for the kernel-channel reboot window (#1917
  shipped one only for the binary-cut window per §6.3c; needs re-verification it
  also covers an apt-driven kernel install).
- **No base-OS major-upgrade playbook** — `do-release-upgrade` is unmodeled.
- **No `xpfd upgrade kernel` subcommand** — `pkg/upgrade` has no kernel verb.

### Load-bearing invariants for the design (three, all verified)

1. **`verify-dataplane` cannot validate an unbooted kernel** (the BPF verifier is
   kernel-space; `ebpf.NewCollection` loads into the *running* kernel). The
   kernel channel is fundamentally **"boot the candidate once, verify from
   inside it, promote-or-revert"** — NOT "verify-then-set-default." This forces
   one-shot-boot over verify-first. (#1917 §6.7, restated.)

2. **GRUB cannot reliably clear its own one-shot variable at boot on this image
   (r1 AGY Hazard A, SMR B2/B3).** GRUB's one-shot (`next_entry` via
   `grub-reboot`) depends on GRUB *itself* running `save_env next_entry=` early
   in boot to consume the flag. On the appliance that write FAILS for two
   independent reasons: (a) Ubuntu formats the boot ext4 with `metadata_csum`,
   which **GRUB's ext4 driver cannot write** (it has no checksum support → treats
   the FS read-only); (b) under UEFI **Secure Boot**, GRUB's env-write path is
   locked down. If the candidate hangs and the watchdog resets, GRUB re-reads the
   still-set `next_entry` and **boots the failing candidate again → infinite
   boot-loop / brick.** This is documented upstream (rear#3578, k3os#804, Arch
   forum 266415). **CONSEQUENCE: a pure GRUB-grubenv one-shot is NOT brick-safe
   on this image.** The design must either (i) write the one-shot marker to a
   GRUB-*writable* location, or (ii) clear it from *Linux userspace* on the
   known-good fallback boot (Linux's ext4 driver writes `metadata_csum` fine;
   `grub-editenv` from userspace also writes fine — the limitation is GRUB-at-
   boot only), or (iii) use a boot-counter the firmware/ESP owns. See §3.1 +
   Path Option A (rewritten).

3. **A clean reboot disarms the watchdog before the candidate boots (r1 AGY
   Hazard C).** `xpfd upgrade kernel` triggers a normal systemd reboot; the
   watchdog driver is cleanly stopped on shutdown, so the candidate kernel's
   *early* boot (decompression, initramfs, pre-systemd init) runs with **no armed
   watchdog**. A pure "arm watchdog before reboot" does not survive the reboot.
   **CONSEQUENCE:** the watchdog must be either (i) a firmware/BMC/hypervisor
   watchdog that persists across the OS reset (a true HW watchdog with
   `nowayout` that the OS shutdown cannot disarm), or (ii) re-armed extremely
   early on the candidate boot (initramfs hook) — and the brick-proof guarantee
   is only as strong as the earliest point the watchdog is armed. The honest
   bound (§6.7 of #1917) tightens: "never brick" holds ONLY where a persistent
   firmware/hypervisor watchdog exists; otherwise LANE 1 degrades to "GRUB
   default preserved, early hang needs operator recovery" — and on THIS image
   even "GRUB default preserved" is not guaranteed (invariant 2). So absent a
   persistent watchdog AND a non-GRUB one-shot, LANE 1 is unavailable → LANE 2.

---

## 3. Design — three lanes by blast radius

The design splits by how far the kernel moves, mirroring #1917's Path-B
(in-place) vs Path-C (image-replace) split:

```
  Kernel CVE point-release (same series, e.g. 6.18.x -> 6.18.y or 7.0.z)
      -> LANE 1: verify-gated one-shot-boot in-place kernel channel
                 (xpfd upgrade kernel <ver> + watchdog + grub-reboot)

  Heavy/uncertain kernel move (new series the shim has never seen, or kernel
  pulled by base-OS upgrade)
      -> LANE 2: image-replace (Path C, #1879). HA: replace secondary ->
                 failover -> replace primary. Standalone: documented reboot gap.

  Base-OS major version (Ubuntu N -> N+1)
      -> LANE 3: image-replace by DEFAULT (carries kernel inside).
                 do-release-upgrade offered ONLY as a documented, gated,
                 non-HA, console-attended fallback (see §3.3 + Path Option B).
```

### 3.1 LANE 1 — verify-gated one-shot-boot kernel channel (in-place)

The mechanism is built around the three invariants of §2. The two parts that
changed from v1 are the **one-shot-revert substrate** (no longer trusts GRUB to
clear its own flag — invariant 2) and the **HA orchestration** (no longer the
in-process `rolling.go` — invariant in §3.1-HA below).

**One-shot-revert substrate (resolves invariant 2 — brick-loop):** the design
does NOT rely on GRUB clearing `next_entry` at boot. Instead it uses
**"counted/userspace-cleared" semantics**: the known-good entry remains the
permanent GRUB default at all times; the candidate is reached via a marker that
is **consumed/cleared from Linux userspace**, never by GRUB-at-boot. Concretely
(Path Option A, rewritten — A1' is the recommendation):
- The permanent default is the **known-good** kernel menuentry (a STABLE id,
  not `0`, not "newest" — invariant 2 + SMR B3). `apt`-installing a new kernel
  must NOT change this (SMR B2): `GRUB_DEFAULT` is pinned to the known-good id,
  and the candidate-kernel `dpkg` postinst's `update-grub` regenerates the menu
  but the pinned default does not move.
- The candidate boot is requested by writing a marker that GRUB reads but
  **Linux clears**: either a one-shot `next_entry` whose clear is performed by
  an **early Linux userspace/initramfs unit** (Linux's ext4 driver writes
  `metadata_csum` fine; the GRUB-at-boot clear is the only thing that fails), or
  a boot-counter on a GRUB-writable medium. On a fallback (watchdog/clean reset
  to the known-good default), the known-good boot's **early Linux unit clears the
  marker** so a subsequent reboot does not re-enter the candidate. Net: a hung
  candidate that triggers a reset comes up on the known-good default and the
  known-good Linux clears the candidate request — NO boot-loop.

**Persistent-watchdog requirement (resolves invariant 3 — clean-shutdown
disarm):** LANE 1's "never brick on early hang" guarantee requires a watchdog
that **persists across the OS reset** — a firmware/BMC/hypervisor watchdog with
`nowayout=1` that a clean systemd shutdown cannot disarm, OR the candidate's
**initramfs re-arms a watchdog at the earliest possible point**. `softdog` armed
from systemd is INSUFFICIENT for early-boot hangs (it isn't loaded yet) AND is
disarmed by the clean reboot. The pre-assert (below) checks for a persistent
watchdog; absent one, LANE 1 refuses to arm and the operator uses LANE 2.

**Mechanism sequence:**

1. **Default posture: `apt-mark hold linux-*`** (added to `bake.py`, INC-0).
   Unattended apt cannot move the kernel. `unattended-upgrades` is also
   configured to never touch `linux-*` (SMR m4 / risk #8). A kernel bump is an
   explicit operator action.
2. Operator runs `xpfd upgrade kernel <candidate-version>` (new `pkg/upgrade`
   kernel verb). It **pre-asserts, fail-closed, before touching anything**:
   - `GRUB_DEFAULT` is pinned to a STABLE known-good menuentry id (NOT `0`/
     newest) and that id resolves in the current `grub.cfg`;
   - a **persistent** (firmware/BMC/hypervisor) watchdog device is present, OR
     an initramfs early-arm hook is installed;
   - **free `/boot` space** ≥ (candidate kernel image + initramfs + margin)
     BEFORE installing (SMR M3 / AGY Hazard E — prune-before-install);
   - the one-shot marker substrate (early Linux clear unit / boot-counter) is
     installed.
   Any failed assert → ABORT with an actionable message ("kernel channel not
   armed; use image-replace / LANE 2").
3. `apt-mark unhold linux-*` → install the candidate kernel package(s) →
   re-`apt-mark hold`. Assert the pinned default did NOT move after the
   candidate postinst's `update-grub` (SMR B2). The candidate is installed but
   NOT the boot default.
4. Write the candidate one-shot marker (substrate above). Arm/confirm the
   persistent watchdog. Reboot.
5. On the candidate boot, a **promotion oneshot systemd unit** runs early,
   before xpfd's `ExecStartPre` admits traffic:
   - Runs `xpfd verify-dataplane` against the now-running candidate kernel
     (exit 0 PASS / 3 REJECT / 1 error).
   - On PASS: runs a bounded **health beacon** (dataplane loads + forwards a
     real probe). **Only on health-beacon PASS** does it `grub-set-default
     <candidate-stable-id>` (promote), write a durable promotion marker, clear
     the one-shot marker, and disarm the watchdog. The disarm is gated on the
     *forward* beacon, NOT the structural verify alone (SMR M2 / AGY Hazard C
     refinement) — a kernel that verifies-structurally but can't forward is
     reverted, not kept.
   - On REJECT/error/timeout: does NOTHING to promote; issues a clean reboot
     (or lets the watchdog fire) → boots the known-good default → the known-good
     Linux clears the candidate marker → dataplane restored. No boot-loop.
6. The candidate kernel package, if not promoted, is pruned (`apt-get purge` the
   un-promoted `linux-*` version) by the `pkg/upgrade` GC (SMR M3 / AGY Hazard
   E) — both to free `/boot` and to avoid accrual.

**Honest bound (do not soften):** "never brick on early hang" holds ONLY with a
persistent firmware/hypervisor watchdog (invariant 3) AND the userspace-cleared
one-shot substrate (invariant 2). With neither, LANE 1 is UNAVAILABLE and the
pre-assert refuses to arm — there is no half-safe mode that silently bricks.

#### 3.1-HA — HA orchestration is EXTERNAL, not in-process `rolling.go`

`pkg/upgrade/rolling.go`'s `RunRolling` (verified runner.go/rolling.go:62-82)
does drain → **STOP→FLIP→START** (a fast in-process binary cut) → restore, all
inside ONE local Go process. A kernel bump's "act" is a **reboot**, which kills
that process mid-sequence (SMR B1 / AGY Hazard B): the node would come up still
`ForceSecondary`-drained, never calling `ResetFailover`, and if a driver blindly
upgrades node B next, **both nodes are down → full outage**. Therefore LANE 1 HA
is driven by an **external orchestrator** (`scripts/deploy/xpf-deploy.py`, the
#1879 deploy driver) that survives node reboots:

```
drain node A (ForceSecondary) -> confirm peer B holds PRIMARY for all RGs ->
arm candidate + watchdog on A -> reboot A -> POLL A until it boots, verifies,
promotes (or reverts) -> confirm A healthy + rejoined + sync re-established ->
ResetFailover A (rejoin as eligible) -> ONLY THEN repeat for node B.
```

The in-guest `xpfd upgrade kernel` handles ONE node's local
arm/verify/promote/revert; the cross-node sequencing + "never both down" gate is
the external driver's job. `pkg/upgrade/rolling.go` is reused for the *binary*
cut (#1917) but NOT for the *kernel* reboot cut. INC-2 implements the external
driver's kernel-rolling sequence + the post-reboot rejoin-confirm gate.

### 3.2 LANE 2 — image-replace for heavy/uncertain kernel moves (Path C)

A new kernel *series* (the shim has never been verified against it), or a kernel
arriving as part of a base-OS upgrade, goes through the fully-tested image
substrate: `bake.py` produces a new image with the new kernel (verify-dataplane
gated at bake AND validate.py boot-gate), `xpf-deploy.py` swaps it in.
- **HA:** replace secondary node's image → failover (VRRP demote, ~60ms) →
  replace primary → fail back.
- **Standalone:** documented reboot gap (image swap + factory boot).

**Mixed-base HA session survival is GATED, not assumed (r1 Codex Finding 7).**
The v1 claim "connections survive via session-sync" was an overclaim. An
image-replace can move the **xpf version AND the base** on the replaced node
while the peer still runs the old image — a *mixed-base* cluster. The existing
guard (`rolling.go:109` / `docs/in-place-upgrade.md:147`) only checks the
*running local↔peer* HA protocol AFTER a mixed cluster already exists, and only
for the binary rolling cut — it does NOT introspect a *staged new image's* HA
protocol before the swap. #1930 therefore REQUIRES, before the LANE-2 HA swap of
the second node: (a) introspect the new image's HA/session-sync protocol version
and **fail-closed if it is not back-compatible with the still-running peer**
(fall to "replace both nodes, connections drop, documented"); (b) extend the
mixed-base session-sync + failover validation in the test plan (§10). Only with
that gate PASS does the plan claim connection survival; otherwise it is a
documented connection-drop. No new *forwarding* mechanism — this is #1879 +
#1917 Path C reused — but the **mixed-base compatibility gate is new** and is
INC-3's responsibility. #1930's contribution to LANE 2 is the **decision rule**
("series change ⇒ LANE 2"), the **mixed-base gate**, and the operator doc.

### 3.3 LANE 3 — base-OS major-version upgrade (Ubuntu N → N+1)

**Default: image-replace (LANE 2).** A baked N+1 image carries the new kernel,
glibc, systemd, FRR, strongSwan, kea, chrony as one tested unit, gated by
`validate.py`. This is the recommended, supported path. What must carry across
the swap (the appliance state contract — already preserved by #1879/#1917):
- the xpf `.deb` (re-installed into the N+1 image at bake time),
- `/etc/xpf/.configdb` (config DB — the in-place upgrade already snapshots +
  validates this; #1917 §8 config-DB version manifest gates a too-old reader),
- `/etc/xpf/node-id` (HA identity),
- `master.key` (config encryption),
- the day-0 config drive + fxp0 DHCP factory bootstrap (#1879).
Validation: `validate.py` factory-boot + in-guest `verify-dataplane` + a forward
probe on the N+1 base proves xpf still loads + forwards.

**In-place `do-release-upgrade` is UNSUPPORTED (r1 SMR M4 + AGY Hazard D — both
reviewers converged to drop it).** It is removed from the design rather than
offered as a fragile escape hatch, because: (a) it modifies the entire userspace
(glibc, systemd, FRR, strongSwan, kea, xpfd) in-place and **irreversibly** —
there is no rollback if the new userspace fails to forward; (b) constrained with
`apt-mark hold linux-*` it leaves the release **half-upgraded** (the release
upgrader expects to own the kernel); (c) it can leave the box running **N+1
userspace on the old N kernel** (the AGY Hazard-D mixed-state brick) where the
new xpfd/shim may not verify on the old kernel → config-only mode with no
automated restore; (d) it cannot be tested in CI. `docs/` will state plainly:
**"In-place base-OS major upgrade (`do-release-upgrade`) is UNSUPPORTED on the
appliance — re-image (LANE 2 / Path C). Operators who run it anyway do so at
their own risk and should re-image afterward."** A documented *unsupported* path
is safer than a documented *fragile* one.

---

## 4. Multiple Path Options (where the design genuinely branches)

### Path Option A — one-shot-boot revert substrate for LANE 1
The r1 reviewers (all three) killed the v1 "A1 = GRUB grubenv one-shot"
recommendation: GRUB cannot clear its own one-shot flag at boot on this image
(ext4 `metadata_csum` + Secure Boot, §2 invariant 2) → boot-loop. The substrate
is re-evaluated; **the discriminator is "what clears the candidate request so a
reset goes back to known-good without re-entering the candidate."**

| Option | Mechanism | Clears one-shot how? | Verdict |
|---|---|---|---|
| **A1 (v1, KILLED): GRUB grubenv one-shot, GRUB clears at boot** | `grub-reboot <cand>`, GRUB `save_env next_entry=` at boot. | GRUB-at-boot — **FAILS** on ext4 `metadata_csum` / Secure Boot → boot-loop. | **REJECT** (r1 unanimous). |
| **A1' (RECOMMENDED): pinned known-good default + Linux-cleared candidate marker** | `GRUB_DEFAULT` pinned to a STABLE known-good menuentry id (never moves on apt kernel install). Candidate requested via a marker GRUB reads once; the **known-good boot's early Linux unit** (initramfs/early systemd) clears the marker (Linux ext4 writes `metadata_csum` fine; `grub-editenv` from userspace writes fine). Promote = `grub-set-default <cand-id>` from Linux on verify+health PASS. | **Linux userspace**, never GRUB-at-boot. A reset → known-good default boots → known-good Linux clears marker → no re-entry → no loop. | **RECOMMENDED.** |
| **A2 (KILLED): softdog** | Software watchdog only. | N/A — softdog can't fire pre-load AND is disarmed by clean reboot (§2 invariant 3). | **REJECT** (r1 AGY Hazard C). |
| **A3 (future): systemd-boot boot-counting on the ESP** | Switch bootloader to systemd-boot; native tries-counter writes EFI vars / ESP (FAT32, writable under Secure Boot). | Firmware/ESP-owned counter; brick-safe by design. | **DEFER** — switching the appliance bootloader is a large separate change; boot-counting reverts on *boot* failure not *verify* failure (a kernel that boots but REJECTs the shim would be miscounted "good" unless the promotion unit explicitly fails the boot on REJECT). Noted as the clean long-term answer if/when the image moves to systemd-boot + UKI. |

**Recommendation: A1'** for this issue (works with the GRUB bootloader the image
already has, and is brick-safe because the clear is done by Linux, not GRUB),
**plus the persistent-watchdog requirement** (firmware/BMC/hypervisor watchdog
with `nowayout`, OR initramfs early-arm) for the early-hang guarantee. A3 is the
documented future direction. The pre-assert (§3.1) refuses to arm LANE 1 if
neither a persistent watchdog nor the A1' clear-substrate is present.

### Path Option B — base-OS major upgrade
| Option | Mechanism | Verdict |
|---|---|---|
| **B1: image-replace only** | Bake N+1 image (validate.py-gated); `xpfd`-driven `xpf-deploy.py` swap; HA mixed-base gate (§3.2). | **RECOMMENDED — the ONLY supported path.** |
| **B2: `do-release-upgrade` in-place** | Ubuntu release upgrader. | **DROPPED / UNSUPPORTED** (r1 SMR M4 + AGY Hazard D + Codex F8 — unanimous). Irreversible userspace move; half-upgraded under kernel hold; N+1-userspace-on-N-kernel mixed-state brick; untestable. Documented as "unsupported, re-image instead." |

**Recommendation: B1 only.** B2 is explicitly unsupported (not a gated escape
hatch — the reviewers showed the gated form is incoherent). The appliance model
is image-replace-first.

### Path Option C — kernel hold scope
| Option | What is held | Verdict |
|---|---|---|
| **C1: `apt-mark hold linux-*`** | All `linux-*` packages. | RECOMMENDED — broad, simple, and the kernel channel explicitly unholds/reholds around a controlled install. |
| **C2: pin a kernel meta-package channel** | A dedicated tested kernel track. | More complex; no signed track exists (depends on #1924). Defer. |

**Recommendation: C1** for this issue; C2 noted as a future once #1924 lands a
signed repo.

---

## 5. Implementation increments (sequenced, each independently shippable)

> All increments are **#1930 design**; this plan stops at PLAN-READY. The
> increments below are the proposed `/engineer 1930` work breakdown.

- **INC-0 (image hardening, no daemon code, closes the biggest hole alone):**
  `bake.py` adds `apt-mark hold linux-*` after the single-kernel assert; pins
  `GRUB_DEFAULT` to the STABLE known-good menuentry id (NOT `0`/saved-without-a-
  pinned-entry — Codex F2/F5, SMR B2/B3) and ensures `GRUB_SAVEDEFAULT` unset;
  installs the **persistent-watchdog** config (firmware/hypervisor + `nowayout`,
  with initramfs early-arm as the fallback) and the **A1' one-shot clear
  substrate** (the early-Linux marker-clear unit); disables
  `unattended-upgrades` for `linux-*`; ships the `needrestart` blacklist
  covering the kernel-channel window. This alone closes "unattended apt moves
  the floor." (Ship FIRST.)
- **INC-1 (LANE 1 in-guest mechanism):** `pkg/upgrade` kernel verb + `xpfd
  upgrade kernel <ver>`: **pre-asserts** (pinned stable default id resolves;
  persistent watchdog OR initramfs early-arm present; free `/boot` ≥ image+
  initramfs+margin BEFORE install — Codex F6/SMR M3; A1' clear-substrate
  present) → unhold→install→rehold → **re-assert pinned default did NOT move
  after the candidate dpkg postinst's `update-grub`** (Codex F2/SMR B2) →
  resolve candidate to a STABLE menuentry id from the regenerated `grub.cfg`
  (Codex F5/SMR B3) → write Linux-cleared one-shot marker → confirm watchdog →
  reboot. Promotion oneshot systemd unit: `verify-dataplane` → **forward** health
  beacon → only-on-beacon-PASS `grub-set-default <cand-id>` + durable marker +
  clear one-shot + disarm watchdog; else clean reboot to known-good. Journal +
  GC prune of un-promoted candidate kernel (Codex F6/AGY E). Single command
  name `xpfd upgrade kernel` (Codex F9).
- **INC-2 (LANE 1 HA — EXTERNAL orchestration):** the cross-node kernel-rolling
  sequence + "never both down" gate lives in `scripts/deploy/xpf-deploy.py` (it
  survives node reboots — Codex F4/SMR B1/AGY B), NOT in-process `rolling.go`.
  Implements: drain A → confirm peer holds all RGs → arm+reboot A → poll A until
  booted+verified+promoted (or reverted) → confirm rejoin + sync re-established →
  `ResetFailover` A → only then node B. Add a **cluster-wide lock so two nodes
  cannot start kernel lanes concurrently** (Codex F4). `pkg/upgrade/rolling.go`
  unchanged (it remains the binary-cut path).
- **INC-3 (LANE 2/3 — image-replace + mixed-base gate + base-OS doc):** add the
  **mixed-base HA compatibility gate** (introspect the new image's HA/session-
  sync protocol; fail-closed to documented connection-drop if not back-compat
  with the running peer — Codex F7); operator playbook in a new
  `docs/os-kernel-upgrades.md` (3-lane decision tree, B1 image-replace base-OS
  procedure via `xpf-deploy.py`, the do-release-upgrade UNSUPPORTED statement,
  the state-carry contract); extend `docs/in-place-upgrade.md:169` to link it.
- **INC-4 (validation — the NEW path, not regression):** (a) live LANE 1 happy +
  **deliberate-REJECT revert** proof (the brick-proof proof — old kernel boots,
  marker cleared by Linux, dataplane restored, NO operator action) on the
  wipeable standalone test VM; (b) mixed-base session-sync + failover validation
  (Codex F7); (c) a baked N+1-base image factory-boots + forwards (validate.py);
  (d) unit tests for the pre-assert/journal/revert state machine.

---

## 6. Risks + mitigations

| # | Risk | Mitigation |
|---|---|---|
| 1 | **GRUB-grubenv one-shot boot-loop** (r1 unanimous FATAL). GRUB can't clear `next_entry` at boot under ext4 `metadata_csum` / Secure Boot → failing candidate re-entered forever. | **A1' substrate:** pinned known-good default + candidate marker cleared by **Linux userspace** on the known-good boot, never by GRUB-at-boot. §2 invariant 2 / §3.1. |
| 2 | **dpkg `linux-image` postinst `update-grub` moves the default** before `grub-reboot` is armed (r1 SMR B2 / Codex F2). | Pin `GRUB_DEFAULT` to a STABLE known-good menuentry id; re-assert it did NOT move after the candidate install; only `grub-set-default` to the candidate on verify+health PASS. |
| 3 | **`grub-reboot <ver>` picks the wrong/no entry** after `update-grub` reorders the submenu (r1 SMR B3 / Codex F5). | Resolve the candidate to a STABLE menuentry **id** from the regenerated `grub.cfg` and assert it exists before arming; never a numeric index/title. |
| 4 | **Watchdog disarmed by clean shutdown → early candidate boot unprotected** (r1 AGY Hazard C / Codex F3). | Require a **persistent** firmware/BMC/hypervisor watchdog (`nowayout`) that the OS reset cannot disarm, OR an initramfs early-arm hook; pre-assert presence; honest bound = guarantee only as early as the watchdog is armed. |
| 5 | **HA in-process `rolling.go` dies at the reboot it sequences → node stuck drained, both-down if driver proceeds** (r1 SMR B1 / AGY Hazard B / Codex F4). | LANE 1 HA orchestration is **EXTERNAL** (`xpf-deploy.py`, survives reboots) with a post-reboot rejoin-confirm gate + a cluster-wide kernel-lane lock. §3.1-HA. |
| 6 | **Candidate boots but REJECTs/can't-forward the shim** (verify-structural ≠ forwards). | Promotion gated on the **forward health beacon**, not just structural `verify-dataplane`; disarm only on beacon PASS (r1 SMR M2). |
| 7 | **`/boot` exhaustion / failed initramfs / broken apt state** during candidate install (r1 SMR M3 / Codex F6 / AGY E). | Pre-assert free `/boot` ≥ image+initramfs+margin and **prune BEFORE install**; validate `update-initramfs`/`update-grub` succeed; GC `apt-get purge` of un-promoted candidate kernels. |
| 8 | **Secure Boot refuses an unsigned candidate kernel** (r1 SMR M1). | State the appliance Secure Boot posture; scope LANE 1 to Canonical-signed `apt` kernels; an unsigned candidate fails cleanly to GRUB (recoverable), document it. |
| 9 | **`needrestart` cuts the dataplane mid-apt** during the candidate install. | `/etc/needrestart/conf.d/xpf.conf` blacklist; verify it covers an apt-driven `linux-*` install (extend the #1917 §6.3c blacklist). |
| 10 | **LANE 2 mixed-base HA drops connections** — new-image HA protocol not introspected before the swap (r1 Codex F7). | Pre-swap mixed-base compatibility gate; fail-closed to a documented connection-drop if not back-compat with the running peer (INC-3). Do NOT claim survival without the gate. |
| 11 | **`apt-mark hold` defeated by unattended-upgrades.** | Bake disables `unattended-upgrades` for `linux-*`; kernel CVEs flow through LANE 1, not unattended-upgrades. |
| 12 | **Config-DB rollback across an OS/kernel move** — new binary writes config the reverted binary can't parse. | #1917 §8 embedded config-DB version manifest (min-reader gate); #1930 must not regress it; INC-4 validates a revert re-reads the DB. |
| 13 | **`do-release-upgrade` mixed-state brick** (N+1 userspace on N kernel; irreversible). | DROPPED/UNSUPPORTED (r1 unanimous). LANE 3 = image-replace only. |
| 14 | **Installed-kernel + `/var/lib/xpf/versions/` accumulation** fills `/var`/`/boot`. | #1917 §6.3c retention + kernel-channel prune of un-promoted candidate packages (mandatory — `/boot` is small). |

---

## 7. Preserved interfaces (must not change)

- `xpfd verify-dataplane` exit-code contract (0 PASS / 3 REJECT / 1 error) — the
  promotion oneshot depends on it.
- `VerifyEmbeddedUserspaceShim` semantics (anonymous, never-attach, never-pin) —
  the kernel channel verifies via this, not a bespoke loader.
- The #1864 toolchain pin + verifier floor (≥ 6.18) — LANE 1 never lowers it.
- `pkg/upgrade` journal / atomic-flip / rollback primitives — the kernel verb is
  a sibling state machine, not a rewrite.
- `pkg/upgrade/rolling.go` drain/act/restore HA primitive — reused UNCHANGED for
  the #1917 *binary* cut. The LANE 1 *kernel reboot* cut is NOT run through it
  (it dies at the reboot — §3.1-HA); kernel HA sequencing is external.
- `bake.py` single-kernel assert + ≥6.18 floor + modules-extra assert — INC-0
  adds to these, never removes them.
- The day-0 config drive + `/etc/xpf` state contract (`.configdb`, `node-id`,
  `master.key`) — carries across all lanes unchanged.
- #1917 §6.5 session-sync wire back-compat rule — LANE 2 HA image-replace
  depends on it AND on the new pre-swap mixed-base compatibility gate (§3.2).

---

## 8. Hidden invariants / gotchas

- **verify-dataplane is kernel-space** — cannot validate an unbooted kernel.
  This is THE invariant forcing one-shot-boot over verify-first (§2 inv 1).
- **GRUB cannot clear its own one-shot at boot on this image** (ext4
  `metadata_csum` / Secure Boot) — the candidate marker MUST be cleared from
  Linux userspace, and the known-good default must be a STABLE pinned menuentry
  id that the dpkg kernel postinst's `update-grub` does not move (§2 inv 2,
  risks #1/#2/#3).
- **A clean reboot disarms a non-persistent watchdog** — only a firmware/
  hypervisor watchdog (or initramfs early-arm) protects the candidate's early
  boot; softdog does not (§2 inv 3, risk #4). Do not overclaim "never brick."
- **The shim travels embedded in xpfd** (`//go:embed`), so a kernel move does
  NOT change the shim bytes — only whether the *running kernel* accepts them.
  The verify is against the kernel, with the xpf version fixed.
- **HA both-node reboot = full outage** — kernel moves MUST be one-at-a-time via
  the EXTERNAL orchestrator (not in-process `rolling.go`, which dies at reboot);
  external driver holds a cluster-wide kernel-lane lock (risk #5).
- **`bake.py` GRUB drop-in lives in `/etc/default/grub.d/99-xpf.cfg`** (Ubuntu
  cloudimg overrides `/etc/default/grub` via `50-cloudimg-settings.cfg`) — the
  `GRUB_DEFAULT=<stable-known-good-id>` pin MUST go in the drop-in too (with a
  higher-numbered filename than cloudimg's), not a sed on the main file, or
  cloudimg clobbers it. Verify `GRUB_DISABLE_SUBMENU`/`GRUB_DEFAULT` interaction
  yields a resolvable stable id.
- **`apt-mark hold` is per-package-name** — `linux-*` glob must cover
  `linux-image-*`, `linux-headers-*`, `linux-modules-*`, `linux-generic`, and
  the meta-packages; verify the hold actually pins what apt would move.

---

## 9. Acceptance criteria (for `/engineer 1930`, NOT this research)

1. INC-0: a deployed image has `linux-*` held; `apt upgrade` does not move the
   kernel; `GRUB_DEFAULT` pins a stable known-good id; `GRUB_SAVEDEFAULT` unset;
   persistent watchdog + A1' clear substrate present; `unattended-upgrades`
   excludes `linux-*`.
2. LANE 1 happy path: `xpfd upgrade kernel <ver>` on a same-series candidate
   boots it once, verify+forward-beacon PASS, candidate promoted, dataplane
   forwards; pinned default did NOT move at install time.
3. LANE 1 brick-proof: a deliberately-REJECTing candidate is reverted — the box
   boots the known-good kernel, Linux clears the candidate marker, dataplane
   restored, NO manual intervention, NO boot-loop (with persistent watchdog).
4. LANE 1 HA: the external orchestrator never has both nodes down; a node stuck
   reverted does not advance the sequence; traffic survives (failover-test green).
5. LANE 2 mixed-base gate: an incompatible new-image HA protocol fails the
   pre-swap gate (documented drop), a compatible one survives session-sync.
6. LANE 3: a baked N+1-base image factory-boots and forwards (validate.py
   green); state contract (`.configdb`/`node-id`/`master.key`) carries;
   do-release-upgrade documented UNSUPPORTED.
7. Docs: 3-lane decision tree + playbook in `docs/os-kernel-upgrades.md`,
   linked from `docs/in-place-upgrade.md`.

---

## 10. Test plan

- **Unit:** `pkg/upgrade` kernel-verb state-machine tests (mirror
  `runner_test.go`/`rolling_test.go`): pre-assert failures abort cleanly;
  journal crash-recovery resumes; revert path leaves default unchanged.
- **Image:** `bake.py` produces an image with held kernel + pinned stable
  default + persistent-watchdog + A1' clear substrate; asserts catch a missing
  hold, a moved default, or a missing watchdog.
- **Live — STANDALONE wipeable test VM (`xpf-fw`, `make test-vm`/`test-deploy`),
  NOT the shared loss cluster's primary:** this is where the NEW boot channel is
  actually exercised end-to-end (per the §10 directive — passing regression
  tests proves no-regression, NOT that the new channel works):
  - LANE 1 happy: drive a real same-series candidate through arm → one-shot boot
    → verify+forward-beacon → promote; capture evidence (booted kernel version,
    promotion marker, dataplane forwards).
  - LANE 1 **deliberate-REJECT revert**: arm a candidate the shim rejects (or
    force a verify fail), confirm the box reboots to the known-good kernel, the
    Linux marker-clear ran, NO boot-loop, dataplane restored — the brick-proof
    proof. This is mandatory live evidence.
  - Watchdog path: force an early-boot hang (or simulate), confirm the
    persistent watchdog resets to known-good (where the test VM exposes one;
    otherwise document the limitation and rely on the initramfs-early-arm unit
    test + a hypervisor-watchdog manual check).
- **Live — HA:** mixed-base session-sync + the external-orchestrator
  rejoin-confirm + "never both down" sequence on a wipeable two-VM env (NOT the
  shared loss primary).
- **Base-OS:** bake an N+1 image in a scratch env, `validate.py` boot+forward
  gate, confirm state carry. A real Ubuntu N→N+1 `do-release-upgrade` is NOT
  tested (it is UNSUPPORTED by design — §3.3).
- **Negative:** no-persistent-watchdog / no-clear-substrate platform → `xpfd
  upgrade kernel` aborts with the "use image-replace" message (refuses to arm).

---

## 11. Recommendation (to be ratified by the 3 reviewers)

Ship #1930 as **three lanes by blast radius**, defaulting to image-replace and
treating in-place kernel moves as a tightly-gated channel:

- **LANE 1** (same-series kernel CVE bumps): verify-gated one-shot-boot via
  **Path Option A1'** — pinned known-good default + **Linux-cleared** candidate
  marker (NOT GRUB-clears-its-own-flag, which boot-loops on ext4 `metadata_csum`
  / Secure Boot) + a **persistent firmware/hypervisor watchdog** (or initramfs
  early-arm). Held-by-default kernel; promotion gated on a **forward** health
  beacon; HA sequencing is **EXTERNAL** (`xpf-deploy.py`, survives reboots), not
  in-process `rolling.go`. Refuses to arm without the watchdog + clear substrate.
- **LANE 2** (new kernel series / heavy moves): image-replace (Path C, #1879) —
  decision rule + the new **pre-swap mixed-base HA compatibility gate**.
- **LANE 3** (base-OS N→N+1): **image-replace ONLY (Path Option B1)**.
  `do-release-upgrade` is **UNSUPPORTED** (documented, not offered as a hatch).

Start with **INC-0** (image hardening — closes the unattended-apt hole with no
daemon code), then INC-1 (LANE 1 in-guest mechanism), INC-2 (external HA
orchestration), then INC-3/4 (LANE 2/3 gate + base-OS doc + live validation).

### r1 → v2 disposition (what changed and why)
All three r1 reviewers (Claude SMR, AGY, Codex) returned PLAN-NEEDS-WORK and
converged on the same three FATALs plus overlapping MAJORs. v2 dispositions:
- **GRUB one-shot boot-loop** (SMR B2/B3, AGY Hazard A, Codex F2): A1 GRUB-grubenv
  one-shot KILLED → A1' Linux-cleared marker + pinned stable default. §2 inv 2,
  §3.1, Path A, risks #1/#2/#3.
- **Watchdog disarm on clean reboot** (AGY Hazard C, Codex F3): persistent
  firmware/hypervisor watchdog (or initramfs early-arm) required; softdog
  rejected. §2 inv 3, §3.1, risk #4.
- **HA rolling.go dies at reboot** (SMR B1, AGY Hazard B, Codex F4): external
  orchestration + rejoin-confirm gate + cluster lock. §3.1-HA, INC-2, risk #5.
- **/boot + initramfs + dpkg preflight** (SMR M3, Codex F6, AGY E): prune-before-
  install + capacity assert + GC purge. INC-1, risk #7.
- **Pinned-default not moved by dpkg postinst** (SMR B2, Codex F2/F5): stable
  menuentry id + post-install re-assert. INC-1, risks #2/#3.
- **Forward-beacon gating** (SMR M2): disarm/promote on forward beacon, not
  structural verify alone. §3.1, risk #6.
- **Secure Boot posture** (SMR M1): stated; LANE 1 scoped to Canonical-signed
  kernels. Risk #8.
- **LANE 2 mixed-base overclaim** (Codex F7): pre-swap compatibility gate; no
  survival claim without it. §3.2, INC-3, risk #10.
- **do-release-upgrade** (SMR M4, AGY Hazard D, Codex F8): DROPPED/UNSUPPORTED.
  §3.3, Path B, risk #13.
- **Command name** (Codex F9): normalized to `xpfd upgrade kernel`.
