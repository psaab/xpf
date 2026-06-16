# #1930 — Major underlying VM/OS + kernel upgrades (plan-of-action)

- **Issue:** #1930 (deferred from #1917)
- **Status:** v3 — folds r2 reviews (Claude SMR B4 + AGY converged
  PLAN-NEEDS-WORK on the SAME residual brick-loop). LANE-1 one-shot revert moves
  to **UEFI `BootNext`** (firmware clears it before boot → watchdog reset
  auto-falls-back to known-good `BootOrder`, no bootloader write — closes the
  boot-LOOP unconditionally). Watchdog reframed as the hang→reset trigger (not
  the chooser); honest hardware-dependence stated. External HA orchestrator gets
  version-check anchor + leased lock + bounded local self-recovery. LANE-2
  mixed-base gate gets a concrete non-boot version-read (bake version manifest).
  apt-mark/GRUB-submenu/secure-boot-lockout fixes folded.
  (v2 folded r1: GRUB-grubenv KILLED, watchdog-disarm, rolling.go-death,
  do-release-upgrade DROPPED, /boot prune, forward-beacon, mixed-base gate.)
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
| `scripts/image/bake.py` | virt-customize: installs `linux-generic`, **HARD-ASSERTs newest kernel ≥ 6.18**, asserts `linux-modules-extra` (mlx5/i40e), purges all-but-newest kernel + **asserts exactly one kernel**, GRUB drop-in (`/etc/default/grub.d/99-xpf.cfg` = `init_on_alloc=0` only), build-host `verify-dataplane` pre-gate. | The **image-replace substrate** (Path C) + the place to add the kernel hold (`apt-mark hold $(dpkg-query …)`), `GRUB_DISABLE_SUBMENU=y` + pinned stable known-good default, the persistent-watchdog config, the UEFI `BootNext` per-kernel boot entries, the promotion oneshot unit, and the image **version manifest** (LANE-2 mixed-base gate). |
| `scripts/deploy/xpf-deploy.py` | `deploy`/`launch`/`inventory` + `deploy_rolling()` at **VM granularity** (recreate from image + day-0 ISO of `xpf.conf`+`node-id`). Does NOT do an in-place base-OS swap or a rejoin-confirm gate today. | LANE 2 reuses `deploy_rolling()` (recreate-from-image) and ADDS the rejoin-confirm + mixed-base + kernel-rolling gates (INC-2/3). Do not over-attribute live-swap capability (r2 Codex NEW-F12). |
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
      -> LANE 3: image-replace ONLY (carries kernel inside).
                 In-place do-release-upgrade is UNSUPPORTED (dropped r1
                 unanimous — irreversible userspace move, mixed-state brick;
                 see §3.3 + Path Option B). Re-image instead.
```

### 3.1 LANE 1 — verify-gated one-shot-boot kernel channel (in-place)

The mechanism is built around the three invariants of §2. The two parts that
changed from v1 are the **one-shot-revert substrate** (now UEFI `BootNext`, NOT
any GRUB-cleared or Linux-cleared marker — invariant 2) and the **HA
orchestration** (no longer the in-process `rolling.go` — §3.1-HA below).

**One-shot-revert substrate — UEFI `BootNext` (resolves invariant 2 — brick-loop;
r2 SMR B4 + AGY converged):** v2's "A1'" (a `next_entry` marker cleared by
Linux) was KILLED in r2 because it still boot-loops on an *early-hang* candidate:
GRUB cannot clear `next_entry` on this image (ext4 `metadata_csum` / Secure
Boot), so a watchdog reset re-reads the still-set marker and re-enters the hung
candidate forever — the "known-good boot's Linux clears it" step is never
reached. **The fix is the standard UEFI one-shot: `BootNext`.** UEFI Boot
variables live in firmware NVRAM (writable from Linux via `efibootmgr`, and OK
under Secure Boot for variable writes); critically, **the UEFI boot manager
itself clears `BootNext` before handing control to that entry** — so a candidate
that hangs and is watchdog-reset comes up with `BootNext` already gone, and the
firmware falls through to the permanent `BootOrder`, which points at the
**known-good** entry. No bootloader write is needed at the failing-boot moment;
the clear happened in firmware before the hang. Concretely (Path Option A1'',
rewritten):
- Each kernel gets its **own UEFI boot entry** (or one GRUB entry whose target
  is selected via a stable GRUB id — but the SELECTION is via `BootNext` to a
  per-kernel UEFI entry, or via a GRUB id that GRUB reads from a one-shot it does
  NOT have to clear, because the firmware already cleared `BootNext`). The
  appliance's permanent `BootOrder` lists the **known-good** entry first.
- A kernel bump: `efibootmgr --create` a boot entry for the candidate (if not
  using a single shim+GRUB entry), then `efibootmgr --bootnext <candidate>` to
  request it ONCE. The permanent `BootOrder` is NOT changed. Promotion = on
  verify+forward PASS, `efibootmgr --bootorder` puts the candidate first
  (durable). The known-good entry stays in `BootOrder` as the rollback target.
- If the single-shim+GRUB topology is kept (one UEFI entry → GRUB → menu), the
  one-shot must still be firmware-owned: use `BootNext` to a **second** UEFI
  entry that chainloads GRUB with a candidate-selecting argument, OR move the
  GRUB grubenv to the **FAT32 ESP** (GRUB *can* write FAT — no `metadata_csum`),
  so GRUB's own `save_env next_entry=` succeeds and the one-shot is consumed
  reliably. Either keeps the clear OFF the un-writable ext4 path. **The plan
  RECOMMENDS the `BootNext`-to-per-kernel-UEFI-entry form** (firmware clears it,
  zero bootloader-write dependency); the ESP-grubenv form is the fallback if
  per-kernel UEFI entries are impractical.
- **Stable GRUB id / submenu (r2 AGY new):** if GRUB still resolves the menu,
  set `GRUB_DISABLE_SUBMENU=y` in `/etc/default/grub.d/99-xpf.cfg` so candidate
  entries are top-level and the menuentry id is directly resolvable; otherwise
  `grub-reboot`/`set default` must use the hierarchical `gnulinux-advanced-…>…`
  id. `GRUB_DEFAULT` is pinned to the stable known-good id and re-asserted
  unchanged after the candidate dpkg postinst's `update-grub` (SMR B2).
- **Secure Boot lockout (r2 AGY new):** an *unsigned* candidate under Secure
  Boot is refused by firmware and, with `BootNext` already cleared by firmware,
  the next reset falls back to known-good (no lockout loop — another reason
  `BootNext` is correct over `next_entry`). LANE 1 is still scoped to
  Canonical-signed `apt` kernels (risk #8); the `BootNext` substrate makes an
  accidental unsigned candidate fail SAFE rather than brick.

**Persistent-watchdog requirement (resolves invariant 3 — clean-shutdown
disarm):** with `BootNext` the firmware already falls back to known-good on ANY
reset, so the *boot-loop* is closed even without a watchdog. The watchdog's job
narrows to **turning an early-boot HANG into a reset** (so the firmware fallback
can fire) — it is the trigger, not the chooser. That still requires a watchdog
that **persists across the OS reset**: a firmware/BMC/hypervisor watchdog with
`nowayout=1`, OR an initramfs early-arm. **Honest limitation (r2 AGY):** (a) an
initramfs hook cannot protect a hang *before* initramfs (decompression / early
CPU / ACPI); (b) many board/BMC watchdogs are reset by the CPU reset line on a
warm reboot, and `nowayout=1` only stops *userspace* from disarming — it does
not guarantee the timer survives the OS reset; (c) there is **no portable Linux
API to verify** a given watchdog survives a warm reset. THEREFORE the "never
brick on early hang" guarantee is **hardware/hypervisor-dependent and cannot be
asserted purely in software**. The pre-assert checks for a watchdog device and
the platform-capability flag the bake records (hypervisor/BMC watchdog known to
persist); absent a *verified-persistent* watchdog, the pre-assert WARNS that
early-hang protection is best-effort and (per the operator's strictness choice —
Path Option D) either proceeds with the `BootNext` firmware-fallback as the only
safety net (loop closed, but an early hang needs the watchdog OR a console reset)
or fail-closed to LANE 2. The boot-LOOP is closed by `BootNext` regardless; only
the early-HANG auto-recovery depends on the watchdog.

**Mechanism sequence:**

1. **Default posture: hold the kernel** (added to `bake.py`, INC-0). Use a
   concrete package query, NOT a shell glob (r2 AGY — `apt-mark hold linux-*`
   shell-expands against the cwd and fails): `apt-mark hold $(dpkg-query -W
   -f='${Package}\n' 'linux-*')`. `unattended-upgrades` is also configured to
   never touch `linux-*` (risk #11). A kernel bump is an explicit operator
   action.
2. Operator runs `xpfd upgrade kernel <candidate-version>` (new `pkg/upgrade`
   kernel verb). It **pre-asserts, fail-closed, before touching anything**:
   - UEFI boot is in use and `efibootmgr` works; the permanent `BootOrder`
     starts with the **known-good** entry; (if GRUB-resolved) `GRUB_DEFAULT`
     pins a STABLE known-good id and `GRUB_DISABLE_SUBMENU=y` (r2 AGY);
   - a watchdog device is present AND the bake's persistence-capability flag is
     set (or the operator's strictness choice — Path Option D — accepts
     best-effort early-hang protection);
   - **free `/boot`/ESP space** ≥ (candidate kernel image + initramfs + margin)
     BEFORE installing (SMR M3 / AGY E — prune-before-install);
   - the promotion oneshot + watchdog-arm units are installed.
   Any failed assert → ABORT ("kernel channel not armed; use image-replace /
   LANE 2").
3. `apt-mark unhold` the kernel set → install the candidate kernel package(s)
   (verify `update-initramfs` + `update-grub` succeeded — r2 AGY/SMR M3) →
   re-hold. **Re-assert** the permanent `BootOrder`/`GRUB_DEFAULT` known-good
   entry did NOT move after the candidate postinst's `update-grub` (SMR B2). The
   candidate is installed but NOT the permanent boot order.
4. **Request the candidate ONCE via firmware:** `efibootmgr --bootnext
   <candidate-entry>` (firmware clears it before boot — invariant 2). Arm/confirm
   the watchdog. Reboot.
5. On the candidate boot, a **promotion oneshot systemd unit** runs early,
   before xpfd's `ExecStartPre` admits traffic:
   - Asserts `uname -r` actually equals the candidate (a `BootNext` that the
     firmware ignored or fell back from must NOT be mistaken for a candidate
     boot — also the HA version-check anchor, §3.1-HA / r2 AGY).
   - Runs `xpfd verify-dataplane` against the running candidate kernel (0 PASS /
     3 REJECT / 1 error).
   - On PASS: runs a **bounded** (tight budget — r2 AGY standalone-outage)
     **forward health beacon** probing a STABLE destination (HA peer link, not
     an external gateway — r2 AGY). **Only on beacon PASS** does it promote
     (`efibootmgr --bootorder` candidate-first / durable `grub-set-default`),
     write a durable promotion marker, and disarm the watchdog. Disarm/promote
     gated on the *forward* beacon, not structural verify alone (SMR M2).
   - On REJECT/error/timeout: does NOT promote; issues a clean reboot. Because
     `BootNext` was already consumed by firmware, the reboot falls through
     `BootOrder` to the **known-good** entry → dataplane restored. No boot-loop.
6. The candidate kernel package, if not promoted, is pruned (`apt-get purge` the
   un-promoted version) by the `pkg/upgrade` GC (SMR M3 / AGY E) — frees
   `/boot`, avoids accrual, and removes the candidate UEFI boot entry.

**Honest bound (do not soften):** with `BootNext` the **boot-LOOP is closed
unconditionally** (firmware-cleared one-shot + permanent known-good `BootOrder`).
The remaining gap is an early-boot **HANG** with NO watchdog: the box sits hung
until an external/console reset, after which `BootNext` is already gone so it
boots known-good. "Never brick, fully unattended, on early hang" therefore holds
ONLY with a verified-persistent firmware/hypervisor watchdog; otherwise an early
hang is "recoverable with one external reset, no data loss, no loop." This is the
strongest honest claim — the loop (the true brick) is gone in all cases.

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

**External-orchestrator failure modes (r2 AGY — must be specified, not just
"external"):**
- **Version-check anchor (r2 AGY).** "POLL A until healthy" is INSUFFICIENT: a
  node that reverted boots the OLD kernel and looks "healthy," so the driver
  would wrongly advance to node B. The driver MUST assert A's **running kernel ==
  target** (`uname -r` / `xpfd version`) AND a durable promotion marker exists
  before proceeding. A reverted node = STOP the rolling drive, surface the revert,
  leave B untouched (cluster stays up on B-old / A-old — a clean abort, not an
  outage).
- **Orchestrator-crash / disconnect → orphaned drain (r2 AGY).** If the driver
  host dies while A is rebooting, A is left `ForceSecondary`-drained with no
  caller to `ResetFailover`. Mitigation: a **bounded local self-recovery** — if a
  node boots, finds itself drained AND there is no active upgrade lease naming it,
  AND the peer is healthy-primary, it auto-`ResetFailover`s after a timeout (it
  rejoins as eligible; VRRP preempt rules govern who is primary). This is a small
  daemon addition (gated, HA-only) and is called out as a sub-item of INC-2.
- **Cluster-lock storage + lease (r2 AGY).** The "never both down" lock is a
  **leased** entry (TTL) stored on a node-reachable store (e.g. a file in the
  cluster control-plane `em0` path / a cluster RPC), NOT only in the driver
  process — so a crashed driver's lock expires and is reclaimable; document where
  it lives and how a stale lease is broken. Without a lease, a driver crash wedges
  all future kernel lanes.

### 3.2 LANE 2 — image-replace for heavy/uncertain kernel moves (Path C)

A new kernel *series* (the shim has never been verified against it), or a kernel
arriving as part of a base-OS upgrade, goes through the fully-tested image
substrate: `bake.py` produces a new image with the new kernel (verify-dataplane
gated at bake AND validate.py boot-gate), and the deploy driver brings it up.

**Capability gap to close (r2 Codex NEW-F12):** today `scripts/deploy/
xpf-deploy.py` does `deploy`/`launch`/`inventory` + a `deploy_rolling()` that
operates at **VM granularity** (recreate/relaunch a VM from an image + day-0
drive), NOT an *in-place base-OS swap with a rejoin-confirm gate*. For VM/cloud
appliances "replace the image" = recreate the instance (boot disk swap), which
the existing rolling path supports; for bare-metal it is a re-flash. #1930 does
NOT invent a new in-place-base-OS-swap mechanism — it specifies that LANE 2 HA
reuses `deploy_rolling()` (recreate-from-new-image) and ADDS the rejoin-confirm +
mixed-base gate (INC-3) on top. The plan must NOT claim `xpf-deploy.py` already
performs a live in-place OS swap; it performs an image-granular recreate + day-0
re-apply, which is the supported "image-replace."
- **HA:** recreate secondary from the new image (day-0 re-applies `xpf.conf` +
  `node-id`) → it boots, verifies, rejoins → failover (VRRP demote, ~60ms) →
  recreate primary → fail back. Rejoin-confirm + version-check gate as §3.1-HA.
- **Standalone:** documented reboot/recreate gap (image swap + factory boot +
  day-0 re-apply).

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
documented connection-drop.

**How the gate reads a non-running image's protocol version (r2 AGY — must be
specified):** the new image already ships the `xpf` `.deb`; the
HA/session-sync protocol version is a **compile-time constant in the staged xpfd
binary** (`ProtocolVersion`/`CurrentHAProtocolVersion`, `pkg/dataplane/.../
protocol.go`). The gate extracts it WITHOUT booting the image: run the staged
binary's existing `xpfd version`/a new `xpfd protocol-versions` subcommand
against the binary unpacked from the image (the deploy host has the `.deb`/image
artifact), OR read a **manifest the bake writes** recording {xpf version, HA
protocol version, session-sync frame version, config-DB min-reader version}. The
bake already writes image metadata (bake.py `--write` of the appliance
description); INC-3 extends it with these version fields so the gate is a file
read, not a boot. No new *forwarding* mechanism — #1879 + #1917 Path C reused —
but the **mixed-base compatibility gate + version manifest are new** (INC-3's
responsibility). #1930's LANE-2 contribution: the **decision rule** ("series
change ⇒ LANE 2"), the **mixed-base gate + version manifest**, and the doc.

### 3.3 LANE 3 — base-OS major-version upgrade (Ubuntu N → N+1)

**Default: image-replace (LANE 2).** A baked N+1 image carries the new kernel,
glibc, systemd, FRR, strongSwan, kea, chrony as one tested unit, gated by
`validate.py`. This is the recommended, supported path.

**State-carry contract — the PORTABLE artifact is the TEXT config, NOT the
encrypted config DB (r2 Codex NEW-F11; corrects a v2 factual error).** The
authoritative image-replace path (`docs/install-images.md:188-190`: *"The text
config is the portable artifact — not `.configdb`"*; `deploy-quickstart.md:127`:
*"`xpf.conf` + `node_id` are the only [carried artifacts]"*) re-applies config
via the day-0 drive / a copied-in `xpf.conf` and lets the freshly-imaged node
**factory-bootstrap** the config DB from text. So what carries is:
- the xpf `.deb` (re-installed into the N+1 image at bake time),
- **`/etc/xpf/xpf.conf` (text config)** + `/etc/xpf/node-id` (HA identity) —
  re-applied via the day-0 drive (`make_config_drive.py` / `xpf-deploy.py`'s
  day-0 ISO, which stages exactly `xpf.conf` + optional `node-id`),
- the day-0 factory bootstrap (#1879) re-derives `.configdb` from the text on
  first boot; `master.key` is RE-GENERATED on the new image, NOT carried — any
  secret material is in the text config (mode 0600) and re-encrypted under the
  new key. **Do NOT assume `.configdb`/`master.key` survive a base-OS replace**;
  carrying the encrypted DB across a fresh image is neither how the path works
  nor safe (a re-imaged node would have a new `master.key` and fail to decrypt a
  carried `.configdb`). For an *in-place* upgrade (#1917) the DB persists; for an
  *image-replace* it is re-bootstrapped from text — these are different paths.
Validation: `validate.py` factory-boot + in-guest `verify-dataplane` + a forward
probe on the N+1 base proves xpf still loads + forwards from the re-applied text.

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
r1 killed "A1 = GRUB grubenv one-shot" (GRUB can't clear its flag at boot on
metadata_csum/Secure Boot). r2 (SMR B4, AGY, Codex NEW-F10 — all three) killed
v2's "A1' = Linux-cleared marker" too: it still loops when the candidate hangs
**before Linux** (the clear never runs; GRUB re-reads the marker forever). **The
discriminator: who clears the one-shot when the candidate NEVER reaches Linux.**
Only the FIRMWARE qualifies.

| Option | Mechanism | Clears one-shot how? | Verdict |
|---|---|---|---|
| **A1 (KILLED): GRUB grubenv, GRUB clears at boot** | `grub-reboot`, `save_env next_entry=` at boot. | GRUB-at-boot — FAILS on metadata_csum/Secure Boot → loop. | **REJECT** (r1). |
| **A1' (KILLED): pinned default + Linux-cleared marker** | Marker GRUB reads, early-Linux clears. | Linux — but an **early-hang candidate never reaches Linux** → marker stays set → loop. | **REJECT** (r2 unanimous). |
| **A1'' (RECOMMENDED): UEFI `BootNext`** | `efibootmgr --bootnext <cand-entry>`; permanent `BootOrder` = known-good first; promote = `efibootmgr --bootorder` cand-first on verify+forward PASS. | **UEFI FIRMWARE clears `BootNext` before booting the entry** — so ANY reset (watchdog or otherwise), at ANY boot stage including pre-Linux hang, falls through to `BootOrder` (known-good). No bootloader/OS write at the failing moment. | **RECOMMENDED.** |
| **A1''-fallback: GRUB grubenv on the FAT32 ESP** | Move grubenv to the ESP (FAT, GRUB-writable, no metadata_csum) so GRUB's own `save_env` succeeds. | GRUB-at-boot, but on a writable FS → succeeds → one-shot consumed. | Fallback if per-kernel UEFI entries are impractical. |
| **A2 (KILLED): softdog** | Software watchdog only. | N/A — can't fire pre-load + disarmed by clean reboot. | **REJECT** (r1 AGY). |
| **A3 (future): systemd-boot/UKI boot-counting** | Switch bootloader; tries-counter on EFI vars/ESP. | Firmware/ESP-owned. | **DEFER** — bootloader migration is a large separate change; boot-counting reverts on *boot* not *verify* failure (mitigate: promotion unit marks good ONLY on forward-beacon PASS). The clean long-term answer; A1'' achieves the same brick-safety on the existing GRUB image NOW. |

**Recommendation: A1'' (UEFI `BootNext`).** It is the only substrate that closes
the boot-LOOP unconditionally — including the pre-Linux early-hang case r2
killed — because the firmware, not GRUB or Linux, consumes the one-shot. It works
on the existing GRUB image (no bootloader migration). The ESP-grubenv form is the
fallback. The watchdog (Path Option D) remains needed to convert a *hang* into
the *reset* that triggers the firmware fallback — but the loop itself is gone
regardless of the watchdog.

### Path Option B — base-OS major upgrade
| Option | Mechanism | Verdict |
|---|---|---|
| **B1: image-replace only** | Bake N+1 image (validate.py-gated); `deploy_rolling()` recreate-from-image + day-0 re-apply (`xpf.conf`+`node-id`); HA mixed-base gate (§3.2). | **RECOMMENDED — the ONLY supported path.** |
| **B2: `do-release-upgrade` in-place** | Ubuntu release upgrader. | **DROPPED / UNSUPPORTED** (r1 SMR M4 + AGY Hazard D + Codex F8 — unanimous). Irreversible userspace move; half-upgraded under kernel hold; N+1-userspace-on-N-kernel mixed-state brick; untestable. Documented "unsupported, re-image instead." |

**Recommendation: B1 only.** B2 is explicitly unsupported. The appliance model is
image-replace-first; state carries as TEXT config (§3.3), not the encrypted DB.

### Path Option D — watchdog strictness (r2 AGY: persistence can't be SW-verified)
Because no portable Linux API proves a watchdog survives a warm reset, the
pre-assert cannot *guarantee* early-hang protection. Two operator postures:
| Option | Posture | Verdict |
|---|---|---|
| **D1: fail-closed strict** | LANE 1 refuses to arm unless the bake's platform flag marks a verified-persistent hypervisor/BMC watchdog. | Safest; recommended for unattended fleets. |
| **D2: warn-and-proceed** | With `BootNext` the LOOP is already closed; allow LANE 1 with a documented "early hang needs one external reset" caveat where no verified-persistent watchdog exists. | Acceptable because A1'' removes the brick (loop); the residual is a recoverable hang, not a brick. |

**Recommendation: D1 default for unattended/cloud fleets; D2 selectable** by an
explicit operator flag where console/hypervisor reset is available. Either way the
boot-loop (the true brick) is closed by A1''.

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
  `bake.py` holds the kernel via `apt-mark hold $(dpkg-query -W -f='${Package}\n'
  'linux-*')` (NOT a raw glob — r2 AGY); sets `GRUB_DISABLE_SUBMENU=y` + pins
  `GRUB_DEFAULT` to the STABLE known-good id (r2 AGY/SMR B2/B3); creates the
  per-kernel **UEFI boot entry** + permanent `BootOrder` known-good-first;
  installs the **persistent-watchdog** config (firmware/hypervisor `nowayout`,
  initramfs early-arm fallback — r2 AGY persistence caveat); records the bake
  **watchdog-persistence platform flag** + the **image version manifest** (xpf
  ver, HA protocol ver, session-sync frame ver, config-DB min-reader ver — for
  the LANE-2 gate); disables `unattended-upgrades` for `linux-*`; ships the
  `needrestart` blacklist. Closes "unattended apt moves the floor" alone. (FIRST.)
- **INC-1 (LANE 1 in-guest mechanism):** `pkg/upgrade` kernel verb + `xpfd
  upgrade kernel <ver>`: **pre-asserts** (UEFI + `efibootmgr` OK; `BootOrder`
  known-good-first; GRUB submenu disabled + pinned id resolves; watchdog present
  + persistence flag OR Path-D2 operator override; free `/boot`/ESP ≥ image+
  initramfs+margin BEFORE install) → unhold→install→rehold (verify
  update-initramfs/update-grub succeeded) → **re-assert `BootOrder`/`GRUB_DEFAULT`
  known-good did NOT move** after the candidate postinst → create candidate UEFI
  entry → `efibootmgr --bootnext <cand>` (firmware-cleared one-shot) → confirm
  watchdog → reboot. Promotion oneshot: assert `uname -r`==candidate →
  `verify-dataplane` → **forward** beacon (tight budget, stable peer-link target)
  → only-on-beacon-PASS promote (`efibootmgr --bootorder` cand-first) + durable
  marker + disarm watchdog; else clean reboot → firmware falls through to
  known-good. Journal + GC prune of un-promoted candidate (kernel pkg + UEFI
  entry). Command `xpfd upgrade kernel`.
- **INC-2 (LANE 1 HA — EXTERNAL orchestration):** the cross-node kernel-rolling
  sequence lives in `scripts/deploy/xpf-deploy.py` (survives reboots — r2/r1),
  NOT in-process `rolling.go`. Implements: drain A → confirm peer holds all RGs →
  `bootnext`+reboot A → poll A until booted AND **running kernel == target AND
  promotion marker present** (a reverted node = STOP, leave B — r2 AGY
  version-check) → confirm rejoin + sync → `ResetFailover` A → only then B. A
  **leased cluster-wide lock** (TTL, on the `em0` control-plane store, not only
  in the driver process) so a driver crash doesn't wedge future lanes (r2 AGY);
  a **bounded local self-recovery** in xpfd (a node booting drained with no
  active lease naming it + healthy peer auto-`ResetFailover`s after a timeout —
  r2 AGY orchestrator-crash). `pkg/upgrade/rolling.go` unchanged (binary-cut path).
- **INC-3 (LANE 2/3 — image-replace + mixed-base gate + base-OS doc):** the
  **mixed-base HA compatibility gate** reads the new image's HA/session-sync
  protocol from the bake **version manifest** (a file read, NOT a boot — r2 AGY/
  Codex F11/F12) and fails-closed to a documented connection-drop if not
  back-compat with the running peer; LANE 2 HA reuses `deploy_rolling()`
  (recreate-from-image) + the rejoin gate; operator playbook in a new
  `docs/os-kernel-upgrades.md` (3-lane tree; the TEXT-config state-carry contract
  — `xpf.conf`+`node-id`, NOT `.configdb`/`master.key`, r2 Codex NEW-F11; the
  do-release-upgrade UNSUPPORTED statement); link from `docs/in-place-upgrade.md`.
- **INC-4 (validation — the NEW path, not regression):** (a) live LANE 1 happy +
  **deliberate-REJECT revert** proof (firmware-cleared `BootNext` → known-good
  boots, dataplane restored, NO operator action, NO loop) on the wipeable
  standalone test VM; (b) **early-hang revert** proof (force a pre-Linux hang →
  watchdog reset → known-good — where the VM exposes a persistent watchdog; else
  document); (c) mixed-base session-sync + failover validation; (d) a baked
  N+1-base image factory-boots + forwards from re-applied TEXT config
  (validate.py); (e) unit tests for the pre-assert/journal/revert/lease/
  self-recovery state machines.

---

## 6. Risks + mitigations

| # | Risk | Mitigation |
|---|---|---|
| 1 | **One-shot boot-loop** — GRUB-cleared (r1) AND Linux-cleared (r2) markers both loop on an EARLY-HANG candidate (cleared only if the candidate reaches Linux). | **UEFI `BootNext` (A1'')**: FIRMWARE clears the one-shot before booting the entry, so ANY reset at ANY stage falls through `BootOrder` to known-good. Loop closed unconditionally. §2 inv 2 / §3.1 / Path A. |
| 2 | **dpkg `linux-image` postinst `update-grub` moves the default** (r1 SMR B2 / Codex F2). | Pin `GRUB_DEFAULT`/`BootOrder` to the stable known-good entry; re-assert unchanged after the candidate install; promote only via `efibootmgr --bootorder` on verify+forward PASS. |
| 3 | **Candidate menuentry id wrong/unresolvable** after `update-grub` submenu reorder (r1 SMR B3 / Codex F5; r2 AGY submenu). | `GRUB_DISABLE_SUBMENU=y`; resolve the STABLE id from the regenerated `grub.cfg` and assert it exists; per-kernel UEFI entries via `efibootmgr` sidestep menu ordering. |
| 4 | **Early-boot HANG unprotected** — clean reboot disarms a non-persistent watchdog; warm-reset may reset board watchdog; persistence not SW-verifiable (r1 AGY C / Codex F3; r2 AGY). | `BootNext` already closes the LOOP. The watchdog only converts a HANG→reset; require a verified-persistent firmware/hypervisor watchdog (Path D1) for unattended early-hang recovery, else Path-D2 documented "one external reset" caveat. Honest: not fully SW-guaranteeable. |
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
| 15 | **`apt-mark hold linux-*` shell-glob failure** — the glob expands against the cwd, holds nothing (r2 AGY). | `apt-mark hold $(dpkg-query -W -f='${Package}\n' 'linux-*')` — a concrete package query, never a bare glob. INC-0. |
| 16 | **Image-replace assumes `.configdb`/`master.key` carry — they DON'T** (r2 Codex NEW-F11). The portable artifact is the TEXT config; a re-imaged node has a new `master.key` and would fail to decrypt a carried encrypted DB. | LANE 2/3 carries `xpf.conf`+`node-id` via day-0; the new image factory-bootstraps `.configdb` from text and re-derives `master.key`. §3.3 + INC-3. Documented in the state-carry contract. |
| 17 | **`xpf-deploy.py` over-attributed live in-place OS swap** (r2 Codex NEW-F12) — it does VM-granular `deploy_rolling()` recreate + day-0, not a live swap or rejoin gate. | LANE 2 reuses recreate-from-image; the rejoin-confirm + version-check + mixed-base gates are NEW (INC-2/3), not existing capability. §3.2 grounding cell corrected. |
| 18 | **External orchestrator crash → orphaned drain / leaked lock / false "healthy" advance** (r2 AGY). | Version-check anchor (running kernel == target + promotion marker) before advancing; leased TTL cluster lock on `em0` store; bounded local self-recovery in xpfd for an orphaned drain. INC-2. |

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
- **Neither GRUB nor Linux can clear the one-shot when the candidate hangs
  pre-Linux** — GRUB can't write on `metadata_csum`/Secure-Boot, and a Linux
  clear never runs if Linux is never reached. ONLY the UEFI FIRMWARE clears its
  own one-shot (`BootNext`) before boot — so `BootNext` is the only loop-safe
  substrate (§2 inv 2, risk #1, Path A). The permanent `BootOrder`/`GRUB_DEFAULT`
  known-good entry must be STABLE and unmoved by the dpkg postinst's `update-grub`
  (risks #2/#3).
- **`BootNext` closes the LOOP; the watchdog only turns a HANG into the reset**
  that triggers the firmware fallback. Watchdog persistence across a warm reset
  is hardware-dependent and NOT SW-verifiable — "fully-unattended never-brick on
  early hang" holds only with a verified-persistent firmware/hypervisor watchdog
  (Path D1); otherwise the residual is a recoverable hang (one external reset),
  not a brick (§2 inv 3, risk #4). Do not overclaim.
- **The shim travels embedded in xpfd** (`//go:embed`), so a kernel move does
  NOT change the shim bytes — only whether the *running kernel* accepts them.
  The verify is against the kernel, with the xpf version fixed.
- **HA both-node reboot = full outage** — kernel moves MUST be one-at-a-time via
  the EXTERNAL orchestrator (not in-process `rolling.go`, which dies at reboot);
  external driver holds a cluster-wide kernel-lane lock (risk #5).
- **`bake.py` GRUB drop-in lives in `/etc/default/grub.d/99-xpf.cfg`** (Ubuntu
  cloudimg overrides `/etc/default/grub` via `50-cloudimg-settings.cfg`) — the
  `GRUB_DEFAULT=<stable-known-good-id>` pin + `GRUB_DISABLE_SUBMENU=y` MUST go in
  the drop-in (higher-numbered than cloudimg's), not a sed on the main file.
- **`apt-mark hold` must NOT take a bare glob** — `apt-mark hold linux-*`
  shell-expands against the cwd; use `apt-mark hold $(dpkg-query -W
  -f='${Package}\n' 'linux-*')`. Cover image/headers/modules/generic/metas;
  verify the hold pins what apt would move (risk #15).
- **Image-replace carries TEXT config, not the encrypted DB** — `xpf.conf` +
  `node-id` via day-0; `.configdb`/`master.key` are re-derived on the new image
  (a carried encrypted DB can't decrypt under a fresh `master.key`). In-place
  (#1917) persists the DB; image-replace re-bootstraps it (risk #16, §3.3).
- **`xpf-deploy.py` does VM-granular recreate, not a live in-place OS swap** —
  LANE 2/3 reuses `deploy_rolling()` recreate-from-image; the rejoin/version/
  mixed-base gates are new (risk #17).

---

## 9. Acceptance criteria (for `/engineer 1930`, NOT this research)

1. INC-0: a deployed image has the kernel held (concrete dpkg-query, not a
   glob); `GRUB_DEFAULT` pins a stable known-good id + `GRUB_DISABLE_SUBMENU=y`;
   `BootOrder` known-good-first + per-kernel UEFI entries; persistent-watchdog
   config + bake persistence flag; image version manifest; `unattended-upgrades`
   excludes `linux-*`.
2. LANE 1 happy: `xpfd upgrade kernel <ver>` on a same-series candidate boots it
   once via `BootNext`, verify+forward-beacon PASS, candidate promoted (BootOrder
   moved), dataplane forwards; pinned known-good did NOT move at install time.
3. LANE 1 brick-proof — REJECT: a deliberately-REJECTing candidate is reverted —
   firmware-cleared `BootNext` → box boots known-good, dataplane restored, NO
   manual intervention, NO boot-loop.
4. LANE 1 brick-proof — EARLY HANG: a candidate that hangs pre-Linux → watchdog
   reset → firmware falls through to known-good (with a verified-persistent
   watchdog); without one, documented "one external reset" recovery, still NO
   loop.
5. LANE 1 HA: the external orchestrator never has both nodes down; a reverted
   node (running kernel != target) does NOT advance the sequence; orchestrator
   crash does not orphan a drain (local self-recovery) or leak the lock (lease);
   traffic survives (failover-test green).
6. LANE 2 mixed-base gate: an incompatible new-image HA protocol (read from the
   version manifest, no boot) fails the pre-swap gate (documented drop); a
   compatible one survives session-sync.
7. LANE 3: a baked N+1-base image factory-boots and forwards from re-applied
   TEXT config (`xpf.conf`+`node-id`) — validate.py green; `.configdb`/
   `master.key` are re-derived, NOT carried; do-release-upgrade UNSUPPORTED.
8. Docs: 3-lane tree + state-carry contract + playbook in
   `docs/os-kernel-upgrades.md`, linked from `docs/in-place-upgrade.md`.

---

## 10. Test plan

- **Unit:** `pkg/upgrade` kernel-verb state-machine tests (mirror
  `runner_test.go`/`rolling_test.go`): pre-assert failures abort cleanly;
  journal crash-recovery resumes; revert path leaves default unchanged.
- **Image:** `bake.py` produces an image with held kernel + pinned stable
  default + `GRUB_DISABLE_SUBMENU=y` + per-kernel UEFI entries + persistent-
  watchdog config + version manifest; asserts catch a missing hold (and that the
  hold used the dpkg-query form, not a glob), a moved default, a missing UEFI
  entry, or a missing manifest.
- **Live — STANDALONE wipeable test VM (`xpf-fw`, `make test-vm`/`test-deploy`),
  NOT the shared loss cluster's primary:** this is where the NEW boot channel is
  actually exercised end-to-end (per the §10 directive — passing regression
  tests proves no-regression, NOT that the new channel works):
  - LANE 1 happy: drive a real same-series candidate through `bootnext` boot →
    verify+forward-beacon → promote; capture evidence (booted kernel version,
    promotion marker, `efibootmgr` BootOrder, dataplane forwards).
  - LANE 1 **deliberate-REJECT revert**: arm a candidate the shim rejects (or
    force a verify fail), confirm firmware-cleared `BootNext` → box boots
    known-good, NO boot-loop, dataplane restored — mandatory live evidence.
  - LANE 1 **early-hang revert**: force a pre-Linux hang (e.g. a deliberately
    broken initramfs / `panic` boot arg on the candidate UEFI entry), confirm the
    persistent watchdog resets and the firmware falls through to known-good
    (where the VM exposes a persistent watchdog; else document and rely on the
    unit test + a hypervisor-watchdog manual check). This is the proof that v3's
    `BootNext` pivot fixed the r2 early-hang loop.
- **Live — HA:** mixed-base session-sync + the external-orchestrator
  rejoin-confirm + "never both down" sequence on a wipeable two-VM env (NOT the
  shared loss primary).
- **Base-OS:** bake an N+1 image in a scratch env, `validate.py` boot+forward
  gate, confirm state carry from re-applied TEXT config (`xpf.conf`+`node-id`;
  confirm `.configdb`/`master.key` are re-derived, not carried). A real Ubuntu
  N→N+1 `do-release-upgrade` is NOT tested (UNSUPPORTED by design — §3.3).
- **Negative:** non-UEFI / no-`efibootmgr` / `BootOrder` not known-good-first /
  (Path-D1) no verified-persistent watchdog → `xpfd upgrade kernel` aborts with
  the "use image-replace" message (refuses to arm).

---

## 11. Recommendation (to be ratified by the 3 reviewers)

Ship #1930 as **three lanes by blast radius**, defaulting to image-replace and
treating in-place kernel moves as a tightly-gated channel:

- **LANE 1** (same-series kernel CVE bumps): verify-gated one-shot-boot via
  **Path Option A1'' (UEFI `BootNext`)** — the firmware clears the one-shot
  before boot, so any reset (incl. a pre-Linux early-hang watchdog reset) falls
  through `BootOrder` to the known-good kernel: the boot-LOOP is closed
  unconditionally, on the existing GRUB image, no bootloader migration. Kernel
  held-by-default; promotion gated on a **forward** health beacon + `uname -r`
  match; HA sequencing **EXTERNAL** (`deploy_rolling()` recreate + a rejoin/
  version/lease gate), not in-process `rolling.go`. The watchdog (Path D)
  converts a hang→reset; "fully-unattended early-hang recovery" needs a
  verified-persistent watchdog, else a documented one-external-reset (still no
  loop, no brick).
- **LANE 2** (new kernel series / heavy moves): image-replace (Path C, #1879) —
  decision rule + the **pre-swap mixed-base HA gate** reading the bake **version
  manifest** (no boot).
- **LANE 3** (base-OS N→N+1): **image-replace ONLY (Path Option B1)**; state
  carries as **TEXT config** (`xpf.conf`+`node-id`), NOT the encrypted DB.
  `do-release-upgrade` is **UNSUPPORTED** (documented, not a hatch).

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

### r2 → v3 disposition (what changed and why)
All three r2 reviewers (Claude SMR B4, AGY, Codex NEW-F10) converged that v2's
A1' STILL boot-loops on a pre-Linux early-hang candidate (the Linux clear never
runs). v3 dispositions:
- **Residual early-hang boot-loop** (SMR B4 / AGY Hazard A / Codex NEW-F10): A1'
  KILLED → **A1'' UEFI `BootNext`** — firmware clears the one-shot before boot,
  so any reset at any stage falls through to known-good. §2 inv 2, §3.1, Path A,
  risk #1. THIS is the headline v3 fix.
- **Watchdog not SW-verifiable for warm-reset persistence** (AGY r2): reframed —
  `BootNext` closes the loop regardless; the watchdog only triggers the reset on
  a hang; Path Option D (D1 fail-closed / D2 warn-proceed) makes the
  hardware-dependence explicit. §3.1, risk #4.
- **`apt-mark hold linux-*` glob expansion** (AGY r2): use `apt-mark hold
  $(dpkg-query -W -f='${Package}\n' 'linux-*')`. INC-0, risk #15.
- **GRUB submenu pathing** (AGY r2): `GRUB_DISABLE_SUBMENU=y` + per-kernel UEFI
  entries. INC-0, risk #3.
- **Secure Boot lockout loop** (AGY r2): `BootNext` makes an unsigned candidate
  fail SAFE (firmware already cleared the one-shot). §3.1, risk #8.
- **External-orchestrator crash / lock-leak / false-healthy advance** (AGY r2):
  version-check anchor + leased TTL lock + bounded local self-recovery. §3.1-HA,
  INC-2, risk #18.
- **Mixed-base introspection mechanism** (AGY r2 / Codex F11): read the bake
  **version manifest** (file read, not a boot). §3.2, INC-3.
- **State-carry contract was WRONG** (Codex NEW-F11): image-replace carries TEXT
  config (`xpf.conf`+`node-id`), NOT `.configdb`/`master.key` (re-derived on the
  new image). §3.3, risk #16.
- **`xpf-deploy.py` over-attributed live-swap** (Codex NEW-F12): it does
  VM-granular `deploy_rolling()` recreate; rejoin/version/mixed-base gates are
  new. §2 grounding + §3.2, risk #17.
- **do-release-upgrade lane-summary contradiction** (Codex F8): removed the
  "gated fallback" line in §3; UNSUPPORTED everywhere. §3 diagram, §3.3.
