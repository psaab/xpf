# #1930 — Major underlying VM/OS + kernel upgrades (plan-of-action)

- **Issue:** #1930 (deferred from #1917)
- **Status:** v1 DRAFT — pre-review
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

3. **Boot-loader / watchdog footguns.** The #1917 research (§6.3c, §6.7)
   surfaced concrete bricking hazards in any one-shot kernel-boot mechanism:
   `GRUB_DEFAULT=saved` + `GRUB_SAVEDEFAULT=false` requirement, `softdog`
   early-boot insufficiency, and `needrestart` mid-transaction restarts. These
   must be designed-in, not discovered live.

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
| `scripts/image/bake.py` | virt-customize: installs `linux-generic`, **HARD-ASSERTs newest kernel ≥ 6.18**, asserts `linux-modules-extra` (mlx5/i40e), purges all-but-newest kernel + **asserts exactly one kernel**, GRUB drop-in (`/etc/default/grub.d/99-xpf.cfg` = `init_on_alloc=0` only), build-host `verify-dataplane` pre-gate. | The **image-replace substrate** (Path C) + the place to add `apt-mark hold linux-*`, `GRUB_DEFAULT=saved`, and a kernel-channel oneshot unit. |
| `scripts/deploy/xpf-deploy.py` | Pushes a baked image to incus / a target; HA two-node deploy. | The Path-C deploy driver the base-OS-major and heavy-kernel paths reuse. |
| `scripts/image/validate.py` | Factory-boot + in-guest `verify-dataplane` validation gate. | The acceptance gate for "xpf still loads + forwards on the new base." |
| `docs/in-place-upgrade.md` | The #1917 operator doc. Line 169 hands kernel/OS to #1930. | The doc to extend with the kernel channel + base-OS playbook. |
| `pkg/dataplane/README.md` §`#1864` | Toolchain pin + 3 verify gates (build, install, deploy pre-flight). | The contract the kernel channel must not break (verify is the only install gate). |

### Concrete gaps in the current substrate (the #1930 work surface)
- **No `apt-mark hold linux-*`** anywhere in `bake.py` — the floor is asserted
  at bake time but nothing prevents `apt upgrade` from moving it post-deploy.
- **GRUB drop-in is `init_on_alloc=0` only** — no `GRUB_DEFAULT=saved`, no
  `GRUB_SAVEDEFAULT` assertion. The one-shot `grub-reboot` channel cannot
  function and would silently no-op or boot-loop (per #1917 §6.3c).
- **No HW/hypervisor watchdog config** in the image — no `/dev/watchdog`,
  `RuntimeWatchdogSec`, nor a softdog-vs-hardware decision.
- **No `needrestart` blacklist** for the kernel-channel reboot window (#1917
  shipped one only for the binary-cut window per §6.3c; needs re-verification it
  also covers an apt-driven kernel install).
- **No base-OS major-upgrade playbook** — `do-release-upgrade` is unmodeled.
- **No `xpfd upgrade kernel` subcommand** — `pkg/upgrade` has no kernel verb.

### The load-bearing invariant for the design
`verify-dataplane` **cannot validate an unbooted kernel** (the BPF verifier is
kernel-space; `ebpf.NewCollection` loads into the *running* kernel). Therefore
the kernel channel is fundamentally **"boot the candidate once, verify from
inside it, promote-or-revert"** — NOT "verify-then-set-default." This is the
single fact that forces the one-shot-boot + watchdog design over any
verify-first design. (#1917 §6.7, round-2 AGY blocker, restated and adopted.)

---

## 3. Design — three lanes by blast radius

The design splits by how far the kernel moves, mirroring #1917's Path-B
(in-place) vs Path-C (image-replace) split:

```
  Kernel CVE point-release (same series, e.g. 6.18.x -> 6.18.y or 7.0.z)
      -> LANE 1: verify-gated one-shot-boot in-place kernel channel
                 (xpf-upgrade kernel <ver> + watchdog + grub-reboot)

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

**Mechanism (the brick-proof sequence):**

1. **Default posture: `apt-mark hold linux-*`** (added to `bake.py`). Unattended
   apt cannot move the kernel. A kernel bump is an explicit operator action.
2. Operator runs `xpfd upgrade kernel <candidate-version>` (new subcommand,
   `pkg/upgrade` kernel verb). It:
   a. **Pre-asserts boot-loader invariants** (fail-closed, before touching
      anything): `GRUB_DEFAULT=saved` present, `GRUB_SAVEDEFAULT` absent/false,
      a HW/hypervisor watchdog device present. If any fails → ABORT with an
      actionable message ("kernel channel not armed; use image-replace").
   b. `apt-mark unhold linux-*` → install the candidate kernel package(s) →
      re-`apt-mark hold`. The candidate is installed but NOT the boot default.
   c. **Arms a one-shot boot** of the candidate via `grub-reboot <candidate>`
      (one-shot; default unchanged — REQUIRES `GRUB_DEFAULT=saved`).
   d. **Arms the HW/hypervisor watchdog** so that if the candidate kernel never
      reaches the promotion oneshot (early-boot hang, no systemd), the box
      resets and — because the GRUB *default* was never changed — boots the OLD
      known-good kernel.
   e. **HA:** does the one-shot boot on the **drained/secondary node only**,
      sequenced inside the rolling drive (reuse `pkg/upgrade/rolling.go`'s drain
      → act → restore primitive) so both nodes never reboot together.
   f. Reboots.
3. On the candidate boot, a **promotion oneshot systemd unit** runs early,
   before xpfd's `ExecStartPre` admits traffic:
   a. Runs `xpfd verify-dataplane` against the now-running candidate kernel
      (exit 0 PASS / 3 REJECT / 1 error).
   b. On PASS: runs a bounded **health beacon** (dataplane loads + forwards a
      probe), then `grub-set-default <candidate>` (promote), writes a durable
      promotion marker, pets/disarms the watchdog, and `apt-mark hold` stays.
   c. On REJECT/error/timeout: does NOTHING to promote. The watchdog fires (or
      a clean reboot is issued) → boots the OLD default kernel → shim verifies
      → dataplane restored. The candidate kernel package stays installed but
      un-defaulted; a retention prune removes it later.
4. **HA failback:** after the secondary promotes the candidate and rejoins, the
   rolling drive fails traffic back and repeats on the (now drained) primary.

**Honest bounds (carried verbatim from #1917 §6.7, do not soften):**
- With a **HW/hypervisor watchdog** this is brick-proof against boot hangs.
- **`softdog` is INSUFFICIENT** — a kernel software watchdog cannot fire if the
  candidate kernel hangs in decompression / early init *before* the softdog
  module + systemd load and arm it. That path bricks. LANE 1 REQUIRES the
  HW/hypervisor watchdog for the "never brick" guarantee; on platforms without
  one, LANE 1 is unavailable and the operator MUST use LANE 2 (image-replace).
- With only `grub-reboot` (no watchdog), the GRUB default is preserved but an
  early-boot hang needs external/operator recovery (console/hypervisor reset).

### 3.2 LANE 2 — image-replace for heavy/uncertain kernel moves (Path C)

A new kernel *series* (the shim has never been verified against it), or a kernel
arriving as part of a base-OS upgrade, goes through the fully-tested image
substrate: `bake.py` produces a new image with the new kernel (verify-dataplane
gated at bake AND validate.py boot-gate), `xpf-deploy.py` swaps it in.
- **HA:** replace secondary node's image → failover (VRRP demote, ~60ms) →
  replace primary → fail back. Connections survive via session-sync (subject to
  the #1917 §6.5 session-sync wire back-compat rule for the xpf version delta).
- **Standalone:** documented reboot gap (image swap + factory boot).
No new mechanism — this is #1879 + #1917 Path C reused verbatim. #1930's
contribution here is the **decision rule** ("series change ⇒ LANE 2") and the
operator doc.

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

**Fallback (Path Option B, see §6): gated `do-release-upgrade`.** Offered only
as a documented, console-attended, non-HA, single-node path for operators who
cannot re-image (e.g. a hand-built box). It MUST: `apt-mark hold linux-*` first
(do-release-upgrade pulls a kernel — route that kernel through LANE 1's verify
gate, NOT do-release-upgrade's blind reboot), neutralize `needrestart`
interactive prompts, and end with a LANE-1-style verify-gated kernel boot rather
than do-release-upgrade's own final reboot. This path is explicitly **not
HA-safe and not the recommended path** — it is a documented escape hatch.

---

## 4. Multiple Path Options (where the design genuinely branches)

### Path Option A — one-shot-boot mechanism for LANE 1
The candidate-kernel one-shot boot + revert can be built three ways:

| Option | Mechanism | Pros | Cons | Verdict |
|---|---|---|---|---|
| **A1: GRUB `grub-reboot` + HW/hypervisor watchdog** | `GRUB_DEFAULT=saved`, `grub-reboot <cand>` one-shot, HW watchdog armed pre-reboot, promote via `grub-set-default` on verify PASS. | Default never changes until PASS; HW watchdog brick-proof against early hang; reuses GRUB the image already has. | Requires HW/hypervisor watchdog present; GRUB env is a known footgun set (`GRUB_SAVEDEFAULT` must be false). | **RECOMMENDED.** |
| **A2: softdog + GRUB** | Same as A1 but `softdog` instead of HW watchdog. | No HW watchdog dependency. | **Bricks on early-boot hang** — softdog can't fire before its own module loads. Fails the "never brick" bar. | REJECT (use only where no HW watchdog AND operator accepts manual recovery — effectively LANE 2 territory). |
| **A3: systemd-boot `boot-counting` (`bootctl` auto-revert)** | systemd-boot's built-in tries-counter auto-reverts a candidate after N failed boots. | Native auto-revert, no GRUB env footguns. | The image uses GRUB, not systemd-boot — switching the bootloader is a large, separate, risky change; boot-counting reverts on *boot* failure not on *verify* failure (a kernel that boots fine but REJECTs the shim would be counted "good"). | REJECT for now; note as a possible future if the image ever moves to systemd-boot. |

**Recommendation: A1.** It is the only option that satisfies both "default never
changes until verify PASS" and "brick-proof against early-boot hang," and it
reuses the bootloader already in the image. A2/A3 are documented as rejected with
reasons so a future reviewer doesn't relitigate.

### Path Option B — base-OS major upgrade
| Option | Mechanism | Pros | Cons | Verdict |
|---|---|---|---|---|
| **B1: image-replace only** | Bake N+1 image; `xpf-deploy.py` swap; HA rolling. | One tested unit; reuses #1879/#1917; validate.py-gated; HA-safe. | Requires re-imaging infra (bake host); not viable for hand-built boxes. | **RECOMMENDED default.** |
| **B2: `do-release-upgrade` in-place** | Ubuntu's own release upgrader, hold-kernel, route kernel through LANE 1, neutralize needrestart. | Works on hand-built boxes with no re-image infra. | High blast radius (FRR/strongSwan/kea/systemd all move untested); interactive by default; multi-reboot; NOT HA-safe; config-file merge prompts. | Offer as a **documented, gated, non-HA escape hatch ONLY** (§3.3). |

**Recommendation: B1 default, B2 documented escape hatch.** Do not invest
mechanism in B2 beyond the doc + the kernel-hold guard; the appliance model is
image-replace-first.

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

- **INC-0 (image hardening, low risk):** `bake.py` adds `apt-mark hold linux-*`
  after the single-kernel assert; sets `GRUB_DEFAULT=saved` + ensures
  `GRUB_SAVEDEFAULT` unset in the GRUB drop-in; installs a HW/hypervisor
  watchdog config (and documents the softdog-insufficiency); ships the
  `needrestart` blacklist covering the kernel-channel window. **No new daemon
  code.** This alone closes the "unattended apt moves the floor" hole.
- **INC-1 (LANE 1 mechanism):** `pkg/upgrade` kernel verb + `xpfd upgrade
  kernel <ver>` subcommand: boot-loader/watchdog pre-asserts, unhold→install→
  rehold, `grub-reboot`, arm watchdog, reboot. Promotion oneshot systemd unit
  (verify-dataplane + health beacon → `grub-set-default` + marker + disarm; else
  revert). Journal entries for crash-recovery (reuse `pkg/upgrade/state.go`).
- **INC-2 (LANE 1 HA sequencing):** wire the kernel verb into
  `pkg/upgrade/rolling.go` so a clustered kernel bump drains the secondary,
  one-shot-boots it, promotes/reverts, fails back, repeats on the primary —
  never both nodes down together.
- **INC-3 (LANE 3 / base-OS doc + Path C reuse):** operator playbook in
  `docs/in-place-upgrade.md` (or a new `docs/os-kernel-upgrades.md`): the
  3-lane decision tree, the B1 image-replace base-OS procedure (reusing
  `xpf-deploy.py`), the B2 gated escape hatch, the state-carry contract.
- **INC-4 (validation):** extend `validate.py` / a new harness to (a) prove
  LANE 1 revert actually boots the old kernel and restores the dataplane after a
  *deliberately-REJECTed* candidate, and (b) prove a baked N+1-base image
  forwards. The deliberate-REJECT test is the brick-proof proof.

---

## 6. Risks + mitigations

| # | Risk | Mitigation |
|---|---|---|
| 1 | **Brick on early-boot kernel hang.** Candidate kernel hangs before systemd → no promotion oneshot, no software watchdog. | HW/hypervisor watchdog armed pre-reboot (A1). GRUB default unchanged ⇒ reset boots old kernel. LANE 1 unavailable (forced to LANE 2) where no HW watchdog. |
| 2 | **`GRUB_SAVEDEFAULT=true` boot-loop.** GRUB writes the candidate as permanent default at boot, so a failing candidate is retried forever. | Pre-assert `GRUB_SAVEDEFAULT` unset/false; bake sets it false; `xpfd upgrade kernel` aborts if true. |
| 3 | **`needrestart` cuts the dataplane mid-apt** during the candidate kernel install. | Ship `/etc/needrestart/conf.d/xpf.conf` blacklist; verify it covers an apt-driven `linux-*` install (extend the #1917 §6.3c blacklist). |
| 4 | **Candidate kernel boots fine but REJECTs the shim** (verify fail, not boot fail) — A3's blind spot. | Promotion oneshot runs `verify-dataplane` and promotes ONLY on PASS; a booted-but-rejecting kernel is reverted, not counted "good." |
| 5 | **HA both-nodes-reboot.** A cluster-wide kernel bump reboots both nodes → full outage. | Kernel verb is driven through `rolling.go` drain/act/restore; one node at a time; the un-drained node holds traffic. |
| 6 | **Base-OS upgrade breaks FRR/strongSwan/kea config compat** (systemd/service-file moves). | B1 image-replace is gated by `validate.py` (factory boot + forward probe) BEFORE the image is published; B2 is non-HA, console-attended, documented-risk only. |
| 7 | **Config-DB rollback across an OS/kernel move.** A new xpf binary on the new base writes new-syntax config the old (reverted) binary can't parse. | Already mitigated by #1917 §8 embedded config-DB version manifest (min-reader gate). #1930 must NOT regress it; INC-4 validates a revert re-reads the DB. |
| 8 | **`apt-mark hold` defeated by unattended-upgrades.** `unattended-upgrades` can be configured to ignore holds for security. | Bake disables/constrains `unattended-upgrades` for `linux-*`; document that kernel CVEs flow through LANE 1, not unattended-upgrades. |
| 9 | **Watchdog fires during a legitimately-slow-but-fine boot** (false brick-avoidance reboot that loses the candidate). | Watchdog deadline tuned with margin; promotion oneshot pets early on first liveness, only disarms on verify PASS — distinguish "alive" (pet) from "promoted" (disarm). |
| 10 | **`/var/lib/xpf/versions/` + installed-kernel accumulation** fills `/var` or `/boot`. | Reuse #1917 §6.3c retention (keep active + N-1 + candidate); kernel channel prunes un-promoted candidate kernel packages. `/boot` is small — prune is mandatory. |

---

## 7. Preserved interfaces (must not change)

- `xpfd verify-dataplane` exit-code contract (0 PASS / 3 REJECT / 1 error) — the
  promotion oneshot depends on it.
- `VerifyEmbeddedUserspaceShim` semantics (anonymous, never-attach, never-pin) —
  the kernel channel verifies via this, not a bespoke loader.
- The #1864 toolchain pin + verifier floor (≥ 6.18) — LANE 1 never lowers it.
- `pkg/upgrade` journal / atomic-flip / rollback primitives — the kernel verb is
  a sibling state machine, not a rewrite.
- `pkg/upgrade/rolling.go` drain/act/restore HA primitive — reused for LANE 1 HA
  + LANE 2 image-replace HA.
- `bake.py` single-kernel assert + ≥6.18 floor + modules-extra assert — INC-0
  adds to these, never removes them.
- The day-0 config drive + `/etc/xpf` state contract (`.configdb`, `node-id`,
  `master.key`) — carries across all three lanes unchanged.
- #1917 §6.5 session-sync wire back-compat rule — LANE 2 HA image-replace
  depends on N↔N+1 sessions syncing during the rolling swap.

---

## 8. Hidden invariants / gotchas

- **verify-dataplane is kernel-space** — cannot validate an unbooted kernel.
  This is THE invariant forcing one-shot-boot over verify-first (§2).
- **GRUB default must never change until verify PASS** — `grub-reboot` is
  one-shot; promotion is `grub-set-default` AFTER verify. `GRUB_SAVEDEFAULT=true`
  silently breaks this (risk #2).
- **softdog cannot protect early boot** — the watchdog must be HW/hypervisor for
  the "never brick" claim (risk #1). State this in the doc; do not overclaim.
- **The shim travels embedded in xpfd** (`//go:embed`), so a kernel move does
  NOT change the shim bytes — only whether the *running kernel* accepts them.
  The verify is against the kernel, with the xpf version fixed.
- **HA both-node reboot = full outage** — kernel moves MUST be one-at-a-time
  through `rolling.go` (risk #5).
- **`bake.py` GRUB drop-in lives in `/etc/default/grub.d/99-xpf.cfg`** (Ubuntu
  cloudimg overrides `/etc/default/grub` via `50-cloudimg-settings.cfg`) — the
  `GRUB_DEFAULT=saved` change MUST go in the drop-in too, not a sed on the main
  file, or cloudimg clobbers it.
- **`apt-mark hold` is per-package-name** — `linux-*` glob must cover
  `linux-image-*`, `linux-headers-*`, `linux-modules-*`, `linux-generic`, and
  the meta-packages; verify the hold actually pins what apt would move.

---

## 9. Acceptance criteria (for `/engineer 1930`, NOT this research)

1. INC-0: a deployed image has `linux-*` held; `apt upgrade` does not move the
   kernel; `GRUB_DEFAULT=saved` + `GRUB_SAVEDEFAULT` false verified.
2. LANE 1 happy path: `xpfd upgrade kernel <ver>` on a same-series candidate
   boots it once, verify PASSes, candidate promoted, dataplane forwards.
3. LANE 1 brick-proof: a deliberately-REJECTing candidate kernel is reverted —
   the box boots the old kernel and the dataplane is restored, NO manual
   intervention (with HW watchdog).
4. LANE 1 HA: a clustered kernel bump never has both nodes down simultaneously;
   traffic survives (failover-test green).
5. LANE 3: a baked N+1-base image factory-boots and forwards (validate.py
   green); the state contract (`.configdb`/`node-id`/`master.key`) carries.
6. Docs: the 3-lane decision tree + operator playbook land in
   `docs/in-place-upgrade.md` / `docs/os-kernel-upgrades.md`.

---

## 10. Test plan

- **Unit:** `pkg/upgrade` kernel-verb state-machine tests (mirror
  `runner_test.go`/`rolling_test.go`): pre-assert failures abort cleanly;
  journal crash-recovery resumes; revert path leaves default unchanged.
- **Image:** `bake.py` produces an image with held kernel + correct GRUB env +
  watchdog config; an assert catches a missing hold or a `GRUB_SAVEDEFAULT=true`.
- **Live (loss userspace cluster, the only smoke env):**
  - LANE 1 same-series bump on the secondary, verify promote, fail back, repeat.
  - LANE 1 deliberate-REJECT candidate → confirm revert restores dataplane.
  - `make test-failover` green across a kernel rolling bump.
- **Base-OS:** bake an N+1 image in a scratch env, `validate.py` boot+forward
  gate, confirm state carry.
- **Negative:** no-HW-watchdog platform → `xpfd upgrade kernel` aborts with the
  "use image-replace" message (LANE 1 correctly refuses to arm).

---

## 11. Recommendation (to be ratified by the 3 reviewers)

Ship #1930 as **three lanes by blast radius**, defaulting to image-replace and
treating in-place kernel moves as a tightly-gated channel:

- **LANE 1** (same-series kernel CVE bumps): verify-gated one-shot-boot via
  **Path Option A1** (GRUB `grub-reboot` + HW/hypervisor watchdog), held-by-
  default kernel, HA-sequenced through `rolling.go`. Brick-proof only with a HW
  watchdog; refuses to arm without one.
- **LANE 2** (new kernel series / heavy moves): image-replace (Path C, #1879)
  unchanged — decision rule + doc only.
- **LANE 3** (base-OS N→N+1): **Path Option B1 image-replace by default**; B2
  `do-release-upgrade` is a documented, non-HA, console-attended escape hatch
  with the kernel routed through LANE 1's gate.

Start with **INC-0** (image hardening — closes the unattended-apt hole with zero
daemon code), then INC-1/2 (LANE 1 mechanism + HA), then INC-3/4 (base-OS doc +
validation).
