# #1925 Item 1 — root-partition auto-grow on operator-resized disks

Status: DRAFT v2 (research; NOT plan-reviewed — no Codex/AGY/Copilot run yet.
The campaign owner runs the serial plan-review later.)
Issue: #1925 (day-2 follow-up of #1879 / PR #1906, appliance images Path C)
Scope of THIS plan: Item 1 ONLY (root-partition auto-grow in the image bake).
Item 2 (HA image-replace mixed-version soak) is explicitly OUT OF SCOPE — see §9.

> v2 supersedes v1. v1 deferred-to-lab on three "blocking empirical unknowns"
> (root type GUID, root-is-last-partition, x-systemd.growfs presence) and on a
> safety question about the #1930 A/B-UEFI substrate. **All four are now answered
> directly, offline, from the cached Ubuntu 26.04 cloudimg
> (`~/.cache/xpf-image-bake/ubuntu-26.04-server-cloudimg-amd64.img`).** The
> answers move the verdict from DEFER-LAB to PLAN-READY and also CORRECT two
> load-bearing claims v1 made (see §1.1). Read §1.1 before §4.

---

## 1. Issue framing

#1925 carries two deferred day-2 gaps from the appliance-image work. Item 1:

> **Root-partition auto-grow** on operator-resized disks via `systemd-repart`.
> Today the deploy docs note it as a manual `growpart`/resize step; the image
> should grow the root filesystem to fill the provisioned disk on first boot.

Concretely: the bake (`scripts/image/bake.py`) ships an 8 GiB qcow2
(`XPF_IMAGE_DISK_SIZE` default `"8G"`, line 481; `virt-resize --expand` expands
the root partition to fill that work disk at line 491). An operator who
provisions a VM with a larger root disk (`incus init ... -d root,size=40GiB`, or
`qemu-img resize`, or a larger libvirt volume) gets a 40 GiB block device whose
**GPT root partition is still 8 GiB** — the extra 32 GiB is unallocated free
space and `/` cannot use it. That bites first on `/var/lib/xpf/versions/*` (the
in-place upgrade keeps N generations + a seeded rollback target, #1964), Kea
lease DBs, FRR/journald logs, and the flow-export spool.

### 1.1 Corrections to BOTH the issue premise AND plan v1 (verified, load-bearing)

I verified the real state by inspecting the actual cached 26.04 cloudimg with
`virt-filesystems` / `guestfish` (offsets, GPT type GUIDs, fstab, shipped units
and binaries). The findings change the design and overturn two v1 claims:

**(A) Nothing grows the partition OR the filesystem today — confirmed.** The
stock cloudimg grows both via **cloud-init** (`/etc/cloud/cloud.cfg` runs the
`growpart` then `resizefs` modules). The xpf bake purges cloud-init
(`bake.py` ~line 309). So with cloud-init gone, neither grow happens. The
issue's "manual `growpart`/resize step" premise is *also* slightly off in the
other direction: there is **no** manual-growpart note in the deploy docs today
(`grep growpart docs/` finds only the bake's own `virt-resize`); the gap is
simply undocumented and unautomated. The fix should *add* both the automation
and the doc.

**(B) v1 was WRONG that `x-systemd.growfs` is present.** v1 claimed the fs grow
"ALREADY happens" via an `x-systemd.growfs` mount option on `/`, citing
`systemd-growfs-root.service`. The 26.04 cloudimg fstab is:

```
LABEL=cloudimg-rootfs  /         ext4  discard,commit=30,errors=remount-ro  0 1
LABEL=BOOT             /boot     ext4  defaults                              0 2
LABEL=UEFI             /boot/efi vfat  umask=0077                            0 1
```

There is **no `x-systemd.growfs`**. `systemd-growfs-root.service` ships, but
the systemd-fstab-generator only emits the dependency that pulls it in when the
mount option is set — so it does NOT auto-fire. v1's "growfs already runs, the
only gap is the partition half" reasoning is therefore invalid: **both** halves
are gone. (This does not change the conclusion much — we still need a
partition+fs grow — but the rationale must be corrected so review doesn't rely
on a false "growfs is free" premise.)

**(C) v1's #1 "blocking" unknown (OQ-1, root type GUID) is RESOLVED — favorably.**
The 26.04 cloudimg `/` partition (`/dev/sda1`) carries GPT type GUID
`4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709` = the **discoverable `root-x86-64`
GUID**, NOT the generic Linux-data GUID. So a `repart.d` `Type=root` selector
matches the root partition out of the box — **no `sgdisk -t` retagging needed.**
(`growpart`, which selects by partition number not GUID, is unaffected either
way.)

**(D) v1's OQ-3 (root must be the LAST partition) is RESOLVED — favorably.**
The cloudimg layout, by *physical sector order* (not partition number), is:

| phys order | part | label / type | sectors (raw img) |
|---|---|---|---|
| 1st | `sda13` | BOOT (ext4, XBOOTLDR GUID) | 1048576 – 1073742335 |
| 2nd | `sda14` | BIOS-boot | 1074790400 – 1078984703 |
| 3rd | `sda15` | UEFI/ESP (vfat) | 1078984704 – 1190133759 |
| **4th (last)** | **`sda1`** | **rootfs (ext4, root-x86-64 GUID)** | **1190133760 – end** |

Root is **partition number 1 but the physically LAST partition** — the canonical
Ubuntu cloudimg layout, designed precisely so growpart/repart can extend rootfs
into trailing free space without touching boot/ESP. "Grow the last partition
into trailing free space" is therefore correct and safe. (`virt-resize --expand`
in the bake preserves this ordering: it grows `sda1` in place; root stays last.)

**(E) Path-A surprise: `systemd-repart` is NOT installed in the cloudimg.** No
`/usr/bin/systemd-repart`, no stock `systemd-repart.service`, no `systemd-repart`
dpkg package. Ubuntu/Debian split `systemd-repart` into its own package. So v1's
preferred "Path A — rely on the stock `systemd-repart.service`" is **not viable
without adding a package** to `RUNTIME_PACKAGES`. Meanwhile **`growpart`
(cloud-utils-growpart) IS already present** in the base image. systemd is 259
(repart + `GrowFileSystem=` fully supported *if* the package were added).

Net effect of A–E: the change is real, the safety story is *better* than v1
feared (root is last + discoverable GUID + A/B substrate is files-on-ESP, see
§6.3), and the lowest-risk mechanism is **the tool already in the image
(`growpart` + `resize2fs`)**, not `systemd-repart`. The issue *names*
systemd-repart, but the substance ("grow root to fill the disk on first boot")
is mechanism-agnostic; §4 weighs both and recommends the simpler one.

---

## 2. Honest scope / value framing

This is a **slow-path, first-boot-only, image-bake-only** change. It touches:

- `scripts/image/bake.py` — add the grow mechanism (one one-shot unit + its
  script, OR a repart.d drop-in + the repart package + a unit enable). ~15–30 lines.
- one or two new files under `scripts/image/` (the unit, and either a tiny
  grow script or a `repart.d/*.conf`).
- `docs/install-images.md` + `docs/deploy-quickstart.md` — document
  "auto-grows on first boot" (replacing the absent/implicit manual step).
- `scripts/image/validate.py` — new **Scenario D** (resized-disk grow) +
  a `launch()` tweak to pass a larger root size.

There is **zero** hot-path, dataplane, Rust, Go, or config-compiler code. No
gRPC/CLI/wire/config-schema/HA-sync surface. The blast radius is the *first-boot
sequence of a freshly-deployed appliance VM*.

Value: removes a real day-2 footgun — silently stranded disk → `/var` fills →
the #1964 upgrade rollback target can't be staged → upgrade/daemon fails in a
hard-to-diagnose way. It is the "appliance should just work" polish that every
cloud image does for free (and that this image USED to get for free from
cloud-init before the bake purged it). It is NOT a perf or correctness fix for
the dataplane.

**If reviewers judge the scope too small to justify the churn, PLAN-KILL is
acceptable** (the honest floor: operators can `growpart`+`resize2fs` by hand, or
bake the size they want via `XPF_IMAGE_DISK_SIZE`). See §11 for the hostile take.
My recommendation is that it is worth doing — small, now-well-understood, and it
restores a capability the appliance silently lost when cloud-init was purged.

---

## 3. What is already shipped / carried forward

- `#1879`/PR #1906: the whole offline image bake (qcow2 + incus metadata),
  cloud-init purge, kernel hold, day-0 config loader, validation harness
  (`validate.py` Scenarios A/B/C).
- `#1930` LANE-1 A/B UEFI kernel-slot substrate. **Verified shape (§6.3):** the
  A/B "slots" are **directories inside the single ESP partition**
  (`/boot/efi/EFI/xpf-A`, `xpf-B`), each holding a copy of the signed
  shim+grub + a `xpf.selector` GRUB script; the grub `09_xpf` drop-in branches
  on `$cmdpath`. Kernels stay in `/boot` (the rootfs), NEVER on the ESP
  (`bake.py` lines 343–381 + `scripts/image/grub.d/09_xpf`). There are **no A/B
  partitions** — only A/B *files on the ESP*. This is the key reason a root
  grow is safe (see §6.3).
- `growpart` (cloud-utils-growpart) and `resize2fs` (e2fsprogs) are present in
  the base cloudimg today. `systemd-growfs` is present; `systemd-repart` is NOT.
- The bake already has the established pattern for shipping a unit + a script +
  enabling a oneshot (day-0 loader, `xpf-uefi-slots.service`,
  `xpf-kernel-promote.service` — `--copy-in` + `chmod` + `systemctl enable`).

---

## 4. Concrete design

Goal: on first boot, if the root *partition* is smaller than the disk, grow it
to fill the trailing free space, then grow the ext4 fs to match — exactly once,
idempotent, never on later boots, never touching boot/ESP. Two mechanisms are
viable; the `repart.d` content and the one-shot wrapper are mutually exclusive.

### Path A — `growpart` + `resize2fs` one-shot (RECOMMENDED — uses tools already in the image)

Ship `scripts/image/xpf-grow-root.service` + a tiny wrapper, or inline the two
commands in the unit. The tools are already present (no new package).

```ini
# scripts/image/xpf-grow-root.service  (copied to /usr/lib/systemd/system)
[Unit]
Description=xpf grow root partition + fs to fill the provisioned disk (#1925)
DefaultDependencies=no
Conflicts=shutdown.target
After=systemd-remount-fs.service
Before=local-fs.target xpfd.service xpf-day0-config.service
# First-boot-only: the seal does NOT create this stamp; first boot makes it.
ConditionPathExists=!/etc/xpf/.root-grown
[Service]
Type=oneshot
RemainAfterExit=yes
# growpart is a no-op (exit 1, "NOCHANGE") when there is no trailing free
# space — the exact-bake-size deploy. resize2fs is a no-op when the fs already
# fills the partition. Both are idempotent. The wrapper resolves the root
# block device + partition number from /proc or findmnt rather than hardcoding
# sda1 (virtio = vda, NVMe = nvme0n1p1, etc.).
ExecStart=/usr/local/sbin/xpf-grow-root
ExecStartPost=/usr/bin/touch /etc/xpf/.root-grown
[Install]
WantedBy=sysinit.target
```

`xpf-grow-root` (sketch — final form in implementation):

```sh
#!/bin/sh
# Resolve the root block device and partition number WITHOUT hardcoding sda1
# (the device node is vda/sda/nvme0n1 depending on the hypervisor bus).
set -e
root_src=$(findmnt -no SOURCE /)          # e.g. /dev/sda1, /dev/vda1, /dev/nvme0n1p1
disk=$(lsblk -no PKNAME "$root_src")      # parent disk: sda / vda / nvme0n1
partnum=$(cat "/sys/class/block/$(basename "$root_src")/partition")
# growpart returns 1 + "NOCHANGE" when there's no free space — treat as success.
growpart "/dev/$disk" "$partnum" || true
resize2fs "$root_src" || true
```

Why this is the recommended path:
- **No new package.** Smallest footprint; `growpart`/`resize2fs` already ship.
- **Lowest data-loss surface.** `growpart` only ever *grows a partition's end
  into adjacent free space*; it cannot create, reformat, shrink, or move a
  partition. `resize2fs` (online, on the mounted root) only grows. There is no
  `Format=`/`CopyBlocks=` equivalent to mis-set. This is the single biggest
  argument over Path B (see §11 / §7).
- Selects root by **partition number under the actual root mount**, not by a
  layout assumption — robust to bus naming (vda vs sda vs nvme).
- Restores *exactly* what cloud-init's `growpart`+`resizefs` modules did before
  the purge — a known-good behavior, not a new mechanism.

Tradeoff: it is imperative shell, not a declarative repart.d file, and it runs
after `/` is mounted rw (online ext4 resize — fully supported). The issue text
names `systemd-repart`; this path satisfies the *intent* with a different,
lower-risk tool. Call that out for review.

### Path B — `systemd-repart` declarative drop-in (matches the issue's named mechanism)

New `scripts/image/repart.d/10-root.conf` → `/usr/lib/repart.d/10-root.conf`:

```ini
# xpf (#1925): grow the existing root partition to fill an operator-resized
# disk on first boot, then grow the ext4 fs. Operate IN PLACE: no Format=,
# no CopyBlocks= => repart MUST NOT create or reformat anything.
[Partition]
Type=root            # matches the cloudimg root-x86-64 GUID (verified §1.1.C)
GrowFileSystem=yes   # resize2fs after the partition grows
# No SizeMinBytes/SizeMaxBytes => grow to fill trailing free space.
```

plus, because the binary is absent (§1.1.E):

```python
RUNTIME_PACKAGES += ["systemd-repart"]   # the binary lives in its own package
...
"--copy-in", f"{HERE}/repart.d/10-root.conf:/usr/lib/repart.d",
"--run-command", "systemctl enable systemd-repart.service",
```

Why Path B is the *less* preferred option despite being the named mechanism:
- Adds a runtime package to a deliberately minimized image.
- A `repart.d` file is the one place in the appliance where a typo
  (`Format=`, a wrong `Type=` that matches nothing → repart could try to
  *create* root) can reformat/recreate `/`. The risk is bounded by review + a
  dry-run gate, but it is a strictly larger failure surface than `growpart`.
- Upside vs Path A: declarative, runs in early boot before `/` is rw (cleaner
  ordering for a resize), and is the mechanism a future reviewer expects from
  the issue title. If the project prefers the declarative form, Path B is sound
  — the type-GUID match (§1.1.C) makes it work without retagging.

### Path C — bake-time size only (NOT auto-grow) — documented fallback

Drop runtime grow; document "bake the size you want" via `XPF_IMAGE_DISK_SIZE`.
Does NOT satisfy the issue (one image can't serve 8/40/200 GiB fleets at deploy
time). Listed only as the PLAN-KILL-adjacent docs-only landing.

### Recommendation

**Path A (growpart + resize2fs one-shot).** It restores the exact pre-purge
behavior with no new package and the smallest data-loss surface, and the
verified geometry (§1.1 C/D) means it Just Works. Offer **Path B** to reviewers
who want the issue's literally-named `systemd-repart` mechanism — it is viable
now that the type-GUID match is confirmed — but flag its larger risk surface and
the added package. Path C is the graceful docs-only degradation.

---

## 5. Public API / wire-compat preservation

None affected. No gRPC, CLI, config-schema (dual-AST), HTTP, Prometheus, HA
sync, or config-DB surface is touched. `XPF_IMAGE_DISK_SIZE` keeps its meaning
(the *floor* size of the shipped image). The day-0 config contract, the
signed-manifest contract (#1924), and the #1930 LANE-1/2 manifest fields are
untouched.

---

## 6. Hidden invariants the change must preserve

1. **No-op on a non-resized disk.** On an exactly-8-GiB deploy the grow must do
   nothing: `growpart` returns NOCHANGE (no free space), `resize2fs` is a no-op
   (fs already fills the partition). Verify with a same-size boot (Scenario D
   control).
2. **Never create/reformat/shrink.** Path A: `growpart`/`resize2fs` cannot do
   any of these by construction. Path B: `Format=`/`CopyBlocks=` MUST be unset
   and `Type=root` must match (it does, §1.1.C). A misconfig that makes repart
   *create*/reformat `/` is the single highest-severity failure mode — the
   strongest reason to prefer Path A.
3. **Boot/ESP/BIOS partitions untouched.** Root is the physically LAST partition
   (§1.1.D); growing it into trailing free space cannot touch `sda13` (BOOT),
   `sda14` (BIOS-boot), or `sda15` (ESP). Partition NUMBERS are unchanged
   (growpart edits only the selected partition's end; it does not renumber).
4. **#1930 A/B-UEFI substrate is files on the ESP — see §6.3.** The grow touches
   only the root partition; the ESP (and the `xpf-A`/`xpf-B` dirs + selectors +
   `09_xpf` it holds) is a *different, untouched partition*. No A/B partitions
   exist to disturb.
5. **Secure Boot posture unchanged.** The grow signs nothing and does not alter
   the ESP. (Reinforces #3/#4.)
6. **Ordering.** The grow must complete BEFORE `xpfd.service` /
   `xpf-day0-config.service` (so `/var` is full-size before xpf writes the
   config DB / stages the runtime). `sysinit.target` ordering (Path A) or early
   boot (Path B) both precede `multi-user.target` where xpfd lives. No
   interaction with the boot-class predicate (a config-state decision, not a
   disk decision).
7. **virt-sysprep seal must NOT pre-create the first-boot stamp.** The seal step
   (`bake.py` line 502–504) already `rm`s `/etc/xpf/.day0-config-applied`. The
   `/etc/xpf/.root-grown` stamp must likewise be ABSENT in the shipped image so
   the grow fires on the operator's first boot. The seal does not create it
   (it only removes); verify it is not present in the artifact.
8. **HA cluster-member first boot (ordering subtlety).** On a cluster member the
   day-0 flow installs `/etc/xpf/node-id`. The grow runs ONCE on the *first boot
   of a never-configured VM* — before the node has any sessions to sync — and a
   partition-end edit + online ext4 resize of empty trailing space is
   sub-second to a few seconds. It cannot regress a *running* cluster's
   failover (that is Item 2, separate). §8 still times it.
9. **No hot-path / byte-order / dual-AST concerns** — N/A (no dataplane, no Go
   config code). Stated so review can check the box.

### 6.3 Why the #1930 A/B substrate is safe (the v1 "key risk", now de-risked)

The directive flagged A/B-slot safety as the key risk. The verified shape
removes it almost entirely:

- The A/B "slots" are **`/boot/efi/EFI/xpf-A` and `xpf-B` directories inside the
  single ESP (`sda15`, vfat)** — not partitions. Kernels live in `/boot`
  (`sda13`, ext4), the grub selector logic is `/etc/grub.d/09_xpf` (regenerated
  into `/boot/grub/grub.cfg`) branching on `$cmdpath`.
- The grow operates ONLY on the **root partition (`sda1`)**. It does not touch
  `sda15` (ESP), so `xpf-A`/`xpf-B`/`xpf.selector`/shim/grub are untouched. It
  does not touch `sda13` (`/boot`), so the kernels + grub.cfg are untouched. It
  does not renumber any partition, so `efibootmgr`/`$cmdpath` entries (which key
  on the ESP partition + dir path) stay valid.
- Therefore a root grow **cannot** disturb the A/B kernel-promote/rollback
  channel. The one remaining check is empirical paranoia, not a structural risk:
  §8 runs a kernel promote/rollback cycle on a *grown* image to prove it.

The risk would only exist if the A/B substrate were separate GPT partitions
*after* root — it is not. (If a FUTURE bake change adds a trailing partition
after root, the "grow the last partition" assumption breaks; §10 OQ-3' makes
that a bake-time assertion.)

---

## 7. Risk assessment

| Class | Risk | Likelihood | Severity | Mitigation |
|---|---|---|---|---|
| **Data loss / unbootable** | Path B `repart.d` reformats/recreates `/` (Format=/CopyBlocks= set, wrong Type=). **Path A cannot do this.** | Low (Path A: ~nil; Path B: low) | **Critical** | Prefer Path A; Path B: assert no Format=/CopyBlocks=, dry-run-first in lab, review the selected partition in `--dry-run` output |
| **GPT / A-B / ESP disturbance** | grow renumbers/moves ESP, breaks #1930 UEFI entries | Very low (root is last; growpart edits one partition end; A/B is files on ESP §6.3) | High | Root-is-last verified (§1.1.D); lab-boot a resized image + run a kernel promote/rollback cycle (§8) |
| **Wrong root device selected** | wrapper assumes sda1 but bus is vda/nvme | Low | High | Resolve device from `findmnt /` + `/sys/.../partition`, never hardcode (§4 Path A) |
| **No-op / silent non-fire** | one-shot condition/stamp wrong → grow never happens | Low | Medium (regression-to-status-quo, not worse) | Scenario D asserts the grow ACTUALLY occurred (`df`/`lsblk` shows the larger `/`); stamp is absent in the sealed artifact (inv #7) |
| **Boot-time delay** | resize adds first-boot latency on a cluster member | Low | Low | First-boot-only, pre-session, sub-second–few-seconds; §8 times it |

---

## 8. Test plan

Image-bake + boot-sequence change → validated by baking + booting, not `go test`.
**It is offline-shippable and offline-validatable** — the cached cloudimg already
let me answer every empirical question, and a baked image boots under LOCAL incus
with a larger root disk. No production media, no operator lab, no loss cluster.

1. **Build/lint:** `python3 -c "import ast; ast.parse(open('scripts/image/bake.py').read())"`;
   `bash -n` on the new wrapper/unit; `systemd-analyze verify` on the new
   `.service`.
2. **New `validate.py` Scenario D (resized disk) — the crux.** Requires a small
   `launch()` extension to pass a root size (today `incus init --vm` takes the
   image default 8 GiB; Scenario D needs `incus config device override <name>
   root size=20GiB` or `-d root,size=20GiB`):
   - **Grow case:** launch with a root disk LARGER than the bake (20 GiB).
     After first boot assert `df -h /` / `lsblk` shows `/` ≈ 20 GiB (not 8),
     the system is reachable, and `xpfd verify-dataplane` still PASSES.
   - **Control (no-op) case:** launch at the EXACT bake size (8 GiB); assert the
     grow was a no-op (boot clean, no GPT change) — guards invariant #1.
   - **Idempotency:** reboot the grown VM; assert no second grow / stamp
     re-fire / clean boot.
3. **A/B + Secure Boot regression (#1930) — highest-value safety check.** On the
   GROWN baked qcow2, run an `xpfd upgrade kernel` promote/rollback cycle (the
   baked-qcow2 substrate, per CLAUDE.md) and confirm the ESP/GPT/`xpf-A`/`xpf-B`
   selectors are intact and A/B still works.
4. **Pre-flight inspection.** In the grown guest, eyeball `lsblk`/`sgdisk -p`:
   exactly the root partition grew; ESP/BIOS/BOOT untouched; partition numbers
   unchanged. (Path B: also capture `systemd-repart --dry-run=yes` showing only
   a grow on root, no create/format.)

### Does it need the loss-cluster lab / `make test-failover` / multi-increment?

- **`make test-failover` / loss cluster: NOT required.** Item 1 fires only on
  the first boot of a never-configured VM; it cannot affect a running HA
  cluster's failover. The failover/soak concern is Item 2 (out of scope, §9).
- **Local incus image-validate IS required** (Scenario D + the #1930 A/B
  regression) — the standalone `xpf-image-*` env `validate.py` already uses, NOT
  the shared loss cluster.
- **Multi-increment: NOT needed.** One PR: the unit + wrapper (or repart.d), a
  few bake lines, doc edits, one new validate scenario + the `launch()` size
  hook.

---

## 9. Out of scope (explicitly)

- **Item 2 of #1925** — HA image-replace runbook rehearsal + mixed-version soak.
  The issue scopes it to the LOCAL legacy cluster and says "out of scope for the
  image PR." Separate, lab-bound work item; depends on the #1930 LANE-2
  mixed-base gate already shipped.
- Growing/repartitioning **data partitions** other than root (single rootfs; no
  separate `/var`). `/boot` (`sda13`) and the ESP (`sda15`) are NEVER grown.
- Shrinking, LVM, btrfs subvolumes, encrypted-root (LUKS) growth — plain ext4 on
  GPT; out of scope.
- Bake-time disk-size parameterization beyond `XPF_IMAGE_DISK_SIZE` (Path C is
  only the fallback, not new surface).
- Any dataplane / Go / Rust / config-schema change.

---

## 10. Open questions for adversarial review

The three v1 "blocking" unknowns are RESOLVED (§1.1 C/D, §3) — listed here only
so review can re-check them. Genuinely open items follow.

- **(resolved) OQ-1 root type GUID** → discoverable `root-x86-64`; `Type=root`
  matches; no retag. (Re-verify if `XPF_BASE_RELEASE` is bumped.)
- **(resolved) OQ-3 root is last partition** → yes, `sda1` is physically last.
- **(resolved) growfs already present?** → NO `x-systemd.growfs`; the grow was
  cloud-init's, now purged (corrects v1).
- **OQ-A (design choice): Path A vs Path B.** Recommend Path A (growpart, no new
  package, smallest data-loss surface) over Path B (`systemd-repart`, the
  issue's named mechanism, +1 package, larger surface). Does the project want
  the literally-named mechanism, or the lower-risk tool that restores the
  pre-purge behavior? **This is the main decision for plan-review.**
- **OQ-3' (bake-time guard): assert root is the last partition at bake time** so
  a future cloudimg/bake layout change that adds a trailing partition fails the
  bake instead of silently growing the wrong partition. Worth a 2-line
  `virt-filesystems` assertion in `bake.py`?
- **OQ-B: grow on EVERY boot, or strictly first boot?** First-boot-only (stamp)
  is safer and matches cloud-image norms, but won't pick up a *post-deploy* disk
  enlargement. growpart-on-every-boot is itself a safe no-op when there's no
  free space (it cannot shrink/reformat), so "every boot" is defensible with
  Path A specifically. Recommend first-boot stamp for predictability; flag the
  trade. (Path B every-boot re-arms the reformat surface — another reason Path A
  is safer if "every boot" is wanted.)
- **OQ-C: device-resolution robustness.** The wrapper must resolve root from
  `findmnt /` (vda/sda/nvme0n1pN). Confirm the resolution handles the incus
  virtio (`vda`) and KVM/libvirt (`sda`/`vda`) buses the image actually boots
  on. Scenario D covers the incus path; KVM path is the same logic.
- **OQ-D: `validate.py launch()` size override mechanism.** Confirm the exact
  incus invocation to give a VM a root larger than the image default
  (`incus config device override <inst> root size=20GiB` after `init`, before
  `start`). Minor; nail down in implementation.
- **OQ-E: minimum systemd / tool floor.** Path A needs only growpart+resize2fs
  (present). Path B needs systemd ≥ 250 for `GrowFileSystem=` (have 259) AND the
  `systemd-repart` package. If `XPF_BASE_RELEASE` is bumped, re-verify presence.

---

## 11. Claude self-SMR (hostile)

**Strongest objection — "smallest benefit, and (for Path B) the riskiest line
in the appliance."** Two prongs, and v2's findings change how each lands:

1. *Marginal value.* The image ships 8 GiB; an operator can `growpart`+`resize2fs`
   by hand or bake a bigger image. xpf is a firewall, not a storage box, so most
   fleets never resize. — **Rebuttal:** the appliance *used to* auto-grow (via
   cloud-init); the bake silently removed that. Restoring a regressed,
   expected-of-every-cloud-image behavior is more defensible than adding a novel
   feature. The day-2 failure (full `/var` → unstageable #1964 rollback target)
   is real and nasty.

2. *Asymmetric risk.* A `repart.d` file can reformat/recreate `/`. — **Rebuttal,
   strengthened by v2:** that risk is **Path B's**, and v2 recommends **Path A**
   (`growpart`+`resize2fs`), which *cannot* create/reformat/shrink by
   construction and needs no new package. The asymmetric-risk objection is the
   reason to pick Path A, and it no longer blocks the change.

The three empirical unknowns v1 used to justify DEFER-LAB are **answered offline**
(discoverable root GUID, root-is-last, no x-systemd.growfs), and the A/B "key
risk" is structurally absent (slots are files on an untouched ESP, §6.3). What
remains is one design choice (Path A vs B) and routine boot validation that the
existing `validate.py` env already supports — not a lab-gated unknown.

**Disposition: PLAN-READY (feasible offline increment).**

The gap is real, the mechanism is well-understood and verified, the safety story
is sound, and it is one small PR validated by the standalone local-incus
image-validate env (Scenario D + a #1930 promote/rollback regression on a grown
image) — no production media, no operator lab, no loss cluster. Recommend
implementing **Path A** (with Path B available if the project wants the
issue's named `systemd-repart` mechanism, and Path C docs-only as the kill
landing). If reviewers still judge the convenience not worth even Path A's
near-nil risk, PLAN-KILL with a documented manual step remains acceptable.
