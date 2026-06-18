# AGY adversarial plan review r2 (#1981)

**Verdict:** PLAN-NEEDS-MAJOR (mechanism B accepted; spec needs tightening)

Verbatim AGY output:

---

**Verdict:** `PLAN-NEEDS-MAJOR`

Flipping the recommendation from Option D to Option B correctly sidesteps the
maintainer-script lifecycle complexity and invalidation races, but the r2 plan
introduces new failure modes, disk-leak hazards, and concurrency races.

### 1. dpkg abort-upgrade / error-unwind — permanent-wedge window
- **Non-atomic symlink overwrite:** `ln -sf <target> current-gen` is NOT atomic
  (unlink-then-create leaves a window where current-gen is absent). Fix: atomic
  swap — `symlink(<genid>, current-gen.tmp)` then `rename(current-gen.tmp,
  current-gen)`. (The preinst's existing `atomic_symlink` already does this.)
- **Idempotency / orphan recovery on postinst crash:** a mid-publish crash
  leaves `staged-gen/<genid>.partial`. The publish command must sweep ALL
  `.partial` dirs BEFORE copying (like `removeAllPartials`), not wait for an
  end-of-run GC.

### 2. Disk cost — /var exhaustion
- **Up to 9 copies of the binary set:** `staged/` (1) + `staged-gen/`
  current+N=3 (4) + `versions/` current+N=3 (4) = 9 × ~50-70 MB ≈ 450-630 MB.
  On a 1-2 GB `/var` this is risky. **staged-gen retention should NOT mirror
  versions/'s N=3** — it only needs the current generation (+ maybe one prior).
- **Disk-full upgrade wedge:** a failed publish under `set -e` aborts configure
  → half-configured package + leaked `.partial` that blocks `apt-get install
  -f`. The publish must be best-effort (not fail configure) and pre-sweep
  partials.

### 3. INIT-time resolution vs #1967 — GC-vs-resume race
- A cut crashes at StateCopied with genid `g0` in the journal; the operator then
  installs a newer package which publishes + GCs, sweeping `g0` (now beyond
  N=3). The resume reads `g0` and fails (dir deleted). Fix: GC must parse the
  journal and protect the genid referenced by any active/resumable transaction.

### 4. New failure modes from B
- **Publish/cut concurrency:** `xpfd publish-generation` (postinst) must acquire
  `/run/xpf/upgrade.lock` so it serializes against an active operator cut; else
  the publish's GC can delete a generation the cut is reading.
- **Postinst failure auto-cut guard:** a failed publish must exit and NEVER run
  the auto-cut.

### 5. postrm staged-gen purge + downgrade
- **Purge:** postrm `purge` removes only `$VERSIONS`, not
  `/var/lib/xpf/staged-gen` → orphan dir after purge (Policy violation). Add
  staged-gen removal on purge.
- **Downgrade leak:** a downgrade to a pre-B package leaves `staged-gen/` as dead
  weight that the old postrm never cleans. `postrm upgrade` must detect a
  pre-B incoming `$2` and `rm -rf staged-gen` (mirror the #1985 version-keyed
  downgrade detection already in the postrm).

### Verification of r1 findings
§11 of plan.md maps all r1 findings; Option B addresses the original preinst
abort-wedge and first-install races. Workspace left clean.
