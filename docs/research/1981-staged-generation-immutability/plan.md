# Plan: Close the dpkg-unpack vs operator-cut staged-source race (#1981)

## 1. Problem

`/usr/local/share/xpf/staged/` is not an immutable source during an
operator `xpfd upgrade`. dpkg replaces the staged binaries during unpack
(`override_dh_auto_install` in `debian/rules:78-84` installs them into the
package payload; on the target, dpkg overwrites them in place during
unpack). The preinst lock gate is point-in-time and does NOT hold across
unpack (`xpf.preinst:14-22, 203-219` — the fd dies at preinst exit). So a
manual cut can begin while dpkg is mid-replace, and `copyStaged` can
publish one `versions/<TargetVersion>` directory containing a MIX of old
and new binaries.

The current integrity check (`cutover.go:503-543`) is `copyTree(StagedDir,
partial)` returning a checksum, then `copyTreeChecksum(partial)` re-hashing
the COPIED bytes, then comparing the two. That proves the copy is
internally intact (no bit-rot during copy) — it does NOT prove all four
managed binaries came from the SAME dpkg unpack generation. The
verify-dataplane gate (`cutover.go:547-569`) proves only `xpfd` + the shim
validate together, not that `cli` / `xpf-userspace-dp` / `xpf-day0-config`
share a generation.

`docs/in-place-upgrade.md:270-279` documents this as the
"dpkg-vs-operator staged-source race" caveat with no tracking issue.

## 2. Hypothesis

The race window is narrow (dpkg unpack of four binaries) and the
operational guidance ("do not run xpfd upgrade during apt upgrade") plus
the existing lock gate already make a real collision unlikely. But "rare +
documented" is not "closed," and a mixed-generation publish is a silent
correctness failure (an apparently successful upgrade running a torn
binary set). The fix is to make the cut's SOURCE provably a single
generation: either (A) a generation sentinel/manifest that exists for the
whole unpack+configure interval and blocks an operator cut, or (B) unpack
into an immutable versioned staging dir and have the cut copy from THAT,
or (C) a source-generation id the operator cut verifies before AND after
copy. The right mechanism is a design choice with dpkg-ordering and
crash-safety tradeoffs — this is the OPEN design question for plan review.

## 3. Goal / acceptance criteria

- An operator `xpfd upgrade` CANNOT publish a `versions/<ver>` dir that
  mixes binaries from two dpkg generations.
- The cut either (i) refuses to read staged while dpkg holds the
  unpack/configure interval, or (ii) copies from an immutable source whose
  contents cannot change mid-copy, or (iii) detects a source-generation
  change across the copy and aborts.
- Crash-safe: a dpkg or operator crash mid-window leaves a recoverable
  state (no torn versions/<ver>, no stranded sentinel that wedges future
  upgrades).
- A regression test that mutates one managed staged binary while
  `copyStaged` runs FAILS before the fix (the self-generated target
  manifest cannot catch a mixed source generation) and PASSES after.

## 4. Approach — candidate mechanisms (review to pick)

### Option A — generation sentinel spanning the unpack/configure interval

dpkg call order for an upgrade: `new-preinst upgrade`, UNPACK,
`old-postrm upgrade`, `new-postinst configure`. The sentinel must exist
across that whole span.

- `preinst` (BEFORE unpack) writes a sentinel
  `/run/xpf/staged-generation.lock` (or a generation-id file) marking
  "staged is being replaced."
- `postinst` (AFTER unpack+configure) removes it.
- The operator cut (`copyStaged` / `Runner.Run` preflight) REFUSES to read
  staged while the sentinel exists (returns a clear error: "package unpack
  in progress").
- Crash-safety: the sentinel lives on `/run` (tmpfs); a crash between
  unpack and postinst leaves it set until reboot — which would block the
  operator cut until reboot OR until the deferred postinst re-runs. Need a
  staleness escape (e.g. sentinel carries the dpkg PID / a timestamp; the
  cut treats a sentinel whose PID is dead as stale and clears it). This is
  the main complexity of Option A.

PRO: small, no layout change. CON: the dead-owner staleness logic
recreates the lock-staleness problem (#1984) in a new place; a crashed
unpack can wedge operator cuts.

### Option B — immutable versioned staging (unpack to a fresh dir, atomic publish)

- dpkg unpacks into `staged/` as today, but `postinst` (after a COMPLETE
  unpack) atomically publishes a new immutable generation:
  `staged-gen/<genid>/` (copy or rename), writes a generation manifest
  (per-binary checksums + genid), and atomically flips a
  `staged-gen/current -> <genid>` symlink.
- The operator cut copies from `staged-gen/current` (resolved ONCE at cut
  start) — an immutable snapshot. dpkg replacing `staged/` mid-cut does not
  touch the resolved generation dir.
- GC old generations like `versions/` (#1964 retention).

PRO: genuinely immutable source; the manifest gives a generation-consistency
proof for free; aligns with the existing `versions/<ver>` + `current`
pattern the team already trusts. CON: a second copy on every package
install (disk + time); more moving parts; the operator cut now copies
gen->versions (two copies total). Could be mitigated by `postinst` doing
`staged -> staged-gen/<genid>` via hardlink/rename.

### Option C — source-generation id verified before+after copy (minimal)

- `postinst` (after complete unpack) writes
  `staged/.generation` = `<genid>` + a manifest of per-binary checksums,
  as the LAST step (so it only appears once staged is fully replaced).
- `copyStaged` reads `.generation` BEFORE copy, copies, then reads
  `.generation` AGAIN AFTER copy; if it changed (or the manifest checksums
  don't match the copied bytes), ABORT (a concurrent dpkg replace
  happened).
- Because postinst writes `.generation` LAST, a cut that starts mid-unpack
  sees either no `.generation` (refuse) or a stale one that won't match the
  partially-replaced binaries (abort on post-copy recheck).

PRO: smallest change; no second staging tree; directly answers Codex's
"verify a stable generation id before and after copying." CON: the manifest
must be written atomically as the final unpack step (dpkg conffile/replace
ordering must guarantee `.generation` is last — needs verification that
postinst is the right hook and that no unpack step touches it later).

### Recommendation to review

Option C is the smallest fix that directly closes the defect and matches
Codex's stated direction (verify a source generation id before+after copy).
Option B is the most robust (true immutability) but adds a second copy and
a new tree. Option A reintroduces a staleness/dead-owner subproblem and is
NOT recommended. **Plan review should choose B vs C** (A rejected). Lean C
for scope; escalate to B if review judges the post-copy recheck window
insufficient (e.g. a copy that finishes within a single dpkg replace step
could still be torn — though the per-binary manifest checksum on the COPIED
bytes catches that).

## 5. Alternatives rejected

- **Hold the flock across unpack.** Impossible — a preinst fd dies at
  preinst exit (dpkg boundary); already documented.
- **Status quo (doc caveat only).** Silent torn-binary publish remains
  possible. Rejected — Codex correctly flags that "documented" != "closed."
- **Operator-only mutex (no package-side cooperation).** The package side
  is the mutator that replaces staged; a fix that ignores it can't see the
  unpack window. Rejected.

## 6. Files touched (depends on chosen option)

- `pkg/upgrade/cutover.go` (`copyStaged` source-generation check)
- `debian/xpf.postinst` (write generation manifest / publish immutable gen
  as the final step) and possibly `debian/xpf.preinst` (sentinel, Option A
  only)
- `debian/rules` (Option B: stage into the gen tree)
- `pkg/upgrade/state.go` / a new manifest type (generation id + per-binary
  checksums) — likely shares the `pkg/upgrade/manifest` SSOT from #1982
  (coordinate: #1982 centralizes the binary LIST; this adds the GENERATION
  manifest over that list)
- `docs/in-place-upgrade.md` (replace the caveat with the closed-race
  contract)

## 7. Test strategy

Strong counter-factual regression test:

- Seed `staged/` with a generation manifest (Option C) or a published gen
  (Option B).
- Start `copyStaged` with a hook (a test seam in `copyTree` or a
  per-binary copy callback) that MUTATES one managed staged binary
  mid-copy AND updates/omits the source `.generation`.
- Assert `copyStaged` ABORTS with a generation-mismatch error.
- Counter-factual: with the source-generation check REMOVED (reconstruct
  the pre-fix `copyTree`+self-checksum path), the same scenario PUBLISHES a
  mixed dir — prove the OLD path would not detect it (the test pins that
  the self-checksum is insufficient).
- Crash-safety tests per chosen option (Option A: dead-owner sentinel
  cleared; Option B: partial publish not resolved by `current`; Option C:
  missing `.generation` → refuse).

## 8. Invariants

- A published `versions/<ver>` always contains binaries from exactly one
  dpkg generation.
- The source-generation check runs on EVERY operator cut, not just the
  postinst-driven one.
- No mechanism reintroduces a wedge (a crashed unpack must not block
  operator upgrades forever — escape via tmpfs reboot and/or dead-owner
  staleness, depending on option).

## 9. Risk

MEDIUM-HIGH (this is the HIGH-severity finding and touches the
dpkg/maintainer-script boundary + the cut copy path). Crash-safety across
the dpkg unpack interval is the hard part. Option C is the lowest-risk that
still closes the defect; Option B is more robust but larger. The
architecture review (engineering-style workflow step 4) is REQUIRED here —
this crosses the packaging boundary.

## 10. Rollout / validation

- Unit + crash-safety tests (above).
- A real .deb upgrade rehearsal on a standalone VM with an injected
  mid-unpack operator cut (scripted race) — best-effort; if the race is
  hard to stage deterministically in the VM, the unit-level seam test is
  the authoritative proof and the limitation is stated in the PR body.
- `make test-deploy` standalone + a normal `apt upgrade`-style install to
  confirm no regression in the happy path.
- Coordinate with #1982 (shared manifest SSOT) so the generation manifest
  is built over the centralized binary list, not a third copy.

## 11. Disposition

needs-research → after this plan converges and review PICKS the mechanism
(B vs C), it becomes engineer-ready. Do NOT engineer before the
mechanism choice is locked. Highest-severity of the five; requires the
architecture-review step. Coordinate sequencing with #1982.

## Reviewer verdicts

- Claude SMR: _pending_
- Codex companion: _pending_
- AGY companion: _pending_
