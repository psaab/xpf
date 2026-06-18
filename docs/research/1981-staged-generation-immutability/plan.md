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

### Option D (RECOMMENDED after AGY review) — preinst invalidates `.generation`, postinst rewrites it (the "Hybrid")

**AGY plan review (NEEDS-MAJOR on bare Option C, FOLDED):** Option C as
written has a FATAL window. dpkg overwrites the staged binaries during the
UNPACK phase, BEFORE any maintainer script that updates `.generation`
runs. The OLD `.generation` sits on disk unchanged while dpkg replaces the
binaries around it. An operator cut that both STARTS and FINISHES during
unpack reads the SAME stale genid before and after the copy → publishes a
torn, mixed-generation set undetected. (The per-binary-checksum mitigation
does not fully save C either: mid-replace the copied bytes can match the
stale manifest's checksum for some files and not others, and a cut that
copies a not-yet-replaced file + an already-replaced file with a manifest
that matches NEITHER cleanly is ambiguous.) Bare C is rejected.

The fix is to make the `.generation` marker reflect the unpack state by
having the SCRIPT THAT RUNS BEFORE UNPACK invalidate it:

- `preinst` (runs BEFORE unpack, `case upgrade`): DELETE or overwrite
  `staged/.generation` with a sentinel value `"unpacking"` (and a dead-PID-
  safe marker is unnecessary here — see crash-safety below). This is the
  key insight: the marker must be invalidated by the script that runs
  before dpkg starts replacing binaries, not the one that runs after.
- dpkg unpacks (binaries replaced; `.generation` says "unpacking").
- `postinst` (runs AFTER unpack+configure completes): write the NEW genid +
  per-binary checksum manifest to `staged/.generation` as the FINAL step.
- `copyStaged` REFUSES to read staged whenever `.generation` is absent or
  reads `"unpacking"` (returns "package unpack in progress, retry after apt
  completes"), AND verifies the genid is UNCHANGED across the copy AND the
  per-binary checksums match the copied bytes.

Now an operator cut during unpack sees `"unpacking"` and refuses — it can
NEVER read a torn set. A cut entirely outside the unpack window sees a
stable valid genid + matching checksums and proceeds. This closes the
window WITHOUT a second staging tree (Option B) or a `/run` lock with
dead-owner staleness (Option A).

**Crash-safety of Option D:** if dpkg crashes mid-unpack, `.generation`
stays `"unpacking"` and operator cuts stay refused until the package
operation is completed (`dpkg --configure -a` re-runs postinst, which
rewrites a valid `.generation`) or the package is reinstalled. AGY's point
stands: WEDGING operator cuts while the package is half-unpacked is the
CORRECT fail-safe — staged is genuinely inconsistent in that state. This is
strictly better than Option A's `/run` sentinel (no tmpfs-reboot escape
needed, no dead-PID logic; the marker lives WITH the thing it describes).

### Option D ordering correction (Codex NEEDS-MAJOR, FOLDED)

**Codex found a self-interference bug in the naive "postinst writes the
manifest at exit" framing.** `debian/xpf.postinst` ITSELF runs the
auto-cut `"$STAGED/xpfd" upgrade` during `configure` (`postinst:136-146`,
before `#DEBHELPER#` at ~:193). If `.generation` is rewritten only at
postinst EXIT, the postinst's own auto-cut runs while `.generation` is
still `"unpacking"` → `copyStaged` REFUSES → the first standalone in-place
cut is permanently deferred (broken first deployment).

**Correction:** postinst must write the VALID `.generation` manifest
BEFORE it invokes its own `"$STAGED/xpfd" upgrade` auto-cut — i.e. right
after unpack/seed completes and the staged tree is known-consistent, and
strictly before any cut (its own OR an operator's) can read it. Concretely:
postinst's ordering becomes: seed/verify staged complete → WRITE valid
`.generation` → THEN the auto-cut (which now reads a valid manifest) →
`#DEBHELPER#`. The preinst-sets-"unpacking" / postinst-sets-valid invariant
holds; only the postinst-internal ordering relative to its own cut needs to
be explicit.

### Old-binary-ignores-`.generation` rollout TOCTOU (Codex, FOLDED)

Until the FIXED `xpfd` is the running/sbin-resolved binary, a manual
`/usr/local/sbin/xpfd upgrade` resolves to the OLD versioned binary that
does NOT know about `.generation` and will not refuse. So Option D protects
operator cuts only once the fixed binary is in service. This is the same
class as #1985's buggy-old-binary rollout gap and is INHERENT to fixing a
binary-side check: the protection engages after the fix is the live binary.
Disposition: document this one-rollout exposure in the PR body +
`docs/in-place-upgrade.md`; the existing verify-dataplane gate +
refuse-before-STOP remain the backstop for the transition. NOT a blocker
for Option D, but must be stated honestly.

### Crash-safety wording reconciliation (Codex)

The acceptance criterion "no permanent wedge" (§3) and §4.4's "stranded
`unpacking` until reinstall/configure" must be reconciled: a half-unpack
that strands `.generation == "unpacking"` is cleared by `dpkg --configure
-a` (re-runs postinst → rewrites a valid manifest) or reinstall — it is NOT
a permanent wedge, it is a wedge that clears when the package operation is
COMPLETED, which is the correct fail-safe (AGY's point). Reword §3 to "no
wedge that outlives completion of the package operation." This is a
documentation fix, not a mechanism change.

### Recommendation to review (UPDATED)

**Option D (Hybrid) is the recommended mechanism**, with the postinst
ordering correction above. It directly closes the unpack window that bare
Option C misses, with the smallest footprint (no second tree, no `/run`
lock). Option B (immutable versioned staging) remains the most robust if
review wants true content immutability AND wants to avoid relying on the
new binary honoring the check — Codex notes B's rejection is "not fully
earned." Options A and bare C are rejected. **Plan review (architecture
step) should ratify D-with-ordering-fix vs B** — the deciding question is
whether the old-binary rollout TOCTOU + postinst-ordering complexity of D
outweighs B's extra copy.

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

Strong counter-factual regression tests (Option D). AGY flagged the bare-C
test as WEAK because it mutated `.generation` mid-copy, which does NOT
recreate the real failure (a cut that reads a STALE-but-stable genid during
unpack). The Option-D tests recreate the REAL window:

- **Unpack-window refuse (the real failure mode):** simulate the unpack
  state — `.generation == "unpacking"` (as preinst left it) with the staged
  binaries in a torn/mixed state. Assert `copyStaged` REFUSES (does not
  publish). Counter-factual: with the refuse check removed (pre-fix
  `copyTree`+self-checksum path), the same torn staged set PUBLISHES a mixed
  dir — prove the OLD path does not detect it.
- **postinst self-ordering (Codex):** assert the postinst writes a VALID
  `.generation` BEFORE its own auto-cut runs — a test that runs the postinst
  flow (or asserts the script ordering) and confirms the auto-cut does NOT
  see `"unpacking"`. This is the regression guard for the first-deployment
  break Codex found.
- **Stable-genid happy path:** valid `.generation` (genid + matching
  per-binary checksums), consistent binaries → `copyStaged` succeeds.
- **Mid-copy genid change:** a test seam that flips `.generation` to a new
  genid between the before-read and after-read → abort on the post-copy
  recheck.
- **Checksum mismatch:** copied bytes don't match the manifest's per-binary
  checksum → abort.
- **Crash-safety:** `.generation == "unpacking"` persists after a simulated
  dpkg crash → cuts stay refused until a valid manifest is rewritten
  (postinst re-run).

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

- Claude SMR: PLAN READY for arch review (B vs C; A rejected) — but see AGY.
- AGY companion: PLAN NEEDS-MAJOR (r1) — bare Option C has a FATAL unpack
  window (dpkg replaces binaries during unpack while `.generation` stays
  stale; a cut entirely within unpack reads the same stale genid before+
  after and publishes a torn set). FOLDED: adopted Option D (Hybrid) —
  preinst invalidates `.generation` to `"unpacking"` BEFORE unpack, postinst
  rewrites the valid manifest AFTER; `copyStaged` refuses on
  absent/"unpacking". AGY also correctly noted wedging operator cuts during
  a half-unpack is the right fail-safe. Re-verdict on Option D: expected
  PLAN YES pending the architecture-review ratification of D vs B.
- Codex companion: PLAN NEEDS-MAJOR (r1) — verified dpkg order, but found
  (1) postinst's OWN auto-cut (`postinst:136-146`) would see
  `.generation=="unpacking"` and refuse → first in-place deploy permanently
  deferred (manifest must be written BEFORE the postinst auto-cut, not at
  exit); (2) old-binary-ignores-`.generation` rollout TOCTOU; (3) §3 "no
  permanent wedge" vs §4.4 "stranded unpacking" wording contradiction; (4)
  B's rejection "not fully earned." ALL FOLDED (postinst ordering
  correction, rollout-TOCTOU disposition, crash-safety reword, B left open
  for the arch review). Re-verdict pending arch-review ratification of D vs
  B. STILL needs the architecture-review step before engineer.
