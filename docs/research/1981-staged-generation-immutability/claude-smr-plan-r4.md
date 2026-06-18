# Claude SMR — hostile plan review r4 (#1981)

**Plan:** `docs/research/1981-staged-generation-immutability/plan.md` r4
**Verdict:** **PLAN-READY.**

r4 closes the single hole on which Codex r3 and AGY r3 independently converged
(the same-version `versions/<ver>` replacement protocol). I re-read the B-P3b
fix hostilely; both resolutions are sound and the recommended OPT1 reuses an
already-proven invariant.

## The r3 hole is genuinely closed

B-P3b now gives a SAFE replacement protocol instead of the unsafe blind rename:

- **OPT1 (recommended):** refuse a same-version-different-genid cut when the
  existing `versions/<ver>` is the live `current` or rollback (`PreviousVersion`)
  target; otherwise RemoveAll+recopy reusing the EXISTING guarded-delete in
  `cleanupFailedVerifyCopy` (`cutover.go:605`). I verified that function already
  proves a version dir is neither `current` nor previous before deleting it — so
  OPT1 adds NO new delete-safety surface; it composes a check the codebase
  already trusts. The refused case (same version, different bytes, dir is live)
  is genuinely pathological — a dev/re-stage scenario, not a production upgrade
  path — and refusing it pre-PREFLIGHT (pure, daemon untouched) is the correct
  fail-safe. This satisfies BOTH Codex's "ENOTEMPTY / don't mutate live dir
  during COPY" and AGY's "active-daemon race" objections: nothing is deleted when
  the dir is live.
- **OPT2 (clean structural):** `versions/<ver>-<genid>` keying makes the rename
  always target a fresh path — AGY's recommendation. r4 correctly flags it
  ripples into `current`, the unit drop-in ExecStart, rollback keying, and GC,
  so it is the larger change. Sound, but OPT1 is the minimal close.

Both close the hole; the plan no longer prescribes an unsafe rename. The choice
is a real engineer-time decision (does same-version-different-genid happen in
production?), not an unresolved correctness gap — exactly the kind of bounded
"pick at implementation" the research deliverable should surface.

## Everything else holds (re-confirmed)

- The deferred-publish recovery (my r3-NIT1, AGY r3-NIT) is folded into B-P2b
  with two named recovery verbs.
- Mechanism B remains ratified by all three; the disk math, crash matrix,
  postrm purge/downgrade, atomic symlink, publish-lock, free-space/ENOSPC
  fail-safe, and the counter-factual torn-source test pin are all in place.
- The bootstrap caveat (O4) is honestly stated and intrinsic.

## Why PLAN-READY

Every finding from r1, r2, and r3 across all three reviewers is folded with a
concrete, invariant-level resolution. The remaining items are genuine
user/engineer decisions (O1 disk budget, O2 genid form, O3 publish verb, O4
bootstrap-caveat acceptance, B-P3b OPT1-vs-OPT2, B-P2b recovery verb), not
correctness holes. The plan correctly identifies the mechanism, the full
invariant set, the crash matrix at every kill point, the disk budget with a
`/var` floor, the maintainer-script lifecycle (incl. error-unwind and
purge/downgrade), and the test shape with the counter-factual pin. This is the
right plan to hand to `/engineer 1981`. PLAN-READY; recommendation Option B
ratified.
