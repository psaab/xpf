# Claude SMR — hostile plan review r3 (#1981)

**Plan:** `docs/research/1981-staged-generation-immutability/plan.md` r3
**Verdict:** **PLAN-READY.** One research-grade NIT for `/engineer` (the
deferred-publish recovery verb); does not block.

r3 folds every r1 and r2 finding from all three reviewers, and the mechanism
(Option B) is ratified by all three (Codex verbatim "B is the right direction
over D"; AGY accepted B as architecturally superior; my r2 was PLAN-READY with
two MINORs). I re-read r3 hostilely for new issues introduced by the edits.

## My r2 MINORs are closed
- **SMR r2-MINOR1 (publish/GC lock + journal-genid GC protection):** closed by
  B-P2b (publish takes `/run/xpf/upgrade.lock`) + B-P3/§4.B.5 (GC protects
  `Journal.SourceGeneration`). ✓
- **SMR r2-MINOR2 (no silent stale cut on publish failure):** closed by B-P2b
  (publish failure logs loudly + skips the auto-cut) + B-P7 (the "no new
  generation published" condition is surfaced). ✓

## NIT-1 (research-grade — resolve at /engineer): the DEFERRED-publish recovery verb

B-P2b says a publish that finds the upgrade lock busy DEFERS (drops
`/run/xpf/upgrade-deferred`, does not cut). Walk the recovery: the operator's
later `xpfd upgrade` takes the lock — but the publish never ran, so
`current-gen` still names the OLD generation, and the cut reads
`TargetVersion == current` → idempotent no-op ("already committed"). The staged
NEW binaries are present but were never published, so the operator's re-run does
nothing and they may believe they upgraded.

This is fail-SAFE (no torn set, no downgrade) and is the SAME class as the
existing #1965 `upgrade-deferred` residual, but the recovery verb must be
explicit. Cleanest options for `/engineer`:
- make `xpfd upgrade` PUBLISH-then-cut when it observes the staged tree is newer
  than `current-gen` (or the `upgrade-deferred` marker is set) — it already holds
  the lock at that point; OR
- document recovery as `dpkg-reconfigure xpf` (re-runs the postinst publish).

The plan should name which (a one-line addition to B-P2b / the recovery
section). NIT, not a blocker: the failure is safe and bounded, and the fix is a
verb choice, not an architecture question.

## Hostile re-read of the r3 edits — no new holes

- **`.srcgen` + GC:** the `.srcgen` stamp lives inside `versions/<ver>/` (not a
  sibling dotfile in `VersionsDir`), so it is removed atomically with its version
  dir on GC and does not create a new orphan-dotfile sweep surface like
  `.dbsnap` did. Good. (If `/engineer` instead places it as a sibling
  `.<ver>.srcgen`, it must extend the orphan-dotfile GC — flag that.)
- **staged-gen retention N=2 + journal protection:** N=2 + protect(current-gen,
  journaled-genid) is sound — an in-flight cut's source is always either
  current-gen or its journaled genid, both protected; a crashed cut's genid is
  protected until its journal clears. No way to GC a needed source.
- **publish-under-lock vs postinst timing:** the postinst publish runs after the
  preinst lock gate proved the lock free; taking the lock in the publish closes
  the #1965 TOCTOU residual for the new publish/GC. Consistent with the existing
  lock-ordering note (`docs/in-place-upgrade.md:382-384`): the publish nests the
  host upgrade lock INSIDE, never crossing the cluster/deploy lock — no new
  deadlock.
- **bootstrap caveat honesty (O4):** correctly framed as intrinsic and bounded;
  matches the #1964 first-install one-hop precedent. Not a residual hole.
- **disk math (~7 copies):** honest and now correctly bounded by N=2 on
  staged-gen; the `/var` floor is surfaced as O1 for the user. Good.

## Why PLAN-READY now

The plan correctly identifies the mechanism (B), the full invariant set
(B-P1..P7 incl. atomicity, locking, free-space, purge/downgrade), the crash
matrix (publish atomicity, GC-vs-resume, ENOSPC fail-safe), the disk budget with
a stated `/var` floor, the honest first-deploy bootstrap caveat, and the test
shape — including the counter-factual torn-source pin that recreates the pre-fix
failure mode (engineering-style "Test strength"). The three open questions (O1
disk budget, O2 genid form, O3 publish verb, O4 bootstrap-caveat acceptance) are
genuine user/engineer decisions, not unresolved correctness holes. NIT-1 is a
recovery-verb choice for `/engineer`. This is the right plan to hand to
`/engineer 1981`.
