---
status: DRAFT v1 — awaiting parent-run plan review (Codex + Gemini hostile review). No production code.
issue: #10487
phase: single PR — prune 2 dead entries + give accepted entries a re-check/expiry; no production code
base: origin/master b71c52d60
---

# Plan: Expire refactoring-audit accepted entries that outlive their floors (#10487)

## 1. Status

DRAFT v1, written 2026-09-21 against `origin/master b71c52d60`.
STEP-0 liveness confirmed: the issue is live at HEAD, no prior fix exists
(empty `git log --grep=10487`, empty refaudit/floor grep on `origin/master`,
no merged or open PR touches it). Work stops after plan commit + push;
production code lands only after adversarial plan review.

## 2. Issue framing

`docs/refactoring-audit-accepted.txt` is the ONLY escape from the hard
touched-file gate (`TestTouchedFileCrossedModularityThreshold`, #7253).
`isAccepted` (`pkg/refactoraudit/audit_touched_test.go:187-197`) matches
**path plus tier only** — no LOC re-check, no expiry — so an accepted entry
is a permanent licence: it silently pre-authorizes any future regrowth of
that file past its floor, forever.

Two of the twelve entries are dead at HEAD: their files were split/shrunk
below the floor the entry accepts, and nothing noticed:

| Entry (line) | Tier / floor | Head LOC (`wc -l`) | Deficit |
|---|---|---|---|
| `pkg/api/metrics_userspace.go` (:24) | [REFACTOR] / 2000 | 529 | −1471 |
| `pkg/vrrp/instance.go` (:26) | [WATCH] / 1500 | 825 | −675 |

The `metrics_userspace.go` case is the sharp one: #7700 split the file and
its scope explicitly required pruning the entry once under the floor; the
prune never happened, and the gate stayed green because nothing re-checks.
The decision record has drifted from reality with no signal, exactly the
failure mode the accepted file's own header claims is impossible
(`docs/refactoring-audit-accepted.txt:16-18`: "cannot go stale from an
unrelated file growing elsewhere" — and `docs/refactoring-audit.md:156-157`
repeats it). Shrinking, not growing, is what stales it.

Acceptance (from the issue): prune the two dead entries (plus audit the
remaining ten for the same drift — done, see §4), give accepted entries a
re-check or expiry, and make re-adding a below-floor entry fail the gate
(red-on-revert).

## 3. Scope-value

**In:** prune dead entries; add a re-check that fails (or warns) when an
accepted path measures below its floor; extend the fail-on-revert pins;
update the two doc claims that assert accepted entries cannot go stale.

**Value:** closes a silent pre-authorization hole in the repo's hardest
modularity gate. Today an author regrowing `metrics_userspace.go` from 529
back past 2000 LOC gets a green gate on a 2010-LOC decision that no longer
describes the file — the crossing that most needs a fresh written decision
is the one the gate waves through. The fix restores the invariant the gate
was built on: every silenced crossing traces to a live decision.

**Not value:** no production behavior changes; no heatmap/freshness changes
(#7253/#7269 territory); no new thresholds.

## 4. Shipped-context (what exists today, with receipts)

Gate decision (all paths at `b71c52d60`):

- Floors/tiers: `auditFloor = 1500`, `refactorFloor = 2000`,
  `tierWatch = "[WATCH]"`, `tierRefactor = "[REFACTOR]"`
  (`pkg/refactoraudit/audit_canary_test.go:20-26`).
- Crossing predicate: `base < floor && head >= floor`, highest floor only
  (`pkg/refactoraudit/audit_touched_test.go:74-103`).
- Escape: `isAccepted` matches `a.path == c.path` and
  `a.tier == c.tier || a.tier == tierRefactor` — path+tier only, no LOC
  (`audit_touched_test.go:187-197`).
- Well-formedness: `TestAcceptedFileWellFormed` checks reason non-empty,
  no duplicate path+tier, and `classify.sh audited <path>` — **no LOC or
  existence leg** (`audit_touched_test.go:514-532`). This is the hole.
- Changed set: `git diff --name-only <merge-base(origin/master,HEAD)>`
  (`docs/refactoring-audit.md:120-125`); on master the set is empty so the
  touched gate is structurally silent there — but `TestAcceptedFileWellFormed`
  reads the committed file + tree, not the diff, so it runs (and can fail)
  on master too.

Blast-radius census (HEAD, `wc -l` per accepted path; 12 entries, :24–:35):

- DEAD (2/12 = 16.7%): `metrics_userspace.go` 529 < 2000;
  `vrrp/instance.go` 825 < 1500.
- LIVE (10/10 verified ≥ tier floor): `daemon.go` 1942, `metrics.go` 1874,
  `coordinator/mod.rs` 1875, `compiler_interfaces.go` 2054 (≥1500 under a
  [WATCH] entry — live; a future [REFACTOR] crossing there would correctly
  NOT be silenced), `compact_normalize_scope.go` 1794, `authz.go` 1594,
  `sync.go` 2540, `afxdp/mod.rs` 1678, `forwarding.rs` 1592,
  `maps_sync.go` 2041. Zero entries point at missing files.
- Corroboration nuance: the *committed* heatmap still lists
  `metrics_userspace.go` at 2010 (`docs/refactoring-audit-current.txt:21`)
  while the tree measures 529 — the snapshot is stale in the other
  direction (freshness-advisory territory, not this issue), and it means a
  fresh recomputation drops the file from the heatmap exactly as the issue
  reports.
- Pre-authorization mechanics (the exploit, concretely): a branch growing
  `metrics_userspace.go` 529 → 2000+ reports a [REFACTOR] crossing via
  `thresholdCrossings`, and `isAccepted` matches the dead :24 entry → green.
  Same shape at 1500 for `instance.go` via :26.
- No existing expiry/decay/prune mechanism: grep for
  `expir|decay|prune|stale.*accept` over `pkg/refactoraudit/` finds only the
  canary's heatmap-row floor check (`audit_canary_test.go:326-329`, a
  different property) and unrelated deploy-lease code.
- History: `git log -3` on both dead paths shows only `254ca9939` (lifecycle
  proof doc); the shrink is old, the deadness is steady-state, not a transient.

## 5. Design

### 5.1 Recommended: fail-closed floor re-check + prune in one PR

Two commits, one PR (order matters — see §5.3):

**Commit 1 — prune the two dead entries.** Delete :24 (`metrics_userspace.go`,
owed since #7700) and :26 (`instance.go`) from
`docs/refactoring-audit-accepted.txt`. Pure deletion; the remaining ten stay
byte-identical. Post-prune the file holds 10 live entries.

**Commit 2 — fail-closed re-check.** Extend `TestAcceptedFileWellFormed`
(or add a sibling test — open question Q5) with a LOC leg: for each entry,
measure the file in the working tree with the **same metric the gate uses**
(open question Q4 pins which), and fail naming the entry when
`headLOC < floor(tier)` where `floor([REFACTOR]) = 2000`,
`floor([WATCH]) = 1500`. Boundary: exactly-at-floor is live
(`1500` satisfies [WATCH]), matching the crossing predicate's `head >= floor`
half. Deleted-file entries must fail too (open question Q3: whether
`classify.sh audited` already catches them or the re-check needs an
existence leg — verify before implementing; do not assume).

Why fail rather than warn: the issue allows either, but warn-only reproduces
the advisory pattern #7253 deliberately demoted for the other half — nobody
is interrupted, so nobody prunes, and #7700 already proved the prune does
not happen voluntarily. The re-check fires only when a human shrinks a file
below its accepted floor (rare, deliberate, actionable: prune the entry in
the same PR), so fail-closed interrupts almost nobody and the interruption
always names its own fix.

### 5.2 Alternatives considered (and why not)

- **A. Prune-only, no mechanism.** Fixes 2/12 but leaves the class open;
  the next split re-creates it. Rejected: the issue explicitly demands a
  re-check or expiry.
- **B. Advisory (warn-only) re-check.** Same predicate, `t.Log` instead of
  `t.Error`. Rejected as primary (see above), acceptable as a fallback if
  adversarial review finds a false-red population fail-closed cannot tolerate
  (e.g. Q6 in-flight branches).
- **C. Decay metadata in the entry format** (accepted-at LOC/rev, TTL).
  Heavier: format change, parser change, migration of all 12 entries, and a
  new semantic (what does "accepted at 2010, now 529" mean that "below floor"
  does not already say?). The floor comparison already expresses the decay
  condition with zero format churn. Rejected unless review shows floor-only
  misfires on a real case.
- **D. Re-check inside `isAccepted` / the touched gate.** Wrong layer: the
  touched gate is diff-local and master-silent by design (§4); the deadness
  property is tree-global. Putting it in the touched path would either never
  fire on master (useless) or break the #7253 split's locality guarantee.
  The well-formedness test is the tree-global surface — that is where a
  tree-global property belongs.

### 5.3 Ordering and master-loudness (load-bearing)

The re-check is deliberately **master-loud**: unlike the touched gate, it
must fire on master, because a dead licence is a repo-global fact, not a
branch-local one. Consequences:

- Within the PR, the prune must land in the same tree as the mechanism (or
  first): a mechanism-only tree reds on the two dead entries. Single PR,
  prune commit first, mechanism second; CI runs on the tip where both hold.
- Any future split that takes an accepted file below its floor MUST prune the
  entry in the same PR or master goes red. That is the point (it is the prune
  #7700 owed), and it is stated in the doc update (§5.4).
- In-flight branches that shrink an accepted file without pruning will go red
  on rebase after this lands — small, announced, self-fixing population (Q6).

### 5.4 Doc updates (same PR)

- `docs/refactoring-audit-accepted.txt:16-18` header: qualify "cannot go
  stale" — it cannot go stale from someone else's *growth*; it CAN go stale
  from a split/shrink, and the re-check now catches that.
- `docs/refactoring-audit.md:156-160` escape-hatch paragraph: same
  qualification + "prune in the same PR that shrinks the file below its
  floor" rule.
- `docs/refactoring-audit.md` two-gates table (:98-101): add the re-check row
  (tree-global, fails build) so the table stays the complete map of
  fail-closed surfaces.

## 6. API

None. Test-only + data-file change. No exported symbols change; the only new
surface is a stricter `TestAcceptedFileWellFormed` (or one new `Test*` in
`pkg/refactoraudit`) plus two fewer lines in the accepted file. No CLI flags,
no script argv changes (unless Q4 forces the re-check to shell out to
`touched.sh` for metric parity — then the contract is the existing
`<base|-> <head> <path>` row format, unchanged).

## 7. Invariants (must hold post-merge; each is pinned by a test in §9)

1. **Live-decision:** every accepted entry's path measures at or above its
   tier floor in the tree (`headLOC >= 2000` for [REFACTOR],
   `>= 1500` for [WATCH]). The two pruned entries are the proof the
   invariant was violated; the re-check is the proof it cannot recur silently.
2. **Boundary parity:** at-floor is live, below-floor is dead — the same
   `>=`/`<` orientation as `thresholdCrossings`' head half, so no file can
   be simultaneously "crossed" and "dead" or neither.
3. **Tier asymmetry preserved:** a [WATCH] entry on a file ≥2000
   (e.g. `compiler_interfaces.go` at 2054) stays live and still does NOT
   silence a future [REFACTOR] crossing — `isAccepted` is untouched.
4. **Master-loud / branch-silent split preserved:** the touched gate stays
   diff-local and master-silent; the re-check stays tree-global and
   master-loud. Neither predicate reads the other's input.
5. **Fail-closed parse:** the re-check measures with the gate's LOC metric
   (Q4); any file it cannot measure fails loudly rather than reading as live.
6. **Red-on-revert:** re-adding either pruned line byte-identical fails the
   gate (direct acceptance criterion from the issue).

## 8. Risk (4-class)

| Class | Level | Why + mitigation |
|---|---|---|
| Gate correctness (false-red) | LOW | Predicate is a strict subset of already-known facts (entry tier × tree LOC); the only reds are true dead entries. Boundary parity (§7.2) removes off-by-one; synthetic boundary cases (1499/1500, 1999/2000) pin it. Residual: metric mismatch (Q4) — mitigated by using the gate's own metric. |
| Gate correctness (false-green) | NONE | Change strictly narrows silence: every crossing silenced before is still silenced (live entries untouched, `isAccepted` untouched); dead licences additionally red. No new silence introduced. |
| Compatibility (in-flight branches) | LOW | Branches that shrink an accepted file below its floor without pruning go red on rebase. Population: ~0 expected (only splits do this; the last one was #7700). Self-fixing: prune one line. Announced in the PR body (Q6). |
| Performance | NONE | ≤12 `wc -l`-scale measurements (or one script call) inside a test that already shells out per entry (`classify.sh` per entry at :526). No hot path; test-only. |
| Security / robustness | NEGLIGIBLE (positive) | Closes silent pre-authorization of 1471/675 LOC of regrowth headroom. Fail-closed on unmeasurable files (§7.5) prevents a broken probe from reading as live. No new trust boundary; no network/input surface. |

(4 classes: correctness, compatibility, performance, security/robustness.)

## 9. Test plan

1. **Synthetic predicate cases** (new `Test*`, same style as
   `TestThresholdCrossingCases` at :283-374 — predicate, not tree):
   below-floor [WATCH] (825/1500) reds; below-floor [REFACTOR] (529/2000)
   reds; at-floor (1500/1500, 2000/2000) green; just-below (1499, 1999) reds;
   just-above greens; [WATCH] entry on 2054-LOC file green (tier asymmetry).
   Each case names the mutation it catches.
2. **Live-tree well-formedness:** `TestAcceptedFileWellFormed` (+ re-check)
   green on the post-prune tree — the 10 live entries prove it.
3. **Red-on-revert:** re-add each pruned line byte-identical in a scratch
   worktree → gate reds naming the file; remove → green. Both files.
4. **Full package suite:** `go test ./pkg/refactoraudit/...` green
   (build isolation: `GOCACHE=/dev/shm/gocache-10487 GOTMPDIR=/dev/shm`).
5. **Metric parity check:** re-check LOC vs `scripts/refactoring-audit-touched.sh`
   LOC vs `wc -l` on all 12 paths — identical, or the difference documented
   and the re-check using the gate's metric (Q4).
6. **CI wiring:** confirm `pkg/refactoraudit` tests run on master CI (if they
   only run on PR diffs, the master-loud leg needs a wiring change — verify,
   do not assume).

## 10. Out of scope

- Heatmap/freshness changes: the committed snapshot listing
  `metrics_userspace.go` at 2010 while the tree is 529 is the freshness
  job's drift (#7253/#7269), fixed by `make audit-refresh`, not by this PR.
- New thresholds, tier renames, or entry-format changes (rejected option C).
- `isAccepted` semantics: untouched by design (§7.3).
- Historical attribution of the #7700 prune debt (issue Limits section:
  outside the evidence window).
- Splitting any live large file; pruning any live entry.
- Auto-prune tooling (a `--prune-dead` flag on the refresh script is a
  possible follow-up, not this PR).

## 11. Open questions for adversarial review

1. **Fail vs warn?** The issue allows either; §5.1 recommends fail-closed.
   Is there a false-red population (e.g. generated-file edge, Q4 metric skew)
   that makes fail-closed net-negative?
2. **One PR or prune-first?** §5.3 sequences prune-then-mechanism in one PR.
   Should the prune land alone first (smaller blast radius if the mechanism
   design changes in review), given the mechanism reds on any tree containing
   a dead entry?
3. **Deleted/renamed files:** does `classify.sh audited <path>` fail for a
   path that no longer exists, or is it pattern-only (roots/skip-regex)?
   If pattern-only, the re-check needs an explicit existence leg — verify by
   reading `scripts/refactoring-audit-classify.sh` + `lib.sh`, not by
   assumption. (Zero missing-file entries today, so this is latent, not live.)
4. **LOC metric parity:** what exactly does `refactoring-audit-touched.sh`
   count (`wc -l`? stripped? CR handling?) — and must the re-check shell out
   to it, or is Go-side `wc -l`-equivalent acceptable? `TestShellFloorsMatchGoConstants`
   (:581-595) pins the floors across the shell/Go boundary; does anything pin
   the *metric*?
5. **Extend `TestAcceptedFileWellFormed` or add a sibling test?** Extension
   keeps one well-formedness surface but grows a test whose name undersells
   the new leg; a sibling (`TestAcceptedEntriesAreLive`?) names the property
   but splits Knuth-style "one test, one property" across two readers of the
   same file. Which does the repo's test-naming convention prefer?
6. **In-flight branch window:** is there any live branch that shrinks an
   accepted file (or a policy requiring a grace/advisory period before a new
   master-loud red)? Zero open PRs at plan time, but stacked local branches
   are invisible — is announcement-in-PR-body sufficient?
7. **Decay metadata after all?** Is floor comparison sufficient as the decay
   condition, or does review want accepted-at LOC/rev recorded (option C) so
   a future reader can distinguish "accepted at 2010, shrunk to 529" from
   "accepted at 1501, shrunk to 529"? What decision would that distinction
   change?
8. **Doc wording:** how should the corrected "cannot go stale" claims read?
   Proposed: "cannot go stale from someone else's growth elsewhere in the
   tree; it CAN go stale when its own file is split or shrunk below its
   floor, and the re-check fails until the entry is pruned." Accurate? Complete?

## 12. Verdict request

PLAN-READY → implement §5.1 (prune + fail-closed re-check + doc updates + §9 tests).
PLAN-NEEDS-MINOR → tweak per findings; design alternatives in §5.2 are pre-analyzed for fast pivots.
PLAN-KILL → only if review shows the dead-licence class is load-bearing somewhere this plan has not found.
