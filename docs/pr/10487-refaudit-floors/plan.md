---
status: DRAFT v2 — delta-review requested after round-1 findings; no production code
issue: #10487
phase: single PR — prune 2 dead entries + add a fail-closed live-entry re-check; tooling/tests/docs only
base: origin/master b71c52d6093f23a7d9c9cca12d00cb40b3dffa8d
---

# Plan: Expire refactoring-audit accepted entries that outlive their floors (#10487)

## 1. Status

DRAFT v2, revised 2026-09-21 after the round-1 Codex/Gemini plan review.
The design verdict was READY-compatible; v2 closes the test, evidence, and
wording findings before delta re-review. No production code is in scope.

STEP-0 was rerun against fresh `origin/master`: `git fetch origin master`
left `origin/master` at `b71c52d6093f23a7d9c9cca12d00cb40b3dffa8d`.
Actual GitHub searches were empty for all of:

- `gh pr list --state merged --search '10487' --limit 100`
- `gh pr list --state merged --search 'refaudit floor' --limit 100`
- `gh pr list --state open --search '10487' --limit 100`

There is no prior fix or competing PR. The issue remains OPEN. This branch
stops after the plan commit and push; implementation waits for parent-run
delta review.

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
|---|---|---:|---:|
| `pkg/api/metrics_userspace.go` (:24) | [REFACTOR] / 2000 | 529 | −1471 |
| `pkg/vrrp/instance.go` (:26) | [WATCH] / 1500 | 825 | −675 |

The `metrics_userspace.go` case is the sharp one. Issue #7700's scope says
to prune its entry once the file is under the floor; the split landed and
the prune never happened. The decision record has drifted from reality with
no signal, exactly the failure mode the accepted file's own header currently
claims is impossible (`docs/refactoring-audit-accepted.txt:16-18`, and the
same claim in `docs/refactoring-audit.md:156-157`). Shrinking, not unrelated
growth, is what stales it.

Acceptance from #10487: prune the two dead entries, audit the remaining ten,
give accepted entries a re-check or expiry, and make re-adding a below-floor
entry fail the gate (red-on-revert).

## 3. Scope-value

**In:** prune the two dead entries; add a tree-global, fail-closed live-entry
re-check; add committed negative controls for re-add, deleted paths, and LOC
metric parity; correct the accepted-file and engineering-style instructions.

**Value:** closes a silent pre-authorization hole in the repo's hardest
modularity gate. Today an author regrowing `metrics_userspace.go` from 529
back past 2000 LOC gets a green gate on a 2010-LOC decision that no longer
describes the file — the crossing that most needs a fresh written decision
is the one the gate waves through. The fix restores the invariant that every
silenced crossing traces to a live decision.

**Not value:** no production behavior; no heatmap/freshness changes
(#7253/#7269 territory); no new thresholds; no CI system is introduced.

## 4. Shipped-context (what exists today, with receipts)

### 4.1 Gate decision and consumers

- Floors/tiers: `auditFloor = 1500`, `refactorFloor = 2000`,
  `tierWatch = "[WATCH]"`, `tierRefactor = "[REFACTOR]"`
  (`pkg/refactoraudit/audit_canary_test.go:20-26`).
- Crossing predicate: `base < floor && head >= floor`, highest floor only
  (`pkg/refactoraudit/audit_touched_test.go:74-103`).
- Escape: `isAccepted` matches `a.path == c.path` and
  `a.tier == c.tier || a.tier == tierRefactor` — path+tier only, no LOC
  (`audit_touched_test.go:187-197`).
- The accepted file has exactly one code reader, `readAccepted`
  (`audit_touched_test.go:200-208`), called by the touched gate and
  `TestAcceptedFileWellFormed`. The fixture in
  `TestAcceptedCrossingIsTheOnlyEscape` is synthetic, not another reader.
  Scripts do not consume the accepted file; the refresh job only writes the
  separate heatmap snapshot.
- Well-formedness currently checks reason non-empty, duplicate path+tier,
  and `classify.sh audited <path>` (`audit_touched_test.go:514-532`) — no
  existence or LOC leg. This is the hole.

### 4.2 Measurement and missing-file semantics (resolved from source)

The shared audit library is the metric source of truth:

- `audit_loc()` is exactly `wc -l < "$1"`
  (`scripts/refactoring-audit-lib.sh:60-72`). It counts byte `0x0a`
  characters only: a CRLF line contributes one, and a final unterminated
  line contributes zero. There is no inline-test stripping or CR handling.
- The generator and touched head column call that same `audit_loc`; touched
  base uses `git show ... | wc -l`
  (`scripts/refactoring-audit-touched.sh:100-116`).
- `audit_is_audited_path()` is pattern-only: extension, root, and skip regex;
  it never checks that a file exists (`refactoring-audit-lib.sh:122-149`).
  `classify.sh audited` therefore prints `AUDITED` for an accepted deleted
  path (`classify.sh:37-46`). The `[ -f ]` check at
  `refactoring-audit-touched.sh:109` is only a changed-set skip, correct
  there because deletions cannot cross upward; copying that skip into the
  re-check would silently revive this bug.
- `classify.sh loc` delegates to `audit_loc` (`classify.sh:47-50`) and
  fails non-zero for a missing file. The new Go re-check must fail explicitly
  on `os.ReadFile`/existence errors rather than rely on that accident or skip.

Implementation choice is now fixed: the re-check reads each accepted path
from the working tree, rejects a missing/unreadable path, and counts
`bytes.Count(content, []byte{'\n'})`. A committed parity test compares that
count to `classify.sh loc` on newline-edge fixtures. This avoids a per-entry
shell fork in the new helper while pinning exact parity with the shell source
of truth; `bytes.Count`, not scanner/split-lines counting, is required.

### 4.3 Blast-radius census

HEAD has 12 entries (lines :24-:35):

- DEAD: 2/12 = 16.7% — `metrics_userspace.go` 529 < 2000 and
  `vrrp/instance.go` 825 < 1500.
- LIVE: 10/10 — `daemon.go` 1942, `metrics.go` 1874,
  `userspace-dp/src/afxdp/coordinator/mod.rs` 1875,
  `compiler_interfaces.go` 2054 (a live [WATCH] entry; it still does not
  silence a future [REFACTOR] crossing), `compact_normalize_scope.go` 1794,
  `authz.go` 1594, `sync.go` 2540, `userspace-dp/src/afxdp/mod.rs` 1678,
  `userspace-dp/src/afxdp/types/forwarding.rs` 1592, and
  `maps_sync.go` 2041.
- MISSING: 0/12. The smallest live margin is 41 LOC
  (`maps_sync.go`, 2041 vs its 2000 [REFACTOR] floor), so ±1 metric
  disagreement cannot false-red a current live entry.
- Corroboration: the committed heatmap still lists
  `metrics_userspace.go` at 2010 (`docs/refactoring-audit-current.txt:21`)
  while the tree measures 529. A fresh heatmap drops it. That snapshot drift
  is freshness-advisory territory, not a second accepted-file reader.
- Exploit mechanics: a branch growing `metrics_userspace.go` 529 → 2000+
  reports a [REFACTOR] crossing and `isAccepted` matches the dead :24 line;
  the same shape occurs at 1500 for `instance.go` via :26.
- #7700 is the direct source receipt for the missed prune obligation. No
  shallow-worktree path-history claim is used as evidence in this plan.

## 5. Design

### 5.1 Recommended: fail-closed floor re-check + prune in one PR

Two logical increments, with the prune first so the mechanism's own tree is
green:

**Increment 1 — prune the two dead entries.** Delete :24
(`pkg/api/metrics_userspace.go`) and :26 (`pkg/vrrp/instance.go`) from
`docs/refactoring-audit-accepted.txt`. The remaining ten entries stay
byte-identical. This is a pure data deletion and is independently safe.

**Increment 2 — add `TestAcceptedEntriesAreLive`.** Keep
`TestAcceptedFileWellFormed` focused on syntax, reasons, uniqueness, and the
audited-path classifier. Add a sibling tree-global test/helper that, for
each parsed entry:

1. maps tier to floor ([WATCH] 1500; [REFACTOR] 2000);
2. requires the accepted path to exist and be readable in the **working
   tree** — missing/deleted/renamed paths are a hard failure, never a skip;
3. counts raw LOC as `bytes.Count(content, []byte{'\n'})`;
4. fails with path, tier, measured LOC, and required floor if
   `headLOC < floor`;
5. treats exactly-at-floor as live; and
6. tells a [REFACTOR] entry on a 1500–1999-LOC file to **demote it to
   [WATCH] or prune it**, rather than blindly saying only "prune". A
   [WATCH] entry on a ≥2000-LOC file remains live and retains current
   `isAccepted` tier asymmetry.

This is deliberately tree-global and master-loud: `readAccepted` uses
`os.ReadFile` on the working-tree path, not a committed Git blob, and this
check does not read the changed set or merge base. The existing touched gate
stays diff-local and master-silent.

Why fail rather than warn: the red names the stale entry and gives an
actionable shrink/split repair. With no CI, a shrinker can skip `make
test-go` and leave master red until the next developer runs it; that manual
enforcement residual is documented in the cutover docs and is preferable to
silently accepting the stale licence. Warn-only would recreate the advisory
shape #7253 deliberately demoted; #7700 already shows that a voluntary prune
is not reliable. A fail-closed [REFACTOR] entry that remains 1500–1999 LOC
is fixed by demotion or pruning, while an entry below 1500 is pruned.

### 5.2 Alternatives considered

- **Prune-only:** fixes 2/12 but leaves the class open after the next split.
  Rejected because #10487 explicitly asks for a re-check or expiry.
- **Warn-only:** avoids a red but leaves the stale licence operational and
  hides the actionable repair in ordinary non-verbose test output. Rejected
  as primary.
- **Accepted-at metadata/TTL:** changes the entry format and all migrations
  without changing any decision: an entry at 529 is dead whether it was
  accepted at 1501 or 2010. Rejected; current floor is the sufficient decay
  condition.
- **Re-check inside `isAccepted`:** wrong layer. The touched gate's
  diff-local/master-silent contract must remain intact; tree-global deadness
  belongs in the tree-global well-formed/live-entry surface.
- **Shelling out to `touched.sh` for LOC:** wrong vehicle. That script is a
  changed-set probe and deliberately skips missing paths; parity belongs to
  `classify.sh loc`/`audit_loc`, as fixed in §4.2.

### 5.3 Ordering and enforcement surface

The PR uses prune-first ordering (either two commits in one PR or a prune
commit followed by the mechanism commit). A mechanism-only intermediate tree
is expected to be red; no CI observes intermediate commits, and the merge
must land a green tip.

This repository has **no CI**: `Makefile:127-131` states that `.github/`
contains only instructions and no CI exists. The enforcement surface is
`make test-go`, whose `test-go` recipe invokes the whole Go suite and then
`-count=1 ./pkg/refactoraudit/` (`Makefile:225-271`).
`TestMakefileRunsAuditPackageUncached` (`audit_canary_test.go:580-643`)
pins that wiring, and any new sibling `Test*` automatically runs under it.
The live-entry check is therefore master-loud when `make test-go` runs on a
master-shaped tree with an empty changed set.

A shrink-without-prune branch goes red as soon as it runs the new package
test after pulling the mechanism; project merges rather than rebases, but
this tree-global check has no merge-base/stacked-branch attribution problem.

### 5.4 Documentation cutover (same PR)

Update every statement that currently treats an accepted entry as permanent
or merely historical:

- `docs/refactoring-audit-accepted.txt:16-18`: qualify the no-unrelated-
  growth claim; a split/shrink can stale an entry and the live-entry check
  catches it.
- `docs/refactoring-audit-accepted.txt:20-23`: replace "Nothing gates on an
  entry's continued presence" and "decision record, not state" with the
  actual rule: an entry may be pruned when no longer live and **must** be
  pruned in the same PR that takes its file below its tier floor, or the
  master-loud re-check fails.
- `docs/refactoring-audit.md:156-160`: document the existence/LOC re-check,
  demotion-vs-prune rule, and same-PR prune obligation.
- `docs/refactoring-audit.md:98-101`: add the tree-global accepted-entry
  check to the two-gates table.
- `docs/engineering-style.md:614-623`: add the third limb to the current
  split-or-record guidance: if a previously accepted file is split/shrunk
  below the accepted tier floor, prune (or demote a [REFACTOR] entry to
  [WATCH]) in that same PR.

No docs/log history rewrite is needed; this is a forward contract correction.

## 6. API

None. Test-only code, data-file pruning, and process documentation. No
exported symbol, CLI flag, script argument, or production runtime behavior
changes. The new helper is package-private. The existing accepted-file
format remains `<tier> <path> <reason...>`.

## 7. Invariants

1. **Live decision:** every accepted entry names an existing, readable file
   whose raw LOC is at or above its tier floor. Below 1500 means prune; a
   [REFACTOR] entry at 1500–1999 must be demoted to [WATCH] or pruned.
2. **Boundary parity:** a crossing is `base < floor && head >= floor`
   (`audit_touched_test.go:89`); an accepted entry is dead when `head < floor`.
   Crossing and dead are mutually exclusive. The steady state
   `base >= floor && head >= floor` is neither.
3. **Tier asymmetry:** a [WATCH] entry on a 2000+ file remains live but does
   not silence a [REFACTOR] crossing (`isAccepted` at :192); a [REFACTOR]
   entry still implies [WATCH].
4. **Layer split:** the touched gate remains branch-diff-local and
   master-silent; the accepted-entry check is tree-global and master-loud.
   Neither reads the other's input.
5. **Metric parity:** the Go count is byte-`0x0a` count and agrees with
   `audit_loc`/`classify.sh loc` for newline-terminated, unterminated, CRLF,
   and empty files.
6. **Fail closed:** missing/unreadable accepted paths fail; no classifier or
   changed-set skip may turn them into a live entry.
7. **Red-on-revert:** putting either pruned line back in a committed fixture
   with its below-floor file fails the live-entry test and names that path;
   removing it is green.
8. **Regrowth recovery:** after a valid prune, a future branch that grows the
   file across a floor has no live acknowledgement and must record a fresh
   decision. This is modulo the existing merge-forward attribution caveat
   documented at `refactoring-audit.md:133-137`, which is out of scope.

## 8. Risk (4 classes)

| Class | Level | Why + mitigation |
|---|---|---|
| Correctness | LOW | The predicate is a strict tree fact (tier floor × current raw LOC); synthetic boundary, band, deleted-path, re-add, and metric-parity fixtures pin false-red/false-green edges. The smallest current live margin is 41 LOC. |
| Compatibility | LOW | A shrinker who runs `make test-go` gets a self-naming prune/demote repair; a shrinker who skips the target can leave master red until the next developer runs it. No open PR matched #10487 at review time; recheck the open-PR list at implementation time. |
| Performance | NONE | At most 12 small `ReadFile`/`bytes.Count` operations in an existing Go test package; no runtime or hot-path work. `classify.sh loc` is used only by parity tests. |
| Security / robustness | POSITIVE | Closes silent pre-authorization of 1471/675 LOC of regrowth headroom. Explicit missing/read errors fail closed; no network or new trust boundary. |

## 9. Test plan

### 9.1 Predicate and tier boundaries

Add synthetic cases in the style of `TestThresholdCrossingCases`, but keep
this pure predicate pin separate from the tree reader:

- [WATCH] at 1499 → dead; at 1500 and 1501 → live;
- [REFACTOR] at 1999 → dead; at 2000 and 2001 → live;
- [REFACTOR] at 1500–1999 → fail with demote-to-[WATCH]-or-prune guidance;
- [WATCH] at 2000+ → live and still not accepted as a [REFACTOR] crossing;
- unknown tier → fail closed (parser already rejects it).

### 9.2 Committed red-on-revert and live-tree control

`TestAcceptedEntriesAreLive` is a committed negative-control test, not a
manual scratch observation. Build a temporary fixture root in the existing
`audit_jobs_test.go`/`runScript` style with audited-looking paths and an
accepted file:

1. post-prune fixture (the ten live entries or a reduced live fixture) is
   green;
2. re-add the exact `metrics_userspace.go` [REFACTOR] line and a 529-line
   fixture file — the test must report that path/tier dead;
3. re-add the exact `vrrp/instance.go` [WATCH] line and an 825-line fixture —
   the test must report that path/tier dead; and
4. remove each line — the same fixture is green again.

The assertions must inspect the returned errors/path names, so a missing
helper call or swallowed I/O error cannot pass merely because the fixture
contains valid syntax. This is the committed fail-on-revert pin for the
issue's explicit acceptance criterion.

### 9.3 Deleted/renamed path case

In the same fixture family, keep an accepted audited-looking path in the
accepted file but do not create the file (and separately rename it away).
`classify.sh audited` is expected to say `AUDITED` because its predicate is
pattern-only; `TestAcceptedEntriesAreLive` must still fail on the missing
path. This pins that the new existence leg does not copy the touched probe's
intentional `[ -f ] || continue` skip.

### 9.4 Go/shell LOC agreement pin

Add committed `TestGoLocMatchesAuditLoc` with temporary files containing:
`"a\nb\n"` (2), `"a\nb"` (1), CRLF content (one count per `\n`), and empty
content (0). For every fixture, compare the Go helper's
`bytes.Count(content, []byte{'\n'})` result to
`scripts/refactoring-audit-classify.sh loc <path>`. This is the parity pin;
live-tree comparison of the current 12 newline-terminated files is not
sufficient and is not used as evidence.

### 9.5 Working-tree/master-shaped wiring

The live-entry test reads `repoRoot/docs/refactoring-audit-accepted.txt`
and current working-tree files directly; it must not invoke
`refactoring-audit-touched.sh`, consult `origin/master`, or depend on a
non-empty diff. Run it on the master-shaped tree where the touched set is
empty to prove the tree-global leg still executes. Keep the existing
`TestTouchedFileCrossedModularityThreshold` as the separate diff-local gate.
`TestMakefileRunsAuditPackageUncached` already proves the package invocation
under `make test-go` carries `-count=1`; no CI wiring claim or new CI is
needed.

### 9.6 Full validation and known baseline

- Focused new/sibling tests: `go test ./pkg/refactoraudit -run
  'TestAcceptedEntriesAreLive|TestGoLocMatchesAuditLoc|TestThreshold...'`.
- Full package: `GOCACHE=/dev/shm/gocache-10487 GOTMPDIR=/dev/shm go test
  ./pkg/refactoraudit/...`.
- Repository enforcement: `GOCACHE=/dev/shm/gocache-10487 GOTMPDIR=/dev/shm
  make test-go` when the shared package baseline is green.

At plan time the full package command is already red for the unrelated
calibration test `TestStructMetricIsTypesNotFields6937` (CompileResult is
32 fields / 21 distinct types, just above its 20-type floor). That #6937
predicate is orthogonal to this accepted-entry work; the implementation PR
must not normalize this existing red or claim a green full suite until the
calibration is repaired/landed. The new tests should be run by name for
scoped proof, then the full package and `make test-go` are re-run in the
post-#6937 green window.

## 10. Out of scope

- Heatmap/freshness changes: the committed snapshot's stale
  `metrics_userspace.go` row belongs to `make audit-refresh` and #7253/#7269.
- New thresholds, tier names, accepted-file syntax, or accepted-at metadata.
- Changes to `isAccepted` or to the touched gate's changed-set semantics.
- Historical attribution beyond issue #7700's explicit prune obligation.
- Splitting any live large file or pruning any live entry.
- A new CI service, merge queue, or automatic commit hook.
- Fixing the pre-existing #6937 struct-floor calibration; it is a prerequisite
  for claiming the full package suite green, not part of #10487.
- Automatic `--prune-dead` tooling; a refresh-script convenience can be a
  follow-up after the invariant is proven.

## 11. Open questions for delta/adversarial review

The source questions about missing paths and LOC are closed in §4.2; these
are the remaining design choices/review checks (proposed resolutions are
explicit so review can flip them deliberately):

1. **Fail versus warn:** retain fail-closed, or is there evidence of a real
   false-red population that justifies advisory behavior? Proposed: fail;
   warning repeats #7253's known silent-advisory failure.
2. **One PR versus two:** retain one PR with prune-first logical increments,
   or land the zero-risk prune as a separate PR before the mechanism? Proposed:
   one PR, prune-first, because the final tip is the only enforced tree and
   the mechanism is intentionally red on the intermediate tree.
3. **Missing-path wording:** is "missing/unreadable accepted path fails
   closed" sufficient, or should the error distinguish deletion from
   permission/read failure for operator repair? Proposed: distinguish in the
   message while keeping one fail-closed outcome.
4. **Go metric implementation:** the plan chooses `bytes.Count` plus a
   `classify.sh loc` fixture pin. Should the helper instead shell out for
   every live entry to eliminate duplicate measurement logic, despite the
   extra forks? Proposed: keep pure Go; the committed parity test protects
   the single-byte-count contract.
5. **Sibling test naming:** retain `TestAcceptedEntriesAreLive` beside
   `TestAcceptedFileWellFormed`, or fold the live check into the old test?
   Proposed: sibling, matching the package's separate predicate/gate/filter/
   well-formedness test surfaces.
6. **Baseline sequencing:** should implementation wait for #6937's calibration
   repair before opening the PR, or may it open with named tests plus an
   explicitly recorded baseline red? Proposed: wait for a green shared
   package, so a second master-loud red is never normalized.
7. **In-flight branch policy:** is the durable same-PR prune/demote rule enough
   notice for a branch that shrinks an accepted file while this lands? Proposed:
   yes; recheck `gh pr list --state open` at implementation time, with no grace
   period because the fix is one line and the current open search is empty.
8. **Documentation wording:** do the proposed edits to accepted.txt:16-23,
   refactoring-audit.md, and engineering-style.md communicate the three
   actions (split, record, prune/demote) without implying accepted entries
   expire by time? Proposed: use the exact same-PR floor rule in all three.

## 12. Verdict request

PLAN-READY → implement §5.1 with the committed tests in §9 and documentation
cutover in §5.4.

PLAN-NEEDS-MINOR → adjust only the proposed resolutions/open wording.

PLAN-KILL → only if delta review demonstrates a load-bearing consumer,
false-red population, or a calibration interaction not found in the source
study. Current evidence shows none.
