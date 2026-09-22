# Preserve rename ancestry in the touched modularity gate (#10488)

## Status

**IMPLEMENTED — PR #10538 (initial implementation at `ce57b56e1`).** v2 addressed round-1 findings; delta re-review confirmed PLAN-READY; implementation landed on base `f4bae0a5a` (merged #10487). This document is retained as review history.

- Issue: <https://github.com/psaab/xpf/issues/10488> (OPEN at intake).
- Comparison/base: `b71c52d6093f23a7d9c9cca12d00cb40b3dffa8d` (`origin/master`).
- Branch: `fix/10488-rename-crossings`.
- Worktree: `/home/ps/git/pi-xpf/.claude/worktrees/10488-rename`.
- Owned file this round: `docs/pr/10488-rename-crossings/plan.md` only.
- v1: `290ffff585520b7f96dee0c1163c6351fa294ee2` (429 lines).
- Round-1: reviewer A **PLAN-NEEDS-MINOR** (premise confirmed end-to-end; one
  `U`-behavior item + five doc/test rows + serialization move), reviewer B
  **PLAN-NEEDS-MAJOR** (mechanism underspecified in load-bearing places).
  Both sustain the design direction (producer-side fix, no consumer guessing).
- Git reference for all v2 behavior pins: `git version 2.53.0`, man pages
  `git-diff(1)` / `git-config(1)` as installed, plus scratch-repo probes whose
  byte outputs are quoted in §8. No `git checkout`, fetch, or deepen was run.

## 1. Issue framing and STEP-0 disposition

A pure rename of an already-large audited file must not be blamed for creating
that file's existing LOC. The reported default-Git control had an `R100`
old-to-new mapping but the touched probe emitted `- 1701 pkg/rename_control/new.go`.
The existing consumer therefore reported a new-file WATCH crossing. The issue's
control is accepted evidence, not a newly executed experiment in this round;
reviewer A independently traced the same `R100` walk (`--name-only` drops the
source → `cat-file -e` misses → `-` → `isNew` → `base=0` → WATCH).

The mechanism remains in the comparison revision:

1. `scripts/refactoring-audit-touched.sh:100-107` requests destination-only
   `git diff --name-only --diff-filter=d` output, adds untracked paths, and sorts.
2. Lines 108-115 classify the destination, then look up only
   `<merge-base>:<destination>`. A missing destination becomes `-` even when Git
   knows its old name.
3. `pkg/refactoraudit/audit_touched_test.go:115-143` parses `-` as `isNew`
   (mapping at :127-128; the issue's `:63-65` citation is line drift since
   evidence rev `1a6952b` — harmless, the comment moved, the logic did not).
   `thresholdCrossings` at lines 74-103 then compares from zero. It correctly
   reports the highest crossed floor, 1500 or 2000; the wrong input is upstream.

**STEP-0: still live, not a duplicate implementation.** The HEAD and
`origin/master` producer blob IDs both resolve to
`b3d07ed14e080412bc360d80e93a7a1564baae79`. The current consumer still uses the
above semantics. These merged-PR searches were executed against `psaab/xpf`:

```text
gh pr list --repo psaab/xpf --state merged --search 10488 --limit 100 --json number,title,mergedAt,url
  -> []
gh pr list --repo psaab/xpf --state merged --search '"refactoring-audit-touched" in:title' --limit 100 --json number,title,mergedAt,url
  -> []
gh pr list --repo psaab/xpf --state merged --search 'rename modularity' --limit 100 --json number,title,mergedAt,url
  -> 24 results, with unrelated implementation/refactor titles
```

The broad titles alone are not proof that every old PR is irrelevant; the
unchanged live producer/consumer mechanism is the decisive freshness evidence.
Path-scoped local history is shallow and supplies no complete historical census.
No claim is made that renaming itself bypasses a runtime security check: this is
a developer-friction false positive in a repository validation gate.

### Round-1 finding close-out ledger (v1 line refs; v2 sections close each)

| Finding | v1 gap | v2 close-out |
|---|---|---|
| A-F1 `U` hidden in reject rule | v1:187 rejected "unsupported statuses" without naming `U` | §4 records the exact command distinction: intended `git diff <commit>` emits one `M` for a conflict; index-form `git diff` can emit duplicate `U+M`, which defensive parser coalescing now feeds through producer-level fake-stream cases in addition to the fresh real-conflict byte probe |
| A-F2 rename-limit unspecified | v1:211-212 left limit to Git | §4: accept-and-document + §8 smoke criterion (1200-file diff, 5× budget, FP-direction preservation) |
| A-F3 no dissimilarity control | 10-case table had no below-threshold row | §8: heavy-rewrite ⇒ new-file crossing row (doubles as `-M90%` lower-bound pin) |
| A-F4 wrong #10487 attribution | v1:385 claimed parser hardening owned by #10487 | §9: corrected — #10487 owns accepted-entry drift/expiry only (issue text + no `docs/pr/*10487*` plan); numeric hardening out of scope for both |
| A-F5 80-vs-50 gap | no reconciliation sentence | §2: fresh generator emits exactly 80 = census; committed 50-row artifact last touched `254ca9939`; gap is pure staleness |
| A-F6 red-package rule implicit | no acceptance rule while 6937 red | §8: failure-set-equality sentence (pass iff failure set == `{TestStructMetricIsTypesNotFields6937}`) |
| A-F7/F8 overlap moved / recreation sound | v1:237-240 serialized the wrong file | §4: zero-touch `audit_touched_test.go`; real overlap is `docs/refactoring-audit.md` gate section; order-independence stated |
| B-F1 `-z` order unspecified | v1:148-151 "decode the extra pathname" | §4: byte-exact `R<score>\0<src>\0<dst>\0` (git 2.53.0, od-quoted) + malformed rules + real/fake source-order fixtures |
| B-F2 non-rename delta unproven | v1 table omitted C/U/X/B; `R+T` unaddressed | §4: full A/C/M/R/T/U/X/B table with per-row delta-vs-today proof; `R+T` probed (`A+D`, zero delta); T/U/C/X/B/D fixtures |
| B-F3 blob-absent policy | v1:184-186 error rule breaks shallow availability | §4: commit-unreadable → error; TRACKED blob-absent-with-present-commit → `-` fallback + stderr warning (today's direction, availability preserved); untracked `W` misses stay silent `-` like `A`/`C` |
| B-F4 staged-vs-working uncited | v1:206-208 asserted without citation | §4: man citation (worktree-vs-commit) + `R099` staged+unstaged probe; growth rows labeled; staged+unstaged fixtures at both floors |
| B-F5 threshold unpinned | v1 bare `-M` (50%) | §4: pinned `-M90%` with FN-bound rationale + boilerplate/ambiguity fixtures; bare `-M` and exact-only explicitly rejected with consequences |
| B-F6 dir renames | no mention | §4: one sentence + 3-file `pkg/olddir→pkg/newdir` fixture |
| B-F7 harness method | `r.script()` vs `r.touched()` unstated; 6 fixtures missing | §8: `r.script()` for all nonzero cases, `R`-precondition snippet, all missing fixtures added |
| B-F8 rebase order | v1:237-240 serialized the wrong file | §4: zero-touch decision + order proposal + one-line numeric-domain compatibility; implementation also records a Bash 4.4 floor |
| B-F9 editorial + smoke bound | "perf gain" wording; unbounded smoke | §2 wording fixed to "value gain"; §8 smoke N=1200 / 5× / row-superset criterion |

## 2. Honest scope/value and quantified blast radius

The win is correct attribution and avoiding unnecessary split/acknowledgement
work for moves. There is **no claimed throughput, allocation, HA, packet-loss,
or latency improvement** in the firewall. No production daemon/dataplane path
changes. No measured frequency or saved developer-hours estimate is available.

If reviewers conclude the value gain is too small to justify the churn,
PLAN-KILL is an acceptable verdict.

For this tooling correctness issue that sentence is not a performance promise:
rejecting an oversized remedy does not refute the false positive.

### Measured population at the pinned base

The census enumerated Git blobs with `git ls-tree -rz b71c52d60 -- pkg cmd
userspace-dp/src userspace-xdp/src bpf/xdp bpf/tc`, selected `.go`/`.rs`/`.c`
candidates, invoked the shipped `scripts/refactoring-audit-classify.sh audited`
on those paths, and counted newline bytes in the selected blobs via
`git cat-file --batch`. This matches `audit_loc`, not a possibly stale heatmap.
Reviewer A reproduced the 6017/1722 split independently.

| Quantity | Measured value / interpretation |
|---|---|
| Candidate files in configured language roots | 6,017 |
| Audit-eligible files | 1,722 |
| Audited Go / Rust / C files | 1,260 / 462 / 0 |
| Files at or above 1500 LOC | 80 |
| WATCH-only files, 1500-1999 LOC | 41 |
| REFACTOR files, at or above 2000 LOC | 39 |
| Fresh generator rows at base (`bash scripts/refactoring-audit.sh \| wc -l`) | 80 — exactly the census |
| Committed artifact rows (`docs/refactoring-audit-current.txt`) | 50 — stale (see below) |
| Configured roots / thresholds | 6 roots / 2 LOC thresholds |
| Producer / parser / decision function | 1 / 1 / 1 |
| Current parser call sites | 2: live gate and fixture-repo adapter |
| Proposed existing files to change after approval | 3: producer script + fixture tests + audit doc (v1's 4th, Go-test comments, removed by the §4 zero-touch decision) |
| Product public APIs, wire formats, runtime hot paths changed | 0 |

Those 80 files are the population whose pure audited-to-audited rename can
produce the reported false crossing if the destination is new and the crossing
is not acknowledged. They are **not** 80 observed incidents. A filename-only
move below 1500 still loses ancestry today but does not trip either floor.

**80-vs-50 reconciliation (A-F5).** The committed 50-row artifact was last
touched by `254ca9939` and lags the tree; running the shipped generator at the
pinned base emits exactly **80 rows = the census**. The gap is pure artifact
staleness, in both directions (the artifact also carries #10487's dead 2010-LOC
entry for a file that now measures 529). The census is validated against the
generator, never the artifact — consistent with the #7253 split, which forbids
the gate from depending on the committed heatmap at all.

`git rev-parse --is-shallow-repository` returned `true`, and
`git rev-list --count --max-count=400 b71c52d60` returned **63**, not 400.
For each of the **62 available first-parent edges** of those reachable commits,
`git diff-tree --no-commit-id --name-status -r -z -M --diff-filter=R <parent>
<commit> --` produced **0 rename records**. This edge census is not a census of
400 first-parent commits, nor proof that earlier renames did not happen. The
issue's historical **11-renames claim remains unverified**; no fetch/deepen or
shared-ref mutation was performed to manufacture that evidence. No load-bearing
v2 decision rests on that claim: the fix rests on the live mechanism plus the
80-file susceptibility upper bound.

## 3. What is already shipped and must compose unchanged

- The #7253 split separates hard changed-file crossings from advisory global
  heatmap freshness. Neither the fix nor its tests should read the committed
  heatmap to decide whether a rename crossed a floor.
- The producer measures **merge base to working tree**, plus untracked files;
  it is neither base-tip-to-HEAD nor last-commit-only. Base selection remains
  argv[1], then `XPF_AUDIT_BASE_REF`, then `origin/master` (script:83-98).
  `git diff <commit>` is documented as "the changes you have in your working
  tree relative to the named `<commit>`" (`git-diff(1)`, single-commit form).
- `scripts/refactoring-audit-lib.sh:60-72,87-93,118-149` is the sole classifier
  and raw-newline LOC source. It excludes test/generated/vendor paths and
  defines the 1500/2000 floors. Do not duplicate those rules.
- `thresholdCrossings` reports only the highest newly crossed floor; in-band
  growth and shrinking do not cross. `isAccepted` is destination-path/tier
  specific (`audit_touched_test.go:183-197`). No acknowledgement migration or
  broader exemption is necessary for a rename that has no crossing.
- `newFixtureRepo`, `fixtureRepo.writeFile`, `fixtureRepo.touched`, `r.script`,
  and `r.git` already exist in `pkg/refactoraudit/audit_jobs_test.go:20-155`.
  They use temporary repos, deterministic newline counts, and isolated Git
  configuration (`GIT_CONFIG_GLOBAL/SYSTEM=/dev/null`). Extend this harness
  rather than add a second one. Note the two execution paths: `r.touched()`
  `t.Fatalf`s on script error (`audit_jobs_test.go:151-153`) and therefore
  cannot assert nonzero exits; `r.script()` returns stdout/stderr/err
  separately (cf. `TestUndeterminableBaseFailsLoudly`, :315-349) and is the
  required path for every nonzero-expectation fixture (§8).
- `Makefile:249-271` deliberately reruns `pkg/refactoraudit` uncached. Preserve
  `-count=1`; Git/tree/script state is not safely represented by the Go cache.
- Current operator wording at `docs/refactoring-audit.md:103-146` explicitly
  describes `--name-only`; update that live contract with the implementation.
- All v2 Git-behavior pins reference `git version 2.53.0` and the installed
  `git-diff(1)` / `git-config(1)` man pages. Any claim the manual does not
  cover is backed by a quoted scratch-repo probe in §8, not by memory.

## 4. Concrete design and alternatives

### Selected option: retain Git's rename identity at `-M90%`, keep the row protocol

Change the producer, not the crossing predicate. Request a status-bearing,
NUL-delimited diff and keep each recognized rename's source paired with its
working-tree destination:

```bash
git -c diff.renames=true diff --name-status -z -M90% --diff-filter=d "$merge_base" --
git ls-files --others --exclude-standard -z
```

`-M` alone with `--name-only` is explicitly insufficient (no status column can
carry the source). Explicit `diff.renames=true` overrides a user's
`diff.renames=false` (which would silently restore destination-only behavior)
and `diff.renames=copies` (which must never lend a baseline to a copy). Do not
request `-C`, `--find-copies-harder`, unlimited rename search, or a
repository-wide content-hash index.

**Similarity decision: `-M90%` (B-F5).** Bare `-M` (default 50%,
`git-diff(1)` `-M[<n>]`: "The default similarity index is 50%"; `-M100%` =
exact-only) is rejected: a delete+add pair sharing 60% boilerplate could pair
as `R60`, attributing a genuinely new 1600-line module to a deleted file's
baseline and suppressing its WATCH — a false negative, worse than the friction
being fixed. Exact-only `-M100%` is rejected in the other direction: it fixes
the issue's `R100` control but leaves every rename-plus-growth (e.g. 1499→1500,
99.9% similar) as a new-file false positive, defeating the gate's below→above
comparison. `-M90%` keeps the edited-move fix for rewrites up to 10% — every
realistic threshold-crossing growth (a +1 line move at 1500 is 99.93%) — while
bounding the false-negative surface to >90%-similar delete+add pairs, i.e.
near-duplicates where move-attribution is the honest reading of the diff.
Residual, disclosed: moves rewritten more than 10% degrade to add+delete =
today's false-positive mode (fail-closed toward crossing, never suppression).
The boundary is pinned from both sides by fixtures (§8: 60%-boilerplate
stays-new; 93%-similar true-source pairing; heavy-rewrite dissimilarity control).

### Byte-exact `-z` record layout (B-F1, git 2.53.0, od-quoted in §8)

- `-z` means "do not munge pathnames and use NULs as output field terminators"
  (`git-diff(1)`). Records are concatenated with no extra framing.
- Rename/copy record: `R<score>\0<src>\0<dst>\0` — observed
  `R 1 0 0 \0 o l d . g o \0 n e w . g o \0`. The score is attached to the
  status token (`R100`, `R099`); the FIRST path is the source, the SECOND the
  destination. The source feeds `git cat-file -e "$merge_base:<src>"`; the
  destination feeds classification, `[ -f ]`, and `audit_loc`.
- Single-path record: `<status>\0<path>\0` — observed `T\0new.go\0`,
  `A\0…\0`, `M\0f.go\0`. Single-letter statuses carry no score.
- `R` with staged mv + 1 unstaged line reports `R099` against working content
  (§8 probe), confirming similarity input is the working tree for the
  `git diff <commit>` form — consistent with the man-page "working tree
  relative to the named commit" definition (B-F4).
- Malformed detection (all loud errors, never skips): status token not
  matching `^[ACDMRTUXB][0-9]*$`; score digits on any status except `R`/`C`;
  `R`/`C` without exactly two following path fields; empty path field;
  truncated tail (stream ends mid-record). A swapped source/destination
  implementation is caught twice: the §8 real-rename order fixture reads an
  absent destination blob → `-` (asserted `!isNew`), and a fake-git
  `R100\0src\0dst\0` feed with both blobs present (1700 vs 900) pins src-first
  byte order — only the correct source yields base 1700.

### Full status table: every `--diff-filter=d`-visible status (B-F2, A-F1)

`--diff-filter=[(A|C|D|M|R|T|U|X|B)...]` selects Added/Copied/Deleted/
Modified/Renamed/Typechanged/Unmerged/Unknown/Broken-pairing, and "upper-case
letters can be downcased to exclude" (`git-diff(1)` ~lines 476-488). Lowercase
`d` excludes only Deletions, so all other eight statuses reach the parser.
Each row states Baseline / Measurement / Row-or-Error and proves its delta
against today (current: destination-only path → `audit_is_audited_path` +
`[ -f ]` + same-path `cat-file -e`, `script:108-115`).

| Status | Baseline | Measurement / row rule | Delta vs today |
|---|---|---|---|
| `A` Added | Absent (`-`) | Working dest via `audit_loc`; row iff audited + `[ -f ]` | None — identical path |
| `C` Copied | Absent (`-`), treated exactly as `A`; the paired source is IGNORED, never a baseline | Same as `A` | None in practice: `C` cannot appear without `-C`/`copies` detection ("copied and renamed entries cannot appear if detection for those types is disabled", `git-diff(1)` ~487), and the command pins `diff.renames=true` with no `-C`. If it ever appears (future default, config leak), treat-as-`A` is the safe defined meaning — a copy is a new module. Explicitly NOT an error (erroring would let a config leak break gate availability) and NOT a rename (copies must not inherit baselines) |
| `M` Modified | Same path at merge base | Working dest; row iff audited + `[ -f ]` | None — identical path. INCLUDES conflicted files: the probe's `git diff <commit>` form reports a merge-conflicted file as `M` (probed, §8), never `U`, so marker-inflated working LOC is measured exactly as today |
| `R` Renamed | Old/source path at merge base (both endpoints audited); Absent (`-`) when the source was excluded/out-of-root (admission to production audit — explicit new boundary policy, see below) | New/destination working path; record src in the consumed-source set (even when dest is excluded, so a restored untracked source cannot reuse the identity) | THE intended fix: `R100 1701→1701` goes from `- 1701` (false WATCH) to `1701 1701` (silent) |
| `T` Typechange | Same path at merge base | `[ -f ]` guard drops non-regular dests (dangling symlink, submodule, gitlink); row iff audited + regular file | None — identical path. `R+T` combined (rename + file→symlink) surfaces as `A+D`, NOT `R` or `T` (probed, §8: no cross-type pairing) → dest is `A` → `-`; `D` dropped by the filter; dangling symlinks additionally dropped by `[ -f ]`. Residual FP for rename-to-valid-symlink disclosed — byte-identical code path to any `A` today |
| `U` Unmerged | Not emitted by the intended tree-vs-working-tree command | No independent `U` row. If a future refactor accidentally feeds index-form `U\0path\0M\0path\0`, coalesce the duplicate current path and measure it once with the same-path `M` rules; a lone `U` is a malformed stream and errors | None for the intended producer: the real gate emits one `M` row. Defensive coalescing preserves today's sorted-unique one-row result; never emit two rows |
| `X` Unknown, `B` Broken pairing | Same path at merge base (today's handling) + stderr warning naming the path | Working dest; row iff audited + `[ -f ]` | None: deliberately today's behavior, not an error. Rationale: `X`/`B` can theoretically appear with uncertain meaning; erroring the whole probe on one such row would turn a single odd path into branch-level infra-red (availability-hostile). Same-path handling degrades safely (miss → `-` → false positive, never suppression), and the stderr warning keeps it visible. `U` is deliberately absent from this rule because it is not an input to the intended producer; only the defensive duplicate-coalescing rule above applies |

`D` Deleted is excluded by `--diff-filter=d`; if a future Git emits one anyway, the parser drops it silently — a deletion cannot cross a floor upward and must not create a duplicate path or an error.

The excluded→audited admission rule (`R` from an excluded/out-of-root source
begins at `-`) is an explicit proposed boundary policy: excluded LOC was never
attributed as production, so inheriting it would land 1701 lines silently,
violating the new-file-crosses rule (`audit_touched_test.go:63-65`,
tcp_segmentation.rs). Reviewer A signed off on this policy in round 1; delta
reviewers must confirm or reject it. The reverse (audited→excluded) emits no
row — the destination is not in the audited population.

### Shell control flow, ownership, and errors

1. Resolve and validate root/base/merge base exactly as today.
2. Capture the NUL-delimited tracked and untracked streams in a private
   `mktemp -d` workspace outside the repository; check each Git command's
   status before parsing. The refresh sibling already uses `mktemp` plus
   `trap ... EXIT` (`scripts/refactoring-audit-refresh.sh:59-63`). Do not use
   unchecked process substitution, which can conceal a failed producer.
3. Parse tracked records in the main shell (a pipeline `while` runs in a
   subshell and would lose the consumed-source set; `lastpipe` is
   non-portable). Keep only a small associative set of source paths consumed
   by recognized renames. Entries live for one invocation, never persist, and
   require no repository/index writes.
4. Use one internal helper, `emit_touched <base-path-or-empty> <working-path>`,
   for classification, file existence, baseline LOC, and destination LOC.
   Empty baseline means new. Blob-absence policy (B-F3), split by cause:
   - Merge-base COMMIT itself unreadable (`git cat-file -e $mb^{commit}`
     fails, checked once and cached) → hard error with a fetch/deepen hint.
     This is the genuinely-undeterminable set; the existing
     `TestUndeterminableBaseFailsLoudly` posture applies. No shallow
     blob-presence guarantee is claimed — none was found — so this branch
     carries the shallow-CI risk, and it triggers only when the base commit
     is actually absent, not on every shallow clone (the merge-base commit
     of a shallow clone against its own `origin/master` is normally present).
   - Commit present but a promised TRACKED source/same-path BLOB unreadable
     (shallow boundary truncation, partial-clone lazy-fetch failure,
     genuinely absent path) → `-` fallback (today's behavior) + stderr
     warning naming the path. This preserves availability (shallow/partial CI
     keeps working) and preserves today's fail direction (miss → new →
     possible false crossing, never suppression). Untracked `W` same-path
     misses stay silent `-`: warning on every genuinely-new untracked file
     would be noise, and silence matches `A`/`C` (always `-` without warning).
     Tracked and untracked agree on fallback; they differ on warning by design.
   - Existence probe succeeds but the subsequent `git show … | wc -l` count
     fails → hard error (the repo changed under the probe or is corrupt;
     counting garbage as a baseline is never acceptable).
   Reject malformed/truncated records per the layout rules above; handle every
   well-formed status the intended Git command can emit per the table (no
   "unsupported status" error for any status Git can emit in this command).
   If a future refactor accidentally feeds index-form `U+M`, coalesce by
   current path before invoking `emit_touched`; a lone `U` is a malformed
   stream. The v1 generic reject rule is otherwise withdrawn.
5. Parse untracked records after the tracked stream: untracked audited path
   with no consumed-source match keeps today's same-path probing (baseline if
   present at base, else `-`); untracked recreation of a CONSUMED rename
   source is `-` (one predecessor, never lent twice). Preserve `[ -f ]`.
   Directory moves surface as one `R` record per file (B-F6); each is handled
   independently — no special-casing, O(changed records) storage. Do not
   follow rename chains per commit: the single merge-base diff yields the
   final pair directly.
6. Stage result rows until measurement succeeds, then emit in deterministic
   C-locale destination-path order. The external line protocol still cannot
   represent whitespace-containing audited destinations; reject them loudly
   rather than emitting ambiguous rows. Source-only whitespace is safe when
   quoted for Git lookup and never emitted (§8 fixture).
7. Clean the private temporary workspace on exit. Do not alter the Git index,
   create a commit, regenerate the heatmap, or write an acknowledgement.

Rename-limit behavior (A-F2): `diff.renameLimit` (default 1000,
`git-config(1)`) bounds the exhaustive inexact portion; exact matches are
found before the budget applies. Beyond the budget, remaining inexact
candidates degrade to `D+A` with exit 0 (probed, §8: no pairing beyond the
budget, no nonzero) — destinations surface as `A` → `-`, i.e. today's FP
mode. Accept-and-document; no error. The §8 smoke (1200-file diff, above the
default limit) pins completion time and the no-silent-drop property.

This is a read-only developer command, not a concurrent snapshot guarantee.
Working-tree content changed during a probe is an existing race; no locking,
retry engine, cache, or persistent metadata is proposed.

### Scope of rename recognition

Committed and staged renames recognized by the merge-base diff are covered.
`git diff <commit>` diffs the working tree against the named tree, and the
`R099` probe (staged `git mv` + 1 unstaged line → still `R`, similarity from
working content) proves unstaged edits neither break pairing nor escape
measurement: head LOC always comes from the working path via `audit_loc`,
and pairing uses working content too. A raw filesystem move whose destination
is entirely untracked is not a Git rename record (`git diff` ignores untracked
files) and remains conservative addition/deletion handling — stage the move
for ancestry recognition (both round-1 reviewers confirm raw-move recognition
must NOT be required). No arbitrary untracked-content matching is proposed:
that is a general file-identity engine, correctly out of scope.

### Other viable paths and reasons not to select them

- **Bare `-M` (50%)**: fixes all edited moves, but the false-negative bound is
  too weak (60%-boilerplate delete+add pairs suppress true new-file
  crossings). Rejected; reviewer B requires the pin, and `-M90%` keeps every
  realistic edited-move fix.
- **Exact-rename-only (`-M100%`)**: smallest identity policy and zero heuristic
  FN, but rename-plus-one-line growth (1499→1500, the gate's core below→above
  comparison) would still look new. Rejected; the edited-move fix is the
  point, and `-M90%` bounds the heuristic tightly enough.
- **Blob/content-hash matching**: can identify exact copies too, but copies are
  new modules and must not inherit a size exemption. More machinery than this
  issue warrants; still unnatural for rename-plus-growth. Rejected.
- **Skip renamed files or grant an acknowledgement automatically**: rejected;
  a renamed file can genuinely grow from 1499 to 1500 or 1999 to 2000.
- **Change `thresholdCrossings`/`parseTouched` to guess ancestry**: rejected;
  the current three columns no longer contain the discarded old path.

### Exact implementation ownership after approval (3 files + one explicitly zero-touch boundary)

1. `scripts/refactoring-audit-touched.sh`: replace changed-set/measurement loop
   at 100-116 and correct its header explanation at 4-10 and 34-41. Add only
   script-local parsing/measurement support needed for the contract above.
2. `pkg/refactoraudit/audit_jobs_test.go`: extend the existing real-repo fixture
   coverage; use `newFixtureRepo`, `writeFile`, `git`, `script`, `touched`, and
   `thresholdCrossings`. No parallel fixture framework.
3. `docs/refactoring-audit.md`: update changed-set and baseline semantics in
   the touched-gate section (including the predecessor-baseline explanation —
   see zero-touch decision); document tracked rename coverage and limits.
4. `pkg/refactoraudit/audit_touched_test.go`: **zero-touch** (B-F8). The v1
   comments-only edit is withdrawn; its explanatory content moves to the audit
   doc already owned above. Rationale: even comment hunks can conflict, and
   the comments explained producer behavior that belongs in the operator doc
   anyway. Numeric-domain compatibility in one line: rename baselines come
   from the same `git show … | wc -l` / `audit_loc` newline domain as today
   (`script:111`, `lib.sh:70-72`), so any future parser hardening is
   unaffected by this change.

**#10487 serialization (A-F7).** Live coordination states #10487 touches no
existing `pkg/refactoraudit` files (NEW `accepted_live_test.go` only) — but no
10487 plan exists under `docs/pr/` to verify against, so the plan-level truth
is: the real overlap is the `docs/refactoring-audit.md` gate section, which
both issues edit. Order-independence holds regardless: `isAccepted` matches
path+tier on the destination (`audit_touched_test.go:187-197`) while rename
awareness changes base LOC only — no semantic interaction. Proposal: whoever
lands first owns the docs hunk; the other rebases it. If both are in flight,
lower issue number (#10487) wins concurrent-edit conflicts per campaign rule.
The parent serializes at implementation time; this plan round touches no
shared file.

## 5. Public API preservation

There are **zero changed product public methods**. Preserve these tooling seams:

```text
bash scripts/refactoring-audit-touched.sh [base-ref]
XPF_AUDIT_BASE_REF=<ref>
stdout: <base-LOC|-> <head-LOC> <destination-path>\n
```

The external format remains exactly three fields, one row per audited current
path, sorted by destination; no fourth old-path column. The interpretation of
base LOC becomes correct for recognized ancestry. Existing invalid-base failures
remain nonzero with diagnostics; a successful empty set is not an error fallback.

stderr additions are allowed and safe: blob-absent warnings, `X`/`B` warnings,
and the shallow hint all go to stderr. The Go consumers parse stdout only —
`runScriptErr` returns stdout/stderr/err separately and `parseTouched`
receives stdout (`audit_canary_test.go:119+`; `fixtureRepo.touched` passes
`stdout` at `audit_jobs_test.go:154`) — so diagnostics cannot corrupt a row.

Preserve these existing Go signatures and representations:

```go
func thresholdCrossings(files []touchedFile) []crossing
func parseTouched(t *testing.T, what, text string) []touchedFile
func isAccepted(c crossing, accepted []acceptedCrossing) bool
func (r *fixtureRepo) touched(baseRef string) []touchedFile
```

No RPC, config schema, HA serialization, deployment, or public CLI change.

## 6. Hidden invariants

- **Attribution:** base means the branch's merge base, never a moving base tip;
  HEAD-to-last-commit comparisons are not equivalent.
- **Growth remains visible:** rename is not an exemption; the strict baseline
  comparison and inclusive 1500/2000 destination comparisons do not change.
  Correctly-paired edited renames across floors still RED — with true
  attribution (`1499 → 1500`), not new-file attribution.
- **One predecessor, not copies:** an added copy and a recreated consumed
  source remain new; identical bytes alone are not proof of ancestry. The
  consumed-source set is checked for tracked and untracked paths alike.
- **Threshold bound:** only ≥90%-similar pairs inherit baselines; everything
  less similar degrades to add+delete (today's FP direction, never
  suppression). The 90% constant lives in exactly one place (the probe
  command) and is pinned by fixtures on both sides.
- **Population:** use the shared classifier on the DESTINATION for inclusion;
  no local exclusion regex, raw LOC estimator, inline-test stripper, or
  additional roots. Destination eligibility governs inclusion; the old path
  supplies merge-base LOC only.
- **Limit degradation preserves FP direction:** rename-limit exhaustion,
  unrecognized rewrites, and cross-type (`R+T`) pairs all surface destinations
  as `A` → `-`. No degradation path can silence a true crossing.
- **Conflict behavior unchanged:** a fresh content-conflict probe shows that
  `git diff --name-status -z <merge-base> --` reports exactly
  `M\0f.go\0`, and the producer emits one same-path row with marker-inflated
  working LOC, exactly as today. The index form (not used by the producer)
  reports `U\0f.go\0M\0f.go\0`; if ever accidentally supplied, duplicate
  current paths are coalesced to that one M-equivalent row. No new error path
  exists for any input the intended producer can emit.
- **Side effects/order:** establish valid inputs before publishing rows; errors
  remain errors, tracked origins precede untracked-source reconciliation, and
  no Git/index/heatmap/acknowledgement write is performed.
- **Lifetime/stale handles:** only invocation-local strings, temporary streams,
  and an origin set; no handles survive checkout changes. No Rust borrows,
  cross-thread references, shared maps, or deferred goroutine ownership.
- **Allocation/performance:** no firewall allocation change. Do not hash the
  whole repository or retain all file contents to identify a rename.
- **HA/kernel/protocol portability:** not applicable to this shell/Go-test gate;
  no network state is touched. Linux shell/Git failure handling is the relevant
  systems boundary, not NIC offloads or transport correctness.
- **Cached results and acceptance:** keep uncached invocation and unchanged
  destination-specific acknowledgement semantics. Heatmap refresh is separate.

## 7. Four-class risk assessment

| Risk class | Rating | Concrete risk and bounding check |
|---|---|---|
| Behavioral regression | MED | Heuristic ancestry remains, now bounded: only ≥90%-similar pairs inherit (near-duplicates = honest moves); every other degradation (limit, rewrite, cross-type, blob-absent, X/B) flows to `-`/same-path, i.e. today's FP direction. Wrong-endpoint suppression is pinned by the swap + ambiguity + boilerplate fixtures. Residual accepted risk: >10%-rewritten moves still FP (unchanged from today, disclosed). |
| Lifetime / borrow-checker | LOW | No Rust or shared ownership changes. Temporary stream cleanup and main-shell parsing state are the actual lifetime risks; `mktemp -d` + `trap … EXIT` (refresh-sibling precedent) and checked Git exits before parsing. No new whole-probe error path for any emittable input, so no availability regression for shallow/partial CI (blob-absent falls back with warning; only a missing base commit errors, as today). |
| Performance regression | LOW | Offline gate; `-M90%` similarity over the changed set plus temp I/O. No `-C`, no unlimited search. Bounded by the §8 smoke: 1200-file rename diff (above the default 1000 limit) within 5× today's probe wall time, exit 0, row-superset. |
| Architectural mismatch | LOW | Producer-side ancestry restores documented author-attribution semantics and keeps the consumer/SSOT untouched. Risk rises if the solution becomes a general file-identity engine (untracked-content matching, hash indexes, per-commit chains — all out of scope); PLAN-KILL that expansion rather than rebuild Git. |

## 8. Test plan and acceptance evidence

### This plan round (v1 + v2 deltas)

v1 performed: live-source inspection, STEP-0 searches, pinned population
census, and bounded history census. The real gate smoke,
`bash scripts/refactoring-audit-touched.sh`, exited 0 with no audited rows, as
expected for the docs-only branch. `GOCACHE=/dev/shm/gocache-10488
GOTMPDIR=/dev/shm go test -count=1 ./pkg/refactoraudit/` was run once; it
failed ONLY in the unrelated existing `TestStructMetricIsTypesNotFields6937`
calibration assertion (`structs_6937_test.go:94-96`: `CompileResult` 32
fields/21 types flags while the test expects just-under the 20-type floor).
This plan-only documentation diff cannot affect that Go test. No Cargo build,
formatter, linter, project-wide suite, cluster, Incus, or
provider/companion reviewer command was run in either round.

v2 delta evidence — scratch-repo Git probes (git 2.53.0, hermetic env,
`/dev/shm` scratch, destroyed after; worktree untouched):

| Probe | Observed bytes / output | Pins |
|---|---|---|
| `git mv` + `diff --cached --name-status -z -M` | `R 1 0 0 \0 o l d . g o \0 n e w . g o \0` | B-F1: `R<score>\0<src>\0<dst>\0`, score attached, src first |
| Staged mv + 1 unstaged line, `git diff HEAD --name-status -M` | `R099 old.go new.go` | B-F4: pairing survives unstaged growth; similarity from working content |
| File→symlink, `-z` | `T\0new.go\0` | B-F2: single-path `T`, no score |
| Symlink→regular, `-z` | `T\0src.go\0`; merge-base blob is link text `target.go` (0 newline bytes, so `wc -l` = 0), working destination is a 1700-line regular file | B-F2/fixture 16: `T` ends in an audited regular file; baseline is the source path's raw merge-base blob LOC (do not dereference the symlink), head is `audit_loc` on the regular destination |
| Rename + file→symlink, `-M HEAD` | `A moved.go` + `D old.go` (no `R`, no `T`) | B-F2: no cross-type pairing; `R+T` = `A+D` |
| Fresh real content conflict: intended gate `git diff --name-status -z $BASE --` | Merge exits 1; gate command exits 0 and emits exactly `M\0f.go\0`; `--diff-filter=d` emits the same bytes | A-F1/B-F2: intended producer sees `M`, not `U`; one same-path row with marker-inflated head LOC is the zero-delta contract |
| Same fresh conflict, index form `git diff --name-status -z --` | Command exits 0 and emits exactly `U\0f.go\0M\0f.go\0`; this stream is NOT an input to the intended producer | Scope guard: if a future refactor accidentally supplies it, coalesce duplicate `f.go` and emit one M-equivalent row; do not count two rows |
| 30-file inexact rename set, `-c diff.renameLimit=5` | Exit 0, no pairing beyond budget, no nonzero | A-F2: limit degradation = `D+A`, safe direction |
| Fresh `bash scripts/refactoring-audit.sh \| wc -l` at base | 80 | A-F5: generator == census; artifact staleness proven |
| `wc -l` artifact + `git log` | 50 rows, last touched `254ca9939` | A-F5: other half of the reconciliation |

Man-page citations (installed pages, verified by excerpt, not memory):
`--diff-filter=[(A|C|D|M|R|T|U|X|B)...]` + lowercase-excludes + "copied and
renamed entries cannot appear if detection for those types is disabled"
(`git-diff(1)` ~476-488); `-z` NUL terminators (~241-242); single-`<commit>`
"working tree relative to the named commit" (~43-45); `-M` default 50%,
`-M100%` exact (~436-443); `diff.renameLimit` default 1000, exhaustive
portion (`git-config(1)` ~2471-2474); `diff.renames` defaults true (~2476-2480).

### After parent approval: permanent regression cases

Reuse `fixtureRepo` to execute the real shell producer, then feed its rows into
`thresholdCrossings`. Require the destination row and its measured LOC, not
just an empty crossing list: silently dropping a rename is not a fix.

Harness method (B-F7): `r.touched()` for all row-asserting cases (it runs the
real copied script + `parseTouched`); `r.script()` — which returns
stdout/stderr/err separately — for ALL nonzero-expectation cases (`U`-defense,
whitespace dest, truncated/failed producer), because `r.touched()`
`t.Fatalf`s on script error and cannot assert an exit code. Layer note: an
old-producer whitespace path exits 0 with a 4-field row → `parseTouched`
"want 3 fields" fatal (`audit_touched_test.go:122-124`); the new producer
exits nonzero with no rows. Both fail; the failure moves script-ward.
`R`-precondition for every rename case (prevents testing `A` while believing
`R`):

```go
status := r.git("diff", "--name-status", "-M90%", base, "--")
// precondition: Git must report THIS pair as a rename.
if !strings.Contains(status, "R") || !strings.Contains(status, "old.go") {
    t.Fatalf("fixture is not a rename (want R old.go -> new.go); got:\n%s", status)
}
```

| # | Case | Required observable result / plausible defect caught |
|---|---|---|
| 1 | Committed pure `1701 -> 1701` rename | One dest row, base 1701, not new; no crossing. Catches destination-only base lookup. Fails pre-fix (`- 1701` WATCH). |
| 2 | Staged pure `2100 -> 2100` rename with `diff.renames=false` | Same contract, no crossing. Catches relying on user rename config; pins higher-band baseline. Fails pre-fix. |
| 3 | Source/destination order: base holds `swap_a.go` 1700 AND `swap_b.go` 900 decoy; branch renames `swap_a.go→swap_c.go` (fresh name) | Dest row base 1700 (source), head 1700, silent. A swapped implementation reads base `swap_c.go` (absent) → `-` → false WATCH, caught via `!isNew`. Both-endpoints-exist overwrite (`a→b` with `b` present) cannot be real `R`: Git reports `M/M` (overwrite `D/M`), never `R`, so the v2 overwrite sketch is withdrawn. Byte order with both blobs present is pinned by a fake-git `R100` feed. Fails pre-fix AND on swapped-lookup. |
| 4 | Staged rename + UNSTAGED `1499 -> 1500` growth | Exactly WATCH at dest, base 1499. Catches skipping renames, HEAD-instead-of-working measurement, and pairing broken by unstaged edits. Tier alone passes pre-fix; the base-1499 assertion discriminates. |
| 5 | Staged rename + UNSTAGED `1999 -> 2000` growth | Exactly REFACTOR at dest, base 1999. Same, higher band. |
| 6 | Committed rename + committed `1499 -> 1500` growth | Exactly WATCH, base 1499. Pins the committed-growth path alongside the unstaged path. |
| 7 | 60%-boilerplate delete+add (unrelated 1600-line files) | Added file is `-` new WATCH; deleted file absent (filter). Proves no pairing below 90%. Passes pre-fix too (non-regression + threshold pin — would FAIL under bare `-M50%` if Git paired at R60). |
| 8 | Ambiguous pair: base `big.go` 2100 (60% boilerplate shared) + `small.go` 1400; branch renames small→`mid.go` 1500 (93% to small) | Dest base exactly 1400, WATCH. Mis-pairing to big (base 2100 → silent) fails; failure-to-pair (`-` → wrong attribution) fails. THE B-F5 suppression guard. |
| 9 | Dissimilarity control: heavy rewrite, similarity <90% | Dest is `-` new-file crossing (WATCH at 1700). Pins the boundary from below; proves over-eager pairing and silent-skip implementations both fail. (A-F3.) |
| 10 | Copy retained + added 1701-line copy, `diff.renames=copies` in fixture env | Copy is new WATCH; retained source untouched. Proves pinned `diff.renames=true` wins over user config AND `C` never inherits (assert `C` absent from the probe's Git output). |
| 11 | Staged rename + untracked recreation of consumed source (1701) | Dest silent with source base; recreated old path is new WATCH. Catches double-lending. Inversion vs pre-fix (pre: dest WATCH, source silent). |
| 12 | Same-path untracked restoration after index removal, no rename | Preserves today's same-path baseline (not unconditional new). Non-regression guard. |
| 13 | Excluded 1701-line source → audited dest; reverse direction | Admission is new WATCH (A-F5 policy); move-out omitted. Catches wrong-endpoint classification. |
| 14 | Two-step committed rename (orig → mid → final) | Merge-base ORIGINAL LOC as base; only final dest emitted. Catches HEAD-only ancestry. |
| 15 | Directory rename: 3 audited `pkg/olddir/*.go` → `pkg/newdir/*.go` (B-F6) | 3 dest rows with correct bases, no crossings; + untracked recreation of one old path is WATCH. Proves per-file independence, C-locale order, set growth. |
| 16 | `T` symlink→regular audited file (base `src.go` is a symlink whose merge-base blob is link text `target.go`; working `src.go` is 1700 regular lines) | Status `T`; baseline is the raw symlink-blob LOC (0, because `wc -l` counts newline bytes), head is 1700 via `audit_loc`; `[ -f ]` passes and the row can cross WATCH. Pins the actual `T` transition and its no-dereference baseline semantics. |
| 17 | `T` file→symlink (dangling) | No row (`[ -f ]` drops). Identical in both versions — non-regression guard. |
| 18 | `R+T`: rename + file→symlink | Surfaces `A+D` → dest `-` (dangling: no row at all). Assert observed Git behavior, identical both versions. Documents the disclosed residual. |
| 19 | Fresh real content-conflict tree via `r.script()` | Merge setup exits 1 but leaves the conflict; intended gate command exits 0 with exactly one `M\0f.go\0` row and marker-inflated head LOC, identical both versions. The index-only diagnostic is exactly `U\0f.go\0M\0f.go\0`; if accidentally fed, coalesce to one same-path M row. Pins the actual zero-delta contract, not a fictional U producer path. |
| 20 | Source-only whitespace: base `"old dir/a.go"` 1700 → `pkg/new.go` | Dest row base 1700, silent. Proves quoted source lookup + non-emission. |
| 21 | Audited dest with whitespace; truncated `-z` tail; `git` producer failure — all via `r.script()` | Each: nonzero exit, no rows on stdout. Catches delimiter, malformed-record, and process-substitution mistakes. (Pre-fix whitespace fails at the Go layer instead — accepted layer move.) |
| 22 | Merge-base commit present but source blob absent (grafted fixture) via `r.script()` | Exit 0 + `-` dest row + stderr warning naming the path. Pins the B-F3 availability policy (fallback, not infra-red). Pre-fix: same `-` row without warning. |

Keep focused tests only where a plausible bug changes the observed result
(cases 1-11, 13-15, 18, 20-22 discriminate; 12, 16, 17, 19 are non-regression
guards pinning zero-delta — each names the behavior it freezes). Assert
script/decision behavior, never source text or exact diagnostic prose (assert
warning PRESENCE via `strings.Contains(stderr, path)`, not wording). Do not
edit the existing gate, thresholds, acceptance file, or fixtures merely to
make a candidate pass. Keep existing local-branch, untracked-growth,
undeterminable-base, crossing-boundary, and acknowledgement tests unchanged.

Proposed post-implementation commands (the v1 package run was a pre-change
baseline attempt and must be rerun after any approved code change):

```bash
GOCACHE=/dev/shm/gocache-10488 GOTMPDIR=/dev/shm \
  go test -count=1 ./pkg/refactoraudit/ \
  -run '^(TestTouchedRename10488|TestTouchedSetIsLocalToTheBranch|TestTouchedSetSeesUncommittedAndUntrackedGrowth|TestBranchTouchingNothingAuditedIsSilent|TestUndeterminableBaseFailsLoudly|TestThresholdCrossingCases|TestAcceptedCrossingIsTheOnlyEscape)$'

GOCACHE=/dev/shm/gocache-10488 GOTMPDIR=/dev/shm \
  go test -count=5 ./pkg/refactoraudit/ -run '^TestTouchedRename10488$'

GOCACHE=/dev/shm/gocache-10488 GOTMPDIR=/dev/shm \
  go test -count=1 ./pkg/refactoraudit/
```

`TestTouchedRename10488` is the proposed fixture entrypoint, not an existing
symbol. Require cases 1-6, 8, 11, 14, 15, 20 to fail against the old producer
(pre-fix discrimination) and pass against the replacement; require real-growth
controls (4, 5, 6, 8) to remain RED crossings in both versions (renames are
not exemptions — only attribution changes). In a throwaway repo, run the
actual CLI for a pure rename and a renamed threshold-crossing control and
inspect rows + exit status.

**Red-package acceptance rule (A-F6).** While `TestStructMetricIsTypesNotFields6937`
is red, the full-package run passes iff its failure set EQUALS the pre-change
baseline set `{TestStructMetricIsTypesNotFields6937}` — green not required, no
NEW failures allowed. The targeted `-run` regex above excludes all 6937 tests,
and the new fixtures create no structs under `pkg/`, so they cannot plausibly
perturb that calibration.

**Many-path smoke (A-F2/B-F9, pass/fail).** In scratch: 1200-file rename
diff. This validates many-path completion, exit status, destination-set
preservation, and predecessor-baseline correctness:
(1) new probe completes within **5×** the same-tree today's-probe wall time;
(2) exit 0; (3) emitted audited-destination set ⊇ today's set (no silent
drops); (4) every row's baseline ∈ {today's baseline, true predecessor}.
This smoke does not by itself claim that Git degraded pairings to A+D; that
status outcome must be recorded directly if the limit path is observed.

**Many-path smoke result.** The post-implementation scratch run used 1,200
inexact renames: a direct status probe reported `R=1200` with no warning, so
no A+D rename-limit degradation is claimed for this content. Old probe:
6.599s / 1,200 rows. New probe: 13.320s / 1,200 rows (2.02×). Both exited
0, the new destination set contained the old set, and every new baseline was
the true 101-line predecessor blob. All four many-path conditions passed.

The parent owns the full integration gate once sibling work has landed. Cargo,
IPv4/IPv6 throughput, per-class CoS, and HA smoke do not discriminate this
shell-only defect; no fabricated old fixed suite counts or network results are
claimed. Any campaign-mandated deployment smoke is parent-sequenced later,
never part of this worker's plan-only round.

## 9. Out of scope

- Historical v2 scope excluded production implementation, test edits, PR creation, review dispatch, or merge; implementation is now landed in PR #10538 and this plan is retained as superseded review history.
- Changing either LOC threshold, band-growth policy, accepted-crossing policy,
  global heatmap freshness, shared classifier, or raw LOC definition.
- Parser numeric-domain hardening: owned by NEITHER #10488 nor #10487. v1's
  attribution was wrong (A-F4): #10487's issue text owns accepted-entry
  drift/expiry (prune + re-check) only, and no `docs/pr/*10487*` plan exists
  to cite. This plan preserves all parser signatures, and the real script
  cannot emit negative LOC (`strconv.Atoi` failure already fatal-loud at
  `audit_touched_test.go:130-135`) — hardening is a separate issue if anyone
  wants it, not a silent dependency of this one.
- Untracked-content ancestry discovery, persistent rename manifests, copy
  detection, content-hash indexes, or reconstructing per-commit rename chains.
  Raw-untracked-move recognition is confirmed NOT required (both reviewers).
- Widening the external row protocol to support whitespace filenames. Reject
  such audited destinations; a new escaped/NUL/structured API is separate work.
- Revalidating the unavailable 400-commit historical census, fetching shared
  history, or asserting that this clone's zero observed renames prove no impact.
- Rust/Go product refactoring, CI/Makefile edits, cluster access, performance
  telemetry, or mandatory large-file splits unrelated to the reported gate.

## 10. Open questions for adversarial review

1. **Threshold constant:** is `-M90%` the right pin, or should delta review
   demand `-M85%`/`-M95%`/exact-only? The bound argument (near-duplicate ⇒
   honest move) holds for any high threshold; the 10% rewrite budget is a
   judgment call. Reject the constant (not the approach) if the FN/FP
   tradeoff curve argues otherwise — the fixtures make re-pinning cheap.
2. **Audit-population admission:** moving excluded/generated/test content into
   an audited path begins at zero (reviewer A signed off in round 1). Delta
   reviewers: confirm or reject this new boundary policy; do not silently
   approve the extra behavior if it contradicts the production-audit contract.
3. **Untracked moves:** acceptance does NOT require raw-filesystem-move
   recognition (both round-1 reviewers concur; conservative add/drop is
   fail-safe). Reopen only with evidence that staged-move coverage misses a
   real author workflow — otherwise this stays closed.
4. **Multiplicity residual:** the consumed-source set + no-copy-detection +
   `-M90%` + ambiguity fixture bound double-lending and mis-pairing. Is the
   remaining pathological case (same-branch delete + >90%-similar unrelated
   add) incredible enough to ship, or does it need a belt-and-braces guard
   (e.g. cap inherited baselines at the destination's own size)? Reject if a
   realistic tree can construct the suppression.
5. **Failure-propagation shape:** materialized streams + main-shell origin set
   + fallback-with-warning (v2) vs observe-and-error (v1). Reviewer A judged
   the machinery proportionate in round 1. Delta reviewers: does the
   fallback+warning resolution of B-F3 keep that verdict, or does any
   warning-that-isn't-an-error hide rot that should red?
6. **Defensive U coalescing:** the intended tree-vs-working-tree command
   cannot emit `U` for a conflict; the fresh probe proves `M\0f.go\0`, while
   index-form output is `U\0f.go\0M\0f.go\0`. If a future refactor accidentally
   changes the input form, should the parser keep the specified duplicate
   coalescing (one M-equivalent row), or should it fail the stream? A lone
   `U` is malformed either way; choose the safer future-proof posture.
7. **`X`/`B` same-path-plus-warning:** v2 deliberately matches today instead
   of erroring, on availability grounds (one odd path must not infra-red the
   branch). Is that the right call for states whose meaning is "Git itself is
   unsure," or should genuinely-uncertain detector output fail the probe?
8. **Smoke bound adequacy:** N=1200 / 5× / row-superset / baseline-∈-{today,
   predecessor}. Does this quartet adjudicate both the cost question (Q7) and
   the limit-degradation question, or is a tighter budget / larger N /
   exit-code assertion on the warning path required?
9. **Evidence strength:** every discriminating case asserts destination row +
   measured base LOC (not just crossing emptiness), both floors carry
   edited-rename controls, and nonzero cases use `r.script()`. Is there a
   remaining case where a broken implementation passes — e.g. an assertion
   that should be exact-equality but is written as contains?
10. **Value:** 80 susceptible files, no verified incident rate, three-file
    remedy with a bounded heuristic. Reviewer A would not KILL on value;
    reviewer B conditioned value on bounding the heuristic FN (done via
    `-M90%` + fixtures). Delta reviewers: does the bound hold the value
    verdict? PLAN-KILL the approach if maintenance exceeds attribution value;
    preserve #10488's defect evidence rather than calling a rejected plan a fix.
