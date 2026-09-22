# Preserve rename ancestry in the touched modularity gate (#10488)

## Status

**DRAFT v1 — pending adversarial plan review.** Plan only; no implementation,
new tests, PR, deployment, or merge is authorized in this round. The parent
owns native reviewer dispatch and the implementation decision.

- Issue: <https://github.com/psaab/xpf/issues/10488> (OPEN at intake).
- Comparison/base: `b71c52d6093f23a7d9c9cca12d00cb40b3dffa8d` (`origin/master`).
- Branch: `fix/10488-rename-crossings`.
- Worktree: `/home/ps/git/pi-xpf/.claude/worktrees/10488-rename`.
- Owned file this round: `docs/pr/10488-rename-crossings/plan.md` only.
- Review status: no independent plan verdicts yet; this is not PLAN-READY.

## 1. Issue framing and STEP-0 disposition

A pure rename of an already-large audited file must not be blamed for creating
that file's existing LOC. The reported default-Git control had an `R100`
old-to-new mapping but the touched probe emitted `- 1701 pkg/rename_control/new.go`.
The existing consumer therefore reported a new-file WATCH crossing. The issue's
control is accepted evidence, not a newly executed experiment in this round.

The mechanism remains in the comparison revision:

1. `scripts/refactoring-audit-touched.sh:100-107` requests destination-only
   `git diff --name-only --diff-filter=d` output, adds untracked paths, and sorts.
2. Lines 108-115 classify the destination, then look up only
   `<merge-base>:<destination>`. A missing destination becomes `-` even when Git
   knows its old name.
3. `pkg/refactoraudit/audit_touched_test.go:115-143` parses `-` as `isNew`.
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

## 2. Honest scope/value and quantified blast radius

The win is correct attribution and avoiding unnecessary split/acknowledgement
work for moves. There is **no claimed throughput, allocation, HA, packet-loss,
or latency improvement** in the firewall. No production daemon/dataplane path
changes. No measured frequency or saved developer-hours estimate is available.

If reviewers conclude the perf gain is too small to justify the churn,
PLAN-KILL is an acceptable verdict.

For this tooling correctness issue that sentence is not a performance promise:
rejecting an oversized remedy does not refute the false positive.

### Measured population at the pinned base

The census enumerated Git blobs with `git ls-tree -rz b71c52d60 -- pkg cmd
userspace-dp/src userspace-xdp/src bpf/xdp bpf/tc`, selected `.go`/`.rs`/`.c`
candidates, invoked the shipped `scripts/refactoring-audit-classify.sh audited`
on those paths, and counted newline bytes in the selected blobs via
`git cat-file --batch`. This matches `audit_loc`, not a possibly stale heatmap.

| Quantity | Measured value / interpretation |
|---|---|
| Candidate files in configured language roots | 6,017 |
| Audit-eligible files | 1,722 |
| Audited Go / Rust / C files | 1,260 / 462 / 0 |
| Files at or above 1500 LOC | 80 |
| WATCH-only files, 1500-1999 LOC | 41 |
| REFACTOR files, at or above 2000 LOC | 39 |
| Configured roots / thresholds | 6 roots / 2 LOC thresholds |
| Producer / parser / decision function | 1 / 1 / 1 |
| Current parser call sites | 2: live gate and fixture-repo adapter |
| Proposed existing files to change after approval | 4, listed below |
| Product public APIs, wire formats, runtime hot paths changed | 0 |

Those 80 files are the population whose pure audited-to-audited rename can
produce the reported false crossing if the destination is new and the crossing
is not acknowledged. They are **not** 80 observed incidents. A filename-only
move below 1500 still loses ancestry today but does not trip either floor.

`git rev-parse --is-shallow-repository` returned `true`, and
`git rev-list --count --max-count=400 b71c52d60` returned **63**, not 400.
For each of the **62 available first-parent edges** of those reachable commits,
`git diff-tree --no-commit-id --name-status -r -z -M --diff-filter=R <parent>
<commit> --` produced **0 rename records**. This edge census is not a census of
400 first-parent commits, nor proof that earlier renames did not happen. The
issue's historical **11-renames claim remains unverified**; no fetch/deepen or
shared-ref mutation was performed to manufacture that evidence.

## 3. What is already shipped and must compose unchanged

- The #7253 split separates hard changed-file crossings from advisory global
  heatmap freshness. Neither the fix nor its tests should read the committed
  heatmap to decide whether a rename crossed a floor.
- The producer measures **merge base to working tree**, plus untracked files;
  it is neither base-tip-to-HEAD nor last-commit-only. Base selection remains
  argv[1], then `XPF_AUDIT_BASE_REF`, then `origin/master` (script:83-98).
- `scripts/refactoring-audit-lib.sh:60-72,87-93,118-149` is the sole classifier
  and raw-newline LOC source. It excludes test/generated/vendor paths and
  defines the 1500/2000 floors. Do not duplicate those rules.
- `thresholdCrossings` reports only the highest newly crossed floor; in-band
  growth and shrinking do not cross. `isAccepted` is destination-path/tier
  specific (`audit_touched_test.go:183-197`). No acknowledgement migration or
  broader exemption is necessary for a rename that has no crossing.
- `newFixtureRepo`, `fixtureRepo.writeFile`, `fixtureRepo.touched`, and the real
  script runner already exist in `pkg/refactoraudit/audit_jobs_test.go:20-155`.
  They use temporary repos, deterministic newline counts, and isolated Git
  configuration. Extend this harness rather than add a second one.
- `Makefile:249-271` deliberately reruns `pkg/refactoraudit` uncached. Preserve
  `-count=1`; Git/tree/script state is not safely represented by the Go cache.
- Current operator wording at `docs/refactoring-audit.md:103-146` explicitly
  describes `--name-only`; update that live contract with the implementation.

## 4. Concrete design and alternatives

### Selected option: retain Git's rename identity, keep the row protocol

Change the producer, not the crossing predicate. Request a status-bearing,
NUL-delimited diff and keep each recognized rename's source paired with its
working-tree destination:

```bash
git -c diff.renames=true diff --name-status -z -M --diff-filter=d "$merge_base" --
git ls-files --others --exclude-standard -z
```

`-M` alone with `--name-only` is explicitly insufficient. Use normal Git rename
similarity (not only `R100`) so a rename followed by real growth compares
against its own old LOC. Explicit rename-only configuration prevents a user's
`diff.renames=copies` from lending an old baseline to a copy. Do not request
`-C`, `--find-copies-harder`, unlimited rename search, or a repository-wide
content-hash index.

The internal record is a tuple `(status, base_path_or_absent, working_path)`;
it is not a new Go type or an exported interface. Decode the extra pathname on
`R<score>` records. Never split Git paths using tabs, spaces, or shell word
splitting. The required baseline decisions are:

| Record / transition | Baseline | Destination measurement |
|---|---|---|
| Modified/type-changed audited path | Same path at merge base | Existing `audit_loc` on working path |
| Added audited path | Absent (`-`) | Working path |
| Rename between audited paths | Old/source path at merge base | New/destination working path |
| Excluded/out-of-root source renamed into audited population | Absent (`-`), an admission to production audit | New working path |
| Rename out of audited population or deleted destination | No row | No row |
| Untracked audited path with no base counterpart | Absent (`-`) | Working path |
| Untracked path still present at base, not consumed by a rename | Existing same-path baseline, preserving current behavior | Working path |
| Untracked recreation of a rename's consumed source path | Absent (`-`); do not lend one old file to two live files | Recreated working path |

The excluded-to-audited admission rule is an explicit proposed boundary policy,
not a claim that the existing producer correctly handles it today. Review it
against the meaning of "production LOC" before implementing it.

### Shell control flow, ownership, and errors

1. Resolve and validate root/base/merge base exactly as today.
2. Capture the NUL-delimited tracked and untracked streams in a private
   `mktemp -d` workspace outside the repository; check each Git command's
   status before parsing. The refresh sibling already uses `mktemp` plus
   `trap ... EXIT` (`scripts/refactoring-audit-refresh.sh:59-63`). Do not use
   unchecked process substitution, which can conceal a failed producer.
3. Parse tracked records in the main shell. Keep only a small associative set
   of source paths consumed by recognized renames, for the source-recreation
   boundary above. Entries live for one invocation, never persist, and require
   no repository/index writes. Record origins even when the destination is
   excluded, so restoring an untracked source cannot reuse the transferred
   identity accidentally.
4. Use one internal helper, `emit_touched <base-path-or-empty> <working-path>`,
   for classification, file existence, baseline LOC, and destination LOC.
   Empty baseline means new. A promised tracked source blob that cannot be read
   is an error, not a silent new-file fallback. Untracked same-path probing
   retains the existing missing-base behavior. Reject malformed/truncated
   status records and unsupported statuses rather than skipping them.
5. Parse untracked records after the tracked stream; apply the table above.
   Preserve the existing `[ -f ]` destination guard. Do not follow rename
   chains per commit: the single merge-base diff gives the final pair directly.
6. Stage result rows until measurement succeeds, then emit them in deterministic
   C-locale destination-path order. The external line protocol still cannot
   represent whitespace-containing audited destinations; reject them loudly
   rather than turning NUL-safe input into ambiguous/multiple output rows.
   Source-only whitespace is safe when quoted for Git lookup and never emitted.
7. Clean the private temporary workspace on exit. Do not alter the Git index,
   create a commit, regenerate the heatmap, or write an acknowledgement.

This is a read-only developer command, not a concurrent snapshot guarantee.
Working-tree content changed during a probe is an existing race; no locking,
retry engine, cache, or persistent metadata is proposed. Storage is O(changed
records), plus the renamed-source set, not O(all repository source blobs).

### Scope of rename recognition

Committed and staged renames recognized by the merge-base diff are covered;
unstaged edits at their destinations still contribute working-tree LOC. A raw
filesystem move whose destination is entirely untracked is not a Git rename
record and remains conservative addition/deletion handling. Stage the move for
Git ancestry recognition. No arbitrary untracked-content matching is proposed.
Git similarity ambiguity and rename-limit behavior remain Git's responsibility;
a non-recognized rewrite is conservatively treated as an addition, not exempted.

### Other viable paths and reasons not to select them initially

- **Exact-rename-only (`-M100%`)**: smallest identity policy, but rename-plus-one-
  line growth would still look new. It does not preserve the gate's old-to-new
  threshold comparison for edited moves. Review may select it only with that
  limitation explicitly accepted.
- **Blob/content-hash matching**: can identify exact copies too, but copies are
  new modules and must not inherit a size exemption. Handling multiplicity,
  source consumption, and untracked trees is more machinery than this issue
  warrants; it still does not naturally handle rename-plus-growth.
- **Skip renamed files or grant an acknowledgement automatically**: rejected;
  a renamed file can genuinely grow from 1499 to 1500 or 1999 to 2000.
- **Change `thresholdCrossings`/`parseTouched` to guess ancestry**: rejected;
  the current three columns no longer contain the discarded old path.

### Exact implementation ownership after approval

1. `scripts/refactoring-audit-touched.sh`: replace changed-set/measurement loop
   at 100-116 and correct its header explanation at 4-10 and 34-41. Add only
   script-local parsing/measurement support needed for the contract above.
2. `pkg/refactoraudit/audit_jobs_test.go`: extend the existing real-repo fixture
   coverage; use `newFixtureRepo`, `writeFile`, `git`, `touched`, and
   `thresholdCrossings`. No parallel fixture framework.
3. `pkg/refactoraudit/audit_touched_test.go`: comments only for baseline identity
   at 31-39 and 210-215, explaining that a renamed destination's baseline can
   be its predecessor. Preserve parser and crossing signatures/logic. Parent
   must serialize this small shared-file boundary with #10487 if both land.
4. `docs/refactoring-audit.md`: update changed-set and baseline semantics in
   the touched-gate section; document tracked rename coverage and limits.

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
- **One predecessor, not copies:** an added copy and a recreated consumed
  source remain new; identical bytes alone are not proof of ancestry.
- **Population:** use the shared classifier; no local exclusion regex, raw LOC
  estimator, inline-test stripper, or additional roots.
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
| Behavioral regression | MED | Wrong rename endpoint can suppress real growth; copies, source reuse, and excluded-source admissions can inherit an improper baseline. Exercise the real script and existing predicate for every distinct boundary below. |
| Lifetime / borrow-checker | LOW | No Rust or shared ownership changes. Temporary stream cleanup and shell subshell state are the actual lifetime risks; parse in the main shell and prove failed producers cannot yield success. |
| Performance regression | LOW | This is an offline gate, but Git similarity matching and temporary I/O can add latency. Do not enable copy search or unlimited exhaustive rename search. Bound the implementation with a many-path scratch smoke; no dataplane performance claim. |
| Architectural mismatch | LOW | Fixing the producer restores already-documented author-attribution semantics and keeps its consumer/SSOT. Risk rises if the solution becomes a general file-identity engine; PLAN-KILL that expansion rather than rebuild Git. |

## 8. Test plan and acceptance evidence

### This plan round

Performed: live-source inspection, STEP-0 searches, pinned population census,
and bounded history census described above. No production or test assets were
modified. The real gate smoke, `bash scripts/refactoring-audit-touched.sh`,
exited 0 with no audited rows, as expected for this docs-only branch.
`GOCACHE=/dev/shm/gocache-10488 GOTMPDIR=/dev/shm go test -count=1
./pkg/refactoraudit/` was also run; it failed in the unrelated existing
`TestStructMetricIsTypesNotFields6937` calibration assertion
(`CompileResult`: 32 fields, 21 types, while the test expects it to be just
under the 20-type floor). This plan-only documentation diff cannot affect that
Go test; the failure remains a parent validation gap. No Cargo build, formatter,
linter, project-wide suite, cluster, Incus, or provider/companion reviewer
command was run. The final document check must require all eleven sections,
at least five distinct review questions, consistent census arithmetic, and only
the owned plan in the staged file set.
The documentation-only shell probe should exit 0 with zero audited rows; that
is not evidence that an unimplemented rename fix works.

### After parent approval: permanent regression cases

Reuse `fixtureRepo` to execute the real shell producer, then feed its rows into
`thresholdCrossings`. Require the destination row and its measured LOC, not
just an empty crossing list: silently dropping a rename is not a fix.

| Case | Required observable result / plausible defect caught |
|---|---|
| Committed pure `1701 -> 1701` rename | One destination row, base 1701, not new; no crossing. Catches destination-only base lookup. |
| Staged pure `2100 -> 2100` rename with `diff.renames=false` | Same contract, no crossing. Catches relying on user rename configuration and losing the higher-band baseline. |
| Recognized rename plus `1499 -> 1500` working-tree growth | Exactly WATCH at the destination, base 1499. Catches skipping all renames or measuring HEAD instead of the working tree. |
| Recognized rename plus `1999 -> 2000` growth | Exactly REFACTOR at the destination, base 1999. Catches stale destination counts or a blanket rename exemption. |
| One source retained plus an added 1701-line copy, with `diff.renames=copies` | Copy is new and WATCH; retained source is not its baseline. Catches copy-detection config leaking into identity policy. |
| Staged rename followed by untracked recreation of its old 1701-line path | Renamed destination does not cross; recreated old path is a new WATCH crossing. Catches lending the same base to two files. |
| Same-path untracked restoration after removal from index, without a rename | Preserve the current same-path base comparison, not an unconditional new-file classification. |
| Excluded 1701-line source renamed into audited production; reverse direction | Admission is new WATCH; move out is omitted. Catches classification of the wrong endpoint. |
| Two-step committed rename from original to intermediate to final | Use merge-base original LOC and emit only final destination. Catches HEAD-only ancestry reconstruction. |
| Audited destination containing whitespace; truncated/failed Git producer | Nonzero failure, not dropped source or a successful empty set. Catches delimiter and process-substitution mistakes. |

Keep focused tests only where a plausible bug changes the observed result.
Use Git's actual status output as a fixture precondition for rename cases;
assert script/decision behavior, never the source text or exact diagnostic prose.
Do not edit the existing gate, thresholds, acceptance file, or fixtures merely
to make a candidate pass. Keep existing local-branch, untracked-growth,
undeterminable-base, crossing-boundary, and acknowledgement tests unchanged.

Proposed post-implementation commands (the package command above was a
pre-change baseline attempt and must be rerun after any approved code change):

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
symbol. Require the pure-rename regression to fail against the old producer and
pass against the replacement; require real-growth controls to remain failing
crossings in both versions. In a separate throwaway repository, run the actual
CLI for a rename and a renamed threshold-crossing control and inspect the rows
and exit status. Also use a many-path scratch diff to check that the new
identity plumbing does not accidentally scan/hash every repository source file.

The parent owns the full integration gate once sibling work has landed. Cargo,
IPv4/IPv6 throughput, per-class CoS, and HA smoke do not discriminate this
shell-only defect; no fabricated old fixed suite counts or network results are
claimed. Any campaign-mandated deployment smoke is parent-sequenced later,
never part of this worker's plan-only round.

## 9. Out of scope

- Production implementation, test edits, PR creation, review dispatch, or merge
  in this round; delivery is a committed/pushed plan only.
- Changing either LOC threshold, band-growth policy, accepted-crossing policy,
  global heatmap freshness, shared classifier, or raw LOC definition.
- Parser numeric-domain hardening owned by #10487. Any shared comment edits are
  parent-integrated, not concurrent competing replacements of its file.
- Untracked-content ancestry discovery, persistent rename manifests, copy
  detection, content-hash indexes, or reconstructing per-commit rename chains.
- Widening the external row protocol to support whitespace filenames. Reject
  such audited destinations; a new escaped/NUL/structured API is separate work.
- Revalidating the unavailable 400-commit historical census, fetching shared
  history, or asserting that this clone's zero observed renames prove no impact.
- Rust/Go product refactoring, CI/Makefile edits, cluster access, performance
  telemetry, or mandatory large-file splits unrelated to the reported gate.

## 10. Open questions for adversarial review

1. **Identity policy:** is Git's normal `-M` similarity the right predecessor
   contract, or should this narrowly guarantee only exact renames? PLAN-KILL
   the selected approach if heuristic ancestry weakens the growth gate.
2. **Audit-population admission:** should moving excluded/generated/test content
   into an audited path begin at zero, as proposed, or inherit its physical LOC?
   Reject this boundary policy if it contradicts the actual production-audit
   contract; do not silently approve the extra behavior.
3. **Untracked moves:** does acceptance require a raw filesystem move before
   `git add` to be recognized? If yes, the selected Git-record-only remedy is
   insufficient; return PLAN-NEEDS-MAJOR or PLAN-KILL rather than pretend it
   covers content-matched untracked destinations.
4. **Multiplicity:** can a source survive through another tracked/untracked
   path, an ambiguous identical-file pair, or a split/copy that lends its old
   baseline twice despite the consumed-source rule? Reject if the design hides
   a genuinely new large module.
5. **Failure propagation:** are materialized input/output streams and main-shell
   origin bookkeeping proportionate, or can a simpler checked pipeline retain
   every error and source-reuse invariant? PLAN-KILL needless machinery; never
   replace it with a success-looking empty set on Git failure.
6. **Filename boundary:** is preserving the three-field fail-closed protocol
   preferable to an interface migration? If audited whitespace filenames must
   work, this plan needs a separate consumer contract, not just `-z` on Git.
7. **Cost and scope:** does enabling explicit rename matching under a user's
   disabled configuration create unacceptable tooling latency on large diffs?
   What concrete measured bound would justify choosing exact-only detection?
8. **Evidence strength:** do the tests distinguish correct predecessor LOC from
   silently skipping renamed files, and do edited-rename controls still cross
   both exact floor boundaries? Reject any validation that observes only green.
9. **Value:** given 80 susceptible large files but no verified incident rate in
   available history, is a four-file remedy still the right small intervention?
   PLAN-KILL the approach if its maintenance cost exceeds correcting attribution;
   preserve #10488's defect evidence rather than calling a rejected plan a fix.
