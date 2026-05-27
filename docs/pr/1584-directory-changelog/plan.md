# #1584 — Directory-based changelog architecture

## Status

DRAFT v1 — pending adversarial plan review (Codex + AGY hostile;
Claude SMR + Gemini-Pro-3 secondary).

## Issue framing

`_Log.md` is a flat chronological-append file. Every PR appends entries
to the tail. Parallel PRs landing in close succession produce trivial
3-way merge conflicts on identical-region tail appends. In this session
alone we hit ~19 rebase declines from `_Log.md` conflicts during Waves
2-3 of the refactor backlog.

PR #1582 attempted to fix this with a `merge=union` gitattribute. AGY
PLAN-KILLED that approach because git's union driver performs LCS-based
dedup on identical adjacent lines — when two PRs both append
`- **HH:MM UTC** — ...` lines with overlapping content, union can
silently drop one side. The corruption is undetectable post-merge.

Issue #1584 (per AGY's recommendation) proposes the alternative: each
PR writes to a unique file under `_Log/PR-<N>.md`. Zero possibility of
git conflict; zero risk of silent LCS dedup.

## Honest scope/value framing

Pure process-improvement refactor; no runtime impact. The value is
operator-side — eliminating a class of rebase friction that currently
costs ~5 min sub-agent re-engagement + ~30s smoke-runner re-poll per
collision, multiplied by the ~30 PRs still in flight across Waves 3-5.
Estimated total cost at current rate: ~3 hours of wall-clock drag.

If reviewers conclude that the migration cost + grep/tooling-break
risk outweighs the rebase-friction savings, **PLAN-KILL is an
acceptable verdict**. The fallback is the carry-forward fast-path in
`feedback_smoke_serialized_single_agent` §5 which already handles
`_Log.md`-only conflicts via the post-marker comment-only delta
exception.

## Concrete design

### Directory layout

```
BEFORE                       AFTER
_Log.md  (4684 LOC flat)     _Log/
                             ├── README.md          (convention doc)
                             ├── PR-1325.md         (one section per PR)
                             ├── PR-1326.md
                             ├── PR-1331.md
                             ├── ...
                             └── PR-1584.md         (this PR)
```

Naming: `_Log/PR-<N>.md` where `<N>` is the closing PR number.
Lowercase `_Log/` matches the existing `_Log.md` prefix.

### Per-PR file format

Identical body schema as today's `## 2026-MM-DD — #N` section, but
hoisted into a file. The current top-level section heading becomes
the H1 of the new file:

```
# PR-1584 — Adopt directory-based changelog architecture

## 2026-05-26 23:55 UTC — plan drafted

- **23:55 UTC** — worktree created at refactor/1584-directory-changelog
  off origin/master
- **23:56 UTC** — wrote docs/pr/1584-directory-changelog/plan.md
- ...

## 2026-05-26 23:59 UTC — implementation

- ...
```

Each entry inside the file keeps the existing bullet schema
(`- **HH:MM UTC** — ...`) so existing skills and `grep` patterns over
log bodies continue to match. The only change is the *file boundary*.

### Migration (backfill of existing `_Log.md`)

One-shot Python script `scripts/migrate_log_to_dir.py` runs as part of
this PR's commit. The script:

1. Parses `_Log.md` top-level `^## ` sections.
2. For each section, extracts the PR number from the heading (regex
   `#(\d+)`), routing:
   - Section that names exactly one `#N` → `_Log/PR-N.md`.
   - Section that names multiple `#N` (rare; e.g. a Wave roll-up) →
     `_Log/PR-N.md` for the FIRST `#N` (with a `Cross-ref:` line for
     each additional `#N`).
   - Section that names NO `#N` (date-only heading, used for
     standalone-session journal entries) → `_Log/MISC-YYYY-MM-DD.md`,
     appended if file already exists for that date.
3. Preserves verbatim section body (no formatting normalization, no
   re-wrapping, no dedup).
4. Writes a manifest `_Log/MANIFEST.md` mapping old `## ` heading →
   new file path, so any external link to a section can be rewritten
   mechanically.
5. Verifies losslessness by reconstructing a single-file view and
   diffing against the original ignoring header-line shifts.
   Reconstruction script is `scripts/render_log_dir.py` (also added
   in this PR — see Tooling below).

### Tooling

- `scripts/render_log_dir.py`: cats `_Log/PR-*.md` and
  `_Log/MISC-*.md` in chronological order (parsed from the first
  `## 2026-MM-DD ...` timestamp in each file). Emits a single
  human-readable view to stdout. NOT committed to disk by default —
  this is the "read the log" tool, replacing `less _Log.md`.
- `Makefile` target `log-view`: invokes the renderer with a sensible
  pager. `make log-view` → `python3 scripts/render_log_dir.py | less`.
- Optional `log-check` target: validates that every committed
  `_Log/PR-*.md` references a real PR number that exists on
  GitHub (sanity gate for the convention; not blocking).

### Fate of flat `_Log.md` (decision: freeze + redirect)

Three options were considered:

- **(a) Delete `_Log.md`** and put a README in `_Log/` explaining the
  redirect.
- **(b) Freeze `_Log.md` as historical**, truncate at the migration
  cut-over commit, leave it in place as read-only history. New
  entries go to `_Log/` only.
- **(c) Auto-generate `_Log.md` from `_Log/` on every commit** via
  pre-commit hook.

**Recommended: (b) freeze.** Rationale:

- (a) breaks `git log -p _Log.md` history continuity for anyone
  spelunking with `git blame` / `git log`. The file's existing
  ~4700-line history is valuable archaeology.
- (c) reintroduces an append-side conflict surface — the
  auto-generated `_Log.md` would itself be a parallel-PR conflict
  hazard, exactly the bug we're fixing. Even gitattribute-ignoring
  it doesn't help because the post-commit hook *writes* to the
  worktree, not to the index.
- (b) preserves the historical record, doesn't reintroduce the
  conflict, and lets future grep-the-log uses transition gradually.
  After this PR lands, `_Log.md` ends with a "FROZEN — see `_Log/`
  for entries after $CUT_OVER_COMMIT" footer. The CUT_OVER_COMMIT
  is this PR's own merge commit.

### CLAUDE.md Logging Rules update

Diff against `CLAUDE.md` line 35:

```
-- Maintain a log of all major actions in `_Log.md`.
++ Maintain a log of all major actions in `_Log/PR-<N>.md`, where
++   `<N>` is the GitHub PR number this branch will close. Historical
++   entries before the directory-changelog migration live in the
++   frozen flat `_Log.md` — do not append new entries there.
```

Also update line ~40 (the `[Write|Edit]` action log line):

```
-- Log every `[Write|Edit]` action.
++ Log every `[Write|Edit]` action in `_Log/PR-<N>.md`.
```

## Public API preservation

N/A — pure tooling/doc change. No code surfaces affected.

## Hidden invariants the change must preserve

1. **Lossless history.** Every byte of every existing `_Log.md`
   section must end up in a `_Log/PR-*.md` or `_Log/MISC-*.md` file.
   The migration script verifies by reconstruction-diff.
2. **`git log -p _Log.md` archaeology.** The frozen `_Log.md` stays
   in tree; its commit history is unbroken.
3. **External links.** A handful of `docs/pr/*/plan.md` and
   `docs/issues/pr-history.md` files reference `_Log.md` literally
   (~40 hits). These references are historical pointers; they should
   stay valid because `_Log.md` still exists (frozen). New text
   should reference `_Log/PR-<N>.md` instead.
4. **Skill compatibility.** Skills under `.claude/skills/` (notably
   `triple-review`, `merge-prs`, `review-pr`, `sync-history`,
   `failover-test`) may grep `_Log.md`. Audit each in the
   implementation step before claiming compatibility.
5. **Memory-file references.** `feedback_smoke_serialized_single_agent`
   §5 references `_Log.md` literally in the carry-forward narrow-delta
   rule. The rule says: if `git diff marker-SHA..HEAD --name-only` is
   "only `*.md` / `_Log.md` / docs". This rule must extend to
   `_Log/*.md` paths. Either update the memory file in a follow-up,
   or rely on the `*.md` glob already covering `_Log/PR-*.md`.

## Risk assessment

| Class | Level | Notes |
|-------|-------|-------|
| Behavioral regression | NONE | No runtime code touched. |
| Lifetime / borrow | NONE | No Rust changes. |
| Performance | NONE | Doc/tooling only. |
| Architectural mismatch | LOW | Directory-per-aspect matches `feedback_refactor_module_dir_layout` convention; this is the analogous "directory-per-PR" rule for changelogs. |
| Migration correctness | MED | Backfill script must be lossless. Mitigated by reconstruction-diff verification step in the script itself. |
| In-flight branch breakage | MED-HIGH | See "Backward compatibility" below. |
| Grep / sub-agent muscle-memory | LOW-MED | Skills + memory entries reference `_Log.md` literally; need audit + update. |

## Backward compatibility — in-flight PRs

This is the load-bearing concern.

At the time of writing there are ~30 in-flight refactor PRs across
Waves 3-5. Each has commits that *modify `_Log.md`* (chronological
appends). When #1584 lands, those PRs will:

1. Conflict on `_Log.md` (because we're about to freeze it with a
   final footer — every other in-flight branch will have appended
   past that frozen point).
2. Have no `_Log/PR-<N>.md` file because they were authored before
   the convention existed.

**Mitigation plan (timing-coordinated landing):**

1. **Land #1584 only AFTER the current Wave-3 batch drains.** The
   `smoke-runner-batch` queue has ~12 PRs pending merge. Wait until
   queue depth ≤ 3.
2. **Rebase sweep:** after #1584 merges, each remaining in-flight
   branch's owner (or smoke-runner singleton) does a one-time
   rebase:
   - Drop the branch's `_Log.md` chronological-append delta.
   - Create `_Log/PR-<N>.md` with the branch's entries hoisted into
     the new file.
   - Force-push the rebased branch.
3. **Tooling:** `scripts/rebase_log_to_dir.sh` automates step 2 for
   a given branch+PR number. Single-command per branch.
4. **Tracking:** `docs/pr/1584-directory-changelog/in-flight-rebase-list.md`
   enumerates the branches that need the rebase. Each entry struck
   through when the rebase lands.

**If the rebase sweep is too painful:** an alternative is a
landing-time temporary shim — keep `_Log.md` *unfrozen* for one more
week, allow existing branches to keep appending, and only freeze
once queue depth → 0. Decision deferred to plan-review; both options
are viable.

## Test plan

This is a docs-only PR — no Rust, no Go, no smoke matrix.

- [x] `git status` clean before commit
- [x] `scripts/migrate_log_to_dir.py` runs without error on the
  current `_Log.md` (verify on a copy first)
- [x] `scripts/render_log_dir.py` output diffs against the
  pre-migration `_Log.md` ignoring header-line shifts (i.e. content
  preserved verbatim)
- [x] Spot-check: 3 random `_Log/PR-*.md` files have their original
  section bodies verbatim
- [x] `make log-view` runs cleanly
- [x] `cargo build` clean (sanity check — no Rust changed)
- [x] `make test` clean (sanity check — no Go changed)
- [x] `grep -rn "_Log\.md" --include='*.md'` audited; remaining
  references are intentional historical pointers
- [x] **Skip smoke matrix per docs-only-skip-smoke scope.** Per
  Wave-3 protocol, docs-only PRs can skip the loss-cluster smoke
  via `<!-- AWAITING-BATCH-MERGE -->` marker (scope:
  `refactor-batch-no-per-pr-smoke`).

## Out of scope (explicitly)

- Rewriting historical `_Log.md` history (we freeze, not rewrite).
- Migrating `docs/issues/pr-history.md` to a directory layout. That
  file is generated by `sync-history` skill; out of scope here.
- Auto-generating `_Log.md` on commit (option c above; rejected).
- Per-PR file size policing or rotation. PR files are small (~50-200
  LOC); no concern.
- Backfilling sections that name multiple PRs into multiple files
  (we route to first `#N` + cross-refs).
- A pre-commit hook that auto-creates `_Log/PR-<N>.md` from branch
  name. Nice-to-have; defer to follow-up if requested.

## Open questions for adversarial review

1. **Is the backward-compat / in-flight rebase plan realistic?**
   The Wave-3 queue has ~12 PRs pending merge. Forcing each to do a
   `_Log/PR-<N>.md` rebase is non-trivial coordination overhead. Is
   the freeze-after-queue-drains approach sound, or should we
   reverse the order — keep `_Log.md` unfrozen indefinitely as a
   redirect target while new entries are dual-written?
2. **Is the migration script's PR-routing heuristic sound?** Some
   `## ` sections name multiple `#N` (Wave roll-ups), some name
   zero `#N` (date-only journal entries). The proposed routing
   (first `#N`, else `MISC-DATE.md`) may misattribute roll-up work.
   Should we instead route by branch context (read `git log --grep`
   to find the closing commit's PR)?
3. **Does freezing `_Log.md` actually break archaeology?** `git log
   -p _Log.md` continues to work on the historical content. But
   future searches that grep both old + new will need to grep
   `_Log.md` AND `_Log/*.md`. Is that an acceptable cost?
4. **Should the `_Log/` directory be promoted to top-level
   `Log/` (no leading underscore)?** Underscore-prefixed dirs are
   sometimes hidden by tools (e.g. mkdocs). Counter-argument:
   `_Log.md`'s underscore prefix is already the convention; keep
   it for continuity.
5. **Does the `merge=union` PLAN-KILL analysis fully transfer?**
   Union dedups identical adjacent tail lines. Could a
   directory-based approach *still* hit a conflict if two PRs both
   create the same filename (e.g. both target the same numbered
   PR)? Filename collisions would be a hard 3-way conflict (both
   add the same path) — louder than silent dedup, but still a
   conflict. Mitigation: PR number is uniquely allocated by GitHub
   before the branch exists, so two PRs never share a number;
   collision is structurally impossible.
6. **Tooling discoverability.** If no one runs `make log-view`,
   does the directory layout regress operator UX vs `less _Log.md`?
   Counter: `cat _Log/PR-*.md | less` is the same key count.
7. **Is the "freeze" footer-edit on `_Log.md` itself a
   parallel-PR-conflict hazard?** This PR appends a footer to
   `_Log.md` at the same moment it stops being the append target.
   If another PR is concurrently appending the chronological-tail
   entry, we collide once more. Mitigation: land #1584 during
   queue-drain (queue depth ≤ 3, no other PR is mid-rebase against
   master).
8. **Does the convention need to extend to `_Log/MISC-YYYY-MM-DD.md`
   collisions?** Two parallel non-PR sessions on the same date
   would both want `_Log/MISC-2026-05-26.md`. Less common (most
   work is PR-scoped) but possible. Mitigation: append-mode write
   in the renderer is fine; for now the convention is that
   non-PR work appends to the dated MISC file (with bullet-level
   timestamping for serializability — same risk class as the
   original flat file, but now scoped to MISC entries only, which
   are rare).
