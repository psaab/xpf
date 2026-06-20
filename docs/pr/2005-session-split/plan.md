# Plan of Action — #2005: split `userspace-dp/src/session/mod.rs` into lookup/install/expire

**Status: PLAN-KILL (already shipped).** The refactor this issue asks for is
already implemented and merged on `origin/master` as **PR #2028**
(`#2005: split session/mod.rs into lookup/install/expire`, merged
2026-06-19T06:24:30Z, merge commit `7b01afeb5`). Issue #2005 is still in the
`OPEN` state only because the auto-close did not fire. This document records the
research that established that fact, audits whether the merged work actually
discharged the high-risk hot-path codegen concern the issue raised, and
recommends closing #2005 rather than opening a duplicate refactor PR.

This is a companion-free plan-drafting pass (no Codex, no AGY). No production
source was changed. The hostile self-review is in
`docs/pr/2005-session-split/claude-smr-plan-r1.md`.

---

## 1. Problem statement / scope

The issue (`agy-review-013 Part II.4`) targets the core conntrack fast-path
module `userspace-dp/src/session/mod.rs`. At the LOC the issue was filed against
(`b1ef3ed16`) it was 1604 LOC and the issue asks for a behavior-preserving,
code-motion-only split into:

```
userspace-dp/src/session/
  mod.rs       # conntrack-table coordinator
  lookup.rs    # forward/reverse tuple match logic
  install.rs   # install flow + capacity limits
  expire.rs    # timer-wheel sweeps + eviction
```

The issue itself flags this as **HIGH-RISK** because `session/mod.rs` is the
per-packet hot path and carries the #1752/#1855 in-place-refresh contract
(single-writer `&mut self`, eager #964 cleanup, secondary-index re-assert
parity). The split must preserve those invariants byte-for-byte and must not
perturb hot-path codegen.

**Scope of THIS research:** decide whether a new plan/PR is warranted. It is
not — the work exists, merged, and matches the suggested layout exactly. Scope
therefore narrows to *verification of the shipped work* and a close
recommendation.

## 2. Current state on `origin/master` (post-#2028)

`git log --oneline -- userspace-dp/src/session/` on the worktree base
(`9979a89a0`, which descends from merge `7b01afeb5`):

```
2d397c372 #2005: make the last expire.rs invariant comment field-agnostic
1b2b9fdf1 session: fix stale/inaccurate comments in #2005 split files
452af364c #2005: document the session/ submodule split in the README
04bb75ebb #2005: extract install flow + capacity limits into session/install.rs
d8ed334b9 #2005: extract forward/reverse tuple match into session/lookup.rs
d118c1006 #2005: extract timer-wheel sweeps/eviction into session/expire.rs
```

Resulting layout (verified with `wc -l`):

| File | LOC | Owns |
|------|-----|------|
| `mod.rs` | 918 | `SessionTable` coordinator: slab + `FxHashMap` secondary indices + delta queue + the #1752/#1855 in-place-refresh contract (`update_session` / `refresh_for_ha_transition` + secondary-index re-assert + #964 eager-cleanup `remove_entry`/`index_*`) |
| `lookup.rs` | 239 | forward/reverse tuple match read path: `lookup` family, NAT/wire reverse finders, read accessors, `take_synced_local` |
| `install.rs` | 311 | session-creation: #1861 capacity preflight (`can_admit`) + counters, new-flow installs (`install_with_protocol*` / `upsert_synced*`), delta-emit / `delete` / `demote_owner_rg` |
| `expire.rs` | 212 | timer-wheel sweeps + eviction: `expire_stale_entries`, `push_to_wheel`, `wheel_observe` |

`mod.rs` is **918 LOC**, down from 1604. That is comfortably under the project's
informal modularity threshold (peer refactors #1986–#1990 / #2003 target
~<1000–1500 LOC per file). The supporting files (`key.rs`, `entry.rs`, `ctx.rs`,
`wheel.rs`) were already separate and are untouched by the split.

`README.md` was updated in the same PR to document the four-way split, the
in-place-refresh contract location, the #1861 admission boundary, and the #1870
uncapped-sync family. The README is the module-contract doc the CLAUDE.md rules
require, so the documentation obligation is also discharged.

## 3. The suggested layout vs. what shipped

Exact match. The merged PR uses the issue's proposed `mod.rs / lookup.rs /
install.rs / expire.rs` filenames and the exact functional boundaries the issue
described (tuple-match → lookup; install flow + capacity limits → install;
timer-wheel sweeps + eviction → expire; coordinator state + in-place-refresh
contract stays in mod.rs). There is no deviation that would justify a
re-do.

## 4. Hot-path codegen risk class — the real bar, and how #2028 cleared it

This is the section the issue and the research brief care about most. The
project has been bitten by codegen regressions on this exact dataplane
(`__rust_probestack` frames in the CoS hot path, #1755; the fused MQFQ
select/pop double-scan, #1763). So "it compiles and tests pass" is **not**
sufficient evidence for a hot-path split. The question is whether the split can
perturb inlining, per-packet allocation, or borrow shapes.

### 4.1 Why a same-crate module split is codegen-neutral *in principle*

Rust modules are a pure **namespacing / visibility** construct. The compiler
operates on the whole crate; module boundaries are erased before MIR/codegen.
Cross-module inlining within one crate is therefore identical to
intra-module inlining — there is no separate translation unit, no
link-time-only inlining dependency, no `extern` boundary. (This is unlike C/C++
translation units or unlike a *new crate*, which would introduce a real
codegen boundary and force `#[inline]` / LTO considerations. #2005 explicitly
does NOT create a new crate — it adds submodules to the existing `session`
module of the existing `userspace-dp` crate.)

Concretely, the split moved `impl SessionTable { ... }` method blocks into
sibling files (verified: `mod.rs` 2 impl blocks, `expire.rs` / `install.rs` /
`lookup.rs` 1 each). The methods remain methods on the same type in the same
crate. The optimizer's view of them is unchanged.

### 4.2 How #2028 *proved* (not just asserted) codegen neutrality

The merged PR body and the commit history show the following safeguards, which
are exactly the discipline this research would have prescribed:

- **Body-level byte-identity.** PR claims a function-body diff against the
  pre-split `mod.rs` shows every moved body is byte-identical; the only change
  to a moved function is the one signature line on `push_to_wheel` (see below).
  This is reconstructable from git: `git show d118c1006`, `d8ed334b9`,
  `04bb75ebb` are the three extraction commits and can be diffed move-for-move.
- **`#[inline]` attributes preserved across the move.** Verified on the merged
  tree: `expire.rs` carries `#[inline]` on its moved methods (lines 30, 49),
  `install.rs` on lines 44/198, `mod.rs` retains its `#[inline]` set, and
  `wheel.rs` is untouched. No `#[inline]` was dropped or added, so the inliner's
  hint set is unchanged. Note `#[inline]` is a *hint*, not a guarantee —
  preservation is necessary but not sufficient; the actual inline decision is
  confirmed by the §6.1/§6.2 symbol check.
- **Exactly one visibility widening, minimal scope.** `push_to_wheel` went from
  private `fn` to `pub(in crate::session)` — the absolute form that preserves
  the original "visible to the whole `session` module tree" scope rather than
  narrowing it. Required because the retained in-place-refresh contract in
  `mod.rs`, the `install`/`lookup` submodules, and the test oracle all call it
  across the new boundary. Visibility does not affect codegen; it only affects
  what the borrow/name resolver permits. No `pub` was widened to crate or public
  beyond what the existing `pub(crate) SessionTable` already exposed.
- **The #1752/#1855 in-place-refresh contract stays in `mod.rs` untouched.**
  `update_session`, `refresh_for_ha_transition`, `refresh_local`,
  `refresh_for_ha_activation`, the secondary-index re-assert, and the #964
  eager-cleanup `remove_entry` all remain in `mod.rs`. The single-writer
  `&mut self` discipline is unchanged — no method signature gained or lost
  `&mut` / `&` in the move, so borrow shapes (and thus the per-packet aliasing
  model the optimizer relies on) are identical.
- **No new allocation.** The split is method relocation only; no `Vec`/`Box`/
  `String` was introduced on a moved hot path. (The hot read path —
  `lookup` family — and the per-tick GC sweep — `expire_stale_entries` — are
  the per-packet / per-second hot loops; both moved as-is.)

### 4.3 What #2028's validation already covered

From the PR record:

- `cargo build --release` clean; `cargo test --release` 2128 tests, session
  module 78/78; 5× flake run 5/5 green.
- The fused-diff / in-place oracle suite (`inplace_*_matches_reference`,
  incl. `inplace_randomized_sequence_matches_reference` and the
  displaced-collision-reassert tests) passes — this is the behavior-preservation
  proof for the in-place-refresh contract, exactly the "`fused_diff_tests`-style
  oracle" the issue asked the split to gate on.
- Public API of `crate::session` unchanged.

### 4.4 Residual codegen-proof gaps in #2028 (audit findings)

Two gaps are worth recording, but neither warrants a re-do — they are at most
*post-merge confirmation chores*, not defects:

1. **No symbol-level (objdump/nm) before/after diff is recorded in the PR.**
   The PR proves source byte-identity and test parity but does not attach a
   `nm`/`objdump` symbol-presence or `perf annotate` comparison of the
   pre-split vs post-split release binary. For a hot path with this project's
   history (#1755 used the local release binary's `objdump` as the codegen
   proof), that is the gold-standard artifact. It is *missing*, not
   *contradicted* — and the theory in §4.1 says the diff would be empty.
2. **No lab smoke iperf3 result is attached to the merged PR.** The PR body
   says "NEEDS LAB SMOKE: loss userspace cluster iperf3 + full quad review
   before merge", but the merge happened (campaign-owner queued). Whether the
   smoke ran before or after merge is not recorded in the PR body.

These gaps are the entirety of what a fresh plan could add, and both are
cheap confirmation steps — see §6.

## 5. Recommendation

**PLAN-KILL.** Do not author a new refactor PR for #2005. The split is shipped
in #2028, matches the issue's suggested layout exactly, preserves the
high-risk in-place-refresh contract in `mod.rs`, preserves all `#[inline]`
hints, introduces no new allocation, and was validated by the in-place oracle
suite plus the full test run. Re-doing it would be pure churn on the hottest
module in the dataplane — exactly the risk the issue warns against.

The correct disposition is administrative: **verify the residual confirmation
chores (§6) and close #2005 as completed-by-#2028.**

## 6. Recommended pre-close confirmation (read-only; no production source change)

These do not change production source; all are read-only verification. They
upgrade #2028's already-strong *behavior-parity* evidence (the oracle proves
results are unchanged) to *cost-parity* evidence (proving codegen/pps were not
regressed). That distinction matters here specifically because this repo has
been bitten by behavior-identical-but-cost-regressed changes on this exact
dataplane (#1755 probestack frames, #1763 double-scan). Items 1–2 are therefore
**recommended as a pre-close gate, not optional**; item 3 is **required if it
was not already run for #2028** (this module is on the session-sync/failover
path, a hard CLAUDE.md gate).

1. **Symbol-presence + frame check (cheap, local — recommended gate).** Build
   the merged-tree release binary and the pre-split parent (`d118c1006^`)
   release binary, then `nm --defined-only` / `objdump -d` the `SessionTable`
   methods. Compare on (a) **no new `__rust_probestack`** in `session::*`,
   (b) hot methods still present / still inlined where they were, (c) no
   surprise large stack subtraction. Do **not** demand raw byte-identity of the
   whole `.text` — the inliner legitimately renames/merges anonymous symbols and
   reorders across a code move even when cost is identical (#1755 method: the
   local release binary's `objdump` is the codegen proof; live `perf annotate`
   over `incus exec` returns empty without a TTY).
2. **Body/receiver eyeball (cheap, local — recommended gate).**
   `git show d118c1006 d8ed334b9 04bb75ebb` and confirm each moved `fn` line is
   identical modulo the single documented `push_to_wheel` visibility widening —
   in particular that no receiver flipped `&self` ↔ `&mut self` and no
   `clone`/alloc was introduced (either would pass the behavior oracle yet
   change cost / aliasing). This converts the "body byte-identical" claim from
   second-hand (PR body) to first-hand.
3. **Smoke iperf3 + failover on the loss userspace cluster — required if not
   already run for #2028.** Sustained `iperf3 -t 30` both directions, v4 + v6,
   to `172.16.80.200` / `2001:559:8585:80::200`, confirming line-rate and zero
   periodic stalls; **plus `make test-failover`** (this module is on the
   session-sync/failover path, so the CLAUDE.md failover gate applies — a
   code-motion split of it is exactly the kind of change that gate exists for).
   Memory lesson: verify throughput with sustained iperf3 through the real DUT,
   never curl/http=200.
4. **Close #2005** referencing #2028 once 1–3 are satisfied. If the campaign
   owner explicitly accepts behavior-parity as sufficient for a same-crate
   code-motion split and confirms #2028's smoke/failover already ran, close
   immediately.

## 7. Files / surfaces (reference map of the shipped split)

- `userspace-dp/src/session/mod.rs` (918) — `SessionTable` coordinator +
  in-place-refresh contract (#1752/#1855) + #964 eager-cleanup.
- `userspace-dp/src/session/lookup.rs` (239) — read path / tuple match.
- `userspace-dp/src/session/install.rs` (311) — install + #1861 capacity
  preflight + #1870 uncapped-sync family.
- `userspace-dp/src/session/expire.rs` (212) — timer-wheel sweep / eviction;
  the lone `pub(in crate::session)` widening (`push_to_wheel`).
- `userspace-dp/src/session/{key,entry,ctx,wheel}.rs` — pre-existing, untouched.
- `userspace-dp/src/session/tests.rs` — co-located tests; gained
  `use super::wheel::{FAR_FUTURE_OFFSET, WHEEL_BUCKETS, WHEEL_TICK_NS}` (same
  symbols previously reached via mod.rs's trimmed glob).
- `userspace-dp/src/session/README.md` — module contract doc, updated by #2028.

## 8. Risks of the recommended action (closing, not re-doing)

- **Risk: the merged split silently regressed codegen and nobody measured it.**
  Mitigation: §6.1/§6.2 give a cheap local confirmation. The structural
  argument (§4.1) plus preserved `#[inline]` plus the oracle suite make a
  regression very unlikely, but the symbol check removes all doubt at near-zero
  cost. This is the only residual risk and it is bounded and cheap to retire.
- **Risk: closing #2005 hides a still-open follow-up.** Mitigation: there is no
  open follow-up; #2028 also folded the README update and comment cleanups
  (`1b2b9fdf1`, `2d397c372`). Nothing dangles.

## 9. Validation performed by THIS research pass

- `gh issue view 2005` → OPEN, title matches; source LOC pinned to stale
  `b1ef3ed16`.
- `gh pr list --search 2005` → PR #2028 MERGED 2026-06-19T06:24:30Z,
  head `refactor/2005-session-decompose`.
- `git log -- userspace-dp/src/session/` on worktree base shows the six #2005
  commits; `git merge-base --is-ancestor 04bb75ebb HEAD` confirms the split is
  in the current master line.
- `wc -l` on the four files confirms mod.rs = 918 (was 1604) and the
  lookup/install/expire LOC above.
- `grep -rn '#[inline'` confirms `#[inline]` preserved on moved hot methods in
  `expire.rs` / `install.rs` and retained in `mod.rs`; `wheel.rs` untouched.
- `grep -n 'pub(in crate::session)'` confirms `push_to_wheel` is the only
  visibility widening.
- `grep -c 'impl SessionTable'` confirms the impl-block-split idiom (the
  codegen-neutral pattern) was used.
- README read confirms the module-contract doc was updated in-PR.
- No production source modified by this pass; worktree
  `research/2005-session-split` off `origin/master`.

## 10. Open questions for the campaign owner

1. Accept the existing oracle-suite + test-parity evidence and close #2005
   immediately, or run the §6.1/§6.2 symbol confirmation first?
2. Was the loss-userspace-cluster smoke + `make test-failover` actually run for
   #2028 before merge? If not, run §6.3 before closing, since this module sits
   on the session-sync / failover path.

## 11. Decision record

- **Verdict: PLAN-KILL — duplicate of merged PR #2028.**
- **Rationale:** the requested split already exists on master, matches the
  suggested layout exactly, and cleared the hot-path bar (in-place-refresh
  contract kept in `mod.rs`, `#[inline]` preserved, impl-block code-motion only,
  in-place oracle suite green). Re-authoring it would add churn and codegen risk
  to the dataplane's hottest module for zero modularity gain.
- **Action:** verify the cheap residual confirmation chores in §6 (optional),
  then close #2005 referencing #2028. No new PR.
