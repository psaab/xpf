## Status

DRAFT v4 — incorporates round-3 review feedback (Codex PLAN-NEEDS-MINOR with 6 additional ordering invariants I missed + a bad line citation; Gemini PLAN-READY with strong round-2 calibration autopsy).

### v4 changes vs v3

1. **Expanded the ordering-invariants enumeration from 6 to 11.**
   Codex round-3 correctly caught that the 6-item list missed
   critical pass/fail-affecting constraints. Added:
   - CoS override block at L686-726 (mutates
     `distribution_a_i` + forces `iface_filter_active = true`;
     must precede all downstream computation; preserves
     `binding_distribution_a_i` for the CoS sum guard)
   - `n_iperf_streams` derivation at L815-819 (prefers
     `connected[].len()` over `num_streams`)
   - Stream-count chain at L820-826 (`n_non_starved`, `dir_mult`,
     `expected_sum` order; uses POST-CoS `iface_filter_active`)
   - Conditional overcount trim at L837-841 (only when
     `a_i_delta > 0 && a_i_sum_check_ok`; not unconditional)
   - **Dual Cstruct usage at L844 + L850** — verdict uses
     trimmed `cstruct_distribution_a_i`, RSS uses untrimmed
     `distribution_a_i`. THE refactor MUST NOT share one
     Cstruct across submodules.
   - L845-846 `n_active` + `max_worker_flow_share` both use
     untrimmed `distribution_a_i`

2. **Fixed bad line citation.** v3 said "L795:
   trim_distribution_to_sum runs BEFORE Cstruct compute
   (L850)". Codex round-3 correctly caught that L795 is the
   harness-guard comment block; actual trim is at L837-841
   and the verdict Cstruct is at L844 (RSS Cstruct at L850).
   v4 splits this into the conditional-trim invariant
   (L837-841) and the dual-Cstruct invariant (L844 + L850).

### v3 changes vs v2

1. **Dropped the prescriptive narrow-input signature sketch.** v2
   listed signatures like `windowing::extract_window(intervals,
   test_start, warmup_secs, final_burst_secs) -> Window` that I
   wrote from imagination without verifying against the actual
   call chain in `fn main()`. Codex round-2 correctly caught
   that the sketch dropped required data (e.g. `extract_window`
   omitted `start.connected[]` which is needed for the
   PR-r1+r2-fixed starved-flow seeding at L610; `rss::evaluate`
   omitted `cstruct` and `n_total_workers`; `verdict::evaluate`
   was underspecified vs the ~15 inputs the actual decision
   tree reads at L866-895). v3 replaces the sketch with a
   discipline statement: submodule fn signatures will be
   derived directly from the existing call-site data
   dependencies at implementation time. No data flow change;
   pure code motion means the inputs are whatever the existing
   block already reads.

2. **Corrected "saturated-only aggregate gate" claim.** v2
   described `verdict.rs` as owning a "saturated-only aggregate
   gate." Codex round-2 correctly caught that the current code
   at L857-864 computes `saturated` as a reporting field stored
   in the `Verdict` struct (L922), but does NOT include it in
   `failure_reasons`. There is no saturation gate today.
   Implementing one would be a behavior change. v3 corrects
   the verdict.rs description to "the actual current failure
   reasons (starved>0, gap>EPSILON, !a_i_sum_check_ok,
   !rss_expectation_pass, cos_queue sum guard) + the saturated
   *reporting* field."

3. **Fixed stale "7 tests" in risk-assessment table.**
   Test count is 16 throughout the doc now.

4. **Removed crate-root/lib fallback residue.** v2 Hidden
   Invariant #6 committed to `#[path]` correctly, but the
   out-of-scope and open-questions sections still mentioned
   "elevation to `pub mod fairness;`" as a possible option.
   v3 deletes that residue — there is one architecture, not
   two.

### v2 changes vs v1

1. **Hidden Invariant #6 rewritten.** v1 handwaved between two
   options ("keep `#[path]` chains" vs "elevate to crate-root via
   `pub mod fairness;`"). Both reviewers correctly pointed out
   there is **no `src/lib.rs`** in this crate — `src/main.rs`
   and `src/bin/fairness-eval.rs` are *separate* binary crate
   roots. Adding `pub mod fairness;` to `main.rs` does NOT
   make `fairness.rs` reachable from `bin/fairness-eval.rs`.
   v2 commits exclusively to the `#[path]` redirection pattern.
2. **Test count corrected** from "7 tests" → 16 tests (Gemini
   round-1 finding C; verified `grep -c "^    #\[test\]"
   tests/fairness_eval_blackbox.rs` returns 16).
3. **Inline test blocks accounted for.** Codex round-1 finding #3
   noted the binary itself has `#[cfg(test)] mod tests` blocks
   at L1190 and L1464 (~370 LOC combined). v2 specifies that
   those test bodies move WITH their helpers into the
   corresponding submodules and remain private-module tests.
4. **Lower-level submodules take narrow inputs**, not `&Args`.
   Codex round-1 finding "passing `&Args` everywhere is too
   blunt" — v2 keeps `&Args` only at the orchestrator entry
   points (`run_evaluation`, `inputs::load`, `report::emit`)
   and uses narrow typed inputs for windowing/per_worker/rss/
   verdict.

## Issue framing

Tracking issue: #1330. `userspace-dp/src/bin/fairness-eval.rs` is
1555 production LOC with a single 383-LOC `fn main()` (L571–L972
in the file at master `fa456ccc`). The Tier-1 threshold is fn
>200 LOC; main is nearly 2× that. The file also encodes ~35 top-
level fns / structs around `main` (parse_args, parse_*_tsv,
read_to_string, parse helpers, aggregate_per_worker,
aggregate_cos_per_worker, etc.) plus ~20 serde Iperf3* DTO
structs.

Re-extract the orchestration into a library module
`fairness_eval::` inside the crate, leave a thin CLI shell in
`bin/fairness-eval.rs`. The fairness-evaluation primitives
(`compute_cstruct`, `compute_observed_cov`, `is_saturated`,
`starved_flow_count`) are **already** in `src/fairness.rs` (293
LOC, imported via `#[path = "../fairness.rs"] mod fairness;`),
so this refactor is NOT about library-izing the algorithm —
those primitives are already library code. It is about
library-izing the **orchestrator** (args → load → window →
aggregate → verdict → emit) that currently sits inside `main`.

## Honest scope/value framing

This is a pure-code-motion refactor on a build-time-only binary
(not on the dataplane). The CLI surface stays identical. The
algorithm stays identical.

The win is structural, not behavioral:

- `main` drops from 383 LOC to ~40 LOC (orchestrator shell).
- The orchestration logic becomes unit-testable without
  spawning the binary subprocess and synthesizing iperf3 JSON
  fixtures (current test contract from #547 is 100% black-box
  CLI invocation; the 16 cargo integration tests in
  `tests/fairness_eval_blackbox.rs` (1144 LOC) cover the
  binary surface).
- Future autoresearch loops that want to call the evaluator
  in-process (e.g. for sweep gating without external process
  invocation, parameter-sweep harnesses, regression-corpus
  replay) become directly possible.

**If reviewers conclude the perf gain is too small to justify
the churn, PLAN-KILL is an acceptable verdict.** This file is
not in the active hot path; nobody pages on its LOC count.
However: at 1555 prod LOC with a 383-LOC main fn that has been
amended across PRs #1217, #1219, #1220, #1224, #1232, #1276,
the next regression-pin or feature addition is increasingly
likely to land entirely inside an opaque 400+ LOC function.
The cost-benefit gets worse over time, not better.

## What's already shipped / partially batched

- `src/fairness.rs` already isolates the four numeric
  primitives (`compute_cstruct`, `compute_observed_cov`,
  `is_saturated`, `starved_flow_count`). This refactor does NOT
  touch them.
- PR #547 established the black-box `tests/*.rs` cargo
  integration test discipline (`env!("CARGO_BIN_EXE_fairness-eval")`
  pattern, 16 tests). This refactor does NOT touch them — they
  continue to invoke the binary externally.
- The binary itself has **2 inline `#[cfg(test)] mod tests`
  blocks** at L1190 and L1464 (~370 LOC combined) covering
  helper-fn behavior: parser tests (parse_number_or_percent,
  parse_rss_expectation, trim_distribution_to_sum,
  aggregate_per_worker, etc.) at L1190 and TSV-parse tests
  (parse_binding_flows_tsv, parse_cos_flows_tsv) at L1464.
  These tests move WITH their target helpers into the
  corresponding submodules and remain private-module tests.
- PR #1220 round-3 added the `aggregate_per_worker()` helper
  (now at L234 in fairness-eval.rs) that fixes a per-binding-
  slot vs per-worker aggregation regression. The helper stays;
  it just moves into the new submodule.
- PR #1217 (fairness regimes contract) — Cstruct math defined
  in `fairness.rs::compute_cstruct`. Stays.
- The Iperf3* serde DTO structs (Iperf3Output / Iperf3Start /
  Iperf3Interval / Iperf3StreamInterval / Iperf3End / …) are
  unique to fairness-eval and have no other call site. They
  move to a new `inputs.rs` submodule.

## Concrete design

Target file layout in the crate:

```
userspace-dp/src/
  bin/
    fairness-eval.rs           ~40 LOC; pub fn main only
  fairness.rs                  UNCHANGED (293 LOC; the 4 primitives)
  fairness_eval/               NEW module — orchestration library
    mod.rs                     pub fn run_evaluation(inputs) -> Report
    args.rs                    Args struct + parse_args + flag-parse helpers
                               (parse_required_*_arg, parse_required_*_value,
                               parse_number_or_percent, parse_fraction_or_percent,
                               parse_nonnegative_number_or_percent,
                               parse_rss_expectation, read_to_string)
    inputs.rs                  Iperf3* serde DTOs (~20 structs);
                               parse_binding_flows_tsv, parse_cos_flows_tsv;
                               BindingFlowsRow, CosFlowsRow types
    windowing.rs               steady-state window selection (warmup_secs /
                               final_burst_secs / MIN_STEADY_STATE_SECS gate);
                               per-stream + aggregate bucket extraction
    per_worker.rs              aggregate_per_worker, aggregate_cos_per_worker,
                               max_worker_flow_share, direction_multiplier,
                               guard_sum_tolerances, trim_distribution_to_sum
    rss.rs                     evaluate_rss_expectation + RssExpectation
                               (currently L367–540, ~170 LOC)
    verdict.rs                 the actual pass/fail decision tree at L866-895
                               of main: starved-flow hard fail (Gate 1),
                               per-flow CoV gap > EPSILON (Gate 2),
                               !a_i_sum_check_ok harness guard,
                               !rss_expectation_pass, and the cos_queue
                               sum-mismatch guard. Owns the GUARD_RELATIVE /
                               GUARD_OVERCOUNT_DIVISOR / GUARD_ABSOLUTE /
                               EPSILON consts. The `saturated` field at L857
                               is computed here as a REPORTING value
                               (in Verdict struct at L922), NOT a gate.
    report.rs                  Report struct + JSON/TSV emission for
                               autoresearch pipelines
```

`bin/fairness-eval.rs` becomes:

```rust
//! `fairness-eval` — consume iperf3 JSON + per-binding active flow
//! count samples, compute the contract gates from
//! `docs/fairness-regimes.md`, emit a verdict JSON. CLI shell only —
//! the orchestrator lives in the `fairness_eval` library module.

use std::process::ExitCode;

#[path = "../fairness.rs"]
mod fairness;

#[path = "../fairness_eval/mod.rs"]
mod fairness_eval;

fn main() -> ExitCode {
    let args = fairness_eval::args::parse_args();
    let inputs = match fairness_eval::inputs::load(&args) {
        Ok(i) => i,
        Err(e) => { eprintln!("fairness-eval: {e}"); return ExitCode::from(2); }
    };
    let report = fairness_eval::run_evaluation(&args, inputs);
    fairness_eval::report::emit(&report, &args);
    if report.passed { ExitCode::SUCCESS } else { ExitCode::FAILURE }
}
```

The `#[path]` redirection from `bin/fairness-eval.rs` into
`../fairness_eval/mod.rs` mirrors the existing
`#[path = "../fairness.rs"]` pattern. The submodule lives
under `src/fairness_eval/` so it is reachable both from the
binary AND from any future in-crate caller.

## Public API preservation

The CLI surface (every `--flag` accepted by `parse_args`) stays
byte-for-byte identical. Verified by:

- `tests/fairness_eval_blackbox.rs` (1144 LOC, 16 tests) invokes
  the binary with every documented flag combination. This test
  surface continues to pass unchanged.
- Argument parsing is moved into `args.rs` but the public
  function signature `pub fn parse_args() -> Args` and the
  `Args` struct shape stay the same.
- All emitted JSON/TSV keys stay the same (`report.rs`
  preserves the exact serde rename attributes).
- Exit codes preserved: 0 = pass, 1 = fail, 2 = input error.

## Hidden invariants the change must preserve

1. **Steady-state window logic side effects.** The current main
   ordering: parse iperf JSON → compute total_dur → check
   `total_dur > warmup + final_burst` → check `ss_dur >= 60s` →
   seed `per_stream_buckets` from `start.connected[]` (PR
   round-1+2 finding #1) → walk intervals → derive
   `per_flow_throughputs`. This sequence must be preserved
   exactly; reordering risks regressing the "starved flow
   silently invisible" bug fixed in earlier rounds.

2. **Allocation patterns.** No `Vec::with_capacity(n_streams)` /
   `BTreeMap::new()` reordering. The current code is
   functionally correct and not on a perf-sensitive path; pure
   move only.

3. **`#[path]` redirection from binary to library.** `bin/`
   crates in Cargo can use `#[path]` to reach into sibling
   modules. The existing pattern (`#[path = "../fairness.rs"]
   mod fairness;`) works; we'll mirror it for `fairness_eval`.

4. **`compute_cstruct` etc. accessibility.** Currently imported
   as `use fairness::{compute_cstruct, …};` from inside
   `bin/fairness-eval.rs`. After the refactor those imports
   move into `fairness_eval/verdict.rs` and similar submodules;
   the redirection chain becomes: bin → fairness_eval module →
   `use crate::fairness::*` or `use super::fairness::*`. The
   existing `#[path = "../fairness.rs"]` declaration in the
   bin needs to be either kept (and re-exported) or moved
   alongside the new `#[path = "../fairness_eval/mod.rs"]`.

5. **GUARD_RELATIVE / GUARD_OVERCOUNT_DIVISOR / GUARD_ABSOLUTE
   and EPSILON consts.** Currently file-top consts. They
   semantically belong with `verdict.rs`. Moving them must
   preserve their numeric values (0.10 / 4 / 2 / 0.05).

6. **`#[path]` redirection chain — committed approach.**
   Verified: there is no `userspace-dp/src/lib.rs`; only
   `src/main.rs` (xpfd binary) and `src/bin/fairness-eval.rs`
   (this binary). Cargo treats them as **separate binary crate
   roots**. Adding `pub mod fairness;` to `main.rs` does NOT
   make `fairness.rs` accessible to `bin/fairness-eval.rs`.
   v1's "elevation to crate-root" option is therefore
   architecturally impossible without creating a new
   `src/lib.rs` (which would create a new public library API
   surface — out of scope for a pure-code-motion refactor).

   v2 commits exclusively to the `#[path]` redirection pattern:

   ```
   bin/fairness-eval.rs:
     #[path = "../fairness.rs"]              mod fairness;
     #[path = "../fairness_eval/mod.rs"]     mod fairness_eval;
   ```

   Inside `fairness_eval/mod.rs`:

   ```
   pub mod args;
   pub mod inputs;
   pub mod windowing;
   pub mod per_worker;
   pub mod rss;
   pub mod verdict;
   pub mod report;

   // Re-import the primitives via the parent's `#[path]`
   // (which is `crate::fairness` from the binary's view, but
   // from `fairness_eval/mod.rs` it's reachable via `super::fairness`).
   pub(crate) use super::fairness;
   ```

   Submodules import primitives via `use super::fairness::*;`
   (one level up from each submodule reaches `mod.rs`, which
   re-exports the parent's `fairness`).

   Net: zero new public API. The binary stays binary-private.
   `src/fairness.rs` is unmodified.

## Risk assessment

| Class | Level | Rationale |
|---|---|---|
| Behavioral regression risk | LOW | Pure code motion. 1144-LOC black-box test suite (16 tests) gates the binary's external behavior. CLI surface unchanged. Numeric constants explicitly preserved. |
| Lifetime / borrow-checker risk | LOW | All current ownership is `&str` / `Vec<...>` / `BTreeMap<u64, Vec<u64>>` — no `Arc`, no async, no `&mut self` across closures. Moving fns to sibling modules doesn't introduce new lifetime constraints. |
| Performance regression risk | NIL | Build-time-only binary. Off the dataplane. No worker, no per-packet path, no shared atomic. |
| Architectural mismatch risk (#961 / #946 Phase 2 dead-end pattern) | LOW | This refactor doesn't propose a new architecture; it splits an existing fn into siblings. There's no premise that could fail — either the file split is mechanical and clean, or it isn't and the PR doesn't go in. |

The dominant residual risk is **scope creep**: editor-temptation
to "improve" the algorithm or DTO shape during the move. Plan
discipline (Step 5: pure code motion only; if the move reveals
a deviation, stop and revise the plan) is the mitigation.

## Test plan

1. **Cargo build clean** — `TMPDIR=/dev/shm CARGO_TARGET_DIR=/dev/shm/cargo cargo build --release` on the refactor branch.
2. **Cargo test full suite** — `cargo test --release` (952+ tests; expect no diff).
3. **5× named-test flake check** on `fairness_eval_blackbox`:
   ```bash
   for i in 1 2 3 4 5; do
     TMPDIR=/dev/shm CARGO_TARGET_DIR=/dev/shm/cargo cargo test --release --test fairness_eval_blackbox 2>&1 | grep "test result" | tail -1
   done
   ```
4. **Go test suite** — `GOCACHE=/dev/shm/cache GOTMPDIR=/dev/shm go test ./...` (no Go side touched; safety check only).
5. **Manual diff smoke**: pick one canonical iperf3 JSON fixture
   from `tests/fairness_eval_blackbox.rs`, run both pre-refactor
   and post-refactor binary, `diff` the emitted report — must
   be byte-identical.
6. **No cluster smoke needed.** This is a build-time-only binary
   that does not touch the AF_XDP dataplane, CoS shaping, HA
   state, or any kernel-facing code. Per the project rule "no
   cluster smoke for build-time-only changes", skip the
   30-measurement Pass A/B matrix.

## Out of scope (explicitly)

- No CLI flag additions, renames, or removals.
- No algorithm changes (Cstruct, observed_cov, is_saturated,
  starved_flow_count, aggregate_per_worker semantics all stay).
- No new dependencies (no `clap`, no `serde_yaml`, no `tempfile`
  — preserve the hand-rolled style PR #547 settled on).
- No touching `src/fairness.rs`. The four primitives stay where
  they are. The submodules under `fairness_eval/` reach them via
  the `#[path]` chain documented in Hidden Invariant #6.
- No touching `tests/fairness_eval_blackbox.rs` — the black-box
  contract is the gate; touching it during the refactor would
  make verification circular.
- No moving fns to `tests/*.rs`. Keep production code in `src/`.
- No new inline unit tests in this PR. Adding `#[cfg(test)] mod
  tests` blocks per submodule is a follow-up — it's exactly the
  thing this refactor unlocks but it would expand PR scope.
- No `bin/cli/` consolidation, no shared-arg-parser extraction
  across other binaries.

## Open questions for adversarial review

1. **Is the win worth the churn?** The file has been amended
   across ≥6 PRs; another N PRs are likely. The argument is
   that 6 future PRs of ~50 LOC each will each be cleaner if
   they land in `verdict.rs` / `windowing.rs` / `per_worker.rs`
   rather than amending a single 383-LOC `main`. Counter-
   argument: those 6 PRs may land regardless; the LOC count
   may not actually predict review velocity. **Reviewer call:
   PLAN-KILL is acceptable if the win is too theoretical.**

2. *Settled by v2/v3.* This crate has no `lib.rs` and growing
   one is out of scope. The `#[path]` chain documented in
   Hidden Invariant #6 is the chosen approach.

3. **Module size after the split.** 1555 prod LOC across 8
   submodules averages ~190 LOC per submodule. Is that the
   right granularity, or are some submodules too small to
   justify their own file? Specifically: `verdict.rs` (~80 LOC)
   and `windowing.rs` (~55 LOC) might be too small. Counter-
   argument: small modules are fine when they encode a single
   cohesion concept (verdict.rs = "the decision tree";
   windowing.rs = "what counts as steady state").

4. **Does the consolidation lose the inline grep-target
   property?** Today you can `git grep "GUARD_RELATIVE"
   bin/fairness-eval.rs` and find every reference in one file.
   After the split, GUARD_RELATIVE moves to verdict.rs, but a
   reader looking at `bin/fairness-eval.rs` to understand the
   binary won't find it. Counter-argument: the same is true for
   `compute_cstruct` already (in `fairness.rs`), and that
   hasn't been a problem. Module-level cohesion at the cost of
   single-file searchability is a net win.

5. **Should `parse_args` use a real arg parser library
   (`clap`, `argh`)?** PR #547 explicitly settled on hand-
   rolled parsing. This PR keeps that decision. But the
   adversarial reviewer might argue the refactor is the right
   moment to revisit. Plan position: NO — that's a separate
   decision with its own trade-offs (added dependency,
   different `--help` UX, etc.). If a reviewer disagrees
   strongly, file a follow-up.

6. **Risk of "subtle reordering" bugs during the move.**
   Several main-body sequences are non-obvious (the
   `per_stream_buckets` seeding from `start.connected[]` is a
   PR-r1+r2 fix for silently-invisible starved flows). Moving
   them across submodule boundaries risks accidentally
   reordering. Mitigation: each submodule must be a `pub fn`
   that takes the upstream output as input and returns the
   downstream input — no shared mutable state across the
   submodule call sites. Plus a manual diff smoke (Test #5
   above) comparing pre/post output on a canonical fixture.

7. **`Args` struct as a parameter-passing vehicle.** v3
   discipline: pass `&Args` only at the orchestrator entry
   points (`run_evaluation`, `inputs::load`, `report::emit`).
   Lower-level submodules take narrow typed inputs that match
   what the existing code block at that responsibility already
   reads.

   v3 deliberately does NOT prescribe the per-fn signatures
   here. Codex round-2 correctly caught that v2's prescriptive
   sketches dropped required data (e.g. omitting
   `start.connected[]` from a proposed `extract_window` would
   silently regress the PR-r1+r2 starved-flow seeding fix at
   `bin/fairness-eval.rs:610`). The honest plan-time commitment
   is:

   - Submodule fn signatures will be derived **directly from
     the existing call-site data dependencies** during
     implementation. Whatever the corresponding L571-L972 block
     in current `fn main()` reads is what the new fn takes as
     parameters.
   - Pure code motion preserves the data flow byte-for-byte;
     the new types (`Window`, `WorkerCounts`, `RssOutcome`,
     etc.) are output containers for what each block already
     produces, NOT new input filters.
   - Reviewers should focus on the boundary placement (which
     fns belong in which submodule) and ordering invariant
     preservation (Hidden Invariants #1 + #6, plus the
     additional ordering invariants enumerated below in v3),
     NOT on signature speculation.

   **Code-motion ordering invariants enumerated** (from
   `bin/fairness-eval.rs` at master `fa456ccc`):

   - L610-620: `per_stream_buckets` MUST be seeded from
     `iperf.start.connected[]` BEFORE the interval walk; this
     is the PR-r1+r2 fix for silently-invisible starved flows.
   - L645-653: `per_flow_throughputs` MUST be derived AFTER
     the full interval walk, never during.
   - L661-680: per-binding flow aggregation at `aggregate_per_worker`
     uses TSV epoch timestamps converted via warmup/final_burst
     deltas (L250), NOT iperf-relative seconds. Submodule
     boundary must preserve the epoch-vs-iperf-relative
     distinction.
   - **L686-726 CoS override block**: when `--cos-flows` is
     given, `distribution_a_i` is reassigned from binding-
     derived to `aggregate_cos_per_worker(...)` output AND
     `iface_filter_active` is forced to `true` AND
     `cstruct_source` flips from `"binding"` to `"cos_queue"`.
     `binding_distribution_a_i` remains the original
     binding-derived snapshot. This block MUST run before any
     downstream computation that reads `distribution_a_i` or
     `iface_filter_active` (i.e. before a_i_sum, expected_sum,
     Cstruct, RSS evaluation, saturation, failure_reasons).
     The CoS sum guard at L891-895 specifically needs
     `binding_distribution_a_i` to remain available for the
     `binding_a_i_sum + tolerance < a_i_sum` comparison.
   - **L815-819 `n_iperf_streams` derivation**: prefer
     `iperf.start.connected[].len()` (concrete observed sockets)
     over `iperf.start.test_start.num_streams` (self-reported).
     Codex round-2 historical fix — moving this would resurrect
     a real bug.
   - **L820-826 stream-count chain**: `n_non_starved =
     n_iperf_streams.saturating_sub(starved)`; `dir_mult =
     direction_multiplier(iface_filter_active)`; `expected_sum
     = n_non_starved.saturating_mul(dir_mult)`. The
     `iface_filter_active` value used here MUST be the
     post-CoS-override value (true under CoS mode), not the
     binding-derived original.
   - **L837-841 conditional overcount trim**:
     `cstruct_distribution_a_i = trim_distribution_to_sum(...)`
     **only if** `a_i_delta > 0 && a_i_sum_check_ok`.
     Otherwise `cstruct_distribution_a_i =
     distribution_a_i.clone()` (untrimmed pass-through).
     Do NOT trim unconditionally.
   - **L844 + L850 dual Cstruct usage** — IMPORTANT:
     - `verdict.rs` Cstruct (the gap-vs-EPSILON gate) uses
       `compute_cstruct(&cstruct_distribution_a_i)` at L844
       (TRIMMED).
     - `rss.rs` Cstruct (passed into `evaluate_rss_expectation`)
       uses `compute_cstruct(&distribution_a_i)` at L850
       (UNTRIMMED).
     The refactor MUST preserve this — there is no single
     Cstruct value shared across submodules. Each submodule
     gets its own input.
   - **L845-846 untrimmed inputs for n_active and
     max_worker_flow_share**: both use `distribution_a_i`
     (untrimmed). Do not pass `cstruct_distribution_a_i` here.
   - L857-864: `saturated` is REPORTING ONLY (in Verdict at
     L922). It is NOT in `failure_reasons` (L866-895). Do not
     introduce a saturation gate.
   - L866-895: failure_reasons composition order matters for
     diagnostic output (Gate 1 starved → Gate 2 CoV → harness
     guard → RSS → CoS sum guard). Preserve order.
