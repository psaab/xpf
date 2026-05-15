## Status

DRAFT v1 — pending adversarial plan review.

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
  CLI invocation; the 7 cargo integration tests in
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
  pattern, 7 tests). This refactor does NOT touch them — they
  continue to invoke the binary externally.
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
    verdict.rs                 the pass/fail decision tree at the bottom of
                               main: Cstruct + 0.05 ceiling, starved-flow
                               hard fail, saturated-only aggregate gate,
                               GUARD_RELATIVE / GUARD_OVERCOUNT_DIVISOR /
                               GUARD_ABSOLUTE consts
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

- `tests/fairness_eval_blackbox.rs` (1144 LOC, 7 tests) invokes
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

6. **`#[path = "../fairness.rs"]` re-import.** Both `bin/` and
   `fairness_eval/` need access to the four primitives. The
   path declaration in `bin/fairness-eval.rs` is the binary's
   entry; the submodules under `fairness_eval/` reach the
   primitives via `use crate::fairness::*` — but `fairness.rs`
   isn't a crate-root module today; it's reached only via
   `#[path]` from the binary. Resolution: add
   `pub mod fairness;` to `lib.rs` if one exists, OR keep the
   `#[path]` redirection in each submodule that needs the
   primitives. The simpler option (and one this plan
   recommends) is to declare `pub mod fairness;` at crate root
   so all callers (binary + tests + future in-crate users) get
   it via `crate::fairness`. This makes `fairness.rs` a
   first-class library module — a small additional benefit.

## Risk assessment

| Class | Level | Rationale |
|---|---|---|
| Behavioral regression risk | LOW | Pure code motion. 1144-LOC black-box test suite (7 tests) gates the binary's external behavior. CLI surface unchanged. Numeric constants explicitly preserved. |
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
- No touching `src/fairness.rs` beyond possibly elevating it to
  `pub mod fairness;` at crate root for cleaner submodule
  imports (see Hidden Invariant #6).
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

2. **Is the `#[path]` redirection from `bin/` into
   `src/fairness_eval/` idiomatic?** The existing pattern
   (`#[path = "../fairness.rs"] mod fairness;` in the binary)
   suggests yes, but a cleaner Rust idiom is to make
   `fairness_eval` a proper crate-root module (added via `pub
   mod fairness_eval;` in `lib.rs` if it exists, or `main.rs`)
   and have the binary import it as `use
   xpf_userspace_dp::fairness_eval;`. Does this crate even
   have a `lib.rs`? If not, can it grow one without
   destabilizing other binaries (xpf-userspace-dp main, xpf-ha,
   etc.)? Worth confirming before write-up.

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

7. **`Args` struct as a parameter-passing vehicle.** With main
   broken up, `Args` gets passed into every submodule.
   Alternative: project `Args` into per-submodule typed inputs
   (e.g. `WindowingArgs { warmup_secs, final_burst_secs }`).
   The latter is cleaner but doubles the type surface. Plan
   position: pass the whole `&Args` (cheap, no allocation,
   no public-API change). If reviewers want typed inputs,
   they're welcome to argue for them.
