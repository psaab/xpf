# #1776 — Decompose `worker_loop` (~1440 LOC single fn), loop_body Phase 2

**Status:** v3.1 — **CONVERGED PLAN-READY (narrowed scope)**. Round-2: Codex
PLAN-NEEDS-MINOR (doc fixes applied), AGY PLAN-NEEDS-MINOR (CORRECTNESS-1
folded), Claude SMR PLAN-READY. Scope = `setup.rs` + `debug_report.rs`
(cfg-gated subset) only; per-tick + `poll_binding` stay inline; perf-neutral.
See §0.1.
**Branch:** `research/1776-loop-body-decomp`
**Issue:** #1776 (follow-up to #1326 Phase 1, CLOSED)

## 0.1 Round-1 disposition (v2 — NARROWED scope)

Round-1 converged on a sharp conclusion: the v1 5-way split was too
aggressive for the hottest loop, but **two extractions are clearly safe and
high-value**. v2 narrows to those.

| r1 finding (reviewer) | v2 disposition |
|---|---|
| **`#[inline(never)]` on per-tick telemetry/config/commands adds an unconditional CALL every tick in front of `load_arc_if_changed`, which was explicitly optimized for 10K–100K ticks/s — could REGRESS** (Codex 4). | **DROP the per-tick telemetry/config/commands extraction.** Keep those blocks inline in the loop. |
| **"Pure code-motion" is FALSE for fabrics** — the real fabric refresh is at ~L715 (after commands/heartbeat/expiry/BPF refresh), NOT in the early config block; grouping it into `config.rs` reorders side effects (Codex 2). | Moot — `config.rs` is dropped. |
| **`ha_runtime` straddles cold+hot** — loaded ~L594, used by command handling ~L599 AND `poll_binding` ~L747; a `drain_commands(ctx,st)` that reloads HA changes snapshot semantics (Codex 3). | Moot — `commands.rs` is dropped; HA load + command drain stay inline. |
| **Worst borrow offender is config refresh** (touches cached state + shared ArcSwap simultaneously) — borrow-checkable but fragile (Codex 1). | Moot — config stays inline (no `(&ctx,&mut st)` split needed). |
| **The extraction doesn't solve the fn-size problem** — the ~500-line debug/report/reset block (~L906–1174) is the real bulk; v1 didn't list it (Codex 5 + Claude SMR + AGY converge). | **PRIMARY extraction: `debug_report.rs`** — but see the v3 refinement below: the L906–1174 region is **NOT wholly cfg-gated**. |
| **v3 (Codex r2-3): the L906 region MIXES cfg-gated verbose `debug-log` reporting/stall-dumps with ALWAYS-ON release behavior** — binding diagnostics/syscalls (~L914) + per-second `BindingLiveState` publish/reset (~L1298). "Zero release risk" is FALSE for the whole block. | `debug_report.rs` extracts **only the `#[cfg(feature="debug-log")]` verbose-reporting + stall-dump subset** (truly zero release-path risk). The always-on per-second `BindingLiveState` publish/reset + binding diagnostics **STAY INLINE** in `mod.rs` (they're release hot-ish maintenance, not debug). The release LOC reduction is therefore smaller than "~500" — it's the cfg-gated subset only. |
| **43-line manual `dbg_* = 0` reset is a forget-a-counter bug risk** (AGY). | `DbgCounters` struct holds **only the per-interval counters** (the ones zeroed each report cycle); `st.dbg = DbgCounters::default()` single-line reset. |
| **v3.1 (AGY r2 CORRECTNESS-1): `DbgCounters::default()` must NOT wipe PERSISTENT debug state.** `dbg_last_report_ns` (L186) and the stall-detection baselines `prev_rx_total`/`prev_fwd_total`/`stall_prev_fwd`/`stall_reported` (L272–275) survive across report intervals. If bundled into `DbgCounters` and `default()`-reset, `elapsed` goes huge every tick → the expensive debug/getsockopt block runs **every tick** (real regression) AND stall detection breaks. | Those 5 persistent fields live **directly in `WorkerLoopState` (or a `StallState` sub-struct), NOT in `DbgCounters`**. Only interval counters (reset-to-0) go in `DbgCounters`. Verified by AGY against L186/L272–275/L1131/L1177–1279. |
| **Perf gate insufficient** — `userspace-perf-compare.sh` is one 8s `-P4` run, no repeated stats/thresholds/`perf stat`/asm-diff/CoS matrix (Codex 6). | §9 strengthened: repeated before/after runs + `perf stat` + CoS matrix + codegen/asm spot-check. |
| Keep `poll_binding` inline (AGY + Codex agree). | Unchanged. |
| Retract any perf-*improvement* claim — LTO/PGO may already cold-split (AGY + Codex 4 + Claude SMR). | v2 claims **readability + reset-safety + zero release risk only**; perf-neutral by construction. |

**v2 scope = exactly two extractions:**
1. **`debug_report.rs`** — move the `#[cfg(feature="debug-log")]` debug/report/
   reset block (~L906–1174) + a `DbgCounters` struct. Release-DCE'd, zero
   hot-path risk, removes the single largest chunk.
2. **`setup.rs`** — the one-shot setup (~L60–308): thread pin, TSC calibration,
   ArcSwap `load_full`s, bindings build, BPF-map-FD cache. Returns the loop's
   initial state. Cold, runs once.

Everything else (per-tick telemetry/config/command checks, HA load, the hot
`poll_binding` sweep, heartbeat, idle regulation) **stays inline in `mod.rs`**.
Net: `worker_loop` ~1440 → ~700 LOC; `mod.rs` 1453 → ~750 — a real fn-size cut
with no call boundary added to the per-tick path. This is exactly Codex's
"Required Revision" (keep setup; extract the debug block; do NOT extract
per-tick config/commands).

## 1. Issue framing
`userspace-dp/src/afxdp/worker/loop_body/mod.rs` is 1453 LOC and is one
function: `worker_loop` (~1440 LOC, ~38 params, ~40 `dbg_*` locals + many
more state locals). The FILE is under the 2000-LOC trigger, but the
FUNCTION is >14× the 100-LOC/fn trigger — the per-function-size standout in
the dataplane. #1326 Phase 1 moved the fn out of `worker/mod.rs`; this is
Phase 2 (decompose the fn itself).

## 2. Honest scope/value
This is a **readability/testability/maintainability** refactor, NOT a perf
win — and it sits on the **hottest function in the dataplane**, so the bar
is "demonstrably zero hot-path regression," not "faster." The audit's
i-cache / register-spilling rationale is **speculative** and must not be
sold as a guaranteed gain. **If reviewers conclude the churn-risk on the
hot path outweighs the maintainability gain, PLAN-KILL is acceptable** —
especially since the file is under the 2000-LOC file trigger and only the
fn-size rule fires.

## 3. Already shipped
- #1326 Phase 1: `worker_loop` extracted from `worker/mod.rs` → `loop_body/`.
- Telemetry already factored into `WorkerRuntimeCounters` /
  `WorkerColdPathCounters` (publish helpers exist) — the in-loop publish is
  a thin call site, a clean extraction candidate.

## 4. Verified structure (the seams)
- **Setup** (~L60–308): thread pin, TSC calibration, startup log, ArcSwap
  `load_full`s, bindings build, ~40 `dbg_*` counters, BPF-map-FD cache,
  initial `cos_status` store, telemetry init.
- **Main `loop {}`** (~L309–1453):
  - (a) telemetry publish (idle accounting, `runtime_atomics.publish`,
    `cold_path_atomics.publish_from_local`) — cold, ~1 s cadence.
  - (b) per-tick ArcSwap config refresh (validation/forwarding/cos*/mirror/
    fabrics, `ptr_eq` gated) — cold-ish.
  - (c) HA runtime load + heartbeat store — cheap.
  - (d) BPF `last_seen` refresh (~10 s throttle) — cold.
  - (e) **hot:** `poll_binding` sweep across bindings.
  - (f) command drain + idle/sleep regulation.

## 5. Design (pure code-motion + one state struct)

**Step A — collapse the 38 params + locals into two structs** (the only
non-mechanical step):
```rust
// read-only shared handles + ids (immutable for the loop's life)
struct WorkerContext { worker_id, shared_validation, shared_forwarding,
    ha_state, dynamic_neighbors, shared_*sessions, commands, stop,
    heartbeat, runtime_atomics, cold_path_atomics, … }      // ~all Arc<…>
// mutable per-loop state
struct WorkerLoopState { validation, forwarding, cos_*, mirror_targets,
    sessions: SessionTable, screen_state, bindings, dbg: DbgCounters,
    wr_counters, timing watermarks (last_publish_ns, last_cos_status_ns, …) }
struct DbgCounters { rx_total, tx_total, … }  // the ~40 dbg_* fields
```
Helpers take `(&WorkerContext, &mut WorkerLoopState)` — ≤2 args, no 34-arg
spill, no per-packet indirection (structs are stack-local; the hot
`poll_binding` call is unchanged).

**NOTE (v2/v3): this §5 describes the SUPERSEDED v1 5-way split. The
authoritative scope is §0.1.** v1's `telemetry.rs`/`config.rs`/`commands.rs`
extractions are **DROPPED** (Codex r1-4: an `#[inline(never)]` call boundary
in front of the per-tick `load_arc_if_changed`, optimized for 10–100K
ticks/s, risks regression; plus the fabrics-reorder and `ha_runtime`-straddle
hazards). v2/v3 extract only:

```text
worker/loop_body/
  ├── mod.rs           # worker_loop: setup() then loop { … }; ALL per-tick
  │                    #   telemetry/config/command checks + poll_binding +
  │                    #   heartbeat + the always-on BindingLiveState publish
  │                    #   stay INLINE here
  ├── setup.rs         # one-shot cold setup (L60–308) → returns initial WorkerLoopState
  └── debug_report.rs  # ONLY the #[cfg(feature="debug-log")] verbose report /
                       #   stall-dump subset + DbgCounters (release-DCE'd)
```

**v3 refinement (Codex r2-3):** the L906–1174 region is NOT wholly
cfg-gated. It interleaves cfg-gated verbose `debug-log` reporting (→
`debug_report.rs`, zero release risk) with **always-on release behavior** —
binding diagnostics/syscalls (~L914) and the per-second `BindingLiveState`
publish/reset (~L1298). The always-on parts **stay inline**; only the
`#[cfg(feature="debug-log")]` subset moves. So the release LOC reduction is
the cfg-gated subset, not the full ~500 lines.

`WorkerContext`/`WorkerLoopState` (Step A) is OPTIONAL in v2 — with only
setup + debug_report extracted, the borrow-split is not forced; it can be
introduced later if/when more is extracted. `DbgCounters` (under the same
cfg) is the one struct worth adding now for the single-line reset.

**Pure code-motion discipline:** each extracted block is moved verbatim
(same statements, order, side-effect sequence) — only variable access
changes. No logic change.

## 6. Public API preservation
`worker_loop`'s signature is unchanged (still called from the coordinator
spawn). `WorkerContext`/`WorkerLoopState`/`DbgCounters` are private to
`loop_body`. No cross-crate or protocol change.

## 7. Hidden invariants
- **Side-effect ordering** within the loop is byte-preserved (telemetry
  before/after config refresh, heartbeat timing, publish cadence).
- **Hot path:** `poll_binding` stays in the loop body with no new
  indirection; extracted helpers are cold (`#[inline(never)]`) so they
  don't bloat the hot path's i-cache footprint.
- **Borrow shape:** the `(&ctx, &mut st)` split must satisfy the borrow
  checker without `RefCell`/clones — the one real risk (some blocks touch
  both a shared handle and mutable state; split fields carefully).
- Calibration / one-shot setup runs exactly once (in `setup.rs`).

## 8. Risk assessment
| Class | Level |
|---|---|
| Behavioral regression | LOW if pure code-motion (verbatim blocks) |
| Borrow/lifetime | **MED** — the ctx/state split is the hazard |
| Performance regression | **MED** — hottest fn; MUST measure (perf + smoke), the gate |
| Architectural mismatch | LOW — #1326 lineage, natural seams |

## 9. Test plan
- `cargo build` + full `cargo test --release` + 5× flake on worker/loop_body tests.
- Go suite.
- **Perf regression guard (not auto-kill — v2 is perf-neutral by construction):**
  `userspace-perf-compare.sh` is one 8s `-P4` v4/v6 run — insufficient alone
  (Codex r1-6/r2-5). Strengthen to: **repeated** before/after runs (≥3 each)
  with a variance threshold; `perf stat` (IPC/cache-miss counters) +
  `perf record` on the hot loop; the **CoS off/on matrix**; and a
  codegen/asm spot-check of the `worker_loop` hot block before/after. Treat a
  flagged delta as a **triage signal**, not an automatic kill (since the
  release loop body is unchanged except setup hoisted to a one-shot call).
- Smoke on loss cluster: v4+v6 × push+reverse × CoS off/on; `make test-failover`
  (worker loop touches HA/command drain).

## 10. Out of scope
- forwarding/mod.rs (#1661 item 7), compiler.go (#1661) — already tracked.
- Any logic change / optimization (AVX2 etc. — speculative, not this).

## 11. Open questions (round-1/2 RESOLVED — kept for the record)
1. ~~ctx/state borrow-split~~ — DROPPED in v2 (config/commands stay inline, no
   split forced). Optional later.
2. ~~`#[inline(never)]` telemetry/config/commands~~ — DROPPED (Codex r1-4:
   regression risk in front of `load_arc_if_changed`).
3. Keeping `poll_binding` inline — CONFIRMED correct (Codex + AGY).
4. Sub-2000-LOC file: the value is **readability + reset-safety**, perf-neutral;
   PLAN-KILL was on the table but the narrowed scope (debug_report.rs + setup.rs)
   is low-risk enough to be worth it. Not killed.
5. `DbgCounters` struct — YES, for the single-line `default()` reset (AGY), under
   the `debug-log` cfg.

**Remaining for /engineer-time review (v3):** precisely partition the L906–1174
region — confirm exactly which lines are `#[cfg(feature="debug-log")]`
(→ `debug_report.rs`) vs always-on `BindingLiveState` publish/diagnostics
(→ stay inline) — Codex r2-3. This is a code-review boundary task, not a plan gap.
