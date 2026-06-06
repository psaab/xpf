# #1776 — Decompose `worker_loop` (~1440 LOC single fn), loop_body Phase 2

**Status:** v2 — **NARROWED** after round-1 (Codex PLAN-NEEDS-MAJOR, AGY
worth-doing-with-caveats, Claude SMR NEEDS-MINOR). v2 drops the risky
per-tick extraction and keeps only the two safe, high-value moves. See §0.1.
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
| **The extraction doesn't solve the fn-size problem** — the ~500-line debug/report/reset block (~L906–1174) is the real bulk; v1 didn't list it (Codex 5 + Claude SMR + AGY converge). | **PRIMARY extraction: `debug_report.rs`** — the cfg-gated debug/report/reset block. ~500 lines out, `#[cfg(feature="debug-log")]` so **zero release-path risk**. |
| **43-line manual `dbg_* = 0` reset is a forget-a-counter bug risk** (AGY). | `DbgCounters` struct lives in `debug_report.rs` under the same cfg; `st.dbg = DbgCounters::default()` single-line reset. |
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

**Step B — extract cold blocks to sibling files**, each `#[inline(never)]`:
```text
worker/loop_body/
  ├── mod.rs        # worker_loop facade: setup() then loop { … } with the
  │                 #   hot poll_binding sweep kept inline
  ├── setup.rs      # build WorkerLoopState from WorkerContext (the L60–308 block)
  ├── telemetry.rs  # publish_telemetry(ctx, st, now)  (block a)
  ├── config.rs     # refresh_shared_config(ctx, st)    (block b)
  └── commands.rs   # drain_commands(ctx, st)           (block f command part)
```
The hot `poll_binding` sweep (e) + heartbeat (c) stay in `mod.rs`'s loop
body — NOT extracted (avoid any call-boundary on the per-packet path).

**Pure code-motion discipline:** each extracted block is moved verbatim
(same statements, same order, same side-effect sequence) — only the
variable access changes (`x` → `st.x`). No logic change.

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
- **Perf gate (mandatory):** `userspace-perf-compare.sh` (or equivalent) before/after — assert no throughput/latency regression on the hot path. This is the kill-or-ship signal.
- Smoke on loss cluster: v4+v6 × push+reverse × CoS off/on; `make test-failover` (worker loop touches HA/command drain).

## 10. Out of scope
- forwarding/mod.rs (#1661 item 7), compiler.go (#1661) — already tracked.
- Any logic change / optimization (AVX2 etc. — speculative, not this).

## 11. Open questions for adversarial review
1. Is the ctx/state split borrow-checkable without clones/RefCell given the
   blocks that touch both shared handles and mutable state? Worst offender?
2. Does extracting telemetry/config/commands to `#[inline(never)]` cold fns
   actually help, or does the current compiler already cold-split them via
   PGO/layout — i.e., is the perf rationale real or speculative?
3. Is keeping `poll_binding` inline in `mod.rs` sufficient to guarantee no
   hot-path regression, or does moving setup/telemetry out shift the hot
   block's address/layout enough to matter?
4. Given the file is UNDER the 2000-LOC trigger (only the fn-size rule
   fires), is the hot-path churn-risk worth it — or is PLAN-KILL right?
5. Is `DbgCounters` worth structifying, or should the ~40 `dbg_*` just move
   into `WorkerLoopState` flat (fewer indirections to reason about)?
