# Claude SMR plan-review — #1776 round 1 (v1 @ e83bb2fe2)

**Verdict: PLAN-NEEDS-MINOR**, and the case for PLAN-KILL is stronger than
v1 admits. The decomposition is sound as pure code-motion, but a hostile
read of the actual function changes the value calculus materially.

## MAJOR factual correction — most of the "1440 LOC" is `#[cfg(feature="debug-log")]`

The ~40 `dbg_*` counters (L186+) are **all** `#[cfg(feature = "debug-log")]`
(L187–207+), and the periodic debug-report block (~L904–1127, ~220 lines)
is the same cfg. **In a release build these DCE entirely.** Consequences:

1. **The audit's register-spilling / i-cache rationale is release-irrelevant.**
   Those ~40 locals do not exist in the release binary, so they cannot
   spill registers on the hot path. v1 already called the rationale
   "speculative"; it's actually *false for release*. The perf gate will
   almost certainly show null — which is the point, but it also means there
   is **no perf upside to claim at all.**
2. **The release-relevant `worker_loop` is much smaller than 1440 LOC.**
   Subtract the ~220-line debug-report block + ~40 counter decls + their
   increment sites and the release fn is plausibly ~1000–1100 LOC. Still
   over the 100-LOC/fn trigger, but the "14× the trigger" framing
   overcounts what ships.
3. **`DbgCounters` structification is debug-build-only ergonomics.** Don't
   put the `dbg_*` fields in the release `WorkerLoopState` — keep them under
   the same cfg, or (cleaner) **extract the whole cfg-gated debug-report
   block to `loop_body/debug_report.rs`** (it's already isolated by cfg →
   trivial, zero hot-path risk, and removes ~260 lines from `mod.rs` for
   free). This is the single highest-value, lowest-risk extraction and v1
   doesn't call it out.

## Revised decomposition priority (evidence-based)
1. **`debug_report.rs`** — move the cfg-gated debug block + its counters.
   ~260 lines out, zero release impact, zero borrow hazard. Do this first.
2. **`setup.rs`** — the L60–308 setup (release-relevant, cold, runs once).
   Returns `WorkerLoopState`. Verify `bindings` (own AF_XDP rings/FDs/UMEM)
   and `SessionTable` move cleanly out of `setup()` — they're locally
   constructed so a move should be fine, but confirm no pinning.
3. **`telemetry.rs` / `config.rs` / `commands.rs`** — the cold per-tick
   blocks. Real release readability win.
4. Keep `poll_binding` + heartbeat inline in `mod.rs` (v1 correct).

## Borrow-split (the real risk) — likely OK, name the offender
The `(&WorkerContext, &mut WorkerLoopState)` split should hold for the cold
helpers (each touches ctx handles + disjoint st fields). The block to scrutinize
is the **per-tick config refresh**: it `.load()`s several `ctx.shared_*` and
writes `st.{validation,forwarding,cos_*,mirror_targets}` — fine, ctx is `&`,
st is `&mut`. No block appears to need a simultaneous `&st` + `&mut st`. The
hot loop body mutating disjoint `st` fields (`st.sessions`, `st.bindings`,
`st.dbg`) is legal (disjoint field borrows). I don't see a forced clone/RefCell
— but the implementer must prove it per-block, not assume.

## Value verdict
This is **readability-only**, on a **sub-2000-LOC file**, where **~18% of the
bulk is debug-only and DCE's in release**. The genuine win is (1) the
trivial debug-block extraction and (2) cold-block tidy. That's worth doing
*if* it's truly pure code-motion with a null perf result — but it is NOT
worth any hot-path risk. If the perf gate shows ANY regression, PLAN-KILL.

## Recommendation
PLAN-NEEDS-MINOR: (a) record the cfg-gating fact + recompute release LOC;
(b) reorder to do `debug_report.rs` first (highest value/lowest risk);
(c) keep `dbg_*` under cfg, not in the release state struct; (d) keep the
perf gate as a hard ship-or-kill with the honest expectation of a null
result and no claimed gain. With those, it's a clean low-risk refactor —
or a defensible PLAN-KILL if the author decides sub-threshold readability
isn't worth touching the hottest fn at all.
