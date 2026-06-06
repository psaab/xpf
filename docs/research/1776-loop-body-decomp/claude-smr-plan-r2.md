# Claude SMR plan-review — #1776 round 2 (v2 NARROWED)

**Verdict: PLAN-READY** for the narrowed scope (debug_report.rs + setup.rs).

v2 drops exactly the parts that drew Codex's MAJOR (per-tick
config/commands/telemetry #[inline(never)] in front of load_arc_if_changed;
the fabrics-reorder and ha_runtime-straddle hazards all live in those dropped
blocks). What remains is the two extractions every reviewer endorsed:
- debug_report.rs: the ~500-line #[cfg(feature="debug-log")] block — DCE'd in
  release, so provably zero hot-path impact; the single largest chunk.
- setup.rs: one-shot cold setup, runs once, no per-tick boundary.

No (&ctx,&mut st) split is forced (the borrow-fragile config block stays
inline), so the borrow risk Codex flagged evaporates. perf-neutral by
construction (release loop body unchanged except setup hoisted to a once-call).
The perf gate is now a regression guard, not a kill signal — correctly framed.
The only residual: confirm `exported_sequences` and any setup-produced state
move cleanly out of setup() (AGY's cross-block note + bindings/SessionTable
movability) — a code-review item at /engineer time, not a plan gap.

PLAN-READY. This is Codex's own "Required Revision" verbatim.
