# Claude SMR hostile plan review — #1827 multi-WAN, round 3 (plan v3)

**Verdict: PLAN-READY**

Round-3 pass re-verified each v3 fold against the worktree rather than the
plan's own claims:

1. **Ordering (AGY r2-1)** — v3 §4.3 step 3 publishes via `apply_snapshot`
   and bumps only on success. Trace check: the partial-republish template
   stamps `next.FIBGeneration = m.readFIBGeneration()` (old gen) into the
   published snapshot; the post-success bump moves `fib_gen_map` to
   old+1, so flows re-resolve against the helper state rebuilt from the
   NEW snapshot. Order is correct and the named test makes it durable.
2. **Operator-commit overlay preservation (AGY r2-2)** — folded as a
   design requirement, not a note: one overlay, one
   `assembleFRRConfig` constructor, two triggers. This was the round's
   only genuine v2 defect; v3 resolves it structurally.
3. **Pin plumbing (Codex r2-1, AGY r2-3)** — per-test mark/table in the
   vacant 50-99 band (verified vacant against `pkg/routing/rules.go`
   bands 100-199 / 31000+ / 33000+), TableID collision check, dev+onlink,
   startup band clear + table flush, same-target-two-uplinks test. I
   added the band-size commit cap (≤50 pinned tests) so allocation can
   never silently spill into the next-table window.
4. **Named API (Codex r2-2)** — `PublishRouteOverlaySnapshot` forbidden
   from `Compile`, modeled on `manager.go:700-740`, three named tests.
   Closes the drift-risk I accepted provisionally in r2.
5. **Throttle + churn metric (AGY r2-4 / Codex Q5)** — 3 s inter-actuation
   floor on top of the 1 s debounce; flap smoke asserts the bound.

No new findings. The plan is staged honestly (PR-1a/PR-1b small and
shippable, zero Rust in the PR-1 unit; PR-2 gated on the two-upstream
topology; PR-3/PR-4 re-enter review), the single-WAN lab gap is stated
plainly, and every stage has a falsifiable kill criterion. PLAN-READY.
