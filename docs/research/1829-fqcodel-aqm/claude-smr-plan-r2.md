# Claude SMR hostile plan review — #1829 FQ-CoDel AQM — round 2

Artifact: plan v2 @ `3f517d48c`. Posture: hostile against my own r1 folds —
each v2 delta re-attacked, not rubber-stamped.

## Verdict

**PLAN-READY** with three MUST-PIN items for `/engineer` (no plan-structure
changes required; all three are implementation-time verification obligations
already implied by v2 text, elevated here to named gates).

## Re-attack of the v2 deltas

1. **§6.2c-bis suppression sequencing (self-attack).** Could an operator
   setting `codel-target` end up with the admission per-flow ECN arm
   suppressed while CoDel enforcement is absent (no signal at all)? Only if
   suppression and enforcement shipped in different builds. Both are Phase-2
   items in the same section; the hazard exists only if /engineer splits them.
   **MUST-PIN P1:** suppression and enforcement land in the SAME PR, with a
   unit test asserting that a codel-enabled queue under standing delay
   produces ≥1 signal (mark or drop) — i.e., the no-signal window is
   structurally impossible.

2. **§6.2c side-effect table, "nonempty/runnable NOT touched inline" row
   (self-attack — this is the riskiest row).** If a CoDel drop empties the
   queue and the loop exits with an EMPTY scratch (nothing transmitted), do
   the callers' settle paths still run the emptiness re-evaluation that
   decrements `nonempty_queues`/`runnable_queues`? The existing capacity-drop
   sites return `Drop{..}` and their callers run dedicated drop settling; the
   continue-the-loop form may exit through the `Ready`-with-empty-scratch
   path, which some callers treat as "no work" without re-evaluating
   emptiness. A stale `nonempty_queues` means wasted drain polls until the
   next push corrects it (degradation, not corruption) — but a stale
   `runnable` flag interacts with the park/timer-wheel machinery. This is NOT
   resolvable at plan level without writing the code. **MUST-PIN P2:** the
   §10 differential test must include the exact scenario "CoDel drop empties
   queue, zero items transmitted in the batch" and diff
   `nonempty_queues`/`runnable`/park state against the reference path; the
   /engineer plan must trace every caller's empty-scratch exit.

3. **Single-place gate invariant vs lifecycle.** `bucket-state.is_some() ↔
   codel_target_ns > 0` holds across: build (allocated with FlowFairState if
   target>0), lazy promote (`promote_to_flow_fair` is already `#[cold]`; the
   codel box allocates there too), demote (box dropped with FlowFairState),
   CoS config commit (full `CoSInterfaceRuntime` rebuild — consistent by
   construction). The unpromoted/FIFO-sentinel path uses an INLINE
   `CodelState` in `CoSQueueHotState` (24 B, zero = disabled) so the
   invariant does not apply there — no panic-class `.expect()` is introduced.
   State selection at the check site (`bucket == MIN_FINISH_BUCKET_FIFO` →
   `&mut queue.hot.codel`, else `&mut box[bucket]`) is a disjoint-field
   borrow against the peeked item reference — same NLL shape #1355 already
   navigates. **MUST-PIN P3:** keep the invariant structurally paired the way
   #1735 pairs `flow_fair()`/`flow_fair_state` (single constructor site), and
   `const _` assert `interval > target_max`.

4. **§6.1d attribution gate** — re-checked: the (a)+(b) split correctly
   handles the "queues stand but don't cause #1359" case (Phase 2 viable as
   bufferbloat control, not sold as the #1359 fix). No further tightening
   needed at plan level.

5. **§4 narrowed claim** — re-checked against Codex r1 #3's language; the
   claim is now scoped to "every forwarded-traffic TX terminates at the XSK
   ring" + explicit control-plane carve-out. Accurate.

## Standing answers

All seven §12 questions remain resolved as recorded in the v2 header; nothing
in the v2 deltas reopens them.
