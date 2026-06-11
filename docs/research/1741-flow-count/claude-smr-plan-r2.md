# #1741 plan v2 — Claude SMR hostile review (round 2)

Scope: the v2 deltas (close-path taxonomy, choreography repro, RST
correction, borrow shape, attribution hedge) plus a re-attack on the
overall narrative.

## Attacks on the v2 deltas

### B1. Is the "final pure ACK re-stamps" claim real at the call site?
Verified: the fast path is gated by `FlowCacheEntry::packet_eligible`
at `poll_descriptor/mod.rs:209` (`flags & 0x17 == 0x10` for TCP,
`flow_cache.rs:215-218`), so the client's final ACK of a close
exchange enters `stage_flow_cache_hit` → `lookup` → re-stamp
(`flow_cache.rs:665-668`). The choreography repro asserts each step
and fails on master with 10 wrap resurrections (run 2/2).
**Attack failed.**

### B2. Does the narrative depend on the FIN actually re-inserting?
No — and this makes the mechanism ROBUST, not fragile: if a closing
session's FIN did NOT re-insert (e.g., a disposition change makes
`should_cache` false for closing flows), the OLD entry with its last
data-ACK stamp would simply survive — frozen nonzero, ghost-able. The
FIN re-insert + final-ACK re-stamp path (proven by the repro) and the
no-re-insert path BOTH bank nonzero stamps for client-initiated closes.
Only "last same-direction packet was the FIN/RST itself AND it
re-inserted" ends sentinel-cleared — correctly excluded in v2 §2.
**The taxonomy is now conservative.**

### B3. RST correction accuracy.
`should_teardown_tcp_rst` returns `false` unconditionally
(`session_glue/mod.rs:621-634`) with a comment explaining the stray-RST
mitigation; `rst_teardowns` scratch is therefore always empty in
production and `worker/lifecycle.rs:235` is dead. v2 §2 now states
exactly this. **Correct.**

### B4. Borrow shape.
The plan now prescribes local `current_epoch` copy + inlined age calc
inside `iter_mut` — the shape AGY compiled and validated against the
full suite in r1. Matches Codex r1 MEDIUM. No remaining design
ambiguity for Phase 2. **Adequate.**

### B5. Attribution hedge.
v2 §2 marks per-scrape attribution of the dig-in's 3-of-6 rows as
plausible-not-demonstrated and states the plan does not rest on it.
This is the honest position; the fix is justified by the proven
mechanism + restored invariant alone. **Adequate.**

## Residual risks accepted

- The live resonance watch may not capture a spike (shared-cluster
  interference, cadence uncertainty); it is explicitly supplementary.
- The elastic (call-count) window semantics remain — documented as out
  of scope (§9); #1746 consumers get the wrap-free invariant, not a
  wall-clock-true window.

## Verdict

**PLAN-READY** (Path A as specified in v2). Both r1 HIGHs are folded
with code-quoted corrections and a deterministic production-shape
repro; no new findings survived attack.
