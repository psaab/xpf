# #1741 plan v1 — Claude SMR hostile review (round 1)

Reviewer stance: domain SMR (dataplane telemetry), CPU/data-structure
design, hostile-by-default. I attempted to refute the plan's mechanism
and its fix before accepting either.

## Attacks attempted and outcomes

### A1. Refute the mechanism: are dead entries really persistent?
Checked every eviction path: stale-stamp on lookup
(`flow_cache.rs:614-653`), RST teardown (`worker/lifecycle.rs:235`),
HA-invalid (`poll_descriptor/flow_cache_hit.rs:113`), set-collision LRU
(`flow_cache.rs:700-712`), `invalidate_all` (dead code outside link
events). There is NO FIN/timeout/GC eviction of flow-cache entries —
conntrack GC removes sessions, not per-binding cache entries. A
FIN-closed flow's entry persists with a frozen `last_used_epoch`.
**Attack failed; mechanism's precondition holds.**

### A2. Refute the wrap arithmetic.
`active_entry_age` (`flow_cache.rs:453-460`):
`current_epoch.wrapping_sub(last_used_epoch) < 10` with both u16 and a
65535-long cycle (0 skipped in `tick_advance_epoch`,
`flow_cache.rs:427-432`). For frozen stamp L, age re-enters [0,10) when
current wraps to [L, L+10). The repro test confirms: resurrection for
exactly 10 ticks, first at tick 65519 after stamping at epoch 1 and
aging 15 ticks (65519 + 15 + 1 = 65535 = cycle length ✓ — the arithmetic
is internally consistent, not a test artifact). Deterministic 3/3.
**Attack failed.**

### A3. Refute "tick and scan are co-located" (clamp airtightness).
`tick_advance_epoch` has exactly ONE production call site
(`umem/debug_state.rs:230`) and `active_flow_debug_entries` exactly one
(`debug_state.rs:234`), four lines apart in the same function
(`publish_binding_debug_state`), reached from both the hot mask path and
the #1294 idle wall-clock path. An epoch can never advance without the
clamp scan running in the same call — a wrap cannot slip past Path A.
Also verified the scan walks ALL entries regardless of the row `limit`
(`flow_cache.rs:489-492`: counting continues after `truncated`), so the
clamp coverage is not limit-bounded.
**Attack failed; Path A is structurally airtight.**

### A4. Does the clamp change counting semantics (new under-count)?
No. An entry at age >= 10 is ALREADY excluded from the count
(`age < ACTIVE_WINDOW_EPOCHS`). Clearing its stamp to the 0 sentinel
changes only future wrap behavior. A returning flow re-stamps on its
next lookup hit (`flow_cache.rs:665-668`) and is counted again — the
sentinel is recoverable. `observed_bytes`, LRU position, and the cached
decision are untouched. Boundary: age 9 counted and NOT clamped; age 10
uncounted and clamped — must be pinned by a test (plan §6 has it).
**No semantic regression found.**

### A5. Attribution honesty: does the ghost explain 3-of-6 bad scrapes?
This is the plan's weakest claim and it must stay hedged. The per-scrape
hit probability depends on the load-dependent tick cadence (mask
0xFFFF on CALLS, several call sites per poll tick — wall period is NOT
a constant 65 ms) and on how many dead cohorts had been banked across
the dig-in's hours of runs and 6+ bindings with independent epoch
phases. The plan correctly claims mechanism + shape (per-worker spikes,
intermittency, truncation=0), and explicitly does NOT claim per-scrape
attribution. I verified no SECOND over-count mechanism is visible:
dedup-on-insert preserves one-way-per-key (`flow_cache.rs:677-696`);
cells are per-egress-ifindex so direction pairs cannot collide
(kill-round result, still true); the coordinator sums disjoint
per-binding snapshots keyed by (ifindex, queue, worker)
(`status.rs:359-384`) with no double-walk. Residual transient
(≤650 ms) duplication after an RSS re-steer is possible but is windowed
by design and was already classified second-order in the kill round.
**Acceptable with the hedge already present in plan §2.**

### A6. Path B straw-man check.
Path B (u32) is honestly assessed: it does not remove the ghost class,
grows a hot struct, and is dominated by A. Not a straw man — A is
genuinely smaller and stronger.

## Required-for-round-2 (none blocking)

- R1: plan §6 should make the boundary test explicitly assert the
  clamp does NOT fire at age 9 (present, keep).
- R2: the /engineer PR must update the stale doc comments that still
  say "count_active_flows" is the production scan (it is #[cfg(test)];
  the production scan is `active_flow_debug_entries`) — plan §8 covers
  module-comment updates; fold this in.

## Verdict

**PLAN-READY** (Path A), contingent on Codex/AGY not producing a
counter-example to A1-A4. The mechanism is proven by a deterministic,
runnable repro; the fix is single-call-site, zero packet-path cost, and
restores a crisp invariant the fairness consumers (#1746) can rely on.
