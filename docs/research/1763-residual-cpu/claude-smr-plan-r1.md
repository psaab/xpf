# Claude SMR hostile review — #1763 plan v1, round 1

Reviewing as domain SMR (CoS/MQFQ scheduler), CPU microarchitecture, and SW
design. Verdict: **PLAN-NEEDS-WORK — the v1 KILL of Path 1 is wrong.**

## Where v1 is right

- **Measurement of N = 14 is sound and decisive.** `active_flow_buckets_peak`
  (cos.rs:781) is max-only (accounting.rs:37, push.rs:380/411), reset only on
  `FlowFairState` realloc. Exact queues promote eagerly (admission.rs ~525) and
  `maybe_demote_drained_best_effort` early-returns on `queue.config.exact`
  (mod.rs:223), so an exact queue's peak is a true lifetime max and 14 is not
  an undercount. The 48-flow → 14-bucket collapse is correct (drain rate >
  arrival, small instantaneous backlog set).
- **A min-heap IS the wrong structure at N=14** — v1's reasoning holds (key
  mutates every pop at pop.rs:163 → re-heapify per dequeue; two-key
  eligible/fallback can't be one heap). KILL the *heap* idea: correct.
- **Path 2 KILL is correct.** `neigh_add` = 0/s measured; the kprobe is the
  right RTM_NEWNEIGH handler. KILL stands.

## Where v1 is WRONG — it killed the whole path on the heap straw-man

v1 only evaluated *replacing the data structure* (heap / incremental pointer /
SoA packing) and never asked **how many times the existing scan runs per pop.**
It runs TWICE per successful dequeue on BOTH hot paths, with no queue mutation
between, so the second scan re-derives the identical bucket:

- Cap-aware drain: `cos_queue_front_with_cap` (drain.rs:209) → inspect → then
  `cos_queue_pop_front_with_cap` (drain.rs:234) re-scans. Same `target_bps`
  ("sampled once… same value used for every pop", drain.rs:206-208), same ring,
  same winner. Prepared path identical (drain.rs:461/472).
- No-cap best-effort builder: `cos_queue_front` (mod.rs:1605) → `cos_queue_pop_front`
  (mod.rs:1617) re-scans. Repeated at mod.rs:1646/1658.

Each `front*` and each `pop*` calls `cos_queue_min_finish_bucket` (mod.rs:81/136/158).
So the 4.28% pop self-time is paying the scan once for the peek and once for the
pop — **~2× the necessary scan work on the dominant path.**

### Safe lever A (Codex) — fuse select+pop
A `peek`-returning-bucket-id + `pop_known_bucket(bucket)` helper removes one
full scan per pop. Preserves MQFQ ordering *exactly* (pops the bucket the peek
selected — identical to today's behavior, which relies on the second scan
returning the same winner). Preserves the eligible/fallback two-pass. No heap,
no layout change. ~halves the scan on the cap-aware drain.

### Safe lever B (AGY) — no-cap fast path
For `target_bps == u64::MAX` (every `cos_queue_front`/`cos_queue_pop_front`
caller — i.e. the whole best-effort builder, mod.rs:1597-1658), the
`flow_bucket_observed_bps` load (mod.rs:113) and the eligible/fallback split are
dead: `observed <= u64::MAX` is always true, so `eligible == fallback` always.
A `target_bps == u64::MAX` branch that scans only `flow_bucket_head_finish_bytes`
removes the second strided big-array load per bucket — halves the cache-miss
exposure (the two arrays are different cache lines) with zero ordering change.

Levers A and B are **complementary** (A removes a whole scan; B halves each
remaining scan on no-cap callers) and **compose** — a fused `peek+pop` that also
takes the no-cap fast path gets both wins. Combined, the realistic upside on the
4.28% is meaningful (a fused no-cap pop does ~1 single-array O(14) scan instead
of 2 double-array O(14) scans → up to ~3-4× less scan work on the best-effort
path), all fairness-neutral by construction.

## Required plan changes

1. Path 1 → **PLAN-READY** for a fused-select-pop + no-cap-fast-path refactor
   (explicitly NOT a heap / not a structure change / not touching selection
   ordering, cap arithmetic, or the eligible/fallback semantics).
2. Spell out the fusion contract: the peek must return the *bucket id* (not just
   the item ref), and `pop_known_bucket` must assert the bucket is still the
   front-of-active (debug_assert) since no mutation occurs between. Handle the
   early-`break` paths in drain.rs (budget/mirror-reserve) — if the caller
   peeks then breaks WITHOUT popping, no scan is wasted vs today (today it also
   only did the front scan), so fusion is strictly ≤ current cost.
3. Validation: property-differential (fused vs current produce identical dequeue
   order on randomized backlogs incl. over-cap mixes), CoV-neutrality on the
   full v4/v6 × push/-R × CoS-on matrix, `make test-failover` (exact-queue HA
   sync), and a re-measure of pop self-time on the live cluster to confirm the
   win.
4. Keep Path 2 KILL.

## One caution for the implement phase

The fusion must NOT change behavior when `front` is inspected but the item is
then *rejected* (drain.rs:217 budget break, :221 mirror-reserve). Today those
paths peek (1 scan) and break without popping. The fused API must let the caller
peek the bucket id, inspect the item, and EITHER pop-known-bucket OR abandon —
the abandon path must be exactly 1 scan (same as today), the pop path 1 scan
(vs today's 2). Net: strictly non-regressing.
