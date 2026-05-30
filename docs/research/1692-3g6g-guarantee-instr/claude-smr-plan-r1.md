# Claude-SMR plan-review r1 — #1692 (HOSTILE)

Reviewer seat: Claude SMR (domain SMR: AF_XDP/CoS scheduler + CPU/memory
ordering + SW design). Mandatory hostile pass per
`feedback_triple_review_includes_claude_smr`.

Verdict: **PLAN-NEEDS-MAJOR.**

The plan correctly reframes the problem onto the shared-exact tier and
the v8 lease (a genuine improvement over #1614 v3's owner-worker framing),
and the instrument-first discipline is right. BUT the §4 distinct-
signature table — the load-bearing artifact, the thing the entire plan
exists to deliver — contains a FALSE discriminator column that I verified
against the code. The table as written CANNOT disambiguate L1-by-design
from L1-fixable, which is precisely the `feedback_review_scaffolding_
against_consumer` failure this plan is supposed to guard against. Fix
before PLAN-READY.

## FINDING 1 (HIGH, disambiguation defect) — `Σ share_i vs class_rate` is a dead column; it is ALWAYS `= class_rate`

§4 row 1 (L1-by-design) hinges on `Σ share_i < class_rate`, and row 2
(L1-fixable) on `Σ share_i ≈ class_rate`. I verified the share formula in
`rotate_epoch_v8.rs:306-312`:

```rust
let total_flows = Σ_id worker_active_flow_buckets[id]   // :209-214, idle=0
let my_share = (new_cap as u128 * my_count as u128 / total_flows as u128)  // :308
```

Therefore `Σ_i my_share_i = new_cap × (Σ_i my_count_i) / total_flows =
new_cap × 1 = new_cap = class_rate × elapsed`. **The per-worker shares
sum to the full class cap BY CONSTRUCTION, every epoch, regardless of how
the flows are distributed.** Idle workers contribute 0 to both numerator
and the sum, so they do not reduce `Σ share_i`. The column can NEVER be
`< class_rate`. Rows 1 and 2 are indistinguishable on this column;
worse, the column is constant.

The plan's own §8 PLAN-KILL exit #1 ("Σ share_i < class_rate") is
therefore unreachable as written, and §4's claimed L1-by-design vs
L1-fixable separation collapses.

**The REAL L1-by-design mechanism** (which the plan gestures at in §2-L1
prose but the table fails to encode) is a DEMAND/SHARE MISMATCH, not a
share-sum deficit: each worker is capped at `my_share_i`, and the class
under-delivers iff `Σ_i min(local_demand_i, my_share_i) < cap` — i.e.
some workers' RSS-placed 3g flows offer LESS than their allotted share
(leaving grant unclaimed) while peers offer MORE (and are capped, cannot
borrow because surplus is bypass-gated and shaper-bound traffic never
arms bypass). The correct discriminating columns are:

- `granted_i` vs `share_i`: if `granted_i < share_i` on the BUSY workers
  (demand-limited they would equal; if granted < share with backlog
  present, the lease is refusing) — this separates "lease caps me" from
  "I didn't ask".
- per-worker BACKLOG (`queued_bytes_i` for the class, already on
  `queue.hot.queued_bytes`): a worker with `granted_i ≈ share_i` AND
  persistent backlog is share-capped (L1-by-design); a worker with
  `granted_i < share_i` AND backlog is being refused by the lease
  (L1-fixable / L2 / L3).
- the EXISTENCE of at least one worker with `granted_i < share_i` while
  another worker is backlogged-and-capped is the by-design signature
  (work would be conserved by letting the capped worker borrow the idle
  worker's slice — exactly what bypass-gated surplus refuses).

§4 must be rebuilt with `queued_bytes_i` (per-worker backlog) added to
the octuple and `Σ share_i` DELETED as a discriminator. Without this the
plan fails its own consumer criterion.

## FINDING 2 (HIGH, disambiguation gap) — the table cannot see DEMAND, so L1-by-design and "demand-bound (not a defect at all)" alias

Even after Finding 1, the table has no column for per-worker OFFERED LOAD
(demand). The §1 signal is that small4+24g reached only 18.2 G with ~6 G
idle. If the 3g flows are simply DEMAND-bound on the workers they landed
on (TCP cwnd / generator-side, the #1630 cause-2 transport-physics floor
at low per-worker parallelism), then `delivered_i < share_i` on every
worker NOT because any layer gates it but because the flows don't offer
that much — and NO scheduler change recovers it. This is the #1630
cause-2 / #1220 precedent and it is a FOURTH outcome the plan's §7
"exactly one of {L1,L2,L3}" criterion does not enumerate.

The plan MUST add a demand/backlog column (`queued_bytes_i` is the
cheapest proxy: if a worker's class backlog is ~0, it is demand-bound,
not gated). Decision rule precedence must become: **(0) demand-bound
[backlog≈0 → not a CoS defect, the cause-2 floor, PLAN-KILL] → (1) L2 park
→ (2) L3 admit-vs-visit → (3) L1 share-cap-with-backlog.** Without the
demand column the instrument cannot tell a gated worker from a
cwnd-starved one — and #1630 cause-2 already proved the mid-rate classes
sit on a transport floor that WORSENS at low per-worker parallelism. That
is the single most likely real answer and the current §4 is blind to it.

## FINDING 3 (MEDIUM) — `delivered_i ≈ granted_i` is not a clean signal; the token bucket banks across epochs

§4 uses `delivered_i ≈ granted_i` as an L1 confirmer. But
`token_bucket.rs:196-214` (the #1630 P1 N-frame bank) accumulates
unspent grant into `queue.hot.tokens` ACROSS epochs (saturating_add up to
`buffer_bytes`). So within a measurement window, `granted` (lease
acquisitions) and `delivered` (drain_sent) can diverge by up to the bank
depth without indicating any gating — a worker can bank grant in epoch N
and spend it in epoch N+1. Over a 30 s steady-state window the rates
converge, but the plan must specify that the comparison is on the
WINDOWED RATE (bytes/30s), not instantaneous, and that the bank depth
(`COS_EXACT_QUEUE_LEASE_BANK_BYTES`, N=8 frames ≈ 12 KB) is below the
noise floor of a 30 s × 3 G window. State this explicitly or a reviewer
re-derives it as a defect.

## FINDING 4 (MEDIUM) — Option B `my_share` read IS race-free, but `v8_granted` per-class accumulator needs care; Option A truncation risk is real and under-stated

Option B's `my_share` read: `worker_fair_share[worker_id]` is an
AtomicU64 read Relaxed (`shared_cos_lease/mod.rs:409, 1588-1592`). A
control-socket dump reading it off the Arc the worker holds in
`queue.queue_lease_v8` (`token_bucket.rs:146`) is race-free in the sense
that matters (a slightly-stale share snapshot is fine for a steady-state
delta). CONFIRMED feasible. Good.

BUT the per-(queue,worker) `v8_granted` accumulator (the one genuinely
new counter, §5 Option A item 3 / folded into B) must be written by the
OWNING worker only and read on the status/RPC path — it is single-writer
per (queue,worker), so a Relaxed accumulator is fine, but the plan should
say so explicitly (it currently hand-waves "no new atomics on
acquire_v8", which is true, but the new per-queue field IS a new
worker-local counter that the status path reads cross-thread; name its
ordering).

Option A truncation: the plan flags it as a PLAN-KILL trigger but
under-quantifies. `cos_active_flow_counts_truncated` exists
(`docs/fairness-regimes.md`), and 11 classes × 6 workers = 66 rows; adding
6 u64/row to the shared-exact subset (q≥2.5G: ~9 of 11 classes × 6 = 54
rows × 6 u64 = 2.6 KB) is plausibly under the snapshot cap but the plan
asserts this without checking the actual snapshot bound. Option B sidesteps
it entirely, which is why B is correctly recommended — but the plan should
state the snapshot-cap number it is avoiding, not just assert "avoids it".

## FINDING 5 (LOW) — L2 is more dead than the plan admits; say so to narrow the search

§2-L2 keeps root-FCFS alive "on the narrow chance the aggregate
park_root=0 masks a per-worker imbalance." Verified: `park_root` is bumped
per-queue per-worker at `queue_service/mod.rs:856-861` BEFORE the
cross-worker sum, and #1614 §2.1/§2.4 reports park_root=0 in EVERY
scenario including the decisive small4+24g. For the root pool to starve
ONE worker's 3g while the per-class sum reads 0, that worker would need
park events that sum to exactly 0 across workers — impossible for a
monotonic counter (sum=0 ⟺ every term=0). **So the aggregate park_root=0
ALREADY proves no worker hit root starvation** — L2 is dead, not
provisionally dead. The plan can drop L2 from the live candidate set and
say the instrument confirms it for completeness only. This tightens the
disambiguation to a genuine two-way (L1-share-cap vs L3-budget) plus the
demand-bound null from Finding 2 — a cleaner consumer contract.

## What is RIGHT (do not regress in v2)

- The shared-exact-tier reframe (§2) is the key insight and is
  code-correct (`worker/cos/mod.rs:31,168`, `cross_binding.rs:69`
  verified).
- The per-class-SUMMED-across-workers blind spot (§3) is real and
  precisely the right gap (`coordinator/mod.rs:1048-1053` verified).
- Option B over a production-gauge approach is the right call
  (cardinality + throwaway discipline).
- The PLAN-KILL exits and the "instrument must DECIDE, not be merely
  correct" consumer criterion (§7) are exactly the right framing — they
  just need Finding 1+2's corrected columns to be satisfiable.

## Required for PLAN-READY (v2)

1. Delete `Σ share_i vs class_rate` from §4 (Finding 1); rebuild the
   table around `granted_i vs share_i` + per-worker `queued_bytes_i`
   backlog.
2. Add a per-worker DEMAND/backlog column and a precedence-0 "demand-
   bound → #1630 cause-2 floor → PLAN-KILL" outcome (Finding 2).
3. Specify windowed-rate comparison + state the bank depth is sub-noise
   (Finding 3).
4. Name the new counter's memory ordering; state the snapshot-cap number
   Option B avoids (Finding 4).
5. Demote L2 to "confirmed dead by monotonic-sum logic; instrument only
   for completeness" (Finding 5).
