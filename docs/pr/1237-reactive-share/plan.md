## v1 PLAN-KILLED 2026-05-09 — convergent Codex + Gemini

Both reviewers convergent kill with sharp arguments:

1. **Causality inversion** (Gemini): worker at 72% of primary means
   primary is NOT the bottleneck. Boosting share doesn't help; just
   steals from healthy peers via normalization.
2. **Bang-bang oscillation** (Gemini): high-demand worker capped at
   0.8× nominal next epoch reads as below target → boost to 1.2× →
   over → cut → cycle.
3. **Aggregate regression via normalization** (both): worst case 3
   slow + 1 fast → fast worker crushed to 0.72× nominal.
4. **CPU-bound case fatal** (Codex): boosting CPU-bound worker
   wastes budget; cuts healthy peers.
5. **Bypass interaction NOT independent** (Codex): #1231 v5.5
   uses my_share in starvation signal; v7 modifying my_share
   masks under-utilization, strangles bypass.
6. **Root cause not established** (Codex): low CPU doesn't prove
   TCP cwnd; could be RX queue, TX completion, etc.

**Convergent recommendation from both reviewers: pivot to #1239
(surplus per-flow proportional).** Per-flow primary is already
equal in v8 (cap/total per flow). Variance comes from per-worker
surplus distribution. Fix surplus to flow-proportional → per-flow
rate = (cap + surplus) / total = EQUAL by construction.


# #1237 v1: Per-worker reactive lease share — closed-loop adjustment

**Status:** DRAFT v1 — pending Codex hostile + Gemini Pro 3 adversarial review

## Issue framing

After PR #1235 (#1231 v5.5 bypass-grace) merged + #1236 v1 (global
per-flow cap) PLAN-KILLED, per-flow CoV on iperf-d 12-stream still
varies 5.6-37.5% across runs (mean 18%) due to per-worker rate
asymmetry that **isn't CPU-bound** — workers are at 5-6% CPU.

Empirical decomposition (single iperf-d run):

| Worker | Flows | Primary share | Actual | Util | Per-flow |
|--------|-------|---------------|--------|------|----------|
| α | 4 | 4.33G | 3.13G | **72%** | 784 |
| β | 3 | 3.25G | 2.82G | 87% | 941 |
| γ | 2 | 2.17G | 2.14G | 99% | 1069 |
| δ | 3 | 3.25G | 3.49G | **107%** | 1163 |

Worker α at 5.8% CPU consumes only 72% of its primary share.
Worker δ at 5.9% CPU exceeds primary share via post-grace surplus
claim. Per-flow rate variance follows from this asymmetry.

**Root cause hypothesis:** TCP cwnd self-reinforcement. Each
worker's actual TX rate becomes the per-flow bottleneck for its
flows. cwnds converge to (worker_rate / num_flows). Different
workers → different cwnds → different per-flow rates.

The per-worker share in v8 is STATIC: `(flows_on_worker / total)
× cap`. Static allocation can't compensate for cwnd-driven
under-utilization.

## Honest scope/value framing

v7 mechanism: at each rotation, observe each worker's actual TX
rate (from packed_granted swap return). Compare to target rate
(`flows_on_worker / total × cap`). Adjust per-worker fair share
in the NEXT epoch:

- If worker is below target × 0.85 → boost its share (helps it
  acquire MORE tokens, drives cwnds higher per flow)
- If worker is above target × 1.15 → cut its share (forces it to
  consume less, frees budget for other workers)

Predicted outcome:
- Workers converge toward equal per-flow rate within 5-10
  rotations (1-2 ms)
- Aggregate preserved (no Harrison Bergeron — slow workers get
  MORE share, not less)
- Per-flow CoV drops to ≤10% mean across runs

**If reviewers conclude the control loop oscillates, doesn't
converge, or breaks aggregate, PLAN-KILL is acceptable.**

Specific KILL triggers:
- Control loop oscillates (workers swing between boost/cut without
  settling)
- Convergence time exceeds 1 epoch (RSS distribution changes
  faster than the loop)
- Aggregate regression > 3% on iperf-c saturated case
- Cannot distinguish from #1239 (surplus per-flow proportional)
  without empirical evidence both are needed

## What's already shipped

- **#1229 v8** (PR #1230): per-worker fair-share lease, hierarchical
  scheduler, atomic-swap rotation.
- **#1231 v5.5** (PR #1235): bypass-grace detector for cross-class
  CPU-bound regime. Peer-utilization gate at 60%.

The lease's per-worker `worker_fair_share` is computed at rotation
from `worker_active_flow_buckets`. v7 introduces an adjustment
factor based on observed rate.

## Concrete design

### v1.1 Per-worker observed rate

`packed_granted.swap` at rotation already returns prior-epoch
total class grants. We need PER-WORKER prior-epoch grants.

`worker_grants[id]` is also packed (epoch_tag, granted). Already
swapped at rotation. Returned old value = worker's prior-epoch
granted bytes. Use this directly.

### v1.2 Adjustment factor

Per-worker share adjustment:

```rust
let target_grant_per_worker = (cap as u128 * worker_flows / total_flows) as u64;
let observed_grant = prev_worker_grant;
let ratio = (observed_grant as f64) / (target_grant_per_worker as f64).max(1.0);

let adjustment = if ratio < 0.85 {
    // Worker under-consumed primary. Boost next-epoch share by 1.2×.
    1.2_f64
} else if ratio > 1.15 {
    // Worker over-consumed (claimed surplus aggressively). Cut to 0.8×.
    0.8_f64
} else {
    // Within ±15% of target. No adjustment.
    1.0_f64
};

// Apply adjustment to next epoch's per-worker share.
// Bounded: total adjusted shares must still ≤ cap.
let raw_share = (cap as u128 * worker_flows / total_flows) as u64;
let adjusted_share = (raw_share as f64 * adjustment) as u64;
```

After computing all workers' adjusted shares, normalize so sum ≤ cap:

```rust
let total_adjusted: u64 = adjusted_shares.iter().sum();
if total_adjusted > cap {
    // Scale down proportionally.
    let scale = (cap as f64) / (total_adjusted as f64);
    for share in adjusted_shares.iter_mut() {
        *share = (*share as f64 * scale) as u64;
    }
}
```

### v1.3 Convergence properties

After K rotations:
- If worker α is at 72% of share: 1.2× boost → next epoch 86%
  → 1.0× (within band) → stable at ~86%
- If worker δ is at 107%: 0.8× cut → next epoch 86% → stable at
  ~86%

Both workers converge to ~86% of their static fair share.
Aggregate = 86% × cap (same as before). Per-worker rates
equalize at 86% × (flows / total) × cap.

Per-flow rate = 86% × cap / total. EQUAL across workers.

CoV → 0 in steady state (excluding TCP cwnd noise).

### v1.4 Implementation

1. **Capture** per-worker prev_grant at rotation (already in code:
   `worker_grants[id].swap` returns old value).
2. **Compute** adjustment factor per worker.
3. **Apply** to share computation (`worker_fair_share[id]` set with
   adjustment factor multiplied in).
4. **Normalize** total share ≤ cap.

Add to `V8State`:

```rust
struct V8State {
    // ... existing fields ...
    /// #1237 v7: per-worker prev-epoch granted bytes, captured by
    /// rotation's atomic-swap. Used to compute next-epoch adjustment.
    worker_adjusted_share_factor: Box<[AtomicU64]>,  // Q24.8 fixed-point factor
}
```

Or simpler: just recompute fair share at rotation using observed
prev_grant directly:

```rust
let observed = prev_grants[id] as u64;
let nominal = (cap as u128 * worker_flows[id] as u128 / total_flows as u128) as u64;
let new_share = compute_adjusted_share(observed, nominal);
worker_fair_share[id].store(new_share, Release);
```

### v1.5 Safeguards

- **Hysteresis band**: ±15% no-op zone prevents oscillation.
- **Adjustment caps**: 1.2× boost / 0.8× cut bounds per-epoch
  change rate.
- **Normalization**: total share ≤ cap always.
- **Reset on RSS change**: if total_flows changes (new flow enters
  or leaves), reset shares to nominal (don't carry stale
  adjustment).

## Public API preservation

- `SharedCoSQueueLease::new_v8` signature unchanged.
- `acquire_v8` signature unchanged.
- New internal state: per-worker prev-grant captured at rotation
  (already implicit in `worker_grants.swap`).

## Hidden invariants

1. **Aggregate cap**: sum(adjusted_shares) ≤ cap, normalization
   enforces.
2. **Convergence stability**: ±15% hysteresis band prevents
   oscillation.
3. **Bounded adjustment per epoch**: 1.2× max boost / 0.8× max
   cut.
4. **No interaction with #1231 v5.5 bypass**: bypass operates on
   surplus path; v7 adjusts primary share. Independent.

## Risk assessment

| Class | Severity | Notes |
|-------|----------|-------|
| Behavioral regression | LOW | Falls back to static share when no rate observation available (e.g., first epoch). |
| Lifetime/borrow-checker | LOW | New atomic per worker. |
| Performance regression | LOW | 1 division + 2 atomic loads per worker per rotation. ~6 workers × 30 ns = 180 ns/rotation. Trivial. |
| Convergence | MED | Control loop must converge within 1-2 ms (5-10 rotations). Empirical validation required. |
| Aggregate regression | LOW-MED | When worker truly is CPU-bound, boosting its share won't help; share gets capped → may slightly reduce aggregate. Bounded by hysteresis. |

## Test plan

- Cargo build clean.
- Cargo test --release: 1086+ tests pass.
- New tests:
  - `share_adjustment_boost_when_underutilized`
  - `share_adjustment_cut_when_overutilized`
  - `share_adjustment_hysteresis_band_no_op`
  - `share_adjustment_normalize_to_cap`
  - `share_adjustment_resets_on_total_flow_change`
- Cluster smoke matrix:
  - **Pass A** (CoS off): no regression vs v8 + v5.5
  - **Pass B** (24 per-class): no regression
  - **iperf-d 12-stream 10-sample mean CoV ≤ 10%** (target)
  - **iperf-c push 12-stream**: aggregate ≥ v5.5 mean (no regression)
  - **iperf-e 12-stream**: per-flow CoV ≤ v5.5 mean

## Out of scope

- Cross-binding flow re-steering (#937 PLAN-KILLED)
- Per-flow ECN/AFD overlay (#1211 PLAN-KILLED)
- Sender-side TCP head-start (#1233)
- 5-worker mode (#1243)

## Open questions for adversarial review

1. **Convergence time**: 1-2 ms claimed. RSS distribution may
   change as TCP flows establish. Will the loop track? Or
   oscillate?

2. **Hysteresis band (±15%)**: too narrow → oscillation; too wide
   → slow convergence. 15% picked from gut feel; empirical
   sweep needed.

3. **Adjustment magnitude (1.2×/0.8×)**: too aggressive →
   overshoot; too gentle → slow convergence. Same empirical
   sweep needed.

4. **Worker fully CPU-bound case**: v7 boosts share but worker
   can't consume more anyway. Boost wastes budget that could
   go to faster peers. Does v7 break iperf-c saturated regime?

5. **Interaction with #1231 v5.5 bypass**: bypass arms when
   peers under-utilize → opens surplus immediately. v7 boosts
   under-utilizing workers' SHARE → reduces surplus available.
   These work in tension. Is the combined behavior still
   correct?

6. **Reset criteria**: when does adjusted share reset to
   nominal? On total_flows change. But minor flow churn
   (one flow ends, another starts) shouldn't reset everyone.
   Hysteresis on total_flows change?

7. **Does this fix per-flow CoV root cause?**: my hypothesis is
   TCP cwnd self-reinforces per-worker rate asymmetry. v7 boosts
   slow workers → their cwnds rise → flows equalize. If hypothesis
   wrong (e.g., dominant cause is RX queue depth), v7 won't help.

8. **Fixed-point math**: float operations in rotation hot path?
   Or use integer Q-format. ~10ns difference per worker; not
   measurable.

9. **First-epoch behavior**: no prior rate observed. Static
   share. Subsequent epochs adjust. Acceptable transient?

10. **Code review readiness**: ~80 LOC core (rotation +
    accessor) + 100 LOC tests. Simple control loop.

## Implementation effort

~80 LOC core + ~100 LOC tests + smoke validation. ~3 hours
focused work. Triple review (Codex hostile + Gemini Pro 3
adversarial) before implementation.
