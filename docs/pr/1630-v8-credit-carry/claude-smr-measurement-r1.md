# #1630 v8 credit-carry — Claude SMR measurement-gate analysis (r1)

Reviewer seat: Claude SMR (CoS-scheduler / WFQ-DRR / token-bucket /
AF_XDP multi-worker-shaper domain).

Phase: §3.6 MEASUREMENT-GATE (pre-implementation). The /research plan
(`docs/pr/1630-v8-credit-carry/plan.md`) converged at PLAN-NEEDS-MAJOR on
a measurement-decided fork. Per the plan, the engineer must run the §3.6
SOLO A/B FIRST and let it pick the fork before writing any production fix.

## What I ran

A throwaway probe build: bounded `elapsed = min(lag, K×EPOCH)` in
`rotate_epoch_v8.rs` (the §3.4 conceptual core — no carry reservoir, no
three-regime logic) plus the P2 per-visit frame cap + P1 N-frame bank
from `fix/1630-cos-lease-watermark @ b29fdb344`. `K` and P2 are baked at
compile time via `option_env!("XPF_COS_K")` / `option_env!("XPF_COS_P2")`
so all variants build from one tree. Deployed each variant's
`xpf-userspace-dp` helper to both `loss:xpf-userspace-fw0/1` nodes
(stop-xpfd → push → start), CoS config (`guarantee-rate 0.7`) preserved
across restarts. Ran `test/incus/cos-gate1-small-four-alone.sh push v4`
(12 streams, 20 s) plus single-port truly-solo confirmation.

## Results

Gate 1 small-four-alone (parallel):

| Variant | 100m | 1g | 3g | 6g | Gate 1 |
|---|---:|---:|---:|---:|---|
| master K=1 | 79.2 | 72.6 | 86.5 | 84.2 | FAIL |
| K=8 / P2off | 91.5 | 93.9 | 91.2 | 90.5 | FAIL |
| K=8 / P2on | 93.2 | 93.9 | 91.0 | 90.2 | FAIL |
| K=64 / P2off | 95.0 | 95.3 | 88.6 | 88.4 | FAIL |
| K=64 / P2on | 95.0 | 95.3 | 90.2 | 90.3 | FAIL |

Truly-solo (single port), master vs K=64:

| Class | master K=1 | K=64 | Δ |
|---|---:|---:|---:|
| 100m | 82.0 | 95.0 | +13.0 pp (clears) |
| 3g | 89.1 | 93.8 | +4.7 pp (no clear) |
| 6g | 89.4 | 92.8 | +3.4 pp (no clear) |

3g/6g solo held ~93-94% at 60 s with `-O5` ramp omitted — a stable
per-class ceiling, not slow-start.

## SMR judgement

The fork resolves to **NEITHER** branch the plan enumerated:

- **Fork A** (small-K=8 + P2 clears Gate 1 on 100m AND 3g): FALSIFIED.
  K=8+P2 → 100m=93.2%, 3g=91.0%, both under 95%.
- **Fork B** (only large-K=64 clears Gate 1): FALSIFIED. K=64 clears
  100m/1g but 3g/6g plateau ~88-90% (4-way) / ~93-94% (solo).

The rotation clamp is the dominant loss ONLY for the lowest-rate class:
the clamp fix (K=64) moves 100m by +13 pp (clears) but 3g/6g by only
+3-5 pp (no clear). The mid-rate exact classes carry a separate,
K-independent ~6 % residual the bounded credit carry cannot recover.

This is exactly **R6 / BLOCKING-2** the plan pre-registered: "If §3.6's
K=64 does not lift 3g to ≥95 % SOLO, the 3g loss is NOT the rotation
clamp and the root cause for that class is re-opened." §3.4 decision-rule
item 3 fires.

## Disposition (SMR)

**Do NOT implement the v8 bounded credit carry as the #1630 fix.** No
bounded-carry-class variant clears Gate 1 (each ≥95 %); Gate 1's failure
on 3g/6g is not caused by the clamp the carry targets. Shipping it would
fix 100m/1g while leaving the central #1614 regression (3g/6g <95 %)
open, i.e. it fails its own acceptance gate. This is **not** Fork B's
cross-worker-allocator blocker, so no escalation for that work. STOP and
escalate to the parent for direction on the distinct mid-rate-class
second root cause, which needs its own diagnosis round before any
production change.

The bounded-`elapsed` clamp relaxation IS a real, isolated win for the
lowest-rate classes (100m +13 pp, 1g +∼22 pp) and could ship as a
narrower fix if the parent re-scopes Gate 1 — but that decision belongs
to the parent, not this measurement gate.

Verdict: **PLAN-BLOCKED — measurement falsifies both forks; escalate.**
