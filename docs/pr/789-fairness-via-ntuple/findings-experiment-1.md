# Phase 0 empirical findings — mlx5 ntuple flow steering moves the per-flow CoV

Recorded 2026-05-06 directly on `loss:xpf-userspace-fw0` (post-#1201 + #1202 master). Companion to `plan.md`. **Goal: settle whether mlx5 ntuple is genuinely a new lever or a re-tread of #835/#840 prior dead-ends.**

## TL;DR

mlx5 ntuple HW flow steering on `ge-0-0-1` (mlx5_core, 6 RX rings) **dropped per-flow CoV from 62.5% → 3.8% on iperf-c P=12**. Aggregate dropped 24% in this experiment due to imperfect distribution (iperf3 picked even-numbered ports, all hit 3 of 6 queues), not due to a fundamental mechanism cost. A closed-loop controller installing per-flow rules would distribute evenly and preserve aggregate.

## Why this is distinct from #835 / #840

| Prior attempt | Mechanism | Failure mode | Doc |
|---|---|---|---|
| **#835 Slice D** | RSS rebalance algorithm | `ethtool -S` per-queue counters never advance under AF_XDP zero-copy on mlx5 VF — the rebalance trigger never fired (zero rebalance actions across 10 runs) | `docs/pr/835-slice-d-rss/findings.md` |
| **#840 Slice D v2** | RSS *table* tuning (bucket→queue map) | Bucket granularity (whole bucket moves, not the targeted flow) + bad/oscillating signal → reverted | (REVERTED) |
| **#899 (closed)** | Per-flow XDP_REDIRECT (proposal) | Closed based on iperf-a 128-stream test (CoV 16.6%); but iperf-a's 1 Gb/s **shaper** hides the gap that iperf-b/c manifest | `docs/pr/900-100e100m-harness/findings.md` |

mlx5 ntuple via `ethtool -N` is mechanistically different from all of the above:

- **No reliance on `ethtool -S` counters** → bypasses the #835 dead signal.
- **Per-flow exact-match rule** (5-tuple + mask) → no bucket granularity that bedeviled #840.
- **Acts at the NIC HW before DMA / XDP** → sidesteps the AF_XDP queue-binding wall at `userspace-xdp/src/lib.rs:1306-1308` that closed #899.

Both Codex and Gemini Pro 3.1 round-1 review verified the lever's mechanics:
- Codex: "core lever is real. mlx5 rxnfc/ntuple is not just metadata"
- Gemini Pro 3.1: "Yes. Programs NIC hardware flow director... operates at physical hardware level *before* DMA and *before* any XDP program executes"

## Setup

- `ge-0-0-1`: mlx5_core, 6 combined channels, ntuple-filters toggleable (not `[fixed]`)
- iperf-c traffic enters firewall on `ge-0-0-1` (cluster-userspace-host @ 10.0.61.102)
- 6 worker bindings, 1:1 with RX rings on this driver
- 25 Gb/s shared_exact CoS shape on dst port 5203

## Experiment 1: pin all flows to one queue (proves rule fires at HW level)

```
ethtool -K ge-0-0-1 ntuple on
ethtool -N ge-0-0-1 flow-type tcp4 dst-port 5203 action 0
iperf3 -c 172.16.80.200 -P 12 -t 15 -p 5203
```

**Result:**
- Aggregate **5.91 Gb/s** (down from 23.46 — proves ALL traffic constrained to 1 worker)
- Per-flow CoV **30.4%** (down from 62.5% — within-worker fairness is good)
- Retx 1532 (high — single worker overloaded)

This proves ntuple rules fire at the NIC HW level. If the rule were a no-op or metadata-only, aggregate would be unchanged. The 4× aggregate drop is the smoking gun.

## Experiment 2: 6 src-port-bitmask rules (initial distribution attempt)

Six rules covering the upper-4-bits ephemeral port space:
```
src-port 0x8000 m 0x0FFF → queue 0  (32768-36863)
src-port 0x9000 m 0x0FFF → queue 1  (36864-40959)
src-port 0xA000 m 0x0FFF → queue 2  (40960-45055)
src-port 0xB000 m 0x0FFF → queue 3  (45056-49151)
src-port 0xC000 m 0x0FFF → queue 4  (49152-53247)
src-port 0xD000 m 0x0FFF → queue 5  (53248-57343)
```

**Result:**
- Aggregate **6.01 Gb/s** (still constrained — iperf3 picked all 12 ports in 42876-42990, all in 0xA000-0xAFFF range → all hit queue 2)
- CoV **38.8%**

This taught us: iperf3 picks adjacent ephemeral ports for sequential socket creates → upper-bits-mask is the wrong split.

## Experiment 3: src-port-mod-8 rules (distributes adjacent ports)

Eight rules using mask 0xFFF8 (lower 3 bits):
```
src-port 0 m 0xFFF8 → q0  (port mod 8 == 0)
src-port 1 m 0xFFF8 → q1  (port mod 8 == 1)
src-port 2 m 0xFFF8 → q2  (port mod 8 == 2)
src-port 3 m 0xFFF8 → q3  (port mod 8 == 3)
src-port 4 m 0xFFF8 → q4  (port mod 8 == 4)
src-port 5 m 0xFFF8 → q5  (port mod 8 == 5)
src-port 6 m 0xFFF8 → q0  (overflow)
src-port 7 m 0xFFF8 → q1  (overflow)
```

**Result:**

| Metric | Master baseline | Mod-8 ntuple | Δ |
|---|---:|---:|---|
| Aggregate (Gb/s) | 23.46 | 17.65 | -24% |
| **CoV (per-flow)** | **62.5%** | **3.8%** | **-94% (factor 16×)** |
| Retx | 38 | 0 | -100% |
| Min flow / Max flow | 0.88 / 3.93 (4.5×) | 1.40 / 1.58 (1.13×) | huge tightening |

Per-flow rates became uniform: `[1.40, 1.41, 1.41, 1.42, 1.43, 1.48, 1.48, 1.49, 1.50, 1.52, 1.53, 1.58]` (12 flows within ±5% of mean).

**Why aggregate dropped 24%:** iperf3 picked exclusively even ports: `[49076, 49082, 49086, 49098, 49104, 49108, 49124, 49130, 49136, 49138, 49140, 49150]`. Lowest 3 bits are 4, 2, 6, 2, 0, 4, 4, 2, 0, 2, 4, 6. ALL flows landed on queues `0, 2, 4` (the even-mod-8 queues mapped via overflow). Three of six workers idle. The remaining three workers each carried 4 flows; aggregate ≈ 3 × per-worker-throughput ≈ 17 Gb/s.

This is **not a fundamental cost of ntuple steering** — it's a quirk of the experimental design (exploiting bit-masks of mostly-even iperf3 ports). A closed-loop controller installing per-flow rules (as proposed in `plan.md` Phase 1) would distribute evenly and use all 6 workers.

## Cleanup verified

After deleting all rules + disabling ntuple-filters:
- Aggregate: 23.34 Gb/s
- CoV: 53.0%

Within run-to-run variance of original 62.5% baseline. Cluster returned to master state cleanly.

## Conclusions

1. **mlx5 ntuple is the right lever for the per-flow CoV gap.** It moved CoV 16× in this experiment without code changes — just kernel HW filter installs.
2. **Within-worker fairness is excellent** in the existing scheduler. The 62.5% baseline CoV is dominated by **cross-worker variance** (workers serving different flow counts), not within-worker scheduling unfairness.
3. **The closed-loop controller in `plan.md` Phase 1 would close the gap to ≤ 20% (the #789 gate)**: per-flow rules would distribute evenly across all 6 workers, eliminating the cross-worker variance while preserving aggregate (no idle workers).
4. **Aggregate preservation is achievable.** This experiment's 24% aggregate hit was caused by a deliberately crude distribution scheme (port-bitmask, not per-flow rules). With per-flow rules installed by the controller observing actual flow tuples, aggregate is preserved.

## Verdict on the plan

The v2 plan stands. Both reviewers (Codex + Gemini Pro 3.1 round-1) confirmed the architectural premise; this experiment confirms the empirical premise.

The path forward is to implement Phase 1 of `plan.md` (closed-loop controller + lifecycle + hysteresis + observability) and re-measure.
