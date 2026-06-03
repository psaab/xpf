# Reactive cross-worker flow rebalance (`class-of-service flow-rebalance`, #1748)

> **Default-OFF, opt-in.** Absent config ⇒ the userspace-dp controller is
> never constructed, no ethtool ioctl socket is opened, zero ntuple rules are
> installed, and the per-tick decision loop never runs. The forwarding path is
> byte-identical to a build without this feature when the knob is unset.

## What it does

The per-flow throughput coefficient-of-variation (CoV) on shaped ports swings
14–29% under many concurrent flows because RSS hashes the N flows unevenly
across the NIC's RX queues. Each RX queue maps to one worker, so workers serve
different flow *counts*, and a worker's fixed capacity splits among *its*
flows — slow flows on the crowded worker, fast flows on the idle one.

The #1746 equal-flow cap can only clip fast flows *down*; it cannot lift slow
flows. The only lever that lifts slow flows **and** preserves aggregate
throughput is moving an established flow off an overloaded worker onto an idle
one. This controller does that automatically: it **count-balances** — it
observes the per-worker steerable-flow COUNT, and when the busiest worker
carries materially more flows than the idlest, it installs one exact-5-tuple
ntuple flow-steering rule (`ethtool -N`-style, via a direct `SIOCETHTOOL`
ioctl) that re-pins one flow from the highest-count worker to the lowest-count
worker. Over a few moves the count partition converges toward even (e.g.
`2,2,2,2,2,2` across 6 queues), which for homogeneous (equal-rate) traffic is
the fair floor.

> **#1751 design note.** The selector is COUNT-based, not byte-rate-based. The
> earlier byte-rate selector never installed a rule under load because the
> per-flow byte-rate signal was unreliable (the flow-cache `observed_bytes`
> counter resets on eviction). The per-worker flow COUNT is reliable, and a
> manual count-balanced re-pin on the cluster drove per-flow CoV to ~3% with
> aggregate preserved (the R1 spike + the #1751 CoS-ON pre-code gate).

## Configuration

```
set class-of-service flow-rebalance count-delta 2
set class-of-service flow-rebalance rebalance-interval 1
set class-of-service flow-rebalance max-rules 64
```

Each sub-leaf is individually optional, but the `flow-rebalance` block is
created by setting at least one of them. Setting any one sub-leaf enables the
controller; the unset sub-leaves take the defaults below.

| Leaf | Units | Default | Range | Meaning |
|---|---|---|---|---|
| `count-delta` | flows (K) | 2 | 2–64 | Move only when the busiest worker carries at least K more steerable flows than the idlest (`max_count − min_count ≥ K`). |
| `imbalance-threshold` | percent | — | 101–1000 | **Deprecated** (the #1748 byte-rate threshold). Parsed for config back-compat but **ignored** by the count-balancing decision. |
| `rebalance-interval` | seconds | 1 | 1–3600 | Minimum dwell between rule installs (one move per interval). |
| `max-rules` | rules | 64 | 1–1024 | Hard cap on concurrently-installed ntuple rules per interface. At the cap the controller STOPS — it never evicts an existing rule. |

To disable, delete the block:

```
delete class-of-service flow-rebalance
```

On disable (or any config change to the block), every installed rule is torn
down — a still-live move hands ownership back to the original worker before its
rule is removed, so no flow is dropped and no orphan hardware rule survives.

## Selection logic (why it converges and does not thrash)

Per tick (coordinator status cadence, ~1 Hz — never per-packet):

1. Count the steerable flows per worker, from the SAME flow-worker-map snapshot
   the candidate 5-tuples come from (count and rows are one object, so the
   count can never disagree with the available rows).

   **PRESENCE, not recent activity.** The flow-worker-map rows that feed this
   count include every flow PRESENT in a worker's flow cache within a ~10 s
   presence window — NOT only flows that saw a packet in the last ~650 ms.
   These are two distinct windows over the same scan: the narrow ~650 ms
   *active* window still backs the `binding_active_flow_count` /
   `cos_active_flow_count` activity metrics, while the wide ~10 s *presence*
   window backs the rebalance count. The reason: the controller must select on
   the FIXED, deterministic RSS placement of live flows, not momentary packet
   activity. On bursty/uncapped traffic a flow briefly idles past 650 ms, drops
   out of a narrow activity window, then bursts again and reappears — which made
   the per-worker count FLICKER even though placement never changed, so the
   controller made redundant moves and over-installed ntuple rules to the cap
   (live regression on the uncapped port). The presence window is wider than any
   burst-idle gap, so the count is stable; it is still BOUNDED — a genuinely
   ended flow ages out within ~10 s and its rule is freed, and an explicit
   RST/teardown/RG-change/rebalance-demote eviction drops it immediately.

   **Each flow is counted exactly once, at its current owner.** When a flow is
   rebalanced, the old worker keeps an abandoned forward copy (origin
   `RebalancedOut`) for local-only cleanup; that copy must NOT be counted (the
   flow now lives on the new worker's `RebalancedOwner` copy). The old worker
   therefore EVICTS the abandoned copy from its flow cache the instant it is
   demoted, so the very next snapshot reflects the flow's departure — and the
   selector additionally refuses to count or re-select any `RebalancedOut` row
   that might briefly linger. Without this exactly-once rule a recently-moved
   flow was double-counted (old + new worker), which made the controller keep
   moving flows off an already-drained worker and never converge.
2. **Anti-churn gate (deadband + sustained dwell).** The controller treats the
   imbalance magnitude `delta = max_count − min_count` through a deadband so it
   does NOT chase the tick-to-tick count fluctuations bursty traffic throws off
   around the even partition:
   - **settle / stop band** — as soon as `delta ≤ 1` (the even-partition
     target) the placement is marked SETTLED and the controller stops. This is
     what makes `installs_total` and `deletes_total` STOP climbing the instant
     the fleet is balanced (steady state = zero churn).
   - **arm threshold + sustained dwell** — while SETTLED, a move is reconsidered
     only when a *real* imbalance `delta ≥ K_high` (`K_high = max(K, 2)`)
     reappears **and persists for `DWELL_TICKS_REQUIRED` (3) consecutive
     evaluation ticks**. A single-tick blip resets the dwell counter, so a
     transient burst never triggers a move. Each subsequent move independently
     re-requires a full dwell window (the dwell counter is reset after every
     move), so the controller cannot rapid-fire moves down a noisy gradient.
3. Move one flow from the highest-count worker (`hi`) to the lowest-count
   worker (`lo`), subject to:
   - **overshoot guard** — require `c_hi − c_lo ≥ 2`, so moving one flow cannot
     make `lo` the new max. This guarantees each accepted move strictly
     decreases the sum-of-squares potential `Ψ = Σ count²` by at least 2
     (`ΔΨ = 2 − 2(c_hi − c_lo) ≤ −2`), so the process terminates at the even
     partition (mean-independent — holds for a non-integer mean too);
   - **strong per-flow cooldown** — a moved flow is ineligible to move again for
     `max(rebalance-interval × 20, 30 s)` (the oscillation guard). This is what
     prevents the install → delete → install ping-pong (a climbing
     `deletes_total`): once a flow is pinned it stays pinned for a long window,
     so bursty count fluctuations cannot drive it back and forth;
   - **one move per `rebalance-interval`** (install-cadence dwell);
   - **truncation defer** — if the flow-worker-map snapshot is truncated (so the
     row count would understate the true count) the controller skips the tick.
4. At `max-rules`, STOP (no eviction).

Because `Ψ` is a non-negative integer that drops by ≥ 2 every accepted move and
no move is accepted once the counts are within ±1 of even, the controller
converges in a bounded number of moves and cannot oscillate. The deadband and
the sustained-imbalance dwell ensure that once converged it issues ZERO further
installs/deletes (no churn) and that the live ntuple-rule count stays bounded to
roughly the number of flows actually relocated — never climbing toward the cap.
Because the per-tick controller work runs on the ~1 Hz status thread and the
ownership barrier blocks that thread on worker acks, keeping the steady-state
move rate at zero is also what keeps the controller from adding latency to new
connection setup when it is enabled.

**Limitation (heterogeneous traffic).** Equal *count* ≠ equal *rate*. For
homogeneous traffic (e.g. iperf `-P`, all flows ≈ equal rate) count-balancing
reaches the fair floor. For an elephant + several mice on one worker, an even
count partition does not flatten per-flow rate; count-balancing cannot fix
within-worker rate skew. A rate-aware tiebreak among count-eligible candidates
is a documented follow-up gated on a reliable per-flow byte feed (#1750).

## Correctness: the move is a barriered ownership transfer

Re-pinning a flow is not free — the old worker (W_old) keeps a stale forward
session entry whose normal GC/purge/terminal cleanup would cascade-delete the
shared session-map entry, conntrack mirror, and SNAT allocation that the new
worker (W_new) is now forwarding against. The controller therefore performs a
genuine ownership transfer:

- **Forward barrier (install):** promote W_new's pre-replicated session to a
  local owner (`RebalancedOwner`) and block on its ack; then demote W_old's
  copy to an inert, cleanup-suppressed `RebalancedOut` and block on its ack;
  *then* install the rule. Because the worker command queues are independent
  per-worker, the ack barrier is what guarantees W_new is committed as owner
  before W_old is demoted — there is always ≥ 1 cleanup owner.
- **Reverse barrier (rollback / teardown of a live move):** restore W_old to
  owner and block on its ack, delete the rule, then demote W_new back to a
  replica. Applying the demote first would re-open a zero-owner window.

`RebalancedOut` is suppressed at every shared-state release/delete site (GC
expiry, worker purge, terminal-filter, SNAT release, `DeleteSynced` broadcast,
peer export, `demote_owner_rg`/`refresh_owner_rgs`). `RebalancedOwner` behaves
like a normal local owner for cleanup/export/sync and demotes to `SyncImport`
on a real RG failover like `ForwardFlow`.

## HA / failover behavior — fairness resets after a failover

> **Operationally important.** After a chassis-cluster failover, the new
> primary node has **no ntuple rules** installed (the rules are local NIC state
> on the node that was active; they do not replicate to the standby in this
> increment). Traffic therefore falls back to plain RSS hashing on the new
> primary.

This is **correct** but **not immediately fair**: the per-flow CoV will jump
back toward the natural RSS imbalance (14–29%) immediately after a failover,
then re-converge toward the balanced floor (~3–4%) as the controller observes
the imbalance on the new primary and re-installs rules over the next several
`rebalance-interval`s. No connectivity is lost across the failover — only the
fairness optimization resets and rebuilds. Forward-only, single-node re-pin is
HA-*correct* (the pre-replicated session substrate forwards on the new worker);
peer rule-mirroring for sustained post-failover fairness is a documented
follow-up (R4), out of scope for this increment.

## Observability

Per-interface Prometheus gauges/counters (`{ifindex}` label):

- `xpf_userspace_flow_rebalance_rules_active` — installed rules now.
- `xpf_userspace_flow_rebalance_installs_total` / `_deletes_total`.
- `xpf_userspace_flow_rebalance_moves_skipped_total{reason}` — why a candidate
  move was not taken. #1751 count-balancing labels: `balanced` (count delta
  `< K`, or counts already even), `magnitude` (count overshoot guard —
  `c_hi − c_lo < 2`), `cooldown`, `no_eligible_flow`, `budget_exhausted`,
  `barrier_failed`, `dwell`, `restore_failed`, `truncated` (deferred on a
  truncated flow-worker-map snapshot). `epsilon` is retained for metric ABI
  but is never recorded by the count selector.
- `xpf_userspace_flow_rebalance_worker_byterate_cov` — the live per-worker
  byte-rate CoV at the last tick. **Observability only** under #1751 (the
  decision is count-driven); it tracks the byte-rate imbalance the operator
  ultimately wants to see fall as the counts balance.

## Hardware support

Exact and masked ntuple steering requires a NIC whose driver supports
`ETHTOOL_SRXCLSRLINS` flow-classification rules (verified on the loss cluster's
mlx5_core SR-IOV VFs). On a NIC without support the controller logs
`EOPNOTSUPP` once and skips that interface; the default forwarding path is
unaffected.

## Scope (this increment)

- **Forward-direction only.** A `-R` / reverse-direction flow needs a reverse
  rule pair (R2, follow-up).
- **Single-node.** No peer rule-mirroring across failover (R4, follow-up —
  see the HA section above).
- **Budget + cooldown**, not a full 1024-rule eviction policy (R5, follow-up).
