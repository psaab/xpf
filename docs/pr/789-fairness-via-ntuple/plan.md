---
status: DRAFT v1 — pending adversarial plan review
issue: #789 (parent), #936 (path A — declined), #937 (path B — current scope)
phase: Phased proposal for closing the per-flow CoV gap on shared_exact CoS queues via mlx5 ntuple HW flow steering
---

## 1. Issue framing

The user has explicitly asked for fairness across flows on Tier B
("don't let it fail"). The current state on master post-#1201/#1202
(2026-05-06) is:

| Class | P | CoV current | Gate (#789) |
|---|---|---:|---:|
| iperf-c | 12 | **62.5%** | ≤ 20% |
| iperf-c | 32 | 46.9% | ≤ 20% |
| iperf-b | 12 | 41.8% | ≤ 20% |
| iperf-b | 32 | 29.1% | ≤ 20% |
| iperf-a | 12 | 0.4% (PASS) | ≤ 20% |

iperf-c P=12 distribution: 4 flows at 0.88-1.05, 3 at 1.27-1.33,
2 at 1.96-1.98, 3 at 3.84-3.93 Gb/s. **Classic RSS-bias
signature** — workers receive uneven flow counts, so each worker's
share-per-flow varies.

iperf-a passes because the 1 Gb/s shape rate divides cleanly across
the 12 flows; the shaper does the equalization.

## 2. Honest scope/value framing

**The headline gap:** 22-42 percentage points below the #789 ≤ 20%
gate on shared_exact at multi-Gbps shapers. This is the residual
after #917 V_min sync; documented in
`docs/pr/917-mqfq-phase4/findings-post-917.md`.

### Prior dead-ends (do not retry without new lever)

- **#840 RSS-table tuning** — REVERTED. Memory:
  `project_rss_rebalance_negative.md`. Tuning the indirection
  table only affects new hash buckets, not in-flight long-lived
  flows.
- **#899 cross-binding XDP_REDIRECT** — CLOSED 2026-04-25. The
  existing comment at `userspace-xdp/src/lib.rs:1306-1308`
  identifies the wall: "AF_XDP delivery is queue-bound. XDP may
  only redirect to a socket bound to the packet's actual RX
  queue." Cross-queue XDP_REDIRECT silently strands packets.
- **#946 Phase 2** (batched per-stage iteration) — KILLED.
  Memory: `project_946_phase2_plan_killed.md`. flow_cache +
  session table + MissingNeighbor are order-coupled.
- **#761 sorted-by-name slot** — KILLED. Memory:
  `project_761_killed.md`. Mid-flight inconsistency.
- **#747 Glide EWMA** — KILLED. Memory: `project_747_killed.md`.
  Idle-then-burst → fix causes its own bug.
- **#794 AFD policer** — closed previously.
- **#838-afd-lite** — closed (negative finding preserved).

### Two known open paths

- **#936** shared per-flow finish-time table (stalls fast workers).
  ~43% aggregate hit on degenerate distributions. The user has
  reopened this as "active fairness gap" — the trade-off was
  unacceptable to close as "declined by default".
- **#937** cross-binding flow re-steering. Better aggregate IF
  feasible. Constrained by AF_XDP queue-binding (no cross-queue
  redirect) AND shared-UMEM unavailability (per
  `docs/userspace-jit-design.md:442-448`).

### The new lever this PR introduces: mlx5 NIC HW flow steering
### via `ethtool -N` flow-director rules

Distinct from #840 (RSS *table*): `ethtool -N` installs per-5-tuple
**hardware** rules that override RSS for matching packets. The
rule applies to all matching packets including in-flight
established flows. mlx5_core supports this:
`ethtool -K ge-0-0-2 ntuple on` then
`ethtool -N ge-0-0-2 flow-type tcp4 src-ip X dst-ip Y src-port a
dst-port b action <queue-id>`.

The cluster's iperf-b/iperf-c traffic enters fw0 via
**ge-0-0-2.80** (VLAN 80) over mlx5_core parent `ge-0-0-2`. mlx5
ntuple-filters are toggleable on this driver (verified
`ethtool -k ge-0-0-2` reports `ntuple-filters: off` — not
`[fixed]`).

**Why this is different from #840:**
- #840 tuned the indirection table → only future hash-bucket
  selections affected.
- ntuple rules pin a specific 5-tuple to a specific queue → all
  future packets of that flow land on that queue.

For long-lived TCP flows (the #899 problem), this is the right
shape.

## 3. What's already shipped

- AF_XDP dataplane on per-binding queues with V_min sync (#917)
- BatchCounters extended for DDoS resilience (#1202)
- ArcSwap short-circuit on hot path (#1201)
- mlx5 driver in test cluster with ntuple-filters available

## 4. Concrete design — phased

### Phase 0 (this plan only — measurement)

Re-baseline current master per-flow CoV (DONE):
- iperf-c P=12: **62.5%** (worse than 48.9% in #936 reopen)
- iperf-c P=32: 46.9%
- iperf-b P=12: 41.8%
- iperf-b P=32: 29.1%

Document the per-flow distribution from one run to characterize
the imbalance shape (DONE — see §1).

### Phase 1 (this PR): static one-shot rebalance for known iperf classes

Smallest verifiable mechanism:

1. New module `pkg/dataplane/userspace/flow_steering.go` (Go side).
2. On `commit` of a CoS shared_exact class config, after the
   userspace dataplane reconciles bindings:
   - Enable ntuple-filters on the parent NIC for shared_exact
     traffic interfaces (`ethtool -K <iface> ntuple on`).
   - Detect the parent NIC of the shared_exact-attached interface
     (handles VLAN sub-interfaces).
   - Maintain a kernel-side rule set keyed by 5-tuple.
3. On a 1Hz tick, scan per-binding flow counts in the userspace
   helper:
   - Compute imbalance score per shared_exact class:
     `max_count - min_count`.
   - If `≥ 2`, pick the heaviest binding's K=1-2 flows and emit
     ntuple rules redirecting them to the lightest binding's
     queue.
   - Track installed rules; on flow termination (session GC), tear
     down the corresponding rule.
4. Bail criterion: if `ethtool -N` install fails (e.g.,
   rule-table exhaustion), log and stop installing for the class.
   Existing RSS continues to handle traffic.

**Out of scope for Phase 1:**
- Per-flow control (>2 flows redirected per tick)
- Hysteresis to prevent flow ping-pong
- Production hardening (rule lifecycle on daemon restart, etc.)
- Anything affecting non-shared_exact traffic
- Anything affecting unshaped (best-effort) traffic
- Anything on virtio interfaces (ntuple not supported)

### Phase 2 (separate PR if Phase 1 PASS gate moves CoV)

Closed-loop controller with:
- Hysteresis bands
- Per-class enable/disable knobs
- Daemon-restart rule reconciliation
- Operator visibility (`show cos flow-steering` CLI)

### Phase 3 (separate PR)

Production hardening:
- Rule-table-exhaustion graceful degradation
- Cross-driver portability (ice/i40e in addition to mlx5)
- Failover behavior (rules survive HA active/secondary swap)

## 5. Public API preservation

- New CLI knob (Phase 2): `set system services userspace-dp flow-steering enable`
- No external API changes in Phase 1; mechanism is internal.

## 6. Hidden invariants the change must preserve

- **Existing RSS behavior unchanged when disabled.** Phase 1
  installs rules only when imbalance is detected; default is
  RSS-as-today.
- **No interaction with the existing XDP redirect path.** ntuple
  steers at the NIC HW level, before XDP runs. The XDP program's
  current per-RX-queue logic continues unchanged.
- **Flow continuity.** A flow steered to queue Q at time T must
  continue arriving on Q until the rule is removed; ntuple rules
  are persistent until cleared.
- **Session table consistency.** When a flow re-steers
  mid-session, the receiving worker may not have the conntrack
  entry yet. Plan must handle the cold-start case (conntrack
  miss → existing slow-path resync).

## 7. Risk assessment

| Class | Level | Why |
|---|---|---|
| Architectural mismatch | **MEDIUM** | mlx5 ntuple is well-documented but not previously used in xpfd. Rule lifecycle bugs could leak rules. |
| Behavioral regression | LOW-MED | Phase 1 only acts on detected imbalance; existing RSS path is fallback. |
| Cross-driver portability | MEDIUM | Phase 1 limited to mlx5; ice/i40e behavior different (different rule-table sizes, different CLI shape) — Phase 3 territory. |
| Rule-table exhaustion | MED | i40e: ~1024 rules. mlx5: 32k+ typically. For 12-32 elephant flows fine; for 1000+ flows could exhaust. Phase 1 bails on install failure. |
| Conntrack miss on re-steer | MED | First packet after re-steer may miss conntrack. Existing slow-path handles this, but is slow. |
| Aggregate throughput regression | LOW | This is the OPPOSITE of #936's trade-off; ntuple steering preserves aggregate. |
| Test coverage | LOW | Smoke matrix already covers shared_exact classes. |

## 8. Test plan

- `cargo build --release`: clean
- `go test ./...`: pass
- 5x flake on a new ntuple-rule-install integration test (Phase 1
  only)
- Smoke matrix on loss userspace cluster: 30 cells, 0 retrans
- **Critical: per-flow CoV measurement** with mechanism active:
  - iperf-c P=12 t=20: capture per-flow distribution, compute
    CoV, report delta from baseline (62.5% → ?).
  - PASS gate for Phase 1: CoV ≤ 30% (interim), ideally ≤ 20%
    (#789 final gate).
  - Aggregate must NOT regress > 5% (preserve win).
- Failover: `make test-failover` if accessible — verify rules
  re-install on activation.

## 9. Out of scope

- VLAN-aware rule-on-parent vs rule-on-VLAN (Phase 1 puts rules
  on parent only).
- IPv6 ntuple support (mlx5 supports `flow-type tcp6` but Phase 1
  defers; iperf-c IPv6 tests would still be RSS-only initially).
- Anything affecting iperf-a (passes already at 0.4% CoV).
- Anything affecting non-shared_exact CoS classes (best-effort,
  bandwidth-limit, etc.) — fairness on those is already governed
  by the shaper.

## 10. Open questions for adversarial review

1. **Is mlx5 ntuple actually a viable lever?** The existing comment
   at `userspace-xdp/src/lib.rs:1306` was conservative about XDP
   cross-queue redirect — does mlx5 ntuple genuinely move packets
   to a different RX queue, or does it just affect the in-CPU XDP
   program's view? (Answer expected: it's a HW filter; rules
   bypass RSS at the device level.)

2. **Rule lifecycle.** What's the failure mode if xpfd crashes
   while rules are installed? `ethtool -N <iface> delete <rule>`
   on daemon start, OR keep them and reconcile? Phase 1 should
   probably tear down all rules on init.

3. **Hysteresis.** With `imbalance ≥ 2` as the trigger, a flow
   that finishes could dump back into imbalance ≥ 2 in the
   opposite direction, causing ping-pong. Phase 1 should pick
   this up — either skip rule installs that would re-steer a
   flow we just placed, or use a delay.

4. **Conntrack migration.** When a flow re-steers from worker A
   to worker B, A's conntrack entry stays (shows phantom
   activity); B builds a new entry. Memory cost (1 stale entry)
   is bounded by GC. But during the re-steer window, packets
   could land on B before the conntrack entry exists → slow
   path. Acceptable for elephants (rare events) but verify under
   stress.

5. **Aggregate throughput preservation.** Phase 1's
   `imbalance ≥ 2` trigger is conservative. Could it move
   throughput in either direction? Worst case: re-steer a
   high-rate flow from a worker that's well-utilized to one
   that's not, but the receiving worker is rate-limited by the
   shaper anyway → no aggregate change. Best case: balance
   flow distribution → both sides utilize CPU more → aggregate
   improves slightly.

6. **iperf-b vs iperf-c gap difference.** iperf-b CoV is 41.8%
   (P=12), iperf-c is 62.5%. The mechanism is the same (RSS
   bias). Should both classes get equal treatment, or
   prioritize by bias severity?

7. **Comparison to #936.** If #936 is "stall fast workers"
   (~43% aggregate hit), this PR is "redistribute flows" (no
   aggregate hit). Does the cycle-cost difference of HW rule
   installs vs in-software stalls justify the additional
   complexity?

## 11. Verdict request

PLAN-READY → execute Phase 1.
PLAN-NEEDS-MINOR → tweak (e.g., hysteresis, rule-lifecycle).
PLAN-NEEDS-MAJOR → revise scope (e.g., extend to IPv6,
include hysteresis, broader driver support).
PLAN-KILL → premise wrong:
- mlx5 ntuple doesn't actually redirect to specific queues;
- the implementation surface is wider than this plan estimates;
- there's a fundamental reason the existing test cluster won't
  exercise this lever.

This plan is positioned as **Phase 1 of a multi-week effort**
($789 has been on master since #785; the user has repeatedly
reopened the dependent issues). PLAN-KILL is acceptable IF the
mechanism doesn't work — but if it works, this is the path that
preserves aggregate while moving CoV.
