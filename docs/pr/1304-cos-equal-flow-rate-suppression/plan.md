# #1304 CoS equal-flow mode: explicit rate suppression for raw per-flow fairness under RSS skew

**Status:** DRAFT v1 — pending adversarial plan review (Codex + AGY hostile)

> Plan author note to reviewers: this is the **8th attempt at a per-5-tuple
> fairness mechanism** in this codebase. Seven prior mechanisms have been
> PLAN-KILLED (#1287/#1288 flow-aware V_min, #1215 local stall, #836 shared
> HOL, #840/#1203 RSS steering, #937 ingress XDP_REDIRECT, #1211 race-safe
> AFD, #1243 5-worker dedicated CPU, #1244 RSS Toeplitz auto-tune).
>
> A naive read of this proposal is "yet another fairness mechanism that
> will be killed by the AF_XDP UMEM physics ceiling." That is the
> hypothesis I want both reviewers to test hostilely. **If the answer
> after hostile review is PLAN-KILL, that is the correct answer.**
>
> However, this proposal is structurally distinct from the prior seven
> in one specific way that I want reviewers to examine before reaching
> a verdict: **#1304 explicitly accepts an aggregate throughput drop as
> the cost of the mode.** The prior seven all attempted to improve raw
> per-flow CoV *while preserving* aggregate throughput at or near the
> Cstruct ceiling. That conservation is what the UMEM physics forbids.
> If you let go of the throughput conservation requirement, the problem
> reduces to "globally cap each worker so it doesn't exceed the
> bottleneck worker's per-flow rate." That is a much weaker problem.
>
> The hostile question is: even with the throughput cost accepted,
> does the proposed control loop (sampled estimator + per-worker cap +
> O(1) hot-path token bucket) actually reduce raw per-flow CoV from the
> measured 0.49+ floor to ≤0.20 on the loss userspace cluster? Or is
> there a second structural ceiling that #1304 doesn't recognize?

## 1. Issue framing

#1304 asks for an **opt-in CoS mode** (default OFF) where the explicit
contract is:

- Goal: reduce raw per-flow CoV (currently 0.39-0.65 on q2/q3/q6 with
  surplus-sharing per #1296 evidence) toward ≤0.20 when RSS distributes
  flows unevenly across workers.
- Cost: aggregate throughput may drop below the structural/work-
  conserving cap. This is the price of the mode.
- Non-goal: throughput-neutral scheduler improvement (which the
  AF_XDP UMEM physics ceiling forbids — see §3 below).
- Default: work-conserving / Cstruct-relative mode (#1217 contract)
  remains the default. Equal-flow mode is per-queue opt-in.

#1304 is explicit that this is a **product-mode choice** — two
contracts coexist:
- Work-conserving (#1217 default): structural fairness, max throughput.
- Equal-flow (#1304 opt-in): raw fairness, possible throughput loss.

## 2. Honest scope and value framing

**Absolute scale of the win (if it works):**

Per the #1296 measurement (`/tmp/cos-headroom-q2q3q6-post1295-20260513T080324Z`):

| Class | Surplus mode raw CoV | Strict-exact raw CoV | Strict-exact throughput loss |
|---|---:|---:|---:|
| q2-iperf-e-16g | 0.490 | 0.039 | 13.5 / 20.6 = -34% |
| q3-iperf-f-19g | 0.647 | 0.088 | 14.9 / 21.1 = -29% |
| q6-iperf-c-25g | 0.393 | 0.136 | 17.6 / 20.4 = -14% |

This proves equal-flow IS achievable today by simply running with
strict-exact CoS class caps (no surplus donation). Per-flow CoV drops
to 0.04-0.14 (well below the 0.20 target) at a 14-34% aggregate
throughput cost.

**So why isn't strict-exact already the answer?** Because strict-exact
suppresses *all* surplus donation, including donation to workers that
are not over-rate per their flow share. It is a blunt instrument:

- A worker with 6 active flows hitting class-cap/6 per flow has no
  surplus to donate even though peers may be starving.
- A worker with 0 active flows still has its full class share
  reserved (wasting the bandwidth).

The #1304 ask is more surgical: cap each worker to
`target_per_flow_bps * active_flows_i` where
`target_per_flow_bps = min_active_worker(r_i)`. Workers with zero
active flows are not capped. Workers above the bottleneck rate are
throttled until they align.

**Expected delta vs strict-exact:** raw CoV similar (≤0.20 target),
throughput loss potentially smaller than strict-exact's 14-34%
because idle-worker capacity is freed.

**If reviewers conclude the perf gain is too small to justify the churn,
PLAN-KILL is an acceptable verdict.**

A specifically valid PLAN-KILL argument: "strict-exact CoS already
delivers raw CoV ≤0.14 (q6) on the workloads of interest; the
incremental win from per-worker surgical capping vs strict-exact is
unmeasured and may be ≤5pp in aggregate throughput; that is below
the engineering cost of the proposed estimator + telemetry +
config surface + Phase 0/1/2/3 rollout."

I want both reviewers to evaluate that specific kill argument
explicitly.

## 3. The AF_XDP UMEM physics ceiling — what #1304 IS and IS NOT proposing to bypass

Per `feedback_cross_binding_impossible.md` and
`project_per5tuple_fairness_killed.md`:

> AF_XDP zero-copy queue binding prevents cheap XDP-level flow
> migration across RX queues. Cross-NIC shared UMEM removes the
> packet-copy cost on forwarding, but it does not change RSS
> provenance or create capacity on an idle RX queue.

The kernel enforces this in `xsk_rcv_check`:
```
xs->dev == xdp->rxq->dev AND xs->queue_id == xdp->rxq->queue_index
```

**What this physics constraint forbids:** moving a packet's processing
from worker A (its RSS-determined queue) to worker B (a less-loaded
queue) without a memory copy and an extra hop through the kernel.

**What this physics constraint does NOT forbid:** asking worker A to
*slow down* via a software rate cap. Slowing a worker doesn't move
packets across queues; it just dequeues fewer of them per epoch.
This is what #1304's "rate suppression" actually does.

**This is the structural reason #1304 might escape the prior kill chain:**

- #1287/#1288 V_min: tried to throttle via vtime drift, but vtime
  drift was driven by served bytes which were already what we wanted
  to equalize — it was a self-referential controller. Killed.
- #1215 local stall: stalled the local worker on a shared per-flow
  signal. Bucket collisions in the signal made it fail on the very
  case it was designed for (RSS skew). Killed.
- #836 shared HOL: HOL-finish-time array under concurrent writers
  is non-commutative. Killed.
- #840/#1203 RSS steering: tried to *move* flows. Net-negative;
  reverted.
- #937 ingress XDP_REDIRECT: tried to bypass UMEM queue binding via
  cpumap. Kernel `xsk_rcv_check` prevents it. Killed.
- #1211 race-safe AFD ECN: needed cross-worker shared state in the
  hot path for the AQM signal. Cache-line bouncing made it
  catastrophic. Killed.
- #1243 5-worker dedicated CPU: changed worker count; multinomial
  CoV cancels at the count change. Killed.
- #1244 RSS Toeplitz auto-tune: current MS key is already at the
  multinomial(12,6) floor. No headroom. Killed.

**The pattern:** all prior kills failed on either (a) cross-worker
shared state in the hot path, or (b) attempting to move work
across UMEM queues. **#1304's proposed control loop avoids both:**

- The estimator runs in the **control plane** (outside the packet
  hot path) at 10-100ms epochs. No per-packet shared state.
- The hot-path enforcement is **per-worker local** (read-only
  per-worker cap, local token bucket). No cross-worker reads in
  the per-batch path.
- Nothing moves across UMEM queues. Workers just slow down.

**However, this is the hypothesis I want hostile review to test.**

## 4. What's already shipped

- **#1217** fairness regimes contract (merged): observed_CoV ≤
  Cstruct + 0.05. This is the work-conserving / structural default.
  #1304 leaves this contract unchanged for the default mode.
- **#1220** fairness-eval harness (merged): empirical 47% per-flow
  CoV is structurally bound. Harness exists and can measure raw
  per-flow CoV plus Cstruct on the loss userspace cluster.
- **#1295** stale active-flow telemetry fixed (active_flow_buckets
  is current, not stale).
- **`SharedCoSQueueLease::acquire_v8`** (mod.rs:1140-1308) — current
  v8 lease primary share + surplus path. The surplus path
  (`bypass_grace_rotations_remaining > 0`) is the specific code path
  that breaks raw equal-flow per #1296's diagnosis.
- **`active_flow_buckets` per-worker** (refresh_bindings.rs +
  cos/fairness.rs:128) — per-worker active-flow count is already
  tracked.
- **`tx_completion.rs`** — per-worker TX completion / delivered byte
  signal already exists at low rate.

What's missing:
- Per-worker delivered-bps over an epoch (currently per-batch only).
- Equal-flow control struct & per-queue config flag.
- The estimator + cap publication code.
- The hot-path token bucket per worker (lease modification or
  parallel structure).

## 5. Concrete design

### 5.1 Control-plane sampled estimator

New file: `userspace-dp/src/afxdp/cos/equal_flow_estimator.rs`.

Module owner: coordinator (already aggregates per-worker telemetry
in `coordinator/refresh_bindings.rs`).

Cadence: tied to existing epoch rotation in
`shared_cos_lease/rotate_epoch_v8.rs` (currently ~10ms grace
rotations). Initially run estimator once per N grace rotations
(N tunable, default 4 = ~40ms).

State (per `(ifindex, cos_queue_id)`):
```rust
struct EqualFlowEstimator {
    enabled: AtomicBool,               // per-queue opt-in
    epoch_id: AtomicU32,
    snapshot_age_ns: AtomicU64,
    per_worker_active_flows: [AtomicU16; MAX_WORKERS],
    per_worker_delivered_bps: [AtomicU64; MAX_WORKERS],
    per_worker_cap_bps: [AtomicU64; MAX_WORKERS],     // published
    suppressed_bytes: AtomicU64,                       // counter
    target_per_flow_bps: AtomicU64,                    // for telemetry
}
```

Estimator algorithm (control plane only):
```
1. For each worker i with active_flows_i > 0:
   r_i = delivered_bps_i / active_flows_i
2. target_per_flow_bps = min over active workers of r_i
3. For each worker i:
   if active_flows_i == 0:
     cap_i = u64::MAX  // do not cap idle workers
   else:
     cap_i = target_per_flow_bps * active_flows_i
4. Apply clamp: per-epoch change limited to ±25% to prevent
   sawtooth amplification.
5. Apply guardrail: if snapshot age > 2x epoch period, fail open
   (cap_i = u64::MAX for all workers).
6. Apply guardrail: do NOT include workers with < 1 epoch of
   measured demand as the bottleneck (avoid newly-active worker
   suppressing peers).
7. Publish caps via Release store.
```

### 5.2 Hot-path enforcement

Modify `SharedCoSQueueLease::acquire_v8` (mod.rs:~1140) to check
the equal-flow cap **after** the existing primary-share grant but
**before** the surplus-bypass path:

```rust
fn acquire_v8(&self, req: AcquireReq) -> AcquireResult {
    // Existing primary share check (unchanged)
    if !self.primary_share_ok(req) { return Throttled; }

    // NEW: equal-flow cap check (only if enabled for this queue)
    if let Some(estimator) = self.equal_flow_estimator() {
        if estimator.enabled.load(Acquire) {
            let cap = estimator.per_worker_cap_bps[req.worker_id]
                .load(Acquire);
            let local_bytes = self.worker_local_byte_counter(
                req.worker_id);
            let local_rate = self.worker_local_rate_estimate(
                req.worker_id);
            if local_rate > cap {
                estimator.suppressed_bytes.fetch_add(
                    req.bytes as u64, Relaxed);
                return Throttled;
            }
        }
    }

    // Existing surplus-bypass path (only if equal-flow mode OFF
    // or local rate < cap)
    if self.bypass_grace_rotations_remaining() > 0 {
        return Granted;
    }
    ...
}
```

The cap read is a single Acquire load of a per-worker cell — no
shared atomic increments on the hot path. `worker_local_rate_estimate`
is a per-worker local EWMA over the last few batches (private to
the worker's lease state).

### 5.3 Per-queue config flag

New Junos config knob:
```
class-of-service forwarding-classes queue <N> equal-flow-mode;
```

Parsed into typed config; propagated through
`pkg/config -> pkg/cmdtree -> userspace-dp` like any other queue
attribute. Default OFF. Per-queue opt-in.

### 5.4 Telemetry surface

New Prometheus metrics in `pkg/api/`:
```
xpf_cos_equal_flow_enabled{queue=N}                  (gauge 0/1)
xpf_cos_equal_flow_epoch_id{queue=N}                 (gauge)
xpf_cos_equal_flow_snapshot_age_ms{queue=N}          (gauge)
xpf_cos_equal_flow_per_worker_active_flows{queue=N,worker=W}
xpf_cos_equal_flow_per_worker_delivered_bps{queue=N,worker=W}
xpf_cos_equal_flow_per_worker_cap_bps{queue=N,worker=W}
xpf_cos_equal_flow_suppressed_bytes_total{queue=N}   (counter)
xpf_cos_equal_flow_target_per_flow_bps{queue=N}      (gauge)
```

CLI surface: `show class-of-service queue equal-flow-status`.

## 6. Public API preservation

- `SharedCoSQueueLease::acquire_v8(...)` — signature unchanged. The
  new check is internal to the impl.
- `cos/fairness.rs` `flow_fair_share` — unchanged.
- `cos/queue_ops/v_min.rs` — unchanged. V_min stays the work-conserving
  primary controller. Equal-flow mode is an additional gate.
- `pkg/grpcapi` CoS status RPC — extended (additive) with equal-flow
  fields; existing fields preserved.

## 7. Hidden invariants to preserve

- **Side-effect ordering on lease acquire** — equal-flow check must
  not skip the existing primary-share check. Order matters: primary
  share first (existing behavior), then equal-flow cap, then surplus.
- **HA portability** — equal-flow estimator state is per-node and
  control-plane; no session-sync wire format change required.
- **GC interaction** — `active_flow_buckets` going to 0 must
  remove the worker from the bottleneck calculation atomically. The
  estimator reads a snapshot, so a stale value can briefly mis-cap a
  newly-idle worker; the per-epoch clamp + 1-epoch grace bounds this.
- **Lifetime** — estimator owned by coordinator; lease holds a
  read-only `Arc<EqualFlowEstimator>` or `*const EqualFlowEstimator`
  with explicit lifetime contract.
- **Stale-handle hazards** — if a worker reads a cap from a stale
  epoch, the worst case is one epoch (~40ms) of mis-throttling.
  Bounded.
- **Fail-open** — if estimator publishes nothing (Phase 0 or
  estimator panic), workers must fall back to the existing
  work-conserving v8 lease behavior.

## 8. Risk assessment

| Risk class | Level | Justification |
|---|---|---|
| Behavioral regression (default mode) | LOW | Mode is opt-in; default work-conserving path is unchanged. The added check is gated on `estimator.enabled.load() == false` and short-circuits. |
| Behavioral regression (equal-flow mode) | MEDIUM | New control loop; needs Phase 0 dry-run validation before enforcement. |
| Lifetime / borrow-checker | LOW-MEDIUM | Estimator is `Arc<...>` with atomic-only fields. No new lock contention. |
| Performance regression on hot path | MEDIUM | One extra Acquire load + local rate compare per acquire. ~2-5 ns overhead. Acceptable if mode OFF (no load); if mode ON, the throughput cost is THE point of the mode. |
| Architectural mismatch vs #961/#946 Phase 2 | LOW-MEDIUM | This is a feature ADD, not a refactor. The architectural mismatch class (wrong-target refactor) doesn't apply directly. The relevant mismatch is: "is the proposed control loop the right shape for this problem?" |
| Cross-worker shared state cache-line bouncing (#1211 kill class) | LOW | The hot path reads per-worker cells (one cache line per worker). The estimator writes once per epoch. Bouncing limited to per-epoch frequency. |
| TCP sawtooth amplification | MEDIUM | Per-epoch ±25% clamp is a hand-waved guardrail. Real sawtooth interaction with TCP CUBIC needs measurement, not theory. |
| Mode contract confusion | LOW | Issue is explicit; config knob is explicit; telemetry surface labels the mode. Operator confusion bounded. |

## 9. Test plan

- `cargo build --release` clean
- `cargo test --release` (existing 952+ tests + new estimator tests)
- 5x flake check on the new estimator named tests
- 30 Go packages pass
- **Phase 0 dry-run on loss userspace cluster:** estimator runs,
  publishes caps, enforces NOTHING. Verify predicted caps match
  what would have equalized observed per-flow rates on q2/q3/q6.
- **Phase 1 enforcement smoke:** equal-flow mode ENABLED on q2/q3/q6.
  Smoke matrix:
  - Mode OFF: v4+v6 × push+reverse × 6 ports — line rate, 0 retr
  - Mode ON q2/q3/q6: raw per-flow CoV ≤ 0.20 (saturated samples)
  - Mode ON q2/q3/q6: aggregate throughput report (with the loss
    surfaced, not hidden)
  - No starved flows
  - Retransmits not increased >10% vs work-conserving baseline

## 10. Out of scope

- Cross-binding flow migration. Forbidden by AF_XDP UMEM physics
  per `feedback_cross_binding_impossible.md`.
- Cross-NIC equal-flow (would require shared UMEM cross-NIC, blocked).
- ECN/AQM equal-flow signal (#1211, killed).
- Default-mode behavior change to equal-flow. Stays opt-in per issue.
- Operator-tunable cadence / clamp. Defaults only in this PR.

## 11. Open questions for adversarial review (each invitable to PLAN-KILL)

1. **Strict-exact CoS already gives raw CoV ≤0.14 on q6 at 14-34%
   throughput cost.** Is the incremental win of #1304 over
   strict-exact actually >5pp throughput recovery on workloads of
   interest? If not, PLAN-KILL: ship a flag that selects strict-exact
   as the equal-flow mode and skip the estimator.

2. **TCP CUBIC sawtooth amplification.** The proposed per-worker
   rate cap shapes outgoing throughput. TCP at the endpoint will
   react with congestion control (cwnd halve on loss, ECN-react).
   The interaction of a 40ms control loop with TCP RTT (~1-5ms on
   the LAN) and CUBIC's beta=0.7 has not been modeled. Is there a
   feedback loop that makes the effective rate oscillate at a
   harmonic of the control-loop period? PLAN-KILL if so.

3. **Bottleneck-worker hazard.** `target = min_active(r_i)` picks the
   *worst-performing* active worker as the rate target. If that
   worker is slow due to a transient hiccup (NIC pause frame, GC,
   page fault), the whole queue gets dragged to its level for at
   least one epoch. Is this acceptable? PLAN-KILL if a worker-level
   hiccup translates to systemic throughput collapse.

4. **Hot-path overhead even when mode OFF.** The acquire_v8 path
   gains a branch + Acquire load even with mode OFF (gated on the
   atomic). On the work-conserving default path at ~28ns hot-path
   budget, this is a measurable percentage. Has anyone measured it?
   PLAN-KILL if mode-OFF regresses default-mode perf by >2%.

5. **Multinomial floor at the equal-flow target.** Even if equal-flow
   mode caps all workers to `target * a_i`, the per-flow throughput
   distribution within a worker still depends on TCP-level fairness
   between flows on that worker's TX path. The harness measures
   per-flow CoV across all 12 flows, not per-worker CoV. Is the
   intra-worker per-flow CoV bounded? PLAN-KILL if the proposed
   mechanism only equalizes per-worker rates, not per-flow rates,
   and per-flow CoV stays high.

6. **Estimator self-reference.** `delivered_bps_i` measures what
   *was* delivered, including under throttle. If worker i was
   capped last epoch, its delivered_bps is the cap, not its
   capacity. So r_i = cap_i / active_flows_i = target_per_flow_bps
   exactly. The estimator becomes a fixed point at whatever the
   first epoch's bottleneck was. Is that a stable equilibrium or a
   degenerate one? PLAN-KILL if the estimator can't escape its
   first bottleneck.

7. **Effective control rate vs cadence.** At 10-100ms epochs, a
   reactive control loop has bandwidth ~10-100 Hz. iperf3
   measurement windows are 1s. If the estimator runs at 40ms it's
   25 Hz, well below TCP's RTT-frequency dynamics. Is the controller
   actually fast enough to track flow arrivals/departures within
   a smoke run? PLAN-KILL if the smoke can't measure equal-flow
   convergence within the 10s -P 12 reproducer window.

## Reviewer instruction

This plan is explicitly inviting PLAN-KILL. The prior history is
8-of-8 PLAN-KILL on this problem space. If this one survives
review, the methodology demands an empirical Phase 0 dry-run
*before* implementation hits any enforcement code. If it doesn't
survive, document the kill and move on.
