# #1314 Adaptive idle-spin budget to recover CPU after copy-elimination — PLAN v1

## Status

**DRAFT v1 — pending adversarial plan review** by Codex (hostile) and
Antigravity (adversarial). This is a Bucket-D perf-driven plan; the
issue itself acknowledges PLAN-KILL is an acceptable outcome if the
projected gain doesn't justify the churn or the proposed mechanism
brings worse failure modes than the status quo.

## Issue framing

After #1301 eliminated cross-NIC data copies on the in-place TX path,
the userspace-dp daemon kept consuming ~600% aggregate CPU on the loss
userspace cluster (6 workers × ~100% each) in `PollMode::Interrupt`,
even at moderate or low load. The hypothesis in the issue is that the
freed cycles got absorbed by the userspace idle-spin hedge at
`userspace-dp/src/afxdp/worker/loop_body/mod.rs:1245-1276`, where each
worker keeps spinning for up to `IDLE_SPIN_ITERS = 256` empty
iterations (`userspace-dp/src/afxdp/mod.rs:241`) before falling into
`poll(2)` / `sleep(2)`. Two `PollMode` arms hit the same constant —
`BusyPoll` and `Interrupt` — but the issue is scoped to `Interrupt`,
since `BusyPoll` operators are explicitly opting in to a 100% CPU
contract.

The goal is to recover wall-clock CPU during idle / low-rate periods
without regressing:

1. line-rate throughput on `iperf3 -P 12 -t 10 -R`,
2. small-flow TCP latency on the first-packet idle→active transition
   (this is the latency-hedge that the existing spin loop is paying
   for, per the existing in-tree comment at lines 1254-1256:
   *"Firewall-local TCP flows are ACK-latency-sensitive; blocking
   immediately on the first empty poll collapses cwnd badly."*).

## Honest scope/value framing

**At absolute scale** the win is bounded by:

- The cluster has 6 workers. Going from ~100% to e.g. ~30% per worker
  on idle, on a ~12-core test machine, saves ~4 cores of wall CPU.
- In a production HA pair sized at 6-12 workers, the absolute win is
  4-10 cores worth of CPU at idle. On a 96-core host, that's 4-10%
  of host CPU.
- During saturated line-rate operation, the worker is in the `Active`
  branch (not the spin branch), so this change should be **neutral
  at line rate**.
- The win is concentrated in low-rate / mostly-idle deployments
  (lab, ISSU testbeds, low-traffic firewalls). At high
  packet-per-second rates the hedge is mostly displaced anyway.

If reviewers conclude the perf gain is too small to justify the churn,
or that the latency-hedge risk on the idle→active transition is worse
than 4-10% of idle host CPU, **PLAN-KILL is an acceptable verdict.**

## What is already shipped / partially batched

- **#869** ships per-worker `WorkerRuntimeState` accounting (Active /
  IdleSpin / IdleBlock) in `userspace-dp/src/afxdp/worker_runtime.rs`.
  Both the cumulative counters (`idle_spin_ns`, `idle_block_ns`,
  `active_ns`, `thread_cpu_ns`) and the rolling-60s window
  (`active_ns_60s`, `thread_cpu_ns_60s`, `wall_ns_60s`, `window_ns`)
  are already published.
- **#1311** ships the last-60s window with a seqlock guard so we can
  read a coherent {active, thread_cpu, wall} tuple in the status path.
- **#1313** just merged orthogonal test-handshake work; we don't
  conflict.
- **#1188** already short-circuits Arc rotation on the hot path via
  `.load() + Arc::ptr_eq + Guard::into_inner`. Don't re-do that.
- `SO_BUSY_POLL` is **already set to 1µs** in `PollMode::Interrupt`
  (`userspace-dp/src/afxdp/bind.rs:469-477`). The 1µs value is
  deliberately small per the in-tree comment: enough to trigger one
  `napi_busy_loop()` per `poll()` so the fill ring gets WQEs posted,
  but small enough that the syscall path isn't itself a CPU sink.
  This matters because **one of the candidate designs below is to
  raise `SO_BUSY_POLL` and shrink the userspace spin** — but the 1µs
  value was a deliberate choice to dodge the 15% CPU overhead from
  the 50µs value (see comment).
- The existing comment on `IDLE_SPIN_ITERS` consumer
  (`userspace-dp/src/afxdp/tx/rings.rs:249`) says cached `now_ns` is
  "stale up to `IDLE_SPIN_ITERS * spin_cost`" — that's the only
  other place in the tree that takes a dependency on the constant.
  Any change to its semantics needs to update that comment.

## Verifying the issue claim BEFORE designing

**Open question / verify-first**: the issue body asserts each idle
iteration costs ~1-2µs (`~18 bindings × ~30-50ns per ring-peek pair`),
which makes `256 iters ≈ 256-512µs of hedge`. This number determines
whether the problem is real and what shape the fix should take.

The plan's **Phase 0** is to verify the claim on the loss userspace
cluster BEFORE designing the algorithm:

```
1. Deploy current master to loss:xpf-userspace-fw0/fw1
2. With NO active flows: read xpf_userspace_worker_idle_spin_secs
   and xpf_userspace_worker_thread_cpu_seconds_total at t0, wait 60s,
   read again. Per-worker ratio idle_spin_secs/thread_cpu_secs > 50%
   confirms the issue.
3. With iperf3 -P 12 -t 60: same measurement. The Active ratio should
   dominate during saturation.
4. perf record -F 999 -g -p <worker_pid> -- sleep 30 during idle.
   Confirm the hot frames are spin_loop / poll_binding ring-peek.
```

If Phase 0 shows the userspace spin path is NOT the dominant idle
consumer (e.g. it's the kernel-side NAPI busy-poll, or it's
`monotonic_nanos()`, or it's CoS-queue lease lookups), the plan
PLAN-KILLs itself and we reframe the issue.

## Concrete design

Two candidate designs. Plan v1 expresses a preference (Design A) and
explicitly invites the reviewers to push back if Design B is cleaner.

### Design A — adaptive userspace spin budget (issue's proposed shape)

Track recent idle-stretch outcomes per worker. When a worker
transitions from idle to active (`did_work = true` after an idle
stretch), record whether the stretch ended inside the spin window
(`IdleSpin` state on the iter the work arrived) or after the worker
had already entered `poll(2)` / `sleep(2)` (`IdleBlock`).

```rust
// At top of loop_body/mod.rs, alongside `let mut idle_iters = 0u32;`
struct IdleBudget {
    /// Current spin ceiling (in iters). Floor MIN, ceiling MAX.
    current: u32,
    /// Bit i = 1 if outcome[i] was SpinResolved (work arrived in
    /// spin window), else 0. Window K = 32.
    recent_outcomes: u32,
}
const IDLE_BUDGET_MIN: u32 = 16;
const IDLE_BUDGET_MAX: u32 = IDLE_SPIN_ITERS; // = 256
const IDLE_BUDGET_INITIAL: u32 = IDLE_SPIN_ITERS;
```

Transition logic, **on every `did_work = true` after at least one
idle iter**:

```rust
let resolved_in_spin = matches!(wr_state, WorkerRuntimeState::IdleSpin);
idle_budget.recent_outcomes =
    (idle_budget.recent_outcomes << 1) | (resolved_in_spin as u32);
let spin_resolved = idle_budget.recent_outcomes.count_ones();
if spin_resolved >= 24 {
    idle_budget.current = idle_budget.current.saturating_mul(2).min(IDLE_BUDGET_MAX);
} else if spin_resolved <= 8 {
    idle_budget.current = (idle_budget.current / 2).max(IDLE_BUDGET_MIN);
}
```

The spin-loop branch becomes:

```rust
if idle_iters <= idle_budget.current { ... spin_loop ... }
```

**Where to place the transition update**: only fires on the
`did_work && idle_iters > 0` boundary, so it's NOT a per-tick cost; it
fires at most once per spin-then-resolve cycle. `count_ones()` on a
u32 is one popcnt on x86 — sub-ns. The whole adaptive block adds 3
integer ops + one branch to a cold-ish path (idle→active transition,
not every iter).

**Hysteresis**: shrink at ≤8/32, grow at ≥24/32, hold in between.
This 50% deadband prevents thrashing.

**Floor of 16**: empirically chosen to preserve the in-tree latency
hedge comment. At ~50-100ns per empty iter on the lab (NOT 1-2µs as
the issue body claims — see Phase 0 verification), 16 iters is
~0.8-1.6µs of spin, still long enough to absorb back-to-back ACK
arrivals across a single TCP flow's ACK gap on most networks. The
floor sets the worst-case latency-hedge degradation per the issue's
"≤5% p99" criterion.

### Design B — kernel-side hedge via SO_BUSY_POLL (issue's alternative)

Set `SO_BUSY_POLL = 25µs` and `IDLE_SPIN_ITERS = 0` (or, scoped to
`Interrupt` only, set `IDLE_SPIN_ITERS_INTERRUPT = 0`). The worker
falls into `poll(2)` immediately on empty ring. The kernel
`napi_busy_loop()` busy-polls for up to 25µs inside the syscall before
blocking, which:

- Pushes the hedge into kernel context, where it can be interrupted
  by softirq directly without spinning user code,
- Pays one `poll(2)` syscall per spin-out cycle (~300ns), much less
  than 25µs of userspace spinning,
- Cleans up CPU accounting (kernel-side busy-poll shows as `%sys`,
  not `%usr`).

**The catch**: the existing 1µs `SO_BUSY_POLL` value was a deliberate
choice per the in-tree comment to avoid 15% CPU overhead from a 50µs
value. So 25µs needs to be benchmarked, not blindly assumed. If 25µs
also costs 7-8% CPU, the gain is marginal.

**Another catch**: `poll(2)` over many fds (one per binding) is not
free, and `SO_BUSY_POLL` interacts with NAPI driver paths that
historically have been i40e/mlx5-specific. We'd need to validate on
mlx5 (the loss cluster's WAN driver).

### Plan v1 preference: Design A, with Design B as a follow-up A/B

Design A keeps the existing latency hedge architecture (userspace
spin) but caps the budget adaptively. It's a smaller blast radius:
~30 lines of new code, no syscall changes, no driver-specific risk,
no `SO_BUSY_POLL` revalidation. It works in both `BusyPoll` and
`Interrupt` (we'll scope the change to `Interrupt` only initially).

Design B is a separate architectural shift that should be its own
issue / PR / measurement once Design A confirms the userspace spin
is in fact the dominant consumer.

## Public API preservation

- `WorkerRuntimeAtomics` and `WorkerRuntimeCounters` unchanged. No new
  fields, no Prometheus surface change.
- `IDLE_SPIN_ITERS` constant retained as the *ceiling* used by Design
  A and untouched in `PollMode::BusyPoll`.
- No protocol / wire / Go-side change. Self-contained inside
  `userspace-dp/src/afxdp/worker/loop_body/mod.rs`.

## Hidden invariants the change must preserve

1. **`idle_iters` reset on `did_work`** — current code resets to 0 on
   the active branch. Design A must NOT reset `idle_budget.current`
   on active; the budget is the cross-cycle memory.
2. **No new per-tick allocations.** `IdleBudget` is a single u64
   (`current: u32 + recent_outcomes: u32`) held in a stack local.
3. **Latency hedge floor**: `IDLE_BUDGET_MIN = 16` must be large
   enough that a single round of back-to-back TCP ACKs (typically
   <2µs gap) resolves in spin. If empirical measurement shows the
   floor needs to be larger (e.g. 32), bump it before MERGE.
4. **`tx/rings.rs:249` comment** says cached `now_ns` is "stale up
   to `IDLE_SPIN_ITERS * spin_cost`". Under Design A, the actual
   staleness bound becomes `idle_budget.current * spin_cost`, which
   is `≤ IDLE_SPIN_ITERS * spin_cost`, so the existing comment's
   bound remains valid (it's an upper bound). Add a clarifying note.
5. **`BusyPoll` mode untouched**: operators in BusyPoll explicitly
   want 100% CPU. The transition update fires unconditionally but
   the branch that uses `idle_budget.current` is `Interrupt` only.
6. **CoS / fairness profile** unchanged. `IdleBudget` lives entirely
   inside the idle branch and never touches the active/poll path
   where CoS scheduling happens. Cross-reference
   [[project_per5tuple_fairness_killed]]: this change does NOT touch
   any AF_XDP UMEM ownership, queue-binding, or per-flow finish-time
   table. Structural multinomial CoV is unaffected.
7. **HA semantics**: idle-spin budget is purely local to a worker
   thread; nothing crosses the HA fabric. No session-sync impact.

## Risk assessment

| Class | Risk | Reasoning |
|-------|------|-----------|
| Behavioral regression | LOW | Change is bounded by `IDLE_BUDGET_MIN..=IDLE_BUDGET_MAX` and reduces to current behavior when `current = 256`. Worst case: behaves like today. |
| Lifetime / borrow-checker | LOW | `IdleBudget` is a stack-local u64. No new references, no Arc, no atomics. |
| Performance regression | MED | If `IDLE_BUDGET_MIN` is too low, the latency-hedge collapses and small TCP flows (HA control sockets, RPM probes, syslog) take a hit. The Phase 0 verification + a p99 latency smoke gate this. |
| Architectural mismatch | LOW-MED | Design A is straightforward; Design B is the architectural shift and we're explicitly NOT picking that. Risk is that Codex / AGY argue Design B is the right move and Design A is a band-aid. |

## Test plan

1. **Cargo build clean.**
2. **`cargo test --release`** — 952+ tests pass.
3. **5/5 flake check** on a new `idle_budget_*` unit test that
   exercises the EWMA-like u32 bitmap transition rules. Place
   alongside `worker_runtime_tests.rs`.
4. **Go suite**: `make test` passes (30 packages). No Go-side change
   means this should be a no-op.
5. **Phase 0 measurement** (BEFORE writing code): deploy master on
   loss:xpf-userspace-fw0/fw1, record:
   - idle-baseline: `xpf_userspace_worker_idle_spin_secs /
     thread_cpu_secs` per worker, 60s steady state, no flows.
   - load-baseline: same metrics during `iperf3 -P 12 -t 60 -R`.
   - flamegraph: `perf record -F 999 -g` during idle.
6. **Smoke matrix on loss userspace cluster**, Pass A + Pass B:
   - Pass A (CoS disabled): v4+v6 × push+reverse single-stream,
     plus `-P 12 -t 10 -R` multi-stream gate. 0 retrans.
   - Pass B (CoS enabled): 24-cell per-class smoke (5201-5206 ×
     v4/v6 × push/rev). 0 retrans.
7. **Phase 1 measurement (post-fix)**: same idle/load measurement as
   Phase 0. Acceptance: idle ratio drops ≥30%, load ratio unchanged,
   p99 small-flow `iperf3 -P 1 -t 30` doesn't regress >5%.
8. **`make test-failover`** — VRRP / HA failover unaffected.
9. **`make test-ha-crash`** — daemon restart unaffected.

## Out of scope (explicitly)

- Design B (`SO_BUSY_POLL = 25µs` shift) — separate issue / measurement
  pass once Design A confirms the userspace spin is the dominant
  consumer.
- Changing `PollMode::BusyPoll` behavior — opt-in 100% CPU contract.
- Removing the per-binding `poll_binding` sweep on empty iters
  (which is the other lever the issue mentions in the alternative
  section). That's a separate "batched ring-peek" refactor and would
  collide with #946 Phase 2 PLAN-KILL territory.
- Adding new Prometheus surface for `idle_budget.current` — could be
  added later if operators need it; v1 keeps the wire format stable.

## Open questions for adversarial review (please push back hostilely)

1. **Is the per-empty-iter cost really 1-2µs?** The issue body asserts
   `~18 bindings × ~30-50ns ≈ 1-2µs`. On x86 with cache-resident
   ring state, a peek pair is typically 10-30ns, so the true cost
   might be 200-600ns/iter, not 1-2µs. If so, 256 × 300ns = 76µs of
   hedge — still a lot but not as alarming. **Reviewers please call
   out if the issue's number is wrong and the problem is smaller
   than claimed.**
2. **Is Design B (SO_BUSY_POLL=25µs) strictly better than Design A?**
   If reviewers think the architecture is wrong, prefer to
   PLAN-NEEDS-MAJOR and redirect to Design B rather than ship Design
   A as a band-aid.
3. **Does `IDLE_BUDGET_MIN = 16` actually preserve the latency
   hedge?** The in-tree comment claims blocking immediately collapses
   cwnd. Is 16 iters (~1-3µs) enough? Is 32 needed? Is the floor
   itself meaningful, or should we just go to 0 and let
   `SO_BUSY_POLL` handle it?
4. **Does adaptive `current` oscillate under bursty traffic?** A
   1Hz workload that arrives once-per-second-then-idle will keep
   the budget at MIN (most idles end in IdleBlock); the first
   packet of each burst pays the hedge cost. Hysteresis at 8/32 ≤
   ≤24/32 may not be enough. Reviewers please simulate this.
5. **Does the cross-binding poll order interact with the budget?**
   `poll_start` rotates each tick; under reduced budget the rotation
   covers fewer iters per work arrival, so some bindings may be
   polled less often relative to others. Cross-binding fairness was
   the #1206/#1217 territory. Verify this doesn't reintroduce
   per-binding skew.
6. **Is the EWMA window K=32 the right size?** Too small → reacts
   too fast → oscillates. Too large → reacts too slow → doesn't
   recover CPU on a 2s-idle-then-2s-active oscillation. Is a
   token-bucket cleaner than a bitmap-of-32?
7. **Architectural mismatch vs #946 Phase 2 / #961 / #1211 KILLs.**
   This is the 5th-or-so attempt to tune the dataplane hot path;
   four prior PLAN-KILLs landed (per `MEMORY.md`). Does this fit
   the pattern of "auto-tune NIC/loop param" pitches that need
   empirical bias evidence before triple-review?

## References

- `userspace-dp/src/afxdp/worker/loop_body/mod.rs:1234-1278` — the
  idle branch under change.
- `userspace-dp/src/afxdp/mod.rs:241-243` — `IDLE_SPIN_ITERS`,
  `IDLE_SLEEP_US`, `INTERRUPT_POLL_TIMEOUT_MS` constants.
- `userspace-dp/src/afxdp/bind.rs:465-505` — `set_busy_poll_opts`.
- `userspace-dp/src/afxdp/worker_runtime.rs` — #869/#1311 telemetry
  this plan reads but does not modify.
- `userspace-dp/src/afxdp/tx/rings.rs:249` — comment that takes a
  dependency on `IDLE_SPIN_ITERS * spin_cost` staleness bound.
- Memory: [[project_per5tuple_fairness_killed]] — multinomial floor
  is independent of this change.
