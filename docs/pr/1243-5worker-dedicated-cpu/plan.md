---
status: DRAFT v1 — pending adversarial plan review
issue: 1243
scope: 5-worker dedicated CPU mode — drop worker on CPU 0, dedicate it to daemon
---

# Plan: 5-worker dedicated CPU mode (#1243)

## 1. Issue framing

Today on the loss userspace cluster: 6 vCPUs, NIC has 6 RSS queues
(i40e PF passthrough), and the daemon spawns 6 workers — one per queue.
Worker 0 shares CPU 0 with the daemon control plane (gRPC, FRR reload,
HA sync, configstore commits, etc). The recipe doc applies a manual
`taskset -pc 0 <daemon-pid>` as a tuning knob; this pins the daemon's
non-worker threads to CPU 0 alongside worker 0.

The proposal in #1243 is to dedicate CPU 0 to the daemon entirely
(no worker on CPU 0) and run 5 workers pinned 1:1 on CPUs 1–5. The
NIC's RSS indirection table reshapes to deliver to queues 0–4 only;
queue 5 is left empty (no userspace consumer).

## 2. Honest scope/value framing

**What this is (and isn't):** a configuration + orchestration change
gated by an existing config knob (`system dataplane workers 5`),
extending the already-shipped #785 RSS indirection logic from mlx5
to i40e, and codifying the recipe-doc daemon CPU pinning into the
systemd unit. **This is not a dataplane scheduler change.** It does
not improve the multinomial RSS variance bound; it only addresses
worker-0 vs. daemon CPU contention.

**Expected impact:** narrow.

- For shaped workloads well below per-worker CPU max (the iperf-d
  12-stream CoS-on test that motivated this issue), worker 0 is at
  3.8% CPU vs others 5.8% — consistent with daemon stealing ~30% of
  worker 0's cycles. Removing that contention should make all
  5 surviving workers' per-binding capacity uniform, eliminating one
  source of within-run per-flow rate skew.
- For saturated workloads, this trades 1/6 ≈ 17% peak parallelism for
  uniform per-worker capacity. Net effect on aggregate throughput is
  expected negative on saturated push (e.g., CoS-off `iperf -P 12`
  topping out around 22.7 G).
- **Multinomial RSS variance** (12 random ephemeral ports into 5 vs 6
  bins) is *worse* with 5 bins than 6: E[max bucket] roughly the same
  but expected per-flow CoV under multinomial(12, 5) is higher than
  multinomial(12, 6). So this change does NOT improve the
  multinomial-bound CoV variance per run; it only improves
  per-binding capacity uniformity.

If reviewers conclude the per-binding-uniformity win is too small
to justify the parallelism loss + churn (especially since the
recipe knob already pins daemon to CPU 0 and gives "30%" of the
purported benefit), **PLAN-KILL is an acceptable verdict.**

## 3. What's already shipped / partially built

The existing infrastructure does most of the work:

- **#785 (`pkg/daemon/rss_indirection.go`):** already reshapes RSS
  indirection table for mlx5_core interfaces so hash outputs land
  only on queues 0..N-1. Driven from `enumerateAndRenameInterfaces()`
  at startup AND `applyConfig` reconcile. Idempotent. Has 800+ LOC of
  unit tests for weight-vector computation.
- **`system dataplane workers N` config knob:** already parsed
  (`pkg/config/parser_system_test.go:1339`); plumbed end-to-end as
  `--workers N` CLI arg to the Rust helper
  (`pkg/dataplane/userspace/process.go:75`).
- **Rust binding planner** (`userspace-dp/src/server/helpers.rs:452`):
  `binding.worker_id = (queue_id % workers.max(1)) as u32`. With
  `workers=5` and `queue_count=5` (after RSS reshape), this yields a
  clean 1:1 queue→worker mapping. *Without* the RSS reshape on i40e,
  `queue_count=6` and `workers=5` causes worker 0 to bind to both
  queue 0 and queue 5 (modulo collision) — that's the bug this plan
  must avoid.
- **Worker CPU pinning** (`userspace-dp/src/afxdp/neighbor.rs:520
  `pin_current_thread`): already honors inherited systemd
  `CPUAffinity=` mask — pins worker N to the N-th CPU in the
  allowed set. Test coverage at `neighbor.rs:617`. So setting the
  systemd unit's `CPUAffinity=1-5` makes workers 0–4 pin to CPUs 1–5
  with no Rust changes.
- **Daemon CPU pinning is currently a recipe knob:** manually applied
  as `taskset -pc 0 <pid>` after every cluster deploy. Needs to
  become permanent (systemd unit `CPUAffinity=0` on a separate
  control-plane slice, OR daemon startup code).

## 4. Concrete design

### 4.1 i40e RSS indirection support

Extend `pkg/daemon/rss_indirection.go` to handle i40e. The driver-guard
today is a hard `drv != mlx5Driver` skip
(`rss_indirection.go:188`). Replace with a driver allowlist:

```go
var rssReshapeDrivers = map[string]bool{
    "mlx5_core": true,
    "i40e":      true,
    // "ice": true — defer until needed
}
```

Then update both `applyRSSIndirection` and `restoreDefaultRSSIndirection`
to consult this map. The ethtool commands (`-L combined N`, `-X equal N`,
`-X default`) are identical across drivers — no per-driver branching
required.

**Critical addition:** i40e requires an explicit `ethtool -L <iface>
combined N` call to reduce queue count from 6 to N. Without it, the
RSS table keeps writing into queues N..5 even after `-X equal N`,
because the indirection table size is bounded by `combined`. Today
the mlx5 path doesn't issue `-L` because mlx5 RSS reshape works via
weight vector (`-X weight ...`) on the existing queue layout. **The
i40e path must use `-X equal N` AND `-L combined N`.**

To keep the abstraction clean: introduce a per-driver "reshape
strategy" (not a full Strategy pattern; just a switch):

```go
func reshapeStrategyFor(drv string) reshapeStrategy {
    switch drv {
    case "mlx5_core":
        return weightVectorStrategy{}
    case "i40e":
        return equalQueueCountStrategy{}
    }
    return nil
}
```

Each strategy implements `Apply(iface, workers, exec)` and
`Restore(iface, exec)`. Tests cover both strategies independently.

### 4.2 Daemon CPU pinning (permanent)

Replace the recipe-doc manual `taskset -pc 0 $tid` with a systemd
unit directive. The xpfd unit (currently at
`test/incus/xpf-userspace-fw.service` or similar for the loss cluster
template) gains:

```ini
[Service]
CPUAffinity=0
```

This pins the daemon's main thread + all spawned threads (gRPC,
FRR reload, HA sync, etc.) to CPU 0. The Rust helper inherits a
*different* affinity via systemd's `Delegate=true` + a sibling
slice, OR by being launched with explicit `CPUAffinity=1-5`.

**Cleanest mechanism:** the helper is launched as a child process
of the daemon. The daemon (Go) sets the helper's CPU affinity
*before* exec'ing it. There's already process-exec code in
`pkg/dataplane/userspace/process.go`. Add a step that calls
`unix.SchedSetaffinity` on the helper PID immediately after fork
but before the `--workers` arg takes effect.

Concretely, in `process.go` `Start()`:

```go
cmd := exec.Command(...)
// ... existing setup ...
if err := cmd.Start(); err != nil { return err }

// Pin helper to CPUs 1..workers
if cfg.Workers > 0 {
    var mask unix.CPUSet
    for cpu := 1; cpu <= cfg.Workers; cpu++ {
        mask.Set(cpu)
    }
    if err := unix.SchedSetaffinity(cmd.Process.Pid, &mask); err != nil {
        slog.Warn("userspace: failed to pin helper CPU affinity",
            "err", err, "workers", cfg.Workers)
        // Best-effort — do not fail the start
    }
}
```

The Rust workers' existing `pin_current_thread()` then sees
inherited mask = {1..N} and pins each worker to one CPU in that set.

**Why not systemd `CPUAffinity=` on the helper unit:** the helper is
not its own systemd unit; it's a child process of xpfd. So the
pinning has to happen at fork time.

### 4.3 Default-mode opt-in

`system dataplane workers N` is the existing knob. Behavior:

- `workers = 0` (unset / default): kernel default — one worker per
  RSS queue, no RSS reshape, no CPU pinning. Backward compatible.
- `workers = N` where N > 0: reshape RSS to N queues, pin daemon to
  CPU 0, pin helper workers to CPUs 1..N. Caller's responsibility to
  pick N ≤ (vcpu_count - 1) so the daemon has its own CPU.

No new Junos config syntax. The plan doc explicitly recommends
`workers = vcpu_count - 1` for the loss cluster (5 on a 6-vCPU VM).

### 4.4 Acceptance test matrix

The triple-review skill matrix already covers what's needed:

- Pass A (CoS off, single-stream baselines + 12-stream `-P 12 -R`):
  verify aggregate throughput regression is ≤ 17% (the parallelism
  loss bound). If aggregate drops more than that, the daemon is
  taking >1 CPU's worth of work — that's a real bug to investigate.
- Pass B (CoS on, per-class 5201–5206 v4+v6 push+rev): verify all
  shaped classes still hit their rate. Per-flow CoV measurement on
  iperf-d 12-stream is the headline acceptance criterion: target is
  CoV mean ≤ 12% over 10 samples (vs current 16.6%, with the recipe
  knob already applied).

## 5. Public API preservation

No public Go or Rust APIs change. New behavior is gated by the
existing `system dataplane workers N` knob. The new code paths
(i40e RSS reshape, helper CPU pinning) are internal helpers in
`pkg/daemon/rss_indirection.go` and `pkg/dataplane/userspace/process.go`.

Status JSON / Prometheus metrics: no schema change. Existing
`debug_planned_workers` counter
(`userspace-dp/src/protocol.rs:764`) already reports the live
worker count.

## 6. Hidden invariants the change must preserve

1. **Failover correctness** — RG transitions, VRRP becomeMaster,
   IPsec SA sync, fabric forwarding all run on the daemon control
   plane. With the daemon pinned to CPU 0, sustained 100% CPU on
   CPU 0 must not stall failover. Current 30 ms VRRP advertisements
   require sub-50 ms wakeup latency; CPU 0 contention from the
   helper's old worker 0 is exactly what's being removed.
2. **Worker→queue 1:1 invariant** — `(queue_id % workers)` produces a
   1:1 mapping ONLY when `queue_count == workers`. If the i40e RSS
   reshape silently leaves `combined=6` while `workers=5`, worker 0
   binds to both queue 0 and queue 5 → a worker handles 2 bindings,
   breaking the "uniform per-worker capacity" promise. The plan
   *must* gate `system dataplane workers N` on a successful RSS
   reshape; if the reshape fails (driver not in allowlist, ethtool
   missing, etc.), fall back to `workers = queue_count` and emit a
   warning.
3. **Boot ordering** — RSS reshape runs at startup before any
   AF_XDP socket binds. If the daemon CPU-pinning step happens
   *before* RSS reshape and reshape then fails, we end up with 6
   workers pinned to CPUs 1–5 (worker 5 pinned to non-allowed CPU
   per inherited mask logic). Order: (a) RSS reshape; (b) decide
   final `effective_workers`; (c) pin helper to CPUs `1..effective_workers`.
4. **Recipe knob backwards compatibility** — operators with the
   manual `taskset -pc 0 <pid>` recipe applied see no regression;
   the systemd-driven pinning is idempotent with the manual one.
5. **Restoration on uninstall / disable** — `system dataplane workers 0`
   (or removing the line) must `ethtool -X <iface> default` and
   `ethtool -L <iface> combined <max>` to restore queue count.
   The existing `restoreDefaultRSSIndirection` is mlx5-only; needs
   the same allowlist extension.

## 7. Risk assessment

| Risk class | Level | Notes |
|------------|-------|-------|
| Behavioral regression | LOW–MED | Failover stall on CPU 0 contention is the main concern. Mitigated by `make test-failover` smoke. |
| Lifetime / borrow-checker | NONE | Pure Go config-side change + ethtool shellouts; no Rust lifetime impact. |
| Performance regression | MED | -17% aggregate at saturation is by design but must not be larger. RSS reshape adds 1 ethtool fork per interface at startup (negligible). |
| Architectural mismatch (#946 P2 / #961 dead-end) | LOW | This is a config knob with already-shipped infrastructure. Not a refactor; not a redesign. |

## 8. Test plan

1. **Unit tests:**
   - `pkg/daemon/rss_indirection_test.go` — extend to i40e: weight
     vector path stays mlx5-only; equal-queue-count path is i40e
     (and any future driver in the allowlist).
   - New test: `applyRSSIndirection_i40eAppliesEqualAndCombined` —
     fake executor records calls, asserts `-L combined 5` AND
     `-X equal 5`.
   - New test: `applyRSSIndirection_i40eRestoresOnDisable`.
   - New test: `applyRSSIndirection_unknownDriverSkipsBoth`.
2. **Integration:** `make test-deploy` on standalone VM with
   `system dataplane workers 4` (single-VM has 4 vCPUs); verify
   `ethtool -l ge-0-0-2` shows `Combined: 4`, `ethtool -x ge-0-0-2`
   shows table cycling 0..3.
3. **5/5 named-test flake check** on the most affected new test.
4. **Go suite** — 30 packages.
5. **Cluster smoke matrix** (loss userspace cluster):
   - Pass A (CoS off): 12-stream `-P 12 -R` v4+v6 — aggregate ≥ 18.5G
     (vs current 22.7G ceiling; 17% loss is acceptable, more is a bug).
   - Pass B (CoS on): per-class 5201–5206 v4+v6 push+rev all 24
     measurements pass with 0 retrans; iperf-d 12-stream CoV ≤ 12%
     mean over 10 samples.
6. `make test-failover` — must pass. CPU 0 daemon-only pinning
   must not stall VRRP advertisements during fw0 reboot.

## 9. Out of scope

- Changing `system dataplane workers` semantics (e.g., "auto" mode
  that picks `vcpu_count - 1`). Operator picks N explicitly.
- ice driver support — defer until lab adds an ice NIC.
- Generalizing CPU pinning to non-Linux. Helper is Linux-only via
  `unix.SchedSetaffinity` already.
- Sender-side TCP head-start (#1233), per-flow buckets (#1238),
  Toeplitz auto-tune (#1244) — separate issues, separate trades.
- Per-flow CoV reduction below the multinomial(12, 5) bound. This
  plan accepts that bound; it only addresses per-binding capacity
  uniformity.

## 10. Open questions for adversarial review

1. **Is the parallelism loss real?** With CoS shaping, all workers
   are well below CPU max — does dropping worker 0 actually slow
   down anything in the shaped workload? The 17% bound is purely
   theoretical; for shaped traffic the real loss may be 0%.
2. **Does daemon→CPU 0 starve VRRP?** VRRP runs on CPU 0 alongside
   gRPC, FRR, HA sync. If a single CPU can't sustain 30 ms VRRP +
   bursty config commits, this plan is wrong and we need a
   2-CPU control-plane slice.
3. **Why not just disable CoS owner_worker_id == 0?** The issue
   body suggests "drop worker 0 from CoS queue ownership" rather
   than dropping the entire worker. That's a smaller change — but
   leaves worker 0 spinning on its AF_XDP socket consuming RX, just
   not owning any CoS queues. Is that better or worse?
4. **i40e + PF passthrough quirks** — the loss cluster runs PF
   passthrough via VFIO. Are there ethtool ordering constraints I'm
   missing? E.g., do `-L combined` and `-X equal` need a specific
   order, or does `-L` invalidate the `-X` table?
5. **Can the fallback ("workers = queue_count if reshape fails")
   itself misbehave?** If the operator sets `workers = 5` on a NIC
   with 6 queues but the i40e reshape silently fails (e.g., NIC
   firmware version that rejects `-L combined N` < default), do we
   silently revert to 6 workers and break the issue's premise? Or
   do we hard-fail the daemon? The plan says "fall back with
   warning"; reviewers should pressure-test this.
6. **Does the fairness gain even exist?** The 16.6% mean CoV on
   12-stream iperf-d already includes the recipe-knob daemon CPU 0
   pinning. The acceptance criterion of CoV ≤ 12% needs supporting
   evidence that the *additional* "no worker on CPU 0" change
   actually reduces variance. Without that evidence, this plan may
   ship a 17% throughput regression for ~zero CoV improvement.
   PLAN-KILL territory if reviewers can't see a path to that gain.
