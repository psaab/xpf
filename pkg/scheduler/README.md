# pkg/scheduler

Time-window scheduler for Junos `schedulers` blocks. Evaluates active
state every 60 s and notifies a callback when any scheduler's
active/inactive state changes. Used to gate firewall filters,
forwarding-class rewrites, and other config that should engage only
during specific windows.

## Entry points

- `Scheduler` — `scheduler.go`.
- `New(schedulers map[string]*config.SchedulerConfig, updateFn func(map[string]bool)) *Scheduler` —
  `scheduler.go`. The `updateFn` callback fires only on state change,
  not every tick.
- `NewPrimed(..., now)` — constructor for daemon apply paths that need the
  initial active-state map without firing the callback while an external
  apply semaphore is already held.
- `Run(ctx context.Context)` — `scheduler.go`.
- `IsActive(name string) bool` — `scheduler.go`.
- `ActiveState() map[string]bool` — `scheduler.go`. Snapshot of every
  scheduler's active flag.
- `Update(schedulers map[string]*config.SchedulerConfig)` —
  `scheduler.go`.

## Callers

`pkg/daemon`, `pkg/cli`, `pkg/grpcapi`.

## Dependencies

`pkg/config`.

## Gotchas

- Evaluation interval is fixed at 60 s. Don't try to drive sub-minute
  precision through this package.
- `updateFn` receives the **full** active-state map, not just the
  changed entries. Callers compute their own diff if they care.
- Daemon callers must publish scheduler changes while holding the daemon
  apply semaphore. Runtime scheduler callbacks take that semaphore before
  touching dataplane state so commits and time-window flips cannot publish
  hybrid policy snapshots.
- The scheduler uses wall-clock time only in the control plane to evaluate
  Junos time windows. Packet workers must consume published active/inactive
  booleans from the userspace snapshot and must not evaluate scheduler time in
  the hot path.
- Wall-clock discontinuities are fail-closed. Each evaluation compares
  wall elapsed time with Go's monotonic elapsed time from the previous
  evaluation; backward wall steps or drift beyond the tolerance publish
  all schedulers inactive for that evaluation instead of extending an
  allow window with a stale wall-clock assumption.
