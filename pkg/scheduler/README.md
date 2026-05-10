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
