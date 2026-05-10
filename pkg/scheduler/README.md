# pkg/scheduler

Time-window scheduler for Junos `schedulers` blocks. Evaluates active
state every 60 s and notifies a callback when any scheduler's
active/inactive state changes. Used to gate firewall filters,
forwarding-class rewrites, and other config that should engage only
during specific windows.

## Entry points

- `Scheduler` — `scheduler.go:14`.
- `New(cfgs, updateFn)` — `scheduler.go:24`. The callback fires only on
  state change, not every tick.
- `Run(ctx)` — `scheduler.go:37`.
- `IsActive(name)` — `scheduler.go:54`.
- `ActiveState()` — `scheduler.go:61`. Snapshot of every scheduler's
  active flag.
- `Update(cfgs)` — `scheduler.go:72`.

## Callers

`pkg/daemon`, `pkg/cli`, `pkg/grpcapi`.

## Dependencies

`pkg/config`.

## Gotchas

- Evaluation interval is fixed at 60 s. Don't try to drive sub-minute
  precision through this package.
- `updateFn` receives the **full** active-state map, not just the
  changed entries. Callers compute their own diff if they care.
