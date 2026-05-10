# pkg/eventengine

Event-driven automation engine implementing Junos-style `event-options`
policies. Matches RPM probe events against policy clauses (with optional
temporal `within` windows) and triggers commit-and-apply actions.

## Entry points

- `Engine` — `engine.go`.
- `New(store, commitFn)` — `engine.go`.
- `Apply(cfg)` — `engine.go`. Loads policies, resets temporal
  state.
- `HandleEvent(evt)` — `engine.go`. Called by the RPM event
  callback.
- `CommitFn` — `engine.go`. The atomic commit-and-apply hook.

## Callers

`pkg/daemon` (event loop, RPM results).

## Dependencies

`pkg/config`, `pkg/configstore`, `pkg/rpm`.

## Gotchas

- 30 s policy cooldown (`engine.go`). The same policy will not
  trigger more than once in any 30 s window.
- Temporal `within` clauses keep a sliding window of timestamps per
  (policy, event) pair. Old timestamps are pruned on every evaluation so
  the window is bounded.
- `CommitFn` holds the apply semaphore across both commit and apply — the
  same primitive HTTP/gRPC commits use (#846) — so event-triggered
  commits serialize with operator commits.
- Policy evaluation runs under a lock; command execution (the actual
  shell-out for `then ...` actions) releases the lock first to avoid
  deadlocking on a self-triggered apply.
