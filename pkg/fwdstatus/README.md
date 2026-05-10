# pkg/fwdstatus

Builds and renders the single-screen forwarding-daemon health view
displayed by `show chassis forwarding`. Computes 5 s / 1 m / 5 m CPU
windows from a sampled time series and pretty-prints a Junos-style
fixed-width table.

## Entry points

- `ForwardingStatus` — `fwdstatus.go:39`. Flat status struct.
- `Format(s ForwardingStatus) string` — `fwdstatus.go:74`. Junos-style
  one-screen render.
- `State` — `fwdstatus.go:14`. Online / Degraded / Unknown.
- `CPUMode` — `fwdstatus.go:24`. Workers vs. eBPF.

## Callers

`pkg/grpcapi` (show command), `pkg/daemon` (status sampling).

## Dependencies

None internal. Pure formatting on top of the standard library — kept
dependency-free to avoid a circular import via `pkg/cli` or `pkg/grpcapi`.

## Gotchas

- The CPU windows are tracked externally by a `Sampler` (a ring buffer
  the caller maintains). This package consumes already-windowed values
  and renders them; it doesn't sample.
- The eBPF mode renders the worker-thread row as `N/A — eBPF path has no
  worker threads`. Don't add code that fakes a worker entry there; the
  N/A is informative.
- Daemon CPU is per-core percent (can exceed 100 on a multi-core
  daemon); worker CPU is `Σ(thread_cpu_ns) / Σ(wall_ns)` and is bounded
  to `n_workers * 100`.
- Windows shorter than the daemon uptime render as `-` to avoid lying
  about a 5 m average that hasn't elapsed yet.
