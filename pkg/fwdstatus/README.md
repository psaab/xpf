# pkg/fwdstatus

Builds and renders the single-screen forwarding-daemon health view
displayed by `show chassis forwarding`. Computes 5 s / 1 m / 5 m CPU
windows from a sampled time series and pretty-prints a Junos-style
fixed-width table.

## Entry points

- `ForwardingStatus` — `fwdstatus.go`. Flat status struct.
- `Format(fs *ForwardingStatus) string` — `fwdstatus.go`. Junos-style
  one-screen render.
- `State` — `fwdstatus.go`. Online / Degraded / Unknown.
- `CPUMode` — `fwdstatus.go`. Workers vs. eBPF.

## Callers

`pkg/grpcapi` (show command), `pkg/daemon` (status sampling).

## Dependencies

`pkg/dataplane` and `pkg/dataplane/userspace` (used by `Sampler` and
`builder.go` for live BPF map / userspace-helper stats). The package
deliberately avoids importing `pkg/cli` or `pkg/grpcapi` to prevent
circular imports — those are the consumers, not dependencies.

## Gotchas

- CPU samples are collected by `Sampler` (`sampler.go`), which owns
  its own ring buffer and timer goroutine started via
  `Sampler.Start(ctx)`. The renderer consumes already-windowed
  values from the Sampler.
- The eBPF mode renders the worker-thread row as `N/A — eBPF path
  has no worker threads`. Don't add code that fakes a worker entry
  there; the N/A is informative.
- Daemon CPU is per-core percent (can exceed 100 on a multi-core
  daemon); worker CPU is computed as `Σ(thread_cpu_ns) / Σ(wall_ns)`,
  i.e. a per-worker average effectively bounded around 100%, not a
  multi-core sum.
- Windows shorter than the daemon uptime render as `-` to avoid lying
  about a 5 m average that hasn't elapsed yet.
