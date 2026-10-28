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

`pkg/grpcapi` (show command), `pkg/cli` (in-process console), `pkg/daemon`
(status sampling). Both show frontends render from THIS package precisely so
one recorded fact cannot render two different ways.

## Helper crash block (#7250)

`Build` probes the dataplane for the named `CrashReporter` interface
(`HelperCrashState() (userspace.HelperCrashRecord, bool)` +
`HelperCrashHistory() ([]userspace.HelperCrashEpisode, int)`), so
`DataPlaneAccessor` stays the two-method surface every caller and test
already implements while the shared accessor is compile-checked.

`HelperCrashHistory() ([]userspace.HelperCrashEpisode, int)` — the #8397
companion, carried by the same `CrashReporter` because they have
different lifetimes. `HelperCrashState` describes the current open episode: a
supervisor retry that proves READY keeps it open until the quiet window ends,
while ordinary generation-advancing Compile closes it immediately. The
completed episode is then retained in history.

The one history row (`Helper crash episodes`) is emitted ABOVE the
`!LastExitWasCrash && !RestartPending` early return. That placement is
load-bearing: completed history exists for a helper that crashed repeatedly
and is healthy now. A row placed after the guard would render in every case
except the one it was written for, and the failure would be invisible because
a clean current-crash surface is what a healthy helper is supposed to look like.

Three things about it are easy to break:

- The probe is **not** gated on `Status()` succeeding. A crash runs
  `resetAfterHelperGoneLocked` → `clearLastStatusLocked`, so `Status()` starts
  erroring — which is the exact case the block exists to explain. Gating it the
  way the Buffer% block is gated would blank the crash surface whenever a
  helper crashed. (`isUserspace` is a type assertion, not a `Status()` outcome,
  which is what keeps the probe reachable across a crash.)
- `HelperCrashKnown` is **not** redundant with `LastExitWasCrash`. A zero
  `HelperCrashRecord` is byte-identical to a healthy one, and `ExitCode: 0`
  satisfies the `ExitCode >= 0` discriminator, so a renderer keyed on the
  record alone prints "exit code 0" for a helper that never crashed. Same
  discipline as `BufferKnown` beside `BufferPercent`.
- Current-episode rows are silent when there is no open crash episode.
  Ordinary Compile recovery journals and clears the record; a supervisor retry
  retains the episode until its quiet window expires and renders a distinct
  "recovered — running after a crash" headline while the helper is live. The
  completed-episode summary above remains visible independently of that record.
- #5838's "last restart timestamp" (#7967) is episode-scoped: a landed
  supervisor retry preserves it with the open record, and quiet-window or
  Compile recovery clears it at that same boundary. It renders WITHOUT a
  `RestartPending` guard, unlike the next-restart deadline: a past attempt is a
  fact, a future deadline is a promise.
- The Prometheus counter `xpf_dataplane_helper_crash_episodes_total` counts
  unexpected exits of helpers that reached readiness, including a sustained
  loop whose quiet window has not completed an episode. Pre-readiness failures
  are excluded. The bounded history ring separately provides completed-episode
  detail.
- The headline has five named states: four combinations of (`RestartPending` x
  `CrashLooping`), plus the recovered-running state. The retry state wins while
  the helper is running; for the other four, `RestartPending` picks the
  headline. An intentional stop is therefore "stopped", never "CRASH LOOPING",
  even though the open episode's record still satisfies the loop predicate.
- `Format` is exported and takes a flat struct, so its guards must hold for
  structs `Build` did not produce. Two mutations escaped the first matrix
  because every cell reached the guard *through* `Build`, which sanitizes on the
  way in; the cells that catch them construct `ForwardingStatus` directly.

The single shared accessor is `fwdstatus.NewAccessor` (#17128): both
frontends supply their map-stats source, the single-resolved published
backend, and their status func, and `NewAccessor` returns the concrete
accessor (userspace flavour only for a `Status`-carrying backend).
Deleting a crash method from the shared `userspaceAccessor` fails to
compile (`var _ CrashReporter = userspaceAccessor{}`), and
`accessor_17128_test.go` covers crash state and history end to end.
The per-surface wiring cells (`cli_show_chassis_adapter_test.go`,
`server_show_forwarding_adapter_test.go`) still red if a frontend
stops routing through `NewAccessor`.

## Dependencies

`pkg/dataplane/userspace` for userspace-helper status. Callers adapt
their runtime dataplane map telemetry into the package-local
`MapStats` shape; `pkg/fwdstatus` deliberately avoids importing the
root `pkg/dataplane` package, `pkg/cli`, or `pkg/grpcapi`.

## Gotchas

- CPU samples are collected by `Sampler` (`sampler.go`), which owns
  its own ring buffer and timer goroutine started via
  `Sampler.Start(ctx)`. The renderer consumes already-windowed
  values from the Sampler.
- The Sampler reads worker telemetry off the **cached** ProcessStatus
  (`CachedStatusProvider.CachedStatus()` — the Sampler's dataplane
  surface narrowed to exactly that one method in #2114, so the
  daemon-side adapter re-probes the currently published dataplane every
  tick and can never be misrouted into a `Build` path, which keys
  backend identity on `Status()` presence), NOT its own `Status()` call
  (#3970). The userspace manager's primary 1 Hz status poll
  (`statusLoop`) already fetches full `ProcessStatus` over the shared
  control socket every second and caches it; the Sampler consumes that
  cache so it adds **zero** control-socket traffic. A second periodic
  `Status()` here would double the status rate (2/s) on the socket
  shared with session installs and starve them during bulk sync
- On a cache miss (helper not yet polled), worker counters hold at
  their previous values and the sample is marked held; every worker
  window spanning that miss renders invalid rather than treating the
  interval as zero CPU. `Build()` (on-demand `show chassis forwarding`)
  still calls `Status()` directly — that is a rare CLI diagnostic, not
  a periodic poller, so it is not a rate violation.
- The eBPF mode renders the worker-thread row as `N/A — eBPF path
  has no worker threads`. Don't add code that fakes a worker entry
  there; the N/A is informative.
- Daemon CPU is per-core percent (can exceed 100 on a multi-core
  daemon); it converts `/proc` ticks with runtime `getconf CLK_TCK`
  when available and labels CPU and uptime approximate if the Linux
  ABI fallback is needed. Heap RSS uses the runtime page size rather
  than assuming 4 KiB.
- CPU windows require enough history and a fresh sampler sample. A
  newest sample older than two intervals invalidates the windows and
  renders an explicit stale-sample note; worker windows intersecting a
  held telemetry sample are invalid.
- Worker CPU is computed as `Σ(thread_cpu_ns) / Σ(wall_ns)`, i.e. a
  per-worker average effectively bounded around 100%, not a multi-core
  sum. Busy-poll mode can report near-100% while idle; it is not a
  throughput signal.
- Windows shorter than the daemon uptime render as `-` to avoid lying
  about a 5 m average that hasn't elapsed yet.
- **Online requires positive, in-window heartbeat evidence (#4875).**
  On the userspace path `State` is `Online` only when the helper
  reported at least one worker heartbeat AND every heartbeat lands in
  the `[0, 2s]` age window (`heartbeatsHealthy` in `builder.go`). An
  empty/omitted heartbeat set (worker startup, or a wire-version
  mismatch that drops the field) and a future-dated heartbeat (a
  malformed/torn clock conversion — heartbeats share the host clock, so
  a heartbeat ahead of `now` is never real liveness) both read as
  `Degraded`, never `Online`. The old `allHeartbeatsFresh` treated an
  empty slice and a future timestamp as "trivially fresh" and fell
  straight through to `Online`, giving operators and failover
  automation a false-green forwarding state.
