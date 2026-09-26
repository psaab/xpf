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

`Build` probes the dataplane for
`HelperCrashState() (userspace.HelperCrashRecord, bool)` — an anonymous
interface, matching the existing `Status()` probe, so `DataPlaneAccessor` stays
the two-method surface every caller and test already implements.

`HelperCrashHistory() ([]userspace.HelperCrashEpisode, int)` — the #8397
companion, asserted independently of `HelperCrashState` because it has a
different lifetime. `HelperCrashState` is episode-scoped and wiped by the
successful restart that ends the episode; the history is what remains, and the
one row it contributes to the block (`Helper crash episodes`) is emitted ABOVE
the `!LastExitWasCrash && !RestartPending` early return. That placement is
load-bearing: history exists for the helper that crashed repeatedly and is
healthy now, which is precisely the state that guard returns on. A row placed
after it renders in every case except the one it was written for, and the
failure is invisible because a clean crash surface is what a healthy helper is
supposed to look like.

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
- `Format` renders **nothing** when there is no episode. The record is wiped on
  a successful restart, so the block reports the current crash episode, never a
  history.
- #5838's "last restart timestamp" **is now backed** (#7967):
  `HelperLastRestartAttempt`, rendered as `Helper last restart attempt`. It is
  episode-scoped like every other field here and is cleared by the same wipe.
  That was once given as the reason it could not exist — "wiped by the very
  event it records" — but the same is true of `Restarts`, `NextRestart`,
  `ExitCode`, `Detail` and `LastExitWasCrash`, every one of which is rendered.
  A property that disqualifies six fields equally is not a reason to omit one.
  It renders WITHOUT a `RestartPending` guard, unlike the next-restart
  deadline: a past attempt is a fact, a future deadline is a promise.
- What is still missing is **history across episodes** — "has this helper
  crashed before?" — which no field on an episode-scoped record can answer and
  which is a different requirement from the bullet. Tracked as #8397.
- The headline is four named states over (`RestartPending` x `CrashLooping`),
  and `RestartPending` picks it — a stopped helper reads "stopped", never
  "CRASH LOOPING", because the loop predicate stays true after an intentional
  stop.
- `Format` is exported and takes a flat struct, so its guards must hold for
  structs `Build` did not produce. Two mutations escaped the first matrix
  because every cell reached the guard *through* `Build`, which sanitizes on the
  way in; the cells that catch them construct `ForwardingStatus` directly.

Both frontends must expose the accessor on their `forwardingStatus*Userspace*`
adapter or the probe silently misses with **no compile error** —
`cli_show_chassis_adapter_test.go` and `server_show_forwarding_adapter_test.go`
each carry a cell that reds on that deletion, because this package's own tests
cannot see the wiring.

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
