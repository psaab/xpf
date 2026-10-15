# pkg/conntrack

Connection-tracking garbage collection. Periodically scans the BPF session
map, ages out expired flows, accumulates per-IP session counts for screen
rate-limiting, and fires delete callbacks (used by HA delete-sync).
The sweep now runs through the #1381 runtime-domain surfaces: `SessionStore`
owns session iteration/deletion and companion NAT cleanup, while `Telemetry`
owns the empty-table change counters.

## Entry points

- `GC` — `gc.go`.
- `NewGC(provider RuntimeDomainProvider, interval time.Duration) *GC` —
  `gc.go`. Convenience adapter for callers that expose `Sessions()` and
  `Telemetry()` runtime domains without accepting the legacy root
  `dataplane.DataPlane` surface.
- `NewGCWithDomains(sessions, telemetry, sessionCount, persistent, interval)`
  — `gc.go`. Preferred constructor for callers that already own the split
  runtime interfaces.
- `GCStats` — `gc.go`. Last-sweep and cumulative GC statistics, also exported
  to Prometheus.
- `OnDeleteV4`, `OnDeleteV6` — per-deleted-session callbacks; HA wires
  these to the session-sync delete path.
- `IsLocalPrimary` — when this callback returns false, expiry is skipped
  on this node (peer is primary; it owns the GC decision).
- `SkipSweep` — when set, the BPF map scan is skipped entirely. The
  userspace dataplane uses this to avoid duplicating its own per-worker
  GC; the helper still mirrors sessions back to the BPF map for CLI
  display.

## Callers

`pkg/daemon`, `pkg/api`, `pkg/cli`, `pkg/grpcapi`.

## Dependencies

`dataplane` runtime-domain interfaces and session value types. Constructors no
longer accept the transitional `dataplane.DataPlane` root interface; callers
that still own a legacy bridge must adapt it before entering this package. The
sweep body must not reach through raw BPF session/counter methods directly.

## Gotchas

- Delete callbacks fire **inside** the GC loop. Keep them non-blocking
  and at `slog.Debug` for high-frequency paths — earlier `slog.Info` here
  flooded HA sync at 15 req/s.
- Expiry deletes must go through `SessionStore.DeleteBatchKnown*` with the
  `(key,value)` pair captured during iteration. That keeps GC on the batched
  map-delete path and prevents a second `GetSession*` read from racing a
  concurrent delete or losing companion metadata on backends that cannot
  perform single-entry lookups. Do not reintroduce local `DeleteDNATEntry*`
  cleanup in GC.
- `MaxSessions` = 10M entries combined (forward + reverse). The
  user-visible session count is the total / 2.
- The adaptive interval kicks in near the high-water mark and aggressively
  shortens until the table drains. Don't read `GCStats.Interval` and
  assume it's the configured value.
- `SkipSweep=true` saves ~19% CPU on the userspace-dp path. If you reach
  for it on the eBPF path, sessions never expire — the eBPF path has no
  alternative GC.
- Aggressive-aging / session-limit config (`agingActive`, `earlyAgeout`,
  `highWatermark`, `lowWatermark`, `sessionLimitEnabled`) is written by the
  config-commit path via `SetAgingConfig` / `SetSessionLimitEnabled` under
  `gc.mu`. The sweep goroutine runs on a *different* goroutine, so it snapshots
  those fields under `gc.mu.RLock()` once at the top of `sweep()` and operates
  on locals for the rest of the pass. `agingActive` is also runtime state the
  watermark hysteresis toggles — the sweep publishes any transition back to
  `gc.agingActive` under `gc.mu.Lock()`. Never read or write these fields from
  the sweep path without holding `gc.mu`; lock-free access is a data race
  (#3604) that `go test -race ./pkg/conntrack/` will flag.
