# pkg/conntrack

Connection-tracking garbage collection. Periodically scans the BPF session
map, ages out expired flows, accumulates per-IP session counts for screen
rate-limiting, and fires delete callbacks (used by HA delete-sync).
The sweep now runs through the #1381 runtime-domain surfaces: `SessionStore`
owns session iteration/deletion and companion NAT cleanup, while `Telemetry`
owns the empty-table change counters.

## Entry points

- `GC` — `gc.go`.
- `NewGC(dp dataplane.DataPlane, interval time.Duration) *GC` — `gc.go`.
  Compatibility adapter for legacy callers; internally converts the dataplane
  to `SessionStore`/`Telemetry` domains.
- `NewGCWithDomains(sessions, telemetry, sessionCount, persistent, interval)`
  — `gc.go`. Preferred constructor for callers that already own the split
  runtime interfaces.
- `GCStats` — `gc.go`. Last-sweep metrics surfaced to `show system
  buffers`.
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

`dataplane` runtime-domain interfaces. The compatibility constructor still
accepts the transitional `dataplane.DataPlane` root interface, but the sweep
body must not reach through raw BPF session/counter methods directly.

## Gotchas

- Delete callbacks fire **inside** the GC loop. Keep them non-blocking
  and at `slog.Debug` for high-frequency paths — earlier `slog.Info` here
  flooded HA sync at 15 req/s.
- Expiry deletes must go through `SessionStore.DeleteWithCompanions*`.
  That is where reverse-key deletion, DNAT/DNATv6 cleanup, and persistent-NAT
  binding preservation are owned. Do not reintroduce local `DeleteDNATEntry*`
  cleanup in GC.
- `MaxSessions` = 10M entries combined (forward + reverse). The
  user-visible session count is the total / 2.
- The adaptive interval kicks in near the high-water mark and aggressively
  shortens until the table drains. Don't read `GCStats.Interval` and
  assume it's the configured value.
- `SkipSweep=true` saves ~19% CPU on the userspace-dp path. If you reach
  for it on the eBPF path, sessions never expire — the eBPF path has no
  alternative GC.
