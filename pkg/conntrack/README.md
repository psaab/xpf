# pkg/conntrack

Connection-tracking garbage collection. Periodically scans the BPF session
map, ages out expired flows, accumulates per-IP session counts for screen
rate-limiting, and fires delete callbacks (used by HA delete-sync).

## Entry points

- `GC` — `gc.go`.
- `NewGC(dp dataplane.DataPlane, interval time.Duration) *GC` — `gc.go`.
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

`dataplane` only.

## Gotchas

- Delete callbacks fire **inside** the GC loop. Keep them non-blocking
  and at `slog.Debug` for high-frequency paths — earlier `slog.Info` here
  flooded HA sync at 15 req/s.
- `MaxSessions` = 10M entries combined (forward + reverse). The
  user-visible session count is the total / 2.
- The adaptive interval kicks in near the high-water mark and aggressively
  shortens until the table drains. Don't read `GCStats.Interval` and
  assume it's the configured value.
- `SkipSweep=true` saves ~19% CPU on the userspace-dp path. If you reach
  for it on the eBPF path, sessions never expire — the eBPF path has no
  alternative GC.
