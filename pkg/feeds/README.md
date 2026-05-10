# pkg/feeds

Dynamic-address feed fetcher. Periodically pulls CIDR prefixes from HTTP
feed servers and triggers config recompile when the resolved set changes.

## Entry points

- `Manager` — `feeds.go`.
- `New(updateFn)` — `feeds.go`.
- `Apply(cfg)` — `feeds.go`. Starts/stops per-feed refresh goroutines.
- `StopAll()`, `FeedInfo` — surfaced to `show security dynamic-address`.

## Callers

`pkg/daemon` (compile-cycle integration), `pkg/grpcapi` (status queries).

## Dependencies

`pkg/config` only.

## Gotchas

- HTTP client timeout is 30 s. Timeouts log a warning but do not stop the
  manager — the next refresh tick retries.
- Multiple feeds can share a server; each feed's path is appended to the
  base URL.
- Default refresh interval is 1 hour; the Junos config can override via
  `update-interval`.
- Feed bodies are parsed line-by-line, one CIDR per line. Invalid lines
  are skipped silently — by design, since feed providers occasionally
  emit comments.
