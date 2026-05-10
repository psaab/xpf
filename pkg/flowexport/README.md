# pkg/flowexport

NetFlow v9 exporter. Exports session-close events to remote
collectors with per-zone direction filters and 1-in-N session
sampling. (Wired only from session close — `pkg/daemon` calls
`Exporter.ExportSessionClose` from the GC delete callback. No
per-packet sampling path.)

## Entry points

- `Exporter` — `exporter.go`.
- `NewExporter(cfg)` — `exporter.go`.
- `Run(ctx)` — `exporter.go`. Main export loop.
- `ExportConfig` — `exporter.go`. Resolved per-collector config.
- `BuildExportConfig(cfg)` — `exporter.go`.
- `SamplingDir` — `exporter.go`. Direction enum.
- `SessionCloseData` — wire shape consumed from `pkg/conntrack` delete
  callbacks.

## Callers

`pkg/daemon` calls `ExportSessionClose()` from the session-close hook.

## Dependencies

`pkg/config`, `pkg/logging`.

## Gotchas

- 1-in-N sampling uses a monotonic counter on `ExportConfig`. With small
  N a burst of close events can sample several consecutive flows; that's
  expected.
- NetFlow v9 templates refresh every 60 s. If a collector restarts and
  misses a refresh it sees opaque records until the next cycle —
  configure the collector to handle template re-resolution.
- Per-zone batches flush on either timeout or batch-full, whichever
  fires first.
- The package never blocks the GC loop — record assembly is offloaded to
  the exporter's own goroutine.
