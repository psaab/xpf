# pkg/flowexport

NetFlow v9 exporter. Exports session-close events to remote
collectors with per-zone direction filters and 1-in-N session
sampling. Wired off `pkg/logging.EventReader` SESSION_CLOSE events
in `pkg/daemon/daemon_flow.go`, not the conntrack GC delete
callback. No per-packet sampling path.

## Entry points

- `Exporter` — `exporter.go`.
- `NewExporter(cfg ExportConfig) (*Exporter, error)` — `exporter.go`.
- `Run(ctx context.Context)` — `exporter.go`. Main export loop.
- `ExportConfig` — `exporter.go`. Resolved per-collector config.
- `BuildExportConfig(svc *config.ServicesConfig, fo *config.ForwardingOptionsConfig) *ExportConfig` — `exporter.go`.
- `SamplingDir` — `exporter.go`. Direction enum.
- `SessionCloseData` — wire shape built from `logging.EventReader` SESSION_CLOSE records (in `pkg/daemon/daemon_flow.go`), not from `pkg/conntrack`
  records.

## Callers

`pkg/daemon/daemon_flow.go::startFlowExporter` and
`startIPFIXExporter` call `Exporter.ExportSessionClose()` from the
`logging.EventReader` SESSION_CLOSE callback.

## Dependencies

`pkg/config`, `pkg/logging`.

## Gotchas

- 1-in-N sampling uses a monotonic counter on `ExportConfig`. With small
  N a burst of close events can sample several consecutive flows; that's
  expected.
- NetFlow v9 templates refresh every 60 s. If a collector restarts and
  misses a refresh it sees opaque records until the next cycle —
  configure the collector to handle template re-resolution.
- Two batches are maintained: `batchV4` and `batchV6` (split by
  family, not by zone). Both flush on a 100 ms ticker or on
  shutdown.
- `ExportSessionClose` builds the flow record synchronously from the
  event-reader callback. The export goroutine (started in `Run(ctx)`)
  is what actually transmits and refreshes templates; record assembly
  itself isn't offloaded.
