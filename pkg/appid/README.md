# pkg/appid

Application identification runtime. Maps Junos `applications` /
`application-set` definitions to protocol+port tuples for BPF compilation,
and resolves session display names from the dataplane's assigned `app_id`.

## Entry points

- `CatalogNames(cfg *config.Config, includeAll bool) ([]string, error)` — `runtime.go`.
  Returns the list of application names the BPF compiler must lower
  into the policy `app_id` table. `includeAll=false` returns only
  apps referenced by policies; `true` returns every defined app.
  Returns an error if application-set expansion fails — callers must
  handle it.
- `ResolveSessionName(appNames map[uint16]string, cfg *config.Config, proto uint8, dstPort uint16, appID uint16) string` —
  `runtime.go`. Three-tier lookup: dataplane `app_id` (authoritative
  from BPF) → exact `(proto, dstPort)` match → narrow built-in fallback
  (`junos-http`, `junos-ssh`, …). Used for session display in the CLI
  and gRPC paths. (`pkg/logging` resolves app names through its own
  `EventReader.resolveAppName`, and `pkg/flowexport` does not call
  this function — the wiring isn't shared with NetFlow / syslog.)

## Callers

`pkg/cli`, `pkg/dataplane` (compilation), `pkg/grpcapi`, `pkg/daemon`.

## Dependencies

`pkg/config` only.

## Gotchas

- The built-in fallback table is intentionally narrow. There is no L7 DPI
  in this package — real identifications come from the dataplane's
  `app_id` field on the session. See PR #1196 for the operator-facing
  contract (`show services application-identification status` plus a
  commit warning that flags policies relying on AppID matches that the
  runtime won't actually evaluate).
- `CatalogNames` calls `config.ExpandApplicationSet` internally to
  flatten `application-set` aliases. Callers don't need to pre-expand.
