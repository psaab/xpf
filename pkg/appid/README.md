# pkg/appid

Application identification runtime. Maps Junos `applications` /
`application-set` definitions to protocol+port tuples for BPF compilation,
and resolves session display names from the dataplane's assigned `app_id`.

## Entry points

- `CatalogNames(cfg, includeAll) ([]string, error)` — `runtime.go`.
  Returns the list of application names the BPF compiler must lower
  into the policy `app_id` table. `includeAll=false` returns only
  apps referenced by policies; `true` returns every defined app.
  Returns an error if application-set expansion fails — callers must
  handle it.
- `ResolveSessionName(appNames, cfg, proto, dstPort, appID) string` —
  `runtime.go`. Three-tier lookup: dataplane `app_id` (authoritative
  from BPF) → exact `(proto, dstPort)` match → narrow built-in fallback
  (`junos-http`, `junos-ssh`, …). Used for session display, NetFlow
  records, and syslog session-close events.

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
- `application-set` aliasing must already be expanded in `cfg` before
  calling either function. This package does not flatten sets.
