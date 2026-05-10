# pkg/appid

Application identification runtime. Maps Junos `applications` /
`application-set` definitions to protocol+port tuples for BPF compilation,
and resolves session display names from the dataplane's assigned `app_id`.

## Entry points

- `CatalogNames(cfg, includeAll) []string` — `runtime.go:42`. Returns the
  list of application names the BPF compiler must lower into the policy
  `app_id` table. `includeAll=false` returns only apps referenced by
  policies; `true` returns every defined app.
- `ResolveSessionName(appNames, cfg, proto, dstPort, appID) string` —
  `runtime.go:95`. Three-tier lookup: dataplane `app_id` (authoritative
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
  `app_id` field on the session. See `project_653_done.md` (memory) for
  why the operator-facing contract was made explicit.
- `application-set` aliasing must already be expanded in `cfg` before
  calling either function. This package does not flatten sets.
