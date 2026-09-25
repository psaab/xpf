# pkg/appid

Application identification runtime. Maps Junos `applications` /
`application-set` definitions to protocol+port tuples for BPF compilation,
and resolves session display names from the dataplane's assigned `app_id`.

## Entry points

- `CatalogNames(cfg *config.Config, includeAll bool) ([]string, error)` — `runtime.go`.
  Returns the list of application names the compiler must lower
  into the `app_id` catalog. `includeAll=false` returns only
  apps referenced by a security policy **or** a source/destination-NAT
  rule's `match application` (#3626 — a NAT term consumes the referenced
  app's port/proto too, so an app referenced ONLY by a NAT rule must
  still be catalogued or the dataplane cannot resolve it and session
  naming for that flow falls back to tuple/numeric); `true` returns every
  defined app. The NAT walk mirrors the commit-time strict validator
  (`config.applicationsToValidateStrict`) exactly — Source +
  Destination.RuleSets, the scalar `rule.Match.Application`, static NAT
  excluded (it carries no application match) — so the runtime catalog and
  the strict gate agree on the referenced-app set. Returns an error if
  application-set expansion fails — callers must handle it.
- `BuildCatalog(cfg *config.Config) (Catalog, error)` — `catalog.go`.
  Returns the ordered application catalog: `Entries` (each carrying
  `AppID` + `(protocol, dst-port-range, src-port-range)` match rule)
  plus `AppNames` (`app_id → name`). The id assignment is in
  lock-step with `pkg/dataplane.compileApplications` (sorted-name
  order, ids from 1), so an `app_id` stamped on a session by the
  dataplane resolves through `ResolveSessionName` to the same name.
  `pkg/dataplane/userspace` ships `Entries` to the Rust dataplane as
  the snapshot `app_catalog` field (#2008 M5); the dataplane stamps
  the matched `app_id` on each new session.
- `ResolveSessionName(appNames map[uint16]string, cfg *config.Config, proto uint8, srcPort, dstPort uint16, appID uint16) string` —
  `runtime.go`. `srcPort` is the session source port; it is threaded
  through so the tuple fallback can honor a configured `source-port`
  constraint (#3428). Lookup order: dataplane `app_id` (authoritative from
  BPF) → user-configured app tuple match (`resolveTupleFallback` →
  `matchTuple`) → narrow built-in fallback (`junos-http`, `junos-ssh`,
  …). Tuple matching requires the configured protocol to match; if the
  app also sets a `source-port` and/or a `destination-port` (single or
  `lo-hi` range), each configured port constraint must match too — when
  both are set the session's source AND destination port must satisfy
  them (#3428; before that fix a `source-port`-scoped app was matched on
  destination port alone, so any session to that dst-port was mislabeled
  regardless of its source port). A **protocol-only** custom app — one with a `protocol`
  but no `destination-port`, e.g. a user-defined GRE/ESP/AH application —
  matches on protocol alone (#2548; before that fix `matchTuple`
  rejected an empty port, so protocol-only apps never matched and their
  sessions reported `UNKNOWN`). An app with neither protocol nor port is
  never a match-all. When several configured apps match the same tuple,
  `resolveTupleFallback` resolves deterministically by **specificity**: a
  port-constrained app (`source-port` and/or `destination-port` set) wins
  over a protocol-only app of the same protocol, with remaining ties
  broken by the lowest assigned `app_id` (#2578/#10722). Before that,
  the map was iterated first-match, so a port-specific app could
  non-deterministically lose to a protocol-only sibling. This is a
  display-only label path — it does not affect policy enforcement, which
  uses the dataplane-assigned `app_id`.

  **Single precedence contract across the AppID knob (#3612):** the
  AppID-ENABLED Rust catalog (`AppCatalog::lookup_directional` in
  `userspace-dp/src/policy.rs`) resolves overlapping application labels by
  the *same* binary-specificity rule — **port-constrained beats
  protocol-only, then lowest assigned `app_id` within a tier, including
  collision-displaced IDs (#5296/#10722).** Before #3612 the enabled
  path tie-broke on the lowest `app_id` regardless of specificity, so
  the same 5-tuple could be labeled with a broad protocol-only app when
  AppID was on but the specific port-based app when AppID was off.
  Both paths now agree; the shared, self-describing fixture
  `userspace-dp/tests/fixtures/appid_precedence_v1.json` pins the agreement
  (`TestAppIDPrecedenceParityFixture` here drives the disabled path;
  `app_catalog_precedence_parity_fixture` in `policy_tests.rs` drives the
  enabled path over the same cases). The divergence was
  display/observability only — enforcement was never affected. Two adjacent
  divergences are deferred out of #3612: the disabled path's non-user
  fallback is a narrow hardcoded `builtinFallbacks` set rather than the full
  predefined catalog the enabled path sees (S1), and the disabled path has
  no reverse-direction service-slot model (S2). When AppID is **enabled** in
  `services.application-identification` and the dataplane has not
  assigned an `app_id` for the session (`appID == 0`), the function
  returns `UNKNOWN` rather than guessing from port heuristics. Used
  for session display in the CLI and gRPC paths. (`pkg/logging`
  resolves app names through its own `EventReader.resolveAppName`,
  and `pkg/flowexport` does not call this function — the wiring
  isn't shared with NetFlow / syslog.)

## Callers

`pkg/cli`, `pkg/dataplane` (compilation), `pkg/dataplane/userspace`
(catalog ship via `BuildCatalog`), `pkg/grpcapi`, `pkg/daemon`.

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
  flatten `application-set` aliases (used for both policy and NAT
  references). Callers don't need to pre-expand.
- The policy walk and the NAT walk share ONE per-reference resolver
  (`addAppRef`) inside `CatalogNames`, so the two reference paths cannot
  diverge (#3626 L04). `TestStrictValidationSetMatchesCatalogNames`
  pins the user-app subset of `CatalogNames(cfg, false)` to
  `config.ApplicationsToValidateStrict` — its fixture now carries a
  NAT-only reference so the parity covers the NAT walk too.
- `CatalogNames` is nil-tolerant on the policy walk (#3622): a nil
  `*config.ZonePairPolicies` entry or a nil `*config.Policy` entry —
  both admitted by the tolerant-load path (#1960) — is skipped rather
  than dereferenced, so a partially-broken-but-tolerated config surfaces
  a fail-closed result instead of panicking the app-catalog build. This
  matches the strict validation walker (`compiler_validate_strict.go`),
  which already `continue`s on the same nil entries.
- A nil user-application VALUE
  (`cfg.Applications.Applications["x"] = nil`, a JSON null decoding to a
  nil `*config.Application`) is another tolerated (#3494) shape.
  `config.ResolveApplication` returns `(nil, true)` for it, so `!found`
  does NOT catch it. Both AppID ingestion boundaries nil-guard the value
  (#4865): `BuildCatalog` skips it without consuming an id slot, and
  `resolveTupleFallback` skips it before `icmpTypeConstrained`/`matchTuple`.
  Without the guard `app.Protocol` panics `BuildCatalog` during
  snapshot/apply (AppID on) or the show/session-name render (AppID off) —
  turning the tolerant "warn/skip and keep running" posture into a crash.

## Tolerant-load port parsers must DEGRADE, not MISLABEL (#3725)

Strict commit (`config.validatePortSpec`, canonical unsigned parsing) rejects a
malformed port spec, but a leniently-loaded / stale-persisted / peer-synced
`config.Application` (#1960) still flows into both the AppID catalog and the
display/filter tuple fallback. The port parsers on that path must DEGRADE — drop
the bad entry — never MISLABEL a session as a wrong-but-plausible application:

- **Tuple fallback (`portInSpec`, `runtime.go`, H02/M05):** parses through
  `config.ParseCanonicalUint` and range-checks `1..65535` (via `canonicalPort`),
  exactly like the strict gate. The prior `strconv.Atoi` parse silently narrowed
  an out-of-range value through the `uint16` cast (`"70000"` → 4464, so a real
  session to port 4464 was labeled as the malformed app) and accepted a signed
  spelling (`"+80"` → 80). A malformed spec now never matches.
- **AppID catalog (`BuildCatalog`, `catalog.go`):** a catalog row is emitted
  only for an **emittable** application — a representable protocol (or an omitted
  spec, which fans out to any-L4), non-inverted destination range, a source-port
  that parses, and a non-inverted source range. A bad `source-port` no longer
  ships an unconstrained `SrcPortLow=0/High=0` row (H03/M06, which would stamp
  ANY matching dst-port flow), a reversed range no longer ships inverted bounds
  (M07), and an EXPLICIT but unrepresentable protocol (`ProtocolNumber` ok=false,
  e.g. `protocol junos-foobar` surviving a tolerant/HA-sync load) no longer ships
  a Protocol:0 (HOPOPT) row that would falsely label protocol-0 sessions (#4887).
  An unemittable app still **consumes** its `app_id` so the id sequence stays in
  lock-step with `compileApplications` (which bumps the id in those cases); only
  a dest-port parse error skips the id.
- **AppNames (`BuildCatalog` and `compileApplications`, M04):** the `app_id →
  name` mapping is recorded ONLY for an emittable app. Recording it before the
  port parse left `AppNames` holding a name at an id no `CatalogEntry` can stamp
  when the malformed app sorted last, so a skewed/stale `app_id` (helper catalog
  skew) resolved to the malformed name instead of `UNKNOWN`. Both producers are
  fixed identically; `TestAppCatalogParityOnTolerantLoadPortEdges` pins them
  byte-identical and dangling-free.

## Protocol fan-out: omitted vs explicit `protocol 0` (#4008)

An application with **no** `protocol` spec means "any L4": `BuildCatalog`
(`catalog.go`) and the retired-eBPF mirror `compileApplications`
(`pkg/dataplane/compiler.go`) each install ONE `CatalogEntry` per **TCP (6)**
and **UDP (17)** under a single shared `app_id` (the Junos custom-application
default). ICMP is naturally excluded — an ICMP app carries a non-empty
protocol.

An **explicit** `protocol <n>` — including `protocol 0` (IANA HOPOPT) — names a
single, specific protocol and compiles to exactly one `CatalogEntry` for that
protocol. Before #4008 the fan-out was keyed on the *resolved* protocol number
being 0 (`proto == 0`), which conflated three distinct cases that all resolve to
0: an omitted protocol (intended fan-out), an explicit `protocol 0`
(`ProtocolNumber("0") == (0, true)`), and an unrepresentable token on the
tolerant-load path (`ok == false`). So a single-protocol `protocol 0` app fanned
out to BOTH TCP and UDP, and a policy referencing it over-matched (a TCP-only
intent also matched the UDP flow on the same port). The fan-out is now keyed on
the protocol being **absent** (`strings.TrimSpace(app.Protocol) == ""`), so only
an omitted spec fans out; every explicit protocol stays single. Regression pins:
`TestCatalogExplicitProtocol0DoesNotFanOut`,
`TestCatalogProtocol0FromParsedConfig`, and `TestCatalogOmittedProtocolFansOut`
in `catalog_proto0_4008_test.go`.

The third case — an **explicit but unrepresentable** token (`ok == false`) — is
handled separately (#4887): keying the fan-out on the protocol being absent
stopped it from fanning to TCP+UDP, but the resolved byte still fell through to
0, so it shipped a single live `Protocol:0` (HOPOPT) row whose `app_id` the Rust
helper stamps on genuine protocol-0 sessions — a false AppID label for an
application whose protocol was known-malformed. `BuildCatalog` and
`compileApplications` now read `ProtocolNumber`'s `ok` bit and treat an
unrepresentable explicit protocol as **unemittable**: no `CatalogEntry`, no
`AppNames` name (the id is still consumed, keeping both `AppNames` maps
byte-identical). An explicit `protocol 0` stays representable (`(0, true)`) and
still ships its single row. Regression pins:
`TestBuildCatalogUnrepresentableProtocolNoRow` and
`TestBuildCatalogExplicitProtocolZeroStillShips` in
`catalog_bad_protocol_4887_test.go`.

## ICMP type/code labeling (#3781 interim)

The catalog wire (`AppCatalogEntrySnapshot`, `CatalogEntry`) is **L3/L4 only** —
it has no ICMP type/code fields — so a catalog row for an ICMP application
matches on protocol alone (a `(0,0)` destination-port pair). Policy MATCHING for
`junos-ping`/`junos-pingv6` is echo-only (`PolicyApplicationSnapshot.icmp_type`,
#3020), but the AppID LABEL catalog was not: an ICMP application that carries an
`icmp-type`/`icmp-code` constraint still shipped a protocol-only row that matched
**every** ICMP type. A non-echo ICMP (destination-unreachable, timestamp,
ICMPv6 ND) that correctly fell to default-deny was then LOGGED in RT_FLOW /
`show security flow session` with `application=junos-ping` — a false label. The
verdict engine was correct; only the audit label was wrong (log-integrity, not a
match fail-open).

**Interim (Go-only, no wire change):**

- `icmpTypeConstrained(app)` (`catalog.go`) reports whether an application has an
  ICMP/ICMPv6 type or code constraint.
- `BuildCatalog` (`catalog.go`) DROPS the over-matching protocol-only
  `CatalogEntry` for such an app, but KEEPS its `AppNames[app_id] = name` row and
  still CONSUMES the id — so the `AppNames` byte-identical parity with
  `compileApplications` (`appid_catalog_parity_test.go`) is preserved. The
  dropped entry means the helper never stamps that id, so the name is inert: a
  non-echo (or echo) ICMP resolves to an honest `UNKNOWN` — or to
  `junos-icmp-all` when a protocol-only ICMP app is also referenced — instead of
  a false `junos-ping` label. An ICMP app WITHOUT a type/code constraint
  (`junos-icmp-all`, a user protocol-only ICMP app) is unaffected.
- `resolveTupleFallback` (`runtime.go`) skips a type-constrained ICMP app on the
  AppID-disabled show/session-name path for the same reason (`matchTuple` is
  protocol+port only, blind to ICMP type/code).
- The protocol wire (`protocol_wire_v1.json`) is byte-identical: no field was
  added, one fewer `Entries` element is shipped.

**Deferred follow-up (per the #3781 /research plan):** the fully type/code-aware
catalog is a two-sided wire change (`icmp_type`/`icmp_code` as `*uint8`
omitempty on the Go snapshot + `Option<u8>` on the Rust `AppCatalogEntry`, with a
Go↔Rust decode parity test) plus a type/code-aware `lookup*` in the Rust
classifier and the deny/create label sites. Tier-2 (session close / `show
security flow session` re-derivation, which crosses the HA session-sync wire) is
a separate deliberate change requiring `test-failover`. The interim guarantees
NO FALSE LABEL (honest `UNKNOWN`), NOT positive echo classification — that
arrives with the deferred wire work.
