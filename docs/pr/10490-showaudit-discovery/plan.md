# Plan — #10490 Showaudit name discovery misses quarantined-state builders

## Status

**DRAFT v3 — round-1 reviewer adjudication applied; plan-only round.**

- Base `b71c52d60`; branch `fix/10490-showaudit-discovery`.
- STEP-0: NOT fixed. The evidence revision
  `1a6952b61ef5f7dcf0fdd1786d91b14c9bb3f705` and HEAD have no diff on
  the four evidence paths; `gh pr list --search "10490"` was empty;
  no merged PR touches the gate or quarantine call sites. The scoped
  gate test passed at HEAD, so the defect is live while the gate is
  green:
  `go test ./pkg/showaudit/ -run TestEveryBuilderDropPredicateIsRegistered6534 -count=1`.
- This round changes documentation only. No production code, gate code,
  or tests are part of this branch.
- Round-1 review dispositions: reviewer A PLAN-NEEDS-MINOR and reviewer
  B PLAN-NEEDS-MAJOR. Their required census, structured-surface,
  ZoneIDs, ifZone, and sibling-order decisions are recorded below.

### Joint implementation contract (locked with #10489)

The two lanes explicitly agreed in hub before this v2:

1. **Order:** #10490 lands first. It owns the gate mechanics, predicate
   names, zone family row, exact census, and one permanent canary. The
   row deliberately has a non-empty `Unannotated` list and live
   `Successor: "#10489"`; the gate remains green because the successor is
   present. #10489 then owns the remaining renderer decisions and drains
   the list to nil. A single combined PR is rejected for this split.
2. **Names:** `config.ZoneQuarantineExclusions` is the builder-facing
   alias delegating to the existing SSOT; the per-object helper is
   `config.ZoneQuarantineExcludedReason(name, cfg)`. No rename of
   `QuarantinedZoneNames`, regex family-name widening, or marker rewrite.
3. **Ownership:** #10490 owns the alias, row, `Security.Zones` +
   `ZoneIDs` collections, census, and the `showZonesDisplay` canary.
   #10489 owns all remaining annotations using those exact helper names.
4. **Structured surfaces:** `GetZones` and `zonesHandler` are included
   in the initial non-nil census under the no-wire-change skeleton.
   #10489 drains them with exact `exemptRenderers` entries naming the
   structured-wire follow-up (no broad package exemption and no claim
   that the current wire is truthful). The remote `cmd/cli showZones`
   is not in `surfacePkgs`; it calls `GetZones`, so its truthfulness is
   inherited from that structured RPC. Two follow-ups are linked before
   drain: structured-wire quarantine truth and adjacent-surface behavior.
5. **Issue liveness:** #10489 stays OPEN until its drain is merged. The
   gate cannot validate that a `Successor` issue remains live.

## Issue framing

`pkg/showaudit` gates the `docs/engineering-style.md` #6534 contract:
"A fail-closed exclusion owes a show-surface annotation".
`TestEveryBuilderDropPredicateIsRegistered6534`
(`pkg/showaudit/surface_gate_6534_test.go:232-282`) scans
`pkg/dataplane/userspace` for `config.*` calls and keeps only names
matching `dropPredicateName` (:214), then asserts exact equality with
registered `BuilderPredicates`. The regex accepts **six suffix shapes**:
`ExcludedReason`, `UnusableReason`, `DisarmedReason`, `Exclusions`,
`Unsupported`, and `Undefined`.

The builder calls `config.QuarantinedZoneNames` at:

- `pkg/dataplane/userspace/zones.go:145` (`quarantinedZoneNames`, the
  #6722 egress pre-filter);
- `pkg/dataplane/userspace/zones_quarantine.go:65`
  (`quarantineCollidingZones`, the actual fail-closed drop); and
- `pkg/dataplane/userspace/zones_quarantine.go:236`
  (`quarantinedZoneNamesForConfig`, the #6480 partial-republish
  re-scrub).

The name matches none of the six accepted suffix shapes. The exact gate
therefore sees no zone family and no zone renderer census, while the
quarantine can remove a zone from the dataplane and ordinary show
surfaces can continue presenting config as installed.

The repo-wide, non-test direct-call census is **6 calls in 5 caller
files**: those three builder calls plus `pkg/cli/apply.go:43`,
`pkg/daemon/ipsec_capture_wiring_9506.go:232`, and
`pkg/policymatch/policymatch.go:1631`. The gate-scoped population is
only the **3 calls in 2 userspace files**. The 10490 landing checklist
must repeat this direct-call census and confirm that no call was missed;
after wrapper cutover, the expected direct old-name remainder is the
three non-builder callers, while the three userspace calls use the
alias.

A second propagation path is `CompileResult.ZoneIDs`: `assignZoneIDs`
(`pkg/dataplane/compiler.go:355-359`) unconditionally assigns an ID to
every configured zone, including a quarantined name. Reverse maps over
`cr.ZoneIDs` can therefore carry the same name/id ambiguity that
`syslogZoneNameMap` explicitly avoids. `ZoneIDs` must be a second
collection in the row; `Security.Zones` alone cannot discover it.

## Scope value

Landing this plan's implementation buys:

1. The gate discovers both direct builder quarantine calls and the
   `ZoneIDs` propagation path, rather than only the obvious config-map
   family.
2. A zone family row forces a renderer census and a shared reason
   predicate. The gate will red on an unregistered new builder call or
   a newly lying renderer.
3. The first PR proves the row is live with one permanent text canary;
   #10489 then carries the larger renderer close without inventing a
   second predicate spelling or a parallel census.
4. Structured output is not silently declared irrelevant: `GetZones`
   and `zonesHandler` remain named, non-nil `Unannotated` entries with
   `Successor: "#10489"` under the explicit no-wire-change skeleton.

## Blast radius and exact census

All counts below are from the gate's own AST helpers
(`parsePackage` + `rangesOverAny`) or a narrow source census; tests are
excluded by `parsePackage` unless explicitly called out.

| Population | Count | Evidence / interpretation |
|---|---:|---|
| Existing gate families | 7 | `surface_gate_6534_test.go:85-194`; no zone row |
| Accepted discovery suffix shapes | 6 | `surface_gate_6534_test.go:214` |
| Builder functions scanned | >=100 | Existing non-vacuity floor in `:245-247` |
| Surface packages | 5 | CLI, gRPC, REST, natshow, userspace/format (`:62-68`) |
| Gate-visible direct old-name calls | 3 calls / 2 files | `zones.go:145`; `zones_quarantine.go:65,236` |
| Repo-wide non-test direct old-name calls | 6 calls / 5 files | + CLI reverse map, daemon capture, policymatch |
| Raw `Security.Zones` loops | 39 loops / 26 files | CLI 15 (14 prod + 1 test), gRPC 16, API 8; one test loop total |
| Gate `Security.Zones` input | 38 functions / 25 files | non-test only, before exemptions |
| Existing global completion exemptions | 2 functions / 2 files | `pkg/cli/completion.go:valueProvider`; `pkg/grpcapi/server_cluster.go:valueProvider` |
| `Security.Zones` baseline after exemptions | 36 functions / 23 files | no new exemption is introduced by #10490 |
| Raw `ZoneIDs` loops | 19 functions / 13 files | CLI, gRPC, REST, and natshow; all non-test |
| `ZoneIDs`/`Security.Zones` function overlap | 2 functions | `pkg/api:buildSessionView`; `pkg/grpcapi:buildSessionFilter` |
| Marginal ZoneIDs population | +17 functions / +9 files | de-duplicated union, before global exemptions |
| Exact union before exemptions | 55 functions / 34 files | `Security.Zones ∪ ZoneIDs` |
| Exact union after existing exemptions | 53 functions / 32 files | completion providers removed |
| Initial permanent canary | 1 function | `pkg/cli/cli_show_security_zones.go:showZonesDisplay` |
| Initial row `Unannotated` | 52 functions | exact union after exemptions minus canary |

The exact union was independently measured by a temporary probe calling
`parsePackage` and `rangesOverAny`; the probe was deleted before the v2
plan edit. The implementation MUST materialize the sorted 52-entry list
below, not hand-wave the count or add a new exemption:

```text
pkg/api/api.go:allInterfaceNames
pkg/api/interfaces.go:interfacesHandler
pkg/api/interfaces.go:writeInterfacesDetail
pkg/api/interfaces.go:writeInterfacesTerse
pkg/api/metrics_counters.go:collectZoneCounters
pkg/api/nat.go:natPoolStatsHandler
pkg/api/security.go:zonesHandler
pkg/api/sessions.go:buildSessionView
pkg/api/sessions.go:sessionZonePairHandler
pkg/api/stats.go:ifaceStatsHandler
pkg/cli/cli_request_testcmd.go:testSecurityZone
pkg/cli/cli_show_cluster.go:showChassisClusterStatus
pkg/cli/cli_show_flow.go:showFlowSession
pkg/cli/cli_show_flow.go:showTopTalkers
pkg/cli/cli_show_interfaces.go:showInterfaces
pkg/cli/cli_show_interfaces_detail.go:showInterfacesDetail
pkg/cli/cli_show_interfaces_detail.go:showInterfacesRethDetail
pkg/cli/cli_show_interfaces_extensive.go:showInterfacesExtensiveFiltered
pkg/cli/cli_show_interfaces_stats.go:showVlans
pkg/cli/cli_show_nat.go:showNATDestinationSummary
pkg/cli/cli_show_nat.go:showNATSourceSummary
pkg/cli/cli_show_security_log.go:showSecurityLog
pkg/cli/cli_show_security_screen.go:showScreen
pkg/cli/cli_show_security_screen.go:showScreenIdsOption
pkg/cli/cli_show_security_screen.go:showScreenIdsOptionDetail
pkg/cli/cli_show_security_screen.go:showScreenStatisticsAll
pkg/cli/apply.go:syslogZoneNameMap
pkg/cli/session_filter.go:populateIfaceMaps
pkg/grpcapi/server_helpers.go:allInterfaceNames
pkg/grpcapi/server_nat.go:GetNATDestination
pkg/grpcapi/server_nat.go:GetNATPoolStats
pkg/grpcapi/server_sessions.go:buildSessionFilter
pkg/grpcapi/server_sessions.go:computeZonePairSummary
pkg/grpcapi/server_show_events.go:GetEvents
pkg/grpcapi/server_show_flow.go:showSessionsTop
pkg/grpcapi/server_show_interfaces.go:GetInterfaces
pkg/grpcapi/server_show_interfaces.go:ShowInterfacesDetail
pkg/grpcapi/server_show_interfaces.go:showInterfacesTerse
pkg/grpcapi/server_show_interfaces.go:writeRethDetail
pkg/grpcapi/server_show_interfaces_text.go:showInterfacesDetail
pkg/grpcapi/server_show_interfaces_text.go:showInterfacesExtensive
pkg/grpcapi/server_show_interfaces_text.go:showVLANs
pkg/grpcapi/server_show_security_text.go:showScreen
pkg/grpcapi/server_show_security_text.go:showScreenIDSOption
pkg/grpcapi/server_show_security_text.go:showScreenIDSOptionDetail
pkg/grpcapi/server_show_security_text.go:showScreenStatisticsAll
pkg/grpcapi/server_show_security_text.go:showSecurityLog
pkg/grpcapi/server_show_zones.go:GetZones
pkg/grpcapi/server_show_zones_text.go:showTestZone
pkg/grpcapi/server_show_zones_text.go:showZonesDetail
pkg/natshow/dest.go:RenderDestRuleDetail
pkg/natshow/source.go:RenderSourceRuleDetail
```

The list intentionally excludes the two global completion providers and
`showZonesDisplay` (the permanent canary). It includes the structured
handlers and the metrics/session/NAT paths so they cannot disappear into
a false "text-only" scope.

## Shipped context

- PR #3837 (merged, 19 files, closes #3719) shipped
  `config.QuarantinedZoneNames` as the sorted-first, HA-symmetric SSOT;
  `quarantineCollidingZones` drops the later-sorting zone, unzones its
  interfaces to default-deny, and scrubs policies so Rust's
  `UnresolvableZoneReference` preflight does not brick the snapshot.
  It also shipped deterministic reverse maps, one-shot logging,
  `ProcessStatus.ZoneIDCollisions`, the
  `xpf_userspace_zone_id_collision` gauge, and Rust's DuplicateZoneId
  backstop. It did not ship a #6534 family row or per-object show
  annotation.
- #6480 added partial-republish policy re-scrubbing;
  #6722 added the egress pre-filter; #5577 defined prune-vs-drop for
  scoped-global sets. Full-build quarantine is entered from
  `pkg/dataplane/userspace/builder.go:205`.
- `TestSurfaceAnnotationCensusIsExact6534` has deliberately **no
  emit-output filter** (`:343-350`). Every non-test function ranging a
  selected collection enters the population unless it is in
  `exemptRenderers`; `reachesPredicate` only partitions annotated from
  unannotated. The existing two completion exemptions are therefore the
  only automatic removals in the exact counts above.
- The strict commit path rejects collisions. Quarantine is the lenient
  backstop for tolerant load, HA sync from an older peer, or persisted
  pre-#3075 config. The implementation must pin this reachability with
  a `Commit()`-based negative fixture rather than assuming every path is
  ordinary commit-reachable.
- `manager_sessionsync_request.go:282-295` contains a separate inline
  sorted-min owner selection. It is not a direct SSOT call and is not
  in the 6-call census; it is an existing follow-up for single-source
  cleanup, not a reason to widen this plan's production scope.

## Design

### Options

**A — true rename.** Rename `QuarantinedZoneNames` to an accepted
shape. This changes 6 production call sites, 2 test files with qualified
calls, and live docs prose (`docs/config-schema.md`), while the 3
non-builder callers sit outside the gate and gain no discovery value.
It also creates avoidable conflicts with quarantine consumers.

**B — wrapper plus explicit row (recommended).** Keep the stable SSOT
and add `ZoneQuarantineExclusions`, which matches the existing generic
`*Exclusions` gate shape. Switch only the 3 userspace builder calls.
Add a row that names both collections and the renderer predicate. This
makes the new builder calls discoverable without a family-specific regex
branch, and avoids the vacuous existence path where the existing
`cli/apply.go:43` reverse map could satisfy a row for the old name.

**C — replace name discovery with a type/marker mechanism.** This would
close the entire convention class but changes the gate contract for all
seven families. File it as a follow-up now; do not combine it with this
bounded wrapper/census work.

### Helper shape (A3 decision)

Adopt A3-(b): expose the exact `(name, cfg)` helper shape and keep the
pure collision computation behind it, rather than exporting A3-(a)'s
name-set core. The renderer owns only the object name and typed config;
deriving the exact `cfg.Security.Zones` key set inside one helper keeps
all surfaces on the builder's SSOT and prevents each caller from
rebuilding a subtly different name set.

### Implementation sequence and ownership


**#10490 first (this plan):**

1. Add `ZoneQuarantineExclusions` and
   `ZoneQuarantineExcludedReason(name, cfg)` in `pkg/config`; both
   delegate to the existing sorted-name SSOT. The reason helper extracts
   exactly `cfg.Security.Zones` keys, matching `buildZoneSnapshots`'s
   source set.
2. Switch the 3 `pkg/dataplane/userspace` call sites to the alias. The
   quarantine behavior and no-brick policy/interface invariants remain
   byte-identical.
3. Add the family row with `Collections: ["Security.Zones", "ZoneIDs"]`,
   `BuilderPredicates: ["ZoneQuarantineExclusions"]`,
   `SurfacePredicates: ["ZoneQuarantineExclusions",
   "ZoneQuarantineExcludedReason"]`, the exact 52-entry initial
   `Unannotated` list, and `Successor: "#10489"`.
4. Add the one permanent canary annotation to
   `pkg/cli/cli_show_security_zones.go:showZonesDisplay`. It is a text
   inventory path and proves the detector has at least one true positive;
   no temporary marker and no new exemption is allowed.
5. Record RED-on-revert: reverting the alias call must fail the exact
   builder registry test naming the alias; reverting the canary's reason
   call must fail the exact census naming `showZonesDisplay`.
6. At landing, re-run the direct-call census: before cutover, exactly 6
   non-test direct SSOT calls in 5 files; after cutover, exactly 4 old
   calls in 4 files (the 3 non-builder consumers plus the wrapper body)
   and 3 alias calls in 2 builder files. Any other result blocks the PR.

**B-A1 hatch:** Post-cutover SSOT reuse from `builderPkg` stays
gate-blind by construction; it is closed at landing by invariant 9 and
long-term by the Option-C follow-up.

**#10489 second:**

1. Use only the exact two helper names and the exact two collections.
2. Triage every remaining entry in the 52-entry list. The five agreed
   operator inventory paths are:

   | Path | v2 disposition | Reason |
   |---|---|---|
   | `pkg/cli/cli_show_security_zones.go:showZonesDisplay` | ANNOTATE in #10490 | Permanent text canary and local inventory surface |
   | `pkg/grpcapi/server_show_zones.go:GetZones` | EXEMPT in #10489 | Structured wire has no reason/presence slot; cite structured-wire follow-up |
   | `pkg/grpcapi/server_show_zones_text.go:showZonesDetail` | ANNOTATE in #10489 | Text surface can carry the shared reason |
   | `pkg/api/security.go:zonesHandler` | EXEMPT in #10489 | Structured wire has no reason/presence slot; cite structured-wire follow-up |
   | `cmd/cli/show_security.go:showZones` | INHERITS GetZones | Outside `surfacePkgs`; remote output truth follows the gRPC wire |

   No adjacent interface, screen, metric, session, NAT, event, or test
   command is silently declared fixed by this five-path scope.
3. For every other entry, output/serialization functions call the
   shared reason helper or add the reviewed structured reason field.
   Only exact no-Zone-value-enforcement helpers may receive an exact
   `exemptRenderers` key; the two named structured inventory handlers
   are the only no-wire exceptions. No adjacent output is exempted just
   because its behavior is deferred.
4. Keep `GetZones` and `zonesHandler` out of the initial skeleton's
   exemption map; they are non-nil `Unannotated` entries under
   `Successor: "#10489"`. At drain, add their exact structured-wire
   exemptions with the follow-up issue linked. This is the agreed
   no-wire-change option, not a hidden collection omission.
5. Annotate `showZonesDetail` and every other text, NAT/session, event,
   screen, interface, VLAN, RETH, or test-command path that outputs a
   zone value. Metric paths call the reason helper and omit the metric
   sample when it returns non-empty. No-Zone-value helpers retain only
   their site-specific rationale.
6. Drain the row to `Unannotated: nil` only after every remaining entry
   is predicate-reached or has an exact, reviewed no-Zone-value or
   structured exemption. #10489 stays OPEN until that drain is merged.
   Before drain, link two follow-ups: structured-wire quarantine truth
   (`GetZones`/`zonesHandler` enum + presence) and adjacent-surface
   behavior (interfaces, screen, metrics, sessions, NAT, events, and
   test commands).

### Per-site interface/ifZone decisions

The gate has no output filter. The annotation bias therefore applies to
every function that prints or serializes a Zone value. The permanent
`showZonesDisplay` canary is the only #10490-owned annotation; every
other ANNOTATE row below is owned by #10489 and must land before its
successor is drained. Only the two no-Zone-value-enforcement cases below
are EXEMPT (plus the explicitly named structured inventory exceptions).

| Function | Disposition | Site-specific rationale |
|---|---|---|
| `pkg/api/interfaces.go:interfacesHandler` | ANNOTATE | Structured InterfaceStats Zone field is an enforcement claim; #10489 adds the shared reason representation in its implementation |
| `pkg/api/interfaces.go:writeInterfacesTerse` | EXEMPT | Builds `ifaceZoneName` but never reads it; this helper makes no Zone-value enforcement claim |
| `pkg/api/interfaces.go:writeInterfacesDetail` | ANNOTATE | Text Zone line reports authored interface state; #10489 uses the shared reason |
| `pkg/api/stats.go:ifaceStatsHandler` | ANNOTATE | Structured interface stats Zone field reports authored state; #10489 adds the shared reason representation in its implementation |
| `pkg/cli/cli_show_cluster.go:showChassisClusterStatus` | EXEMPT | Emits VRRP rows, not a Zone value; this output makes no Zone-value enforcement claim |
| `pkg/cli/cli_show_interfaces.go:showInterfaces` | ANNOTATE | Authored Security Zone column can lie after dataplane unzoning |
| `pkg/cli/cli_show_interfaces_detail.go:showInterfacesDetail` | ANNOTATE | Authored Security zone text can lie after dataplane unzoning |
| `pkg/cli/cli_show_interfaces_detail.go:showInterfacesRethDetail` | ANNOTATE | Authored RETH Security zone text can lie after dataplane unzoning |
| `pkg/cli/cli_show_interfaces_extensive.go:showInterfacesExtensiveFiltered` | ANNOTATE | Authored Security zone text is an enforcement claim |
| `pkg/cli/cli_show_interfaces_stats.go:showVlans` | ANNOTATE | VLAN Zone column is an enforcement claim |
| `pkg/grpcapi/server_show_interfaces.go:GetInterfaces` | ANNOTATE | Structured protobuf Zone field is an enforcement claim; #10489 adds the shared reason representation in its implementation |
| `pkg/grpcapi/server_show_interfaces.go:ShowInterfacesDetail` | ANNOTATE | Interface detail output carries Zone state |
| `pkg/grpcapi/server_show_interfaces.go:showInterfacesTerse` | ANNOTATE | Terse interface output carries Zone state |
| `pkg/grpcapi/server_show_interfaces.go:writeRethDetail` | ANNOTATE | RETH Zone output is an enforcement claim |
| `pkg/grpcapi/server_show_interfaces_text.go:showInterfacesDetail` | ANNOTATE | Text Security zone line can lie after dataplane unzoning |
| `pkg/grpcapi/server_show_interfaces_text.go:showInterfacesExtensive` | ANNOTATE | Text Security zone line is an enforcement claim |
| `pkg/grpcapi/server_show_interfaces_text.go:showVLANs` | ANNOTATE | VLAN Zone column is an enforcement claim |

The same rule applies to the remaining non-interface entries: exact
no-Zone-value-enforcement helpers (`allInterfaceNames`,
`populateIfaceMaps`, `buildSessionView`, `buildSessionFilter`, and the
existing collision-aware `pkg/cli/apply.go:syslogZoneNameMap`) are
EXEMPT only because they emit no Zone enforcement state. Metrics,
NAT/session/event/screen, and test-command functions that output zone
names are ANNOTATE; metric functions omit the sample when the shared
reason is non-empty, and #10489 owns those calls. The only no-wire
structured exemptions are the explicitly named `GetZones` and
`zonesHandler`, each citing the structured-wire follow-up.

## API

- `pkg/config/zoneid.go`:
  - `func ZoneQuarantineExclusions(names []string) map[string]struct{}`
    delegates to `QuarantinedZoneNames`; it is the set-shaped builder
    alias matching the `*Exclusions` discovery convention.
  - `func ZoneQuarantineExcludedReason(name string, cfg *Config) string`
    extracts the config's zone-name set, delegates to the SSOT, and
    returns `""` for the survivor/ordinary case or a reason naming the
    quarantined zone, surviving owner, and stable ID.
  - `QuarantinedZoneNames` remains unchanged for the 3 non-builder
    callers and existing tests.
- `pkg/showaudit/surface_gate_6534_test.go`: add one family row:
  - `Name: "security zone"`;
  - `Collections: []string{"Security.Zones", "ZoneIDs"}`;
  - `BuilderPredicates: []string{"ZoneQuarantineExclusions"}`;
  - `SurfacePredicates: []string{"ZoneQuarantineExclusions", "ZoneQuarantineExcludedReason"}`;
  - exact 52-entry `Unannotated` list in the initial skeleton;
  - `Successor: "#10489"` (must remain a live issue until drain).
- `pkg/dataplane/userspace`: only the 3 builder call expressions
  switch to the alias. No snapshot, wire, REST, protobuf, or Rust
  schema change is part of the #10490 skeleton.
- Structured `GetZones` and `zonesHandler` are explicitly in the row's
  initial census, not out of scope; they are carried by #10489's live
  successor under the no-wire-change first landing.

## Invariants

1. **Exact builder equality:** called and registered predicate sets are
   equal in both directions; a new alias call or stale row reds.
2. **Exact collection union:** the row scans both `Security.Zones` and
   `ZoneIDs`; the 55-function/34-file union is de-duplicated by the
   gate's function identity and has only the 2 existing completion
   exemptions.
3. **Shared verdict:** builder and annotated surfaces use the same
   alias/reason chain; no new sorted-first algorithm is introduced.
4. **Reason or explicit disposition:** every output/serialization path
   consults the shared reason. Text and structured paths carry the
   reason representation; metric paths omit the sample when the reason
   is non-empty. Only exact no-Zone-value-enforcement helpers and the
   named `GetZones`/`zonesHandler` no-wire cases are exemptions.
5. **HA symmetry:** the verdict is a pure function of the full config
   zone-name set; both HA nodes and cold boot agree.
6. **No-brick behavior:** dropping the later-sorting zone, unzoning its
   interfaces, and scrubbing policies is unchanged; the first PR adds
   discovery/annotation only.
7. **Lenient reachability:** a strict commit rejects the collision; the
   negative fixture proves the quarantine path is tolerant-load/HA-sync
   reachable.
8. **Order/ownership:** #10490 first has a live non-nil successor and
   one canary; #10489 owns and closes every remaining census entry.
9. **Landing reconciliation:** direct old-name calls are exactly 6/5
   before cutover and exactly 4/4 after alias cutover (3 non-builder
   consumers plus the wrapper body); alias calls are exactly 3/2.
   Any missed direct call blocks the row.
10. **Successor liveness:** the row cannot self-validate issue liveness;
    human merge gates require #10489 to remain open until the census is
    drained.

## Risk (4-class)

1. **Discovery correctness.** A wrapper that misses `Exclusions$`, or a
   stale row, can make the builder gate vacuous or falsely clean.
   Mitigation: exact callsite equality, non-vacuity floor, alias
   RED-on-revert, and the landing direct-call reconciliation.
2. **Census correctness.** The 55/34 union includes interface maps,
   metrics, session/NAT reverse maps, structured handlers, and text
   renderers. `ZoneIDs` is not a synonym for `Security.Zones`.
   Mitigation: gate-owned AST list, exact 52-entry skeleton, no new
   exemptions in #10490, per-site #10489 rationale, and a second
   RED-on-revert for the canary.
3. **API and wire truthfulness.** Structured JSON/protobuf paths require
   the shared reason representation in their #10489-owned implementation;
   metric paths have no text slot, so they consult the reason helper and
   omit the sample for a quarantined object. The only no-wire exceptions
   are `GetZones`/`zonesHandler`, which remain non-nil under #10490 and
   receive exact #10489 exemptions citing the structured-wire follow-up.
   No package-wide exemption is allowed, and the gate closes only after
   every output key is annotated, omitted by that metric rule, or covered
   by one of those exact no-claim dispositions.
4. **Coordination and cutover.** Two branches could use different
   names, rows, or issue ownership. Mitigation: locked exact names,
   #10490-first order, #10489-open-until-drain, explicit canary, and
   no single-PR overlap.

## Test plan

### #10490 skeleton gate

- Run the full module, not only the expected flip:
  `go test ./pkg/showaudit/... -count=1`.
- `TestEveryBuilderDropPredicateIsRegistered6534`: the three alias
  calls and one row match exactly; stale direct old-name rows are not
  allowed.
- `TestEveryFamilyHasABuilderAndASurfaceCaller6534`: the alias and
  canary reason helper make the row non-vacuously two-sided.
- `TestSurfaceAnnotationCensusIsExact6534`: the 55/34 union minus the
  two global completion exemptions has 53 entries; the permanent
  `showZonesDisplay` canary is annotated and the other exact 52 are
  listed with `Successor: "#10489"`.
- `TestExemptionsNameRealRenderers6534`: existing completion entries
  remain real; #10490 adds no exemption. When #10489 drains the row,
  only exact no-Zone-value helpers and the two named structured handlers
  may be added, each with a written rationale; no package wildcard.
- RED-on-revert evidence in the PR: remove one alias call and observe
  the named builder-registry failure; remove the canary reason call and
  observe the named census failure.

### Agreement and reachability

- Add the style-rule-4 agreement fixture for the known colliding pair
  `z174`/`z214` (premise-check that both fold to 53547): builder drops
  `z214`, the canary reports the reason, and survivor `z174` is clean.
  #10489 extends the fixture to every renderer it closes.
- Keep a `Commit()`-based negative fixture proving ordinary strict commit
  rejects the collision and tolerant load reaches the quarantine.
- At implementation landing, record the direct-call census numbers and
  the exact sorted function list; do not derive them from docs,
  comments, or broad grep output.
- Parent runs project-wide validation and cluster/incus smoke after all
  wave-1 branches land. No cluster command is required in this plan
  round.

## Out of scope

- No production code in this plan-only branch; no gate implementation,
  renderer implementation, or wire change lands here.
- The independent u04 `LastSnapshotRejectReasons` show gap
  (`manager.go:233`, `protocol_status.go:81`,
  `metrics_userspace.go:170`) remains a separate issue.
- Rust helper changes; the DuplicateZoneId backstop shipped in #3837.
- Replacing name discovery with a type/marker mechanism (Option C).
  File that follow-up before A+B lands; it remains the class-level fix.
- Renaming `QuarantinedZoneNames`; the wrapper is the agreed cutover.
- Changing the existing `ZoneIDCollisions` status/gauge wording; the
  status channel is already additive and working.
- The existing inline sorted-min owner in
  `manager_sessionsync_request.go`; it is acknowledged follow-up debt,
  not another implementation in this PR.
- Historical `_Log.md` and review-archive prose.

## Open questions (resolved for DRAFT v3)

1. **Wrapper or rename?** Wrapper. The 3 non-builder callers gain no
   gate value from a rename; true rename costs 6 prod + 2 test files +
   docs. `ZoneQuarantineExclusions` is the generic #7357 shape.
2. **Regex widening?** No. A `Quarantin\\w*` branch makes the generic
   gate enumerate family names and lets the existing reverse-map call
   satisfy an existence check vacuously.
3. **Reason signature?** `(name, cfg)`, with config-name extraction in
   `pkg/config`; this prevents each surface from rebuilding a name set.
4. **Add ZoneIDs?** Yes. The gate-owned union is 55 functions/34 files,
   with 17 marginal functions beyond the 2 overlaps; the six-function
   estimate was not the AST population and is rejected.
5. **ifZone verdict?** Annotation bias was applied per site. Every
   interface/ifZone function that prints or serializes a Zone is an
   #10489-owned ANNOTATE row and must land before the successor drains.
   Only the two no-Zone-value-enforcement functions have exact EXEMPT
   rationale.
6. **Structured surfaces?** They are initial Unannotated entries under
   live #10489. Interface stats/`GetInterfaces` become annotations with
   the shared reason representation before drain. Only `GetZones` and
   `zonesHandler` receive exact no-wire exemptions citing the
   structured-wire follow-up; this is not a broad exemption or a claim
   that the current wire is truthful. The remote CLI inherits the
   GetZones wire decision.
7. **Order and successor?** #10490 first, one permanent canary,
   exact 52-entry non-nil list, `Successor: "#10489"`; #10489 stays
   open and drains to nil. Single PR is rejected.
8. **Status text?** Additive per-object reason only; no existing status
   or gauge wording change.
9. **Inline sorted-min?** Acknowledge it as pre-existing follow-up;
   do not expand this plan into manager session-sync refactoring.
10. **Option C timing?** File the tracking issue before A+B lands and
    retain the class-level follow-up priority after this family closes.
