# Plan: annotate quarantined zones on operator show surfaces (#10489)

## Status

DRAFT v2 (delta re-review round). No production code in this round.
Worktree `/home/ps/git/pi-xpf/.claude/worktrees/10489-quarantine`,
branch `fix/10489-quarantine-show`, base `origin/master b71c52d60`.
Round-1: BOTH hostile reviewers PLAN-NEEDS-MAJOR
(`agent://Rev10489PlanA`, `agent://Rev10489PlanB`); direction sound,
contracts wrong. v2 resolves all eight findings per Main adjudication:
F1 input rule (Design); F2 enum/presence wire contract assigned to #10531
(API boundary); F3/F4 counter-id-interfaces-policies attribution for the
in-scope text paths (Design table + tests); F5 sibling contract (Design gate
row + Q8); F6 functions-unit gate census (Design + test cell 4); F7 skew
wording (Design + Q5); F8 corrected numbers (census + API citations).
Sibling-order paragraph lands with the recorded #10490 agreement (see Design
gate row + Q8); adjacent behavior is filed as #10530.

## Issue framing

The zone-quarantine mechanism is real and enforced, but no operator `show`
surface annotates a zone as quarantined. `config.QuarantinedZoneNames`
(`pkg/config/zoneid.go:219`) drops the later-sorting colliding zone from the
dataplane entirely — "its interfaces are unzoned (fail to id 0) and its
policies are scrubbed" (`pkg/policymatch/policymatch.go:1595-1598`) — yet
every zone renderer prints the quarantined zone as though it were enforced.

PR #3837 (merge `ee7e5e132`) promised `ProcessStatus.ZoneIDCollisions`
(`show`) observability. Its 19-file stat contains the runtime quarantine, the
status field, and the Prometheus gauge — and zero show-renderer files. The
runtime landed; the show surface never materialized. This issue is the
missing-show regression against that merged scope.

Impact (Medium, per issue): a zone can be quarantined — isolation DEGRADED —
with no operator-visible annotation on any `show` surface; the daemon knows
and the operator cannot see it.

Acceptance (per issue): an operator `show` surface (CLI at minimum)
annotates quarantined zones — quarantined name, surviving name, and
degraded-isolation state — plus a regression test against PR #3837's
promised `(show)` observability.

- `ZoneIDCollisions|zone_id_collisions|lastZoneIDCollisions` over
  `pkg/` + `userspace-dp/` → 6 producer-side files, all
  (stamp/record/gauge/field-def); ZERO readers in `pkg/cli`,
  `pkg/grpcapi`, `pkg/api` server handlers, or `cmd/cli`. The diagnostic is
  written and never rendered (except as the existing gauge).
- Last-50 merged-PR scan (`pr://?state=merged&limit=50`, #10483..#10412) →
  no #10489 fix.

## Scope-value

In scope: per-zone quarantine annotation on the 3 text zone-inventory paths
(local CLI, gRPC text, and remote detail), so a quarantined zone can never
again render as enforced on those text surfaces. Structured `GetZones` and
REST `zonesHandler` are named gate exemptions deferred to #10531; remote
brief follows that structured-wire boundary. Adjacent same-class surfaces
(interfaces, screen, policy inventory, per-zone metrics, sessions/events)
are explicitly dispositioned in Out of scope, not silently claimed.

Blast-radius census (measured, not asserted):

| Class | Count | Members |
|---|---|---|
| Quarantine SSOT + runtime enforcement sites | 7 prod files (1 def + 5 calling + 1 hand-rolled) | `pkg/config/zoneid.go` (warning :182-192, `QuarantinedZoneNames` :219, `StableZoneIDOwner` :254); `pkg/dataplane/userspace/zones_quarantine.go` (`ZoneIDCollision` :15, `String` :22, `quarantineCollidingZones` :57, `scrubPoliciesForQuarantinedZones` :128); `pkg/dataplane/userspace/zones.go:145` wrapper; `pkg/policymatch/policymatch.go:1595-1631`; `pkg/cli/apply.go:43`; `pkg/daemon/ipsec_capture_wiring_9506.go:232`; `pkg/dataplane/userspace/manager_sessionsync_request.go:283-287` (hand-rolled survivor logic — no `QuarantinedZoneNames` call) |
| Status plumbing (exists, no show reader) | 9 references across 6 files | `protocol_status.go:92` (field), `manager.go:244` (store), `manager_compile.go:172,173,179,428` (record/call), `manager_status.go:31` (stamp), `protocol.go:753` (builder carry), `pkg/api/metrics_userspace.go:184` (gauge) |
| Zone render paths with ZERO annotation | 5 paths / 4 daemon-side renderers + 1 remote client | (1) local CLI `show security zones[ detail]` → `showZonesDisplay` (`pkg/cli/cli_show_security_zones.go:16`, dispatch `:253` in `cli_show_security_dispatch.go`); (2) gRPC structured `GetZones` → `GetZones` (`pkg/grpcapi/server_show_zones.go:18`); (3) gRPC text `ShowText zones-detail` → `showZonesDetail` (`pkg/grpcapi/server_show_zones_text.go:38`, via `server_show.go:165`); (4) REST `GET /api/v1/security/zones` and `/api/v1/statistics/zones` (the latter aliases the former at `pkg/api/stats.go:172-174`) → `zonesHandler` (`pkg/api/security.go:19`) + REST `ZoneInfo` (`pkg/api/types.go:107`); (5) remote CLI `show security zones` → `showZones` (`cmd/cli/show_security.go:243`) over `GetZones` + `GetPolicies` |
| Structured-schema owners | 2 | `proto/xpf/v1/xpf.proto:244` (`ZoneInfo`, current fields 1-17; #10531 contract fields 18-19); `pkg/api/types.go:107` (REST `ZoneInfo`) |
| Show-gate families | 7 registered, 0 zone | `pkg/showaudit/surface_gate_6534_test.go:85` (port-mirroring, CoS, static-route, flow-server, static NAT, source NAT, destination NAT) |
| Golden/agreement tests over the 5 zone render paths | 29 files | `grep -rl showZonesDisplay\|showZonesDetail\|zonesHandler\|GetZones(` over `pkg/**/*_test.go` (6 api + 11 cli + 12 grpcapi) |
| Broader lexical `Security.Zones` candidate population | 39 raw loops across 26 files (CLI 15, gRPC 16, API 8); 38 non-test loops across 25 files enter the gate | Cross-lane scan by Eng10490, independently confirmed in-worktree (`grep -rn -E 'for .*range .*Security.Zones' pkg/cli pkg/grpcapi pkg/api cmd` → 39/26/CLI15); ONE loop in `apply_syslog_zonemap_3704_test.go:40` is excluded by `parsePackage` (`surface_gate_6534_test.go:493-495`). Lexical candidates, not confirmed renderers: the 38 non-test candidates include non-render helpers (if-zone maps, session/completion paths). The 3 in-scope text paths above are the confirmed #10489 behavior scope; structured handlers are explicit #10531 exemptions; the gate classifies FUNCTIONS (not loops) via annotation or `exemptRenderers` — see Design gate row. |
| Planned gate function universe after #10490 F1 | 53 functions across 32 files; 52 `Unannotated` plus one permanent canary | Locked sibling contract: baseline 36 functions / 23 files after two global completion exemptions; adding `ZoneIDs` to `Collections` contributes 17 marginal functions from 19 loops (two overlaps: `grpcapi buildSessionFilter`, `api buildSessionView`). #10490 owns this census and lands the skeleton first; #10489 drains all 52 with exact predicates, then closes the row to nil. |
| Consumers of this plan | 3 text paths | local CLI operators, gRPC text `show`, and remote-detail operators; structured automation is #10531 |

Value: closes the exact defect class #6534 exists for (builder knows,
surface lies) on the zone family; delivers the observability PR #3837
merged-scope promised; every number above is re-measurable with the greps
in Test plan.

## Shipped context (what exists at b71c52d60)

1. **Deterministic SSOT predicate.** `QuarantinedZoneNames(names)` is a pure
   function of the zone-name set (sorted tie-break, `StableZoneID` fold);
   both HA nodes compute the identical set (`zoneid.go:214-218`). Pinned by
   `TestQuarantinedZoneNamesDropsLaterColliding` (`z174`/`z214` colliding
   pair) and `TestQuarantinedZoneNamesNoFalsePositive`.
2. **Snapshot enforcement.** `quarantineCollidingZones` drops the zone,
   unzones its interfaces (fail-closed; #6722 egress carve-out documented),
   and scrubs its policies with drop-vs-prune semantics (#5577 fail-closed,
   #6480 shared with republish paths). `ZoneIDCollision.String()` already
   renders an operator-grade sentence naming quarantined zone, id, survivor.
3. **Status + metrics plumbing.** Collisions flow builder → `m.mu` →
   `ProcessStatus.ZoneIDCollisions` (JSON `zone_id_collisions`) →
   `xpf_userspace_zone_id_collision` gauge, plus a one-shot `slog.Error`
   transition alarm (`manager_compile.go:181-182`). Sibling diagnostic
   `LastSnapshotRejectReasons` shares the identical shape (stamped + gauged,
   no text renderer); it remains out of scope.
4. **Three text paths, two daemon renderer functions, and one dependent
   remote client** (table above). The local CLI and gRPC text paths iterate
   `cfg.Security.Zones` and consult only `applyResult()` + counters; neither
   reaches `QuarantinedZoneNames`, `lastZoneIDCollisions`, or
   `ProcessStatus.ZoneIDCollisions`. Remote detail reuses gRPC text. Remote
   brief consumes structured `GetZones`; its truthful wire state is explicitly
   deferred to #10531, so #10489 must not claim it is fixed.
5. **Show-gate blind spot, by construction.** `QuarantinedZoneNames` matches
   none of the `dropPredicateName` shapes (`*Excluded|Unusable|Disarmed`
   `Reason`, `*Exclusions`, `*Unsupported`, `*Undefined` —
   `surface_gate_6534_test.go:214`), so
   `TestEveryBuilderDropPredicateIsRegistered6534` cannot see the zone
   exclusion and no zone family row exists until the sibling skeleton.
6. **Precedents to mirror.** #6895 (explicit UNAVAILABLE vs silent zero on
   all three surfaces + shared generic line); #7181 (applied-vs-desired
   `host_inbound_applied`, omitted-when-unwired so absence claims nothing);
   #3654/#3328 (host-inbound split fields across CLI/gRPC/REST in lockstep);
   #7473 (exported composition shared by all three surfaces instead of
   per-surface re-derivation).
7. **Zone-ID/counter aliasing (the attribution fact).** `assignZoneIDs`
   (`pkg/dataplane/compiler.go:355-358`) and the HA mirror `buildZoneIDs`
   (`pkg/daemon/daemon_ha_userspace_convert.go:28-31`) assign
   `StableZoneID(name)` for EVERY configured zone, so `cr.ZoneIDs` carries
   BOTH collider names → the same id. Every renderer therefore reads the
   survivor's live counters under the quarantined name today; the fix must
   specify ID-line + counter treatment per surface (see Design table).
8. **Third spelling + regen notes for the implementer.** `policymatch`
   carries its own unexported `quarantinedZoneNames(cfg)`
   (`policymatch.go:1623-1631`); under the #7473 rule it must delegate to
   the new shared helper (disposition in API). Any proto change requires
   `make proto` regen of checked-in `pkg/grpcapi/xpfv1/*.pb.go`
   (`Makefile:80-84`).

## Design

**Recommended: config-derived per-zone annotation on 3 text paths implemented
by 2 daemon renderer functions, with structured-wire truthfulness deferred to
#10531.**
This is a sequential two-PR close: #10490 lands the gate skeleton first;
#10489 drains the text outputs and named exemptions second.

- New shared verdict/explanation helpers in `pkg/config` (locked exact
  #10490 spelling): `ZoneQuarantineExclusions(names)` is the builder
  predicate; `ZoneQuarantineExcludedReason(name, cfg)` is the surface
  predicate/extractor. Both delegate to `QuarantinedZoneNames` +
  `StableZoneIDOwner` (no SSOT behavior change). Rationale: #7473 — one
  exported composition all surfaces share; the `policymatch` private wrapper
  (`policymatch.go:1623-1631`) delegates to them too, leaving exactly one
  spelling. No rename, regex widening, or marker mechanism is in this plan.
- Input contract (F1/F3 fix): every daemon-side renderer computes the
  verdict ONCE per invocation over the FULL active `cfg.Security.Zones` key
  set, BEFORE any display filter, nil-tolerant (`zone == nil` skipped like
  the renderers already do). This matches the builder exactly:
  `quarantinedZoneNames` (`zones.go:137-145`) and
  `quarantinedZoneNamesForConfig` (`zones_quarantine.go:228-236`) both build
  `names` from ALL cfg keys ("buildZoneSnapshots publishes exactly
  cfg.Security.Zones", `zones.go:133-136`), as does
  `policymatch.quarantinedZoneNames` (`policymatch.go:1627-1631`).
  Filtered detail (`show security zones z214 detail`) therefore still marks:
  the filter selects from an already-verdict-annotated set. Filter=survivor
  renders the survivor unmarked (it IS enforced); the collision record stays
  visible on the quarantined name only — no cross-annotation.
- Remote detail is not a sixth renderer: `cmd/cli/show.go:508-511` routes
  `show security zones detail` through `server_show.go:165` to
  `showZonesDetail:44-47`; the full-set server verdict therefore covers it.
  Remote brief uses the structured `GetZones` state and never recomputes the
  verdict client-side.
- Attribution table (F3/F4 fix): for a QUARANTINED zone, per surface —
  marker, id line, counters+availability, interfaces, policies. The survivor
  renders byte-identical to today (silent default, Q6).
  | Surface | Marker | Zone-ID line | Counters + availability | Interfaces | Policies |
  |---|---|---|---|---|---|
  | Local CLI brief/detail (`cli_show_security_zones.go`) | `QUARANTINED (id <n> collides with "<survivor>")` + degraded note (detail: full block) | id kept, qualified: `Zone ID: <n> (collides with "<survivor>" — not installed)` | traffic block REPLACED by a shared quarantined-counters line (never the survivor's live numbers) | authored list kept, header qualified `(unzoned at runtime — quarantined)`; per-interface detail unchanged | `ZoneDetailPolicySummary` output prefixed with a `(policies referencing this zone are scrubbed at runtime — quarantined)` header line |
  | gRPC structured `GetZones` | DEFERRED — explicit `exemptRenderers` entry: `deferred to #10531 — gRPC GetZones structured-wire quarantine enum/presence and counter truthfulness` | no #10489 change | no #10489 change | no #10489 change | n/a |
  | gRPC text `zones-detail` | same text as local CLI | same qualification | same replacement line (shared const) | same qualification | refs (`server_show_zones_text.go:151-172`) + summary (`:229`) get the same scrubbed-header line |
  | REST `/security/zones` | DEFERRED — explicit `exemptRenderers` entry: `deferred to #10531 — REST zonesHandler structured-wire quarantine presence and counter truthfulness` | no #10489 change | no #10489 change | no #10489 change | n/a |
  | Remote CLI brief/detail | brief DEFERRED with structured `GetZones` until #10531; detail inherits the gRPC text marker | detail wire id rendered with `(collides … — not installed)` qualification | brief deferred; detail same replacement line | detail wire list gets runtime-unzoned qualification | brief policy refs remain coupled to #10531; detail inherits gRPC text policy annotation; `/security/policies` inventory remains #10530 follow-up |
  Rationale: the id is a stable pure function of the name (still TRUE, so kept
  and qualified); counters/interfaces/policies describe RUNTIME state the
  quarantine revoked (so replaced/qualified, never survivor-aliased, never
  silently listed). UNKNOWN-state rendering is specified in API, not here.
- Why config-derived recompute instead of reading `m.lastZoneIDCollisions`
  via `Status()`: (a) the local CLI runs with `dp == nil` (all detail tests
  construct `&CLI{store: store}`) and must annotate without a dataplane;
  (b) the predicate is provably the builder's own input function over the
  same name set, HA-symmetric; (c) the remote CLI cannot reach daemon
  memory — it needs the verdict on the `GetZones` wire format anyway.
  Status-plumbing stays as the daemon-side record and gauge source.
- Divergence guard (the #3643 skew class, F7 fix): option (b) (suppress the
  active-config marker when `applyResult()` is nil/stale) is DROPPED — it
  contradicts the dp-nil contract (`pkg/cli/cli.go:238-243`,
  `pkg/dataplane/apply_result.go:5-10`, `pkg/api/api.go:117-120`). Decided:
  (a) annotate from active config unconditionally, plus a #5067-style drift
  banner (`printFirewallEffectiveBanner` precedent,
  `cli_show_security_filters.go:355-387`) ONLY when an applied result exists:
  compare `keys(cfg.Security.Zones)` against `keys(cr.ZoneIDs)` (the
  applied-set key source at `pkg/cli/apply.go:118-119`). When they differ,
  render `note: zone inventory differs from last applied result — quarantine
  verdict per active configuration`. With no `cr` baseline (dp-nil), omit
  only that note; never suppress the marker/attribution. The applied-set
  refinement (verdict over `keys(cr.ZoneIDs)`) stays future work.
- **Sibling gate contract (locked with Eng10490, v2):** #10490 lands FIRST;
  a single combined PR is rejected. It owns predicate names, the zone-family
  row, and the census; #10489 owns the 3 text paths using the exact names
  above, with `GetZones` and `zonesHandler` explicitly exempted to #10531.
  Its skeleton adds both helpers (each delegating to the SSOT), switches the
  three builderPkg sites to `ZoneQuarantineExclusions`, and registers:
  `Name: "security zone"`;
  `Collections: ["Security.Zones", "ZoneIDs"]`;
  `BuilderPredicates: ["ZoneQuarantineExclusions"]`;
  `SurfacePredicates: ["ZoneQuarantineExclusions", "ZoneQuarantineExcludedReason"]`;
  `Unannotated: [52 exact entries]`;
  `Successor: "#10489"`.
  The one permanent canary is local-CLI `showZonesDisplay` (primary text
  inventory); this satisfies the gate's not-all-unannotated floor while the
  other 52 functions remain explicitly tracked. Gate green is required at
  each step; #10490's two global completion exemptions apply, with no new
  broad exemptions. The function universe is 53 functions / 32 files:
  baseline 36/23 plus 17 marginal functions from 19 `ZoneIDs` loops (two
  overlaps: `grpcapi buildSessionFilter`, `api buildSessionView`).
  #10489 then annotates the two daemon renderer implementations
  (`showZonesDisplay`, `showZonesDetail`), records the remote-detail route,
  and drains all 52 with exact predicates/reasons before closing
  `Unannotated` to nil.
 **Gate-only drain versus behavior scope (binding):** the 3 text paths are
  the only #10489 behavior obligations. After the two in-gate renderer
  implementations are annotated (remote detail reuses `showZonesDetail`;
  remote client is outside `surfacePkgs`), every remaining census entry is
  handled by an exact per-function `exemptRenderers` reason: concrete helper
  role, adjacent output `deferred to #10530 — <surface/function>`, or exactly
  `GetZones`/`zonesHandler` `deferred to #10531 — <surface/function>`.
  There are NO package-wide exemptions. Adjacent wording makes ZERO claim
  that the function cannot render enforcement state; structured wording makes
  ZERO claim that the handler currently emits truthful state.
  `TestExemptionsNameRealRenderers6534` guards the boundary. Only after all
  52 entries are predicate-reached or explicitly reasoned-exempt does the
  row close `Unannotated` to nil. This is a gate census drain, not expansion
  of #10489's runtime/show behavior scope.

**Considered and rejected:**

- B. CLI-only annotation. Meets the letter of acceptance ("CLI at minimum")
  but leaves the gRPC text and remote-detail #6534-class lie live; the
  structured and adjacent surfaces are separately tracked by #10531/#10530.
  Rejected because the two daemon text implementations should share one
  helper and one fail-on-revert cell.
- C. Status-surface-only (`show system` renders `ZoneIDCollisions` strings).
  Cheap but dp-dependent, unreachable from dp-nil CLI and remote CLI without
  new RPCs, and per-zone join is lost. Kept as a possible complement, not
  the fix.

## API boundary

- #10489 deliberately makes NO protobuf or REST structured-wire change.
  `GetZones` and `zonesHandler` are the two named gate exemptions; their
  truthful state is the separately filed #10531 follow-up. Keeping this
  boundary explicit prevents a half-added field whose default can false-clean
  under old-server/new-client skew.
- #10531's locked wire contract is `ZoneQuarantineState quarantine_state = 18`
  plus `string quarantine_survivor = 19` in `proto/xpf/v1/xpf.proto`,
  with `UNKNOWN = 0`, `NO = 1`, `YES = 2`; REST uses
  `QuarantineState *string json:"quarantine_state,omitempty"` with `"no"`/
  `"yes"` and nil/absent = UNKNOWN, plus
  `QuarantineSurvivor string json:"quarantine_survivor,omitempty"`. Bare
  `[]ZoneInfo` stays an array (`pkg/api/types.go:211-216`). #10531 must run
  `make proto` (`Makefile:80-84`) and force quarantined counters to zero +
  `UNAVAILABLE`, so old clients cannot display survivor traffic under the
  loser. UNKNOWN=0 follows #6895 (`xpf.proto:220-230`): bool false would
  claim clean; quarantine skew is the un-upgraded HA peer case
  (`zoneid.go:208-210`).
- #10489 text contract (local CLI + gRPC text + remote detail):
  `QUARANTINED (id <n> collides with "<survivor>") — dropped from dataplane,
  interfaces unzoned, traffic denied; zone isolation DEGRADED until one zone
  is renamed`. Detail adds the full attribution table; the shared const/
  format helper keeps all three text surfaces identical (#6895 lesson).
- UNKNOWN is not a local/gRPC render state because those servers compute from
  active config; they render the explicit quarantine marker, never clean.
  Remote brief is deferred with `GetZones` until #10531, so #10489 makes no
  old-server/old-client wire claim and no fabricated `quarantine_state`.
- `pkg/config`: new exported gate-shaped verdict helper (spelling per joint
  #10490 decision) + keep `QuarantinedZoneNames` as the SSOT (no signature
  change; 6 prod call sites across 5 files untouched semantically:
  `zones_quarantine.go:65,236`, `zones.go:145`, `policymatch.go:1631`,
  `apply.go:43`, `ipsec_capture_wiring_9506.go:232`). The `policymatch`
  private wrapper (`policymatch.go:1623-1631`) is consolidated onto the new
  helper (third spelling removed, same verdict).
- No `ProcessStatus` wire change (field exists); no Prometheus change
  (gauge exists); no syslog/RT_FLOW change (survivor naming already
  correct via `apply.go:43`).

## Invariants

1. The dataplane never receives two zones sharing a numeric id (#3719) —
   unchanged; this plan adds observation only, zero enforcement change.
2. The annotation verdict is computed by the same predicate family the
   builder enforces (`QuarantinedZoneNames` + `StableZoneIDOwner`) over the
   same FULL key set (`cfg.Security.Zones` keys, pre-filter), never
   re-derived per surface (#7473 composition rule).
3. On each of the 3 in-scope text paths (local CLI, gRPC text, remote
   detail), a quarantined zone renders as NOT enforced (marker + qualified
   id/counters/interfaces/policies per the attribution table); a surviving
   zone renders as enforced with no quarantine marker (signal direction
   pinned by fail-on-revert tests). `GetZones`, `zonesHandler`, and remote
   brief are explicitly deferred to #10531 and claim no #10489 wire behavior.
4. dp-nil renderers annotate identically to dp-loaded ones for marker,
   qualified id, counters, interfaces, and policy attribution (verdict is
   config-derived; no `Status()` round trip). The drift note is omitted only
   when there is no applied-result baseline to compare.
5. HA symmetry: identical configs render identical annotations on both
   nodes (pure function of the name set; no node-local state).
6. The #10489 text path has no false-clean skew default: its verdict is
   config-derived and explicit. Structured new/old-client behavior,
   UNKNOWN=0 presence, and server-forced zero + UNAVAILABLE counters belong
   exclusively to #10531; no old-client marker claim is made here.
7. The show-gate zone census stays exact in both directions (new unannotated
   zone renderer reds; repaired entry still listed reds).

## Risk (4-class)

- **R1 — Correctness (wrong signal direction).** Annotating the survivor
  instead of the quarantined zone, or marking both, would invert the
  operator's mental model. Mitigation: survivor/quarantined assignment comes
  straight from the SSOT pair (`StableZoneIDOwner` names the survivor);
  fail-on-revert tests assert the marker appears on `z214` and NOT on
  `z174` (the frozen colliding pair from `zoneid_test.go:152`). Residual:
  LOW.
- **R2 — Compatibility (text/wire boundary).** #10489 changes text
  renderers only; the two structured handlers are explicit gate exemptions
  deferred to #10531, so no partial bool wire field can false-clean old
  clients. The #10531 follow-up must use UNKNOWN=0 enum + REST presence and
  server-side zero/UNAVAILABLE counters; #10489's 29 related test files
  remain byte-stable apart from the intended text annotations. Residual:
  LOW for this text-only cut; HIGH if #10531 is incorrectly folded here.
- **R3 — Operability (skew, fatigue, HA).** Active-vs-applied skew (#3643
  class) could annotate from a config the dataplane never installed; a new
  per-zone marker could double-page alongside the existing gauge + one-shot
  alarm. Mitigation: annotation labels its input; no new alarm and no new
  gauge (existing two are the paging path); HA symmetry inherited from the
  pure predicate; the explicit drift banner names active-vs-last-applied
  state. Residual: LOW-MEDIUM (wording review required).
- **R4 — Verification (fixture reachability).** The quarantine state is
  lenient-path-only (strict commit rejects collisions) — a `Commit()`-based
  fixture cannot reach it (gate doc's reachability warning,
  `pkg/showaudit/doc.go:66-77`). Mitigation: fixtures build the colliding
  config via the lenient/tolerant load path (the `z174`/`z214` pair through
  `validateZoneIDCollisionAST(lenient=true)` + snapshot build), mirroring
  `zones_collision_3719_test.go`; filtered fixtures copy
  `cli_show_logical_unit_5325_test.go:77,96`,
  `zones_metadata_3684_test.go:109`,
  `policy_tiers_3658_test.go:111`, and
  `host_inbound_display_3654_test.go:133`. Residual: LOW.

## Test plan

No test files are modified in this plan round. Implementation PR must carry:

1. **RED cell (PR #3837 regression), pin-table.** Colliding `z174`/`z214`
   config × unfiltered × three text paths (local CLI, gRPC text, and remote
   detail; two daemon implementations because remote detail reuses gRPC):
   `z214` renders QUARANTINED naming survivor `z174` + degraded state, and
   `z174` renders unmarked. Then filtered cells use the real filter
   topology: local CLI `showZonesDisplay(filter=z214)` and gRPC text
   `showZonesDetail(filter=z214)` STILL mark `z214`; `filter=z174` leaves the
   survivor unmarked; unfiltered output is unchanged. Remote detail follows
   the gRPC text path (`cmd/cli/show.go:508-511` → `server_show.go:165` →
   `showZonesDetail:44-47`). Every `z214` block pins qualified id line,
   generic/degraded traffic wording (no survivor live numbers), qualified
   interfaces header, and scrubbed-policy header. Reverting any renderer
   call site or using post-filter names makes its cells RED.
2. **Remote CLI split cell:** remote detail is covered by cell 1; remote
   brief is explicitly DEFERRED because it consumes structured `GetZones`
   data that remains absent until #10531. The #10489 test must not fake
   `quarantine_state` on an unmodified `GetZonesResponse`; #10531 owns the
   `UNKNOWN/NO/YES` structured-wire and old-server/old-client cells.
3. **Structured-handler exemption cell:** gate `exemptRenderers` carries
   exact per-entry rationale for `GetZones` and `zonesHandler`: “deferred to
   #10531 — structured-wire quarantine enum/presence and counter
   truthfulness”; no broad package exemption and no claim that either
   handler currently emits truthful quarantine state. The follow-up's
   contract is protobuf UNKNOWN=0/NO=1/YES=2 + survivor string, REST
   presence (absent=UNKNOWN), and quarantined counters zero/UNAVAILABLE.
4. **Show-gate census cell:** the raw `Security.Zones` population is
   classified exactly as 39 loops across 26 files (CLI 15, gRPC 16, API 8),
   including 1 test loop; the non-test count is 38 loops across 25 files.
   Eng10490's gate skeleton records 53 functions across 32 files with 52
   `Unannotated` entries plus the permanent local `showZonesDisplay`
   canary. #10489 annotates the 2 daemon renderer implementations
   (`showZonesDisplay`, `showZonesDetail`; remote detail reuses the latter)
   and gives every remaining entry an exact `exemptRenderers` reason:
   concrete helper role; `deferred to #10530 — <surface/function>` for an
   adjacent output; or `deferred to #10531 — <surface/function>` for exactly
   `GetZones`/`zonesHandler`.
   `TestExemptionsNameRealRenderers6534`,
   `TestEveryBuilderDropPredicateIsRegistered6534`, and
   `TestSurfaceAnnotationCensusIsExact6534` are green; only then does
   `Unannotated` close to nil.
5. **No-false-positive cell:** `{"trust","untrust","dmz"}` renders zero
   markers on local CLI, gRPC text, and remote detail AND byte-identical
   counters/ids to today (extends `TestQuarantinedZoneNamesNoFalsePositive`
   to the text layer with survivor attribution pins — the F4 mirror).
6. **Scoped parity gates:** focused tests over the 29 related files
   (6 API, 11 CLI, 12 gRPC) plus `pkg/showaudit`, `pkg/config`, and
   `pkg/policymatch`; byte-drift triage for text goldens; dedicated dp-nil
   marker/attribution cell (Invariant 4: store-less output has identical
   quarantine annotation; the drift note is absent because no applied
   baseline exists); HA-symmetry cell (identical configs → identical text);
   active-vs-applied skew cell asserting the drift banner fires exactly when
   an applied result exists and active config keys differ from `cr.ZoneIDs`.
   `make proto` only in #10531 when its wire fields land.
7. **Re-measure commands (acceptance evidence):** the new verdict helper
   appears in both daemon renderer implementations
   (`showZonesDisplay`, `showZonesDetail`) consuming FULL pre-filter key
   sets (remote detail is the `showZonesDetail` path; assert the call-site
   input, not just helper presence); structured handlers are present only in
   the named #10531 exemptions; no renderer reads manager-local
   `ProcessStatus.ZoneIDCollisions` directly (that grep stays
   producer/gauge-only by design).

## Out of scope

- Any enforcement change: quarantine loser selection, unzoning, policy
  scrub, strict-vs-lenient commit behavior — all untouched.
- `LastSnapshotRejectReasons` text rendering (sibling diagnostic, same
  shape; scoped to the `u04-beyond-packet` finding per the issue's Limits —
  not this one).
- New alarms, gauges, or syslog formats (gauge + one-shot alarm already
  exist and remain the paging path).
- Adjacent same-class surfaces are explicitly deferred to filed follow-up
  #10530 (no #10489 behavior claim): `show interfaces` iface→zone map
  (`cli_show_interfaces.go:117-125`, desired-config truth vs runtime
  `Zone=''`); screen `zonesByProfile`
  (`cli_show_security_screen.go:47-56`, `server_show_security_text.go:839-847`
  "Applied to zones"); policy inventory (`api/security.go:193` policiesHandler,
  `GetPolicies`, CLI hit-count — scrubbed rules still render live);
  Prometheus per-zone series (`metrics_counters.go:650-657` attributes
  survivor volume under the quarantined name); sessions/events zone loops
  (`session_filter.go:385`, `server_sessions.go:531`, `sessions.go:1258`).
  The gate gives each adjacent output an exact
  `deferred to #10530 — <surface/function>` rationale and makes no claim it
  cannot emit state. Invariant 3 explicitly excludes them.
- Structured `GetZones` and `zonesHandler` are explicitly deferred to filed
  follow-up #10531 (enum/presence and counter truthfulness); the gate gives
  each the exact `deferred to #10531 — <surface/function>` rationale. This is
  not a broad structured-package exemption and makes no claim those handlers
  currently emit truthful quarantine state.
- `q04-failure-policy-F2+u04` mechanics (the gate's discovery half stays
  with Eng10490; the zone-family ROW is jointly owned per the recorded
  sibling contract — see Design gate row + Q8).
- The 39-site consumer census from the source review (explicitly not
  reproduced per the issue's Limits; this plan vendors its own measured
  census above).
- Old-helper / pre-#3075 persisted-config migration behavior.

## Open questions (resolved in v2)

1. **Single PR or split? CLOSED: sequential campaign.** A single PR is
   rejected. #10490 lands the gate predicate names, row, and census first;
   #10489 then drains the three text output paths and exact exemptions;
   #10530 and #10531 remain the filed adjacent-surface and structured-wire
   follow-ups.
2. **Bool vs enum on the wire? CLOSED: enum in #10531.**
   `ZoneQuarantineState` UNKNOWN=0/NO/YES at 18 plus survivor string at 19;
   REST presence-typed with absent=UNKNOWN. Decisive: `xpf.proto:220-230` +
   `show_security.go:850-855` (either bool polarity makes a skewed pair
   produce a new wrong answer), and the skew pair is the quarantine threat
   model itself (HA sync from an un-upgraded peer). v1's bool proposal is
   withdrawn.
3. **Gate-row landing shape? CLOSED: exact two-step drain.** Eng10490's
   skeleton records 53 functions across 32 files, with 52 `Unannotated`
   entries and the permanent local `showZonesDisplay` canary; #10489
   annotates its three output paths and exact exemptions, then closes
   `Unannotated` to nil only after `TestExemptionsNameRealRenderers6534`
   and the census tests pass.
4. **Predicate alias vs regex widening? CLOSED: exact aliases.**
   `ZoneQuarantineExclusions(names)` and
   `ZoneQuarantineExcludedReason(name,cfg)` are the locked names; builder
   and policymatch delegate to the shared SSOT. No `dropPredicateName`
   widening, rename, regex broadening, or marker mechanism.
5. **Skew wording? CLOSED: active-config verdict + conditional drift
   banner.** Suppression when `applyResult()` is nil/stale is dropped because
   dp-nil implies nil (`pkg/cli/cli.go:238-243`,
   `pkg/dataplane/apply_result.go:5-10`, `pkg/api/api.go:117-120`):
   the marker/attribution still renders. When an applied result exists,
   compare `keys(cfg.Security.Zones)` with `keys(cr.ZoneIDs)` and use the
   #5067 banner precedent (`cli_show_security_filters.go:355-387`); when no
   applied baseline exists, omit only the note. #10489 makes no
   structured-wire skew claim, which belongs to #10531.
6. **Survivor-side note? CLOSED: silent default.** The survivor renders
   byte-identically to today; the collision id is audit-visible only on the
   quarantined text block and existing one-shot alarm
   (`ZoneIDCollision.String()` names both).
7. **Text spelling SSOT location? CLOSED: `pkg/config`.** One shared const/
   format helper next to the verdict (the #6895 `UnavailableLineFor`
   precedent) serves local CLI, gRPC text, and remote detail. Direct
   `String()` reuse is blocked by import direction (userspace → config).
8. **Eng10490 boundary? CLOSED and locked.** Eng10490 owns predicate names,
   the zone-family row, the 53-function census, and gate skeleton; #10489
   uses those exact names for its three text paths and drains every remaining
   entry with a concrete helper reason, `deferred to #10530 — <surface/function>`
   for adjacent output, or `deferred to #10531 — <surface/function>` for
   exactly `GetZones`/`zonesHandler`. Lower issue #10490 lands first; no
   unilateral renaming or gate-mechanics edit.
9. **Candidate classification ownership? CLOSED: row-local reasons.** The
   corrected lexical population is 39 raw loops across 26 files (CLI 15,
   gRPC 16, API 8), including 1 test loop; 38 non-test loops across 25
   files. The generic scanner stays generic; the family row carries exact
   per-function reasons. No broad package exemption, and `Unannotated`
   closes to nil only after all 52 entries are predicate-covered or
   reasoned exempt.
