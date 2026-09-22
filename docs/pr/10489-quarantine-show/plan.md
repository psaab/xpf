# Plan: annotate quarantined zones on operator show surfaces (#10489)

## Status

DRAFT v4 (delta-2 fold: evidenced sibling conformance). No production code
in this round.
Worktree `/home/ps/git/pi-xpf/.claude/worktrees/10489-quarantine`,
branch `fix/10489-quarantine-show`, base `origin/master b71c52d60`.
Round-1: BOTH hostile reviewers PLAN-NEEDS-MAJOR
(`agent://Rev10489PlanA`, `agent://Rev10489PlanB`); v2 fixed the core
contracts; v3 folded six adjudicated residuals. Delta-2
(`agent://Rev10489Delta2`) kept R1/R6/R8/R9/R10 open and raised N1-N3.
v4 conforms to the sibling's COMMITTED text — #10490 is already
implementing, so every shared claim below quotes
`origin/fix/10490-showaudit-discovery` at `00afcf64d43f4d4062764726e0c7ecbb6dbb5bc1`
(`docs/pr/10490-showaudit-discovery/plan.md`, DRAFT v3) by exact line
number, plus the recorded delta-plan decision on #10530
(`issuecomment-5771218190`). No shared claim cites chat.

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
brief follows that structured-wire boundary. `showTestZone` is a separately
named diagnostic obligation: its interface→zone line gets the shared
quarantine qualification, while adjacent same-class inventory/telemetry
surfaces remain behavior refinements in #10530 and are not silently claimed.
Adjacent same-class surfaces (interfaces, screen, policy inventory, per-zone
metrics, sessions/events) are explicitly dispositioned in Out of scope.

Blast-radius census (measured, not asserted):

| Class | Count | Members |
|---|---|---|
| Quarantine SSOT + runtime enforcement sites | 7 prod files (1 def + 5 calling + 1 hand-rolled) | `pkg/config/zoneid.go` (warning :182-192, `QuarantinedZoneNames` :219, `StableZoneIDOwner` :254); `pkg/dataplane/userspace/zones_quarantine.go` (`ZoneIDCollision` :15, `String` :22, `quarantineCollidingZones` :57, `scrubPoliciesForQuarantinedZones` :128); `pkg/dataplane/userspace/zones.go:145` wrapper; `pkg/policymatch/policymatch.go:1595-1631`; `pkg/cli/apply.go:43`; `pkg/daemon/ipsec_capture_wiring_9506.go:232`; `pkg/dataplane/userspace/manager_sessionsync_request.go:283-287` (hand-rolled survivor logic — no `QuarantinedZoneNames` call) |
| Status plumbing (exists, no show reader) | 9 references across 6 files | `protocol_status.go:92` (field), `manager.go:244` (store), `manager_compile.go:172,173,179,428` (record/call), `manager_status.go:31` (stamp), `protocol.go:753` (builder carry), `pkg/api/metrics_userspace.go:184` (gauge) |
| Zone render paths with ZERO annotation | 5 paths / 4 daemon-side renderers + 1 remote client | (1) local CLI `show security zones[ detail]` → `showZonesDisplay` (`pkg/cli/cli_show_security_zones.go:16`, dispatch `:253` in `cli_show_security_dispatch.go`); (2) gRPC structured `GetZones` → `GetZones` (`pkg/grpcapi/server_show_zones.go:18`); (3) gRPC text `ShowText zones-detail` → `showZonesDetail` (`pkg/grpcapi/server_show_zones_text.go:38`, via `server_show.go:165`); (4) REST `GET /api/v1/security/zones` and `/api/v1/statistics/zones` (the latter aliases the former at `pkg/api/stats.go:172-174`) → `zonesHandler` (`pkg/api/security.go:19`) + REST `ZoneInfo` (`pkg/api/types.go:107`); (5) remote CLI `show security zones` → `showZones` (`cmd/cli/show_security.go:243`) over `GetZones` + `GetPolicies` |
| Structured-schema owners | 2 | `proto/xpf/v1/xpf.proto:244` (`ZoneInfo`, current fields 1-17; #10531 contract fields 18-19); `pkg/api/types.go:107` (REST `ZoneInfo`) |
| Show-gate families | 7 registered, 0 zone | `pkg/showaudit/surface_gate_6534_test.go:85` (port-mirroring, CoS, static-route, flow-server, static NAT, source NAT, destination NAT) |
| Broader lexical `Security.Zones` candidate population | 39 raw loops across 26 files (CLI 15, gRPC 16, API 8); 38 non-test loops across 25 files enter the gate | Cross-lane scan by Eng10490, independently confirmed in-worktree (`grep -rn -E 'for .*range .*Security.Zones' pkg/cli pkg/grpcapi pkg/api cmd` → 39/26/CLI15); ONE loop in `apply_syslog_zonemap_3704_test.go:40` is excluded by `parsePackage` (`surface_gate_6534_test.go:493-495`). Lexical candidates, not confirmed renderers: the 38 non-test candidates include non-render helpers (if-zone maps, session/completion paths). The 3 operator text paths plus the named `showTestZone` diagnostic are the confirmed #10489 text behavior obligations; structured handlers remain explicit #10531 wire follow-ups, while the gate still drains every remaining output/serialization entry per the committed sibling rule (`origin/fix/10490-showaudit-discovery@00afcf64d`, `docs/pr/10490-showaudit-discovery/plan.md:299-337,339-377`). |
| Planned gate function universe after #10490 F1 | 53 functions across 32 files; 52 `Unannotated` plus the #10490-owned local `showZonesDisplay` canary | The committed sibling census is 55/34 before two existing completion exemptions, 53/32 after them, one canary, and 52 initial `Unannotated` entries (`origin/fix/10490-showaudit-discovery@00afcf64d`, `docs/pr/10490-showaudit-discovery/plan.md:110-139`). #10490 owns this census/skeleton and canary first; #10489 drains every remaining entry with a shared reason or exact no-claim exemption, then closes the row to nil. |
| Golden/agreement tests over the 5 zone render paths | 29 files | `grep -rl showZonesDisplay\|showZonesDetail\|zonesHandler\|GetZones(` over `pkg/**/*_test.go` (6 api + 11 cli + 12 grpcapi) |
| Consumers of this plan | 3 text paths plus showTestZone | local CLI operators, gRPC text `show`, remote-detail operators, and the interface→zone diagnostic; structured automation is #10531 |

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
8. **Apply-result freshness coupling.** `ApplyResult.SnapshotPublishDeferred`
  (`pkg/dataplane/apply.go:145-150`) means a successful apply did not publish
  its snapshot yet; `CompileResult.SnapshotPublishDeferred` is the source
  (`pkg/dataplane/compiler.go:81-88`). It is a freshness input, not a second
  quarantine verdict: `cr.ZoneIDs` still carries both collider names because
  `assignZoneIDs` is config-derived. #10489 therefore uses active-config
  prospective text and never treats `ZoneIDs` as proof of current publication;
  #10530 owns collector/adjacent-runtime handling and #10531 coordinates any
  structured counter disposition with that freshness rule.
9. **Third spelling + regen notes for the implementer.** `policymatch`
   carries its own unexported `quarantinedZoneNames(cfg)`
   (`policymatch.go:1623-1631`); under the #7473 rule it must delegate to
   the new shared helper (disposition in API). Any proto change requires
   `make proto` regen of checked-in `pkg/grpcapi/xpfv1/*.pb.go`
   (`Makefile:80-84`).
## Design

**Recommended: config-derived per-zone annotation on the 3 text paths
implemented by 2 daemon renderer functions, plus the named `showTestZone`
diagnostic; structured-wire truthfulness is deferred to #10531.**
This is a sequential two-PR close from the committed sibling contract:
#10490 lands the gate skeleton and owns the `showZonesDisplay` canary first;
#10489 drains the remaining entries and its named text obligations
(`origin/fix/10490-showaudit-discovery@00afcf64d`,
`docs/pr/10490-showaudit-discovery/plan.md:21-47,268-337`).

- New shared verdict/explanation helpers in `pkg/config`, using the exact
  names committed by #10490 (`origin/fix/10490-showaudit-discovery@00afcf64d`,
  `docs/pr/10490-showaudit-discovery/plan.md:21-45,268-297`):
  `ZoneQuarantineExclusions(names)` is the builder predicate;
  `ZoneQuarantineExcludedReason(name, cfg)` is the surface
  predicate/extractor. Both delegate to `QuarantinedZoneNames` +
  `StableZoneIDOwner` (no SSOT behavior change). Rationale: #7473 — one
  exported composition all surfaces share; the `policymatch` private wrapper
  (`policymatch.go:1623-1631`) delegates to them too, leaving exactly one
  spelling. No rename, regex widening, or marker mechanism is in this plan.
- Input contract (F1/F3/R9): every daemon-side renderer computes the
  verdict ONCE per invocation over EVERY key in the FULL active
  `cfg.Security.Zones` map, including keys whose value is nil, BEFORE any
  display filter. A render loop may skip a nil zone only after this full-key
  verdict is computed; nil render skipping must not shrink the verdict set.
  This matches the builder exactly:
  `quarantinedZoneNames` (`zones.go:141-145`) and
  `quarantinedZoneNamesForConfig` (`zones_quarantine.go:232-235`) both build
  `names` from ALL cfg keys ("buildZoneSnapshots publishes exactly
  `cfg.Security.Zones`", `zones.go:133-136`), as does
  `policymatch.quarantinedZoneNames` (`policymatch.go:1627-1630`).
  Filtered detail (`show security zones z214 detail`) therefore still marks:
  the filter selects from an already-verdict-annotated set. Filter=survivor
  renders the survivor unmarked (it IS enforced); the collision record stays
  visible on the quarantined name only — no cross-annotation.
- Remote detail is not a sixth renderer: `cmd/cli/show.go:508-517` routes
  `show security zones detail` through `server_show.go:165` to
  `showZonesDetail:44-47`; the full-set server verdict therefore covers it.
  Remote brief uses the structured `GetZones` state and never recomputes the
  verdict client-side.
- Attribution table (F3/F4 fix): for a QUARANTINED zone, per surface —
  marker, id line, counters+availability, interfaces, policies. The survivor
  renders byte-identically to today (silent default, Q6).
  | Surface | Marker | Zone-ID line | Counters + availability | Interfaces | Policies |
  |---|---|---|---|---|---|
  | Local CLI brief/detail (`cli_show_security_zones.go`) | `QUARANTINED (id <n> collides with "<survivor>")` + degraded-state disposition (detail: full block) | id kept, qualified: `Zone ID: <n> (collides with "<survivor>" — would not be installed if this snapshot is applied)` | traffic block REPLACED by a shared quarantined-counters line (never survivor live numbers; prospective disposition) | authored list kept, header qualified `(would be unzoned if this snapshot is applied — quarantine candidate)`; per-interface detail unchanged | `ZoneDetailPolicySummary` output prefixed with a `(would be scrubbed if this snapshot is applied — quarantine candidate)` header line |
  | gRPC structured `GetZones` | DEFERRED — explicit `exemptRenderers` entry: `deferred to #10531 — gRPC GetZones structured-wire quarantine enum/presence and counter truthfulness` | no #10489 change | no #10489 change | no #10489 change | n/a |
  | gRPC text `zones-detail` | same text as local CLI | same qualification | same replacement line (shared const) | same qualification | refs (`server_show_zones_text.go:151-172`) + summary (`:229`) get the same prospective scrubbed-header line |
  | REST `/security/zones` | DEFERRED — explicit `exemptRenderers` entry: `deferred to #10531 — REST zonesHandler structured-wire quarantine presence and counter truthfulness` | no #10489 change | no #10489 change | no #10489 change | n/a |
  | Remote CLI brief/detail | brief DEFERRED with structured `GetZones` until #10531; detail is opaque `ShowTextResponse.Output` and inherits every gRPC text column | detail inherits server text id qualification; no client wire-id rendering | brief deferred; detail inherits server text replacement line | detail inherits server text interface qualification | after #10531 state=YES, brief `GetPolicies` refs prepend the prospective scrubbed-at-runtime header; detail inherits gRPC text policy annotation; `/security/policies` inventory remains #10530 refinement |
  Auxiliary zone-output obligation: `showTestZone` (`server_show_zones_text.go:242-349`)
  must apply the shared reason helper to its interface→zone diagnostic. A
  quarantined match says the interface would belong to the quarantined zone if
  this snapshot is applied and includes the survivor/id plus the same shared
  qualification; ordinary matches remain byte-identical. (The server-side loop
  and diagnostic are real output, not a pure helper.)
  Rationale: the id is a stable pure function of the name (still TRUE, so
  kept and qualified); counters/interfaces/policies receive prospective
  qualification because active config may not yet be applied. The shared
  annotation makes that disposition explicit. UNKNOWN-state rendering is
  specified in API, not here.
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
  `pkg/grpcapi/apply_result.go:5-10`, `pkg/api/api.go:117-120`). Decided:
  (a) annotate from active config unconditionally, plus a #5067-style drift
  banner (`printFirewallEffectiveBanner` precedent,
  `cli_show_security_filters.go:355-387`) ONLY when an applied result exists:
  compare `keys(cfg.Security.Zones)` against `keys(cr.ZoneIDs)` (the
  applied-set key source at `pkg/dataplane/apply.go:118-119`). When they
  differ, render `note: zone inventory differs from last applied result —
  quarantine annotation follows active configuration`. This is an inventory
  freshness note, NOT an applied-quarantine verdict: `assignZoneIDs` places
  both colliding names in `cr.ZoneIDs` (`pkg/dataplane/compiler.go:355-358`).
  With no `cr` baseline (dp-nil), omit only that note; never suppress the
  marker/attribution.
- **Sibling gate contract (committed, not chat-only):** #10490 lands FIRST;
  a single combined PR is rejected. Its committed contract gives #10490 the
  predicate names, zone-family row, exact census, collections, and permanent
  `showZonesDisplay` canary, while #10489 owns all remaining annotations
  (`origin/fix/10490-showaudit-discovery@00afcf64d`,
  `docs/pr/10490-showaudit-discovery/plan.md:21-47`). The exact names and
  row are:
  `Name: "security zone"`;
  `Collections: ["Security.Zones", "ZoneIDs"]`;
  `BuilderPredicates: ["ZoneQuarantineExclusions"]`;
  `SurfacePredicates: ["ZoneQuarantineExclusions", "ZoneQuarantineExcludedReason"]`;
  `Unannotated: [52 exact entries]`;
  `Successor: "#10489"` (`docs/pr/10490-showaudit-discovery/plan.md:268-297`).
  The permanent canary is local-CLI `showZonesDisplay`, annotated by #10490
  and excluded from #10489's annotation set; the other 52 remain tracked.
  The committed census is 53 functions / 32 files: baseline 36/23 plus
  17 marginal functions from 19 `ZoneIDs` loops (two overlaps:
  `grpcapi buildSessionFilter`, `api buildSessionView`)
  (`docs/pr/10490-showaudit-discovery/plan.md:110-139`).
- **Gate-only drain versus behavior scope (binding):** the sibling's five
  agreed operator inventory paths define the behavior matrix:
  `showZonesDisplay` is #10490's permanent canary; `GetZones` and
  `zonesHandler` are exact no-wire exemptions; `showZonesDetail` is a text
  annotation; and remote `showZones` inherits the structured GetZones wire
  decision (`origin/fix/10490-showaudit-discovery@00afcf64d`,
  `docs/pr/10490-showaudit-discovery/plan.md:299-325`). That five-path matrix
  does NOT waive the gate drain for adjacent census entries. The gate has no
  output filter: every remaining function that prints or serializes a Zone
  calls the shared reason helper or receives a reviewed exact disposition.
  Only exact no-Zone-value-enforcement helpers and the two named structured
  handlers may be exempt; metric paths omit a quarantined sample
  (`docs/pr/10490-showaudit-discovery/plan.md:339-377`). #10489's gate
  annotation/reason accounting for adjacent outputs is not a claim that
  #10530's runtime policy, counter, interface, session, or event behavior is
  fixed. There are NO package-wide exemptions. The shared
  `showaudit.exemptRenderers` map is the actual mechanism; this plan's
  per-function matrix records how each shared-map entry is applied, not a
  row-local map. The row closes `Unannotated` only after all 52 entries are
  predicate-reached or explicitly reasoned-exempt. The sibling explicitly
  requires #10489 to stay open until that drain is merged
  (`docs/pr/10490-showaudit-discovery/plan.md:331-337`).

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
- #10531's follow-up wire contract is `ZoneQuarantineState
  quarantine_state = 18` plus `string quarantine_survivor = 19` in
  `proto/xpf/v1/xpf.proto`,
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
  `QUARANTINED (id <n> collides with "<survivor>") — if this snapshot is
  applied, construction would omit the quarantined zone and clear its
  interface zone references; ordinary zone-directed traffic would then have
  no matching zone policy (default-deny); zone isolation would be DEGRADED
  until one zone is renamed`.
  Host-bound lifeline traffic remains on the kernel path
  (`zones_quarantine.go:83-107`, #3682), and egress identity resolution keeps
  the surviving zone rather than blanking `EgressZone` (#6722). Detail adds
  the full attribution table; the shared const/format helper keeps all three
  text surfaces identical (#6895 lesson).
- UNKNOWN is not a local/gRPC render state because those servers compute from
  active config; they render the explicit prospective quarantine marker, never
  clean as an active-config verdict.
  Remote brief is deferred with `GetZones` until #10531, so #10489 makes no
  old-server/old-client wire claim and no fabricated `quarantine_state`.
- `pkg/config`: new exported gate-shaped verdict helper using the exact names
  committed by #10490 (`origin/fix/10490-showaudit-discovery@00afcf64d`,
  `docs/pr/10490-showaudit-discovery/plan.md:21-45`) + keep
  `QuarantinedZoneNames` as the SSOT (no signature change; 6 prod call sites
  across 5 files untouched semantically:
  `zones_quarantine.go:65,236`, `zones.go:145`, `policymatch.go:1631`,
  `apply.go:43`, `ipsec_capture_wiring_9506.go:232`). The `policymatch`
  private wrapper (`policymatch.go:1623-1631`) is consolidated onto the new
  helper (third spelling removed, same verdict).
- No `ProcessStatus` wire change (field exists) and no new Prometheus metric
  name; the existing gauge remains. `collectZoneCounters`' quarantined
  sample omission and REST parity are the #10530 runtime disposition
  recorded in Test plan, while #10489's gate drain supplies the shared reason
  accounting required by the committed sibling rule. No new syslog/RT_FLOW
  format (survivor naming remains correct via `apply.go:43`).

## Invariants

1. The dataplane never receives two zones sharing a numeric id (#3719) —
   unchanged; this plan adds observation only, zero enforcement change.
2. The annotation verdict is computed by the same predicate family the
   builder enforces (`QuarantinedZoneNames` + `StableZoneIDOwner`) over EVERY
   key in the FULL `cfg.Security.Zones` map, including nil-valued keys, before
   any display filter. A renderer skips a nil zone only at render time; that
   skip cannot shrink the verdict set. No surface re-derives the verdict
   (#7473 composition rule).
3. On each of the 3 in-scope text paths (local CLI, gRPC text, remote
   detail), an active-config quarantined candidate renders the prospective
   marker plus qualified id/counters/interfaces/policies per the attribution
   table; the named `showTestZone` diagnostic also qualifies a candidate
   interface match. A surviving zone renders with no quarantine marker
   (signal direction pinned by fail-on-revert tests). These qualifications
   describe the active-config disposition, not proof that the current
   dataplane applied it. `GetZones`, `zonesHandler`, and remote brief are
   explicitly deferred to #10531 and claim no #10489 wire behavior.
4. dp-nil renderers annotate identically to dp-loaded ones for marker,
   qualified id, counters, interfaces, and policy attribution (verdict is
   config-derived; no `Status()` round trip on the render path). The drift
   note is omitted only when no applied-result baseline exists; with a
   baseline, it is emitted only for active-vs-applied key skew.
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
   `cli_show_security_zones_metadata_3684_test.go:109`,
   `server_show_zones_metadata_3684_test.go:98`,
   `cli_show_security_zones_policy_tiers_3658_test.go:111`,
   `server_show_zones_policy_tiers_3658_test.go:87-93`, and
   `host_inbound_display_3654_test.go:133`. Residual: LOW.

## Test plan

No test files are modified in this plan round. Implementation PR must carry:

1. **RED cell (PR #3837 regression), pin-table.** Colliding `z174`/`z214`
   config × unfiltered × the #10489 gRPC text and remote-detail paths (the
   local CLI canary is owned by the committed #10490 plan and is not repeated
   here). #10489's implementation cells pin `showZonesDetail` and its
   remote-detail route. `z214` renders the QUARANTINED disposition naming
   survivor `z174` + degraded-state wording, and `z174` renders unmarked.
   Filtered cells use the real topology: #10489 covers gRPC
   `showZonesDetail(filter=z214)` and `filter=z174` leaves the survivor
   unmarked. Unfiltered output is unchanged. Remote detail follows the gRPC
   text path (`cmd/cli/show.go:508-517` → `server_show.go:165` →
   `showZonesDetail:44-47`). Every `z214` block pins qualified id line,
   prospective/generic traffic wording (no survivor live numbers), qualified
   interfaces header, and prospective scrubbed-policy header. Reverting any
   renderer call site or using post-filter names makes its cells RED.
2. **Remote CLI split cell:** remote detail is covered by cell 1; remote
   brief is explicitly DEFERRED because it consumes structured `GetZones`
   data that remains absent until #10531. The #10489 test must not fake
   `quarantine_state` on an unmodified `GetZonesResponse`; #10531 owns the
   `UNKNOWN/NO/YES` structured-wire and old-server/old-client cells. Once
   state=YES exists, remote `GetPolicies` references in each zone block
   carry the same prospective scrubbed-at-runtime qualification as local/gRPC
   text.
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
   Eng10490's committed skeleton records 53 functions across 32 files with
   52 `Unannotated` entries and owns/annotates the permanent
   `showZonesDisplay` canary (`origin/fix/10490-showaudit-discovery@00afcf64d`,
   `docs/pr/10490-showaudit-discovery/plan.md:110-139,268-297`). #10489
   annotates `showZonesDetail` and `showTestZone`
   (`server_show_zones_text.go:242-349`; this is real diagnostic output, not
   a pure helper), records the remote-detail route, and handles every other
   census entry with the shared reason helper or an exact reviewed
   no-claim disposition. Only concrete no-Zone-value helpers and the two
   structured handlers may be exempt; metric paths omit quarantined samples.
   `TestExemptionsNameRealRenderers6534` proves only that exemption keys name
   existing functions (`surface_gate_6534_test.go:424-445`); reviewed
   per-function reasons control the semantic boundary. The builder registry
   and exact census tests are green before `Unannotated` closes to nil.
5. **No-false-positive cell:** `{"trust","untrust","dmz"}` renders zero
   markers on local CLI, gRPC text, and remote detail; `showTestZone`
   remains byte-identical for ordinary interface matches; counters/ids stay
   byte-identical to today (extends
   `TestQuarantinedZoneNamesNoFalsePositive` to the text layer with
   survivor attribution pins — the F4 mirror).
6. **Scoped parity gates and follow-up order:** focused tests cover the 29
   related files (6 API, 11 CLI, 12 gRPC) plus `pkg/showaudit`, `pkg/config`,
   and `pkg/policymatch`; byte-drift triage covers text goldens; a dedicated
   dp-nil cell proves store-less output has identical quarantine annotation
   while omitting only the drift note; HA symmetry uses identical configs;
   active-vs-applied skew asserts the drift banner fires exactly when an
   applied result exists and active config keys differ from `cr.ZoneIDs`.
   After #10490's committed skeleton, #10489 drains the shared gate and text
   obligations; #10530 then owns adjacent runtime behavior and the
   REST/metrics parity disposition; #10531 lands the structured wire fields
   and consumes that parity contract. Any change to this order requires both
   follow-up plans to mirror it.
   #10530 owns `collectZoneCounters`
   (`pkg/api/metrics_counters.go:564`, loop `:620-657`) and must treat a
   quarantined/unpopulated zone as an omitted per-zone series, not a zero:
   increment the unpopulated gauge and preserve REST
   `per_zone_counters_available:false`. The owner pin is
   `TestZoneUnpopulatedGaugeMatchesRESTAvailability`
   (`pkg/api/zone_counters_metrics_test.go:320-388`), which requires the
   gauge to count exactly the zones REST reports false. `make proto` is only
   in #10531 when its wire fields land.
7. **Re-measure commands (acceptance evidence):** the shared reason helper
   appears in `showZonesDetail`, `showTestZone`, and every census entry that
   emits a Zone value; `showZonesDisplay` is the #10490-owned canary, and
   remote detail is the `showZonesDetail` path. Assert the verdict consumes
   the FULL pre-filter key set including nil-valued keys, then skips nil only
   at render time; do not assert helper presence alone. Structured handlers
   are present only in the named #10531 exemptions; metric paths omit
   quarantined samples; no renderer reads manager-local
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
- Adjacent same-class runtime surfaces remain explicitly deferred to filed
  follow-up #10530 (no #10489 behavior claim): `show interfaces` iface→zone
  map (`cli_show_interfaces.go:117-125`, desired-config truth vs runtime
  `Zone=''`); screen `zonesByProfile`
  (`cli_show_security_screen.go:47-56`, `server_show_security_text.go:839-847`
  "Applied to zones"); policy inventory (`api/security.go:193` policiesHandler,
  `GetPolicies`, CLI hit-count — scrubbed rules still render live);
  Prometheus per-zone series (`metrics_counters.go:650-657` attributes
  survivor volume under the quarantined name); sessions/events zone loops
  (`session_filter.go:385`, `server_sessions.go:531`, `sessions.go:1258`).
  This follow-up owns the runtime marker/counter/absent-state decisions, but
  #10489 must still satisfy the committed gate's no-output-filter rule: each
  zone-valued output entry gets the shared reason or an exact no-claim
  disposition. That gate accounting is not a claim that #10530 behavior is
  fixed. #10530 owns `collectZoneCounters` and the REST/metrics parity
  decision pinned by `TestZoneUnpopulatedGaugeMatchesRESTAvailability`
  (`pkg/api/zone_counters_metrics_test.go:320-388`): quarantined/unpopulated
  entries omit per-zone series (not zero), increment the unpopulated gauge,
  and count exactly the zones REST reports with
  `per_zone_counters_available:false`; #10531 consumes this contract.
- Structured `GetZones` and `zonesHandler` are explicitly deferred to filed
  follow-up #10531 (enum/presence and counter truthfulness); the gate gives
  each the exact `deferred to #10531 — <surface/function>` rationale. This is
  not a broad structured-package exemption and makes no claim those handlers
  currently emit truthful quarantine state.
- `q04-failure-policy-F2+u04` mechanics follow the committed sibling split:
  #10490 owns the discovery half, row, census, and canary; #10489 owns the
  remaining annotations and drains the row
  (`origin/fix/10490-showaudit-discovery@00afcf64d`,
  `docs/pr/10490-showaudit-discovery/plan.md:21-47,299-337`).
- The 39-site consumer census from the source review (explicitly not
  reproduced per the issue's Limits; this plan vendors its own measured
  census above).
- Old-helper / pre-#3075 persisted-config migration behavior.

## Open questions (resolved in v4)

1. **Single PR or split? CLOSED: sequential campaign.** A single PR is
   rejected. The committed sibling contract puts #10490 first for names, row,
   census, collections, canary, and live successor; #10489 then owns the
   remaining annotations and drains the 52-entry list
   (`origin/fix/10490-showaudit-discovery@00afcf64d`,
   `docs/pr/10490-showaudit-discovery/plan.md:21-47,268-337`). The five
   operator inventory paths define the behavior matrix, while every other
   Zone-valued census entry still follows the no-output-filter drain rule.
   #10530 and #10531 remain the filed adjacent runtime and structured-wire
   follow-ups in the explicit order recorded in Test plan.
2. **Bool vs enum on the wire? CLOSED: enum in #10531.**
   `ZoneQuarantineState` UNKNOWN=0/NO/YES at 18 plus survivor string at 19;
   REST presence-typed with absent=UNKNOWN. Decisive: `xpf.proto:220-230` +
   `show_security.go:850-855` (either bool polarity makes a skewed pair
   produce a new wrong answer), and the skew pair is the quarantine threat
   model itself (HA sync from an un-upgraded peer). v1's bool proposal is
   withdrawn.
3. **Gate-row landing shape? CLOSED: exact two-step drain.** The committed
   sibling skeleton records 53 functions across 32 files, with 52
   `Unannotated` entries and the permanent local `showZonesDisplay` canary
   annotated by Eng10490. #10489 applies the shared reason to every
   zone-valued output/serialization entry, with only exact no-claim helpers
   and the two structured handlers exempted; it specifically annotates
   `showZonesDetail` and `showTestZone`. It closes `Unannotated` to nil only
   after `TestExemptionsNameRealRenderers6534` and the census tests pass
   (`origin/fix/10490-showaudit-discovery@00afcf64d`,
   `docs/pr/10490-showaudit-discovery/plan.md:110-139,299-337,339-377`).
4. **Predicate alias vs regex widening? CLOSED: exact aliases.**
   `ZoneQuarantineExclusions(names)` and
   `ZoneQuarantineExcludedReason(name,cfg)` are the names in the committed
   sibling contract (`origin/fix/10490-showaudit-discovery@00afcf64d`,
   `docs/pr/10490-showaudit-discovery/plan.md:21-45`); builder and policymatch
   delegate to the shared SSOT. No `dropPredicateName` widening, rename,
   regex broadening, or marker mechanism.
5. **Skew wording? CLOSED: active-config verdict + conditional drift
   banner.** Suppression when `applyResult()` is nil/stale is dropped because
   dp-nil implies nil (`pkg/cli/cli.go:238-243`,
   `pkg/grpcapi/apply_result.go:5-10`, `pkg/api/api.go:117-120`):
   the marker/attribution still renders. When an applied result exists,
   compare `keys(cfg.Security.Zones)` with `keys(cr.ZoneIDs)` (applied-set
   source `pkg/dataplane/apply.go:118-119`) only for an inventory-freshness
   note; `assignZoneIDs` puts both colliders in that map
   (`pkg/dataplane/compiler.go:355-358`), so it is never a quarantine verdict.
   Use the #5067 banner precedent (`cli_show_security_filters.go:355-387`);
   when no applied baseline exists, omit only the note. #10489 makes no
   structured-wire skew claim, which belongs to #10531.
6. **Survivor-side note? CLOSED: silent default.**
   The survivor renders byte-identically to today; the collision id is
   audit-visible only on the quarantined text block and existing one-shot alarm
   (`ZoneIDCollision.String()` names both).
7. **Text spelling SSOT location? CLOSED: `pkg/config`.** One shared const/
   format helper next to the verdict (the #6895 `UnavailableLineFor`
   precedent) serves local CLI, gRPC text, remote detail, and showTestZone.
   Direct `String()` reuse is blocked by import direction (userspace → config).
8. **Eng10490 boundary? CLOSED per committed sibling text.** Eng10490 owns
   predicate names, the zone-family row, the 53-function census, gate
   mechanics, and the `showZonesDisplay` canary; #10489 owns every remaining
   annotation/reason disposition and drains the row
   (`origin/fix/10490-showaudit-discovery@00afcf64d`,
   `docs/pr/10490-showaudit-discovery/plan.md:21-47,268-337,339-377`).
   Lower issue #10490 lands first; no unilateral renaming or gate-mechanics
   edit.
9. **Candidate classification ownership? CLOSED: shared map plus review
   matrix.** `showaudit.exemptRenderers` is the shared global mechanics map;
   #10490 owns its structure and completion entries, while #10489's
   per-function matrix records the reviewed application of each key. Every
   zone-valued output entry uses the shared reason; only exact no-output/
   no-Zone-value helpers and the two structured handlers may be exempt.
   Adjacent #10530 behavior is a runtime follow-up, not a package-wide or
   row-local exemption. No family-local map is introduced.
10. **showTestZone disposition? CLOSED: annotate.** Its server-side loop
    (`server_show_zones_text.go:306-344`) emits an interface→zone membership
    diagnostic, so exempting it would leave an operator-facing zone value
    unqualified. The shared reason helper adds the survivor/id quarantine
    qualification; ordinary membership and host-inbound output remain
    unchanged. This is a named diagnostic obligation, not a new inventory
    surface.
