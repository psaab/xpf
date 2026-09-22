# Plan: annotate quarantined zones on operator show surfaces (#10489)

## Status

PLAN-READY (Wave 1, plan-only round). No production code in this round.
Worktree `/home/ps/git/pi-xpf/.claude/worktrees/10489-quarantine`,
branch `fix/10489-quarantine-show`, base `origin/master b71c52d60`.
Issue #10489 is OPEN and live at base: verified by STEP-0 below.

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

STEP-0 freshness proof (all run in-worktree at `b71c52d60`):

- `git log --all --oneline --grep='10489'` → empty (no prior fix commit).
- `git log --all --oneline -i --grep='quarantine.*show|show.*quarantine'` →
  2 unrelated hits (`86a6f657b` WireGuard scope, `d80fab02c` DDNS degraded
  state). No zone-show quarantine work.
- Last-50 merged-PR scan (`pr://?state=merged&limit=50`, #10483..#10412) →
  no #10489 fix.
- `ZoneIDCollisions|zone_id_collisions|lastZoneIDCollisions` over
  `pkg/` + `userspace-dp/` → 7 files, ALL producer-side
  (stamp/record/gauge/field-def); ZERO readers in `pkg/cli`,
  `pkg/grpcapi`, `pkg/api` server handlers, or `cmd/cli`. The diagnostic is
  written and never rendered (except as a boolean gauge).

## Scope-value

In scope: per-zone quarantine annotation on the zone show surfaces, so a
quarantined zone can never again render as enforced.

Blast-radius census (measured, not asserted):

| Class | Count | Members |
|---|---|---|
| Quarantine SSOT + runtime enforcement sites | 7 prod files | `pkg/config/zoneid.go` (warning :182-192, `QuarantinedZoneNames` :219, `StableZoneIDOwner` :249); `pkg/dataplane/userspace/zones_quarantine.go` (`ZoneIDCollision` :15, `String` :22, `quarantineCollidingZones` :57, `scrubPoliciesForQuarantinedZones` :128); `pkg/dataplane/userspace/zones.go:145` wrapper; `pkg/policymatch/policymatch.go:1595-1631`; `pkg/cli/apply.go:43`; `pkg/daemon/ipsec_capture_wiring_9506.go:232`; `pkg/dataplane/userspace/manager_sessionsync_request.go:283-287` (survivor-semantics reverse map) |
| Status plumbing (exists, no show reader) | 9 references across 6 files | `protocol_status.go:92` (field), `manager.go:244` (store), `manager_compile.go:172,173,179,428` (record/call), `manager_status.go:31` (stamp), `protocol.go:753` (builder carry), `pkg/api/metrics_userspace.go:184` (gauge) |
| Zone render paths with ZERO annotation | 5 paths / 4 daemon-side renderers + 1 remote client | (1) local CLI `show security zones[ detail]` → `showZonesDisplay` (`pkg/cli/cli_show_security_zones.go:16`, dispatch `:253` in `cli_show_security_dispatch.go`); (2) gRPC structured `GetZones` → `GetZones` (`pkg/grpcapi/server_show_zones.go:18`); (3) gRPC text `ShowText zones-detail` → `showZonesDetail` (`pkg/grpcapi/server_show_zones_text.go:38`, via `server_show.go:165`); (4) REST `GET /api/v1/security/zones` → `zonesHandler` (`pkg/api/security.go:19`) + `ZoneInfo` (`pkg/api/types.go:107`); (5) remote CLI `show security zones` → `showZones` (`cmd/cli/show_security.go:243`) + `zoneHostInboundView` (:210), `renderZoneTraffic6895` (:856) |
| Structured-schema owners | 2 | `proto/xpf/v1/xpf.proto:244` (`ZoneInfo`, fields 1-17 used, next free 18); `pkg/api/types.go:107` (REST `ZoneInfo`) |
| Show-gate families | 7 registered, 0 zone | `pkg/showaudit/surface_gate_6534_test.go:85` (port-mirroring, CoS, static-route, flow-server, static NAT, source NAT, destination NAT) |
| Golden/agreement tests over the 5 zone render paths | 29 files | `grep -rl showZonesDisplay\|showZonesDetail\|zonesHandler\|GetZones(` over `pkg/**/*_test.go` (6 api + 11 cli + 12 grpcapi) |
| Broader lexical `Security.Zones` candidate population | 40 raw loops across 26 files (CLI 16, gRPC 16, API 8); 38 non-test loops across 25 files enter the gate | Cross-lane source scan by Eng10490; this is a lexical candidate set, not 40 confirmed renderers. Two loops are in `apply_syslog_zonemap_3704_test.go` and are excluded by `parsePackage`; the 38 non-test candidates include non-render helpers (if-zone maps, session/completion paths). The 5 operator output paths above are the confirmed #10489 scope; the gate must classify candidates by range, emitted output, and predicate reachability rather than silently dropping them. |
| Consumers of the fix | 5 operator paths | local CLI operators, remote CLI operators, REST automation, gRPC structured automation, and gRPC text `show` |

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
   no text renderer) — the fix should decide whether to carry both or stay
   scoped to quarantine (see Open questions).
4. **Four config-iterating zone renderers** (table above). All iterate
   `cfg.Security.Zones` and consult only `applyResult()` + counters; none
   reaches `QuarantinedZoneNames`, `lastZoneIDCollisions`, or
   `ProcessStatus.ZoneIDCollisions`. The remote CLI assembles its view
   client-side from `GetZones` + `GetPolicies` and cannot ask the config.
5. **Show-gate blind spot, by construction.** `QuarantinedZoneNames` matches
   none of the `dropPredicateName` shapes (`*Excluded|Unusable|Disarmed`
   `Reason`, `*Exclusions`, `*Unsupported`, `*Undefined` —
   `surface_gate_6534_test.go:214`), so
   `TestEveryBuilderDropPredicateIsRegistered6534` cannot see the zone
   exclusion and no zone family row exists. A zone family needs either a
   gate-shaped predicate alias or a regex widening (owned decision below;
   mechanics coordinated with Eng10490 showaudit-discovery).
6. **Precedents to mirror.** #6895 (explicit UNAVAILABLE vs silent zero on
   all three surfaces + shared generic line); #7181 (applied-vs-desired
   `host_inbound_applied`, omitted-when-unwired so absence claims nothing);
   #3654/#3328 (host-inbound split fields across CLI/gRPC/REST in lockstep);
   #7473 (exported composition shared by all three surfaces instead of
   per-surface re-derivation).

## Design

**Recommended: config-derived per-zone annotation on all four daemon-side
renderers + proto/REST fields + remote-CLI render (full close, one PR).**

- New shared verdict helper in `pkg/config` (name TBD in review; must be
  gate-shaped, e.g. `ZoneQuarantineExclusions(names)`, returning
  quarantined→survivor pairs). Rationale: #7473 — one exported composition
  all surfaces share, so per-surface re-derivation cannot drift; gate-shaped
  so `pkg/showaudit` can register the zone family. It delegates to
  `QuarantinedZoneNames` + `StableZoneIDOwner` (no behavior change to the
  SSOT).
- Each of the 4 daemon-side renderers computes the verdict once per invocation
  over the rendered zone-name set and annotates:
  - quarantined zone: `QUARANTINED` marker + surviving zone name + degraded
    note (interfaces unzoned, policies scrubbed, traffic denied until
    rename). Text surfaces reuse the `ZoneIDCollision.String()` sentence
    shape; brief CLI gets a one-line marker, detail gets the full block.
  - surviving zone: no marker (it is enforced; marking it would invert the
    signal), but detail surfaces may note the collision id for auditability.
- Why config-derived recompute instead of reading `m.lastZoneIDCollisions`
  via `Status()`: (a) the local CLI runs with `dp == nil` (all detail tests
  construct `&CLI{store: store}`) and must annotate without a dataplane;
  (b) the predicate is provably the builder's own input function over the
  same name set, HA-symmetric; (c) the remote CLI cannot reach daemon
  memory — it needs the verdict on the `GetZones` wire format anyway.
  Status-plumbing stays as the daemon-side record and gauge source.
- Divergence guard (the #3643 skew class): active config vs last-applied
  snapshot can differ after a failed apply. The annotation labels its input
  ("per active configuration") and, where `applyResult()` is available,
  renderers note when the config set differs from the applied set. Exact
  wording is an Open question; silent agreement is not assumed.
- Show-gate row: add the zone family to `families` with
  `Collections: ["Security.Zones"]`, builder predicate = the new
  gate-shaped alias (builder calls it via the alias at `zones.go:145` /
  `zones_quarantine.go:65,236` — mechanical delegation, no semantic change),
  surface predicates likewise. The raw lexical candidate scan is 40 loops
  across 26 files (CLI 16, gRPC 16, API 8), including 2 test loops;
  `parsePackage` supplies 38 non-test candidates across 25 files. Only the
  5 confirmed operator output paths above are annotation obligations;
  non-render helpers and tests need explicit classification/exemption in the
  gate, never silent omission. Close with `Unannotated: nil` only after that
  census is exact, or land the census explicitly non-nil first per gate
  convention (Open question; coordinate with Eng10490 so discovery mechanics
  and this family do not collide — 10489 owns the zone family row + predicate
  alias, 10490 owns gate mechanics).

**Considered and rejected:**

- B. CLI-only annotation. Meets the letter of acceptance ("CLI at minimum")
  but leaves the #6534-class lie live on gRPC structured, gRPC text, REST,
  and remote CLI — the same partial close #7330/#7348/#7354 had to redo per
  family. Rejected; the full close is 4 small call sites sharing one helper.
- C. Status-surface-only (`show system` renders `ZoneIDCollisions` strings).
  Cheap but dp-dependent, unreachable from dp-nil CLI and remote CLI without
  new RPCs, and per-zone join is lost. Kept as a possible complement, not
  the fix.

## API

- `proto/xpf/v1/xpf.proto`, `message ZoneInfo` (fields 1–17 taken):
  `bool quarantined = 18;` + `string quarantine_survivor = 19;`
  (empty unless quarantined; proto3 omit-equivalent). Follows the #6895
  availability-enum lesson in the cheap direction: a bool defaults false on
  old servers, which is the common-case truth (no collision), unlike the
  counter-zero ambiguity. If review wants a third UNKNOWN state for
  old-server interop, use an enum at 18 instead (Open question).
- REST `ZoneInfo` (`pkg/api/types.go:107`): `quarantined` +
  `quarantine_survivor` JSON fields, `omitempty`, mirroring the #3329
  description/tcp_rst precedent. Bare `[]ZoneInfo` array shape unchanged
  (no envelope break — the README:2357 warning is respected).
- CLI text (local + gRPC text + remote): `QUARANTINED (id <n> collides with
  "<survivor>") — dropped from dataplane, interfaces unzoned, traffic
  denied; zone isolation DEGRADED until one zone is renamed`. Brief mode:
  first clause only. Exact spelling shared as one const/format helper so
  the three text surfaces cannot drift (#6895 lesson).
- `pkg/config`: new exported gate-shaped verdict helper (name TBD) + keep
  `QuarantinedZoneNames` as the SSOT (no signature change; 8 call sites
  untouched semantically).
- No `ProcessStatus` wire change (field exists); no Prometheus change
  (gauge exists); no syslog/RT_FLOW change (survivor naming already
  correct via `apply.go:43`).

## Invariants

1. The dataplane never receives two zones sharing a numeric id (#3719) —
   unchanged; this plan adds observation only, zero enforcement change.
2. The annotation verdict is computed by the same predicate family the
   builder enforces (`QuarantinedZoneNames` + `StableZoneIDOwner`), never
   re-derived per surface (#7473 composition rule).
3. A quarantined zone renders as NOT enforced on every zone surface; a
   surviving zone renders as enforced with no quarantine marker (signal
   direction pinned by fail-on-revert tests).
4. dp-nil renderers annotate identically to dp-loaded ones (verdict is
   config-derived; no `Status()` round trip on the render path).
5. HA symmetry: identical configs render identical annotations on both
   nodes (pure function of the name set; no node-local state).
6. Old-server interop: absent proto fields decode to not-quarantined, the
   common-case truth; REST omits unset fields (no `false = admit-all`
   inversion of the #3653 class).
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
- **R2 — Compatibility (API/wire shape).** New proto fields (18, 19) and
  REST JSON fields must not break old clients/servers or golden fixtures.
  Mitigation: proto3 scalar defaults + `omitempty`; 29 golden test files
  re-run to catch byte drift; remote-CLI old-server case (`ZoneInfo{Name}`
  only) asserted UNKNOWN-safe per the #6895 test shape. Residual: LOW.
- **R3 — Operability (skew, fatigue, HA).** Active-vs-applied skew (#3643
  class) could annotate from a config the dataplane never installed; a new
  per-zone marker could double-page alongside the existing gauge + one-shot
  alarm. Mitigation: annotation labels its input; no new alarm and no new
  gauge (existing two are the paging path); HA symmetry inherited from the
  pure predicate. Residual: LOW-MEDIUM (wording review required).
- **R4 — Verification (fixture reachability).** The quarantine state is
  lenient-path-only (strict commit rejects collisions) — a `Commit()`-based
  fixture cannot reach it (gate doc's reachability warning,
  `pkg/showaudit/doc.go:66-77`). Mitigation: fixtures build the colliding
  config via the lenient/tolerant load path (the `z174`/`z214` pair through
  `validateZoneIDCollisionAST(lenient=true)` + snapshot build), mirroring
  `zones_collision_3719_test.go`; plus a pure unit cell calling builders
  directly with a hand-built colliding config. Residual: LOW.

## Test plan

No test files are modified in this plan round. Implementation PR must carry:

1. **RED cell (PR #3837 regression):** colliding `z174`/`z214` config →
   each of the 4 daemon-side renderers renders `z214` QUARANTINED naming
   survivor `z174` + degraded state, and renders `z174` with no marker.
   Reverting the builder call sites (or the helper) makes all four RED.
2. **Remote CLI cell:** `GetZonesResponse` with `quarantined=true` renders
   the marker via `showZones`; old-server `ZoneInfo{Name}`-only response
   renders no marker (no false positive).
3. **REST/JSON cell:** `zonesHandler` emits `quarantined:true` +
   `quarantine_survivor:"z174"` for `z214`; omits both for ordinary zones.
4. **Show-gate cell:** the raw 40-loop `Security.Zones` population is
   classified exactly (CLI 16, gRPC 16, API 8), including the 2 test loops;
   the gate's `parsePackage` input is 38 non-test loops across 25 files.
   Only the 5 confirmed output paths are annotation obligations, while
   non-render helpers/tests have explicit reasons. The zone family is
   registered with `Unannotated: nil` after classification (or an explicit
   in-flight census first), and `TestEveryBuilderDropPredicateIsRegistered6534`
   plus `TestSurfaceAnnotationCensusIsExact6534` are green.
5. **No-false-positive cell:** `{"trust","untrust","dmz"}` renders zero
   markers on all surfaces (extends `TestQuarantinedZoneNamesNoFalsePositive`
   to the render layer).
6. **Full-suite gate:** `go test ./...` with focus on the 29 census files +
   `pkg/showaudit`, `pkg/config`, `pkg/policymatch`; byte-drift triage for
   any golden that newly carries the (absent-by-default) fields.
7. **Re-measure commands (acceptance evidence):** the STEP-0 greps must flip —
   the new verdict helper appears in all 4 daemon-side renderers and its
   structured fields appear in `pkg/api`, `pkg/grpcapi`, and the remote CLI;
   no renderer should read manager-local `ProcessStatus.ZoneIDCollisions`
   directly.

## Out of scope

- Any enforcement change: quarantine loser selection, unzoning, policy
  scrub, strict-vs-lenient commit behavior — all untouched.
- `LastSnapshotRejectReasons` text rendering (sibling diagnostic, same
  shape; scoped to the `u04-beyond-packet` finding per the issue's Limits —
  not this one).
- New alarms, gauges, or syslog formats (gauge + one-shot alarm already
  exist and remain the paging path).
- `q04-failure-policy-F2+u04` (showaudit gate carrying no zone family —
  filed alongside; the gate row here is the zone family's registration, the
  gate mechanics stay with Eng10490).
- The 39-site consumer census from the source review (explicitly not
  reproduced per the issue's Limits; this plan vendors its own measured
  census above).
- Old-helper / pre-#3075 persisted-config migration behavior.

## Open questions

1. **Single PR or split?** Full close (4 daemon-side renderers + remote CLI +
   proto + REST + gate row) in one PR, or text-surfaces-first with structured
   following? Recommendation: one PR (shared helper makes it atomic), but
   parent review may prefer a CLI-text-first split for a smaller blast
   radius.
2. **Bool vs enum on the wire?** `bool quarantined = 18` (absent = false =
   common-case truth) vs a `ZoneQuarantineState` UNKNOWN/NO/YES enum in the
   #6895 style. Bool is cheaper; enum distinguishes old-server silence.
   Which does the API owner want?
3. **Gate-row landing shape:** register the zone family with an explicit
   non-nil `Unannotated` census first (gate convention for in-flight
   families), then close to nil in the same PR — or land closed directly?
   Latter is one diff; former proves the detector sees the family.
4. **Predicate alias vs regex widening:** should the gate-shaped verdict be
   a new `ZoneQuarantineExclusions`-style alias in `pkg/config` (builder
   delegates mechanically), or should `dropPredicateName` widen to match
   `QuarantinedZoneNames`? Alias keeps the gate convention strict; widening
   risks matching unrelated future symbols.
5. **Skew wording:** when active config and last apply result disagree on
   the zone set, what exactly does the annotation say? Options: (a) annotate
   from active config unconditionally with a "per active configuration"
   tag; (b) suppress the marker when `applyResult()` is nil/stale; (c)
   render both. Needs an operator-voice decision.
6. **Survivor-side note:** should detail surfaces note the collision id on
   the SURVIVING zone (auditability: "this id collided, you kept it"), or
   stay silent there to keep the signal binary? Silent-by-default is the
   plan; confirm.
7. **Text spelling SSOT location:** one shared const/format helper — in
   `pkg/config` (next to the verdict), `pkg/zonecounters`-style presenters,
   or per-surface with an agreement test? `pkg/config` next to the verdict
   is the recommendation (verdict + wording cannot drift apart).
8. **Eng10490 boundary:** 10489 owns the zone family row + predicate alias;
   10490 owns showaudit discovery mechanics. If 10490 lands a mechanics
   change that reshapes `families`/`reachesPredicate`, who rebases?
   Proposal: whichever lands second rebases (lower issue number merges
   first on collision per campaign rule → 10489 first).
9. **Candidate classification ownership:** the 40-loop lexical population
   includes non-render helpers and a test. Should explicit exemptions live in
   the shared `showaudit` scanner (Eng10490's mechanics) or in this zone
   family's registry row? Recommendation: keep the scanner generic and put
   stable, reasoned exemptions beside the zone family row so a new output
   renderer cannot hide behind a broad package exemption.
