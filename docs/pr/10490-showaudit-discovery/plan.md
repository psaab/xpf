# Plan — #10490 Showaudit name discovery misses quarantined-state builders

## Status

PLAN (Wave 1, plan-only round — no production code this round).

- Base `b71c52d60`, branch `fix/10490-showaudit-discovery`.
- STEP-0: NOT fixed. Zero-diff between evidence revision
  `1a6952b61ef5f7dcf0fdd1786d91b14c9bb3f705` and HEAD on all four
  evidence paths; `gh pr list --search "10490"` empty; no merged PR
  touches the gate or the quarantine call sites. Scoped proof:
  `go test ./pkg/showaudit/ -run TestEveryBuilderDropPredicateIsRegistered6534`
  passes at HEAD (0.133s) — the gate is green while zone quarantine
  ships with no show family registered.
- Sibling coordination: Eng10489 (`fix/10489-quarantine-show`,
  adjacent show/quarantine surfaces) is plan-only too; neither side
  claims shared builders as owned. Mutual read-only on
  `zones.go` / `zones_quarantine.go` / `surface_gate_6534_test.go`;
  sole write on each side is its own `docs/pr/<issue>-*/plan.md`.

## Issue framing

`pkg/showaudit` gates the `docs/engineering-style.md` #6534 contract
("A fail-closed exclusion owes a show-surface annotation"):
`TestEveryBuilderDropPredicateIsRegistered6534`
(`pkg/showaudit/surface_gate_6534_test.go:232-282`) scans
`pkg/dataplane/userspace` for `config.*` calls and keeps only names
matching `dropPredicateName`
(`/(?:Excluded|Unusable|Disarmed)Reason$|Exclusions$|Unsupported$|Undefined$/`,
:214), then asserts EXACT equality with the union of registry
`BuilderPredicates`. The registry carries exactly 7 families (:85-194,
no zone row).

`config.QuarantinedZoneNames` is called from the builder at
`pkg/dataplane/userspace/zones.go:145`
(`quarantinedZoneNames`, #6722 egress pre-filter) and
`zones_quarantine.go:65` (`quarantineCollidingZones` — the actual
fail-closed drop) and `:236` (`quarantinedZoneNamesForConfig`, #6480
republish re-scrub) — and matches none of the five alternations. So
zone quarantine, a fail-closed exclusion, passes the gate unseen, and
the degraded-`ZoneIDCollisions` per-object show omission persists with
the gate green.

The deeper defect class is convention-as-enumeration: any future
exclusion spelled outside the naming family is invisible BY
CONSTRUCTION. The gate's own comment (:196-199) admits it ("a builder
exclusion spelled outside this family has no row and no test").

## Scope value

What landing this fix buys:

1. Zone quarantine gets a registry row plus an exact renderer census,
   so the next quarantine-adjacent change cannot silently drop operator
   visibility — the gate reds instead.
2. The discovery hole closes for THIS family (rename/widen + row), with
   the class-level fix (type/marker discovery) evaluated as a tracked
   follow-up.
3. The `ZoneIDCollisions` quarantine-show omission, a regression
   against merged PR #3837's scope, gets a forcing function: the row
   fails if quarantine loses its show registration.

Blast-radius numbers (measured at HEAD, all pinned in Design):

| Population | Count | Where |
|---|---|---|
| Gate families today | 7, 0 zone rows | `surface_gate_6534_test.go:85-194` |
| Discovery regex alternations | 5 | `:214` |
| Builder fns scanned (non-vacuity floor) | >= 100 | `pkg/dataplane/userspace` |
| Surface pkgs censused | 5 | `pkg/cli`, `pkg/grpcapi`, `pkg/api`, `pkg/natshow`, `pkg/dataplane/userspace/format` (:62-68) |
| Prod `config.QuarantinedZoneNames` call sites | 6 in 5 files | zones_quarantine.go:65,236; zones.go:145; cli/apply.go:43; daemon/ipsec_capture_wiring_9506.go:232; policymatch/policymatch.go:1631 |
| Builder-internal (`builderPkg`) sites | 3 in 2 files | zones.go:145, zones_quarantine.go:65,236 |
| Raw `for range` over `Security.Zones` | 40 loops, 26 files | 16 cli, 16 grpcapi, 8 api; 0 in natshow/format; includes 2 loops in `*_test.go` |
| Gate population before explicit exemptions | 38 loops, 25 files | `parsePackage` excludes `*_test.go` (:493-495); gate has no output filter (:343-350) |
| Surface renderers consulting the verdict today | 0 | (apply.go:43 is a reverse map, not a show annotation) |

## Shipped context

- PR #3837 (merged, 19 files, closes #3719) shipped the quarantine
  itself: `config.QuarantinedZoneNames` SSOT (sorted-first survivor,
  pure function of the name set, HA-symmetric),
  `quarantineCollidingZones` (drop zone + unzone interfaces to
  default-deny + scrub policies so the Rust
  `UnresolvableZoneReference` preflight does not brick the snapshot),
  deterministic reverse maps, and observability: one-shot `slog.Error`,
  `ProcessStatus.ZoneIDCollisions` (`protocol_status.go:92`),
  `xpf_userspace_zone_id_collision` 0/1 gauge
  (`metrics_userspace.go:184`), plus the Rust `DuplicateZoneId`
  backstop. What it did NOT ship: per-object show annotation or a #6534
  family row — that is the regression surface this issue covers.
- Follow-ups that widened the quarantine call graph: #6480 (partial
  republish re-scrub via `quarantinedZoneNamesForConfig`, called at
  `manager_compile.go:983`), #6722 (egress pre-filter via
  `quarantinedZoneNames`, called at `interfaces.go:331`), #5577
  (prune-vs-drop for scoped-global sets). Full-build entry:
  `builder.go:205`.
- Gate history that constrains the design: #7357 added the
  `*Exclusions` shape as a WIDENING (map-returning whole-config walk
  for order-dependent verdicts — quarantine's sorted-first rule is the
  same shape); #7473 added shared surface compositions; #8185 closed
  the collect/render split. The style guide's rule 1 wants
  `...ExcludedReason(...) string` per-object predicates with the REASON
  surfaced (rule 3), builder and renderer calling the SAME predicate
  (rule 2), bound by an agreement test (rule 4).
- Reachability is already classified by construction: the STRICT commit
  path rejects collisions (`validateZoneIDCollisionAST`, #3075), so the
  quarantine is a LENIENT-path backstop (tolerant load, HA sync from an
  un-upgraded peer, pre-#3075 persisted config; #1960 no-brick) — like
  the NAT families, not the ordinary-commit ones. Implementation must
  pin this with a `Commit()`-based negative fixture per the style
  guide's "measure it rather than assuming".
- The `ZoneIDCollisions` STATUS channel exists and works
  (`manager.go:244`, `recordZoneIDCollisionsLocked` at
  `manager_compile.go:172`, `manager_status.go:31`); the omission is
  per-object annotation in zone renderers, not a missing diagnostic.

## Design

Three options per the issue; analysis narrows them.

**Option A — rename the predicate.** Rename `QuarantinedZoneNames` to a
name the regex sees (e.g. `*Exclusions`, matching the #7357
whole-set precedent). Effect: the gate SEES the predicate and REDS
until a family row exists — the rename forces the row. Ripple if done
as a true rename: 6 prod sites + `zoneid_test.go` + `docs/config-schema.md`
prose (+ historical `_Log.md` / review archives, which must NOT be
touched). Preferred sub-variant: keep the SSOT name and add a thin
builder-facing wrapper (e.g. `QuarantinedZoneExclusions`) that the 3
`builderPkg`-internal sites call. The gate scans ONLY
`pkg/dataplane/userspace`, so switching just zones.go:145 and
zones_quarantine.go:65,236 suffices for discovery; the policymatch,
daemon, and cli reverse-map callers keep the stable SSOT name. Zero
ripple outside `builderPkg` + gate + new helper.

**Option B — register the zone family explicitly.** CANNOT work alone:
bare registration of `QuarantinedZoneNames` in `BuilderPredicates`
fails the gate's stale-row check (:273-281 — "registry declares X but
no file calls it", because `called` contains only regex matches). B
requires A (rename/wrapper) or a regex widening (new `Quarantin\w*`
alternation, #7357-style "widening what the gate sees"). So the
issue's three options are really: A+B (rename/widen + row), or C.

**Option C — replace name-discovery with a type/marker mechanism.**
Kills the class (no future spelling can evade), but is the largest
review surface and changes the gate contract all 7 families rely on.
Tracked follow-up, not this fix — unless plan review demands it.

**Recommendation: A+B with a wrapper, C as follow-up.** Concretely:

1. `pkg/config`: add the builder-facing set-shaped wrapper plus a
   per-object reason helper (style rule 1+3); both delegate to the
   SSOT — no second implementation (rule 2). See API.
2. `pkg/showaudit`: add the 8th family row (zone); let the gate
   compute the `Unannotated` census over `Collections:
   ["Security.Zones"]` (38 non-test candidates before exemptions;
   raw source is 40 loops/26 files including 2 test loops). The gate
   deliberately has NO emit-output filter
   (`surface_gate_6534_test.go:343-350`): `reachesPredicate` only
   partitions annotated vs unannotated. Map-builders, completion
   providers, and session helpers therefore need an explicit
   `exemptRenderers` rationale or annotation.
3. Builder: switch the 3 internal sites to the wrapper. Builder drop
   behavior byte-identical (#1960 no-brick preserved).
4. Annotate the censused renderers with the reason helper; RED-on-revert
   both directions (drop the wrapper call → registration test reds
   naming it; drop an annotation → census test reds naming the
   renderer).
5. Census triage notes for implementation: every zone loop carries the
   #3493 nil-guard (must not confuse the scan); the five confirmed
   operator paths are `cli.showZonesDisplay`, gRPC `GetZones`
   structured, gRPC `showZonesDetail` text, REST `zonesHandler`, and
   remote `cmd/cli showZones` over `GetZones`. All other candidate
   loops need the explicit annotation/exemption decision.

## API

New/changed symbols (names provisional pending review):

- `pkg/config/zoneid.go`:
  - `func QuarantinedZoneExclusions(names []string) map[string]struct{}`
    — builder-facing wrapper delegating to `QuarantinedZoneNames`.
    Set-shaped like `StaticRouteExclusions` (sorted-first survival is
    set-dependent, the same reason #7357 needed the whole-config walk).
  - `func ZoneQuarantineExcludedReason(name string, names []string) string`
    — per-object verdict for renderers; `""` means installed,
    otherwise names the surviving owner + colliding id (rule 3: the
    REASON, not just the fact). Pure function of its inputs
    (HA-symmetry preserved).
  - `QuarantinedZoneNames` itself UNCHANGED (SSOT stability for the 3
    non-builder callers).
- `pkg/showaudit/surface_gate_6534_test.go`: +1 `family` row —
  `Name: "security zone"`, `Collections: ["Security.Zones"]`,
  `BuilderPredicates: ["QuarantinedZoneExclusions"]`,
  `SurfacePredicates: [wrapper + reason helper]`,
  `Unannotated: [exact census, computed at implementation]`,
  `Successor: #10490` (or #10489 if sequencing decides otherwise).
- `pkg/dataplane/userspace`: zones.go:145, zones_quarantine.go:65,236
  call the wrapper. No signature changes elsewhere.
- No wire/REST/proto changes: text annotation plus the existing
  `ZoneIDCollisions` channel. Structured `not_installed` for zones is
  out of scope unless the census forces it.

## Invariants

Must hold post-fix (each gets a test in Test plan):

1. Exact-equality: `called == registered`; drift in EITHER direction
   reds (new unseen predicate; stale row for a removed one).
2. Single verdict: builder and every annotated renderer consult the
   same predicate chain (wrapper → SSOT); no second implementation of
   the sorted-first rule anywhere.
3. Reason-surfaced: a quarantined zone renders with survivor name +
   colliding id, never a bare flag.
4. HA-symmetry: the verdict stays a pure function of the zone-name set
   (no allocation history, no node-local state); both HA nodes and a
   cold-booting node agree.
5. No-brick (#1960): builder drop behavior byte-identical; surfaces
   change annotation-only.
6. Lenient-only reachability: pinned by a `Commit()`-based negative
   fixture (strict path rejects; quarantine reachable only via lenient
   load / HA-sync / pre-#3075 config).

## Risk (4-class)

1. **Discovery-correctness.** A wrapper name that misses the regex, or a
   regex edit that over-matches, leaves the gate vacuous or stale-row
   red. Mitigation: RED-on-revert demo in the PR (revert the wrapper
   call → registration test reds NAMING the predicate); keep the
   non-vacuity floors (>= 100 fns scanned, non-empty called set).
2. **Census-exactness.** Raw source has 40 candidate loops across 26
   files; the gate sees 38 non-test candidates before explicit
   exemptions. They mix true renderers, `ifZone` map-builders,
   session-filter validators, and completion providers; alias-expansion
   or the #3493 guard pattern could mis-partition.
   Mitigation: let the gate compute the census, triage each entry on its
   merits, and exempt non-enforcement helpers with a written
   `exemptRenderers` rationale; a wrongly-exempted renderer is a named,
   reviewable line — not silence.
3. **Symbol-ripple.** A true rename touches 6 prod sites + tests + live
   docs and risks churn conflicts with in-flight quarantine work.
   Mitigation: wrapper-not-rename keeps the diff to `builderPkg`
   (3 sites) + gate + 2 new helpers; historical `_Log.md` / review
   archives untouched by policy.
4. **Coordination.** Eng10489 (#10489 quarantine-show) works the
   adjacent surface; unsequenced implementation could double-annotate
   or carry conflicting censuses. Mitigation: agree sequencing before
   code (discovery-row-first vs single PR), share one Successor issue
   for any non-empty initial census.

## Test plan

- Existing gate tests (must stay green AND gain the row):
  `TestEveryBuilderDropPredicateIsRegistered6534` (called-set grows by
  the wrapper),
  `TestEveryFamilyHasABuilderAndASurfaceCaller6534` (zone row has both
  halves), `TestSurfaceAnnotationCensusIsExact6534` (zone census exact
  both directions), `TestExemptionsNameRealRenderers6534`.
- New agreement test per style rule 4 (model:
  `TestNATExclusionBuilderRendererAgree_6534`): colliding `z174`/`z214`
  pair (both fold to 53547 — premise-checked so the fixture fails
  loudly, never vacuously); assert the builder drops `z214` AND each
  censused renderer annotates it with the survivor + id; assert `z174`
  renders clean (no cry-wolf).
- RED-on-revert proofs recorded in the PR: (a) wrapper call reverted →
  registration test reds naming `QuarantinedZoneExclusions`; (b) one
  annotation reverted → census test reds naming the renderer.
- Regression suites: `go test ./pkg/showaudit/... ./pkg/config/...
  ./pkg/dataplane/userspace/...` green; `go vet`, `gofmt` clean.
  Record at implementation: scan fn count, called-set size
  before/after, final census length.
- No cluster/incus commands in the implementation round until parent
  sequences smoke at merge time (build isolation:
  `GOCACHE=/dev/shm/gocache-10490`, `GOTMPDIR=/dev/shm`).

## Out of scope

- The independent u04 `LastSnapshotRejectReasons` show gap
  (`manager.go:233`, `protocol_status.go:81`,
  `metrics_userspace.go:170`) — separate issue/PR, explicitly not this
  fix.
- Option C (type/marker discovery replacement) unless plan review
  demands it — tracked follow-up.
- Structured `not_installed` for zones (JSON/proto wire change) — text
  annotation first.
- Rust helper changes — the `DuplicateZoneId` backstop shipped in
  #3837; untouched.
- Renaming `QuarantinedZoneNames` itself — wrapper preferred; rename
  only on review insistence.
- `_Log.md` / review-archive archaeology — historical prose stays.

## Open questions

1. Wrapper vs true rename for the builder-facing symbol — does review
   accept the extra symbol, or insist the SSOT itself match the regex?
2. Alternatively, should the REGEX gain a `Quarantin\w*` alternation
   (widen-what-the-gate-sees, #7357 precedent) with no builder change
   at all — and does that set a worse precedent than a wrapper?
3. Per-object reason signature: `(name, names)` set-plumbed, or
   `(name, cfg)` with internal name extraction — which do surface pkgs
   (all cfg-holding) prefer, and who owns the extractor?
4. Census triage: do `ifZone`-building helpers in interface renderers
   (the majority of the 40 raw loops) count as renderers that must
   annotate, or helpers explicitly excluded via `exemptRenderers` — and
   where a helper feeds both an emitting and non-emitting path, which
   verdict?
5. Implementation sequencing with #10489 (quarantine-show): single PR
   or discovery-row-first? Who carries the initial `Unannotated`
   census if it is non-empty on landing?
6. `Successor` field on the new row: #10490 or #10489?
7. Should `ZoneIDCollisions` status text change at all, or is
   per-object annotation purely additive to the existing channel?
8. Option C follow-up: file the tracking issue now (before landing
   A+B) or after — and does landing A+B reduce its priority below the
   bar?
