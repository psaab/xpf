# Plan: operator show surface for last-snapshot reject reasons (#10500)

## Status

READY v2 implementation design. The reviewed artifact and its accepted
implementation are kept as separate commits on this branch. Implementation
base `7dcdd7383` (= `origin/master` at implementation time;
`fix/10500-reject-show-surface`). V1 (base 11 commits behind) drew two
convergent PLAN-NEEDS-MAJOR verdicts; this revision folds all eight binding
parent decisions plus every must-fix from both reviews. Delta review marked
this design READY; implementation follows the binding contracts below.

What changed since v1 (review-driven corrections):

- DUAL-SURFACE: overview block AND `show chassis forwarding` row (v1's
  overview-only left standalone read-only operators with no surface, and
  its "interface surgery twice refused" premise was false — both
  citations were crash-provider-separation comments, and `fwdstatus.Build`
  already holds the stamped field via its existing `usStatus` fetch).
- One-reason-per-line block (v1's `"; "` join collides with the
  intra-reason cause separator — the specified contract was unparseable).
- Grammatical label + measured alignment (v1's label was ungrammatical
  and off by one column; its "`%-` widths" claim was false — the
  renderer uses literal-padded strings only).
- I3/Q4 rewritten to true mechanics (<=1s re-stamp without rebuild;
  helper-down omits the block — v1's "until rebuild" window was wrong).
- F5b producer fix specified (scheduler + route-overlay republishes
  recompute caps without re-recording — v1 never examined the
  incremental paths).
- Real-shaped fixtures + byte-compare absent cell (v1's fixtures were
  fake and its absent cell punted).
- #3837 follow-up resolved WITHOUT a new filing: OPEN issue #10489
  already covers the `ZoneIDCollisions` show-half regression (see Q1);
  filing again would duplicate it. I5 exclusion stays binding.
- V1-Q5 text-only ACCEPTED and V1-Q7 NO KILL recorded per binding
  decisions.

## Issue framing

The userspace manager knows the last snapshot build carries unrepresentable
policy content that the helper integrity preflight rejects (previous-good
retained, fresh-boot default-deny — never fail-open). That knowledge lives in
exactly one struct field:

- `ProcessStatus.LastSnapshotRejectReasons` (`[]string`, #3261 diagnostic),
  defined at `pkg/dataplane/userspace/protocol_status.go:71-81`,
  recorded under `m.mu` by `recordPolicyContentRejectionLocked`
  (`pkg/dataplane/userspace/manager_compile.go:147`, called at `:424` with
  `snap.Capabilities.PolicyContentRejected`), and stamped onto every status
  the manager hands out by `recordHelperStatusLocked`
  (`pkg/dataplane/userspace/manager_status.go:27`), funneled through
  `applyHelperStatusLocked` (`pkg/dataplane/userspace/maps_sync.go:641`).

Its only two consumers are the Prometheus 0/1 gauge
`xpf_userspace_policy_content_rejected`
(`pkg/api/metrics_userspace.go:168-173`, via `emitPolicyContentRejected`) and
a transition-only one-shot `slog.Warn`/`slog.Info`
(`manager_compile.go:152-158`). No `show` on any surface names the reasons:
at base, `LastSnapshotRejectReasons` has zero references in `pkg/cli`,
`pkg/grpcapi`, `pkg/dataplane/userspace/format`, and `pkg/natshow`
(verified by scoped grep over both the Go identifiers and the
`last_snapshot_reject_reasons` / `zone_id_collisions` JSON spellings; the
only repo hits outside the manager/protocol/metrics triangle are review
docs and `docs/issues` history). An operator staring at `show` output sees
a healthy system while the dataplane never took the config. Impact per the
issue: Medium.

STEP-0 (re-run at v2 base `ad76780c4`): the producer/stamp/consumer sites
above are all present at the cited lines (line numbers re-confirmed
post-rebase); the four-package zero-reference check still holds; the
explicit merged-PR search `repo:psaab/xpf is:pr is:merged 10500` via the
GitHub API returns `total_count: 0` (no merged PR references the issue);
the identifier search `repo:psaab/xpf LastSnapshotRejectReasons` returns
only the open issue itself plus related open/closed quarantine and
duplicate-rule issues (#10489 open, #10490 closed, #9584/#9586 closed,
#3837 closed) — none of which renders this field. The adjacent commit
`8e9b81bce` ("surface the #3727 content-rejected verdict on all surfaces")
is a different diagnostic (`policymatch.Result.ContentRejected`, a
per-policy match verdict on the match-policies surfaces), not a fix for
this snapshot-level field — but it is the in-tree precedent for printing
"ContentRejectedShowLine plus each reason" on text surfaces, which v2
follows.

Bounded scope — `ZoneIDCollisions` EXCLUDED. This issue files only the
`LastSnapshotRejectReasons` no-operator-show residual. `ZoneIDCollisions`
(`ProcessStatus` field #3719) is owned by merged PR #3837 ("Quarantine
lenient StableZoneID collisions", closes #3719). This plan does not touch
that field, its recorder (`recordZoneIDCollisionsLocked`), its gauge, or
any render of it. V1 flagged that #3837's claimed "`(show)`" has zero
named show refs too; the v2 disposition is Q1: OPEN issue #10489
("Quarantined zones are absent from operator show surfaces") already files
exactly that regression against #3837's scope (including a demand for a
regression test of the promised show), so no new filing was made. Landed
partial coverage exists adjacent: #10490 (at the v2 base tip) renders a
config-derived `Quarantine:` row in `show security zones`
(`cli_show_security_zones.go`, via `config.ZoneQuarantineExcludedReason`)
— a config derivation, not a read of the runtime `ZoneIDCollisions`
stamp. Reconciling #10490's row against #10489's runtime-show demand is
#10489-owner business; this lane stays out.

## Scope-value

Honest value statement: this fixes operator blindness to a degraded,
fail-closed state, not a forwarding bug. The dataplane already does the
right thing (retains previous-good / default-deny); Prometheus already
exposes the boolean; the log already carries the reasons once per
transition. What is missing is the durable, on-demand, operator-facing
surface: an admin SSHing into a box after the one-shot warning scrolled
past, or without a metrics scrape in front of them, currently cannot learn
from any `show` that the running config is NOT the committed config, nor
which content is being refused.

V2 scope (dual-surface + producer fix, all small):

- One conditional block in `writeOverviewSection`
  (`pkg/dataplane/userspace/format/status_sections.go:313`), placed after
  `Forwarding blocked by:` (`:335-337`) and before the #9642 retry-debt
  line (`:341-343`) — grouping the "why is this box not enforcing what I
  committed" diagnostics adjacently. Covers the 7 existing
  `FormatStatusSummary` call sites (2 cluster-gated passive + 5 mutating;
  see Shipped-context for the honest reachability census).
- One conditional block in `fwdstatus.Format`
  (`pkg/fwdstatus/fwdstatus.go:159`), reading a new `ForwardingStatus`
  field copied from the already-fetched `usStatus` in `Build`
  (`pkg/fwdstatus/builder.go:161-168`) — zero interface change, zero
  extra control-socket fetch. Covers `show chassis forwarding` on CLI
  and gRPC ShowText, standalone and cluster — the universal read-only
  surface v1 lacked.
- Two one-line producer records mirroring `:424` on the scheduler and
  route-overlay republish paths (F5b fix), so the stamp tracks the latest
  incremental snapshot-build attempt with the same pre-publish semantics
  as the full-build recorder, instead of staying at the last FULL build.

Total production delta: ~25 lines (2 render blocks + 1 struct field + 1
copy + 2 record calls + comments). Cost is two conditional renders plus
tests; risk is golden churn plus review of one label string.
What this deliberately does NOT buy: it does not add a REST field (no
REST status surface exists to extend — text-only accepted as a recorded
decision); it does not change enforcement, retention, or alarm/log
message semantics.
The F5b calls intentionally reuse the existing transition-only Warn/Info
recorder behavior at newly covered republish sites; no log string or
alarm channel is redesigned. It does not realign the pre-existing
28-col retry-debt row (explicitly left alone); it does not render
`ZoneIDCollisions` (owned by #10489 lineage).

## Shipped-context

Surrounding machinery this change plugs into (all shipped, none reopened
except the two F5b record calls):

- Producer (full build): `buildSnapshot` records
  `snap.Capabilities.PolicyContentRejected` (the pure-builder diagnostic);
  `recordPolicyContentRejectionLocked` copies it into
  `m.lastSnapshotRejectReasons` BEFORE publish (`manager_compile.go:424`),
  so the diagnostic is captured even when the publish is rejected;
  transition-only alarm (`slog.Warn` naming `reasons` on
  representable→unrepresentable, `slog.Info` on recovery). Recovery
  clears the field (`recordPolicyContentRejectionLocked(nil)`), pinned by
  `lenient_keep_armed_3261_test.go:105-124` (record/clear of the private
  field only — no existing test asserts stamp→status for reasons).
- Producer (incremental paths — F5b): `UpdatePolicyScheduleState`
  (`manager_compile.go:1005-1112`, holds `m.mu` throughout) rebuilds
  policy sections via `rebuildScheduledPolicySectionsLocked` (`:941`),
  which RECOMPUTES `next.Capabilities.PolicyContentRejected` from the
  scrubbed rules (`:985-987`, comment: "the copied lastSnapshot value
  would be stale") — then commits `m.lastSnapshot = &next` (`:1093`)
  WITHOUT recording. `PublishRouteOverlaySnapshot`
  (`manager_overlay.go:103-293`, holds `m.mu` throughout) rebuilds routes
  (`:212`), optionally rebuilds policy sections when scheduler state is
  carried (`:235-241`, same shared helper), then commits (`:277`) WITHOUT
  recording. Only production caller of the recorder today is `:424`. A
  scheduler transition flipping representability therefore leaves the
  recorded reasons (and gauge, and any render) stale until the next FULL
  build. Rich same-package test seams exist for both paths
  (`apply_snapshot_identity_9520_test.go`,
  `manager_overlay_scheduler_5328_test.go`, `manager_republish_3780_test.go`
  all drive `UpdatePolicyScheduleState` with scripted helpers).
- Reason shapes (new in v2 — v1 never examined them):
  `collectPolicyContentRejections`
  (`policies_reject.go:54-98`) emits one reason per poisoned rule:
  `policy <scope> names content the userspace matcher cannot represent:
  <causes>` (`:94-95`), where scope is `from->to/name`,
  `global/name`, or `global(a->b)/name` (`policyRejectionScope`,
  `:194-208`) and causes join per-side entries with `"; "` (`:95`).
  Each cause is `<side> "tok", "tok"` with `%q`-quoted
  operator-configured names (`rejectionCause`, `:215-224`) that may
  themselves contain `";"`, `":"`, or `","`; the bare-side fallback
  (no tokens, e.g. wire-decoded snapshots) renders just the side label.
  A minimal real reason runs ~101 chars; two reasons joined run 200+.
  Deterministic order: slice order from `walkPolicyRuleSlots` over
  config slices (`policies.go:91-122`).
- Stamp: `recordHelperStatusLocked` deep-copies (`append([]string(nil),
  ...)`) the manager-owned diagnostics onto the status because the helper
  strips unknown fields on the control-socket round-trip; `Status()`,
  `CachedStatus()`/`lastStatus` (1 Hz `statusLoop`:
  `process_status.go:277-280` ticker, poll + `applyHelperStatusLocked` at
  `:329-337`), and the counter-sync poll paths (`natcounters.go:63`,
  `policycounters.go:426`, `zonecounters.go:66`, `maps_sync.go:641`,
  `floodcounters.go:42`) all serve stamped snapshots. The stamp is
  re-applied from the surviving manager field on EVERY successful poll —
  no rebuild needed (see I3).
- Existing partial observability: `xpf_userspace_policy_content_rejected`
  0/1 gauge (emitted unconditionally — 0 is a real "representable"
  signal) plus the one-shot log lines above.
- Text single-source (overview leg): `pkg/dataplane/userspace/format`
  (`dpformat`) builders are consumed by both local CLI and gRPC text
  paths so "the console and the remote `cli` cannot disagree"
  (`server_show_system.go`, `cli_show_system.go` comments; #7357 parity
  tests bind the wiring, not the formatter). The 7
  `FormatStatusSummary` call sites, with honest reachability (v1
  correction): 2 passive but cluster-gated — CLI `show chassis cluster
  data-plane statistics` (`cli_show_cluster.go:355-365`, gate `:356-359`
  returns before the `:361` fetch) and its gRPC twin
  (`server_show_cluster_text.go:181-191`, gate `:182-185` before the
  `:187` fetch); 5 mutating — CLI `request chassis cluster data-plane
  userspace {...}` confirmations (`cli_request_chassis.go:192`, no
  cluster gate, goes straight to control verbs) and 4 gRPC SystemAction
  messages (`server_diag_system_action.go:431,447,472,501`, gated on
  dpProbe only). On a standalone box the overview leg reaches a
  read-only operator through NONE of these — hence the forwarding leg.
- Forwarding leg (new in v2): `fwdstatus.Build` performs exactly ONE
  `Status()` call (`usStatus, usErr = acc.Status()`,
  `builder.go:161-168`, via anonymous-interface probe precisely so
  "`DataPlaneAccessor` stays the two-method surface" — `:216-218`,
  `README.md:25-27`); both forwarding adapters already expose `Status()`
  (CLI `cli_show_chassis.go:100`, gRPC `server_show_forwarding.go:64`);
  `Build` has no early returns (single `return fs, nil` at `:279`; the
  State switch at `:266-277` maps `usErr != nil` to Unknown). Copying
  `usStatus.LastSnapshotRejectReasons` into a new `ForwardingStatus`
  field is therefore ~10 lines with zero interface change and zero
  extra fetch (honoring the "fold into that lookup to avoid a second
  `Status()` call" rule at `:153-155`). `show chassis forwarding` is
  the ONE surface rendering standalone: CLI `showChassisForwarding`
  builds `localBuf` unconditionally (`cli_show_chassis.go:21-22`), and
  the gRPC twin renders `localBuf` and returns early when `s.cluster ==
  nil` (`server_show_cluster_text.go:38-42`).
- Text-vs-structured rules observed in-tree: text surfaces render through
  `dpformat`/`fwdstatus` builders with omit-when-empty conditional
  sections (`writeEventStreamSection` early return,
  `FormatSYNCookieCounterRows` returning `""`, `writeHelperCrash`
  "SILENT WHEN THERE IS NOTHING TO REPORT"); structured REST surfaces
  add explicit JSON fields on result types; gRPC `ShowText` is text,
  dedicated RPCs are structured. `fwdstatus.Format` labels/ordering/
  spacing are a contract surface ("do not rearrange without updating
  unit tests" — additive conditional blocks are the sanctioned delta).
  Overview rows use literal-padded `Fprintf` strings with a 29-char
  value grid (e.g. `  Forwarding blocked by:     `); there are no
  `%-` verbs in `writeOverviewSection` (v1's "`%-` widths" claim was
  false and is struck).
- `pkg/api` (REST) has no forwarding-status endpoint and no wholesale
  `ProcessStatus` JSON marshal. Corrected census (v1 said three): four
  sites reach userspace `Status()` — the Prometheus collector via
  `fetchUserspaceStatus` (`metrics_userspace.go:23`, called from
  `Collect`), the sessions summary via the SAME helper for
  `MaxSessions` only (`sessions.go:820-822`), NAT pools (`nat.go:46`),
  and system buffers (`system.go:311`); `vrrp.go:55` is a different
  `Status` homonym (`vrrpMgr.Status()`). The
  `json:"last_snapshot_reject_reasons,omitempty"` tag exists on the
  wire struct but no REST handler serves it.
- `pkg/natshow` (8 non-test files: `dest/source/static/persistent/walk`
  + match/action helpers) renders NAT-rule views only; it has no
  snapshot-status concept and no `ProcessStatus` consumption.
- Golden mechanics: `testdata/status_summary.golden` (162 lines) pins the
  full byte-for-byte `FormatStatusSummary` output of a fixture exercising
  every conditional section; `-update` regenerates after a deliberate,
  reviewed change; wall-clock-relative fields are excluded from the
  golden and covered by substring tests in `status_test.go`. Note (new):
  the #9642 debt precedent is substring-only (the golden depicts no debt
  line) — extending the golden with reasons makes it permanently depict
  a rejected box (see Q4).
- Adjacent landed coverage: #10490's config-derived `Quarantine:` row in
  `show security zones` (config derivation, not a runtime-stamp read).

Blast-radius numbers (all verified at v2 base): 1 full-build producer +
1 stamp site + 1 funnel + 2 unrecorded incremental paths; 2 existing
consumers; 0 show refs in the 4 render packages; 2 render functions to
edit (`writeOverviewSection`, `fwdstatus.Format`) + 1 struct field + 1
`usStatus` copy + 2 producer record calls; overview leg covers 7
existing call sites (2 cluster-gated passive + 5 mutating); forwarding
leg covers the universal `show chassis forwarding` (CLI + gRPC ×
local/peer); 19 test files in `format/` (+1 new, +golden regen); 7 test
files in `fwdstatus/` (+1 new row test); same-package userspace stamping,
scheduler + route-overlay pinning tests; 8 non-test files in `pkg/natshow`
  (excluded, no status concept).

## Design

### Overview block (cluster + control-verb leg)

Render a conditional block in `writeOverviewSection`, placed directly
after the `Forwarding blocked by:` line (`:335-337`) and before the #9642
retry-debt line (`:341-343`) — grouping the "why is this box not
enforcing what I committed" diagnostics adjacently in causal order
(capability gate → content rejection → publish debt). Shape (binding:
one-reason-per-line; v1's `"; "` join is struck as unparseable per F1):

```go
if len(status.LastSnapshotRejectReasons) > 0 {
    fmt.Fprintf(b, "  Last snapshot rejection:   %s\n", status.LastSnapshotRejectReasons[0])
    for _, reason := range status.LastSnapshotRejectReasons[1:] {
        fmt.Fprintf(b, "%29s%s\n", "", reason)
    }
}
```

Label decision (binding: grammatical and 29-column aligned):
`Last snapshot rejection:` — a grammatical noun phrase that preserves the
`Last`/last-build meaning while naming the state rather than assigning a
person to "reject by". The first reason follows three literal spaces,
so the rendered label/value prefix is exactly 29 columns without any
trailing whitespace; additional reasons use a 29-space value-column
prefix via `%29s`, one reason per line. The pre-existing retry-debt line
(`Snapshot retry debt:`) is already 28-col padded; explicit decision:
leave it byte-identical and out of scope rather than mixing this fix with
its pre-existing alignment nit.

No aggregate change: reasons are a plain `[]string` on the status
snapshot, read directly like `UnsupportedReasons` — the one-pass
aggregate/render split (`aggregateStatusSummary` owns the only
bindings/queues/CoS walks) is untouched.

### Forwarding row (universal read-only leg)

`pkg/fwdstatus/builder.go` `Build`: after the userspace Buffer block,
copy the already-fetched stamped reasons (no new fetch, no interface
change):

```go
if isUserspace && usErr == nil {
    fs.LastSnapshotRejectReasons = append([]string(nil), usStatus.LastSnapshotRejectReasons...)
}
```

`pkg/fwdstatus/fwdstatus.go`: add `LastSnapshotRejectReasons []string`
to `ForwardingStatus` (same name as the source field — grep-able
lineage), and render a conditional block in `Format` after the `Uptime:`
row (`:199`), before `writeHelperCrash` (`:201`) — degraded-config
state reads before the process-health epilogue. Use a grammatical header
row and a uniform one-reason-per-line continuation block:

```go
if len(fs.LastSnapshotRejectReasons) > 0 {
    writeRow(&b, "Last snapshot rejection", fs.LastSnapshotRejectReasons[0])
    for _, reason := range fs.LastSnapshotRejectReasons[1:] {
        fmt.Fprintf(b, "%37s%s\n", "", reason)
    }
}
```

`writeRow` places the first reason on the existing 34-character label
grid; the `%37s` continuation prefix (2 + 34 + 1) is the value column,
and every reason occupies its own line without a blank header or trailing
whitespace. When the helper is down (`usErr != nil`), the copy is skipped
and the block is omitted — consistent with I3. Total forwarding delta:
~10 lines. V1's "interface surgery twice refused" rationale is struck:
both citations were crash-provider-separation comments, and the
anonymous-probe pattern (`:216-218`) exists precisely to avoid widening.

Surfaces covered by construction: overview leg = the 7
`FormatStatusSummary` call sites (single-source, no per-surface code);
forwarding leg = `show chassis forwarding` everywhere it renders (local
CLI, cluster-peer CLI via ShowText, local + peer gRPC text). No new CLI
verb, no new RPC, no REST field.

Format rules honored: omit-when-empty on both blocks (empty =
representable = healthy; no "none" row); deterministic rendering (no
wall clock; slice order); overview first reason is on the exactly
29-column label/value row and later reasons use `%29s`; forwarding
first reason is on the existing row grid and later reasons use `%37s`;
both blocks are additive contract deltas with no emitted trailing
whitespace.

### F5b producer fix (preferred branch: record on both paths)

Both incremental paths hold `m.mu` throughout and the recorder is a
`Locked`-suffix method called in the same lock context as `:424` —
mirroring is small (2 calls + comments, ~6 lines) and safe (transition
alarm preserved; a transition fired by a scheduler-driven flip is
correct behavior, since representability genuinely changed):

- Scheduler path: after `rebuildScheduledPolicySectionsLocked` success
  (`manager_compile.go:1058`), before `requestApplySnapshotLocked`
  (`:1077`) — mirrors `:424`'s record-before-publish (captured even
  when the publish is rejected):
  `m.recordPolicyContentRejectionLocked(next.Capabilities.PolicyContentRejected)`.
  On rebuild failure the early return leaves prior state (correct: the
  prior snapshot is retained).
- Overlay path: after the rebuild section (`manager_overlay.go:235-241`
  scheduler branch; routes at `:212`), before the duplicate-skip
  evaluation (`:248`) and publish (`:266`) — same call on
  `next.Capabilities.PolicyContentRejected`. For route-only republishes
  the caps are inherited so the record is a transition no-op (harmless
  and converging); recording before the skip also converges staleness
  on the skip path (see Q3 for the placement alternative).

This restores the intended property that the manager-owned stamp tracks
the latest snapshot-build attempt, matching the full-build
record-before-publish semantics. V1's R2 claim that "text and metrics
cannot disagree" was vacuous — both read the same stale stamp; the
producer mirror is load-bearing.

Rejected alternatives (costs corrected):

- A. Overview-only (v1 as written): REJECTED. Leaves standalone
  read-only operators with no surface (2/7 cluster-gated, 5/7
  mutating — v1 never disclosed this split).
- B. Forwarding-only: REJECTED in favor of dual. The overview block is
  ~8 lines, groups causally with the other degraded-state lines, and
  costs no new call sites; dropping it would leave cluster-box
  overviews blind while forwarding shows the state.
- C. New dedicated verb/RPC: REJECTED (more surface for a diagnostic
  that belongs beside the other degraded-state lines).
- D. REST-only/structured twin: REJECTED for this change (no REST
  status surface exists; text-only accepted as a recorded decision;
  automation keeps the gauge).
- E. Log-only (Q7 kill): REJECTED — NO KILL recorded. Gauge is
  boolean-only, the one-shot log scrolls past with unverified
  operator visibility, and the match-policies simulator covers
  pre-commit content, not enforced-vs-committed skew on a running box.
- F. F5b document-only branch: REJECTED in favor of the record fix —
  taken only if delta review finds the mirrored calls unsafe (the
  fallback is a documented staleness window + a test pinning
  scheduler-path behavior).

## API

No signature changes to exported functions, no new RPC, CLI verb, REST
route, or Prometheus series. Additive deltas: one `ForwardingStatus`
field (`LastSnapshotRejectReasons []string` — an internal view struct,
not wire), and two conditional text blocks present if and only if
`len(LastSnapshotRejectReasons) > 0`, plus the regenerated golden bytes.
`DataPlaneAccessor` (two methods), `ProcessStatus` wire shape, and the
gauge/log contracts are unchanged. The producer fix changes no
signatures; its observable delta is that the recorded reasons (hence
gauge + both renders + one-shot alarm) track scheduler/overlay
republishes — the intended convergence.

## Invariants

- I1 (stamped-source): both renders read manager-stamped snapshots —
  overview via `Status()` → `applyHelperStatusLocked` →
  `recordHelperStatusLocked`; forwarding via the same `Status()` result
  already fetched as `usStatus` in `Build`. A raw helper-socket decode
  bypassing the stamp carries no reasons (the helper strips the unknown
  field) — any future consumer MUST source from the stamped path, never
  a direct `ControlRequest{Type: "status"}` decode.
- I2 (empty-means-healthy): nil/empty reasons render nothing on EITHER
  surface. Recovery returns both surfaces to their exact prior bytes;
  there is no "recovered" or "none" row.
- I3 (manager-owned, re-stamped; REWRITTEN per F5a — v1's "until
  rebuild" window was false): reasons describe the latest snapshot
  build ATTEMPTED for publication (I7), preserving the full-build
  record-before-publish semantics, and live in the manager field
  `m.lastSnapshotRejectReasons`, which `clearLastStatusLocked` does NOT
  touch (`manager_status.go:62-66` zeroes `lastStatus` only). Every
  successful 1 Hz `statusLoop` poll re-stamps from the surviving field
  (`process_status.go:329-337` → `maps_sync.go:641`) — so after a
  helper restart the block reappears within <=1s with NO rebuild
  (correct: the content did not change). While the helper is down,
  `Status()` errors (`manager_status.go:72-76`) and both surfaces omit
  the block: the overview paths skip the userspace section on error
  (`cli_show_cluster.go:361`, `server_show_cluster_text.go:187`), and
  `Build` skips the copy on `usErr != nil` (State Unknown). Gauge
  parity holds for the <=1s window trivially (same stamp).
- I4 (no re-walk, no second fetch): the overview lines read `status`
  fields directly; `aggregateStatusSummary` remains the only
  bindings/queues/CoS walker. The forwarding copy reads the existing
  `usStatus` — no second `Status()` call (the rule at
  `builder.go:153-155`).
- I5 (#3837 boundary + #10489 link): no line in this change reads,
  renders, or tests `ZoneIDCollisions`. Its zero-show-ref residual is
  owned by OPEN issue #10489 ("Quarantined zones are absent from
  operator show surfaces", filed as the #3837 show regression with a
  #3837-scope regression-test demand); #10490's config-derived
  `Quarantine:` row is adjacent partial coverage for the #10489 owner
  to reconcile. This lane stays out even if #10489's scope overlaps
  this plan's render sites.
- I6 (determinism + alignment): new lines contain no wall-clock, PID,
  or map-iteration-ordered content; reasons render in builder slice
  order (deterministic per build). The overview's first reason starts
  at the exactly 29-column value position and later reasons use a
  29-space prefix; the forwarding first reason uses `writeRow` and later
  reasons use the 37-space value-column prefix. Neither block emits a
  blank header or trailing whitespace. The pre-existing 28-char
  retry-debt row and every other label row are byte-identical.
- I7 (producer completeness; NEW per F5b): after the fix, every
  policy-rebuilding publish path records `next.Capabilities.PolicyContentRejected`
  before publish: full build (`:424`), scheduler republish, and
  route-overlay republish. Route-only overlay publishes inherit the
  current capabilities and are covered by the overlay record call. The
  deferred-worker-arm path (`manager_worker_arm_5134.go:65-84`) is a
  fourth apply path, but it only clones `m.lastSnapshot` and changes
  `DeferWorkers`; it does not rebuild policy content, so it correctly
  inherits the already-recorded diagnostic without a separate record call.
  The recorded reasons always describe the last snapshot the manager
  ATTEMPTED to publish (even when the publish is rejected — the `:424`
  rationale), never an older build.

## 4-class risk

| Class | Risk | Assessment and guard |
|---|---|---|
| R1 — behavior-change | Show output churn (two surfaces) | LOW. Additive conditional text only; empty-field output is byte-identical on both surfaces (byte-compare absent cells prove it). Intended churn: regenerated golden + overview/forwarding outputs if and only if a box is actually rejected. Forwarding contract rule respected (additive block, no reorder). |
| R2 — data-correctness | Stale or misleading reasons | LOW after the F5b fix. The record mirror tracks the latest attempted snapshot-build, matching full-build record-before-publish semantics; renders read the same stamp as the gauge. Residuals: <=1s crash re-stamp window (I3 — gauge parity suffices) and multi-reason block readability (delta-judged). Pre-fix, R2 would be MAJOR (faithfully displayed stale reasons) — the producer fix is load-bearing, not optional. |
| R3 — scope-creep | `ZoneIDCollisions` bleed | LOW. I5 makes the exclusion structural and points at OPEN #10489; a collisions line would be a visible, reviewable addition. Reviewer pressure to fold it in is answered by #10489 ownership. |
| R4 — test-brittleness | Golden/contract over-pinning | LOW. Golden regen is the sanctioned `-update` flow; present/absent substring + byte-compare cells pin behavior without asserting neighboring wording; fwdstatus row tests follow the existing row-test files (`*_row_*_test.go`). No existing test is edited except the deliberate golden-fixture extension. |

## Test plan

Real-shaped fixtures (binding — v1's fake strings are struck). All
fixtures match `policy <scope> names content the userspace matcher
cannot represent: <causes>` (`policies_reject.go:94-95`):

- R1 (multi-cause single-policy): `policy trust->untrust/web names
  content the userspace matcher cannot represent: source-address
  "missing-book"; application "bad-app", "worse-app"` — pins the F1
  collision (intra-reason `"; "`, `", "`, `%q` quotes) surviving the
  one-per-line render.
- R2 (multi-policy, bare-side fallback): `policy global/dns names
  content the userspace matcher cannot represent:
  destination-address` — pins the no-tokens fallback shape
  (`rejectionCause` `:215-218`) and the multi-reason block.
- R3 (operator-hostile quoting, optional hardening): a token containing
  `";"` (e.g. `application "weird;name"`) — pins that no parser splits
  the block on `";"`.

Cells (no edits to existing tests except the deliberate golden-fixture
extension — nothing else re-pinned):

1. Overview present: `ProcessStatus` carrying `[R1, R2]` through
   `FormatStatusSummary` contains the label/value row and each reason
   exactly once on its own line (the first reason shares the label row;
   subsequent reasons use the continuation column); neighboring lines
   (`Enabled:`, `Forwarding supported:`, retry-debt ABSENT without
   debt) intact.
2. Overview absent (byte-compare — binding): the same fixture with nil
   reasons renders byte-identical to the captured pre-change bytes. The
   test subtracts only the two additive rejection lines from the extended
   golden to retain the complete healthy baseline.
3. Golden: the shared fixture includes `[R1, R2]`; the rejected-box golden
   is accepted as a deliberate additive contract change, with correct
   placement and indentation.
4. Forwarding present/absent (new `pkg/fwdstatus` row test following
   the `*_row_*_test.go` files): `ForwardingStatus` with/without
   reasons through `Format` — first reason on the grammatical
   `writeRow` label/value row, subsequent reasons on separate value-
   column lines, and byte-absent when empty; plus a `Build`-level cell
   with a stub adapter serving a stamped `ProcessStatus` asserting the
   `usStatus` copy lands on the struct (zero-interface-change proof:
   stub implements only the two `DataPlaneAccessor` methods + `Status()`).
5. Stamping (same-package `pkg/dataplane/userspace` test — genuinely
   new coverage: no existing test asserts stamp→status for reasons):
   seed `m.lastSnapshotRejectReasons`, call
   `recordHelperStatusLocked(&status)`, assert an independent reasons
   slice on the stamped status.
6. Incremental-path pinning (F5b proof) has TWO required subcells:
   (a) drive `UpdatePolicyScheduleState` with a
   representability-flipping transition (existing scripted-helper seams,
   e.g. `manager_republish_3780_test.go` /
   `manager_overlay_scheduler_5328_test.go` fixtures) and assert
   `m.lastSnapshotRejectReasons` reflects the republished caps; (b)
   drive `PublishRouteOverlaySnapshot` through its existing
   `manager_overlay_scheduler_5328_test.go` seam (or add a focused
   same-package fixture beside it) with the same transition and assert
   the same stamp. Removing either mirrored record call makes its
   corresponding subcell RED; implementation may not downgrade this to
   scheduler-only coverage.
7. RED-on-revert (issue acceptance): a rejected snapshot names its
   reasons on BOTH surfaces. Revert checks: neutralize the overview
   block → cells 1 and 3 fail, 2 passes; neutralize the forwarding
   copy/render → cell 4 fails; neutralize the scheduler record call →
   cell 6a fails; neutralize the overlay record call → cell 6b fails.
   All cells unit-speed; no cluster/incus.
8. Scope proof: the implementation commit lists the five production files
   touched (`status_sections.go`, `fwdstatus.go`, `builder.go`,
   `manager_compile.go`, `manager_overlay.go`), the new/extended tests,
   and the golden; full affected package suites are green, and RED-on-
   revert tripwires fail when each required render/copy/producer call is
   neutralized. `gofmt` is clean.

## Out-of-scope

- `ZoneIDCollisions` render, recorder, gauge, or alarm: owned by OPEN
  #10489 (see I5/Q1). Even where render sites coincide, this lane does
  not add the collisions line.
- REST field/endpoint and any structured twin: no status surface
  exists to extend; text-only accepted as a recorded decision.
- New CLI verbs, new RPCs, or new metrics: gauge and one-shot log
  implementations are unchanged; F5b reuses their existing
  transition-only recording behavior at two additional producer paths.
- Retry-debt row realignment (28→29 cols): pre-existing off-by-one,
  explicitly left alone.
- Recording-semantics changes beyond the F5b mirror: transition-only
  alarming, recovery clearing, and fail-closed retention stay as
  shipped (`lenient_keep_armed_3261_test.go`).
- Whether the one-shot warning reaches an operator-visible log by
  default: explicitly unverified in the issue; not investigated here.
- #9584 `DuplicateRuleId` corrective scope and #3727 match-verdict
  surfaces: distinct diagnostics, cited as precedent only.

## Delta-review decisions (recorded)

1. **[BOUNDARY]** RETAINED: #10489 (OPEN) is the required #3837
   show-half follow-up, so this lane files no duplicate. #10490's
   config-derived `Quarantine:` row is adjacent partial coverage, not a
   runtime `ProcessStatus.ZoneIDCollisions` render; the #10489 exclusion
   remains binding even if its future render touches these blocks.
2. **[FWDSHAPE]** ACCEPTED: the first reason uses the grammatical
   `writeRow` label/value row; each remaining reason uses its own
   37-space value-column line. There is no blank header or trailing
   whitespace.
3. **[OVERLAY-PLACEMENT]** ACCEPTED: the overlay record runs BEFORE the
   duplicate-skip check, converging staleness even when the publish is
   skipped as unchanged. This is the chosen F5b behavior.
4. **[GOLDEN-PERMANENCE]** ACCEPTED: the shared golden permanently
   depicts the rejected box, while the absent-byte cell proves the
   healthy output remains unchanged.
5. **[TEST-SEAM]** ACCEPTED: the focused same-package fixture in
   `reject_show_10500_test.go` independently drives scheduler and
   route-overlay republish paths; removing either recorder call makes
   its corresponding cell RED. The byte-compare absent cell is binding.

Other recorded decisions: text-only ACCEPTED (automation keeps the
gauge; no structured twin); Q7 NO KILL (blindness is real, the fix is
small, and gauge+log are not on-demand surfaces); v1-Q3 dual-surface
DECIDED (overview + forwarding, true costs); v1-Q4 REWRITTEN to true
mechanics (I3).
