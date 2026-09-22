# DRAFT v1 — Issue #10507: standby FabricRedirect revalidation stamps recorded-egress Permit surviving promotion (fail-open)

Status: DRAFT v1 for parent-lane plan review. No production code on this path.
Worktree: `.claude/worktrees/10507-fabricredirect`, branch `fix/10507-fabricredirect`, base `5049e78c9`.
Issue: https://github.com/psaab/xpf/issues/10507 (OPEN, no comments at STEP-0 time).

## 1. Problem

On a standby node, a peer-owned session hit is judged by M2 zone-policy
revalidation against the PEER-RECORDED egress zone instead of the live
to-zone. A Permit stamps `policy_revalidated_gen` at the LIVE config
generation. Promotion rewrites decision/metadata/liveness but no
revalidation field, so the stamp survives and the promoted node forwards
a flow the live policy denies until the next generation-bumping publish
or session end. Fail-open, High severity.

## 2. STEP-0 evidence (verified at HEAD `5049e78c9`, not just the `b71c52d6` pin)

Pin `b71c52d6` is an ancestor of HEAD. No merged PR references #10507
(`git log --all --grep=10507` empty; merged-PR search for
FabricRedirect/recorded-egress/revalidation shows only unrelated work).
Full chain re-verified from source at HEAD:

1. Hit path order, `userspace-dp/src/afxdp/session_glue/mod.rs`
   `resolve_flow_session_decision_with_conntrack`: live FIB re-resolution
   incl. #326 synced-with-local-egress (L2403-2431) → `enforce_session_ha_resolution`
   (L2442-2449, peer-owned on standby becomes `HAInactive`) →
   `redirect_session_via_fabric_if_needed` (L2450-2455, becomes
   `FabricRedirect`) → returned as `resolved.decision`.
2. Redirect REPLACES the resolution: `fabric.rs`
   `resolve_fabric_redirect_from_list` (L500-525) builds a fresh
   resolution with `egress_ifindex = fabric.parent_ifindex`. The #326
   real local egress is unreachable at M2; the issue text's "meaningful
   live_to_id" exists only pre-redirect.
3. M2 override, `poll_descriptor/policy_revalidation.rs:738-740` keys on
   `disposition == FabricRedirect` alone and wins at L754, substituting
   recorded `metadata.egress_zone` for the live to-zone.
4. Permit stamps the LIVE gen at two sites: forward arm L432-433 and
   reverse arm L662-663, via `SessionTable::mark_policy_revalidated`
   (`session/mod.rs:1838-1846`, writes `self.policy_revalidation_gen`).
5. Promotion preserves the stamp: `refresh_for_ha_transition`
   (`session/mod.rs:2936-3006`) rewrites decision/metadata/last_seen/
   `first_held_ns`/`seen_rg_epoch` and touches NO revalidation field.
   `update_session` (`mod.rs:2622-2873`, the unified refresh/promote
   funnel) likewise never writes `policy_revalidated_gen` (grep-confirmed:
   only writers are the two `install.rs` init-to-0 sites plus the stamp).
6. M2 receives the post-redirect decision: `poll_descriptor/mod.rs:1246`
   passes `resolved.decision` (no enforce/redirect happens between resolve
   and M2 in the hit arm).

Second promotion path with the same hole (hit-driven): `maybe_promote_synced_session`
(`session_glue/promote.rs:71-162`, requires `ForwardCandidate`) funnels into
`promote_synced_with_origin` → `update_session` (stamp preserved), and the SAME
packet's M2 then sees `Fresh` and skips live re-judgment.

## 3. Blast radius (measured)

- `FabricRedirect`: 45 files / 158 hits under `userspace-dp/src`.
- M2 judgment: `poll_descriptor/policy_revalidation.rs` (1143 lines) + 4 files
  referencing the policy-revalidation fns (`session/mod.rs`,
  `session/policy_revalidation_8356_tests.rs`,
  `afxdp/tests_policy_revocation_8356.rs`).
- Stamp writers: 2 `install.rs` init sites + 1 stamp fn + 2 M2 call sites.
  Stamp readers: `policy_revalidation_target` only (receiver-local, no wire
  field per `session/README.md` — no `ProtocolVersion` bump for any fix here).
- Transition funnels (production callers): `update_session` ←
  `promote_synced_with_origin` ← `maybe_promote_synced_session` (1 site);
  `refresh_for_ha_transition` ← `refresh_owner_rgs.rs:67` (activation) +
  `demote_owner_rgs.rs:111` (demotion). `refresh_for_ha_activation` has NO
  production callers (tests only).
- Test surface that must stay green / gets new cells:
  `tests_policy_revocation_8356`, `policy_revalidation_8356_tests`,
  `ha_tests`, `tests_fabric_zone_stamp`, `session/tests.rs` (incl. the
  `reference_refresh_for_ha_transition` differential double at L4897, which
  MUST mirror any production change to the refresh per the #9856 precedent).
- Guards that must NOT regress: #7770 punt-seed override (seed entries store
  post-redirect transport egress; judging transport revokes them),
  #9513 no-revoke of the standby population on lookup failure,
  #9604 reverse-companion recorded-from handling.

## 4. Options

### Option A (tentative recommendation): invalidate the policy stamp on HA ownership transition

- A1: in `update_session`'s mutation block, clear
  `record.entry.policy_revalidated_gen = 0` iff `was_peer_synced &&
  !origin.is_peer_synced()` (peer→local transition; `was_peer_synced`
  already computed at L2697). Covers hit-driven promotion through the
  single unified funnel — present AND future callers — while leaving the
  per-packet local→local refresh untouched (clearing there would force a
  cold revalidation per packet: perf catastrophe, explicitly out).
- A2: in `refresh_for_ha_transition`, clear the stamp unconditionally
  (both command callers are genuine HA transitions; the fn preserves origin
  so in-band transition detection is impossible there).
- Effect: any promotion (command-driven RefreshOwnerRGS or hit-driven
  maybe_promote) forces exactly one cold live re-judgment on the next hit;
  Deny revokes without waiting for a publish. All failure directions are
  fail-closed (extra cold evals only).
- Costs/notes: already-owned sessions refreshed on UNRELATED activations
  also re-judge once (bounded, cold, rare — acceptable); demote-side clears
  are harmless (standby re-stamps a recorded Permit); `SessionOrigin: Copy`
  must be confirmed for placement after L2720.

### Option B: judge standby FabricRedirect hits against the live to-zone

Thread the pre-redirect egress (or the stored #326 SyncImport resolution)
to M2 and discriminate #7770 seeds (origin threading into
`PolicyJudgmentInput`, both arms). REJECTED as primary: signature churn
across the hot resolve→M2 path; must not revoke the standby population
(#9513) or the seeds (#7770); risks sync revoke→re-import churn; any
mis-discrimination is fail-open (new recorded-as-live population) or
outage (standby teardown). Larger, riskier, same acceptance.

### Option C: separate recorded-verdict stamp (new entry field)

Robust by construction (recorded judgments can never masquerade), but
touches the hot `SessionEntry` layout plus all readers/publish paths.
Heavier than A with no additional acceptance coverage. Revisit only if
review finds A's site enumeration incomplete.

## 5. Why A needs plan review (do-not-implement-unreviewed)

A is small but its load-bearing claim is SITE COMPLETENESS, and these are
unresolved at STEP-0 (each a residual fail-open if answered badly):

1. `collect_refresh_owner_rgs_items` coverage: is EVERY promotable session
   (all origins incl. `WorkerLocalImport`/`SharedPromote`/replicas)
   refreshed on activation? A promotable-but-uncollected session keeps a
   recorded stamp into local forwarding.
2. Cross-worker materialization: confirm `materialize_shared_session_hit`
   installs at gen 0 (shared entries carry no revalidation field) on every
   worker, and RefreshOwnerRGS fans out per worker.
3. `upsert_synced` refresh-of-existing-entry: confirm stamp preserve is
   standby-harmless (recorded pair may be superseded by re-import).
4. Demote path: `demote_owner_rg` retags local→`SyncImport`, but
   `refresh_for_ha_transition` is SKIPPED when refreshed disposition is
   `HAInactive`/`TableUnavailable` (demote_owner_rgs.rs:107-116) — so
   demote often does NOT clear. Analyzed safe (genuine live-verdict stamp
   on a copy that now only fabric-forwards to the new owner), but review
   must concur.
5. `is_promotable_synced` vs `is_peer_synced` taxonomy: prove no origin can
   hold a recorded stamp AND become locally-forwarding without passing A1
   or A2.
6. Hot-path cost: A1 adds a branch to per-packet `update_session`.
   Negligible in theory (predictable, mostly-folded); still needs the
   repo-standard loss-cluster smoke/iperf gate, which this lane cannot run
   (no cluster commands) — parent validation must cover it.
7. Adjacent residual (OUT of scope, do not fix here): FIB route flap to a
   new egress within one config generation also rides a stale live stamp.
   General #8356 residual, not HA-recorded. Note only.

## 6. Regression tests (for the implementing lane)

- Cell 1 (command-driven, mirrors acceptance verbatim): SyncImport session
  on standby, diverged egress (recorded zone permitted, live zone denied)
  → forward-hit M2 Permits + stamps → run RefreshOwnerRGS activation →
  next hit MUST Revoke with NO generation publish. RED pre-fix (M2 skips,
  forwards).
- Cell 2 (hit-driven): same setup, RG flips active, promoting packet via
  `maybe_promote_synced_session` MUST re-judge live on that same packet
  (Deny/revoke). RED pre-fix.
- Cell 3 (guard): already-owned live-verdict session survives unrelated-RG
  activation with at most one extra cold re-judge and NO verdict change
  (pins A2 over-invalidation as benign).
- Lock-step: update `reference_refresh_for_ha_transition` alongside A2
  (differential-test parity, #9856 precedent — not a test-to-pass edit).
- RED-on-revert firsthand + affected suites green required before PR.

## 7. Verification contract (implementing lane)

- `go`-side untouched; Rust: `cargo test -p userspace-dp` affected suites
  (session, poll_descriptor, session_glue) green; RED-on-revert demonstrated
  per cell; rebase on master; PR body `Closes #10507`.
- Perf: loss-cluster smoke + iperf failover gate for the A1 hot-path branch
  (parent-run; lane has no cluster access).
- No wire/format change; no docs beyond the PR body.

## 8. STEP-0 close-out

- Issue OPEN, body captured, zero comments; live at HEAD (chain above).
- No production code changed on this path. Next: parent-lane review of
  this DRAFT, then a MECHANICAL implement lane only if review closes §5.
