# Claude SMR — hostile plan re-review r2 (on plan r2.1) — #2120

Reviewer: Claude SMR (in-conversation, hostile). All claims re-verified against
source in the research worktree.

VERDICT: PLAN-READY-WITH-NITS — r2.1 resolves every r1 BLOCKER/MAJOR with a
source-grounded mechanism; the residual items are bounded design choices for r3,
not correctness holes. Recommendation (Option B + relative ceiling) stands.

## r1 findings — resolution check (all verified resolved in r2/r2.1)
- **M1 / A#1 / B#2 promotion-race + false "re-bucket re-stamps":** RESOLVED.
  The false claim is removed; expire never re-stamps (mod.rs:601 is the only
  re-stamp). The self-heal is now EDGE-triggered via `rg_epochs`
  (Arc<[AtomicU32;16]>, bumped on activate ha.rs:101 AND demote ha.rs:74,
  already in worker scope loop_body:63, already the flow-cache invalidation
  primitive flow_cache.rs:98). A `seen_rg_epoch` on SessionEntry makes it
  one-shot → no over-retention. This also closes the SYMMETRIC demotion race
  (A#4) by the same epoch edge.
- **A#2 gate-too-narrow (owner_rg_id==0 fabric/reverse):** RESOLVED — hybrid
  origin+ownership gate with an explicit `owner_rg_id==0` branch (hold on a
  whole-node standby).
- **A#3 not-faithful-restoration:** RESOLVED — plan now states it is a per-RG
  refinement, not a node-global restoration.
- **B#1 lost-delete leak / false "reconnect reconciles":** RESOLVED — verified
  warm reconnect is coldStart-only (sync_conn.go:197-209) and the journal is
  bounded+lossy (:541-543); ceiling is now NON-optional AND relative.
- **A#5/A#6/B#3 history:** RESOLVED — #270 was sync.go (relocated by 0dc166c7b);
  fast-path is 62e3a9026.
- **A#7 origin coverage / A#8 delete-filter / B#4 lease-non-issue / stats-reset:**
  RESOLVED in the test plan + risk table.

## Residual findings (NITs for r3)
1. [MINOR] `seen_rg_epoch` field add to `SessionEntry` — confirm it fits the
   slab record budget (the struct is hot; the plan should state the byte
   impact and whether it packs into existing padding). Low risk; mechanical.
2. [MINOR] `owner_rg_id==0` HOLD branch (`!node_has_active_rg`) iterates
   `ha_state.values()` per held entry in the expired arm. For a large held set
   this is O(held × RGs). RGs ≤ 16 so it is bounded, but prefer hoisting
   `node_has_active_rg` once per `expire_stale_entries` call.
3. [MINOR] Ceiling MULT and the reaper's delete-sync: when the ceiling reaps a
   held peer-synced entry on the standby, it must NOT emit a Close delta back to
   the primary (the primary still owns it) — the existing expire.rs:155-157
   `!is_peer_synced()` suppression already covers this, but the plan should
   state that the reaper path keeps that suppression.
4. [NIT] The self-heal re-stamps `last_seen = now` which RESETS the failover
   flow's idle clock on the new primary. That is correct (the flow is now
   locally owned and active) but worth a one-line note that post-promotion the
   timeout restarts from promotion, matching refresh_for_ha_transition (mod.rs:601).

## Bottom line
r2.1 is architecturally sound and every load-bearing claim is source-verified.
The recommended path (Option B hybrid gate + edge self-heal + relative ceiling +
mandatory counters + idle-window failover test) is correct and bounded. I would
PASS at r3 once the two hostile reviewers confirm the r2.1 mechanisms and the
residual NITs are folded.
