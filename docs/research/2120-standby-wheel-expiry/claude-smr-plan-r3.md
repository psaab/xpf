# Claude SMR — hostile plan re-review r3 — #2120

Reviewer: Claude SMR (in-conversation, hostile). All claims re-verified against
source in the research worktree (base 325d10683 = origin/master).

VERDICT: PLAN-READY (the design is coherent, every r1/r2 finding is resolved
with a source-grounded mechanism, and the residuals are documented + accepted).
Recommendation: Option B (forwarding-gate HOLD + node-level epoch-edge self-heal
bumped before store + relative/abs-capped/first_held_ns ceiling).

## r2 findings — resolution check (verified)
- **A2#1/B2#3 internal contradiction (option-iii / fixed-ceiling / symbol):**
  RESOLVED — r3 is one design; grep finds no stale option-(iii) default, no
  `STALE_SYNCED_CEILING_NS`, no demotion code/test mismatch (the demotion test
  now asserts the FORWARDING gate, matching the code).
- **A2#2/B2#1 demotion-window / no-ownership-branch:** RESOLVED — HOLD keys on
  `!forwards_here`, a single branch that holds a still-ForwardFlow
  demotion-window entry (when the node still has the synced copy / is a
  multi-RG standby). See residual note below for the single-RG sub-case.
- **B2#2 owner_rg_id==0 promotion epoch:** RESOLVED — node-level `rg_epochs[0]`
  (verified free: all bumps + flow-cache consumer guard `idx>0`, ha.rs:73/100,
  flow_cache.rs:98) drives the `==0` self-heal.
- **A2#3 residual epoch-after-store race:** RESOLVED + feasible — `activated_rgs`
  / `demoted_rgs` are computed at ha.rs:26-27 BEFORE the store at :39, so the
  epoch bumps hoist cleanly before the store (no data dependency forces them
  after). r3 makes this MANDATORY.
- **B2#4 flapping defeats ceiling:** RESOLVED — ceiling measured from
  `first_held_ns` (set on entering HOLD, cleared on real-traffic/promotion
  refresh), NOT `last_seen`, so self-heal re-stamps cannot reset it.
- **B2#5 90-day hold:** RESOLVED — `min(MULT×timeout, ABS_CAP)`; abs-cap only
  reaps NON-forwarding held entries, never a live local flow.
- **A2#4 ==0 active/active:** documented + accepted as a rare residual with a
  named follow-up (resolve RG at import). Acceptable for this issue's scope.
- **SMR M3 SharedPromote:** RESOLVED — SharedPromote set only on the active node
  (promote.rs:99-103) → ages; excluded from the hold; tests assert it.

## Residual findings (NITs, for the implementer / r3-final)
1. [MINOR] **Single-RG-cluster demotion-window AGE is acceptable, but the plan
   should SAY so.** In a single-RG cluster, demoting RG1 makes `node_active`
   false; a still-`ForwardFlow` (pre-DemoteOwnerRGS-flip) entry then has
   `(peer_synced || node_active) == false` → AGED in the ~1-poll window. This is
   NOT a failover hole: the demoting node is becoming standby, the PEER (new
   primary) already holds the synced copy, and after the flip the entry is held
   normally (peer_synced true). Aging this node's redundant copy in the window
   loses nothing the cluster needs. Add one sentence to §4 stating this is
   intentional (it matches A2's "age the demoting node's copy" position for that
   sub-window specifically).
2. [MINOR] **`first_held_ns` lifecycle must be spelled out exactly:** set on the
   first HOLD observation (when 0); cleared (→0) by `update_session`
   (real-traffic refresh, mod.rs:449), `refresh_for_ha_transition` (promotion,
   mod.rs:601), and `upsert_synced` (re-import, install.rs); and NOT cleared by
   the self-heal re-stamp (so flapping cannot reset it). The plan §6.4 lists the
   write sites — make the "self-heal does NOT clear first_held_ns" explicit (it
   is the crux of B2#4).
3. [MINOR] **ABS_CAP floor argument:** 24 h assumes no legitimate failover needs
   a session idle >24 h on the standby. A configured 30-day `inactivity-timeout`
   means the PRIMARY keeps such a session alive 30 days; if that flow then idles
   >24 h on the wire and the standby reaps its copy at 24 h, a failover in the
   24 h–30 day window would drop it. This is a narrow corner (a flow simultaneously
   (a) configured 30-day, (b) idle >24 h, (c) failing over in that window). The
   plan should either raise ABS_CAP to cover the largest realistic
   `inactivity-timeout` deployment, or state the corner explicitly. Cheapest
   safe choice: ABS_CAP = a few × the default established timeout but NOT below a
   plausible long-idle (e.g. 7 days), accepting only truly pathological configs.
   Pin this in r3-final.
4. [NIT] The `rg_active_any` hoist (once per call) is noted; ensure the
   `epoch_of(rg)` helper uses the same `<MAX_RG_EPOCHS` guard as flow_cache.rs:98.

## Bottom line
r3 is coherent and complete; the three MINORs are wording/constant pins, not
mechanism holes. I PASS r3. Convergence depends on the two hostile r3 reviewers
agreeing; the most likely residual they raise is the ABS_CAP floor (NIT-3) —
which is a tunable, not a design flaw.
