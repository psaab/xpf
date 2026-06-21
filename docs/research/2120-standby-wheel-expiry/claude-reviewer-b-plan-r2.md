# Hostile Claude plan-reviewer B — r2 (on r2.1) — #2120

VERDICT: PLAN-REJECT (substantive r1 findings folded correctly; doc internally
self-contradicting + 2 new mechanism gaps).

Confirmed: MaxDurationSeconds=9223372036 → fixed ceiling unsafe; r2.1 relative
ceiling correctly avoids inversion. Ceiling/self-heal interaction sound for a
SINGLE transition (one-shot epoch). History corrections accurate; lease-race is
a non-issue preserved; control-socket cost of A named; re-bucket-doesn't-restamp
corrected; per-RG-refinement framing honest.

Findings:
1. [BLOCKER] r2.1 code block has NO ownership branch; the demotion-window test
   (expire_in_demotion_window_holds) + prose demand one but a still-ForwardFlow
   entry matches neither standby_hold nor self-heal (both need peer_synced) →
   aged → demotion race (r1 A#4) reopened by the code claiming to close it.
2. [BLOCKER] Epoch-edge self-heal cannot fire for owner_rg_id==0 (rg_epochs only
   valid/bumped for idx>0, ha.rs:74/101, flow_cache.rs:98). A ==0 peer-synced
   entry held via !node_has_active_rg is reaped in the promotion window (no epoch
   for RG 0). Need a node-level activation epoch + a ==0 promotion-window test.
3. [MAJOR] Half-migrated r2/r2.1 doc: §5/§8/§11 still describe option (iii) +
   absolute ceiling; symbol mismatch STALE_SYNCED_CEILING_NS vs _MULT. One design.
4. [MAJOR] Flapping-RG defeats the ceiling: every activate edge re-stamps via
   self-heal → a dead leaked entry on a flapping cluster never reaches the
   ceiling. Need a separate first_held_ns clock (ceiling measured from first
   hold, not last_seen) or cap self-heal re-stamps.
5. [MAJOR] 90-day worst case: MULT=3 × 30-day timeout = 90-day hold; "bounded"
   only formally. Add an absolute cap min(MULT×timeout, e.g. 24h) — safe because
   a held synced session is NOT a live local flow.
6. [MINOR] Integration test only covers the promotion leg of an owner_rg_id>0
   reth flow; add demotion-then-failback + a fabric (==0) flow.
7. [MINOR] SharedPromote (SMR M3) — confirm it is never standby-must-hold.
   (A2 confirms: yes, ages.)
8. [NIT] seen_rg_epoch sizing hand-wavy.
