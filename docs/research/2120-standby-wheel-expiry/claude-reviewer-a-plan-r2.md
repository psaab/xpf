# Hostile Claude plan-reviewer A — r2 (on r2.1) — #2120

VERDICT: PLAN-REJECT (approach correct; 3 doc/mechanism hardenings block clean pass)

Positive confirmations (source-verified): r2.1 epoch-edge self-heal genuinely
resolves the r2 over-retention BLOCKER (rg_epochs is a real u32 atomic array
coordinator/mod.rs:212, bumped activate ha.rs:101 / demote ha.rs:74 w/ Release,
in worker scope loop_body:63, already the flow-cache primitive flow_cache.rs:98;
after one self-heal epochs match → ages, no perpetual re-stamp). Relative ceiling
correctly fixes the fixed-ceiling hazard (timeouts reach MaxDurationSeconds≈9.2e9,
schema_validators.go:132; saturating_mul overflow-safe). SharedPromote correctly
EXCLUDED (set only on the active node, promote.rs:99-103 — should age; resolves
SMR M3). History claims all accurate. Base = 325d10683 = origin/master.

Findings:
1. [BLOCKER] Internal contradiction: stale r2 paragraph (plan §4) still names the
   rejected level-triggered "option (iii)" as the default, contradicting the r2.1
   epoch-edge fix. Verified the lease-derived option (i) is broken (lease slides
   every update_ha_state, ha.rs:9-24) and a level self-heal re-stamps an idle
   promoted SyncImport (origin preserved by refresh_for_ha_transition mod.rs:601)
   forever. Delete the (i)/(ii)/(iii) menu; state epoch-edge as the sole default.
2. [MAJOR] Demotion handling contradictory: prose claims an "ownership branch
   holds before the origin flip" but the r2.1 code requires peer_synced in BOTH
   branches; a still-ForwardFlow demotion-window entry ages. Tests
   expire_ages_local_session_regardless_of_rg vs expire_in_demotion_window_holds
   demand opposite outcomes for the same state. RESOLUTION (recommended): accept
   that a demoting node AGES its formerly-local copy — no failover loss, the
   now-active peer owns the synced copy. Drop the demotion-hold prose + test.
3. [MAJOR] Residual promotion race: epoch bump (ha.rs:101) FOLLOWS rg_runtime.store
   (ha.rs:39); a worker observing active-rg in the store→bump gap with epoch not
   yet bumped removes a held entry. FIX: bump rg_epochs for activated RGs BEFORE
   the store (the correct ordering belt; reordering the command enqueue does not
   help the epoch mechanism). Add a test driving expire with rg active + epoch
   not-yet-bumped, assert survival.
4. [MAJOR] owner_rg_id==0 hold under-retains in active/active: `!node_has_active_rg`
   ages an RG2-standby fabric/reverse ==0 entry on a node where RG1 is active
   (the loss cluster can run active/active). Settle the ==0 predicate before
   implementation; add mixed active/active tests.
5. [MINOR] Pseudo-code indexes rg_epochs[owner_rg_id] without the <MAX_RG_EPOCHS
   (16) guard the canonical consumer uses (flow_cache.rs:98); mirror
   FlowCacheStamp::capture exactly; Relaxed load.
6. [MINOR] seen_rg_epoch must be written coherently at ALL 4 SessionEntry
   write sites (install.rs:143/229, refresh_for_ha_transition mod.rs:601,
   update_session mod.rs:449); the "within padding" size claim is unverified.
7. [MINOR] A#8 lost-Close path: update risk wording to the relative ceiling;
   rename the ceiling test off STALE_SYNCED_CEILING_NS.
8. [NIT] Stale symbol STALE_SYNCED_CEILING_NS at the ceiling test; full path for
   refresh_owner_rgs.rs.
