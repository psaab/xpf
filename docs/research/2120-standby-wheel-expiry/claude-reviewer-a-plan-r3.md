# Hostile Claude plan-reviewer A — r3 — #2120

VERDICT: PLAN-READY-WITH-NITS

All four r2 BLOCKERs and eight r2 MAJORs source-verified as RESOLVED by the
single r3 design. The two issues flagged as most-likely-real both verify CLEAN:
- Single-RG demotion-window AGE (check #2): NOT a hole — apply_worker_commands
  (loop_body:500) precedes expire (:573) so DemoteOwnerRGS flips origin +
  re-stamps before expire; the only window needs the entry simultaneously
  idle-expired, but a just-demoted entry has recent last_seen; and the peer (new
  primary) holds the synced copy. Matches A2#2 resolution + plan §4 single-RG note.
- Epoch-bump-before-store reorder (check #3): FEASIBLE — demoted_rgs/activated_rgs
  computed (ha.rs:26-27) from `previous` + locally-built `state`, both before the
  store (:39); bumps depend only on those, not the stored ArcSwap. Handlers that
  read the stored value run after the store regardless.
- rg_epochs[0] node-level epoch (check #4): CORRECT — index 0 genuinely unused
  (all bumps + flow_cache consumers guard idx>0/owner>0); bumping it cannot break
  the flow cache.
- Ceiling from first_held_ns (check #5): flapping-safe + abs-capped + NOT cleared
  on self-heal (§4.4 explicit). B2#4/B2#5 resolved.
- ==0 active/active residual (check #6): acceptable as documented (mirrors the
  existing synced_entry_allows_local_replace ==0 convention; prewarm-recovered).

NITs (non-blocking):
1. ABS-cap magnitude inconsistent (§4.4/§11 say ~7 days; §6.5/§8 said ~24 h) —
   24 h is unsafe vs a 30-day-timeout long-idle flow per the doc's own argument.
   Pick the ≥-real-failover-window value (~7 days). [FOLDED]
2. MAX_RG_EPOCHS is pub(super) in afxdp::flow_cache; the new expire site in
   crate::session must derive the bound from rg_epochs.len(), not cross-module
   const. [FOLDED as impl note]
3. ha_runtime is an ArcSwap Guard; match the working loop_body:508 `as_ref()`
   convention. [FOLDED as impl note]

Approach (Option B + non-optional ceiling) correct; recommendation honest
(acknowledges A's lost-delete edge); mandatory idle-window failover gate correctly
identified. PLAN-READY pending the NIT folds (applied).
