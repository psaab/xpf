# Hostile Claude plan-reviewer A — r1 — #2120

VERDICT: PLAN-REJECT

Source-verified the full root-cause chain (SkipSweep, dead IsLocalPrimary,
unconditional wheel removal, tcp_flags:0→300s, #270 narrowing). Findings:

1. [BLOCKER] Promotion re-stamp is RACY and the plan's stated mitigation is
   factually wrong: `rg_runtime.store(active)` (ha.rs:39) precedes the
   `RefreshOwnerRGS` enqueue (ha.rs:80-117); a worker can observe active-RG
   (loop_body:491) before draining the refresh command (loop_body:497) and run
   its 1s-gated expire (loop_body:573) → removes the held-but-stale session.
   `expire_stale_entries` NEVER re-stamps last_seen (only refresh_for_ha_transition
   mod.rs:601/605 does), so re-bucket does NOT protect it. The proposed
   promotion_restamps_held_session test calls handle_refresh_owner_rgs in-process
   and does NOT exercise the race.
2. [MAJOR] `owner_rg_id>0` gate is narrower than the retention need:
   handle_refresh_owner_rgs scopes on `owner_rg_id>0 || fabric_ingress`
   (refresh_owner_rgs.rs:34); peer-synced entries with owner_rg_id==0
   (fabric_ingress / reverse-no-owner) would age on the standby — the very bug.
3. [MAJOR] "Faithful restoration of IsLocalPrimary" is false: old gate is
   node-global (gc.go:249/277, IsLocalPrimaryAny), Option B is per-RG +
   per-session + owner_rg_id>0-gated. State it as a per-RG refinement.
4. [MAJOR] Symmetric demotion race: ha.rs:39 store(inactive) precedes
   DemoteOwnerRGS enqueue (ha.rs:51); demote_owner_rg flips ForwardFlow→SyncImport
   (install.rs:304-306); in the window a still-ForwardFlow inactive-RG session
   could be aged. Unanalyzed in r1.
5. [MINOR] #270 (391ea5a14) change was in sync.go:759/774, not sync_conn.go
   (later refactor 0dc166c7b moved it). Anachronistic citation.
6. [MINOR] #270 did NOT reinstate the empty-sweep fast-path (grep on the diff=0).
7. [MINOR] Close-delta suppression is a 3-way AND (!is_reverse &&
   !is_peer_synced && !is_transient_local_seed); is_peer_synced covers 3 origins
   (SyncImport|SharedMaterialize|WorkerLocalImport) — tests only cover SyncImport.
8. [MINOR] Primary delete can be filtered by shouldSyncUserspaceDelta
   (daemon_ha_userspace.go:381-386) → standby leaks under B.
9. [NIT] Standalone safety (owner_rg_id==0) verified OK.
10. [NIT] Test plan misses the race repro + the per-call last_pop_stats reset
    (expire.rs:95) interaction.
