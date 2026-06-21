# Hostile Claude plan reviewer B — round 3 convergence re-review (against r3)

VERDICT: PLAN-READY

Both r2 findings RESOLVED, verified against the worktree source:

## r2 MAJOR (clear-on-disable) — RESOLVED
- Robust unconditional-on-false form confirmed: the setter clears both
  maps whenever the flag is set false (self-heals a missed edge), not
  just on the ON→OFF edge.
- Setter is genuinely called on every profile apply: startup
  (setup.rs:122/124) and runtime reload (loop_body/mod.rs:306 →
  :318/:320, inside `if let Some(new_forwarding) = load_arc_if_changed`).
  Reads new_forwarding (same source update_profiles consumes). No
  ordering hazard (ScreenState vs SessionTable, different objects).
- Clearing live-session counts while OFF is consistent (per-profile >0
  gate is false when OFF; the no-back-count residual is §6.9, benign).
- Subset-of-zones-drop-limit is the existing global-per-IP scoping
  (§6.4), not a new bug.

## r2 MINOR (§3.5 audit) — RESOLVED
- refresh_for_ha_transition (mod.rs:546): verified NEVER assigns origin;
  CAN reindex on is_reverse (so structural-immutability would be FALSE)
  — the plan correctly rests on the caller-level invariant + the
  !is_reverse count gate. Both callers (refresh_owner_rgs.rs:74,
  demote_owner_rgs.rs:71) pass metadata.clone() of the existing entry,
  preserving direction. Verified.
- demote_shared_owner_rgs flips (shared_ops.rs:137/154/162): on
  SyncedSessionEntry in the cross-worker SHARED maps, not the per-worker
  SessionTable — never touch the counter. Correctly classified.

## Impl NITs (§3.5b) — accurate (increment-vs-delta-move, demote borrow
ordering, relocated-event ScreenPacketInfo, zone-name profile key).

## New-hole hunt — none.
- Miss-path :746+ dominates both counted installs (LocalMiss :907,
  ForwardFlow :1379), not TCP-gated. ReverseFlow/seed excluded.
- is_peer_synced / is_transient_local_seed match the plan exactly.
- clear-on-disable + new-flow check + HA transitions mutually consistent
  across OFF→ON→OFF.
- §5.10 catches a missing clear two ways.

Both my findings folded with the correct mechanism; all citations check
out; no new defect. Ready.
