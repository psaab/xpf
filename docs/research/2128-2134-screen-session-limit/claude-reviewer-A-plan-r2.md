# Hostile Claude plan reviewer A — round 2 (against plan r2)

VERDICT: PLAN-READY-WITH-NITS

All four r1 findings verified FIXED against the worktree HEAD; could not
break the relocated mechanism.

1. [r1 BLOCKER per-packet self-drop] FIXED, confirmed. stage_screen_check
   (poll_descriptor:199) + flow-cache (Consumed=>continue) + session
   lookup (:298) all precede the miss-branch check site (:746+).
   Established-flow packets never reach it. Old per-packet check confirmed
   OUTSIDE the is_syn gate (screen/mod.rs:343-358 vs gate close at :330).
2. [SMR-1 LocalMiss dominance] REFUTED as a hole — both counted installs
   (LocalMiss :907 in `if LocalDelivery`, ForwardFlow :1375 in
   `else if ForwardCandidate`) are mutually exclusive and both downstream
   of :746 zone resolution; a check after :746 dominates both. LocalMiss
   increments via install_helper_local_session_on_miss
   (forwarding/mod.rs:1112) — symmetric with the check.
3. [r1 MAJOR promote/demote] CONFIRMED. mod.rs:472 promote branch
   (SharedPromote not peer-synced; no double-count — second pass has
   was_peer_synced=false). demote install.rs:305 flip; the !is_reverse
   gate is load-bearing because owner_rg_session_keys returns both
   forward+reverse keys.
4. [r1 MAJOR §3.5 audit] CONFIRMED exhaustive: only in-place origin
   writes are mod.rs:446-447 (promote), mod.rs:599
   (refresh_for_ha_transition — never assigns origin), install.rs:305
   (demote). refresh_local/refresh_for_ha_activation have zero prod
   callers.
5. [is_reverse invariant] CONFIRMED — no prod path flips is_reverse for a
   key; the !is_reverse count gate is additional protection.
6. [#2128] FIXED by construction (non-mutating get; reject path allocates
   nothing).
7. [telemetry] re-emit path correct; screen_drops in scope at miss site.

NITs (fold at /engineer, no re-review needed):
- N1: relocated event needs a ScreenPacketInfo rebuilt via
  extract_screen_info at the new site.
- N2: OFF-gate true-transition starts counts empty (no back-fill);
  true→false leaves stale counts unless cleared — document.
- N3: screen_profiles keyed by zone NAME not id.
- N4: promotions intentionally not new-flow-checked (Junos-equivalent) —
  keep explicit in operator doc.

Line citations all accurate against worktree HEAD.
