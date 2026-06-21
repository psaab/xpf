# Hostile Claude plan reviewer A — round 1 (against plan r1)

VERDICT: NEEDS-REVISION

Confirmed correct: #2134 no-op (session_created/expired have zero
production callers), #2128 leak (entry().or_insert), remove_entry is the
sole slab-delete sink, NAT keys on pre-NAT tuple, RG-vacate is
redirect-only.

Findings:

1. [BLOCKER] The session-limit check runs PER-PACKET with no new-flow
   gate (screen/mod.rs:343-358 is OUTSIDE the is_syn gate at :319-320;
   stage_screen_check runs before the session lookup). Wiring the counter
   would make an established flow re-check `count >= limit` on every data
   packet and self-drop at the boundary — configuring limit-session N
   would tear down all N established flows the moment the Nth establishes.
   Junos checks only at session creation. Required: gate to
   session-creating packets only. The r1 test plan would not catch this
   (only tests distinct new-flow tuples).

2. [MAJOR] "Single choke point" thesis false: promote (update_session
   in-place branch) creates a counted session without
   install_with_protocol_with_origin; demote (demote_owner_rg) un-counts
   in place without remove_entry. Both are live production paths. r1
   leaves §6.3 as an open question. Required: concrete increment at the
   promote branch + decrement at demote, plus a differential test.

3. [MAJOR] Systematic stale file/line references — the #2005 split moved
   the cited functions out of session/mod.rs into install.rs/lookup.rs/
   expire.rs; r1's mod.rs line numbers are wrong for the actual base.
   Required: re-cite against the worktree HEAD.

4. [MAJOR] is_reverse flip across in-place refresh (update_session /
   refresh_for_ha_transition overwrite metadata wholesale) is an
   unaudited potential leak-up. Required: prove is_reverse is invariant
   across refresh, or hook is_reverse changes too.

5. [MINOR] upsert_synced pre-clear decrement unanalyzed.
6. [MINOR] Borrow feasibility correct but mis-cited.
7. [MINOR] Smoke observability: aggregate screen_drops can't distinguish
   session-limit drops; pin to the per-reason event stream.
8. [NIT] LocalMiss / SharedPromote counting correct-by-predicate but
   undocumented.

Net: diagnosis right, Path B right architecture, but Finding 1 is a
functional showstopper the plan and its tests both miss; Finding 2
undercuts the central claim; Finding 3 will misdirect implementation.
