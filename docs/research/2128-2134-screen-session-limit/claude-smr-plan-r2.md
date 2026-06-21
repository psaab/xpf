# Claude SMR — hostile plan review, round 2 (against r2; verdict on r3 fix)

VERDICT on r2: NEEDS-REVISION (concur with reviewer B's new MAJOR).
VERDICT on r3 (clear-on-disable folded): PLAN-READY.

I independently confirmed reviewer B's clear-on-disable MAJOR is real and
not a false alarm, and verified the r3 fix is correct and complete:

## On the MAJOR (reviewer B)
The OFF-gate is necessary for cost (reviewer B's own r1 finding), but it
creates an asymmetry the r2 plan missed: when active=false, increments
AND decrements are both skipped. Increments-skipped is fine (no new
counted sessions enter the map while OFF). But decrements-skipped is the
bug: any session that was counted while ON and then expires/closes while
OFF leaves its +1 in the map forever. The map is frozen, not drained.
Re-enabling then reads a count that includes long-dead sessions → an IP
with 0 live sessions could read count==n==limit → next SYN blocked. This
is a real, routine-config-reachable correctness defect in a security
feature. Reviewer B is correct to gate PLAN-READY on it.

Confirmed the r3 fix (clear-on-disable in the setter, §3.1):
- Clearing on the false transition is the right discipline and matches
  the precedent (`ScreenState::update_profiles` `.retain` at
  screen/mod.rs:118-139, which already drops trackers for zones losing
  profiles). Verified that precedent exists.
- The hook is correct: the setter is called at both the startup
  (setup.rs:122-124) and reload (loop_body:318-320) profile-apply sites,
  so the flag (and the clear) fire on every forwarding change — verified
  those are the only two profile-apply sites.
- The OFF→ON re-enable "no back-count" residual (§6.9) is benign and
  Junos-approximate — Junos does not retroactively count pre-existing
  flows when a screen option is enabled. Acceptable.

## SMR additional checks (no new findings)
- The clear-on-disable does NOT interact badly with the per-worker model:
  each worker's setter fires independently on its own snapshot apply;
  there is no shared map to race.
- An alternative (clear unconditionally when !active, every snapshot
  apply) is slightly more robust than "only on the ON→OFF edge" because
  it self-heals if a worker somehow missed the edge; the plan's
  "set false → clear" achieves this since the setter is called every
  apply and clears whenever the computed flag is false. Confirmed the
  plan's wording ("clear whenever the flag is set false") is the
  unconditional form — good.
- §3.5 audit completeness (reviewer B MINOR): r3 names
  refresh_for_ha_transition + the shared-map flips explicitly. The
  refined is_reverse-invariant statement (caller-level, not structural)
  is more accurate than r2's — refresh_for_ha_transition CAN reindex on
  an is_reverse change (mod.rs:37-43), so the structural claim was
  technically wrong; the caller-level claim + the !is_reverse count gate
  is correct.

## Verdict
r3 is PLAN-READY. The architecture (Path B), the check-at-new-flow
relocation, the two enumerated HA transitions, the OFF-gate WITH
clear-on-disable, the non-mutating read (#2128), and the exhaustive
in-place-mutation audit are all sound and source-verified. The remaining
items are documentation NITs folded into §3.5b/§6.9, none requiring a
further round.
