# Claude SMR hostile plan-review — #6371 r3

Reviewing `docs/research/6371-rgactive-fence/plan.md` @ r3 (commit 91f192c9f),
base origin/master @ 3ecdc80568a3.

## My own r2 error, corrected by r3 (intellectual honesty)
My SMR-r2 F-r2-2 asserted the decouple was "safe because the poll won't sync a
new value the map doesn't hold." That was **wrong**: the poll
(`refreshHAStateFromMapsLocked` → `mergeHAStateFromMaps`, `Active = rgVal != 0`)
re-derives `haGroups.Active` **from** the map, so a failed map write + successful
live clear lets the next poll re-read `active=1` and the watchdog re-publish
`true` → reactivation/oscillation. Codex r2 caught this as a BLOCKER; I
independently re-verified it firsthand (`manager_ha.go:325-341`). r3 correctly
rejects the decouple and affirms the current ordering. Good.

## Verification of the r3 corrections (firsthand)
- **Current `UpdateRGActive` ordering is correct:** confirmed. The map is the
  daemon's single `Active` authority (`mergeHAStateFromMaps`), so map-first /
  return-on-map-error is the right invariant; sending a live update past a failed
  map write would diverge the two. r3 §4 states this correctly.
- **Conditional ~11 s bound:** confirmed. The watchdog renews the lease only
  while `haGroups.Active=true`, and `haGroups.Active` is map-derived; under the
  issue's precondition (socket down) the watchdog cannot renew → lease expires
  ≤~11 s. The §3.2 qualification ("latched inactive OR socket-down") is the
  honest bound and covers the issue's scenario.
- **Ack-not-a-fence / Option D PLAN-KILL:** confirmed (`election.go:160`,
  `failover.go:127`).
- **Four clear sites:** confirmed — cluster-event (`daemon_ha.go:367`),
  VRRP-BACKUP (`:583`), reconcile (`:846`), peer-fence
  (`fenceAllRedundancyGroups`, `daemon_ha_sync.go:1268`).
- **#5079 relabel** (demoted owner's election-eligibility lease) and **taxonomy
  "cluster-event" not "direct"**: correct.

## Findings on r3

**F-r3-1 (affirm — no unaddressed hard defect).** I probed whether Path C leaves a
genuine defect unfixed. The candidate is the unconditional `signalFailoverActuated`
at 389. Changing it to gate on a confirmed clear is exactly Option D (invalid
fence — peer promotes via `SecondaryHold`/priority-0 regardless) and in RETH mode
the clear has not even happened at 389 (it is the VRRP-BACKUP handler). So leaving
389 unchanged is correct, and Path C's "no HA-path code change" is the right call.
No hard defect is left unaddressed within a proportionate scope.

**F-r3-2 (MINOR — the alarm IS actionable; state the operator action).** §5.1
should name the operator action so the alarm earns its surface: there is **no**
auto-restart of a wedged-but-alive helper (the status poll only logs on a failed
`requestLocked`; `ensureProcessLocked` restarts only on config apply). So a
persistent `rg_active`-clear failure is a signal for the operator to
investigate / restart the helper before the fail-closed lease turns a bounded
window into a longer outage — and it distinguishes a real helper fault from
benign transients the deduped reconcile `Warn` buries. That is the actionable
value; state it.

**F-r3-3 (MINOR — doc-only is a legitimate alternative; the plan already surfaces
it).** Open Question 1 correctly frames "alarm+counter vs doc-only." The alarm is
justified (F-r3-2), but a reasonable reviewer could choose doc-only given the
rarity + bounded/fail-closed nature. The plan is honest to leave this as the
user's call at /engineer time; I would ship the persistence alarm, but flag that
if the user prefers doc-only the research conclusion is unchanged (the fix is
PLAN-KILLed either way).

**F-r3-4 (MINOR — test-plan parent-RED for the "correct ordering" regression).**
§7's first test is the strongest part of Path C: it pins that the current
ordering is correct by making the decouple go RED (oscillation on a stale-active
map). Ensure the parent-RED is an **assertion** failure (assert
`update_ha_state(false)` was NOT sent on a failed map write; assert the poll keeps
`Active=true`), not a build break — per
`feedback_red_on_revert_must_be_assertion_not_build_break`. Keep it in the
userspace-manager package with a recording control socket + `TMPDIR=/tmp`.

## Verdict
r3 is factually solid and every r1/r2 finding from both reviewers (and my own r2
error) is correctly incorporated. The recommendation — PLAN-KILL Option D + Path
A′ + the decouple; affirm the current `UpdateRGActive` ordering as correct; ship a
minimal Option-(c) (doc + persistence/hysteresis alarm); explicit security-risk
acceptance + PLAN-DEFER the single-`Active`-authority redesign — is the honest,
proportionate outcome. This is r3 after two substantive revisions that fixed real
defects (not a first-pass soft-pass). The residual findings are MINOR wording/test
refinements, not blockers.

VERDICT: PLAN-READY
