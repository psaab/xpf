# Claude SMR hostile plan-review — #6371 r4

Reviewing `docs/research/6371-rgactive-fence/plan.md` @ r4 (commit 371a74305),
base origin/master @ 3ecdc80568a3.

## The re-scope is correct (and I missed the BLOCKER at r3 — noted)
Codex r3's stale-active-restart BLOCKER is real and I verified it firsthand:
`rg_active` is pinned (`loader_userspace_shim.go:602`), cluster startup re-arms
the helper `active=true` from it (`manager_compile.go:372-378`), the fresh
`rgStateMachine` is `applied=false` (`rg_state.go:75`), and the reconcile acts
only on `Changed||NeedsApply` (`daemon_ha.go:806`) → no corrective clear → the
watchdog re-publishes `active=true` indefinitely. My r3 PLAN-READY was wrong to
conclude "no HA-path defect." r4 correctly re-scopes to this. The core fix (Path D
item 1, seed `applied`-from-map so `NeedsApply` fires the corrective clear) is
mechanically sound: I confirmed `NeedsApply = applyPending = (active != applied)`
(`rg_state.go:204,261`), so seeding `applied=true` with `desired/active=false`
yields `NeedsApply=true` → `SetRGActive(false)` → map cleared. Good.

## Findings on r4

**F-r4-1 (MUST FIX — "hitless for a still-owner" is overstated).** §5.1 claims a
genuine still-owner "stays applied (hitless)." Firsthand: a non-preempt boot stays
`StateSecondary` until it hears from / times out the peer (`election.go:113-120`),
so at the immediate startup reconcile `desired=false` for a former owner **even if
it will legitimately re-win** — so the seed-applied fix **DOES** fire
`SetRGActive(false)` on boot and re-activates only after election. That is the
**correct fail-closed posture** (a restarting node must not resume forwarding from
a stale pin before confirming ownership), but it is **not hitless** — there is a
bounded gap = boot-to-election/heartbeat-timeout. Re-state §5.1 as "fail-closed on
boot, re-activate on legitimate election — a bounded gap, the correct safe
posture; true hitless restart is ISSU-scope, out of plan." Also note the
interaction with the existing hitless-restart machinery (`vrrpPostureDelayStartup`,
`rg_state.go`): confirm the seed clear does not fight the 30 s posture delay.

**F-r4-2 (MUST FIX — the unresolved-clear debt must be DAEMON-level, and item 2's
restart coverage depends on item 1).** §6 places `unresolvedClearSince` ambiguously.
It CANNOT live on `rgStateMachine`: the peer-fence (`fenceAllRedundancyGroups`,
`daemon_ha_sync.go:1267`) bypasses `rgStateMachine` entirely (Codex r3), so a
failed peer-fence clear would never register debt tracked there. State explicitly
that the debt is a **daemon-level per-RG structure** written by ALL five clear
sites. Separately: the restart case only produces a clear-request (hence debt)
**because** item 1 makes the reconcile issue one — so item 2's restart coverage is
**conditional on item 1**; without item 1 a stale-active restart issues no clear
and the alarm sees nothing (exactly Codex's r3 point). Make that dependency
explicit so /engineer does not ship item 2 alone.

**F-r4-3 (SHOULD — confirm the reconcile backs up a failed peer-fence).** The plan
relies on the reconcile as the safety net for the rgStateMachine-bypassing
peer-fence. That holds only if the peer-fence is accompanied by a cluster-state
change that drives `rgStateMachine` `desired=false` (so `NeedsApply` retries the
clear). Verify a peer-fence without a corresponding cluster event (if reachable)
still gets reconciled — else the peer-fence failed-clear is both undetected AND
uncorrected. If it cannot be reconciled, the debt/alarm is the only backstop and
must be load-bearing.

**F-r4-4 (MINOR — deferral disclosure is good; tighten the residual list).** §5.4's
explicit unbounded-mode disclosure + tracked follow-up is the right answer to
Codex r3. Tighten: after Path D, the residual **indefinite** modes are (a)
persistent map-write failure with live reads (reconcile keeps erroring, map never
reaches 0 — DETECTED by the alarm, not fixed) and (b) genuinely-stuck VRRP
ownership (arguably correct, not dual-active unless split-brain — a VRRP/heartbeat
domain, not this defect). Say (a) is alarmed-not-fixed and (b) is out-of-domain,
so the "tracked follow-up" is scoped to the authority redesign for (a), not a
vague catch-all.

**F-r4-5 (MINOR — test the boot re-arm-then-clear window).** §7's core regression
is right. Add an assertion that a legitimate still-owner (peer down → re-elects)
ends up `active` after election (no permanent fail-close), and that the
intermediate clear→re-activate window is bounded — so the fix is proven safe for
the owner case, not only the stale case.

## Verdict
r4 is factually solid on the now-correct core defect (stale-active restart) and
its fix (seed `applied`-from-map → reconcile self-corrects). Path D is the honest,
proportionate scope: fix the reachable unbounded restart path, alarm the residual,
correct the record, defer the authority redesign with disclosure + a tracked
issue. The findings are precision fixes (the "hitless" overstatement F-r4-1 and the
daemon-level-debt/item-dependency F-r4-2 are material for correctness and
implementability), not architectural blockers.

VERDICT: PLAN-NEEDS-REVISION
