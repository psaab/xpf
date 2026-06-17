# Claude SMR — HOSTILE plan review r4 — #1918

Reviewer: Claude SMR. Re-review of the r4 Axis-D rewrite + the folded Codex r2 NF1-NF4 and
Codex r3 LinkSet-error blocker. Hunt for any new defect introduced by the commit-after-success
restructure and the generation-token guard.

## Verdict: PLAN-READY

r4 resolves every outstanding finding from all three reviewers. The Axis-D rewrite is the right
shape and I could not construct a counterexample that breaks the commit-after-success invariant.

## Disposition of the r3→r4 findings

- **Codex NF1 / AGY #5 (source bind) — RESOLVED (r3 §5c).** Two independent reviewers converged;
  high confidence. API-correct (`icmp.ListenPacket(network, source)` → `syscall.Bind`).
- **Codex NF2 (optimistic-Up window) — RESOLVED.** r4 never writes `Up` before the netlink op.
  Steps 1 (classify + commit `Failures`, compute intent, no `Up` write) and 6 (commit `Up` only
  on netlink success) bracket the unlocked netlink call. A racing `Apply`/`GetStatus` between
  them reads the *pre-transition* `Up` — correct, not optimistic. Verified against the actual
  reader sites: `GetStatus` reads `ks.Up` under `ks.mu` (`tunnel.go:1158-1167`) and `Apply`'s
  `skipUp` reads `runner.state.Up` under the runner lock (`tunnel.go:531-538`). Both see the
  old value until step 6 commits.
- **Codex NF3 (ifindex-reuse bypass) — RESOLVED.** The action-time `LinkByName().Index` was the
  defect; r4 uses a per-tunnel monotonic `linkGen` captured at `startKeepalive` and bumped by
  `Apply` on (re)create. A stale runner's captured gen ≠ current gen → it drops the action. This
  is immune to ifindex reuse. (Implementation note for /engineer: the gen bump and the
  `startKeepalive` capture must both happen under `t.mu` in the same `Apply` critical section that
  recreates the link, so the new runner always captures ≥ the bumped value — the plan says
  "bumped under `t.mu` ... captures the current `linkGen`", which is consistent since
  `startKeepalive` is already called with `t.mu` held per its doc comment `tunnel.go:944-945`.)
- **Codex r3 LinkSet-error blocker — RESOLVED.** r4 step 6 commits `Up` only when `LinkSet*`
  returns nil; on error it logs and leaves `Up` unchanged, so the step-1 guard re-fires next
  tick. Codex's exact counterexample (dead → `Up=false` → `LinkSetDown` error → never retried)
  cannot occur because `Up` is not set to false until `LinkSetDown` succeeds. Test added.
- **Codex NF4 (errno table) — RESOLVED.** Complete structural/transient table + the crucial
  total default **UNRECOGNIZED → TRANSIENT (escalate)**, which makes the classification total and
  fail-loud — a resource errno can never be silently mis-held as structural.

## New-defect hunt over r4

- **Failures-committed-before-netlink (step 1) is correct, not a bug.** I checked whether
  committing `Failures` in step 1 while gating `Up` on netlink success could double-count or
  desync. It cannot: `Failures` is a monotone counter that only resets on the alive branch; the
  down transition guard is `Up && Failures>=MaxRetries`. If `LinkSetDown` keeps erroring, each
  dead tick increments `Failures` further (already ≥ MaxRetries) and re-attempts the down — the
  desired "keep trying to bring it down" behavior, with status showing the climbing count. No
  double down occurs because the *first* successful `LinkSetDown` commits `Up=false`, after which
  the guard `Up==true` is false and no further down fires. Exactly-one-successful-LinkSet holds.
- **Generation-token capture ordering — flagged as an /engineer implementation note, not a plan
  defect.** As long as the bump and capture are in the same `t.mu`-held `Apply` section (which
  the existing locking discipline provides), there is no window where a new runner captures a
  stale gen. The plan states this; /engineer must honor it.
- **`linkGen` unbounded growth — trivial.** Keyed by tunnel name; entries are removed when the
  tunnel is cleared (alongside the existing `ownedNames`/`appliedRI` cleanup). One-line note for
  /engineer; not a plan blocker.

## Conclusion

PLAN-READY. The recommended combination (A1 + auto-A2 + B1 + C1-with-complete-errno-table + D
commit-after-success + 5a + 5b + 5c) is sound and fully specified. All four reviewers'
findings across r1-r3 are folded. Remaining items (monitor.go 5a, C3 knob, underlay-in-VRF,
package split) are correctly scoped out as follow-ups.
