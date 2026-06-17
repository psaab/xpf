# Claude SMR — HOSTILE plan review r5 — #1918

Reviewer: Claude SMR. Re-review of the r5 F7 resolution (drain-before-recreate).

## Verdict: PLAN-READY

r5 resolves Codex r4's F7 with the correct mechanism. I independently verified the race and the
fix against the actual code, and confirmed the rejected alternative would have reintroduced the
very bug this issue exists to fix.

## F7 disposition

- **The race is real.** I read `Apply` (`tunnel.go:455-548`): the `LinkDel`+`LinkAdd` recreate
  (461-482) runs, then `finishTunnelLocked` (540), then `startKeepalive` (542+) which drains the
  old runner via `<-runner.done` (519). So the recreate precedes the drain — a stale runner can
  be mid-`LinkSet*` (no `t.mu` held during its syscall) while `Apply` recreates the link. Codex
  r4's counterexample stands.
- **r5's fix is correct and minimal.** Moving the cancel+drain ahead of the recreate makes the
  old runner's goroutine provably exited before `LinkDel` — so it cannot issue any `LinkSet*`
  concurrent with the new link. The drain already exists (#848); r5 only changes *when* it runs.
  After the drain there is exactly one runner per link, by construction. The `linkGen` token
  becomes belt-and-suspenders for the identity-unchanged retain path (where no recreate/drain
  happens) — appropriate.
- **The rejected alternative is correctly rejected.** Codex suggested holding `t.mu` across the
  keepalive `LinkSet*`. That is exactly the lock-across-netlink pattern the secondary defect in
  #1918 is about (status reads blocking behind netlink). r5 is right to refuse it;
  drain-before-recreate achieves the same exclusion with zero lock-across-syscall.

## New-defect hunt over r5

- **Does drain-before-recreate deadlock?** No. The drain (`<-runner.done`) blocks `Apply` until
  the runner goroutine returns. The runner's tick does NOT acquire `t.mu` (only `state.mu` and
  bare netlink), so it cannot be blocked waiting on the `t.mu` that `Apply` holds. The drain
  therefore completes once the in-flight tick (if any) finishes its single `LinkSet*` + commit.
  No lock-ordering cycle. (This matches the existing #848 drain semantics, which already work
  with `Apply` holding `t.mu`.)
- **Worst-case `Apply` latency from the moved drain.** `Apply` now waits up to one probe
  deadline (≤800ms) + one netlink op for a recreate that hits an in-flight tick. This is the same
  bound the existing late drain already imposes — r5 just moves it earlier in the same critical
  section. No new latency class; acceptable and unchanged in magnitude.
- **Retain path (no recreate) still safe?** Yes — when `matches()` is true and the link is
  reused (not recreated), no `LinkDel`/`LinkAdd` happens and the runner is retained (not
  drained). There is no ifindex change, so no F7 window; `linkGen` is unchanged and the
  defense-in-depth check is a no-op. Correct.

## Conclusion

PLAN-READY. Every finding from all four reviewer-rounds (Codex F1-F6 + NF1-NF4 + F7; AGY #1-#5;
SMR F1-F4 + N1) is folded. The recommended combination plus drain-before-recreate is sound and
fully specified. Follow-ups remain correctly scoped out.
