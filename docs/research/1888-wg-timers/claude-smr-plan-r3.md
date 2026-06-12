# Claude SMR hostile plan review — round 3 (v5 → v6 fold audit)

Stance: audit the round-3 external findings against each other and against
v6; attack the armed-timer model before signing it.

## Cross-reviewer audit

- Codex r3 F1 (T7 latest-send suppression, BLOCKER) — VERIFIED against the
  v5 text (every non-empty encap stored `last_send_data_ns`; predicate
  `now − last_send_data ≥ 15s` is unreachable under ≥1 pkt/15s outbound).
  The armed-timer fix is the Linux model verbatim. ACCEPTED.
- Codex r3 F2 (T6 first-fire) + AGY r2 A4 are BOTH satisfied by the armed
  model — checked the three traffic shapes: idle→first-inbound (fires at
  +10s, not instantly), inbound-only stream (one keepalive/~10s: fire's own
  send clears, next inbound re-arms), bidirectional (every send clears; arm
  only survives when traffic is truly one-sided). No shape regresses A4.
- AGY r3 G1 (skip-pacing) — real; v6 adds the rule plus the SMR catch that
  `timer_pass` cannot see the LEARNED endpoint (control-thread-local
  `effective_endpoint`), hence the `endpoint_known` parameter.
- AGY r3 G2 (`is_some()` clause) — real; folded.
- AGY r3 G3 (ns→ms) — folded.

## New attacks attempted against v6 (none survive)

1. **Armed-timer CAS races.** t7 arm (CAS 0→now, control + transit worker)
   vs clear (store 0, control-thread decap only): a clear racing an arm can
   leave the timer armed although a receive existed — the next authenticated
   receive clears it within the 15s window unless the peer is genuinely
   silent, in which case firing is correct. t6 arm (control-thread decap
   only) vs clear (any send, incl. transit worker): worst case is one
   spurious keepalive — harmless by protocol. Relaxed ordering suffices at
   1s granularity.
2. **T7 armed + attempt interplay loop.** arm → T7 fires → attempt start
   clears arm → give-up at 90s → no re-arm without new data (sends during
   the attempt CAS-arm again — but any send implies the NoSession/rekey
   path or a live session; if a send arms t7 mid-attempt and the attempt
   gives up, T7 fires 15s after that send — correct: there WAS new egress
   data). No infinite loop without traffic.
3. **G1(a) re-arm `t6_arm := now` on skipped keepalive** — could a
   no-endpoint peer accumulate keepalive obligations forever? It re-arms
   at now and re-fires every 10s doing nothing but a deadline computation —
   not a spin (deadline strictly future), bounded at 0.1 action/s. Fine.

## Verdict

**PLAN-READY** — v6 folds all four r3 findings along the reviewers' own
fix directions, the armed-timer model is kernel-faithful and closes the
last semantic gap in the section of record, and my adversarial traces
against the new machinery all terminate correctly. Remaining items are
naming/engineering details explicitly deferred to the engineer phase.
