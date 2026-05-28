# Codex plan review — round 4 (#1636)

**Task ID**: task-mppsygv9-n0gwuq
**Plan reviewed**: `docs/research/1636-cold-connect-mitigation/plan.md` v4 @ `d5a4a5eb87b5`
**Note**: Round 3 was REVIEW-BLOCKED by sandbox failure; round 4 retry used inlined plan sections per `feedback_codex_infra_must_retry`.

## VERDICT: PLAN-NEEDS-MINOR

## Findings (verbatim from Codex)

1. **HA demotion still has an in-flight-item hole.** `ha.is_active()` only gates production; queued current-generation items can still dequeue and call `trigger_kernel_arp_probe()` after demotion. Add an explicit demote hook that disables warming and bumps `warm_generation`, and have the worker re-check active/generation immediately before triggering. Otherwise §9 invariant 2 is stated but not mechanically guaranteed.

2. **"generation bump on each call" must mean each admitted warm sweep, not every `queue_warm_pass()` invocation.** If snapshot refreshes happen faster than 1 Hz and no-op calls bump generation, the system can self-stale all queued work and never warm reliably.

3. **`Disconnected` logging should be prod-visible but rate-limited or transition-logged.** As written, every key in every sweep can emit `ERROR: neighbor warmer disconnected`, which can flood logs after worker death. Keep the Prometheus counter; log once or periodically.

4. **The §10 table is now basically acceptable, but rename/clarify `first-probe-LOST`.** The ~1.02s case assumes the initial resolution train fails and the retry's first probe succeeds. Sustained loss is still governed by TCP retry behavior, not bounded by D.

5. **IPv6 warming must be NDP-capable.** If `trigger_kernel_arp_probe()` is just placeholder naming, fine; if literal ARP-only implementation leaks into PR-2, routes_v6 support is fake.

## Answers to Codex's check-list

1. r2 #3 generation collapse: adequate, subject to finding #2.
2. r2 #4 HA invariant: not fully adequate until in-flight demote suppression is specified.
3. r2 #5 §10 derivation: acceptable with the wording fix above.
4. r2 #6 kernel defaults: acceptable.
5. AGY r3 findings: folded in; only the disconnected log storm remains as a minor operational correction.

## Recommendation

Iterate once with the HA demote/generation wording fixes, then proceed to `/engineer 1636`.

## Session

Codex session ID: 019e6fc2-3ef8-77a0-b682-a764481d1fda
