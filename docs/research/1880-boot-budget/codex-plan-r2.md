# Codex plan review r2 — task-mqabt799-itscgj (session 019eb9ba-432e-7c21-8fad-e663b684164f)

Verdict: PLAN-NEEDS-REVISION.

1. High — degraded fallback safety proof false for removals/Clear():
   today's stale removals converge only via the FRR murder+restart that
   Path A removes; on frr-reload.py failure or missing binary, additive
   fallback leaves deleted routes / Clear() removals unapplied
   indefinitely. Sentinel signals but does not define bounded
   convergence.
2. Medium — timeout can widen writer concurrency: CommandContext kills
   only the python process; a child vtysh can survive and overlap the
   fresh fallback. Needs process-group teardown or proof.
3. Low — risk section attributed sysrq style to test-ha-crash.sh, which
   actually uses incus stop --force; test-double-failover.sh is the
   sysrq evidence.

"Everything else from r1 is materially addressed" (signature, fresh
contexts, ErrNotFound + provisioning, applySem grounding, sysrq-b
primitive, 2.7x wording, Phase-2 remeasurement, stale-comment scope).
