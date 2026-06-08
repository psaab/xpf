# #1780 cold-connect idle-hang — reviewer ledger
Signature: cold connect 0 bytes / overnight idle / retries hang-then-recover.
Code-walk: resolver probes on ALL non-REACHABLE (refutes no-probe); hang = compounding
slowness (neg-cache 3s + resolver rate-limit + TCP SYN backoff) on a fully-aged hop +
warmer-stall letting .200 fully age overnight. Multi-path A/B/C.

## Round 1 (v1) — pending
- Codex r1: task-mq4o5g1g-phbr6p
- AGY r1: adversarial-review-mq4o5gc3-yuenj5
- Claude SMR r1: claude-smr-plan-r1.md (PLAN-NEEDS-MAJOR — root cause unpinned; 3rd hypothesis; Path B premise unverified; keep Path A, defer/diagnose Path B)
- Codex r1: task-mq4o5g1g-phbr6p — PLAN-NEEDS-MAJOR/rewrite (warmer is GO runPeriodicNeighborResolution not Rust queue_warm_pass; first-probe-bypass wrong target; capture gates dominance)
- AGY r1: adversarial-review-mq4o5gc3-yuenj5 — INFRA-TIMEOUT (retry round-2)
- Claude SMR r1: PLAN-NEEDS-MAJOR (root cause unpinned; keep Path A, defer Path B)
- v2: Path A retargeted to Go periodic-resolver stall-hardening + watchdog gauge (committable); resolver-fix dropped/deferred + capture-gated

## Round 2 (v2) — pending confirm
- Codex r2: task-mq4ohvhy-pkje1d
- AGY r2: adversarial-review-mq4ohvta-7zmm4x (retry after r1 infra-timeout)
- Claude SMR r2: PLAN-READY (Path A committable; resolver-fix capture-gated)

## Round 2 (v2) — CONVERGED on Path A
- Codex r2: task-mq4ohvhy-pkje1d — PLAN-NEEDS-MINOR (add cleanFailedNeighbors; guarded-goroutine not bare ctx-timeout; phase-labeled gauge; scrub stale first-probe refs)
- AGY r2: adversarial-review-mq4ohvta-7zmm4x — PLAN-NEEDS-MINOR (per-phase in-flight guards; document regenDebouncer + warmNeighborCache UDP-flood)
- Claude SMR r2: PLAN-READY
- v3 folds all r2 minors -> CONVERGED PLAN-READY for Path A (resolver/probe fix capture-gated follow-up)
