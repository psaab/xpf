# #1780 cold-connect idle-hang — reviewer ledger
Signature: cold connect 0 bytes / overnight idle / retries hang-then-recover.
Code-walk: resolver probes on ALL non-REACHABLE (refutes no-probe); hang = compounding
slowness (neg-cache 3s + resolver rate-limit + TCP SYN backoff) on a fully-aged hop +
warmer-stall letting .200 fully age overnight. Multi-path A/B/C.

## Round 1 (v1) — pending
- Codex r1: task-mq4o5g1g-phbr6p
- AGY r1: adversarial-review-mq4o5gc3-yuenj5
- Claude SMR r1: claude-smr-plan-r1.md (PLAN-NEEDS-MAJOR — root cause unpinned; 3rd hypothesis; Path B premise unverified; keep Path A, defer/diagnose Path B)
