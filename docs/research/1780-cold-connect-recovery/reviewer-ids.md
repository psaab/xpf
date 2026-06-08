# #1780 cold-connect idle-hang — reviewer ledger
Signature: cold connect 0 bytes / overnight idle / retries hang-then-recover.
Code-walk: resolver probes on ALL non-REACHABLE (refutes no-probe); hang = compounding
slowness (neg-cache 3s + resolver rate-limit + TCP SYN backoff) on a fully-aged hop +
warmer-stall letting .200 fully age overnight. Multi-path A/B/C.

## Round 1 (v1) — pending
