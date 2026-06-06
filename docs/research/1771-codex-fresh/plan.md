# #1771 — Codex-fresh INDEPENDENT research (cross-check of v3.1)

**Status:** Codex authored read-only (could not write/commit in companion mode);
recommendation captured here verbatim by the orchestrator. Codex did NOT read
the prior plan — this is a blind independent pass.

## Codex's independent recommendation (task-mq253xm5-o5hi1u, base c4a56d135)
1. **Per-key epoch/source state INSIDE `ShardedNeighborMap`** (not a separate
   lock domain). Every kernel/RX/manager mutation bumps that key's epoch under
   the key shard lock, **including absent-key DEL/FAILED tombstones**, so stale
   GET replies cannot resurrect removed MACs.
2. **Resolver-owned per-key state:** one scheduled/in-flight GET/probe per
   `(egress_ifindex, next_hop)`, cross-sweep backoff, pressure coalescing,
   negative-active drops duplicate packets without stopping resolution.
3. **Pending-key registry:** one representative pending packet per neighbor key
   under a global cap, idempotent release on dispatch/timeout, counters.
4. **ENOBUFS detection + throttled ADDITIVE (upsert) re-dumps.** Do NOT hold
   `with_all_shards` during netlink I/O; **do NOT delete RX/manager-learned
   entries** from a kernel dump.
5. Extend Rust status / Go protocol / Prometheus for per-key state, pending
   admit/drop, backoff, epoch rejects, ENOBUFS, dump attempts/success/throttle.

**Worth doing?** "Yes, but not as a monolithic rewrite. Correctness-worthy:
per-key epoch equivalence + ENOBUFS recovery. The per-key pending bound and
deeper state-machine optimization should be **gated by #1772 metrics** unless
`neighbor_pending_max_depth` / timeout drops / resolver queue pressure show real
production signal."

## Convergence with the v3.1 plan (PR #1775) — INDEPENDENT VALIDATION
Codex, blind, reached the SAME architecture as the 3-round v3.1:
- co-located per-key epoch in `ShardedNeighborMap` + absent-key tombstone bump  = v3.1 §2.1
- ENOBUFS additive/upsert, no `with_all_shards` I/O, don't delete RX/manager entries = v3.1 §2.5
- one in-flight GET/probe per key + cross-sweep backoff = v3.1 §2.3
- per-key pending bound = v3.1 §2.2
- "not monolithic; correctness first; gate the optimizations on #1772 metrics" = v3.1 Path B

**Only divergence:** Codex is slightly MORE conservative — it would gate even the
per-key **pending bound** (§2.2) on observed `neighbor_pending_max_depth`/timeout
signal, whereas v3.1 Path B ships §2.2 now. Reasonable refinement to fold.

## Constraint discovered
The Codex companion `task` runs READ-ONLY (no approval path) — it cannot author
files or implement. "Codex /engineers it" is not directly possible through this
tool; Codex can produce plan/diff as text only.
