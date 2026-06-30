# Claude SMR hostile plan review — #2852 r2 (converged)

Verdict: **PLAN-READY-pending-lab → terminal PLAN-DEFER
(plan-deferred-research)**.

Round 1 (PLAN-NEEDS-MINOR, F1-F4) is folded into plan v2. Round 2 folds
the Codex + AGY findings into v3. The architecture is now firm; the only
remaining gate is the mandatory loss-cluster new-flow-ceiling measurement
(and PLAN-KILL stays the correct outcome if that measurement shows no
win). I do not rubber-stamp: I missed a real deadlock in r1, and I say so.

## What I got wrong in r1 (honest)

My r1 review validated the two-lock persistent ordering ("persist-shard
before flow-shard … deadlock-free") **without examining how
`release_flow` discovers the `persistent_key`**. Both Codex and AGY,
independently, caught that the v1/v2 release sketch reads `live_by_flow`
(flow-shard) FIRST to learn the persistent key, then takes the
persist-shard — i.e. flow→persist, the inverse of allocate's persist→flow
— a textbook AB/BA deadlock under concurrent allocate+release churn. Two
independent reviewers landing on the identical gap is decisive: it is
real. **F5 is the most important finding in this whole review and neither
the plan nor I had it.** This is exactly why the /research contract runs
three reviewers.

## F5 resolution — accepted, and it is clean

The fix turns on a fact the sketch overlooked: the persist-shard key
`(proto, src_ip, src_port)` is a strict subset of the 5-tuple
`SourceNatFlowKey`. So `release_flow`/`rollback_flow` can compute the
persist-shard index **directly from their argument** — they never need to
read `live_by_flow` to learn which persist-shard to take. Therefore every
two-lock path can acquire persist→flow unconditionally, both indices
known up front. A non-persistent release takes+noops the persist-shard
lock (trivial cost on the colder path) to keep one global order. This is
Codex's (A) with the direction pinned; equivalent to AGY's stratified
hierarchy. Folded into §5.2 (F5), §7.9, §8, and the §9 test 6 loom (which
must now RACE a persistent allocate against a release, not just model the
ordered path in isolation). Critically, **Phase 1 (F3) has no map
sharding and thus no two-lock path at all — it sidesteps F5 entirely**,
which independently reinforces F3's "bitmap first" sequencing: ship the
dominant win with zero deadlock surface, add sharding only if Phase-1 lab
numbers still show the residual mutex.

## F6 / F7 — accepted (minor)

- **F6 (false sharing):** adjacent `Mutex` shard cells on one 64 B line
  bounce between cores; pad each (`CachePadded`). Correct and cheap.
- **F7 (duplicate pool IP):** the static `translated.ip→addr_index`
  reverse lookup mis-resolves if a pool ever carries the same IP at two
  indices. Storing `addr_index` in the live/lease record is strictly
  safer and deletes the reverse map; fold it regardless of whether
  duplicate IPs are reachable today (verify the Go builder as a residual).

## Cross-reviewer convergence

All three reviewers (Claude-SMR, Codex, AGY) now agree:
- The bottleneck is real, correctly located (one mutex per pool,
  allocator.rs:166, held 336-475), and is **per-new-flow, not per-packet**
  (poll_descriptor session-miss gate; allocate reached only from
  source.rs:904/960).
- F1-F4 are all genuine and correctly folded.
- The §7.5 HA-reservation correction is correct: no production reserve
  caller, `debug_seed_owner`/`debug_clear_owner` are `#[cfg(test)]`;
  preserving current behavior (no synced-tuple reservation) is right and
  HA-reservation hardening is correctly OUT OF SCOPE (own follow-up issue).
- The white-box churn is ~32 of 185 tests (AGY re-verified the exact
  count), not 185 — the churn-vs-win axis is more favorable than v1 said.
- The recommended design (lock-free per-address occupancy bitmap +
  optional two-tier map sharding, phased) is sound.

## The PLAN-KILL line stands — do not weaken it

The win is entirely contingent on the lab demonstrating that the single
mutex is the dominant new-flow bottleneck on the loss cluster (6 workers)
*before another limit (RX queue, session-table insert, conntrack publish,
NIC) saturates*. The lab needs a connection-rate generator that the
`perf-test` skill does not provide. **If the lab cannot drive a new-flow
rate high enough for the mutex to dominate, the correct outcome is
PLAN-KILL (or PLAN-DEFER pending a connection-rate generator), NOT a
speculative rewrite of correctness-critical NAT state.** All three
reviewers endorse this.

## Disposition

Design firm (v3). No code, no PR — this is /research. Terminal disposition
for the issue: **PLAN-DEFER / plan-deferred-research**, left open,
/engineer-able once an operator decides to spend the churn AND the lab
gate is run. Implementation begins only on an explicit `/engineer 2852`,
which must (1) deliver Phase 1 first, (2) run the loss-cluster new-flow
measurement, and (3) PLAN-KILL if the contention is not measurable.
