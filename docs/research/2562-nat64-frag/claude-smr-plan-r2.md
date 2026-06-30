# Claude SMR — plan review r2 (#2562) — CONVERGED

Re-reviewing `plan.md` v3 after folding AGY r1 + Codex r1.

**Verdict: PLAN-DEFER (converged, 3-of-3).**

## Resolution of the r1 reviewer divergence

r1 produced a FACTUAL conflict on the cross-worker question:
- AGY r1: "session state is strictly thread-isolated" → worker-local cache
  guaranteed to fail → process-shared sharded cache mandatory.
- My r1 (S2/S3): per-worker session table → worker-local fails → process-shared.
- Codex r1 (MAJOR): sessions ARE replicated/published cross-worker.

Resolved against SOURCE (the project rule — trust neither reviewer, read the
code). **Codex is correct:** `publish_shared_session(worker_ctx.shared_sessions,
…)` (`poll_descriptor/mod.rs:2298`, shared lookup `shared_ops.rs:563-605`) and
`replicate_session_upsert(worker_ctx.peer_worker_commands, …)`
(`session_glue/mod.rs:721`, installed `upsert_synced.rs:64-85`) make sessions
cross-worker visible. AGY's "thread-isolated" and my "session fallback fails on
worker B" were both wrong. §3.4/§5.3 rewritten accordingly. This also resolves the
r1 open question (Q3) of how reverse NAT64 reaches the right worker today.

The corrected design driver is sharper, not weaker: the real hazards are (i) a
non-first fragment has **no `SessionKey`** (needs an L3+IP-ID index) and (ii) a
**replication-ordering race** (miss → drop+counter). The index must ride the
existing cross-worker machinery; a new sharded mutex is one option, not a
requirement. Net: a cleaner design than v1's bespoke cache.

## Refinement of my own S1 (Codex r1 #2)

My S1 claimed the cached value must carry `Nat64ReverseInfo`. Codex showed the
reverse `decision.nat` (via `NatDecision::reverse`, `nat/mod.rs:89`,
`poll_descriptor/mod.rs:2368`) already carries the original v6 addresses, so the
value is **data-sufficient**; only the egress frame-build API (`frame/mod.rs:246`,
consumes `Nat64ReverseInfo`) needs adapting to read `decision.nat`. Folded — §3.3
now says "data-sufficient, egress-API-insufficient", and §5.4 drops the
no-longer-needed value field.

## What all three agree on (no remaining blockers)

- The bug is real and two-layered (translator drop + flowless arm
  `nat=default()`/no `classify_ipv6_dest`). Confirmed by all three.
- SHARE the #3291 stage-4 cache; #2562 = cross-family egress dispatch + egress-API
  adaptation + translator un-drop. No second cache.
- Drop fragmented ICMP/ICMPv6 (RFC 7915; checksum covers whole datagram).
- No UDP zero-checksum cache flag (first-frag drop ⇒ no insert ⇒ non-first
  miss-drops).
- HA: no sync of the transient association; durable mapping rides session sync.
- **PLAN-DEFER:** #2562 is strictly dependent on the deferred #3291 stage 4; the
  NAT64 delta is converged but not standalone-shippable. Co-delivery (PLAN-READY)
  is premature — stage 4 must first exist with a cross-family egress dispatch seam.

No further rounds needed; the verdict is unanimous and the factual corrections are
folded.
