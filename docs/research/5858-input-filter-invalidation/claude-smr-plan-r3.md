# Claude SMR — plan review r3 (v5) — #5858

**Posture:** convergence check after Codex r2's 2nd PLAN-NEEDS-MAJOR.

## Verdict: **converge with Codex — NOT a bounded PLAN-READY; PLAN-DEFERRED pending a product decision**

I independently re-verified Codex r2's load-bearing findings and they hold:
- `emit_close_delta_with_origin` returns early for reverse metadata
  (`install.rs:467`) — a reverse-discovered deny emits **no** cross-node Close. ✔
- The flow cache is per-binding keyed by `(SessionKey, physical ingress_ifindex)`;
  the correct invalidation is the **all-binding `invalidate_slot(key, ifindex)`
  loop** (`loop_body:1332`), not my SMR2-B `evict(key)`. ✔
- `delete_terminal_filtered_session` does **no** NAT release; the family purge
  releases separately at `session_glue:355`. My v4 attribution was wrong → would
  leak allocations. ✔
- Reverse ingress is unknowable at forward install (asymmetric routing,
  `poll_descriptor:649`); my SMR2-C stamp = forward-egress was wrong. ✔

I was too soft in r1/r2. Codex out-verified me on NAT (r1), and on the
cache-key / pair-teardown / reverse-Close / reverse-ingress mechanics (r2). I
retract SMR2-B (targeted eviction sufficient) and SMR2-C (reverse=forward-egress)
as incorrect.

## Convergent position (Codex + Claude SMR)
1. **Bug real, High.** ✔
2. **Bounded fix (v1/v2 family purge) DEAD** — breaks permitted SNAT flows. ✔
3. **Correct fix (precise per-tuple) is a MAJOR multi-subsystem feature**, not a
   bounded change — it requires pair-aware teardown, reverse-ingress-on-reply,
   all-binding + sibling-coherent cache invalidation, separate NAT release, a
   reverse-Close fix, an authoritative BulkSync resync, and (for the High
   guarantee) a failover fence. Each has an in-tree pattern to follow, so it is
   **tractable but large**. ✔
4. **Neither PLAN-READY nor PLAN-KILL.** Codex: "Path C is salvageable, not
   PLAN-KILL," "needs another substantial design revision." Agreed. It is not
   PLAN-READY because the design is not converged and the central fork is a
   **product decision** (§13.4: full failover-fenced guarantee vs scoped MVP with
   a documented weaker guarantee) that `/research` must not auto-resolve.

## Why stop here (not iterate to v6 now)
The escalating-coupling pattern across two MAJOR rounds shows the remaining work
is genuine mechanism design whose shape depends on the §13.4 product choice
(Option A adds a fence + full BulkSync; Option B accepts a documented residual
and is ~half the surface). Designing v6 before that choice would be speculative.
The `/research` value — proving the bounded fix unsafe, mapping the true scope,
and isolating the one decision a human must make — is delivered.

## Recommendation
**PLAN-DEFERRED**: surface the §13.4 decision to the product/security owner.
Recommend **Option B (scoped MVP + documented residual failover window)** as the
pragmatic default — it moves revocation from *never/until-timeout* to *prompt on
the active node* at far lower cost and **no** failover-latency risk — unless the
security owner requires the strict cross-failover guarantee (Option A). After the
decision, one v6 design round + a final Codex/SMR pass gets to PLAN-READY; then
`/engineer` (a substantial, HA-touching, multi-file PR with a `make test-failover`
gate). Do **not** `/engineer 5858` mechanically from v5.
